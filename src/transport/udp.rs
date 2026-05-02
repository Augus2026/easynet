use crate::codec::{ByteCodec, Message, MessageType};
use crate::common::tun_io_task;
use crate::config::{ClientConfig, ServerConfig, TransparentProxyConfig};
use crate::server::{
    get_destination_ip, handle_data, handle_disconnect, handle_handshake, handle_keepalive,
    send_to_client,
};
use crate::transparent_proxy::start_transparent_proxy;
use crate::transport::{run_connected_client, TransportTrait};
use anyhow::Result;
use futures::{SinkExt, StreamExt};
use log::{error, info};
use easynet_rules::RulesEngine;
use socket2::Socket;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

pub struct UdpTransport {
    framed: UdpFramed<ByteCodec>,
}

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> Self {
        const BUFFER_SIZE: usize = 8 * 1024 * 1024;
        let std_socket = socket.into_std().expect("Failed to convert to std socket");
        let socket2_socket = Socket::from(std_socket);
        let _ = socket2_socket.set_send_buffer_size(BUFFER_SIZE);
        let _ = socket2_socket.set_recv_buffer_size(BUFFER_SIZE);
        let std_socket = socket2_socket.into();
        let socket = UdpSocket::from_std(std_socket).expect("Failed to convert back to UdpSocket");

        Self {
            framed: UdpFramed::new(socket, ByteCodec::new()),
        }
    }

    pub async fn bind(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self::new(socket))
    }
}

impl TransportTrait for UdpTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        msg: Message,
        addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Self::Error>> + Send + '_>>
    {
        Box::pin(async move { self.framed.send((msg, addr)).await })
    }

    fn next(
        &mut self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Option<Result<(Message, SocketAddr), Self::Error>>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move { self.framed.next().await })
    }
}

pub async fn run_udp_client(
    config: ClientConfig,
    rules_config: easynet_rules::RulesConfig,
    transparent_proxy_config: TransparentProxyConfig,
    tun: tun2::AsyncDevice,
    transport: UdpTransport,
) -> Result<()> {
    run_connected_client(
        config,
        rules_config,
        transparent_proxy_config,
        tun,
        transport,
    )
    .await
}

async fn transport_io_task(
    mut transport: UdpTransport,
    mut tun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    loop {
        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, src_addr))) => {
                        match msg.msg {
                            Some(MessageType::Handshake(handshake)) => {
                                let (dummy_tx, _) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
                                let provided_session_id = if handshake.session_id.is_empty() {
                                    None
                                } else {
                                    Some(handshake.session_id.clone())
                                };
                                let provided_token = if handshake.token.is_empty() {
                                    None
                                } else {
                                    Some(handshake.token.clone())
                                };
                                handle_handshake(src_addr, &mut transport, dummy_tx, provided_session_id, provided_token).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr).await;
                                info!("Client {} disconnected: {}", src_addr, disconnect.reason);
                            }
                            _ => {
                                info!("Unknown message type from {}", src_addr);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading message: {}", e);
                        break;
                    }
                    None => {
                        break;
                    }
                }
            }

            result = tun_rx.recv() => {
                match result {
                    Some(data) => {
                        if let Some(dest_ip) = get_destination_ip(&data) {
                            send_to_client(&data, &mut transport, dest_ip).await;
                        }
                    }
                    None => {
                        error!("Transport: Channel disconnected");
                        break;
                    }
                }
            }
        }
    }
}

pub async fn run_udp_server(
    config: ServerConfig,
    rules_config: easynet_rules::RulesConfig,
    transparent_proxy_config: TransparentProxyConfig,
    tun: tun2::AsyncDevice,
) -> Result<()> {
    let (tun_tx, tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (direct_proxy_tx, direct_proxy_rx_in) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (direct_proxy_tx_out, direct_proxy_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let transport = UdpTransport::bind(&config.bind_addr.to_string()).await?;

    let rules_engine = RulesEngine::from_config(rules_config)
        .map_err(|e| anyhow::anyhow!("Failed to load rules: {}", e))?;

    let direct_proxy_task = start_transparent_proxy(
        transparent_proxy_config.interface.clone(),
        transparent_proxy_config.upstream_server,
        direct_proxy_rx_in,
        direct_proxy_tx_out,
        transparent_proxy_config.smoltcp_addr,
        transparent_proxy_config.smoltcp_netmask,
        transparent_proxy_config.smoltcp_gateway,
    );

    let tun_handle = tokio::spawn(tun_io_task(
        tun,
        tun_tx,
        transport_rx,
        rules_engine,
        direct_proxy_tx,
        direct_proxy_rx,
    ));
    let transport_handle = tokio::spawn(transport_io_task(
        transport,
        tun_rx,
        transport_tx
    ));

    tokio::select! {
        _ = direct_proxy_task => {},
        _ = tun_handle => {},
        _ = transport_handle => {},
    }
    Ok(())
}

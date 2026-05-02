use crate::codec::{ByteCodec, Data, Message, MessageType};
use crate::common::tun_io_task;
use crate::config::{ClientConfig, ServerConfig, TransparentProxyConfig};
use crate::server::{
    handle_data, handle_disconnect, handle_handshake, handle_keepalive, handle_tun_packet,
};
use crate::transparent_proxy::start_transparent_proxy;
use crate::transport::{run_connected_client, TransportTrait};
use anyhow::Result;
use futures::{SinkExt, StreamExt};
use log::{error, info, warn};
use easynet_rules::RulesEngine;
use socket2::Socket;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

pub struct TcpTransport {
    framed: Framed<TcpStream, ByteCodec>,
    peer_addr: SocketAddr,
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;

        const BUFFER_SIZE: usize = 8 * 1024 * 1024;
        let socket = Socket::from(stream.into_std()?);
        socket.set_send_buffer_size(BUFFER_SIZE)?;
        socket.set_recv_buffer_size(BUFFER_SIZE)?;
        let stream = TcpStream::from_std(socket.into())?;

        Ok(Self {
            framed: Framed::new(stream, ByteCodec::new()),
            peer_addr,
        })
    }

    pub async fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::new(stream)
    }

    pub async fn accept(listener: &TcpListener) -> io::Result<Self> {
        let (stream, _) = listener.accept().await?;
        Self::new(stream)
    }

    pub async fn bind(addr: &str) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl TransportTrait for TcpTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        msg: Message,
        _addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Self::Error>> + Send + '_>>
    {
        Box::pin(async move { self.framed.send(msg).await })
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
        Box::pin(async move {
            let result = self.framed.next().await;
            result.map(|r| r.map(|msg| (msg, self.peer_addr)))
        })
    }
}

pub async fn run_tcp_client(
    config: ClientConfig,
    rules_config: easynet_rules::RulesConfig,
    transparent_proxy_config: TransparentProxyConfig,
    tun: tun2::AsyncDevice,
    transport: TcpTransport,
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

async fn handle_tcp_connection(
    mut tcp_transport: TcpTransport,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let peer_addr = tcp_transport.peer_addr();
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    loop {
        tokio::select! {
            result = tcp_transport.next() => {
                match result {
                    Some(Ok((msg, src_addr))) => {
                        match msg.msg {
                            Some(MessageType::Handshake(handshake)) => {
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
                                handle_handshake(peer_addr, &mut tcp_transport, client_tx.clone(), provided_session_id, provided_token).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut tcp_transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr).await;
                                info!("Client {} disconnected: {}", src_addr, disconnect.reason);
                            }
                            _ => {
                                warn!("Unknown message type from {}", src_addr);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading message from {}: {}", peer_addr, e);
                        break;
                    }
                    None => {
                        info!("Client {} disconnected", peer_addr);
                        break;
                    }
                }
            }

            result = client_rx.recv() => {
                match result {
                    Some(data) => {
                        let message = Message::data(Data { payload: data });
                        if let Err(e) = tcp_transport.send(message, peer_addr).await {
                            warn!("Failed to send data to {}: {}", peer_addr, e);
                            break;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        }
    }

    handle_disconnect(peer_addr).await;
}

pub async fn transport_io_task(
    config: ServerConfig,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let listener = TcpTransport::bind(&config.bind_addr.to_string())
        .await
        .expect("Failed to bind to address");
    info!("TCP server listening on {}", config.bind_addr);

    loop {
        match TcpTransport::accept(&listener).await {
            Ok(tcp_transport) => {
                info!("new tcp connection client {}", tcp_transport.peer_addr());
                let tx = transport_tx.clone();
                tokio::spawn(async move { handle_tcp_connection(tcp_transport, tx).await });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

pub async fn run_tcp_server(
    config: ServerConfig,
    rules_config: easynet_rules::RulesConfig,
    transparent_proxy_config: TransparentProxyConfig,
    tun: tun2::AsyncDevice,
) -> Result<()> {
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (direct_proxy_tx, direct_proxy_rx_in) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (direct_proxy_tx_out, direct_proxy_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

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

    tokio::spawn(async move {
        handle_tun_packet(&mut tun_rx).await;
    });

    let transport_task = tokio::spawn(transport_io_task(config, transport_tx));

    tokio::select! {
        _ = direct_proxy_task => {},
        _ = tun_handle => {},
        _ = transport_task => {},
    }
    Ok(())
}

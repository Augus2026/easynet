use crate::codec::{ByteCodec, Data, Message, MessageType};
use crate::common::tun_io_task;
use crate::config::ServerConfig;
use crate::server::{
    handle_data, handle_disconnect, handle_handshake, handle_keepalive, handle_tun_packet,
};
use crate::transport::TransportTrait;
use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use log::{error, info, warn};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use tokio_util::codec::{FramedRead, FramedWrite};

const EASYNET_ALPN: &[u8] = b"easynet/iroh/0";
const SECRET_KEY_PATH: &str = "config/iroh_secret_key";

pub struct IrohTransport {
    _connection: Connection,
    send: FramedWrite<SendStream, ByteCodec>,
    recv: FramedRead<RecvStream, ByteCodec>,
    peer_addr: SocketAddr,
}

fn make_peer_addr(endpoint_id: &EndpointId) -> SocketAddr {
    let bytes = endpoint_id.as_bytes();
    let port = 1024u16 + ((bytes[0] as u16) << 8 | bytes[1] as u16) % 64511;
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

fn load_or_generate_secret_key() -> Result<SecretKey> {
    let path = Path::new(SECRET_KEY_PATH);
    if path.exists() {
        let bytes = std::fs::read(path).context("failed to read iroh secret key")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid secret key length: expected 32 bytes"))?;
        Ok(SecretKey::from_bytes(&arr))
    } else {
        let key = SecretKey::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, key.to_bytes())?;
        info!("generated new iroh secret key at {}", SECRET_KEY_PATH);
        Ok(key)
    }
}

impl IrohTransport {
    pub async fn connect(server_node_id: &str) -> Result<(Self, Endpoint)> {
        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![EASYNET_ALPN.to_vec()])
            .bind()
            .await
            .context("failed to bind iroh endpoint")?;

        let node_id: EndpointId = server_node_id
            .parse()
            .context("invalid server node id")?;

        let addr = EndpointAddr::from(node_id);

        let connection = endpoint
            .connect(addr, EASYNET_ALPN)
            .await
            .context("failed to connect to iroh server")?;

        let (send, recv) = connection
            .open_bi()
            .await
            .context("failed to open bidirectional stream")?;

        let transport = Self {
            peer_addr: make_peer_addr(&node_id),
            send: FramedWrite::new(send, ByteCodec::new()),
            recv: FramedRead::new(recv, ByteCodec::new()),
            _connection: connection,
        };
        Ok((transport, endpoint))
    }

    fn from_connection(
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
        endpoint_id: EndpointId,
    ) -> Self {
        Self {
            peer_addr: make_peer_addr(&endpoint_id),
            send: FramedWrite::new(send, ByteCodec::new()),
            recv: FramedRead::new(recv, ByteCodec::new()),
            _connection: connection,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl TransportTrait for IrohTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        msg: Message,
        _addr: SocketAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), Self::Error>> + Send + '_>,
    > {
        Box::pin(async move {
            self.send
                .send(msg)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
        })
    }

    fn next(
        &mut self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Option<Result<(Message, SocketAddr), Self::Error>>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            match self.recv.next().await {
                Some(Ok(msg)) => Some(Ok((msg, self.peer_addr))),
                Some(Err(e)) => Some(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
                None => None,
            }
        })
    }
}

pub async fn run_iroh_server(
    config: ServerConfig,
    tun: tun2::AsyncDevice,
) -> Result<()> {
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    let tun_handle = tokio::spawn(tun_io_task(tun, tun_tx, transport_rx));

    tokio::spawn(async move {
        handle_tun_packet(&mut tun_rx).await;
    });

    let transport_task = tokio::spawn(transport_io_task(config, transport_tx));

    tokio::select! {
        _ = tun_handle => {},
        _ = transport_task => {},
    }
    Ok(())
}

async fn transport_io_task(
    _config: ServerConfig,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let secret_key = match load_or_generate_secret_key() {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to load iroh secret key: {}", e);
            return;
        }
    };

    let endpoint = match Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![EASYNET_ALPN.to_vec()])
        .bind()
        .await
    {
        Ok(ep) => ep,
        Err(e) => {
            error!("Failed to bind iroh endpoint: {}", e);
            return;
        }
    };

    info!(
        "iroh server ready, EndpointId: {}",
        endpoint.id()
    );

    loop {
        match endpoint.accept().await {
            Some(incoming) => match incoming.accept() {
                Ok(accepting) => match accepting.await {
                    Ok(connection) => {
                        let remote_id = connection.remote_id();
                        info!("new iroh connection from {}", remote_id);

                        match connection.accept_bi().await {
                            Ok((send, recv)) => {
                                let tx = transport_tx.clone();
                                tokio::spawn(async move {
                                    handle_iroh_connection(
                                        connection, send, recv, remote_id, tx,
                                    )
                                    .await;
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept iroh bi stream: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to complete iroh connection: {}", e);
                    }
                },
                Err(e) => {
                    error!("Failed to accept incoming: {}", e);
                }
            },
            None => {
                info!("iroh endpoint closed");
                break;
            }
        }
    }
}

async fn handle_iroh_connection(
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    endpoint_id: EndpointId,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let peer_addr = make_peer_addr(&endpoint_id);
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    let mut transport = IrohTransport::from_connection(connection, send, recv, endpoint_id);

    loop {
        tokio::select! {
            result = transport.next() => {
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
                                handle_handshake(peer_addr, &mut transport, client_tx.clone(), provided_session_id, provided_token).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut transport, keepalive.timestamp).await;
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                handle_disconnect(src_addr).await;
                                info!("Iroh client {} disconnected: {}", src_addr, disconnect.reason);
                            }
                            _ => {
                                warn!("Unknown message type from iroh client {}", src_addr);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading from iroh client {}: {}", peer_addr, e);
                        break;
                    }
                    None => {
                        info!("Iroh client {} disconnected", peer_addr);
                        break;
                    }
                }
            }

            result = client_rx.recv() => {
                match result {
                    Some(data) => {
                        let message = Message::data(Data { payload: data });
                        if let Err(e) = transport.send(message, peer_addr).await {
                            warn!("Failed to send data to iroh client {}: {}", peer_addr, e);
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

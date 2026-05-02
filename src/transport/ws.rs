use crate::codec::{Data, Message, MessageType};
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
use native_tls::Identity;
use prost::Message as _;
use easynet_rules::RulesEngine;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{accept_async_with_config, MaybeTlsStream, WebSocketStream};

pub struct WsTransport {
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    peer_addr: SocketAddr,
}

impl WsTransport {
    pub fn create_tls_acceptor(cert_path: &str, key_path: &str) -> io::Result<TlsAcceptor> {
        let resolve_path = |path: &str, default: &'static str| -> String {
            if Path::new(path).exists() {
                path.to_string()
            } else {
                default.to_string()
            }
        };

        let cert_path = resolve_path(cert_path, "certs/server-cert.pem");
        let key_path = resolve_path(key_path, "certs/server-key.pem");

        if !Path::new(&cert_path).exists() || !Path::new(&key_path).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Certificate or key file not found. Looking for {} and {}",
                    cert_path, key_path
                ),
            ));
        }

        let cert_bytes = fs::read(&cert_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read certificate: {}", e),
            )
        })?;
        let key_bytes = fs::read(&key_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read key: {}", e),
            )
        })?;
        let identity = Identity::from_pkcs8(&cert_bytes, &key_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to create identity: {}", e),
            )
        })?;

        native_tls::TlsAcceptor::new(identity)
            .map(TlsAcceptor::from)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to create TLS acceptor: {}", e),
                )
            })
    }

    pub async fn accept(
        listener: &TcpListener,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> io::Result<Self> {
        let (stream, addr) = listener.accept().await?;

        let tls_stream = if let Some(acceptor) = &tls_acceptor {
            acceptor
                .accept(stream)
                .await
                .map_err(|e| {
                    log::error!("TLS handshake failed from {}: {}", addr, e);
                    io::Error::new(io::ErrorKind::ConnectionRefused, e)
                })
                .map(MaybeTlsStream::NativeTls)?
        } else {
            MaybeTlsStream::Plain(stream)
        };

        let ws_stream = accept_async_with_config(tls_stream, None)
            .await
            .map_err(|e| {
                log::error!("WebSocket handshake failed from {}: {}", addr, e);
                io::Error::new(io::ErrorKind::ConnectionRefused, e)
            })?;

        log::info!(
            "{} connection established from {}",
            if tls_acceptor.is_some() {
                "WSS"
            } else {
                "WebSocket"
            },
            addr
        );

        Ok(Self {
            ws_stream,
            peer_addr: addr,
        })
    }

    pub async fn bind(addr: &str) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn parse_url(url: &str) -> io::Result<(String, u16, bool)> {
        let parsed_url = url::Url::parse(url).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed to parse URL: {}", e),
            )
        })?;

        let host = parsed_url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing host in URL"))?
            .to_string();
        let port = parsed_url
            .port_or_known_default()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing port in URL"))?;
        let use_tls = parsed_url.scheme() == "wss";

        Ok((host, port, use_tls))
    }

    async fn wrap_with_tls(
        tcp_stream: TcpStream,
        host: &str,
        ca_cert_path: &str,
    ) -> io::Result<MaybeTlsStream<TcpStream>> {
        let mut builder = native_tls::TlsConnector::builder();

        if Path::new(ca_cert_path).exists() {
            let cert_pem = fs::read_to_string(ca_cert_path).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to read CA certificate: {}", e),
                )
            })?;
            let certificate =
                native_tls::Certificate::from_pem(cert_pem.as_bytes()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to parse CA certificate: {}", e),
                    )
                })?;
            builder.add_root_certificate(certificate);
        }

        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);

        let tls_connector = TlsConnector::from(builder.build().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to build TLS connector: {}", e),
            )
        })?);

        let tls_stream = tls_connector.connect(host, tcp_stream).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("TLS handshake failed: {}", e),
            )
        })?;

        Ok(MaybeTlsStream::NativeTls(tls_stream))
    }

    pub async fn connect(url: &str, ca_cert_path: &str) -> io::Result<Self> {
        let (host, port, use_tls) = Self::parse_url(url)?;

        let tcp_stream = TcpStream::connect((&*host, port)).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Failed to connect to {}:{}", host, e),
            )
        })?;

        let stream = if use_tls {
            Self::wrap_with_tls(tcp_stream, &host, ca_cert_path).await?
        } else {
            MaybeTlsStream::Plain(tcp_stream)
        };

        let ws_stream = tokio_tungstenite::client_async_with_config(url, stream, None)
            .await
            .map(|(ws, _)| ws)
            .map_err(|e| {
                log::error!("WebSocket handshake failed: {}", e);
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("WebSocket handshake failed: {}", e),
                )
            })?;

        let server_addr = format!("{}:{}", host, port)
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap());

        log::info!("Connected to WebSocket server at {}", url);

        Ok(Self {
            ws_stream,
            peer_addr: server_addr,
        })
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl TransportTrait for WsTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        msg: Message,
        _addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Self::Error>> + Send + '_>>
    {
        Box::pin(async move {
            let bytes = msg.encode_to_vec();
            let ws_msg = WsMessage::Binary(bytes.into());
            self.ws_stream
                .send(ws_msg)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
        })
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
            loop {
                match self.ws_stream.next().await {
                    Some(Ok(WsMessage::Binary(bytes))) => {
                        return Message::decode(&bytes[..])
                            .map(|msg| Ok((msg, self.peer_addr)))
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                            .ok();
                    }
                    Some(Ok(msg)) => {
                        log::warn!("Received unsupported WebSocket message type: {:?}", msg);
                        continue;
                    }
                    Some(Err(e)) => return Some(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
                    None => return None,
                }
            }
        })
    }
}

pub async fn run_ws_client(
    config: ClientConfig,
    rules_config: easynet_rules::RulesConfig,
    transparent_proxy_config: TransparentProxyConfig,
    tun: tun2::AsyncDevice,
    transport: WsTransport,
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

async fn handle_ws_connection(
    mut ws_transport: WsTransport,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let peer_addr = ws_transport.peer_addr();
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

    loop {
        tokio::select! {
            result = ws_transport.next() => {
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
                                handle_handshake(peer_addr, &mut ws_transport, client_tx.clone(), provided_session_id, provided_token).await;
                            }
                            Some(MessageType::Data(data)) => {
                                handle_data(&data.payload, &transport_tx).await;
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                handle_keepalive(src_addr, &mut ws_transport, keepalive.timestamp).await;
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
                        info!("WS client {} disconnected", peer_addr);
                        break;
                    }
                }
            }

            result = client_rx.recv() => {
                match result {
                    Some(data) => {
                        let message = Message::data(Data { payload: data });
                        if let Err(e) = ws_transport.send(message, peer_addr).await {
                            warn!("Failed to send data to WS client {}: {}", peer_addr, e);
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
    tls_acceptor: Option<TlsAcceptor>,
    transport_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    let listener = WsTransport::bind(&config.bind_addr.to_string())
        .await
        .expect("Failed to bind to address");
    info!("WS server listening on {}", config.bind_addr);

    loop {
        match WsTransport::accept(&listener, tls_acceptor.clone()).await {
            Ok(ws_transport) => {
                info!("new ws connection client {}", ws_transport.peer_addr());
                let tx = transport_tx.clone();
                tokio::spawn(async move { handle_ws_connection(ws_transport, tx).await });
            }
            Err(e) => {
                error!("Failed to accept WS connection: {}", e);
            }
        }
    }
}

pub async fn run_ws_server(
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

    let tls_acceptor = if config.transport_type == "wss" {
        Some(WsTransport::create_tls_acceptor(&config.cert_path, &config.key_path).unwrap())
    } else {
        None
    };

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

    let transport_task = tokio::spawn(transport_io_task(config, tls_acceptor, transport_tx));

    tokio::select! {
        _ = direct_proxy_task => {},
        _ = tun_handle => {},
        _ = transport_task => {},
    }
    Ok(())
}

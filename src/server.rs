use crate::codec::{Data, Handshake, KeepAlive, Message, TunConfig};
use crate::config::{AppConfig, ServerConfig};
use crate::transport::{run_tcp_server, run_udp_server, run_ws_server, TransportTrait};
use crate::tun_device::create_tun_device;
use anyhow::Result;
use lazy_static::lazy_static;
use log::{error, info, warn};
use nanoid;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};
use std::{collections::HashMap, net::Ipv4Addr};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
struct Client {
    addr: SocketAddr,
    virtual_ip: Ipv4Addr,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    tun_config: TunConfig,
    last_seen: SystemTime,
}

lazy_static! {
    static ref NEXT_CLIENT_ID: AtomicU32 = AtomicU32::new(2);
    static ref SESSIONS: Mutex<HashMap<String, Client>> = Mutex::new(HashMap::new());
}

fn build_session_id() -> String {
    format!("{}", nanoid::nanoid!(21))
}

fn validate_token(token: &str, server_token: &str) -> bool {
    if server_token.is_empty() {
        return true;
    }
    token == server_token
}

pub(crate) fn get_destination_ip(data: &[u8]) -> Option<Ipv4Addr> {
    if data.len() < 20 {
        return None;
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    if version != 4 {
        return None;
    }

    let dest_ip_bytes: [u8; 4] = data[16..20].try_into().ok()?;
    Some(Ipv4Addr::from(dest_ip_bytes))
}

pub(crate) async fn handle_data(data: &[u8], transport_tx: &tokio::sync::mpsc::Sender<Vec<u8>>) {
    if let Err(e) = transport_tx.send(data.to_vec()).await {
        warn!("Failed to send to transport writer: {}", e);
    }
}

pub(crate) async fn handle_keepalive(
    src_addr: SocketAddr,
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    timestamp: i64,
) {
    let response = Message::keepalive(KeepAlive { timestamp });
    if let Err(e) = transport.send(response, src_addr).await {
        warn!("Failed to send keepalive response to {}: {}", src_addr, e);
    }
}

pub(crate) async fn handle_handshake(
    src_addr: SocketAddr,
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    provided_session_id: Option<String>,
    provided_token: Option<String>,
) {
    let server_config = match ServerConfig::load() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load server config: {}", e);
            return;
        }
    };
    let server_token = server_config.token.clone();
    let session_id: String;
    let virtual_ip: Ipv4Addr;
    let tun_config: TunConfig;

    if let Some(handshake_token) = provided_token {
        if !validate_token(&handshake_token, server_token.as_str()) {
            warn!(
                "Invalid token provided by {}: {}",
                src_addr, handshake_token
            );

            let message = Message::handshake(Handshake {
                token: String::new(),
                session_id: String::new(),
                tun_config: None,
            });

            if let Err(e) = transport.send(message, src_addr).await {
                error!("Failed to send handshake to {}: {}", src_addr, e);
                return;
            }

            return;
        } else {
            info!("Valid token provided by {}: {}", src_addr, handshake_token);
        }
    }

    if let Some(provided_id) = provided_session_id {
        let sessions_map = SESSIONS.lock().await;
        if let Some(existing_client) = sessions_map.get(&provided_id) {
            session_id = provided_id;
            virtual_ip = existing_client.virtual_ip;
            tun_config = existing_client.tun_config.clone();
            info!(
                "Client reconnecting with session_id: {}, IP: {}",
                session_id, virtual_ip
            );
        } else {
            session_id = build_session_id();
            let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);
            virtual_ip = Ipv4Addr::new(10, 0, 0, client_id as u8);
            tun_config = build_tun_config(&server_config);
            info!(
                "Client {} created new session with session_id: {}, IP: {}",
                client_id, session_id, virtual_ip
            );
        }
    } else {
        session_id = build_session_id();
        let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);
        virtual_ip = Ipv4Addr::new(10, 0, 0, client_id as u8);
        tun_config = build_tun_config(&server_config);
        info!(
            "Client {} created new session with session_id: {}, IP: {}",
            client_id, session_id, virtual_ip
        );
    }

    let message = Message::handshake(Handshake {
        token: server_token.clone(),
        session_id: session_id.clone(),
        tun_config: Some(tun_config.clone()),
    });

    if let Err(e) = transport.send(message, src_addr).await {
        error!("Failed to send handshake to {}: {}", src_addr, e);
        return;
    }

    let client = Client {
        addr: src_addr,
        virtual_ip,
        tx: client_tx,
        tun_config: tun_config.clone(),
        last_seen: SystemTime::now(),
    };

    {
        let mut sessions_map = SESSIONS.lock().await;
        sessions_map.insert(session_id.clone(), client.clone());
    }

    info!(
        "Client connected from {}, assigned IP: {}, session_id: {}",
        src_addr, virtual_ip, session_id
    );
}

pub(crate) async fn handle_disconnect(addr: SocketAddr) {
    let mut sessions_map = SESSIONS.lock().await;
    if let Some((session_id, client)) = sessions_map
        .iter()
        .find(|(_k, v)| v.addr == addr)
        .map(|(k, v)| (k.clone(), v.clone()))
    {
        sessions_map.remove(&session_id);
        info!("Client {} disconnected ({})", session_id, client.addr);
    }
}

pub(crate) async fn handle_tun_packet(tun_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = tun_rx.recv().await {
        let sessions_map = SESSIONS.lock().await;
        if let Some(dest_ip) = get_destination_ip(&data) {
            let target_client = sessions_map.values().find(|c| c.virtual_ip == dest_ip);
            if let Some(client) = target_client {
                if let Err(e) = client.tx.send(data).await {
                    warn!("Failed to send to client {}: {}", client.addr, e);
                }
            }
        }
    }
}

pub(crate) async fn send_to_client(
    data: &[u8],
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    dest_ip: Ipv4Addr,
) {
    let sessions_map = SESSIONS.lock().await;
    if let Some(client) = sessions_map.values().find(|c| c.virtual_ip == dest_ip) {
        let message = Message::data(Data {
            payload: data.to_vec(),
        });
        if let Err(e) = transport.send(message, client.addr).await {
            warn!("Failed to send to {}: {}", client.addr, e);
        }
    }
}

pub async fn run_server_from_config(app_config: AppConfig) -> Result<()> {
    tokio::spawn(cleanup_expired_sessions());
    let config = app_config.server.clone();
    let rules_config = app_config.rules.clone();
    let transparent_proxy_config = app_config.transparent_proxy.clone();
    let tun = create_tun_device(
        &config.tun_name,
        config.tun_addr,
        config.tun_netmask,
        config.tun_destination,
        &config.tun_dns_servers,
        config.tun_mtu as u16,
    )?;

    match config.transport_type.to_lowercase().as_str() {
        "tcp" => {
            info!("Using TCP transport");
            run_tcp_server(config, rules_config, transparent_proxy_config, tun).await
        }
        "udp" => {
            info!("Using UDP transport");
            run_udp_server(config, rules_config, transparent_proxy_config, tun).await
        }
        "ws" => {
            info!("Using WebSocket transport");
            run_ws_server(config, rules_config, transparent_proxy_config, tun).await
        }
        "wss" => {
            info!("Using WebSocket(Secure) transport");
            run_ws_server(config, rules_config, transparent_proxy_config, tun).await
        }
        _ => {
            error!("Unknown transport type: {}", config.transport_type);
            Err(anyhow::anyhow!(
                "Unknown transport type: {}",
                config.transport_type
            ))
        }
    }
}

pub async fn run_server() -> Result<()> {
    let config = AppConfig::load()?;
    info!("Server configuration: {:?}", config.server);
    run_server_from_config(config).await
}

fn build_tun_config(config: &ServerConfig) -> TunConfig {
    TunConfig {
        name: config.tun_name.clone(),
        address: config.tun_addr.to_string(),
        netmask: config.tun_netmask.to_string(),
        destination: config.tun_destination.to_string(),
        dns: config
            .tun_dns_servers
            .iter()
            .map(ToString::to_string)
            .collect(),
        mtu: config.tun_mtu as u32,
    }
}

async fn cleanup_expired_sessions() {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

        let mut sessions = SESSIONS.lock().await;
        let now = SystemTime::now();
        let mut removed_count = 0;

        sessions.retain(|session_id, client| {
            let elapsed = now
                .duration_since(client.last_seen)
                .unwrap_or(Duration::MAX);
            let should_keep = elapsed < Duration::from_secs(3600);

            if !should_keep {
                info!(
                    "Cleaning up expired session: {}, last seen: {:?}",
                    session_id, client.last_seen
                );
                removed_count += 1;
            }

            should_keep
        });

        if removed_count > 0 {
            info!("Cleaned up {} expired sessions", removed_count);
        }
    }
}

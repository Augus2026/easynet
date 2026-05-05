use crate::codec::{Handshake, Message, MessageType, TunConfig};
use crate::config::{load_client_state, save_client_state, AppConfig, ClientConfig};
use crate::transport::{
    run_tcp_client, run_udp_client, run_ws_client, TcpTransport, TransportTrait, UdpTransport,
    WsTransport,
};
use crate::tun_device::create_tun_device;
use anyhow::Result;
use log::{error, info, warn};
use std::time::Duration;
use tokio::time::sleep;

async fn handshake_async(
    transport: &mut impl TransportTrait<Error = std::io::Error>,
    server_addr: std::net::SocketAddr,
    config: &mut ClientConfig,
) -> Result<TunConfig> {
    let is_reconnect = !config.session_id.is_empty();
    if is_reconnect {
        info!("Reconnecting with session_id: {}", config.session_id);
    } else {
        info!("New connection to server at {}", server_addr);
    }

    let handshake_message = Message::handshake(Handshake {
        token: config.token.clone(),
        session_id: config.session_id.clone(),
        tun_config: None,
    });

    transport.send(handshake_message, server_addr).await?;

    let timeout = sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    tokio::select! {
        result = transport.next() => {
            match result {
                Some(Ok((msg, _addr))) => {
                    match msg.msg {
                        Some(MessageType::Handshake(handshake)) => {
                            info!("Received handshake response: {:?}", handshake);

                            if handshake.token != config.token {
                                return Err(anyhow::anyhow!("Invalid token in handshake response"));
                            }

                            if let Some(tun_config) = handshake.tun_config {
                                if handshake.session_id != config.session_id {
                                    info!("Session ID changed: {} -> {}", config.session_id, handshake.session_id);
                                    config.session_id = handshake.session_id.clone();
                                    let mut state = load_client_state()?;
                                    state.session_id = config.session_id.clone();
                                    save_client_state(&state)?;
                                }

                                let tun_config_obj = TunConfig {
                                    name: tun_config.name,
                                    address: tun_config.address,
                                    netmask: tun_config.netmask,
                                    destination: tun_config.destination,
                                    dns: tun_config.dns,
                                    mtu: tun_config.mtu,
                                };

                                return Ok(tun_config_obj);
                            } else {
                                return Err(anyhow::anyhow!("No TUN config in handshake response"));
                            }
                        }
                        _ => {
                            return Err(anyhow::anyhow!("Invalid handshake response: unexpected message type"));
                        }
                    }
                }
                Some(Err(e)) => {
                    return Err(anyhow::anyhow!("Error during handshake: {}", e));
                }
                None => {
                    return Err(anyhow::anyhow!("Transport closed during handshake"));
                }
            }
        }
        _ = &mut timeout => {
            return Err(anyhow::anyhow!("Handshake timed out"));
        }
    }
}

pub async fn run_client_from_config(app_config: AppConfig) -> Result<()> {
    let mut config = app_config.client.clone();
    let rules_config = app_config.rules.clone();
    let transparent_proxy_config = app_config.transparent_proxy.clone();
    let server_addr = config.server_addr;

    match config.transport_type.to_lowercase().as_str() {
        "tcp" => {
            info!("Using TCP transport");

            let mut transport = TcpTransport::connect(&config.server_addr.to_string()).await?;
            let tun_config = handshake_async(&mut transport, server_addr, &mut config).await?;

            info!(
                "Creating TUN device with server config: {}",
                tun_config.name
            );
            let tun_device = create_tun_device(
                &tun_config.name,
                tun_config.address.parse()?,
                tun_config.netmask.parse()?,
                tun_config.destination.parse()?,
                &tun_config
                    .dns
                    .iter()
                    .map(|dns| dns.parse())
                    .collect::<Result<Vec<std::net::IpAddr>, _>>()?,
                tun_config.mtu as u16,
            )?;

            run_tcp_client(
                config,
                rules_config,
                transparent_proxy_config,
                tun_device,
                transport,
            )
            .await?;
        }
        "udp" => {
            info!("Using UDP transport");

            let mut transport = UdpTransport::bind("0.0.0.0:0").await?;
            let tun_config = handshake_async(&mut transport, server_addr, &mut config).await?;

            info!(
                "Creating TUN device with server config: {}",
                tun_config.name
            );
            let tun_device = create_tun_device(
                &tun_config.name,
                tun_config.address.parse()?,
                tun_config.netmask.parse()?,
                tun_config.destination.parse()?,
                &tun_config
                    .dns
                    .iter()
                    .map(|dns| dns.parse())
                    .collect::<Result<Vec<std::net::IpAddr>, _>>()?,
                tun_config.mtu as u16,
            )?;

            run_udp_client(
                config,
                rules_config,
                transparent_proxy_config,
                tun_device,
                transport,
            )
            .await?;
        }
        "ws" => {
            info!("Using WebSocket transport");

            let ws_url = format!("ws://{}", config.server_addr);
            let mut transport = WsTransport::connect(&ws_url, &config.ca_cert_path).await?;

            let handshake_addr = transport.server_addr();
            let tun_config = handshake_async(&mut transport, handshake_addr, &mut config).await?;

            info!(
                "Creating TUN device with server config: {}",
                tun_config.name
            );
            let tun_device = create_tun_device(
                &tun_config.name,
                tun_config.address.parse()?,
                tun_config.netmask.parse()?,
                tun_config.destination.parse()?,
                &tun_config
                    .dns
                    .iter()
                    .map(|dns| dns.parse())
                    .collect::<Result<Vec<std::net::IpAddr>, _>>()?,
                tun_config.mtu as u16,
            )?;

            run_ws_client(
                config,
                rules_config,
                transparent_proxy_config,
                tun_device,
                transport,
            )
            .await?;
        }
        "wss" => {
            info!("Using WebSocket(Secure) transport");

            let wss_url = format!("wss://{}", config.server_addr);
            let mut transport = WsTransport::connect(&wss_url, &config.ca_cert_path).await?;

            let handshake_addr = transport.server_addr();
            let tun_config = handshake_async(&mut transport, handshake_addr, &mut config).await?;

            info!(
                "Creating TUN device with server config: {}",
                tun_config.name
            );
            let tun_device = create_tun_device(
                &tun_config.name,
                tun_config.address.parse()?,
                tun_config.netmask.parse()?,
                tun_config.destination.parse()?,
                &tun_config
                    .dns
                    .iter()
                    .map(|dns| dns.parse())
                    .collect::<Result<Vec<std::net::IpAddr>, _>>()?,
                tun_config.mtu as u16,
            )?;

            run_ws_client(
                config,
                rules_config,
                transparent_proxy_config,
                tun_device,
                transport,
            )
            .await?;
        }
        _ => {
            error!("Unknown transport type: {}", config.transport_type);
            return Err(anyhow::anyhow!(
                "Unknown transport type: {}",
                config.transport_type
            ));
        }
    }

    Ok(())
}

async fn run_client_with_retry(config: AppConfig) -> Result<()> {
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(300);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!("Client connection attempt {}...", attempt);

        match run_client_from_config(config.clone()).await {
            Ok(()) => {
                info!("Client completed successfully");
                return Ok(());
            }
            Err(e) => {
                error!("Client attempt {} failed: {}", attempt, e);
                warn!("Retrying in {}s...", retry_delay.as_secs());
                sleep(retry_delay).await;
                retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
            }
        }
    }
}

pub async fn run_client() -> Result<()> {
    let config = AppConfig::load()?;
    info!("Client configuration: {:?}", config.client);
    run_client_with_retry(config).await
}

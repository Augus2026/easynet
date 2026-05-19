//! Transport module for TCP, UDP, and WebSocket communication

pub mod iroh;
pub mod tcp;
pub mod transport;
pub mod udp;
pub mod ws;

use crate::codec::{Data, KeepAlive, Message, MessageType};
use crate::common::tun_io_task;
use crate::config::ClientConfig;
use anyhow::Result;
use log::info;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

pub use iroh::{run_iroh_server, IrohTransport};
pub use tcp::{run_tcp_client, run_tcp_server, TcpTransport};
pub use transport::TransportTrait;
pub use udp::{run_udp_client, run_udp_server, UdpTransport};
pub use ws::{run_ws_client, run_ws_server, WsTransport};

pub(crate) async fn client_transport_io_task<T>(
    mut transport: T,
    server_addr: std::net::SocketAddr,
    mut tun_rx: mpsc::Receiver<Vec<u8>>,
    transport_tx: mpsc::Sender<Vec<u8>>,
) -> anyhow::Result<()>
where
    T: TransportTrait<Error = std::io::Error>,
{
    let mut keepalive_interval = interval(Duration::from_millis(3000));
    loop {
        tokio::select! {
            result = transport.next() => {
                match result {
                    Some(Ok((msg, _addr))) => {
                        match msg.msg {
                            Some(MessageType::Data(data)) => {
                                if let Err(e) = transport_tx.send(data.payload).await {
                                    return Err(anyhow::anyhow!("Failed to send to TUN: {}", e));
                                }
                            }
                            Some(MessageType::Keepalive(keepalive)) => {
                                let sent_timestamp = keepalive.timestamp;
                                let received_timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64;
                                let latency_ms = received_timestamp - (sent_timestamp as u64);
                                info!("Keepalive received from server, latency: {}ms", latency_ms);
                            }
                            Some(MessageType::Disconnect(disconnect)) => {
                                return Err(anyhow::anyhow!("Server disconnected: {}", disconnect.reason));
                            }
                            _ => {
                                info!("Transport: Unknown message type");
                            }
                        }
                    }
                    Some(Err(e)) => {
                        return Err(anyhow::anyhow!("Error receiving: {}", e));
                    }
                    None => {
                        return Err(anyhow::anyhow!("Connection closed"));
                    }
                }
            }

            result = tun_rx.recv() => {
                match result {
                    Some(data) => {
                        let message = Message::data(Data { payload: data });
                        if let Err(e) = transport.send(message, server_addr).await {
                            return Err(anyhow::anyhow!("Failed to send to server: {}", e));
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Channel disconnected"));
                    }
                }
            }

            _ = keepalive_interval.tick() => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64;
                let message = Message::keepalive(KeepAlive { timestamp });
                if let Err(e) = transport.send(message, server_addr).await {
                    return Err(anyhow::anyhow!("Keepalive failed: {}", e));
                }
            }
        }
    }
}

pub(crate) async fn run_connected_client<T>(
    config: ClientConfig,
    tun: tun2::AsyncDevice,
    transport: T,
) -> Result<()>
where
    T: TransportTrait<Error = std::io::Error> + Send + 'static,
{
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(4096);
    let (transport_tx, transport_rx) = mpsc::channel::<Vec<u8>>(4096);
    let server_addr = config.server_addr;

    let tun_handle = tokio::spawn(tun_io_task(tun, tun_tx, transport_rx));
    let transport_handle = tokio::spawn(client_transport_io_task(
        transport,
        server_addr,
        tun_rx,
        transport_tx,
    ));

    tokio::select! {
        result = tun_handle => {
            match result {
                Ok(Ok(())) => info!("TUN task completed successfully"),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("TUN task failed: {}", e));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("TUN task panicked: {}", e));
                }
            }
        }
        result = transport_handle => {
            match result {
                Ok(Ok(())) => info!("Transport task completed successfully"),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("Transport task failed: {}", e));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Transport task panicked: {}", e));
                }
            }
        }
    }
    Ok(())
}

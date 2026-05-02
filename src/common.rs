use easynet_rules::{DomainCache, PacketContext, RuleAction, RulesEngine};
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const TUN_MTU: usize = 1500;

async fn handle_packet_route(
    packet: Vec<u8>,
    rules_engine: &RulesEngine,
    domain_cache: &mut DomainCache,
    tun_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    direct_proxy_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
) -> anyhow::Result<()> {
    let Some(packet_ctx) = PacketContext::from_ip_packet(&packet) else {
        debug!("could not parse packet for rules, forwarding through tunnel");
        tun_tx
            .send(packet)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send to transport: {}", e))?;
        return Ok(());
    };

    let domains = domain_cache.lookup(packet_ctx.dst_ip);
    let packet_ctx = packet_ctx.with_domains(domains);
    let decision = rules_engine.match_packet(&packet_ctx);
    match decision.action {
        RuleAction::Direct => {
            direct_proxy_tx
                .send(packet)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send packet to direct proxy: {}", e))?;
            Ok(())
        }
        RuleAction::Proxy => {
            tun_tx
                .send(packet)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send to transport: {}", e))?;
            Ok(())
        }
        RuleAction::Reject => Ok(()),
    }
}

pub async fn tun_io_task(
    mut tun: tun2::AsyncDevice,
    tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut transport_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    rules_engine: RulesEngine,
    direct_proxy_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut direct_proxy_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut tun_buf = vec![0u8; TUN_MTU];
    let mut domain_cache = DomainCache::new();

    loop {
        tokio::select! {
            result = transport_rx.recv() => {
                match result {
                    Some(data) => {
                        domain_cache.observe_packet(&data);
                        if let Err(e) = tun.write_all(&data).await {
                            return Err(anyhow::anyhow!("Failed to write to TUN: {}", e));
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Channel disconnected"));
                    }
                }
            }

            result = direct_proxy_rx.recv() => {
                match result {
                    Some(data) => {
                        domain_cache.observe_packet(&data);
                        if let Err(e) = tun.write_all(&data).await {
                            return Err(anyhow::anyhow!("Failed to write direct packet to TUN: {}", e));
                        }
                    }
                    None => {
                        return Err(anyhow::anyhow!("Direct proxy channel disconnected"));
                    }
                }
            }

            result = tun.read(&mut tun_buf) => {
                match result {
                    Ok(n) => {
                        let data = tun_buf[..n].to_vec();
                        if let Err(e) = handle_packet_route(
                            data,
                            &rules_engine,
                            &mut domain_cache,
                            &tun_tx,
                            &direct_proxy_tx,
                        ).await {
                            return Err(e);
                        }
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Error reading from TUN: {}", e));
                    }
                }
            }
        }
    }
}

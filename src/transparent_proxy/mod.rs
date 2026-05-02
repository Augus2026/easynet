use anyhow::Result;
use log::{error, info, warn};
use smoltcp::{
    iface::Config,
    phy::{DeviceCapabilities, Medium},
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, IpVersion},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_smoltcp::device::ChannelCapture;
use tokio_smoltcp::{BufferSize, Net, NetConfig};

mod filter;
mod icmp_proxy;
mod tcp_proxy;
mod udp_proxy;

#[derive(Debug, Default)]
pub(crate) struct UpstreamServer {
    ip: Option<IpAddr>,
}

#[derive(Debug, Default)]
pub(crate) struct ProxyStats {
    pub(crate) active_tcp: AtomicUsize,
    pub(crate) active_udp: AtomicUsize,
    pub(crate) active_icmp: AtomicUsize,
}

impl UpstreamServer {
    fn new(ip: Option<IpAddr>) -> Self {
        Self { ip }
    }

    pub(crate) fn translate_socket(&self, addr: SocketAddr) -> SocketAddr {
        match self.ip {
            Some(ip) => SocketAddr::new(ip, addr.port()),
            None => addr,
        }
    }

    pub(crate) fn translate_ipv4(&self, addr: Ipv4Addr) -> Result<Ipv4Addr, IpAddr> {
        match self.ip {
            Some(IpAddr::V4(ip)) => Ok(ip),
            Some(IpAddr::V6(ip)) => Err(IpAddr::V6(ip)),
            None => Ok(addr),
        }
    }
}

pub fn start_transparent_proxy(
    interface: String,
    upstream_server: Option<IpAddr>,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    smoltcp_addr: IpAddr,
    smoltcp_netmask: IpAddr,
    smoltcp_gateway: IpAddr,
) -> JoinHandle<()> {
    let net = Arc::new(create_net_with_channels(
        inbound_rx,
        outbound_tx,
        smoltcp_addr,
        smoltcp_netmask,
        smoltcp_gateway,
    ));
    net.set_any_ip(true);

    tokio::spawn(async move {
        if let Err(err) = run_transparent_proxy(net, interface, upstream_server).await {
            error!("transparent_proxy stopped: {}", err);
        }
    })
}

async fn run_transparent_proxy(
    net: Arc<Net>,
    interface: String,
    upstream_server: Option<IpAddr>,
) -> Result<()> {
    let mut tcp_listener = net.tcp_bind_all().await?;
    let udp_socket = Arc::new(net.udp_bind_all().await?);
    let icmp_socket = Arc::new(net.raw_socket(IpVersion::Ipv4, IpProtocol::Icmp).await?);
    let filters = Arc::new(filter::IpFilters::with_non_broadcast());
    let upstream = Arc::new(UpstreamServer::new(upstream_server));
    let stats = Arc::new(ProxyStats::default());
    let stats_reporter = tokio::spawn(report_proxy_stats(stats.clone()));
    let tcp_interface = interface.clone();
    let udp_interface = interface.clone();
    let icmp_interface = interface.clone();

    if let Some(ip) = upstream_server {
        info!("transparent proxy upstream={}", ip);
    }

    tokio::select! {
        result = tcp_proxy::handle_inbound_stream(&mut tcp_listener, tcp_interface, filters.clone(), upstream.clone(), stats.clone()) => {
            if let Err(err) = result {
                error!("tcp proxy failed: err={:?}", err);
            }
        }
        result = udp_proxy::handle_inbound_datagram(udp_socket, udp_interface, filters.clone(), upstream.clone(), stats.clone()) => {
            if let Err(err) = result {
                error!("udp proxy failed: err={:?}", err);
            }
        }
        result = icmp_proxy::handle_inbound_icmp(icmp_socket, icmp_interface, filters.clone(), upstream.clone(), stats.clone()) => {
            if let Err(err) = result {
                error!("icmp proxy failed: err={:?}", err);
            }
        }
    }

    stats_reporter.abort();
    warn!("transparent proxy shutting down");
    Ok(())
}

async fn report_proxy_stats(stats: Arc<ProxyStats>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        info!(
            "active_sessions tcp={} udp={} icmp={}",
            stats.active_tcp.load(Ordering::Relaxed),
            stats.active_udp.load(Ordering::Relaxed),
            stats.active_icmp.load(Ordering::Relaxed),
        );
    }
}

fn create_net_with_channels(
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    smoltcp_addr: IpAddr,
    smoltcp_netmask: IpAddr,
    smoltcp_gateway: IpAddr,
) -> Net {
    let mut caps = DeviceCapabilities::default();
    caps.max_transmission_unit = 1500;
    caps.medium = Medium::Ip;
    caps.max_burst_size = Some(64);

    let capture = ChannelCapture::new(
        move |tx| {
            while let Some(pkt) = inbound_rx.blocking_recv() {
                if tx.blocking_send(Ok(pkt)).is_err() {
                    break;
                }
            }
        },
        move |mut rx| {
            while let Some(pkt) = rx.blocking_recv() {
                if outbound_tx.blocking_send(pkt).is_err() {
                    break;
                }
            }
        },
        caps,
    );

    let interface_config = Config::new(HardwareAddress::Ip);
    let prefix_len = match smoltcp_netmask {
        IpAddr::V4(mask) => u32::from(mask).count_ones() as u8,
        IpAddr::V6(mask) => u128::from(mask).count_ones() as u8,
    };
    let mut net_config = NetConfig::new(
        interface_config,
        IpCidr::new(IpAddress::from(smoltcp_addr), prefix_len),
        vec![IpAddress::from(smoltcp_gateway)],
    );
    net_config.buffer_size = BufferSize {
        tcp_rx_size: 4 * 1024 * 1024,
        tcp_tx_size: 4 * 1024 * 1024,
        udp_rx_size: 128 * 1024,
        udp_tx_size: 128 * 1024,
        udp_rx_meta_size: 128,
        udp_tx_meta_size: 128,
        raw_rx_size: 128 * 1024,
        raw_tx_size: 128 * 1024,
        raw_rx_meta_size: 128,
        raw_tx_meta_size: 128,
    };

    Net::new(capture, net_config)
}

use log::info;
use tun2::{create_as_async, AsyncDevice, Configuration, Layer};

pub fn create_tun_device(
    name: &str,
    address: std::net::IpAddr,
    netmask: std::net::IpAddr,
    destination: std::net::IpAddr,
    dns_servers: &[std::net::IpAddr],
    mtu: u16,
) -> anyhow::Result<AsyncDevice> {
    let mut config = Configuration::default();
    config
        .tun_name(name)
        .layer(Layer::L3)
        .mtu(mtu)
        .address(address)
        .netmask(netmask)
        .destination(destination)
        .up();

    #[cfg(windows)]
    if !dns_servers.is_empty() {
        config.platform_config(|platform| platform.dns_servers(dns_servers));
    }

    let device = create_as_async(&config)?;
    info!(
        "TUN device created: name={} address={} netmask={} destination={} dns_servers={:?} mtu={}",
        name,
        address,
        netmask,
        destination,
        dns_servers,
        mtu
    );
    Ok(device)
}

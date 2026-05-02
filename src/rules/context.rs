use super::rule::Protocol;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct PacketContext {
    pub src_ip: Ipv4Addr,

    pub dst_ip: Ipv4Addr,

    pub src_port: Option<u16>,

    pub dst_port: Option<u16>,

    pub protocol: Protocol,

    pub domains: Vec<String>,
}

impl PacketContext {
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            domains: Vec::new(),
        }
    }

    pub fn with_domains(mut self, domains: Vec<String>) -> Self {
        self.domains = domains;
        self
    }

    pub fn from_ip_packet(data: &[u8]) -> Option<Self> {
        let sliced = etherparse::SlicedPacket::from_ip(data).ok()?;

        let (src_ip, dst_ip) = match &sliced.net {
            Some(etherparse::InternetSlice::Ipv4(ipv4_slice)) => {
                let header = ipv4_slice.header();
                let src = Ipv4Addr::from(header.source());
                let dst = Ipv4Addr::from(header.destination());
                (src, dst)
            }
            _ => return None,
        };

        let mut src_port = None;
        let mut dst_port = None;
        let mut protocol = Protocol::Other(0);

        if let Some(transport) = &sliced.transport {
            match transport {
                etherparse::TransportSlice::Tcp(tcp) => {
                    src_port = Some(tcp.source_port());
                    dst_port = Some(tcp.destination_port());
                    protocol = Protocol::Tcp;
                }
                etherparse::TransportSlice::Udp(udp) => {
                    src_port = Some(udp.source_port());
                    dst_port = Some(udp.destination_port());
                    protocol = Protocol::Udp;
                }
                etherparse::TransportSlice::Icmpv4(_icmp) => {
                    protocol = Protocol::Icmp;
                    src_port = None;
                    dst_port = None;
                }
                etherparse::TransportSlice::Icmpv6(_) => {
                    return None;
                }
            }
        }

        Some(Self::new(src_ip, dst_ip, src_port, dst_port, protocol))
    }
}

impl std::fmt::Display for PacketContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip,
            self.src_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.dst_ip,
            self.dst_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.protocol
        )
    }
}

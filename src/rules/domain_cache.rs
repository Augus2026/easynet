use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct DomainEntry {
    domain: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct DomainCache {
    entries: HashMap<Ipv4Addr, Vec<DomainEntry>>,
}

impl DomainCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, ip: Ipv4Addr, domain: impl AsRef<str>, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }

        let Some(domain) = normalize_domain(domain.as_ref()) else {
            return;
        };

        let expires_at = Instant::now() + ttl;
        let entries = self.entries.entry(ip).or_default();

        if let Some(entry) = entries.iter_mut().find(|entry| entry.domain == domain) {
            entry.expires_at = expires_at;
            return;
        }

        entries.push(DomainEntry { domain, expires_at });
    }

    pub fn lookup(&mut self, ip: Ipv4Addr) -> Vec<String> {
        let now = Instant::now();
        let Some(entries) = self.entries.get_mut(&ip) else {
            return Vec::new();
        };

        entries.retain(|entry| entry.expires_at > now);
        let domains = entries
            .iter()
            .map(|entry| entry.domain.clone())
            .collect::<Vec<_>>();

        if entries.is_empty() {
            self.entries.remove(&ip);
        }

        domains
    }

    pub fn observe_packet(&mut self, packet: &[u8]) {
        let Some(payload) = dns_response_payload(packet) else {
            return;
        };

        let Ok(message) = Message::from_vec(payload) else {
            return;
        };

        if message.metadata.message_type != MessageType::Response {
            return;
        }

        for answer in &message.answers {
            let RData::A(addr) = &answer.data else {
                continue;
            };

            self.insert(
                addr.0,
                answer.name.to_utf8(),
                Duration::from_secs(answer.ttl as u64),
            );
        }
    }
}

fn dns_response_payload(packet: &[u8]) -> Option<&[u8]> {
    let sliced = etherparse::SlicedPacket::from_ip(packet).ok()?;
    let transport = sliced.transport.as_ref()?;
    let udp = match transport {
        etherparse::TransportSlice::Udp(udp) => udp,
        _ => return None,
    };

    if udp.source_port() != 53 {
        return None;
    }

    Some(udp.payload())
}

fn normalize_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::{rdata::A, Name, Record};
    use std::str::FromStr;
    use std::thread;

    #[test]
    fn caches_a_records_from_dns_response() {
        let packet = dns_response_packet("Example.COM.", Ipv4Addr::new(1, 2, 3, 4), 60);
        let mut cache = DomainCache::new();

        cache.observe_packet(&packet);

        assert_eq!(cache.lookup(Ipv4Addr::new(1, 2, 3, 4)), vec!["example.com"]);
    }

    #[test]
    fn drops_expired_entries() {
        let mut cache = DomainCache::new();
        cache.insert(
            Ipv4Addr::new(1, 2, 3, 4),
            "example.com",
            Duration::from_millis(1),
        );

        thread::sleep(Duration::from_millis(5));

        assert!(cache.lookup(Ipv4Addr::new(1, 2, 3, 4)).is_empty());
    }

    fn dns_response_packet(domain: &str, addr: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let name = Name::from_str(domain).unwrap();
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_answer(Record::from_rdata(name, ttl, RData::A(A(addr))));
        udp_packet(message.to_vec().unwrap())
    }

    fn udp_packet(payload: Vec<u8>) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = Vec::with_capacity(total_len);

        packet.push(0x45);
        packet.push(0);
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.push(64);
        packet.push(17);
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
        packet.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());

        packet.extend_from_slice(&53u16.to_be_bytes());
        packet.extend_from_slice(&53000u16.to_be_bytes());
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&payload);
        packet
    }
}

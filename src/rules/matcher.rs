use super::context::PacketContext;
use super::geoip::GeoIpMatcher;
use super::rule::{Protocol, Rule};
use crate::config::parse_port_range;
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;

pub struct Matcher;

impl Matcher {
    pub fn matches(rule: &Rule, packet: &PacketContext, geoip: &GeoIpMatcher) -> bool {
        if let Some(ref src_ip) = rule.src_ip_cidr {
            if !Self::matches_ip(src_ip, packet.src_ip) {
                return false;
            }
        }

        if let Some(ref dst_ip) = rule.dst_ip_cidr {
            if !Self::matches_ip(dst_ip, packet.dst_ip) {
                return false;
            }
        }

        if let Some(ref src_port) = rule.src_port {
            if !Self::matches_port(src_port, packet.src_port) {
                return false;
            }
        }

        if let Some(ref dst_port) = rule.dst_port {
            if !Self::matches_port(dst_port, packet.dst_port) {
                return false;
            }
        }

        if let Some(ref proto) = rule.proto {
            if !Self::matches_protocol(proto, packet.protocol) {
                return false;
            }
        }

        if let Some(ref domain) = rule.domain {
            if !Self::matches_domain(domain, &packet.domains) {
                return false;
            }
        }

        if let Some(ref suffix) = rule.domain_suffix {
            if !Self::matches_domain_suffix(suffix, &packet.domains) {
                return false;
            }
        }

        if let Some(ref keyword) = rule.domain_keyword {
            if !Self::matches_domain_keyword(keyword, &packet.domains) {
                return false;
            }
        }

        if let Some(ref geoip_code) = rule.geoip {
            if !geoip.matches(packet.dst_ip, geoip_code) {
                return false;
            }
        }

        true
    }

    pub fn matches_ip(cidr: &str, ip: Ipv4Addr) -> bool {
        match cidr.parse::<Ipv4Network>() {
            Ok(network) => network.contains(ip),
            Err(_) => cidr.parse::<Ipv4Addr>() == Ok(ip),
        }
    }

    pub fn matches_port(port_spec: &str, packet_port: Option<u16>) -> bool {
        let Some(port) = packet_port else {
            return false;
        };

        match parse_port_range(port_spec) {
            Ok((start, end)) => (start..=end).contains(&port),
            Err(_) => false,
        }
    }

    pub fn matches_protocol(proto_str: &str, packet_proto: Protocol) -> bool {
        match Protocol::from_str(proto_str) {
            Some(proto) => proto == packet_proto,
            None => false,
        }
    }

    pub fn matches_domain(domain: &str, packet_domains: &[String]) -> bool {
        packet_domains.iter().any(|value| value == domain)
    }

    pub fn matches_domain_suffix(suffix: &str, packet_domains: &[String]) -> bool {
        packet_domains
            .iter()
            .any(|value| value == suffix || value.ends_with(&format!(".{suffix}")))
    }

    pub fn matches_domain_keyword(keyword: &str, packet_domains: &[String]) -> bool {
        packet_domains.iter().any(|value| value.contains(keyword))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_domain_only() {
        let domains = vec!["example.com".to_string(), "www.example.org".to_string()];

        assert!(Matcher::matches_domain("example.com", &domains));
        assert!(!Matcher::matches_domain("www.example.com", &domains));
    }

    #[test]
    fn matches_domain_suffix_with_root_and_subdomain() {
        let domains = vec!["example.com".to_string(), "www.example.com".to_string()];

        assert!(Matcher::matches_domain_suffix("example.com", &domains));
        assert!(Matcher::matches_domain_suffix("www.example.com", &domains));
        assert!(!Matcher::matches_domain_suffix("ample.com", &domains));
    }

    #[test]
    fn matches_domain_keyword() {
        let domains = vec!["www.youtube.com".to_string()];

        assert!(Matcher::matches_domain_keyword("youtube", &domains));
        assert!(!Matcher::matches_domain_keyword("google", &domains));
    }

    #[test]
    fn domain_rules_do_not_match_without_domains() {
        let domains = Vec::new();

        assert!(!Matcher::matches_domain("example.com", &domains));
        assert!(!Matcher::matches_domain_suffix("example.com", &domains));
        assert!(!Matcher::matches_domain_keyword("example", &domains));
    }
}

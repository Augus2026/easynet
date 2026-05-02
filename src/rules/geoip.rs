use maxminddb::{geoip2, Reader};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug)]
pub struct GeoIpMatcher {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpMatcher {
    pub fn load(config_path: Option<&str>) -> Self {
        let reader = config_path
            .filter(|path| !path.trim().is_empty())
            .and_then(|path| Reader::open_readfile(path).ok());

        Self { reader }
    }

    pub fn without_database() -> Self {
        Self { reader: None }
    }

    pub fn matches(&self, ip: Ipv4Addr, code: &str) -> bool {
        if code.eq_ignore_ascii_case("PRIVATE") {
            return is_private_ip(ip);
        }

        let Some(reader) = &self.reader else {
            return false;
        };

        let Ok(result) = reader.lookup(IpAddr::V4(ip)) else {
            return false;
        };
        let Ok(Some(country)) = result.decode::<geoip2::Country>() else {
            return false;
        };

        let code = code.to_ascii_uppercase();
        country.country.iso_code == Some(code.as_str())
            || country.registered_country.iso_code == Some(code.as_str())
            || country.represented_country.iso_code == Some(code.as_str())
    }
}

fn is_private_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_private_ranges_without_database() {
        let matcher = GeoIpMatcher::without_database();

        assert!(matcher.matches(Ipv4Addr::new(10, 0, 0, 1), "PRIVATE"));
        assert!(matcher.matches(Ipv4Addr::new(172, 16, 0, 1), "PRIVATE"));
        assert!(matcher.matches(Ipv4Addr::new(192, 168, 0, 1), "PRIVATE"));
        assert!(matcher.matches(Ipv4Addr::new(127, 0, 0, 1), "PRIVATE"));
        assert!(matcher.matches(Ipv4Addr::new(169, 254, 1, 1), "PRIVATE"));
        assert!(matcher.matches(Ipv4Addr::new(100, 64, 0, 1), "PRIVATE"));
    }

    #[test]
    fn does_not_match_public_ip_as_private() {
        let matcher = GeoIpMatcher::without_database();

        assert!(!matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "PRIVATE"));
    }

    #[test]
    fn country_code_without_database_does_not_match() {
        let matcher = GeoIpMatcher::without_database();

        assert!(!matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "US"));
    }
}

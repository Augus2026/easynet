use log::warn;
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
            .and_then(|path| {
                Reader::open_readfile(path)
                    .map_err(|e| warn!("failed to load GeoIP database from {}: {}", path, e))
                    .ok()
            });
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
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || is_cgnat(ip)
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB_PATH: &str = "rules/geoip/GeoLite2-Country.mmdb";

    fn load_db() -> GeoIpMatcher {
        GeoIpMatcher::load(Some(DB_PATH))
    }

    // --- is_private_ip tests ---

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(is_private_ip(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_private_ip(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(is_private_ip(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(100, 127, 255, 255)));

        assert!(!is_private_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ip(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_private_ip(Ipv4Addr::new(100, 128, 0, 0)));
    }

    // --- PRIVATE pseudo-code tests (no database needed) ---

    #[test]
    fn test_matches_private_without_database() {
        let matcher = GeoIpMatcher::without_database();

        assert!(matcher.matches(Ipv4Addr::new(10, 0, 0, 1), "PRIVATE"));
        assert!(matcher.matches(Ipv4Addr::new(192, 168, 1, 1), "private"));
        assert!(matcher.matches(Ipv4Addr::new(127, 0, 0, 1), "Private"));
        assert!(!matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "PRIVATE"));
    }

    #[test]
    fn test_matches_private_with_database() {
        let matcher = load_db();
        // PRIVATE should still work and not touch the database
        assert!(matcher.matches(Ipv4Addr::new(10, 0, 0, 1), "PRIVATE"));
        assert!(!matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "PRIVATE"));
    }

    // --- Database-based country code tests ---

    #[test]
    fn test_database_country_code_matches_us() {
        let matcher = load_db();
        // 8.8.8.8 is Google DNS, located in the US
        assert!(matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "US"));
    }

    #[test]
    fn test_database_country_code_matches_cn() {
        let matcher = load_db();
        // 223.5.5.5 is Alibaba DNS, located in China
        assert!(matcher.matches(Ipv4Addr::new(223, 5, 5, 5), "CN"));
    }

    #[test]
    fn test_database_country_code_does_not_match_wrong_country() {
        let matcher = load_db();
        // Google DNS is not in China
        assert!(!matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "CN"));
        // Google DNS is not in Germany
        assert!(!matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "DE"));
    }

    #[test]
    fn test_database_country_code_case_insensitive() {
        let matcher = load_db();
        assert!(matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "us"));
        assert!(matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "Us"));
        assert!(matcher.matches(Ipv4Addr::new(223, 5, 5, 5), "cn"));
    }

    #[test]
    fn test_database_unknown_code_returns_false() {
        let matcher = load_db();
        assert!(!matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "XX"));
    }

    #[test]
    fn test_without_database_country_code_always_false() {
        let matcher = GeoIpMatcher::without_database();

        assert!(!matcher.matches(Ipv4Addr::new(8, 8, 8, 8), "US"));
        assert!(!matcher.matches(Ipv4Addr::new(1, 1, 1, 1), "CN"));
        assert!(!matcher.matches(Ipv4Addr::new(223, 5, 5, 5), "CN"));
    }
}

use log::{debug, info};
use std::path::Path;

use super::action::RuleAction;
use super::config::{ConfigError, RulesConfig};
use super::context::PacketContext;
use super::geoip::GeoIpMatcher;
use super::matcher::Matcher;
use super::rule::Rule;

pub struct RulesEngine {
    rules: Vec<Rule>,
    geoip: GeoIpMatcher,
}

impl RulesEngine {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let config = RulesConfig::from_file(path)?;
        Self::from_config(config)
    }

    pub fn from_config(config: RulesConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let rules = config.rules;

        debug!("rules engine initialized with {} rules", rules.len());

        Ok(Self {
            rules,
            geoip: GeoIpMatcher::load(config.geoip_path.as_deref()),
        })
    }

    pub fn match_packet(&self, packet: &PacketContext) -> RuleAction {
        for (index, rule) in self.rules.iter().enumerate() {
            if Matcher::matches(rule, packet, &self.geoip) {
                debug!("packet {} matched rule #{} ({})", packet, index + 1, rule);

                if rule.action == RuleAction::Reject {
                    info!(
                        "[REJECT] src={} dst={} rule=#{} ({})",
                        packet.src_ip,
                        packet.dst_ip,
                        index + 1,
                        rule
                    );
                }

                return rule.action;
            }
        }
        RuleAction::Direct
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    #[cfg(test)]
    fn with_geoip(mut self, geoip: GeoIpMatcher) -> Self {
        self.geoip = geoip;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::super::rule::Protocol;
    use super::*;

    fn create_test_engine() -> RulesEngine {
        RulesEngine::from_config(
            RulesConfig::from_yaml(
                r#"
  - DST-PORT,22,reject
  - DST-IP-CIDR,10.0.0.0/8,proxy
  - DST-PORT,443,proxy
  - MATCH,direct
"#,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_matches_first_matching_rule() {
        let engine = create_test_engine();
        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.1.5".parse().unwrap(),
            Some(12345),
            Some(22),
            Protocol::Tcp,
        );

        let action = engine.match_packet(&packet);
        assert_eq!(action, RuleAction::Reject);
    }

    #[test]
    fn test_uses_match_rule_as_catch_all() {
        let engine = create_test_engine();
        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            Some(12345),
            Some(80),
            Protocol::Tcp,
        );

        let action = engine.match_packet(&packet);
        assert_eq!(action, RuleAction::Direct);
    }

    #[test]
    fn test_matches_port_rule() {
        let engine = create_test_engine();
        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            Some(12345),
            Some(443),
            Protocol::Tcp,
        );

        let action = engine.match_packet(&packet);
        assert_eq!(action, RuleAction::Proxy);
    }

    #[test]
    fn test_matches_domain_rule() {
        let engine = RulesEngine::from_config(
            RulesConfig::from_yaml(
                r#"
  - DOMAIN-SUFFIX,example.com,proxy
  - MATCH,direct
"#,
            )
            .unwrap(),
        )
        .unwrap();
        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
            Some(12345),
            Some(443),
            Protocol::Tcp,
        )
        .with_domains(vec!["www.example.com".to_string()]);

        let action = engine.match_packet(&packet);
        assert_eq!(action, RuleAction::Proxy);
    }

    #[test]
    fn test_matches_geoip_private_rule() {
        let engine = RulesEngine::from_config(
            RulesConfig::from_yaml(
                r#"
  - GEOIP,PRIVATE,direct
  - MATCH,proxy
"#,
            )
            .unwrap(),
        )
        .unwrap()
        .with_geoip(GeoIpMatcher::without_database());
        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.0.8".parse().unwrap(),
            Some(12345),
            Some(443),
            Protocol::Tcp,
        );

        let action = engine.match_packet(&packet);
        assert_eq!(action, RuleAction::Direct);
    }

    #[test]
    fn test_geoip_country_without_database_falls_through() {
        let engine = RulesEngine::from_config(
            RulesConfig::from_yaml(
                r#"
  - GEOIP,CN,direct
  - MATCH,proxy
"#,
            )
            .unwrap(),
        )
        .unwrap()
        .with_geoip(GeoIpMatcher::without_database());
        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            Some(12345),
            Some(443),
            Protocol::Tcp,
        );

        let action = engine.match_packet(&packet);
        assert_eq!(action, RuleAction::Proxy);
    }
}

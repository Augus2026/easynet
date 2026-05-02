use log::{debug, info};
use std::path::Path;

use super::action::RuleAction;
use super::config::{ConfigError, RulesConfig};
use super::context::PacketContext;
use super::decision::RuleDecision;
use super::matcher::Matcher;
use super::rule::Rule;

pub struct RulesEngine {
    default_action: RuleAction,
    rules: Vec<Rule>,
}

impl RulesEngine {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let config = RulesConfig::from_file(path)?;
        Self::from_config(config)
    }

    pub fn from_config(config: RulesConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let config = config.assign_ids();
        let mut rules = config.rules;
        rules.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));

        debug!("rules engine initialized with {} rules", rules.len());

        Ok(Self {
            default_action: config.default_action,
            rules,
        })
    }

    pub fn match_packet(&self, packet: &PacketContext) -> RuleDecision {
        for rule in &self.rules {
            if Matcher::matches(rule, packet) {
                debug!(
                    "packet {} matched rule \"{}\" (id={}, priority={})",
                    packet, rule.name, rule.id, rule.priority
                );

                if rule.action == RuleAction::Reject {
                    info!(
                        "[REJECT] src={} dst={} rule=\"{}\" rule_id={}",
                        packet.src_ip, packet.dst_ip, rule.name, rule.id
                    );
                }

                return RuleDecision::from_rule(rule.id, rule.name.clone(), rule.action);
            }
        }

        debug!(
            "packet {} matched no rule, using default action {}",
            packet, self.default_action
        );

        if self.default_action == RuleAction::Reject {
            info!(
                "[REJECT] src={} dst={} rule=\"default\"",
                packet.src_ip, packet.dst_ip
            );
        }

        RuleDecision::default_action(self.default_action)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn default_action(&self) -> RuleAction {
        self.default_action
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
  - DST_PORT,22,reject
  - DST_ADDR,10.0.0.0/8,proxy
  - DST_PORT,443,proxy
  - MATCH,direct
"#,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_matches_highest_priority_rule() {
        let engine = create_test_engine();
        let packet = PacketContext::new(
            "192.168.1.1".parse().unwrap(),
            "10.0.1.5".parse().unwrap(),
            Some(12345),
            Some(22),
            Protocol::Tcp,
        );

        let decision = engine.match_packet(&packet);
        assert_eq!(decision.action, RuleAction::Reject);
        assert_eq!(decision.rule_id, Some(1));
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

        let decision = engine.match_packet(&packet);
        assert_eq!(decision.action, RuleAction::Direct);
        assert!(!decision.is_default);
        assert_eq!(decision.rule_name.as_deref(), Some("rule-4-match"));
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

        let decision = engine.match_packet(&packet);
        assert_eq!(decision.action, RuleAction::Proxy);
        assert_eq!(decision.rule_name.as_deref(), Some("rule-3-dst-port"));
    }
}

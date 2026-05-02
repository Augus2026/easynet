use super::action::RuleAction;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RuleDecision {
    pub action: RuleAction,

    pub rule_id: Option<u32>,

    pub rule_name: Option<String>,

    pub timestamp: Instant,

    pub is_default: bool,
}

impl RuleDecision {
    pub fn default_action(action: RuleAction) -> Self {
        Self {
            action,
            rule_id: None,
            rule_name: None,
            timestamp: Instant::now(),
            is_default: true,
        }
    }

    pub fn from_rule(rule_id: u32, rule_name: String, action: RuleAction) -> Self {
        Self {
            action,
            rule_id: Some(rule_id),
            rule_name: Some(rule_name),
            timestamp: Instant::now(),
            is_default: false,
        }
    }

    pub fn is_reject(&self) -> bool {
        self.action == RuleAction::Reject
    }

    pub fn rule_id(&self) -> Option<u32> {
        self.rule_id
    }
}

impl std::fmt::Display for RuleDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_default {
            write!(f, "default -> {}", self.action)
        } else {
            write!(
                f,
                "rule '{}' (id={}) -> {}",
                self.rule_name.as_deref().unwrap_or("unknown"),
                self.rule_id.unwrap_or(0),
                self.action
            )
        }
    }
}

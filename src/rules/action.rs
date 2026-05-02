use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    #[serde(alias = "direct", alias = "DIRECT")]
    Direct,
    #[serde(alias = "proxy", alias = "PROXY")]
    Proxy,
    #[serde(alias = "reject", alias = "REJECT")]
    Reject,
}

impl Hash for RuleAction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl Default for RuleAction {
    fn default() -> Self {
        RuleAction::Direct
    }
}

impl std::fmt::Display for RuleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleAction::Direct => write!(f, "Direct"),
            RuleAction::Proxy => write!(f, "Proxy"),
            RuleAction::Reject => write!(f, "Reject"),
        }
    }
}

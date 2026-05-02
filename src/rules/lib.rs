#[path = "../config.rs"]
pub mod config;

pub mod action;
pub mod context;
pub mod decision;
pub mod engine;
pub mod matcher;
pub mod rule;

pub use action::RuleAction;
pub use config::{ConfigError, RulesConfig};
pub use context::PacketContext;
pub use decision::RuleDecision;
pub use engine::RulesEngine;
pub use rule::{Protocol, Rule};

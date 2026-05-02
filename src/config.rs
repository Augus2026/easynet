use crate::action::RuleAction;
use crate::rule::{Protocol, Rule};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

pub const APP_CONFIG_PATH: &str = "config/easynet.yaml";
pub const CLIENT_STATE_PATH: &str = "config/client_state.yaml";

#[derive(Debug)]
pub enum ConfigError {
    IoError(std::io::Error),
    ParseError(serde_yaml::Error),
    ValidationError(String),
    InvalidCidr(String),
    InvalidPortRange(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError(e) => write!(f, "failed to read file: {}", e),
            ConfigError::ParseError(e) => write!(f, "failed to parse YAML: {}", e),
            ConfigError::ValidationError(msg) => write!(f, "rule validation failed: {}", msg),
            ConfigError::InvalidCidr(cidr) => write!(f, "invalid CIDR notation: {}", cidr),
            ConfigError::InvalidPortRange(range) => write!(f, "invalid port range: {}", range),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::IoError(e)
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(e: serde_yaml::Error) -> Self {
        ConfigError::ParseError(e)
    }
}

#[derive(Debug, Clone)]
pub struct RulesConfig {
    pub default_action: RuleAction,
    pub rules: Vec<Rule>,
    pub geoip_path: Option<String>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            default_action: RuleAction::Reject,
            rules: Vec::new(),
            geoip_path: None,
        }
    }
}

impl RulesConfig {
    pub fn from_yaml(yaml_str: &str) -> Result<Self, ConfigError> {
        let config: RulesConfig = serde_yaml::from_str(yaml_str)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.has_conditions() {
                return Err(ConfigError::ValidationError(format!(
                    "rule '{}' (index {}) has no match conditions",
                    rule.name, index
                )));
            }

            if let Some(ref cidr) = rule.src_ip_cidr {
                if let Err(e) = cidr.parse::<ipnetwork::Ipv4Network>() {
                    return Err(ConfigError::InvalidCidr(format!(
                        "rule '{}' has an invalid SRC-IP-CIDR: {} ({})",
                        rule.name, cidr, e
                    )));
                }
            }

            if let Some(ref cidr) = rule.dst_ip_cidr {
                if let Err(e) = cidr.parse::<ipnetwork::Ipv4Network>() {
                    return Err(ConfigError::InvalidCidr(format!(
                        "rule '{}' has an invalid DST-IP-CIDR: {} ({})",
                        rule.name, cidr, e
                    )));
                }
            }

            if let Some(ref port) = rule.src_port {
                if let Err(e) = parse_port_range(port) {
                    return Err(ConfigError::InvalidPortRange(format!(
                        "rule '{}' has an invalid SRC-PORT: {} ({})",
                        rule.name, port, e
                    )));
                }
            }

            if let Some(ref port) = rule.dst_port {
                if let Err(e) = parse_port_range(port) {
                    return Err(ConfigError::InvalidPortRange(format!(
                        "rule '{}' has an invalid DST-PORT: {} ({})",
                        rule.name, port, e
                    )));
                }
            }

            if let Some(ref proto) = rule.proto {
                if Protocol::from_str(proto).is_none() {
                    return Err(ConfigError::ValidationError(format!(
                        "rule '{}' has an invalid PROTO: {} (must be tcp/udp/icmp)",
                        rule.name, proto
                    )));
                }
            }

            for (field, value) in [
                ("DOMAIN", rule.domain.as_ref()),
                ("DOMAIN-SUFFIX", rule.domain_suffix.as_ref()),
                ("DOMAIN-KEYWORD", rule.domain_keyword.as_ref()),
            ] {
                if let Some(value) = value {
                    validate_domain_rule_value(&rule.name, field, value)?;
                }
            }

            if let Some(value) = &rule.geoip {
                validate_geoip_rule_value(&rule.name, value)?;
            }
        }

        Ok(())
    }

    pub fn assign_ids(mut self) -> Self {
        let mut next_id = 1u32;
        for rule in &mut self.rules {
            if rule.id == 0 {
                rule.id = next_id;
            }
            next_id += 1;
        }
        self
    }
}

fn validate_geoip_rule_value(rule_name: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::ValidationError(format!(
            "rule '{}' has an empty GEOIP value",
            rule_name
        )));
    }
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '/' | ','))
    {
        return Err(ConfigError::ValidationError(format!(
            "rule '{}' has an invalid GEOIP value: {}",
            rule_name, value
        )));
    }
    Ok(())
}

fn validate_domain_rule_value(
    rule_name: &str,
    field: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::ValidationError(format!(
            "rule '{}' has an empty {} value",
            rule_name, field
        )));
    }
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '/' | ','))
    {
        return Err(ConfigError::ValidationError(format!(
            "rule '{}' has an invalid {} value: {}",
            rule_name, field, value
        )));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for RulesConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RulesConfigVisitor;

        impl<'de> de::Visitor<'de> for RulesConfigVisitor {
            type Value = RulesConfig;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a compact rules list")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut rules = Vec::new();
                while let Some(raw_rule) = seq.next_element::<String>()? {
                    let index = rules.len();
                    let rule = Rule::parse_compact(index, &raw_rule).map_err(de::Error::custom)?;
                    rules.push(rule);
                }

                Ok(RulesConfig {
                    default_action: RuleAction::Reject,
                    rules,
                    geoip_path: None,
                })
            }
        }

        deserializer.deserialize_any(RulesConfigVisitor)
    }
}

impl Serialize for RulesConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let rules: Vec<String> = self.rules.iter().map(ToString::to_string).collect();
        rules.serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetConfig {
    #[serde(default)]
    pub geoip_path: Option<String>,
}

impl Default for RuleSetConfig {
    fn default() -> Self {
        Self { geoip_path: None }
    }
}

pub fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err("invalid range format".to_string());
        }
        let start: u16 = parts[0]
            .parse()
            .map_err(|_| "invalid start port".to_string())?;
        let end: u16 = parts[1]
            .parse()
            .map_err(|_| "invalid end port".to_string())?;
        if start > end {
            return Err("start port is greater than end port".to_string());
        }
        Ok((start, end))
    } else {
        let port: u16 = s.parse().map_err(|_| "invalid port".to_string())?;
        Ok((port, port))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub mode: String,
    pub log_level: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            mode: "client".to_string(),
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub transport_type: String,
    pub server_addr: SocketAddr,
    pub ca_cert_path: String,
    #[serde(default, skip_serializing)]
    pub session_id: String,
    pub token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientState {
    #[serde(default)]
    pub session_id: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            transport_type: "udp".to_string(),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            ca_cert_path: "certs/ca-cert.pem".to_string(),
            session_id: String::new(),
            token: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub transport_type: String,
    pub bind_addr: SocketAddr,
    pub tun_name: String,
    pub tun_addr: IpAddr,
    pub tun_netmask: IpAddr,
    pub mtu: usize,
    pub cert_path: String,
    pub key_path: String,
    pub token: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            transport_type: "udp".to_string(),
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            tun_name: "tun0".to_string(),
            tun_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            tun_netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
            mtu: 1500,
            cert_path: "certs/server-cert.pem".to_string(),
            key_path: "certs/server-key.pem".to_string(),
            token: String::new(),
        }
    }
}

impl ServerConfig {
    pub fn load() -> anyhow::Result<Self> {
        Ok(AppConfig::load()?.server)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparentProxyConfig {
    pub interface: String,
    pub smoltcp_addr: IpAddr,
    pub smoltcp_netmask: IpAddr,
    pub smoltcp_gateway: IpAddr,
    pub upstream_server: Option<IpAddr>,
}

impl Default for TransparentProxyConfig {
    fn default() -> Self {
        Self {
            interface: "".to_string(),
            smoltcp_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            smoltcp_netmask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
            smoltcp_gateway: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            upstream_server: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub client: ClientConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default = "default_rules")]
    pub rules: RulesConfig,
    #[serde(default)]
    pub rule_sets: RuleSetConfig,
    #[serde(default)]
    pub transparent_proxy: TransparentProxyConfig,
}

fn default_rules() -> RulesConfig {
    RulesConfig {
        default_action: RuleAction::Reject,
        rules: Vec::new(),
        geoip_path: None,
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            runtime: RuntimeConfig::default(),
            client: ClientConfig::default(),
            server: ServerConfig::default(),
            rules: default_rules(),
            rule_sets: RuleSetConfig::default(),
            transparent_proxy: TransparentProxyConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            let config = Self::default();
            config.save_to_file(path)?;
            return Ok(config);
        }

        let content = std::fs::read_to_string(path)?;
        let config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn load() -> anyhow::Result<Self> {
        let mut config = Self::load_from_file(APP_CONFIG_PATH)?;
        config.client.session_id = load_client_state()?.session_id;
        config.apply_rule_set_paths();
        Ok(config)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to_file(APP_CONFIG_PATH)
    }
}

impl AppConfig {
    fn apply_rule_set_paths(&mut self) {
        self.rules.geoip_path = self.rule_sets.geoip_path.clone();
    }
}

pub fn load_client_state() -> anyhow::Result<ClientState> {
    let path = Path::new(CLIENT_STATE_PATH);
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        return Ok(serde_yaml::from_str(&content)?);
    }

    Ok(ClientState::default())
}

pub fn save_client_state(state: &ClientState) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(CLIENT_STATE_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = serde_yaml::to_string(state)?;
    std::fs::write(CLIENT_STATE_PATH, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_config_applies_rule_set_geoip_path() {
        let mut config: AppConfig = serde_yaml::from_str(
            r#"
rules:
  - GEOIP,CN,direct
rule_sets:
  geoip_path: rules/geoip/GeoLite2-Country.mmdb
"#,
        )
        .unwrap();

        config.apply_rule_set_paths();

        assert_eq!(
            config.rules.geoip_path.as_deref(),
            Some("rules/geoip/GeoLite2-Country.mmdb")
        );
    }
}

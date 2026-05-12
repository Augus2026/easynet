use super::action::RuleAction;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Other(value),
        }
    }
}

impl Protocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            _ => None,
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Other(0)
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Other(n) => write!(f, "other({})", n),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub src_ip_cidr: Option<String>,

    pub dst_ip_cidr: Option<String>,

    pub src_port: Option<String>,

    pub dst_port: Option<String>,

    pub proto: Option<String>,

    pub domain: Option<String>,

    pub domain_suffix: Option<String>,

    pub domain_keyword: Option<String>,

    pub geoip: Option<String>,

    pub match_all: bool,

    pub action: RuleAction,
}

impl Rule {
    pub fn new(action: RuleAction) -> Self {
        Self {
            src_ip_cidr: None,
            dst_ip_cidr: None,
            src_port: None,
            dst_port: None,
            proto: None,
            domain: None,
            domain_suffix: None,
            domain_keyword: None,
            geoip: None,
            match_all: false,
            action,
        }
    }

    pub fn parse_compact(value: &str) -> Result<Self, String> {
        let parts: Vec<&str> = value.split(',').map(str::trim).collect();
        if parts.is_empty() || parts[0].is_empty() {
            return Err("rule is empty".to_string());
        }

        let field = parts[0].to_ascii_uppercase();
        let rule = match field.as_str() {
            "MATCH" => {
                if parts.len() != 2 {
                    return Err("MATCH rule format must be MATCH,action".to_string());
                }
                let action = parse_action(parts[1])?;
                let mut rule = Rule::new(action);
                rule.match_all = true;
                rule
            }
            "SRC-IP-CIDR" => {
                let (rule_value, action) = parse_field_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.src_ip_cidr = Some(rule_value);
                rule
            }
            "DST-IP-CIDR" => {
                let (rule_value, action) = parse_field_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.dst_ip_cidr = Some(rule_value);
                rule
            }
            "SRC-PORT" => {
                let (rule_value, action) = parse_field_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.src_port = Some(rule_value);
                rule
            }
            "DST-PORT" => {
                let (rule_value, action) = parse_field_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.dst_port = Some(rule_value);
                rule
            }
            "PROTO" => {
                let (rule_value, action) = parse_field_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.proto = Some(rule_value);
                rule
            }
            "DOMAIN" => {
                let (rule_value, action) = parse_domain_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.domain = Some(rule_value);
                rule
            }
            "DOMAIN-SUFFIX" => {
                let (rule_value, action) = parse_domain_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.domain_suffix = Some(rule_value);
                rule
            }
            "DOMAIN-KEYWORD" => {
                let (rule_value, action) = parse_domain_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.domain_keyword = Some(rule_value);
                rule
            }
            "GEOIP" => {
                let (rule_value, action) = parse_geoip_rule_parts(&parts, &field)?;
                let mut rule = Rule::new(action);
                rule.geoip = Some(rule_value);
                rule
            }
            _ => return Err(format!("unknown rule field '{}'", parts[0])),
        };

        Ok(rule)
    }

    pub fn has_conditions(&self) -> bool {
        self.match_all
            || self.src_ip_cidr.is_some()
            || self.dst_ip_cidr.is_some()
            || self.src_port.is_some()
            || self.dst_port.is_some()
            || self.proto.is_some()
            || self.domain.is_some()
            || self.domain_suffix.is_some()
            || self.domain_keyword.is_some()
            || self.geoip.is_some()
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RuleVisitor;

        impl<'de> de::Visitor<'de> for RuleVisitor {
            type Value = Rule;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a compact rule string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Rule::parse_compact(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(RuleVisitor)
    }
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.match_all {
            return write!(f, "MATCH,{}", self.action);
        }
        if let Some(value) = &self.src_ip_cidr {
            return write!(f, "SRC-IP-CIDR,{},{}", value, self.action);
        }
        if let Some(value) = &self.dst_ip_cidr {
            return write!(f, "DST-IP-CIDR,{},{}", value, self.action);
        }
        if let Some(value) = &self.src_port {
            return write!(f, "SRC-PORT,{},{}", value, self.action);
        }
        if let Some(value) = &self.dst_port {
            return write!(f, "DST-PORT,{},{}", value, self.action);
        }
        if let Some(value) = &self.proto {
            return write!(f, "PROTO,{},{}", value, self.action);
        }
        if let Some(value) = &self.domain {
            return write!(f, "DOMAIN,{},{}", value, self.action);
        }
        if let Some(value) = &self.domain_suffix {
            return write!(f, "DOMAIN-SUFFIX,{},{}", value, self.action);
        }
        if let Some(value) = &self.domain_keyword {
            return write!(f, "DOMAIN-KEYWORD,{},{}", value, self.action);
        }
        if let Some(value) = &self.geoip {
            return write!(f, "GEOIP,{},{}", value, self.action);
        }
        write!(f, "MATCH,{}", self.action)
    }
}

impl Serialize for Rule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

fn parse_field_rule_parts(parts: &[&str], field: &str) -> Result<(String, RuleAction), String> {
    if parts.len() != 3 {
        return Err(format!(
            "{} rule format must be {},value,action",
            field, field
        ));
    }
    if parts[1].is_empty() {
        return Err(format!("{} rule value cannot be empty", field));
    }
    Ok((parts[1].to_string(), parse_action(parts[2])?))
}

fn parse_domain_rule_parts(parts: &[&str], field: &str) -> Result<(String, RuleAction), String> {
    let (value, action) = parse_field_rule_parts(parts, field)?;
    Ok((normalize_domain_rule_value(&value)?, action))
}

fn normalize_domain_rule_value(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() {
        return Err("domain rule value cannot be empty".to_string());
    }
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '/' | ','))
    {
        return Err(format!("invalid domain rule value '{}'", value));
    }
    Ok(value)
}

fn parse_geoip_rule_parts(parts: &[&str], field: &str) -> Result<(String, RuleAction), String> {
    let (value, action) = parse_field_rule_parts(parts, field)?;
    Ok((normalize_geoip_rule_value(&value)?, action))
}

fn normalize_geoip_rule_value(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_uppercase();
    if value.is_empty() {
        return Err("GEOIP rule value cannot be empty".to_string());
    }
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '/' | ','))
    {
        return Err(format!("invalid GEOIP rule value '{}'", value));
    }
    Ok(value)
}

fn parse_action(value: &str) -> Result<RuleAction, String> {
    match value.to_ascii_lowercase().as_str() {
        "direct" => Ok(RuleAction::Direct),
        "proxy" => Ok(RuleAction::Proxy),
        "reject" | "drop" => Ok(RuleAction::Reject),
        _ => Err(format!("unknown rule action '{}'", value)),
    }
}

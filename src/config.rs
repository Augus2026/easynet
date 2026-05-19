use serde::{de, Deserialize, Deserializer, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

pub const APP_CONFIG_PATH: &str = "config/easynet.yaml";
pub const CLIENT_STATE_PATH: &str = "config/client_state.yaml";

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
    #[serde(default)]
    pub server_node_id: String,
    #[serde(default, skip_serializing)]
    pub session_id: String,
    pub token: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            transport_type: "udp".to_string(),
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            ca_cert_path: "certs/ca-cert.pem".to_string(),
            server_node_id: String::new(),
            session_id: String::new(),
            token: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientState {
    #[serde(default)]
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub transport_type: String,
    pub bind_addr: SocketAddr,
    pub tun_name: String,
    pub tun_addr: IpAddr,
    pub tun_netmask: IpAddr,
    pub tun_destination: IpAddr,
    #[serde(default, deserialize_with = "deserialize_tun_dns_servers")]
    pub tun_dns_servers: Vec<IpAddr>,
    pub tun_mtu: usize,
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
            tun_destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            tun_dns_servers: vec![
                IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ],
            tun_mtu: 1400,
            cert_path: "certs/server-cert.pem".to_string(),
            key_path: "certs/server-key.pem".to_string(),
            token: String::new(),
        }
    }
}

fn deserialize_tun_dns_servers<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    struct TunDnsServersVisitor;

    impl<'de> de::Visitor<'de> for TunDnsServersVisitor {
        type Value = Vec<IpAddr>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a comma-separated DNS server string or a list of DNS server IPs")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_dns_servers(value.split(',')).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut dns_servers = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                let value = value.trim();
                if !value.is_empty() {
                    dns_servers.push(value.parse::<IpAddr>().map_err(de::Error::custom)?);
                }
            }
            Ok(dns_servers)
        }
    }

    deserializer.deserialize_any(TunDnsServersVisitor)
}

fn parse_dns_servers<'a, I>(values: I) -> Result<Vec<IpAddr>, std::net::AddrParseError>
where
    I: IntoIterator<Item = &'a str>,
{
    values
        .into_iter()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse)
        .collect()
}

impl ServerConfig {
    pub fn load() -> anyhow::Result<Self> {
        Ok(AppConfig::load()?.server)
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
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            runtime: RuntimeConfig::default(),
            client: ClientConfig::default(),
            server: ServerConfig::default(),
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
        Ok(config)
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

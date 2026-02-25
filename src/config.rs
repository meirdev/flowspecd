use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub router: RouterConfig,
    pub interfaces: Vec<InterfaceConfig>,
    #[serde(default)]
    pub bgp: Option<BgpConfig>,
    #[serde(default)]
    pub ipfix: Option<IpfixConfig>,
    #[serde(default)]
    pub api: Option<ApiConfig>,
    #[serde(default)]
    pub flowspec: FlowSpecConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouterConfig {
    pub router_id: Ipv4Addr,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub role: InterfaceRole,
    #[serde(default)]
    pub address: Option<Ipv4Net>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceRole {
    Wan,
    Lan,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BgpConfig {
    pub local_as: u32,
    #[serde(default = "default_bgp_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub peers: Vec<BgpPeerConfig>,
}

fn default_bgp_port() -> u16 {
    179
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BgpPeerConfig {
    pub address: Ipv4Addr,
    pub remote_as: u32,
    #[serde(default = "default_true")]
    pub flowspec: bool,
    #[serde(default)]
    pub password: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpfixConfig {
    pub collector: SocketAddr,
    #[serde(default = "default_export_interval")]
    pub export_interval_secs: u64,
    #[serde(default = "default_observation_domain")]
    pub observation_domain_id: u32,
    /// Sampling rate: 1 means sample every packet, N means sample 1 in N packets
    #[serde(default = "default_sampling_rate")]
    pub sampling_rate: u32,
}

fn default_sampling_rate() -> u32 {
    1 // Sample every packet by default
}

fn default_export_interval() -> u64 {
    60
}

fn default_observation_domain() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiConfig {
    #[serde(default = "default_api_listen")]
    pub listen: SocketAddr,
}

fn default_api_listen() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FlowSpecConfig {
    #[serde(default)]
    pub default_action: FlowSpecAction,
    #[serde(default)]
    pub rules: Vec<StaticFlowSpecRule>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowSpecAction {
    #[default]
    Accept,
    Drop,
    RateLimit,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StaticFlowSpecRule {
    pub name: String,
    #[serde(default)]
    pub src_prefix: Option<Ipv4Net>,
    #[serde(default)]
    pub dst_prefix: Option<Ipv4Net>,
    #[serde(default)]
    pub protocol: Option<u8>,
    #[serde(default)]
    pub src_port: Option<PortRange>,
    #[serde(default)]
    pub dst_port: Option<PortRange>,
    pub action: FlowSpecAction,
    #[serde(default)]
    pub rate_limit_bps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.interfaces.is_empty() {
            anyhow::bail!("At least one interface must be configured");
        }

        let wan_count = self.interfaces.iter()
            .filter(|i| i.role == InterfaceRole::Wan)
            .count();
        let lan_count = self.interfaces.iter()
            .filter(|i| i.role == InterfaceRole::Lan)
            .count();

        if wan_count == 0 || lan_count == 0 {
            anyhow::bail!("At least one WAN and one LAN interface must be configured");
        }

        Ok(())
    }

    pub fn wan_interface(&self) -> &InterfaceConfig {
        self.interfaces.iter()
            .find(|i| i.role == InterfaceRole::Wan)
            .expect("WAN interface validated")
    }

    pub fn lan_interface(&self) -> &InterfaceConfig {
        self.interfaces.iter()
            .find(|i| i.role == InterfaceRole::Lan)
            .expect("LAN interface validated")
    }
}

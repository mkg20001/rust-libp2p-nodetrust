//! TOML configuration. One file per service; see `examples/*.toml`.

use std::{collections::HashMap, net::IpAddr, path::PathBuf};

use libp2p::Multiaddr;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub node: NodeConfig,
    pub dns: Option<DnsConfig>,
    pub proof: Option<ProofConfig>,
    pub issue: Option<IssueConfig>,
    pub client: Option<ClientConfig>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// protobuf-encoded libp2p keypair, generated if missing
    #[serde(default = "default_key_file")]
    pub key_file: PathBuf,
    #[serde(default)]
    pub listen: Vec<Multiaddr>,
    /// act as circuit relay (hop) for other peers
    #[serde(default)]
    pub relay: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self { key_file: default_key_file(), listen: Vec::new(), relay: false }
    }
}

fn default_key_file() -> PathBuf {
    PathBuf::from("identity.key")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// UDP+TCP socket addresses
    pub listen: Vec<std::net::SocketAddr>,
    /// zone served, e.g. `nt.example.org`
    pub zone: String,
    /// authoritative name servers of the zone (NS records)
    pub ns: Vec<String>,
    /// SOA RNAME (mailbox with `.` instead of `@`)
    #[serde(default)]
    pub hostmaster: Option<String>,
    /// peer ids allowed to push DNS-01 challenges (the issue servers)
    pub admins: Vec<String>,
    /// TTL of ip/id records, seconds
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// lifetime of DNS-01 TXT records, seconds
    #[serde(default = "default_txt_ttl")]
    pub txt_ttl: u32,
    /// static A/AAAA records inside the zone, e.g. glue for the NS names
    #[serde(default)]
    pub records: HashMap<String, Vec<IpAddr>>,
}

fn default_ttl() -> u32 {
    36000
}
fn default_txt_ttl() -> u32 {
    120
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofConfig {
    /// protobuf-encoded keypair used to sign proofs (shared by all proof servers)
    pub key_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueConfig {
    pub zone: String,
    /// account credentials and certificate cache
    pub state_dir: PathBuf,
    /// ACME contact email
    #[serde(default)]
    pub email: Option<String>,
    /// `staging`, `production` or a directory URL
    #[serde(default = "default_directory")]
    pub directory: String,
    /// extra root CA (PEM) for the ACME server's HTTPS, e.g. Pebble's
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// DNS server addresses (`…/p2p/<id>`)
    pub dns: Vec<Multiaddr>,
    /// trusted proof public keys (base64 protobuf, as printed by `nodetrust keygen`)
    pub proof_keys: Vec<String>,
    pub proof_servers: Vec<ProofServerConfig>,
    #[serde(default = "default_cryptos")]
    pub cryptos: Vec<String>,
    /// ACME order timeout, seconds
    #[serde(default = "default_order_timeout")]
    pub order_timeout: u64,
    /// cache garbage collection interval, seconds
    #[serde(default = "default_gc_interval")]
    pub gc_interval: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProofServerConfig {
    pub display: String,
    /// addresses of one proof server (`…/p2p/<id>`)
    pub addrs: Vec<Multiaddr>,
}

fn default_directory() -> String {
    "staging".into()
}
fn default_cryptos() -> Vec<String> {
    vec!["ecdsa-p256".into(), "rsa".into()]
}
fn default_order_timeout() -> u64 {
    120
}
fn default_gc_interval() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// issue server address (`…/p2p/<id>`)
    pub issuer: Multiaddr,
    /// TLS key and certificate
    pub state_dir: PathBuf,
    /// WSS listen address
    #[serde(default = "default_wss")]
    pub wss_listen: Multiaddr,
    /// UPnP port mapping
    #[serde(default = "default_true")]
    pub nat: bool,
    /// key types in order of preference
    #[serde(default = "default_cryptos")]
    pub cryptos: Vec<String>,
    /// dial peers learned via discovery
    #[serde(default = "default_true")]
    pub dial_discovered: bool,
    /// extra trust roots (PEM) for dialing other peers' WSS, e.g. a test CA
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

fn default_wss() -> Multiaddr {
    "/ip4/0.0.0.0/tcp/0/tls/ws".parse().expect("valid multiaddr")
}
fn default_true() -> bool {
    true
}

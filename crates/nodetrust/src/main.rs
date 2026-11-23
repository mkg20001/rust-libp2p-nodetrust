use std::{path::PathBuf, time::Duration};

use anyhow::{Context, anyhow, bail};
use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, identity::Keypair};
use nodetrust::{
    client,
    config::Config,
    node::{self, Node, NodeEvent, NodeOptions},
    server,
};
use tracing_subscriber::{EnvFilter, prelude::*};

#[derive(Parser)]
#[command(version, about = "DNS names and ACME certificates for libp2p nodes")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the DNS server (`[dns]` section)
    Dns { #[arg(long, short)] config: PathBuf },
    /// Run the proof server (`[proof]` section)
    Proof { #[arg(long, short)] config: PathBuf },
    /// Run the issue server (`[issue]` section)
    Issue { #[arg(long, short)] config: PathBuf },
    /// Run a client: obtain a certificate, serve WSS, announce (`[client]` section)
    Client { #[arg(long, short)] config: PathBuf },
    /// Generate a libp2p keypair (identity or proof key)
    Keygen {
        #[arg(long, short)]
        out: PathBuf,
    },
    /// Print peer id and public key of a key file
    Pubkey {
        #[arg(long, short)]
        key: PathBuf,
    },
    /// Dial a peer (e.g. its `/dns4/…/tls/ws/p2p/…` address) and wait for a ping
    Ping {
        addr: Multiaddr,
        /// extra trust root (PEM) for `/tls/ws`
        #[arg(long)]
        ca: Option<PathBuf>,
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Protocol probes for testing and debugging; print the server's reply, exit 1 unless OK
    #[command(subcommand)]
    Debug(Debug),
}

#[derive(Subcommand)]
enum Debug {
    /// Push a DNS-01 value to a DNS server (only admins are accepted)
    Dns01 {
        dns: Multiaddr,
        fqdn: String,
        value: String,
        /// identity to use (default: ephemeral)
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Fetch a proof from a proof server and save it
    Proof { server: Multiaddr, #[arg(long)] out: PathBuf },
    /// Ask an issue server for a certificate using a saved proof (with a fresh identity unless --key)
    Issue {
        issuer: Multiaddr,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    #[cfg(feature = "sentry")]
    let _sentry = init_logging();
    #[cfg(not(feature = "sentry"))]
    init_logging();
    tokio::runtime::Runtime::new()?.block_on(run(cli.cmd))
}

#[cfg(feature = "sentry")]
fn init_logging() -> Option<sentry::ClientInitGuard> {
    let guard = std::env::var("SENTRY_DSN").ok().map(|dsn| sentry::init((dsn, sentry::ClientOptions { release: sentry::release_name!(), ..Default::default() })));
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(sentry_tracing::layer())
        .init();
    guard
}

#[cfg(not(feature = "sentry"))]
fn init_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
}

fn service_node(cfg: &Config, discovery: bool) -> anyhow::Result<Node> {
    let key = node::load_or_create_key(&cfg.node.key_file)?;
    tracing::info!(peer = %key.public().to_peer_id(), "starting");
    let (node, mut events) = Node::spawn(
        key,
        NodeOptions { listen: cfg.node.listen.clone(), relay: cfg.node.relay, discovery, ..Default::default() },
    )?;
    tokio::spawn(async move { while events.recv().await.is_some() {} });
    Ok(node)
}

async fn run(cmd: Cmd) -> anyhow::Result<()> {
    match cmd {
        Cmd::Dns { config } => {
            let mut cfg = Config::load(&config)?;
            let dns = cfg.dns.take().ok_or_else(|| anyhow!("missing [dns] section"))?;
            server::dns::run(service_node(&cfg, true)?, dns).await
        }
        Cmd::Proof { config } => {
            let mut cfg = Config::load(&config)?;
            let proof = cfg.proof.take().ok_or_else(|| anyhow!("missing [proof] section"))?;
            let key = Keypair::from_protobuf_encoding(&std::fs::read(&proof.key_file).with_context(|| format!("reading {}", proof.key_file.display()))?)?;
            server::proof::run(service_node(&cfg, false)?, key)?;
            futures::future::pending().await
        }
        Cmd::Issue { config } => {
            let mut cfg = Config::load(&config)?;
            let issue = cfg.issue.take().ok_or_else(|| anyhow!("missing [issue] section"))?;
            server::issue::run(service_node(&cfg, true)?, issue).await
        }
        Cmd::Client { config } => {
            let mut cfg = Config::load(&config)?;
            let c = cfg.client.take().ok_or_else(|| anyhow!("missing [client] section"))?;
            let key = node::load_or_create_key(&cfg.node.key_file)?;
            tracing::info!(peer = %key.public().to_peer_id(), "starting");
            client::run(key, &cfg.node, c).await
        }
        Cmd::Keygen { out } => {
            if out.exists() {
                bail!("{} already exists", out.display());
            }
            let key = node::load_or_create_key(&out)?;
            print_key(&key);
            Ok(())
        }
        Cmd::Pubkey { key } => {
            print_key(&Keypair::from_protobuf_encoding(&std::fs::read(&key)?)?);
            Ok(())
        }
        Cmd::Debug(d) => debug(d).await,
        Cmd::Ping { addr, ca, timeout } => {
            let (target, _) = node::split_peer(&addr)?;
            let (node, mut events) = Node::spawn(
                Keypair::generate_ed25519(),
                NodeOptions { extra_roots: client::load_roots(ca.as_deref())?, ..Default::default() },
            )?;
            node.dial(&addr).await?;
            let rtt = tokio::time::timeout(Duration::from_secs(timeout), async {
                while let Some(ev) = events.recv().await {
                    if let NodeEvent::Pong { peer, rtt } = ev
                        && peer == target
                    {
                        return Ok(rtt);
                    }
                }
                Err(anyhow!("node stopped"))
            })
            .await
            .context("no ping reply")??;
            println!("pong from {target} in {rtt:?}");
            Ok(())
        }
    }
}

async fn debug(cmd: Debug) -> anyhow::Result<()> {
    use nodetrust::proto::*;
    use prost::Message;
    let key = |k: Option<PathBuf>| match k {
        Some(p) => Keypair::from_protobuf_encoding(&std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?).map_err(Into::into),
        None => anyhow::Ok(Keypair::generate_ed25519()),
    };
    let check = |code: i32, what: &str| {
        let e = Error::try_from(code).unwrap_or(Error::EOther);
        println!("{what}: {e:?}");
        if e == Error::Ok { Ok(()) } else { bail!("{what} returned {e:?}") }
    };
    match cmd {
        Debug::Dns01 { dns, fqdn, value, key: k } => {
            let (node, _ev) = Node::spawn(key(k)?, NodeOptions::default())?;
            let r: Dns01Response = node.request(&dns, DNS01_PROTOCOL, &Dns01Request { fqdn, value }).await?;
            check(r.error, "dns-01")
        }
        Debug::Proof { server, out } => {
            let (node, _ev) = Node::spawn(Keypair::generate_ed25519(), NodeOptions::default())?;
            let r: ProofResponse = node.request(&server, PROOF_PROTOCOL, &ProofRequest {}).await?;
            check(r.error, "proof")?;
            std::fs::write(&out, r.proof.unwrap_or_default().encode_to_vec())?;
            Ok(())
        }
        Debug::Issue { issuer, proof, key: k } => {
            let proof = ProofWrapper::decode(std::fs::read(&proof)?.as_slice())?;
            let crypto = Crypto::EcdsaP256;
            let tls = nodetrust::tlskey::generate(crypto)?;
            let (node, _ev) = Node::spawn(key(k)?, NodeOptions::default())?;
            let csr = nodetrust::tlskey::csr(&tls, &[nodetrust::names::fqdn(&nodetrust::names::id_label(&node.peer_id)?, "invalid")])?;
            let req = IssueRequest { proofs: vec![proof], supported_cryptos: vec![crypto as i32], csr };
            let r: IssueResponse = node.request(&issuer, ISSUE_PROTOCOL, &req).await?;
            if !r.message.is_empty() {
                println!("message: {}", r.message);
            }
            check(r.error, "issue")
        }
    }
}

fn print_key(key: &Keypair) {
    println!("peer_id = \"{}\"", key.public().to_peer_id());
    println!("public_key = \"{}\"", server::public_key_b64(key));
}

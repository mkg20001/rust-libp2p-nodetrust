//! Native client: obtain a certificate from an issue server, serve WSS with it, announce the
//! WSS addresses over pubsub and renew in place before expiry.

use std::{net::IpAddr, path::Path, time::Duration};

use anyhow::{Context, anyhow, bail};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    config::{ClientConfig, NodeConfig},
    discovery, names,
    node::{Node, NodeEvent, NodeOptions, split_peer},
    proof::now_ms,
    proto::{
        Crypto, Error, INFO_PROTOCOL, ISSUE_PROTOCOL, IssueInfo, IssueInfoRequest, IssueRequest, IssueResponse,
        PROOF_PROTOCOL, Proof, ProofRequest, ProofResponse, ProofWrapper,
    },
    tlskey, wss,
};

/// What the client stores in `state_dir/cert.json` (also read by tests and operators).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertState {
    pub cn: String,
    pub altnames: Vec<String>,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub from_cache: bool,
    pub issuer: String,
    pub chain: String,
}

/// Load PEM certificates as DER (for `ca_file` options).
pub fn load_roots(path: Option<&Path>) -> anyhow::Result<Vec<Vec<u8>>> {
    let Some(path) = path else { return Ok(vec![]) };
    let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(rustls_pemfile::certs(&mut pem.as_slice()).map(|c| c.map(|c| c.to_vec())).collect::<Result<_, _>>()?)
}

pub async fn run(key: Keypair, node_cfg: &NodeConfig, cfg: ClientConfig) -> anyhow::Result<()> {
    let state = cfg.state_dir.clone();
    std::fs::create_dir_all(&state).with_context(|| format!("creating {}", state.display()))?;
    let cryptos = cfg.cryptos.iter().map(|c| tlskey::parse_crypto(c)).collect::<anyhow::Result<Vec<_>>>()?;
    let handle = wss::CertHandle::default();
    let (node, mut events) = Node::spawn(
        key,
        NodeOptions {
            listen: node_cfg.listen.clone(),
            relay: node_cfg.relay,
            upnp: cfg.nat,
            discovery: true,
            dial_discovered: cfg.dial_discovered,
            wss_cert: Some(handle.clone()),
            extra_roots: load_roots(cfg.ca_file.as_deref())?,
        },
    )?;

    let mut cert = match load_state(&state) {
        Some(c) if !tlskey::renew_due(c.not_before_ms, c.not_after_ms, now_ms()) => {
            tracing::info!(cn = %c.cn, "using stored certificate");
            c
        }
        _ => obtain_retrying(&node, &cfg.issuer, &cryptos, &state).await,
    };
    handle.set(&cert.chain, &std::fs::read_to_string(state.join("tls.key"))?)?;
    node.listen(cfg.wss_listen.clone()).await?;

    let mut ports = Ports::default();
    let mut tick = tokio::time::interval(discovery::ANNOUNCE_INTERVAL);
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else { bail!("node stopped") };
                let changed = match ev {
                    NodeEvent::Listening(addr) => ports.listening(&addr),
                    NodeEvent::ExternalPortMapped { local, external } => ports.mapped(&local, &external),
                    _ => false,
                };
                if changed {
                    node.set_external(external_addrs(&cert, &ports));
                }
            }
            _ = tick.tick() => {
                if let Err(e) = node.dial(&cfg.issuer).await {
                    tracing::warn!("issuer unreachable: {e:#}");
                }
                if tlskey::renew_due(cert.not_before_ms, cert.not_after_ms, now_ms()) {
                    tracing::info!(not_after_ms = cert.not_after_ms, "renewing certificate");
                    match obtain(&node, &cfg.issuer, &cryptos, &state).await {
                        Ok(c) => {
                            cert = c;
                            handle.set(&cert.chain, &std::fs::read_to_string(state.join("tls.key"))?)?;
                            node.set_external(external_addrs(&cert, &ports));
                        }
                        Err(e) => tracing::warn!("renewal failed, keeping old certificate: {e:#}"),
                    }
                }
                node.announce();
            }
        }
    }
}

#[derive(Default)]
struct Ports {
    v4: Option<u16>,
    v6: Option<u16>,
}

fn wss_port(addr: &Multiaddr) -> Option<(bool, u16)> {
    let mut v4 = None;
    let mut port = None;
    let mut tls = false;
    for p in addr.iter() {
        match p {
            Protocol::Ip4(_) => v4 = Some(true),
            Protocol::Ip6(_) => v4 = Some(false),
            Protocol::Tcp(p) => port = Some(p),
            Protocol::Tls | Protocol::Wss(_) => tls = true,
            _ => {}
        }
    }
    tls.then_some((v4?, port?))
}

impl Ports {
    fn listening(&mut self, addr: &Multiaddr) -> bool {
        // port is the same for every interface address of one listener; keep the first seen
        match wss_port(addr) {
            Some((true, p)) if self.v4.is_none() => self.v4 = Some(p),
            Some((false, p)) if self.v6.is_none() => self.v6 = Some(p),
            _ => return false,
        }
        true
    }

    /// ponytail: trusts the gateway's mapping for the whole family; per-listener mapping if several WSS listeners matter
    fn mapped(&mut self, local: &Multiaddr, external: &Multiaddr) -> bool {
        if wss_port(local).is_none() {
            return false;
        }
        let port = external.iter().find_map(|p| match p {
            Protocol::Tcp(p) => Some(p),
            _ => None,
        });
        let v4 = external.iter().next().map(|p| matches!(p, Protocol::Ip4(_)));
        match v4.zip(port) {
            Some((true, p)) => self.v4 = Some(p),
            Some((false, p)) => self.v6 = Some(p),
            None => return false,
        }
        true
    }
}

fn external_addrs(cert: &CertState, ports: &Ports) -> Vec<Multiaddr> {
    cert.altnames
        .iter()
        .filter_map(|name| {
            let label = name.split('.').next()?;
            let (dns, port) = match names::parse_ip_label(label)? {
                IpAddr::V4(_) => (Protocol::Dns4(name.clone().into()), ports.v4?),
                IpAddr::V6(_) => (Protocol::Dns6(name.clone().into()), ports.v6?),
            };
            Some(
                Multiaddr::empty()
                    .with(dns)
                    .with(Protocol::Tcp(port))
                    .with(Protocol::Tls)
                    .with(Protocol::Ws("/".into())),
            )
        })
        .collect()
}

fn load_state(dir: &Path) -> Option<CertState> {
    let c: CertState = serde_json::from_slice(&std::fs::read(dir.join("cert.json")).ok()?).ok()?;
    // the stored key must still belong to the certificate (it may have been regenerated)
    std::fs::metadata(dir.join("tls.key")).ok()?;
    Some(c)
}

async fn obtain_retrying(node: &Node, issuer: &Multiaddr, cryptos: &[Crypto], state: &Path) -> CertState {
    let mut delay = Duration::from_secs(5);
    loop {
        match obtain(node, issuer, cryptos, state).await {
            Ok(c) => return c,
            Err(e) => {
                tracing::warn!("obtaining certificate failed, retrying in {delay:?}: {e:#}");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(120));
            }
        }
    }
}

/// Fetch proofs and a certificate from `issuer`; stores key and certificate in `state`.
pub async fn obtain(node: &Node, issuer: &Multiaddr, cryptos: &[Crypto], state: &Path) -> anyhow::Result<CertState> {
    let info: IssueInfo = node.request(issuer, INFO_PROTOCOL, &IssueInfoRequest {}).await?;
    tracing::info!(domain = %info.domain, proof_servers = info.proofs.len(), "issuer info");
    let crypto = *cryptos
        .iter()
        .find(|c| info.supported_cryptos.contains(&(**c as i32)))
        .ok_or_else(|| anyhow!("issuer supports none of our key types"))?;

    let proofs = collect_proofs(node, &info).await;
    if proofs.is_empty() {
        bail!("could not acquire a single proof");
    }
    let mut ips = Vec::new();
    for p in &proofs {
        let proof = Proof::decode(p.proof.as_slice())?;
        ips.extend(proof.addrs.iter().filter_map(|a| a.address.parse::<IpAddr>().ok()));
    }
    let names = names::cert_names(&node.peer_id, &ips, &info.domain)?;

    let key_path = state.join("tls.key");
    let key = match std::fs::read_to_string(&key_path) {
        Ok(k) if tlskey::key_crypto(&k).ok() == Some(crypto) => k,
        _ => {
            let k = tlskey::generate(crypto)?;
            write_private(&key_path, &k)?;
            k
        }
    };
    let csr = tlskey::csr(&key, &names)?;
    let resp: IssueResponse = node
        .request(issuer, ISSUE_PROTOCOL, &IssueRequest { proofs, supported_cryptos: vec![crypto as i32], csr })
        .await?;
    if resp.error != Error::Ok as i32 {
        bail!("issue error {:?}: {}", Error::try_from(resp.error).unwrap_or(Error::EOther), resp.message);
    }
    let chain = String::from_utf8(resp.chain).context("chain is not PEM")?;
    let parsed = tlskey::parse_chain(&chain)?;
    let cert = CertState {
        cn: resp.cn,
        altnames: resp.altnames,
        not_before_ms: parsed.not_before_ms,
        not_after_ms: parsed.not_after_ms,
        from_cache: resp.from_cache,
        issuer: parsed.issuer,
        chain,
    };
    let tmp = state.join("cert.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&cert)?)?;
    std::fs::rename(&tmp, state.join("cert.json"))?;
    tracing::info!(cn = %cert.cn, altnames = ?cert.altnames, not_after_ms = cert.not_after_ms, from_cache = cert.from_cache, "certificate obtained");
    Ok(cert)
}

async fn collect_proofs(node: &Node, info: &IssueInfo) -> Vec<ProofWrapper> {
    let tasks = info.proofs.iter().map(|server| async move {
        let peer = PeerId::from_bytes(&server.id).map_err(|e| anyhow!("bad proof server id: {e}"))?;
        let mut last = anyhow!("no addresses");
        for addr in &server.addrs {
            let mut addr = Multiaddr::try_from(addr.clone())?;
            if split_peer(&addr).is_err() {
                addr.push(Protocol::P2p(peer));
            }
            match node.request::<_, ProofResponse>(&addr, PROOF_PROTOCOL, &ProofRequest {}).await {
                Ok(r) if r.error == Error::Ok as i32 => return r.proof.ok_or_else(|| anyhow!("empty proof")),
                Ok(r) => last = anyhow!("proof error {:?}", Error::try_from(r.error)),
                Err(e) => last = e,
            }
        }
        Err(last)
    });
    futures::future::join_all(tasks)
        .await
        .into_iter()
        .zip(&info.proofs)
        .filter_map(|(r, s)| match r {
            Ok(p) => {
                tracing::info!(server = %s.display, "acquired proof");
                Some(p)
            }
            Err(e) => {
                tracing::warn!(server = %s.display, "failed to get proof: {e:#}");
                None
            }
        })
        .collect()
}

fn write_private(path: &Path, data: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
        Ok(())
    }
}

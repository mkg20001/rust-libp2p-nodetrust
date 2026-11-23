//! Issue service: verifies proofs, then obtains an ACME certificate (DNS-01 via the nodetrust
//! DNS server) for the client's CSR. Certificates are cached per peer + names + key.

// the Err variant is the IssueResponse sent back to the client, not worth boxing
#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use instant_acme::{Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy};
use libp2p::{Multiaddr, PeerId, identity::PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::IssueConfig,
    names,
    node::{Node, split_peer},
    proof,
    proto::{
        Crypto, DNS01_PROTOCOL, Dns01Request, Dns01Response, Error, INFO_PROTOCOL, ISSUE_PROTOCOL, IssueInfo, IssueInfoRequest,
        IssueRequest, IssueResponse, ProofServer,
    },
    tlskey,
};

#[derive(Serialize, Deserialize)]
struct Cached {
    chain: String,
    names: Vec<String>,
    not_before_ms: i64,
    not_after_ms: i64,
    crypto: i32,
}

struct Issuer {
    zone: String,
    node: Node,
    account: Account,
    dns: Vec<Multiaddr>,
    proof_keys: Vec<PublicKey>,
    cryptos: Vec<Crypto>,
    certs_dir: PathBuf,
    order_timeout: Duration,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

pub async fn run(node: Node, cfg: IssueConfig) -> anyhow::Result<()> {
    let proof_keys = cfg.proof_keys.iter().map(|k| crate::server::parse_public_key(k)).collect::<anyhow::Result<Vec<_>>>()?;
    let cryptos = cfg.cryptos.iter().map(|c| tlskey::parse_crypto(c)).collect::<anyhow::Result<Vec<_>>>()?;
    for a in &cfg.dns {
        split_peer(a)?;
    }
    let info = IssueInfo {
        domain: cfg.zone.trim_end_matches('.').to_ascii_lowercase(),
        proofs: cfg
            .proof_servers
            .iter()
            .map(|s| {
                let (peer, _) = split_peer(s.addrs.first().ok_or_else(|| anyhow!("proof server {} has no addrs", s.display))?)?;
                Ok(ProofServer { id: peer.to_bytes(), addrs: s.addrs.iter().map(|a| a.to_vec()).collect(), display: s.display.clone() })
            })
            .collect::<anyhow::Result<_>>()?,
        supported_cryptos: cryptos.iter().map(|c| *c as i32).collect(),
    };

    std::fs::create_dir_all(&cfg.state_dir).with_context(|| format!("creating {}", cfg.state_dir.display()))?;
    let account = account(&cfg).await?;
    let certs_dir = cfg.state_dir.join("certs");
    let issuer = Arc::new(Issuer {
        zone: info.domain.clone(),
        node: node.clone(),
        account,
        dns: cfg.dns.clone(),
        proof_keys,
        cryptos,
        certs_dir: certs_dir.clone(),
        order_timeout: Duration::from_secs(cfg.order_timeout),
        locks: Mutex::default(),
    });

    node.serve(INFO_PROTOCOL, move |_, _: IssueInfoRequest| {
        let info = info.clone();
        async move { info }
    })?;
    let i = issuer.clone();
    node.serve(ISSUE_PROTOCOL, move |peer, req: IssueRequest| {
        let i = i.clone();
        async move {
            match i.issue(peer, req).await {
                Ok(resp) => resp,
                Err(resp) => {
                    tracing::warn!(%peer, error = resp.error, message = %resp.message, "issue failed");
                    resp
                }
            }
        }
    })?;
    tracing::info!(zone = %issuer.zone, "issue service ready");

    let mut gc_tick = tokio::time::interval(Duration::from_secs(cfg.gc_interval.max(1)));
    loop {
        gc_tick.tick().await;
        if let Err(e) = gc(&certs_dir, proof::now_ms()) {
            tracing::warn!("cache gc: {e:#}");
        }
    }
}

async fn account(cfg: &IssueConfig) -> anyhow::Result<Account> {
    let builder = || match &cfg.ca_file {
        Some(ca) => Account::builder_with_root(ca).context("loading ACME CA file"),
        None => Account::builder().context("ACME HTTP client"),
    };
    let path = cfg.state_dir.join("account.json");
    if let Ok(json) = std::fs::read_to_string(&path) {
        let creds: AccountCredentials = serde_json::from_str(&json).context("account.json")?;
        return builder()?.from_credentials(creds).await.context("restoring ACME account");
    }
    let directory = match cfg.directory.as_str() {
        "staging" => LetsEncrypt::Staging.url().to_owned(),
        "production" => LetsEncrypt::Production.url().to_owned(),
        url => url.to_owned(),
    };
    let contact: Vec<String> = cfg.email.iter().map(|e| format!("mailto:{e}")).collect();
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, creds) = builder()?
        .create(&NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false }, directory.clone(), None)
        .await
        .with_context(|| format!("creating ACME account at {directory}"))?;
    std::fs::write(&path, serde_json::to_string(&creds)?)?;
    tracing::info!(%directory, "created ACME account");
    Ok(account)
}

type Reply = Result<IssueResponse, IssueResponse>;

impl Issuer {
    async fn issue(&self, peer: PeerId, req: IssueRequest) -> Reply {
        use IssueResponse as R;
        if req.proofs.is_empty() {
            return Err(R::fail(Error::EInvalidProof, "no proofs"));
        }
        let now = proof::now_ms();
        let mut ips = Vec::new();
        for p in &req.proofs {
            ips.extend(proof::verify(p, &self.proof_keys, &peer, now).map_err(|e| R::fail(Error::EInvalidProof, e.to_string()))?);
        }
        let csr = tlskey::parse_csr(&req.csr).map_err(|e| R::fail(Error::EInvalidRequest, format!("{e:#}")))?;
        let offered: Vec<Crypto> = req.supported_cryptos.iter().filter_map(|c| Crypto::try_from(*c).ok()).collect();
        if !self.cryptos.contains(&csr.crypto) || !offered.contains(&csr.crypto) {
            return Err(R::fail(Error::ENoMatchingCrypto, format!("CSR key is {}", tlskey::crypto_name(csr.crypto))));
        }
        let names = names::cert_names(&peer, &ips, &self.zone).map_err(|e| R::fail(Error::EInvalidRequest, e.to_string()))?;
        if names.iter().cloned().collect::<BTreeSet<_>>() != csr.names {
            return Err(R::fail(Error::EInvalidRequest, format!("CSR must name exactly {names:?}")));
        }

        let key = cache_key(&names, &csr.spki);
        let path = self.certs_dir.join(peer.to_string()).join(format!("{key}.json"));
        let lock = self.locks.lock().unwrap().entry(key.clone()).or_default().clone();
        let _guard = lock.lock().await;
        let result = self.cached_or_order(&path, &names, &req.csr, csr.crypto).await;
        {
            // drop the entry unless someone else is already waiting on it
            let mut locks = self.locks.lock().unwrap();
            if Arc::strong_count(&lock) <= 2 {
                locks.remove(&key);
            }
        }
        let (cached, from_cache) = result?;

        tracing::info!(%peer, ?names, from_cache, "certificate issued");
        let mut pems = cached.chain.split_inclusive("-----END CERTIFICATE-----");
        let cert = pems.next().unwrap_or_default().trim().to_owned() + "\n";
        let ca = pems.collect::<String>().trim().to_owned() + "\n";
        Ok(IssueResponse {
            error: Error::Ok as i32,
            cert: cert.into_bytes(),
            chain: cached.chain.into_bytes(),
            ca: ca.into_bytes(),
            cn: names[0].clone(),
            altnames: names[1..].to_vec(),
            validity: cached.not_after_ms,
            from_cache,
            crypto_type: cached.crypto,
            message: String::new(),
        })
    }

    async fn cached_or_order(&self, path: &Path, names: &[String], csr: &[u8], crypto: Crypto) -> Result<(Cached, bool), IssueResponse> {
        if let Some(c) = std::fs::read(path).ok().and_then(|b| serde_json::from_slice::<Cached>(&b).ok())
            && !tlskey::renew_due(c.not_before_ms, c.not_after_ms, proof::now_ms())
        {
            return Ok((c, true));
        }
        let chain = tokio::time::timeout(self.order_timeout, self.order(names, csr))
            .await
            .map_err(|_| IssueResponse::fail(Error::EOther, "ACME order timed out"))?
            .map_err(acme_error)?;
        let info = tlskey::parse_chain(&chain).map_err(|e| IssueResponse::fail(Error::EOther, format!("{e:#}")))?;
        let cached = Cached { chain, names: names.to_vec(), not_before_ms: info.not_before_ms, not_after_ms: info.not_after_ms, crypto: crypto as i32 };
        let write = || -> anyhow::Result<()> {
            std::fs::create_dir_all(path.parent().expect("cert path has parent"))?;
            std::fs::write(path, serde_json::to_vec(&cached)?)?;
            Ok(())
        };
        if let Err(e) = write() {
            tracing::warn!(path = %path.display(), "caching certificate: {e:#}");
        }
        Ok((cached, false))
    }

    async fn order(&self, names: &[String], csr: &[u8]) -> anyhow::Result<String> {
        let ids: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
        let mut order = self.account.new_order(&NewOrder::new(&ids)).await?;
        let mut authzs = order.authorizations();
        while let Some(authz) = authzs.next().await {
            let mut authz = authz?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                s => bail!("authorization is {s:?}"),
            }
            let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| anyhow!("CA offered no dns-01 challenge"))?;
            let fqdn = challenge.identifier().to_string();
            self.set_dns01(&fqdn, &challenge.key_authorization().dns_value()).await?;
            challenge.set_ready().await?;
        }
        let retry = RetryPolicy::new().timeout(self.order_timeout);
        let status = order.poll_ready(&retry).await?;
        if status != OrderStatus::Ready {
            bail!("order is {status:?}");
        }
        order.finalize_csr(csr).await?;
        Ok(order.poll_certificate(&retry).await?)
    }

    /// Publishes the challenge on every configured DNS server; all must accept.
    async fn set_dns01(&self, fqdn: &str, value: &str) -> anyhow::Result<()> {
        let req = Dns01Request { fqdn: fqdn.to_owned(), value: value.to_owned() };
        for addr in &self.dns {
            let resp: Dns01Response = self.node.request(addr, DNS01_PROTOCOL, &req).await?;
            if resp.error != Error::Ok as i32 {
                bail!("dns server {addr} refused dns-01 for {fqdn}: {:?}", Error::try_from(resp.error));
            }
        }
        Ok(())
    }
}

fn acme_error(e: anyhow::Error) -> IssueResponse {
    let rate_limited = e
        .downcast_ref::<instant_acme::Error>()
        .is_some_and(|e| matches!(e, instant_acme::Error::Api(p) if p.r#type.as_deref() == Some("urn:ietf:params:acme:error:rateLimited")));
    IssueResponse::fail(if rate_limited { Error::ERateLimit } else { Error::EOther }, format!("{e:#}"))
}

fn cache_key(names: &[String], spki: &[u8]) -> String {
    let mut sorted = names.to_vec();
    sorted.sort();
    let mut h = Sha256::new();
    h.update(sorted.join("!"));
    h.update(spki);
    hex::encode(h.finalize())
}

/// Deletes expired certificates and empty peer directories.
fn gc(dir: &Path, now: i64) -> anyhow::Result<()> {
    let Ok(peers) = std::fs::read_dir(dir) else { return Ok(()) };
    let (mut removed, mut kept) = (0, 0);
    for peer in peers {
        let peer = peer?.path();
        for cert in std::fs::read_dir(&peer)? {
            let cert = cert?.path();
            let expired = std::fs::read(&cert)
                .ok()
                .and_then(|b| serde_json::from_slice::<Cached>(&b).ok())
                .is_none_or(|c| c.not_after_ms <= now);
            if expired {
                std::fs::remove_file(&cert)?;
                removed += 1;
            } else {
                kept += 1;
            }
        }
        if std::fs::read_dir(&peer)?.next().is_none() {
            std::fs::remove_dir(&peer)?;
        }
    }
    tracing::info!(removed, kept, "cache gc");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_removes_expired() {
        let dir = std::env::temp_dir().join(format!("nodetrust-gc-{}", std::process::id()));
        let peer = dir.join("peer");
        std::fs::create_dir_all(&peer).unwrap();
        let c = |after| serde_json::to_vec(&Cached { chain: String::new(), names: vec![], not_before_ms: 0, not_after_ms: after, crypto: 2 }).unwrap();
        std::fs::write(peer.join("old.json"), c(10)).unwrap();
        std::fs::write(peer.join("new.json"), c(1000)).unwrap();
        gc(&dir, 100).unwrap();
        assert!(!peer.join("old.json").exists() && peer.join("new.json").exists());
        gc(&dir, 2000).unwrap();
        assert!(!peer.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cache_key_is_order_independent() {
        let a = vec!["a".to_string(), "b".to_string()];
        let b = vec!["b".to_string(), "a".to_string()];
        assert_eq!(cache_key(&a, b"k"), cache_key(&b, b"k"));
        assert_ne!(cache_key(&a, b"k"), cache_key(&a, b"j"));
    }
}

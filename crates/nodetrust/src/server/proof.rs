//! Proof service: signs the TCP source addresses a peer is connected from.

use libp2p::identity::Keypair;

use crate::{
    node::{Node, tcp_ip},
    proof,
    proto::{Error, PROOF_PROTOCOL, ProofRequest, ProofResponse},
};

pub fn run(node: &Node, key: Keypair) -> anyhow::Result<()> {
    tracing::info!(proof_key = %crate::server::public_key_b64(&key), "proof service ready");
    let conns = node.conn_addrs.clone();
    node.serve(PROOF_PROTOCOL, move |peer, _: ProofRequest| {
        let mut ips: Vec<_> =
            conns.lock().unwrap().get(&peer).map(|c| c.values().filter_map(tcp_ip).collect()).unwrap_or_default();
        ips.sort();
        ips.dedup();
        let resp = if ips.is_empty() {
            tracing::info!(%peer, "proof refused: no plain TCP connection");
            ProofResponse { error: Error::EInvalidRequest as i32, proof: None }
        } else {
            match proof::sign(&key, &peer, &ips, proof::now_ms()) {
                Ok(p) => {
                    tracing::info!(%peer, ?ips, "proof created");
                    ProofResponse { error: Error::Ok as i32, proof: Some(p) }
                }
                Err(e) => {
                    tracing::error!(%peer, "signing proof: {e}");
                    ProofResponse { error: Error::EOther as i32, proof: None }
                }
            }
        };
        async move { resp }
    })
}

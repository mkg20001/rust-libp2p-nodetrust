//! Address proofs: a proof server attests "peer X connected from IPs Y at time T".

use std::net::IpAddr;

use libp2p::{
    PeerId,
    identity::{Keypair, PublicKey},
};
use prost::Message;

use crate::proto::{Address, AddressType, Proof, ProofWrapper};

/// A proof is accepted within this many ms of its timestamp (either direction).
pub const VALIDITY_MS: i64 = 5 * 60 * 1000;

pub fn now_ms() -> i64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn sign(key: &Keypair, peer: &PeerId, ips: &[IpAddr], now: i64) -> Result<ProofWrapper, ProofError> {
    let proof = Proof {
        id: peer.to_bytes(),
        timestamp: now,
        addrs: ips
            .iter()
            .map(|ip| Address {
                r#type: match ip {
                    IpAddr::V4(_) => AddressType::IPv4,
                    IpAddr::V6(_) => AddressType::IPv6,
                } as i32,
                address: ip.to_string(),
            })
            .collect(),
    }
    .encode_to_vec();
    let signature = key.sign(&proof).map_err(|_| ProofError::Signing)?;
    Ok(ProofWrapper { proof, signature })
}

/// Checks signature (against any trusted key), freshness and that it was issued to `peer`.
pub fn verify(w: &ProofWrapper, trusted: &[PublicKey], peer: &PeerId, now: i64) -> Result<Vec<IpAddr>, ProofError> {
    if !trusted.iter().any(|k| k.verify(&w.proof, &w.signature)) {
        return Err(ProofError::Signature);
    }
    let proof = Proof::decode(w.proof.as_slice()).map_err(|_| ProofError::Malformed)?;
    if (proof.timestamp - now).abs() > VALIDITY_MS {
        return Err(ProofError::Expired);
    }
    if PeerId::from_bytes(&proof.id).ok().as_ref() != Some(peer) {
        return Err(ProofError::WrongPeer);
    }
    proof
        .addrs
        .iter()
        .map(|a| {
            let ip: IpAddr = a.address.parse().map_err(|_| ProofError::Malformed)?;
            let ty = match ip {
                IpAddr::V4(_) => AddressType::IPv4,
                IpAddr::V6(_) => AddressType::IPv6,
            };
            if a.r#type != ty as i32 {
                return Err(ProofError::Malformed);
            }
            Ok(ip)
        })
        .collect()
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ProofError {
    #[error("signing failed")]
    Signing,
    #[error("signature not from a trusted proof key")]
    Signature,
    #[error("malformed proof")]
    Malformed,
    #[error("proof expired")]
    Expired,
    #[error("proof was issued to another peer")]
    WrongPeer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_rules() {
        let key = Keypair::generate_ed25519();
        let trusted = [key.public()];
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let now = now_ms();
        let w = sign(&key, &peer, &ips, now).unwrap();

        assert_eq!(verify(&w, &trusted, &peer, now + 1000), Ok(ips));
        assert_eq!(verify(&w, &trusted, &other, now), Err(ProofError::WrongPeer));
        assert_eq!(verify(&w, &trusted, &peer, now + VALIDITY_MS + 1), Err(ProofError::Expired));
        assert_eq!(verify(&w, &[Keypair::generate_ed25519().public()], &peer, now), Err(ProofError::Signature));
        let mut tampered = w.clone();
        tampered.proof[3] ^= 1;
        assert_eq!(verify(&tampered, &trusted, &peer, now), Err(ProofError::Signature));
    }
}

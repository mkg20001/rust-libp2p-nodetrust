//! The three nodetrust services. Each runs on its own libp2p node (they may share a host).

pub mod dns;
pub mod issue;
pub mod proof;

use base64::Engine;
use libp2p::identity::{Keypair, PublicKey};

/// Base64 protobuf encoding of a public key, as used in `issue.proof_keys`.
pub fn public_key_b64(key: &Keypair) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.public().encode_protobuf())
}

pub fn parse_public_key(s: &str) -> anyhow::Result<PublicKey> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s.trim())?;
    Ok(PublicKey::try_decode_protobuf(&bytes)?)
}

//! Pubsub discovery: nodes with a certificate periodically announce their WSS addresses on
//! [`DISCOVERY_TOPIC`]; servers subscribe so they relay announcements between clients.

use std::time::Duration;

use libp2p::{Multiaddr, gossipsub, identity::Keypair, multiaddr::Protocol};
use prost::Message;

use crate::proto::{Announce, DISCOVERY_TOPIC};

pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(10);

pub fn topic() -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(DISCOVERY_TOPIC)
}

pub fn gossipsub(key: &Keypair) -> Result<gossipsub::Behaviour, String> {
    let config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .flood_publish(true)
        .build()
        .map_err(|e| e.to_string())?;
    gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(key.clone()), config).map_err(str::to_owned)
}

pub fn encode(addrs: &[Multiaddr]) -> Vec<u8> {
    Announce { addr: addrs.iter().map(|a| a.to_vec()).collect() }.encode_to_vec()
}

/// Decoded addresses without any trailing `/p2p` (the sender is the message source).
pub fn decode(data: &[u8]) -> Option<Vec<Multiaddr>> {
    let msg = Announce::decode(data).ok()?;
    msg.addr
        .into_iter()
        .map(|b| {
            let mut a = Multiaddr::try_from(b).ok()?;
            if matches!(a.iter().last(), Some(Protocol::P2p(_))) {
                a.pop();
            }
            Some(a)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let a: libp2p::Multiaddr = "/dns4/ip4-1-2-3-4.nt.test/tcp/4443/tls/ws".parse().unwrap();
        let with_p2p = a.clone().with(libp2p::multiaddr::Protocol::P2p(libp2p::PeerId::random()));
        assert_eq!(super::decode(&super::encode(&[a.clone(), with_p2p])), Some(vec![a.clone(), a]));
        assert_eq!(super::decode(b"\x0a\x02\xff\xff"), None);
    }
}

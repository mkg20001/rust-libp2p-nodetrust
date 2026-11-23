//! DNS label <-> IP / peer id mapping.
//!
//! * `ip4-1-2-3-4.<zone>` → `A 1.2.3.4`
//! * `ip6-2001-db8-0-0-0-0-0-1.<zone>` → `AAAA 2001:db8::1` (issued fully expanded: a compressed
//!   address can start or end with `-`, which is not a valid hostname label)
//! * `p<base36 peer id>.<zone>` → `TXT "id=<peer id>"` (the "id0" name, used as certificate CN)
//!
//! Decoding also accepts the v1 forms without the dash after the prefix (`ip41-2-3-4`, `ip6--1`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::PeerId;
use multibase::Base;

pub const MAX_LABEL: usize = 63;

pub fn ip_label(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("ip4-{}", v4.to_string().replace('.', "-")),
        IpAddr::V6(v6) => {
            let segs: Vec<String> = v6.segments().iter().map(|s| format!("{s:x}")).collect();
            format!("ip6-{}", segs.join("-"))
        }
    }
}

pub fn parse_ip_label(label: &str) -> Option<IpAddr> {
    let label = label.to_ascii_lowercase();
    if let Some(rest) = label.strip_prefix("ip4") {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        return rest.replace('-', ".").parse::<Ipv4Addr>().ok().map(IpAddr::V4);
    }
    let rest = label.strip_prefix("ip6")?;
    // try "ip6-<addr>" first, then the v1 "ip6<addr>" form (where "ip6--1" is "::1")
    [rest.strip_prefix('-'), Some(rest)]
        .into_iter()
        .flatten()
        .find_map(|r| r.replace('-', ":").parse::<Ipv6Addr>().ok())
        .map(IpAddr::V6)
}

pub fn id_label(peer: &PeerId) -> Result<String, NameError> {
    let label = format!("p{}", Base::Base36Lower.encode(peer.to_bytes()));
    if label.len() > MAX_LABEL {
        return Err(NameError::TooLong(label.len()));
    }
    Ok(label)
}

pub fn parse_id_label(label: &str) -> Option<PeerId> {
    let rest = label.to_ascii_lowercase();
    let rest = rest.strip_prefix('p')?;
    PeerId::from_bytes(&Base::Base36Lower.decode(rest).ok()?).ok()
}

/// `label.zone`, lower-cased, without trailing dot.
pub fn fqdn(label: &str, zone: &str) -> String {
    format!("{label}.{}", zone.trim_end_matches('.')).to_ascii_lowercase()
}

/// The certificate names for a peer: `[id0, ipN...]`, deduplicated, CN first.
pub fn cert_names(peer: &PeerId, ips: &[IpAddr], zone: &str) -> Result<Vec<String>, NameError> {
    let mut names = vec![fqdn(&id_label(peer)?, zone)];
    for ip in ips {
        let n = fqdn(&ip_label(*ip), zone);
        if !names.contains(&n) {
            names.push(n);
        }
    }
    Ok(names)
}

#[derive(Debug, thiserror::Error)]
pub enum NameError {
    #[error("peer id label is {0} chars, DNS allows {MAX_LABEL}")]
    TooLong(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_roundtrip() {
        for ip in ["127.0.0.1", "8.8.8.8", "::1", "2001:db8::", "fe80::1:2", "::"] {
            let ip: IpAddr = ip.parse().unwrap();
            let label = ip_label(ip);
            assert!(!label.ends_with('-') && label.len() <= MAX_LABEL, "{label}");
            assert_eq!(parse_ip_label(&label), Some(ip), "{label}");
        }
        assert_eq!(ip_label("::1".parse().unwrap()), "ip6-0-0-0-0-0-0-0-1");
    }

    #[test]
    fn v1_forms_and_garbage() {
        assert_eq!(parse_ip_label("ip4127-0-0-1"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(parse_ip_label("IP48-8-8-8"), Some("8.8.8.8".parse().unwrap()));
        assert_eq!(parse_ip_label("ip6--1"), Some("::1".parse().unwrap()));
        assert_eq!(parse_ip_label("ip4-1-2-3"), None);
        assert_eq!(parse_ip_label("ip4-1-2-3-999"), None);
        assert_eq!(parse_ip_label("www"), None);
        assert_eq!(parse_id_label("pzzzz"), None);
    }

    #[test]
    fn id_roundtrip() {
        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let label = id_label(&peer).unwrap();
        assert!(label.len() <= MAX_LABEL);
        assert_eq!(parse_id_label(&label.to_uppercase()), Some(peer));
        let names = cert_names(&peer, &["1.2.3.4".parse().unwrap(); 2], "NT.test.").unwrap();
        assert_eq!(names, vec![format!("{label}.nt.test"), "ip4-1-2-3-4.nt.test".into()]);
    }
}

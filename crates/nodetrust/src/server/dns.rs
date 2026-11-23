//! Authoritative DNS for the nodetrust zone plus the `/dns-01` libp2p service that lets issue
//! servers publish ACME challenges.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use hickory_server::{
    net::runtime::Time,
    proto::{
        op::{Header, HeaderCounts, Metadata, ResponseCode},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{A, AAAA, HINFO, NS, SOA, TXT},
        },
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use libp2p::PeerId;

use crate::{
    config::DnsConfig,
    names,
    node::Node,
    proto::{DNS01_PROTOCOL, Dns01Request, Dns01Response, Error},
};

/// DNS-01 values per challenge name; several may coexist (parallel orders for the same name).
#[derive(Clone, Default)]
pub struct Challenges(Arc<Mutex<HashMap<String, Vec<(String, Instant)>>>>);

impl Challenges {
    pub fn set(&self, fqdn: &str, value: &str, ttl: Duration) {
        let mut map = self.0.lock().unwrap();
        let now = Instant::now();
        let entry = map.entry(fqdn.to_ascii_lowercase()).or_default();
        entry.retain(|(v, exp)| *exp > now && v != value);
        entry.push((value.to_owned(), now + ttl));
    }

    pub fn get(&self, fqdn: &str) -> Vec<String> {
        let mut map = self.0.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, v| {
            v.retain(|(_, exp)| *exp > now);
            !v.is_empty()
        });
        map.get(fqdn).map(|v| v.iter().map(|(s, _)| s.clone()).collect()).unwrap_or_default()
    }
}

pub struct Zone {
    apex: Name,
    ns: Vec<Name>,
    hostmaster: Name,
    ttl: u32,
    txt_ttl: u32,
    records: HashMap<String, Vec<IpAddr>>,
    pub challenges: Challenges,
}

#[derive(Debug, PartialEq)]
pub struct Answer {
    pub code: ResponseCode,
    pub answers: Vec<Record>,
    /// SOA for negative answers
    pub soa: Vec<Record>,
}

fn fqdn_name(s: &str) -> anyhow::Result<Name> {
    let mut n = Name::from_ascii(s.trim_end_matches('.').to_ascii_lowercase()).with_context(|| format!("bad name {s}"))?;
    n.set_fqdn(true);
    Ok(n)
}

impl Zone {
    pub fn new(cfg: &DnsConfig) -> anyhow::Result<Self> {
        let apex = fqdn_name(&cfg.zone)?;
        let hostmaster = match &cfg.hostmaster {
            Some(h) => fqdn_name(h)?,
            None => fqdn_name(&format!("hostmaster.{}", cfg.zone))?,
        };
        Ok(Self {
            apex,
            ns: cfg.ns.iter().map(|n| fqdn_name(n)).collect::<anyhow::Result<_>>()?,
            hostmaster,
            ttl: cfg.ttl,
            txt_ttl: cfg.txt_ttl,
            records: cfg.records.iter().map(|(k, v)| (k.trim_end_matches('.').to_ascii_lowercase(), v.clone())).collect(),
            challenges: Challenges::default(),
        })
    }

    /// `name` is inside the zone (or the apex itself).
    pub fn contains(&self, name: &str) -> bool {
        fqdn_name(name).is_ok_and(|n| self.apex.zone_of(&n))
    }

    fn soa(&self) -> Record {
        let serial = (crate::proof::now_ms() / 1000) as u32;
        let soa = SOA::new(self.ns[0].clone(), self.hostmaster.clone(), serial, 3600, 600, 86400, 60);
        Record::from_rdata(self.apex.clone(), 60, RData::SOA(soa))
    }

    pub fn lookup(&self, name: &Name, qtype: RecordType) -> Answer {
        let ok = |answers| Answer { code: ResponseCode::NoError, answers, soa: vec![] };
        let nodata = || Answer { code: ResponseCode::NoError, answers: vec![], soa: vec![self.soa()] };
        let nxdomain = || Answer { code: ResponseCode::NXDomain, answers: vec![], soa: vec![self.soa()] };
        let mut name = name.to_lowercase();
        name.set_fqdn(true);
        if !self.apex.zone_of(&name) {
            return Answer { code: ResponseCode::Refused, answers: vec![], soa: vec![] };
        }
        if qtype == RecordType::ANY {
            // RFC 8482
            return ok(vec![Record::from_rdata(name, self.ttl, RData::HINFO(HINFO::new("RFC8482".into(), String::new())))]);
        }
        let key = name.to_ascii().trim_end_matches('.').to_owned();
        let rec = |rdata| Record::from_rdata(name.clone(), self.ttl, rdata);
        let ips = |ips: &[IpAddr]| -> Vec<Record> {
            ips.iter()
                .filter_map(|ip| match (ip, qtype) {
                    (IpAddr::V4(v4), RecordType::A) => Some(rec(RData::A(A(*v4)))),
                    (IpAddr::V6(v6), RecordType::AAAA) => Some(rec(RData::AAAA(AAAA(*v6)))),
                    _ => None,
                })
                .collect()
        };

        if name == self.apex {
            return match qtype {
                RecordType::SOA => ok(vec![self.soa()]),
                RecordType::NS => ok(self.ns.iter().map(|ns| rec(RData::NS(NS(ns.clone())))).collect()),
                _ => match self.records.get(&key) {
                    Some(v) if !ips(v).is_empty() => ok(ips(v)),
                    _ => nodata(),
                },
            };
        }

        let challenges = self.challenges.get(&key);
        if !challenges.is_empty() {
            return match qtype {
                RecordType::TXT => ok(challenges
                    .into_iter()
                    .map(|v| Record::from_rdata(name.clone(), self.txt_ttl, RData::TXT(TXT::new(vec![v]))))
                    .collect()),
                _ => nodata(),
            };
        }
        if let Some(v) = self.records.get(&key) {
            let r = ips(v);
            return if r.is_empty() { nodata() } else { ok(r) };
        }
        // dynamic names are exactly one label below the apex
        if name.num_labels() != self.apex.num_labels() + 1 {
            return nxdomain();
        }
        let label = String::from_utf8_lossy(name.iter().next().unwrap_or_default()).into_owned();
        if let Some(ip) = names::parse_ip_label(&label) {
            let r = ips(&[ip]);
            return if r.is_empty() { nodata() } else { ok(r) };
        }
        if let Some(peer) = names::parse_id_label(&label) {
            return match qtype {
                RecordType::TXT => ok(vec![rec(RData::TXT(TXT::new(vec![format!("id={peer}")])))]),
                _ => nodata(),
            };
        }
        nxdomain()
    }
}

pub struct Handler(pub Arc<Zone>);

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(&self, request: &Request, mut response: R) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut meta = Metadata::response_from_request(&request.metadata);
        let fail = |mut meta: Metadata, code| {
            meta.response_code = code;
            ResponseInfo::from(Header { metadata: meta, counts: HeaderCounts::default() })
        };
        let info = match request.request_info() {
            Ok(info) => info,
            Err(_) => {
                let msg = builder.error_msg(&request.metadata, ResponseCode::FormErr);
                return response.send_response(msg).await.unwrap_or_else(|_| fail(meta, ResponseCode::FormErr));
            }
        };
        let qname: Name = Name::from(info.query.name().clone());
        let qtype = info.query.query_type();
        let answer = self.0.lookup(&qname, qtype);
        tracing::info!(src = %request.src(), name = %qname, %qtype, code = %answer.code, answers = answer.answers.len(), "query");
        meta.response_code = answer.code;
        meta.authoritative = answer.code != ResponseCode::Refused;
        meta.recursion_available = false;
        let msg = builder.build(meta, answer.answers.iter(), std::iter::empty(), answer.soa.iter(), std::iter::empty());
        match response.send_response(msg).await {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("sending DNS response: {e}");
                fail(meta, ResponseCode::ServFail)
            }
        }
    }
}

/// Start the DNS listeners and the `/dns-01` service. Runs until the process exits.
pub async fn run(node: Node, cfg: DnsConfig) -> anyhow::Result<()> {
    let zone = Arc::new(Zone::new(&cfg)?);
    let admins: Vec<PeerId> = cfg.admins.iter().map(|a| a.parse().with_context(|| format!("admin {a}"))).collect::<anyhow::Result<_>>()?;
    let txt_ttl = Duration::from_secs(cfg.txt_ttl.into());

    let z = zone.clone();
    node.serve(DNS01_PROTOCOL, move |peer, req: Dns01Request| {
        let error = dns01(&z, &admins, peer, &req, txt_ttl);
        async move { Dns01Response { error: error as i32 } }
    })?;

    let mut server = hickory_server::Server::new(Handler(zone));
    for addr in &cfg.listen {
        server.register_socket(tokio::net::UdpSocket::bind(addr).await.with_context(|| format!("bind udp {addr}"))?);
        let tcp = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("bind tcp {addr}"))?;
        server.register_listener(tcp, Duration::from_secs(5), 4096);
        tracing::info!(%addr, zone = %cfg.zone, "dns listening");
    }
    server.block_until_done().await?;
    Ok(())
}

fn dns01(zone: &Zone, admins: &[PeerId], peer: PeerId, req: &Dns01Request, ttl: Duration) -> Error {
    if !admins.contains(&peer) {
        tracing::warn!(%peer, fqdn = %req.fqdn, "dns-01 from unauthorized peer");
        return Error::ENotAuthorized;
    }
    let fqdn = format!("_acme-challenge.{}", req.fqdn.trim_end_matches('.')).to_ascii_lowercase();
    if !zone.contains(&req.fqdn) || req.value.is_empty() || req.value.len() > 255 {
        tracing::warn!(%peer, %fqdn, "dns-01 outside zone or bad value");
        return Error::EInvalidRequest;
    }
    tracing::info!(%peer, %fqdn, "dns-01 challenge set");
    zone.challenges.set(&fqdn, &req.value, ttl);
    Error::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Zone {
        Zone::new(&DnsConfig {
            listen: vec![],
            zone: "nt.test".into(),
            ns: vec!["ns1.nt.test".into()],
            hostmaster: None,
            admins: vec![],
            ttl: 100,
            txt_ttl: 10,
            records: [("ns1.nt.test".to_string(), vec!["192.168.1.1".parse().unwrap()])].into(),
        })
        .unwrap()
    }

    fn q(z: &Zone, name: &str, t: RecordType) -> Answer {
        z.lookup(&Name::from_ascii(name).unwrap(), t)
    }

    fn data(a: &Answer) -> Vec<String> {
        a.answers.iter().map(|r| r.data().to_string()).collect()
    }

    #[test]
    fn records() {
        let z = zone();
        assert_eq!(data(&q(&z, "IP4-8-8-8-8.Nt.Test.", RecordType::A)), vec!["8.8.8.8"]);
        assert_eq!(data(&q(&z, "ip48-8-8-8.nt.test", RecordType::A)), vec!["8.8.8.8"]);
        assert_eq!(data(&q(&z, "ip6-0-0-0-0-0-0-0-1.nt.test", RecordType::AAAA)), vec!["::1"]);
        let nodata = q(&z, "ip4-8-8-8-8.nt.test", RecordType::AAAA);
        assert!(nodata.code == ResponseCode::NoError && nodata.answers.is_empty() && nodata.soa.len() == 1);
        assert_eq!(q(&z, "junk.nt.test", RecordType::A).code, ResponseCode::NXDomain);
        assert_eq!(q(&z, "a.ip4-8-8-8-8.nt.test", RecordType::A).code, ResponseCode::NXDomain);
        assert_eq!(q(&z, "example.org", RecordType::A).code, ResponseCode::Refused);
        assert_eq!(data(&q(&z, "ns1.nt.test", RecordType::A)), vec!["192.168.1.1"]);
        assert_eq!(data(&q(&z, "nt.test", RecordType::NS)), vec!["ns1.nt.test."]);
        assert_eq!(q(&z, "nt.test", RecordType::SOA).answers.len(), 1);
        assert_eq!(q(&z, "x.nt.test", RecordType::ANY).answers[0].record_type(), RecordType::HINFO);

        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let id = format!("{}.nt.test", names::id_label(&peer).unwrap());
        assert_eq!(data(&q(&z, &id, RecordType::TXT)), vec![format!("id={peer}")]);
    }

    #[test]
    fn dns01_rules() {
        let z = zone();
        let admin = PeerId::random();
        let req = |fqdn: &str| Dns01Request { fqdn: fqdn.into(), value: "tok".into() };
        let ttl = Duration::from_secs(10);
        assert_eq!(dns01(&z, &[admin], PeerId::random(), &req("ip4-1-2-3-4.nt.test"), ttl), Error::ENotAuthorized);
        assert_eq!(dns01(&z, &[admin], admin, &req("evil.org"), ttl), Error::EInvalidRequest);
        assert_eq!(dns01(&z, &[admin], admin, &req("ip4-1-2-3-4.nt.test"), ttl), Error::Ok);
        assert_eq!(dns01(&z, &[admin], admin, &Dns01Request { fqdn: "ip4-1-2-3-4.nt.test".into(), value: "two".into() }, ttl), Error::Ok);
        let a = q(&z, "_acme-challenge.ip4-1-2-3-4.nt.test", RecordType::TXT);
        assert_eq!(data(&a), vec!["tok", "two"]);
        z.challenges.set("_acme-challenge.x.nt.test", "gone", Duration::ZERO);
        assert_eq!(q(&z, "_acme-challenge.x.nt.test", RecordType::TXT).code, ResponseCode::NXDomain);
    }
}

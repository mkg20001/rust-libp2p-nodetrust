//! Wire messages. Mirrors `proto/nodetrust.proto` (hand-derived so no protoc is needed).

use libp2p::StreamProtocol;

pub const PROOF_PROTOCOL: StreamProtocol = StreamProtocol::new("/nodetrust/proof/2.0.0");
pub const INFO_PROTOCOL: StreamProtocol = StreamProtocol::new("/nodetrust/issue/info/2.0.0");
pub const ISSUE_PROTOCOL: StreamProtocol = StreamProtocol::new("/nodetrust/issue/2.0.0");
pub const DNS01_PROTOCOL: StreamProtocol = StreamProtocol::new("/nodetrust/dns-01/2.0.0");
pub const DISCOVERY_TOPIC: &str = "_nodetrust_discovery_v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Error {
    Ok = 0,
    ERateLimit = 1,
    EInvalidProof = 2,
    ENotAuthorized = 3,
    ENoMatchingCrypto = 4,
    EInvalidRequest = 5,
    EOther = 9,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Crypto {
    CryptoUnknown = 0,
    Rsa = 1,
    EcdsaP256 = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum AddressType {
    AddressUnknown = 0,
    IPv4 = 1,
    IPv6 = 2,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Address {
    #[prost(enumeration = "AddressType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub address: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Proof {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(int64, tag = "2")]
    pub timestamp: i64,
    #[prost(message, repeated, tag = "3")]
    pub addrs: Vec<Address>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ProofWrapper {
    #[prost(bytes = "vec", tag = "1")]
    pub proof: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ProofServer {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub addrs: Vec<Vec<u8>>,
    #[prost(string, tag = "3")]
    pub display: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ProofRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ProofResponse {
    #[prost(enumeration = "Error", tag = "1")]
    pub error: i32,
    #[prost(message, optional, tag = "2")]
    pub proof: Option<ProofWrapper>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct IssueInfoRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct IssueInfo {
    #[prost(string, tag = "1")]
    pub domain: String,
    #[prost(message, repeated, tag = "2")]
    pub proofs: Vec<ProofServer>,
    #[prost(enumeration = "Crypto", repeated, tag = "3")]
    pub supported_cryptos: Vec<i32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct IssueRequest {
    #[prost(message, repeated, tag = "1")]
    pub proofs: Vec<ProofWrapper>,
    #[prost(enumeration = "Crypto", repeated, tag = "2")]
    pub supported_cryptos: Vec<i32>,
    #[prost(bytes = "vec", tag = "3")]
    pub csr: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct IssueResponse {
    #[prost(enumeration = "Error", tag = "1")]
    pub error: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub cert: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub chain: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub ca: Vec<u8>,
    #[prost(string, tag = "6")]
    pub cn: String,
    #[prost(string, repeated, tag = "7")]
    pub altnames: Vec<String>,
    #[prost(int64, tag = "8")]
    pub validity: i64,
    #[prost(bool, tag = "9")]
    pub from_cache: bool,
    #[prost(enumeration = "Crypto", tag = "10")]
    pub crypto_type: i32,
    #[prost(string, tag = "11")]
    pub message: String,
}

impl IssueResponse {
    pub fn fail(error: Error, message: impl Into<String>) -> Self {
        Self { error: error as i32, message: message.into(), ..Default::default() }
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Dns01Request {
    #[prost(string, tag = "1")]
    pub fqdn: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Dns01Response {
    #[prost(enumeration = "Error", tag = "1")]
    pub error: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Announce {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub addr: Vec<Vec<u8>>,
}

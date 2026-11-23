//! Certificate keys, CSRs and certificate inspection.

use std::collections::BTreeSet;

use anyhow::{Context, anyhow, bail};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use x509_parser::{
    certification_request::X509CertificationRequest,
    extensions::{GeneralName, ParsedExtension},
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSAENCRYPTION},
    prelude::FromDer,
};

use crate::proto::Crypto;

pub fn crypto_name(c: Crypto) -> &'static str {
    match c {
        Crypto::Rsa => "rsa",
        Crypto::EcdsaP256 => "ecdsa-p256",
        Crypto::CryptoUnknown => "unknown",
    }
}

pub fn parse_crypto(s: &str) -> anyhow::Result<Crypto> {
    match s {
        "rsa" => Ok(Crypto::Rsa),
        "ecdsa-p256" => Ok(Crypto::EcdsaP256),
        _ => bail!("unknown crypto {s:?} (expected rsa or ecdsa-p256)"),
    }
}

/// New private key as PKCS#8 PEM.
pub fn generate(crypto: Crypto) -> anyhow::Result<String> {
    match crypto {
        Crypto::EcdsaP256 => Ok(KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?.serialize_pem()),
        Crypto::Rsa => {
            use rsa::pkcs8::EncodePrivateKey;
            let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?;
            Ok(key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?.to_string())
        }
        Crypto::CryptoUnknown => bail!("no key type"),
    }
}

fn keypair(key_pem: &str) -> anyhow::Result<(KeyPair, Crypto)> {
    if let Ok(kp) = KeyPair::from_pem_and_sign_algo(key_pem, &rcgen::PKCS_ECDSA_P256_SHA256) {
        return Ok((kp, Crypto::EcdsaP256));
    }
    let kp = KeyPair::from_pem_and_sign_algo(key_pem, &rcgen::PKCS_RSA_SHA256).context("unsupported private key")?;
    Ok((kp, Crypto::Rsa))
}

pub fn key_crypto(key_pem: &str) -> anyhow::Result<Crypto> {
    Ok(keypair(key_pem)?.1)
}

/// DER PKCS#10 request for `names` (first one is the CN).
pub fn csr(key_pem: &str, names: &[String]) -> anyhow::Result<Vec<u8>> {
    let (kp, _) = keypair(key_pem)?;
    let mut params = CertificateParams::new(names.to_vec())?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, names.first().ok_or_else(|| anyhow!("no names"))?.as_str());
    Ok(params.serialize_request(&kp)?.der().to_vec())
}

pub struct CsrInfo {
    pub crypto: Crypto,
    pub names: BTreeSet<String>,
    /// DER SubjectPublicKeyInfo, identifies the key for caching
    pub spki: Vec<u8>,
}

/// Parses a CSR and checks its self-signature.
pub fn parse_csr(der: &[u8]) -> anyhow::Result<CsrInfo> {
    let (_, req) = X509CertificationRequest::from_der(der).map_err(|e| anyhow!("bad CSR: {e}"))?;
    req.verify_signature().map_err(|e| anyhow!("bad CSR signature: {e}"))?;
    let spki = &req.certification_request_info.subject_pki;
    let alg = &spki.algorithm;
    let crypto = if alg.algorithm == OID_PKCS1_RSAENCRYPTION {
        Crypto::Rsa
    } else if alg.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && alg.parameters.as_ref().and_then(|p| p.as_oid().ok()).as_ref() == Some(&OID_EC_P256)
    {
        Crypto::EcdsaP256
    } else {
        bail!("unsupported CSR key algorithm {}", alg.algorithm);
    };
    let mut names = BTreeSet::new();
    for ext in req.requested_extensions().into_iter().flatten() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext {
            for n in &san.general_names {
                match n {
                    GeneralName::DNSName(d) => names.insert(d.to_ascii_lowercase()),
                    other => bail!("unsupported CSR name {other:?}"),
                };
            }
        }
    }
    Ok(CsrInfo { crypto, names, spki: spki.raw.to_vec() })
}

pub struct CertInfo {
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub names: Vec<String>,
    pub issuer: String,
}

/// Inspects the first certificate of a PEM chain.
pub fn parse_chain(pem: &str) -> anyhow::Result<CertInfo> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow!("bad PEM: {e}"))?;
    let cert = pem.parse_x509().map_err(|e| anyhow!("bad certificate: {e}"))?;
    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(CertInfo {
        not_before_ms: cert.validity().not_before.timestamp() * 1000,
        not_after_ms: cert.validity().not_after.timestamp() * 1000,
        names,
        issuer: cert.issuer().to_string(),
    })
}

/// Renew once less than a third of the lifetime is left (scales from 90 day to 5 minute certs).
pub fn renew_due(not_before_ms: i64, not_after_ms: i64, now_ms: i64) -> bool {
    now_ms >= not_after_ms - (not_after_ms - not_before_ms) / 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_roundtrip() {
        let names = vec!["pabc.nt.test".to_string(), "ip4-1-2-3-4.nt.test".to_string()];
        for crypto in [Crypto::EcdsaP256, Crypto::Rsa] {
            let key = generate(crypto).unwrap();
            assert_eq!(key_crypto(&key).unwrap(), crypto);
            let info = parse_csr(&csr(&key, &names).unwrap()).unwrap();
            assert_eq!(info.crypto, crypto);
            assert_eq!(info.names, names.iter().cloned().collect());
        }
        assert!(parse_csr(b"junk").is_err());
    }

    #[test]
    fn renewal_threshold() {
        assert!(!renew_due(0, 300, 199));
        assert!(renew_due(0, 300, 200));
    }
}

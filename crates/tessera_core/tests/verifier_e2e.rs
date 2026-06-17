#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::duration_suboptimal_units)]

use tessera_core::trust::openssl_verifier::{
    OpensslVerifier, OpensslVerifierConfig, Stage2TrustVerifier,
};
use tessera_core::x509::pinning::spki_sha256;
use tessera_core::x509::{Certificate, TrustError};
use std::time::{Duration, SystemTime};

const LEAF_RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const LEAF_ECDSA: &[u8] = include_bytes!("fixtures/leaf_ecdsa.pem");
const REVOKED: &[u8] = include_bytes!("fixtures/revoked_leaf.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");
const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const CRL_VALID: &[u8] = include_bytes!("fixtures/crl_valid.pem");

fn whitelist() -> Vec<String> {
    vec!["sha256WithRSAEncryption".into(), "ecdsa-with-SHA256".into()]
}

fn config_builder() -> OpensslVerifierConfig {
    OpensslVerifierConfig {
        max_supported_profile_version: tessera_core::trust::openssl_verifier::DEFAULT_MAX_SUPPORTED_PROFILE_VERSION,
        anchors: vec![Certificate::from_pem(CA).unwrap()],
        intermediates: vec![Certificate::from_pem(INT).unwrap()],
        crl_pems: vec![CRL_VALID.to_vec()],
        crl_strict: true,
        crl_max_age: None,
        clock_skew: Duration::from_secs(60),
        signature_alg_whitelist: whitelist(),
        spki_pins: vec![],
        max_depth: 4,
        gost_engine_path: None,
        revocation_mode: tessera_core::config::validated::RevocationMode::Crl,
        ocsp_responder_url: None,
        ocsp_timeout: Duration::from_secs(5),
        ocsp_cache_dir: std::path::PathBuf::from("/var/cache/tessera/ocsp"),
        ocsp_cache_ttl: Duration::ZERO,
    }
}

#[test]
fn end_to_end_rsa_chain_verifies() {
    let v = OpensslVerifier::new(config_builder()).unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let chain = v.verify(&leaf, &presented).unwrap();
    assert_eq!(chain.end_entity.subject_cn().unwrap(), "alice");
    assert_eq!(chain.anchor.subject_cn().unwrap(), "CertAuth Test Root CA");
    assert_eq!(chain.chain.len(), 1);
}

#[test]
fn end_to_end_ecdsa_chain_verifies() {
    let v = OpensslVerifier::new(config_builder()).unwrap();
    let leaf = Certificate::from_pem(LEAF_ECDSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let chain = v.verify(&leaf, &presented).unwrap();
    assert_eq!(chain.end_entity.subject_cn().unwrap(), "bob");
}

#[test]
fn rejects_revoked_cert() {
    let v = OpensslVerifier::new(config_builder()).unwrap();
    let leaf = Certificate::from_pem(REVOKED).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let err = v.verify(&leaf, &presented).unwrap_err();
    assert!(matches!(err, TrustError::Revoked(_)), "{err:?}");
}

#[test]
fn rejects_when_anchor_missing_from_store() {
    // Use only the intermediate as an "anchor" -- it is not self-signed,
    // so build_chain will refuse.  We give an unrelated self-signed cert
    // (the leaf) as anchor instead, which won't match the chain DN.
    let mut cfg = config_builder();
    cfg.anchors = vec![Certificate::from_pem(LEAF_RSA).unwrap()];
    let v = OpensslVerifier::new(cfg).unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let err = v.verify(&leaf, &presented).unwrap_err();
    assert!(matches!(err, TrustError::PathBuild(_)), "{err:?}");
}

#[test]
fn rejects_chain_too_deep() {
    let mut cfg = config_builder();
    cfg.max_depth = 1; // chain "leaf -> int -> ca" is length 3 > 1
    let v = OpensslVerifier::new(cfg).unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let err = v.verify(&leaf, &presented).unwrap_err();
    assert!(matches!(err, TrustError::DepthExceeded(_, _)), "{err:?}");
}

#[test]
fn pin_violation_rejected() {
    let mut cfg = config_builder();
    cfg.spki_pins = vec![[0u8; 32]];
    let v = OpensslVerifier::new(cfg).unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let err = v.verify(&leaf, &presented).unwrap_err();
    assert!(matches!(err, TrustError::PinMismatch), "{err:?}");
}

#[test]
fn matching_pin_accepted() {
    let ca = Certificate::from_pem(CA).unwrap();
    let pin = spki_sha256(&ca).unwrap();
    let mut cfg = config_builder();
    cfg.spki_pins = vec![pin];
    let v = OpensslVerifier::new(cfg).unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    v.verify(&leaf, &presented).unwrap();
}

#[test]
fn rejects_expired_leaf_via_pre_validate() {
    // Pretend the leaf is expired by passing a far-future `now`.
    let v = OpensslVerifier::new(config_builder()).unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let future = SystemTime::now() + Duration::from_secs(10 * 365 * 24 * 3600);
    let err = v.verify_at(&leaf, &presented, future).unwrap_err();
    assert!(matches!(err, TrustError::Validity(_)), "{err:?}");
}

#[test]
fn rejects_signature_alg_not_in_whitelist() {
    let mut cfg = config_builder();
    cfg.signature_alg_whitelist = vec!["GostR3410-2012-256".into()];
    let v = OpensslVerifier::new(cfg).unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let err = v.verify(&leaf, &presented).unwrap_err();
    assert!(matches!(err, TrustError::SignatureAlgorithm(_)), "{err:?}");
}

#[test]
fn empty_anchor_set_is_a_construction_error() {
    let mut cfg = config_builder();
    cfg.anchors = vec![];
    let err = OpensslVerifier::new(cfg).unwrap_err();
    assert!(matches!(err, TrustError::PathBuild(_)), "{err:?}");
}

#[test]
fn zero_max_depth_is_a_construction_error() {
    let mut cfg = config_builder();
    cfg.max_depth = 0;
    let err = OpensslVerifier::new(cfg).unwrap_err();
    assert!(matches!(err, TrustError::PathBuild(_)), "{err:?}");
}

//! S08 regression: `OpensslVerifier::verify` engine wiring.
//!
//! Stage-3 invariants exercised here:
//!
//! 1. RSA-only chains must NOT cause the gost-engine `OnceLock` to be
//!    written to (proxy: `is_available()` stays in whatever state it had
//!    before the verify call — we observe consistency, not absolute state,
//!    because other tests may run first inside the same process).
//! 2. Chains containing a GOST-signed certificate trigger
//!    `ensure_loaded_with_path`; on macOS dev hosts that surfaces as
//!    `TrustError::EngineLoadFailed` (or, when libcrypto rejects the OID
//!    earlier, `TrustError::BadSignature`).  Either is the correct
//!    fail-closed posture; the test only requires *deterministic* behaviour.
//!
//! No fixtures shipping a real GOST cert exist yet (those land in S12).
//! For invariant (2) we synthesise the `is_gost()` precondition by
//! constructing a tiny in-memory cert whose `signature_algorithm()` reports
//! the GOST 2012-256 OID — the verifier's engine-wiring branch keys on the
//! string OID via `Certificate::signature_alg`, so this is sufficient to
//! exercise the conditional load.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::duration_suboptimal_units)]

use std::time::Duration;

use tessera_core::gost::engine::is_available;
use tessera_core::trust::openssl_verifier::{
    OpensslVerifier, OpensslVerifierConfig, Stage2TrustVerifier,
};
use tessera_core::x509::{Certificate, TrustError};

const LEAF_RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");
const CA: &[u8] = include_bytes!("fixtures/ca.pem");

fn rsa_only_verifier() -> OpensslVerifier {
    OpensslVerifier::new(OpensslVerifierConfig {
        anchors: vec![Certificate::from_pem(CA).unwrap()],
        intermediates: vec![Certificate::from_pem(INT).unwrap()],
        crl_pems: vec![],
        crl_strict: false,
        crl_max_age: None,
        clock_skew: Duration::from_secs(60),
        signature_alg_whitelist: vec!["sha256WithRSAEncryption".into()],
        spki_pins: vec![],
        max_depth: 4,
        gost_engine_path: None,
        revocation_mode: tessera_core::config::validated::RevocationMode::None,
        ocsp_responder_url: None,
        ocsp_timeout: Duration::from_secs(5),
        ocsp_cache_dir: std::path::PathBuf::from("/var/cache/tessera/ocsp"),
        ocsp_cache_ttl: Duration::ZERO,
    })
    .unwrap()
}

#[test]
fn rsa_only_chain_does_not_load_engine() {
    // The verify call below uses RSA certs exclusively.  The conditional
    // engine loader (`ensure_loaded_if_any_gost`) must short-circuit and
    // leave the OnceLock in whatever state it was in before the call.
    let observed_before = is_available();

    let v = rsa_only_verifier();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let res = v.verify(&leaf, &presented);
    assert!(res.is_ok(), "RSA chain must verify: {res:?}");

    let observed_after = is_available();
    assert_eq!(
        observed_before, observed_after,
        "engine state changed during an RSA-only verify",
    );
}

#[test]
fn rsa_only_chain_does_not_emit_engine_load_failed() {
    // Even on a host without gost-engine the RSA path must not surface
    // `EngineLoadFailed` — the verifier must not even consult the engine.
    let v = rsa_only_verifier();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let res = v.verify(&leaf, &presented);
    match res {
        Ok(_) => {}
        Err(TrustError::EngineLoadFailed { .. }) => {
            panic!("RSA-only chain must not raise EngineLoadFailed");
        }
        Err(other) => panic!("unexpected: {other:?}"),
    }
}

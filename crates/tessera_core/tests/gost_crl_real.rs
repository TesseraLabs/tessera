//! S15: GOST CRL signature verification — real-fixture integration tests.
//!
//! Gated by the `gost-tests` feature.  Skipped at runtime when fixtures or
//! engine are unavailable (see `tests/common/mod.rs`).
//!
//! The GOST CRL fixture is best-effort — `openssl ca -gencrl` against an
//! engine-managed key fails on some builds (see `gen_gost.sh`).  When the
//! fixture is missing or empty, the test prints a `skipped: ...` line and
//! returns; the surrounding test suite still passes.

#![cfg(all(unix, feature = "gost-tests"))]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use tessera_core::crl::Crl;

use crate::common::{fixture_path, gost_ready_engine, load_pem_cert};

#[test]
fn gost_signed_crl_verifies() {
    let Some(engine) = gost_ready_engine() else {
        return;
    };
    let crl_path = fixture_path("gost_signed.crl");
    if !crl_path.exists() {
        eprintln!(
            "skipped: gost_signed.crl missing — `openssl ca -gencrl` likely failed in fixture script.",
        );
        return;
    }
    let crl_bytes = std::fs::read(&crl_path).expect("read crl");
    if crl_bytes.is_empty() {
        eprintln!("skipped: gost_signed.crl is empty (fixture script could not produce it).");
        return;
    }
    let crl = Crl::from_pem(&crl_bytes)
        .or_else(|_| Crl::from_der(&crl_bytes))
        .expect("parse crl");
    let ca = load_pem_cert("gost_ca_256.pem");
    crl.verify_signature_with_issuer(&ca, Some(&engine))
        .expect("GOST CRL signature must verify");
}

/// A GOST-signed CRL is not checked at all on a deployment that named no
/// engine — it is refused.
///
/// The issuer's signature algorithm is what puts the CRL on the engine path,
/// and a CRL is a file the deployment fetches rather than one it authored, so
/// "no engine configured" must mean "this CRL cannot be processed" rather than
/// "go and find an engine".
#[test]
fn gost_signed_crl_without_a_configured_engine_is_refused() {
    let Some(_engine) = gost_ready_engine() else {
        return;
    };
    let crl_path = fixture_path("gost_signed.crl");
    if !crl_path.exists() {
        eprintln!("skipped: gost_signed.crl missing — see gost_signed_crl_verifies.");
        return;
    }
    let crl_bytes = std::fs::read(&crl_path).expect("read crl");
    if crl_bytes.is_empty() {
        eprintln!("skipped: gost_signed.crl is empty.");
        return;
    }
    let crl = Crl::from_pem(&crl_bytes)
        .or_else(|_| Crl::from_der(&crl_bytes))
        .expect("parse crl");
    let ca = load_pem_cert("gost_ca_256.pem");
    let err = crl
        .verify_signature_with_issuer(&ca, None)
        .expect_err("a GOST CRL must not verify without a configured engine");
    assert!(
        matches!(err, tessera_core::x509::TrustError::EngineLoadFailed { .. }),
        "expected a fail-closed engine error, got {err:?}",
    );
}

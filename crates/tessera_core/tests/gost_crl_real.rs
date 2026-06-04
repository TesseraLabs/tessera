//! S15: GOST CRL signature verification — real-fixture integration tests.
//!
//! Gated by the `gost-tests` feature.  Skipped at runtime when fixtures or
//! engine are unavailable (see `tests/common/mod.rs`).
//!
//! The GOST CRL fixture is best-effort — `openssl ca -gencrl` against an
//! engine-managed key fails on some builds (see `gen_gost.sh`).  When the
//! fixture is missing or empty, the test prints a `skipped: ...` line and
//! returns; the surrounding test suite still passes.

#![cfg(feature = "gost-tests")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use tessera_core::crl::Crl;

use crate::common::{fixture_path, load_pem_cert, skip_unless_gost_ready};

#[test]
fn gost_signed_crl_verifies() {
    if skip_unless_gost_ready() {
        return;
    }
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
    crl.verify_signature_with_issuer(&ca, None)
        .expect("GOST CRL signature must verify");
}

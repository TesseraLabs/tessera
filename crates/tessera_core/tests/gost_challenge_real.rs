//! S14: GOST challenge round-trip — real-fixture integration tests.
//!
//! Gated by the `gost-tests` feature.  Skipped at runtime when fixtures or
//! engine are unavailable (see `tests/common/mod.rs`).

#![cfg(feature = "gost-tests")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use openssl::pkcs12::Pkcs12;
use tessera_core::challenge::challenge_response;

use crate::common::{fixture_path, skip_unless_gost_ready};

fn round_trip_gost_p12(p12_name: &str) {
    let p12_bytes =
        std::fs::read(fixture_path(p12_name)).unwrap_or_else(|e| panic!("read {p12_name}: {e}"));
    let p12 = Pkcs12::from_der(&p12_bytes).expect("parse p12");
    let parsed = p12
        .parse2("correct-pin")
        .expect("decrypt p12 (engine must be loaded)");
    let pkey = parsed.pkey.expect("private key present in p12");
    let cert_native = parsed.cert.expect("cert present in p12");
    // Re-parse via our own Certificate type so the challenge dispatcher sees
    // a consistent SignatureAlg classification.
    let der = cert_native.to_der().expect("cert to DER");
    let cert = tessera_core::x509::Certificate::from_der(&der).expect("parse cert");

    challenge_response(&cert, &pkey, None).expect("GOST challenge round-trip");
}

#[test]
fn gost256_challenge_roundtrip() {
    if skip_unless_gost_ready() {
        return;
    }
    round_trip_gost_p12("gost_ee_256.p12");
}

#[test]
fn gost512_challenge_roundtrip() {
    if skip_unless_gost_ready() {
        return;
    }
    round_trip_gost_p12("gost_ee_512.p12");
}

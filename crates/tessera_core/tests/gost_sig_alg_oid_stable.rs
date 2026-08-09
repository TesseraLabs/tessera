//! The signature-algorithm OID of a GOST certificate must not change when
//! gost-engine is loaded into the process.
//!
//! This file deliberately contains exactly one test.  Loading an engine is a
//! process-wide, irreversible act: once libcrypto knows the GOST OIDs it
//! knows them for every thread until the process exits.  A second test in
//! the same binary could therefore load the engine before this one reads the
//! "engine not loaded yet" value, and the test would silently stop checking
//! what it claims to check.
//!
//! Gated by the `gost-tests` feature and skipped when the fixtures produced
//! by `tests/fixtures/gen_gost.sh` are absent or the host has no working
//! gost-engine.

#![cfg(all(unix, feature = "gost-tests"))]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use crate::common::{gost_fixtures_present, gost_ready_engine, load_pem_cert};

/// Dotted OID of `id-tc26-signwithdigest-gost3410-2012-256`.
const GOST_2012_256_OID: &str = "1.2.643.7.1.1.3.2";

/// What this proves: the reported algorithm is the dotted OID both before
/// and after gost-engine is loaded, so the value does not come from
/// libcrypto's OID-naming tables.  Both halves matter, because how much
/// libcrypto knows about the GOST OIDs before any engine is loaded differs
/// per host: on the macOS dev host (OpenSSL 3.6) the built-in table already
/// names them, so the pre-load assertion is the one that catches the
/// regression there, while on a host whose table lacks them it is the
/// post-load assertion that does.  With the accessor delegating to
/// `Display`, one or the other read is
/// `GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)` — a string no
/// allow-list recognises.
///
/// What it does not prove: independence from *every* possible set of engines
/// and providers, and it cannot show the transition itself on a host where
/// libcrypto already names the OID before the load.  Loading an engine is
/// irreversible within a process, so a single process can only ever observe
/// one such transition.
#[test]
fn signature_algorithm_oid_survives_loading_the_gost_engine() {
    if !gost_fixtures_present() {
        eprintln!("skipped: GOST fixtures missing; run tests/fixtures/gen_gost.sh.");
        return;
    }

    // Read first: nothing in this binary has touched the engine yet.
    let leaf = load_pem_cert("gost_ee_256.pem");
    let before = leaf.signature_algorithm();
    assert_eq!(
        before, GOST_2012_256_OID,
        "without gost-engine the OID must already read as dotted",
    );

    // `gost_ready_engine` performs the engine load attempt.
    if gost_ready_engine().is_none() {
        return;
    }

    let after = leaf.signature_algorithm();
    assert_eq!(
        after, before,
        "loading gost-engine must not change how a parsed certificate reads",
    );

    // A certificate parsed *after* the load must read the same way too: the
    // OID text is derived from the certificate, not from libcrypto's tables.
    let reparsed = load_pem_cert("gost_ee_256.pem");
    assert_eq!(reparsed.signature_algorithm(), GOST_2012_256_OID);
}

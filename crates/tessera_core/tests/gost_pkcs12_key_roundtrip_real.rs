//! A GOST container opens, and its key survives the PKCS#8 round-trip, in a
//! process that has not loaded `gost-engine` beforehand.
//!
//! This is the shape of a real login: the PAM module reaches the container
//! before it reaches anything that would ask for GOST by name, and the OpenSSL
//! binding never reads the host's `openssl.cnf`, so the engine a host
//! registers there is not registered in this process. Everything the container
//! needs must therefore be arranged by the container-opening path itself.
//!
//! Gated by the `gost-tests` feature. Skipped at runtime when the fixtures or
//! the engine are unavailable (see `tests/common/mod.rs`); unlike the other
//! GOST integration tests this one cannot use `skip_unless_gost_ready`, which
//! would load the engine and so erase the very condition under test.

#![cfg(all(unix, feature = "gost-tests"))]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use secrecy::SecretString;
use tessera_core::pkcs12::LoadedKeyMaterial;

use std::path::Path;

use crate::common::{fixture_path, gost_engine_path, gost_fixtures_dir, gost_fixtures_present};

/// Password `gen_gost.sh` exports the GOST containers with.
const FIXTURE_PIN: &str = "correct-pin";

/// Opens a fixture container and proves the key it yields survives being
/// stored as PKCS#8 DER and read back.
///
/// The proof is the public key: it is derived from the private key on both
/// sides, so two runs agreeing means the reloaded handle holds the same
/// private key and not merely a structurally valid one.
fn round_trip(p12_name: &str, engine: &Path) {
    let bytes = std::fs::read(fixture_path(p12_name))
        .unwrap_or_else(|e| panic!("read fixture {p12_name}: {e}"));
    let pin = SecretString::from(FIXTURE_PIN.to_owned());

    let material = LoadedKeyMaterial::from_p12(&bytes, &pin, Some(engine))
        .unwrap_or_else(|e| panic!("{p12_name} must open with gost-engine loaded on demand: {e}"));

    let reloaded = material
        .private_key()
        .unwrap_or_else(|e| panic!("{p12_name}: stored PKCS#8 DER must read back: {e}"));

    let from_container = openssl::pkcs12::Pkcs12::from_der(&bytes)
        .expect("fixture is a container")
        .parse2(FIXTURE_PIN)
        .expect("the engine is loaded by now")
        .pkey
        .expect("the fixture carries a key");

    assert_eq!(
        reloaded.public_key_to_der().expect("reloaded key encodes"),
        from_container
            .public_key_to_der()
            .expect("container key encodes"),
        "{p12_name}: the key read back from PKCS#8 DER is not the one the container held",
    );
}

/// Both GOST key sizes Tessera claims support for, in one test.
///
/// They share a test binary and the engine is process-global, so only the
/// first container to be opened exercises the cold path this test exists for.
/// Keeping them in one test function makes which one that is deterministic
/// instead of leaving it to the order the harness happens to pick.
#[test]
fn gost_containers_open_without_a_preloaded_engine() {
    if !gost_fixtures_present() {
        eprintln!(
            "skipped: GOST fixtures missing under {}; run tests/fixtures/gen_gost.sh on a host with gost-engine.",
            gost_fixtures_dir().display(),
        );
        return;
    }

    let Some(engine) = gost_engine_path() else {
        eprintln!(
            "skipped: gost-engine .so not found on this host; set \
             TESSERA_TEST_GOST_ENGINE_PATH to the engine the containers were made with.",
        );
        return;
    };

    // The fixtures exist, so this host generated them and had the engine at
    // that point. Probing for the engine now would load it and turn the cold
    // path below into the warm one, so the check is deferred: if the first
    // container fails to open, ask then whether the engine is reachable at
    // all. A host where it is not — the .so is there but does not load into
    // this libcrypto — has nothing to test, so that outcome is a skip; a host
    // where it does load and the container still failed is a real failure.
    let bytes = std::fs::read(fixture_path("gost_ee_256.p12")).expect("read fixture");
    let pin = SecretString::from(FIXTURE_PIN.to_owned());
    if let Err(e) = LoadedKeyMaterial::from_p12(&bytes, &pin, Some(&engine)) {
        // The load attempt this reports on is the one `from_p12` already made:
        // its outcome is cached process-wide, so asking again cannot change
        // the answer, only read it.
        if !tessera_core::gost::engine::is_available_after_attempt(Some(&engine)) {
            eprintln!(
                "skipped: gost-engine at {} did not load into this libcrypto, so the container \
                 could not open ({e}).",
                engine.display(),
            );
            return;
        }
        panic!("gost_ee_256.p12 must open on a host where gost-engine is loadable: {e}");
    }

    round_trip("gost_ee_256.p12", &engine);
    round_trip("gost_ee_512.p12", &engine);
}

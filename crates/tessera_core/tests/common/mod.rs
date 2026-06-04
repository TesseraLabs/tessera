//! Helpers shared across the GOST integration tests in `tessera_core`.
//!
//! The actual fixtures (`gost_ca_256.pem`, `gost_ee_256.p12`, etc.) live in
//! `tests/fixtures/gost/` and are produced by `tests/fixtures/gen_gost.sh`
//! on a host with `gost-engine` available.  They are NOT committed to the
//! repository — see the workspace `.gitignore`.
//!
//! Tests that depend on these fixtures call [`skip_unless_gost_ready`]
//! before doing any work.  When the fixtures are missing or the engine is
//! unavailable the helper prints an `eprintln!("skipped: ...")` line and
//! returns `true`; the test then short-circuits with `return`, treating the
//! absence as "test passes by skipping" rather than as a failure.
//!
//! This module is intentionally small: every helper here is `#[allow(dead_code)]`
//! because some of them are referenced only from feature-gated tests.
#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

/// Absolute path to `tests/fixtures/gost/`.
#[must_use]
pub fn gost_fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gost")
}

/// Absolute path of a single fixture file under `tests/fixtures/gost/`.
#[must_use]
pub fn fixture_path(name: &str) -> PathBuf {
    gost_fixtures_dir().join(name)
}

/// Returns `true` if at least the GOST-256 CA fixture is present on disk.
///
/// We probe a single representative file rather than checking every fixture
/// individually because the script either generates them all or none; a
/// partial state would imply the script was interrupted, which is rare and
/// will surface as a load error in the test itself.
#[must_use]
pub fn gost_fixtures_present() -> bool {
    gost_fixtures_dir().join("gost_ca_256.pem").exists()
}

/// Combined skip-condition for GOST integration tests.
///
/// Returns `true` and prints a `skipped: ...` line if either:
///
/// * the fixtures aren't present (developer hasn't run `gen_gost.sh` yet,
///   typical on macOS dev hosts), or
/// * the gost-engine isn't loadable on this host.
///
/// Tests should treat the boolean as "skip the rest of the test".
#[must_use]
pub fn skip_unless_gost_ready() -> bool {
    if !gost_fixtures_present() {
        eprintln!(
            "skipped: GOST fixtures missing under {}; run tests/fixtures/gen_gost.sh on a Linux host with gost-engine.",
            gost_fixtures_dir().display(),
        );
        return true;
    }
    if !tessera_core::gost::engine::is_available_after_attempt(None) {
        eprintln!("skipped: gost-engine not available on this host (load attempt failed).");
        return true;
    }
    false
}

/// Loads a PEM-encoded fixture file and parses it as a [`Certificate`].
///
/// Panics if the file is missing or unparseable — callers must run
/// [`skip_unless_gost_ready`] first.
#[must_use]
pub fn load_pem_cert(name: &str) -> tessera_core::x509::Certificate {
    let path = fixture_path(name);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    tessera_core::x509::Certificate::from_pem(&bytes)
        .unwrap_or_else(|e| panic!("parse fixture {}: {e:?}", path.display()))
}

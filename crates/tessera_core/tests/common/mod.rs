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

#[path = "../../src/test_support.rs"]
mod test_support;

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

/// Path of the `gost-engine` shared object on this host, if one can be named.
///
/// The product loads the engine only from a configured path — an unconfigured
/// deployment must never fall back to an `OPENSSL_ENGINES` lookup — so a test
/// that exercises that load has to supply a path just like an operator would.
///
/// Re-exported from the crate's own `test_support` so the unit tests and the
/// integration tests agree on one definition of "where is the engine".
pub use test_support::gost_engine_path;

/// The engine and the fixtures a GOST integration test needs, or `None`.
///
/// Replaces the older boolean skip-check. Every GOST entry point in the
/// product now insists on being told which shared library to load, so a test
/// cannot merely establish that an engine *exists* — it has to carry the path
/// into the config, the verifier or the CRL check it is exercising, exactly as
/// a deployment does. Handing the path back is what makes that possible;
/// returning a bare `true`/`false` would leave every caller passing `None` and
/// quietly failing closed.
///
/// Prints a `skipped: ...` line and returns `None` when the fixtures are
/// absent (no `gen_gost.sh` run on this host — the normal case on macOS dev
/// hosts), when no engine can be located, or when the engine that was located
/// refuses to load into this libcrypto.
#[must_use]
pub fn gost_ready_engine() -> Option<PathBuf> {
    if !gost_fixtures_present() {
        eprintln!(
            "skipped: GOST fixtures missing under {}; run tests/fixtures/gen_gost.sh on a Linux host with gost-engine.",
            gost_fixtures_dir().display(),
        );
        return None;
    }
    let Some(engine) = gost_engine_path() else {
        eprintln!(
            "skipped: no gost-engine .so found on this host; set {} to the engine the fixtures were made with.",
            test_support::GOST_ENGINE_PATH_ENV,
        );
        return None;
    };
    if !tessera_core::gost::engine::is_available_after_attempt(Some(&engine)) {
        eprintln!(
            "skipped: gost-engine at {} did not load into this libcrypto.",
            engine.display(),
        );
        return None;
    }
    Some(engine)
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

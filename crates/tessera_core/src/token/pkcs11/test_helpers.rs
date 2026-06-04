//! Helpers for PKCS#11 integration tests.
//!
//! All the heavy integration tests under
//! `crates/tessera_core/tests/pkcs11_*.rs` are gated by both the
//! `pkcs11-tests` Cargo feature and a runtime check for the
//! `PKCS11_MODULE_PATH` environment variable.  This module hosts the
//! tiny shared helper that does the runtime detection.
//!
//! On a macOS dev host with no PKCS#11 provider installed, callers
//! should print a `skipped: PKCS#11 module not available` line and
//! return `Ok` from the test.

use std::path::PathBuf;

/// Environment variable that integration tests look up to find a
/// PKCS#11 module on the host.  Mirrors the convention used by upstream
/// `cryptoki`'s own test suite.
pub const PKCS11_MODULE_ENV: &str = "PKCS11_MODULE_PATH";

/// Return the path to the PKCS#11 module configured for integration
/// tests, if any.
///
/// Returns `Some(path)` when:
/// - the `PKCS11_MODULE_PATH` env var is set, and
/// - the resulting path actually exists on disk.
///
/// Returns `None` when the env var is unset, empty, or points to a
/// path that doesn't exist.  Callers should treat `None` as "skip the
/// test on this host".
#[must_use]
pub fn pkcs11_test_module_path() -> Option<PathBuf> {
    let raw = std::env::var(PKCS11_MODULE_ENV).ok()?;
    if raw.is_empty() {
        return None;
    }
    let path = PathBuf::from(raw);
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

/// Convenience: print a uniform "skipped" message and return `true`
/// when the PKCS#11 module is missing.  Tests use:
///
/// ```ignore
/// if tessera_core::token::pkcs11::test_helpers::skip_if_no_module() {
///     return;
/// }
/// ```
#[must_use]
pub fn skip_if_no_module() -> bool {
    if pkcs11_test_module_path().is_none() {
        eprintln!("skipped: PKCS#11 module not available (set PKCS11_MODULE_PATH)");
        true
    } else {
        false
    }
}

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
//!
//! [`private_objects_visible_without_login`] is feature-gated behind
//! `pkcs11-tests`: it deliberately opens a session that never presents a
//! PIN, which is exactly the capability production code must not have.

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

/// Count the objects with `CKA_PRIVATE = TRUE` that a session which
/// never presented a PIN can see on `slot`.
///
/// PKCS#11 scopes the login to the *application*, and the application is
/// defined by the `C_Initialize` call — so with a process-global context
/// a session that skipped `C_Login` still reads private objects while
/// any other session of the same process is logged in.  That makes this
/// count the only direct observation of "is the token currently logged
/// in", which the residual-login test needs: on a host process that
/// outlives a single authentication (the `fly-dm` display slave lives
/// for the whole uptime) a missed `C_Logout` would hand the next login
/// attempt access it never authenticated for.
///
/// Returns `0` on a logged-out token.
///
/// # Errors
///
/// - [`Pkcs11Error::SessionOpenFailed`] when `C_OpenSession` fails.
/// - [`Pkcs11Error::Cryptoki`] when the object search fails.
#[cfg(feature = "pkcs11-tests")]
pub fn private_objects_visible_without_login(
    backend: &super::Pkcs11Backend,
    slot: super::Slot,
) -> Result<usize, super::Pkcs11Error> {
    use cryptoki::object::Attribute;

    use super::locking::with_global_lock;
    use super::Pkcs11Error;

    let mode = backend.locking_mode();
    let session = with_global_lock(mode, || backend.ctx().open_ro_session(slot))
        .map_err(|source| Pkcs11Error::SessionOpenFailed { source })?;
    let found = with_global_lock(mode, || session.find_objects(&[Attribute::Private(true)]))
        .map_err(Pkcs11Error::Cryptoki)?;
    // `Session::Drop` issues `C_CloseSession`; keep it inside the
    // serialization layer like every other cryptoki call.
    with_global_lock(mode, || drop(session));
    Ok(found.len())
}

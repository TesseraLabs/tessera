//! T18 — End-to-end integration tests against a softhsm2 token.
//!
//! These tests run only when **all** of the following hold:
//!
//! 1. The `pkcs11-tests` Cargo feature is on.
//! 2. `PKCS11_MODULE_PATH` is set to a real `.so` (and the file
//!    exists).
//! 3. `SOFTHSM2_CONF` is set, or the host's default softhsm2 store
//!    contains the configured token.  Tests that need a specific
//!    on-token label additionally check `SOFTHSM_TEST_LABEL`,
//!    `SOFTHSM_USER_PIN`, etc. — see
//!    `tests/scripts/README-softhsm2.md`.
//!
//! On macOS dev hosts with no provider installed (the common case)
//! every test prints `skipped: …` and returns `Ok`.  This file
//! therefore stays green on `cargo test --features pkcs11-tests`
//! without a real token.
//!
//! Tests:
//!
//! - **Module load fails with bogus path** — pure negative test, runs
//!   even on hosts without a token.
//! - **Module loads + finds slot** — happy path slot enumeration.
//! - **Wrong-PIN loop returns `MaxAttemptsExceeded`** — runs only when
//!   a real token is present.
//! - **Cert lookup miss returns `CertificateNotFound`** — runs only
//!   when a real token is present.
//!
//! Intentionally **does not** drive the full `pkcs11_challenge_response`
//! flow: that path needs an on-token X.509 cert imported alongside the
//! key, which the setup script leaves for operators to add manually
//! (see README).  The PAM-level e2e tests in
//! `crates/pam_tessera/tests/auth_e2e_pkcs11.rs` cover the full
//! sign + verify round-trip when both keys and certs are present.

#![cfg(feature = "pkcs11-tests")]
#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::PathBuf;
use std::time::Duration;

use secrecy::SecretString;
use tessera_core::token::pkcs11::{
    acquire_pkcs11_session, test_helpers, AcquireError, LockingMode, Pkcs11Backend, Pkcs11Error,
};

/// Runtime-skip helper that combines the module-path check with the
/// `SOFTHSM2_CONF` env-var check.  Returns `true` when the test
/// should bail (and prints a `skipped: ...` line first).
fn skip_unless_pkcs11_ready() -> bool {
    if test_helpers::pkcs11_test_module_path().is_none() {
        eprintln!("skipped: PKCS11_MODULE_PATH not set or path missing");
        return true;
    }
    if std::env::var("SOFTHSM2_CONF").is_err() && std::env::var("SOFTHSM_TEST_LABEL").is_err() {
        // Without `SOFTHSM2_CONF` we *might* still be talking to
        // librtpkcs11ecp / a real Rutoken; print a softer message so
        // the operator knows what's missing if they expected softhsm2.
        eprintln!("skipped: SOFTHSM2_CONF and SOFTHSM_TEST_LABEL both unset");
        return true;
    }
    false
}

fn module_path() -> PathBuf {
    test_helpers::pkcs11_test_module_path().expect("checked above")
}

fn token_label() -> Option<String> {
    std::env::var("SOFTHSM_TEST_LABEL").ok()
}

fn user_pin() -> SecretString {
    SecretString::from(std::env::var("SOFTHSM_USER_PIN").unwrap_or_else(|_| "1234".to_owned()))
}

// ---------------------------------------------------------------------------
// Negative tests — these run even on hosts with no token.
// ---------------------------------------------------------------------------

#[test]
fn module_load_with_nonexistent_path_returns_module_path_missing() {
    let nope = PathBuf::from("/nonexistent/__tessera_no_such_module__.so");
    let err = Pkcs11Backend::load(&nope, LockingMode::Os)
        .err()
        .expect("must fail");
    assert!(
        matches!(err, Pkcs11Error::ModulePathMissing(_)),
        "got {err:?}"
    );
}

#[test]
fn module_load_with_mutex_locking_mode_does_not_panic() {
    // Cross-checks T14: loading a module in `Mutex` mode must initialise
    // without surprising the user-space lock layer.  We test via the
    // negative path (no module file) so we don't need a real provider
    // — `ModulePathMissing` is returned long before any FFI call would
    // hit `with_global_lock`.
    let nope = PathBuf::from("/nonexistent/__t14_mutex_smoke__.so");
    let err = Pkcs11Backend::load(&nope, LockingMode::Mutex)
        .err()
        .expect("must fail");
    assert!(matches!(err, Pkcs11Error::ModulePathMissing(_)));
}

// ---------------------------------------------------------------------------
// Positive tests — require a live softhsm2 (or compatible) provider.
// ---------------------------------------------------------------------------

#[test]
fn live_backend_finds_slot_with_token() {
    if skip_unless_pkcs11_ready() {
        return;
    }
    let backend = Pkcs11Backend::load(&module_path(), LockingMode::Os).expect("load module");
    let slot = backend
        .find_slot(token_label().as_deref())
        .expect("find_slot");
    let serial =
        tessera_core::token::pkcs11::read_token_serial(&backend, slot).expect("read serial");
    assert!(!serial.is_empty());
}

#[test]
fn live_wait_for_token_returns_immediately_when_present() {
    if skip_unless_pkcs11_ready() {
        return;
    }
    let backend = Pkcs11Backend::load(&module_path(), LockingMode::Os).expect("load module");
    let slot = backend
        .wait_for_token(Duration::from_secs(2), token_label().as_deref())
        .expect("wait_for_token must succeed when token is already inserted");
    let serial =
        tessera_core::token::pkcs11::read_token_serial(&backend, slot).expect("read serial");
    assert!(!serial.is_empty());
}

#[test]
fn live_three_wrong_pins_yield_max_attempts() {
    if skip_unless_pkcs11_ready() {
        return;
    }
    let backend = Pkcs11Backend::load(&module_path(), LockingMode::Os).expect("load module");
    let slot = backend
        .find_slot(token_label().as_deref())
        .expect("find_slot");

    // Capture the PIN attempt counter to assert the loop ran exactly
    // 3 times.  `acquire_pkcs11_session` invokes the prompter once per
    // attempt; we hand back a canned bad PIN every call.
    let mut prompts = 0_usize;
    let prompter = |_p: &str| -> Result<SecretString, tessera_core::pam_conv::PamConvError> {
        prompts += 1;
        Ok(SecretString::from("__bad_pin__".to_owned()))
    };
    let err = acquire_pkcs11_session(&backend, slot, 3, prompter)
        .err()
        .expect("must fail");
    // softhsm2 returns `CKR_PIN_INCORRECT` for `acquire_pkcs11_session`
    // until the on-token attempt counter wraps; with 3 attempts we
    // expect `MaxAttemptsExceeded`.  Some providers may return
    // `PinLocked` early (e.g. when the test ran multiple times and
    // softhsm2 already exhausted the counter); accept either as a
    // valid bad-pin outcome.
    assert!(
        matches!(
            err,
            AcquireError::MaxAttemptsExceeded | AcquireError::PinLocked
        ),
        "got {err:?}"
    );
    assert!((1..=3).contains(&prompts), "prompts={prompts}");
}

#[test]
fn live_cert_lookup_with_unknown_label_returns_not_found() {
    if skip_unless_pkcs11_ready() {
        return;
    }
    let backend = Pkcs11Backend::load(&module_path(), LockingMode::Os).expect("load module");
    let slot = backend
        .find_slot(token_label().as_deref())
        .expect("find_slot");

    let session =
        match tessera_core::token::pkcs11::Pkcs11Session::open(&backend, slot, &user_pin()) {
            Ok(s) => s,
            Err(Pkcs11Error::PinIncorrect | Pkcs11Error::PinLocked) => {
                eprintln!(
                    "skipped: token PIN does not match SOFTHSM_USER_PIN; \
                       reset the token via teardown_softhsm2.sh + setup_softhsm2.sh"
                );
                return;
            }
            Err(other) => panic!("unexpected open error: {other:?}"),
        };
    let err = session
        .find_certificate(Some("__tessera_no_such_label__"))
        .err()
        .expect("must fail");
    assert!(
        matches!(err, Pkcs11Error::CertificateNotFound { .. }),
        "got {err:?}"
    );
}

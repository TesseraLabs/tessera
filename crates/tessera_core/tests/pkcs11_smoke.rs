//! Smoke test: scaffold for the Stage 4 PKCS#11 module compiles and the
//! key types from the `cryptoki` re-export are reachable.
//!
//! No real PKCS#11 module is loaded; this test is intended to run on
//! every host (Linux dev, macOS dev, CI without softhsm2) and only
//! exists to catch a future regression where `tessera_core::token`
//! stops being a public module.

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::Path;

use tessera_core::token::pkcs11::{
    test_helpers::pkcs11_test_module_path, AcquireError, LockingMode, Pkcs11Backend, Pkcs11Error,
    Pkcs11Session, Slot, TokenLocator,
};

#[test]
fn module_paths_resolve() {
    // Compilation alone is the assertion; we just touch the names.
    let _: Option<Pkcs11Error> = None;
    let _: Option<Pkcs11Backend> = None;
    let _: Option<Pkcs11Session> = None;
    let _: Option<AcquireError> = None;
    let _: Option<LockingMode> = Some(LockingMode::Os);
    // Slot is a re-export from cryptoki — make sure it's reachable.
    let _: Option<Slot> = None;
}

#[test]
fn loading_missing_path_returns_module_path_missing() {
    let nope = Path::new("/nonexistent/__tessera_no_such_module__.so");
    let err = Pkcs11Backend::load(nope, LockingMode::Os)
        .err()
        .expect("loading a nonexistent module must fail");
    assert!(
        matches!(err, Pkcs11Error::ModulePathMissing(_)),
        "got {err:?}"
    );
}

#[test]
fn locator_trait_is_object_safe_via_blanket_impl() {
    // Compile-only: ensure `Pkcs11Backend: TokenLocator` resolves so the
    // T04 `wait_for_token` polling helper is generic-bounded correctly.
    fn assert_impl<T: TokenLocator>() {}
    assert_impl::<Pkcs11Backend>();
}

#[test]
fn integration_module_path_check_does_not_panic() {
    // Calling the helper without env var set must return None and not
    // panic.  This protects the macOS dev workflow.
    let _ = pkcs11_test_module_path();
}

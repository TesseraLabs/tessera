//! Feature-gated integration tests for PKCS#11 certificate / key lookup
//! (Tasks T08, T09, T10, T11).
//!
//! All tests in this file:
//! 1. Compile only when the `pkcs11-tests` Cargo feature is on.
//! 2. Skip at runtime when `PKCS11_MODULE_PATH` is unset / absent.
//!
//! On macOS dev hosts both gates ensure the suite stays green without a
//! provider installed.  Real CI hosts (softhsm2 / librtpkcs11ecp) need
//! to populate the env var and provision a token with a known PIN
//! before the integration harness runs.

#![cfg(feature = "pkcs11-tests")]
#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic,
    clippy::unwrap_used
)]

use tessera_core::token::pkcs11::{test_helpers, LockingMode, Pkcs11Backend};

#[test]
fn live_module_loads_or_skips() {
    if test_helpers::skip_if_no_module() {
        return;
    }
    let path = test_helpers::pkcs11_test_module_path().expect("module path checked");
    let backend = Pkcs11Backend::load(&path, LockingMode::Os).expect("load module");
    assert_eq!(backend.module_path(), path.as_path());
}

#[test]
fn live_token_serial_or_skips() {
    if test_helpers::skip_if_no_module() {
        return;
    }
    let path = test_helpers::pkcs11_test_module_path().expect("module path checked");
    let backend = Pkcs11Backend::load(&path, LockingMode::Os).expect("load module");
    let slots = backend.list_slots_with_token().expect("list slots");
    if slots.is_empty() {
        eprintln!("skipped: no token present in any slot");
        return;
    }
    let slot = slots[0];
    let serial =
        tessera_core::token::pkcs11::read_token_serial(&backend, slot).expect("read serial");
    assert!(!serial.is_empty(), "serial must be non-empty");
}

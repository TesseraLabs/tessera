//! End-to-end happy-path test for the stage-2 PKCS#12 authentication flow.
//!
//! Drives [`pam_tessera::flow::authenticate`] with the in-memory FlowIo
//! adapter so we can run on macOS dev hosts without root.  Real hardware
//! integration lives in stage 7's `pamtester` runbook.

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::duration_suboptimal_units,
    clippy::pedantic
)]

mod common;

use common::*;
use tessera_core::x509::Certificate;

#[test]
fn happy_path_rsa() {
    let serial = Certificate::from_pem(&fixture_bytes("leaf_rsa.pem"))
        .unwrap()
        .serial_hex()
        .to_lowercase();
    let outcome = run_flow_with(
        "leaf_rsa.p12",
        vec![cn_mapping("alice", "alice")],
        (),
        "alice",
        "correct-pin",
        vec![],
        "host-T-hash",
    )
    .expect("happy_path_rsa flow");
    assert_eq!(outcome.auth_ctx.cert_cn.as_deref(), Some("alice"));
    assert_eq!(
        outcome.auth_ctx.cert_serial.as_deref(),
        Some(serial.as_str())
    );
    assert!(outcome.auth_ctx.cert_not_after.is_some());
}

#[test]
fn happy_path_ecdsa() {
    let serial = Certificate::from_pem(&fixture_bytes("leaf_ecdsa.pem"))
        .unwrap()
        .serial_hex()
        .to_lowercase();
    let outcome = run_flow_with(
        "leaf_ecdsa.p12",
        vec![cn_mapping("bob", "bob")],
        (),
        "bob",
        "correct-pin",
        vec![],
        "host-T-hash",
    )
    .expect("happy_path_ecdsa flow");
    assert_eq!(outcome.auth_ctx.cert_cn.as_deref(), Some("bob"));
    assert_eq!(
        outcome.auth_ctx.cert_serial.as_deref(),
        Some(serial.as_str())
    );
    assert!(outcome.auth_ctx.cert_not_after.is_some());
}

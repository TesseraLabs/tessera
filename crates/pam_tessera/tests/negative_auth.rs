//! Negative-path integration suite for the stage-2 authentication flow.
//!
//! Unlike the runbook in the original plan, these tests run on every
//! platform: `pam_tessera::flow::InMemoryFlowIo` lets us drive the whole
//! pipeline without root, udev, or `mount(2)`.
//!
//! Tests that genuinely require kernel facilities (true `mount(2)` errno
//! reproduction, real udev events) remain `#[ignore]`-by-default.

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
use pam_tessera::flow::FlowError;
use tessera_core::mapping::MappingError;
use tessera_core::x509::{Certificate, TrustError};

fn leaf_serial(name: &str) -> String {
    Certificate::from_pem(&fixture_bytes(name))
        .unwrap()
        .serial_hex()
        .to_lowercase()
}

#[test]
fn wrong_pin_three_times_returns_max_tries() {
    let _serial = leaf_serial("leaf_rsa.pem");
    let err = run_flow_with(
        "leaf_rsa.p12",
        vec![cn_mapping("alice", "alice")],
        (),
        "alice",
        "wrong-pin",
        vec![],
        "host-T-hash",
    )
    .unwrap_err();
    assert!(matches!(err, FlowError::MaxTries));
    assert_eq!(err.pam_code(), 8); // PAM_MAXTRIES
}

#[test]
fn missing_p12_returns_authinfo_unavail() {
    use pam_tessera::flow::{authenticate, Deps, InMemoryFlowIo};
    use secrecy::SecretString;
    use tessera_core::host_identity::HostIdSourceKind;
    use tessera_core::ipc::StubClient;

    let tmp = tempfile::tempdir().unwrap();
    // No `certs/` directory at all.
    let verifier = build_verifier(vec![]);
    let cfg = minimal_cfg();
    let mappings = vec![cn_mapping("alice", "alice")];
    let monitor = StubClient;
    let exec = tessera_core::hooks::NoopExecutor::new();
    let deps = Deps {
        cfg: &cfg,
        trust: &verifier,
        monitor: &monitor,
        hook_executor: &exec,
        host_id_hash: "host-T-hash",
        host_id_source: HostIdSourceKind::Override,
        user_mappings: &mappings,
        pam_target: tessera_proto::SessionTarget::Unknown,
        role_stage: pam_tessera::flow::RoleStage::disabled(),
        device_tags: pam_tessera::flow::empty_device_tags(),
    };
    let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
    let err = authenticate(deps, &io, "alice", "ssh", "sess-x".into(), |_| {
        Ok(SecretString::from("correct-pin"))
    })
    .unwrap_err();
    assert!(matches!(
        err,
        FlowError::Discovery(tessera_core::discovery::DiscoveryError::P12NotFound { .. })
    ));
    assert_eq!(err.pam_code(), 9); // PAM_AUTHINFO_UNAVAIL
}

#[test]
fn subject_mismatch_returns_perm_denied() {
    let _serial = leaf_serial("leaf_no_user_binding.pem");
    let err = run_flow_with(
        "leaf_no_user_binding.p12",
        vec![cn_mapping("alice", "ghost")], // expect CN=ghost; cert has CN=alice
        (),
        "alice",
        "correct-pin",
        vec![],
        "host-T-hash",
    )
    .unwrap_err();
    assert!(matches!(
        err,
        FlowError::Mapping(MappingError::SubjectMismatch { .. })
    ));
    assert_eq!(err.pam_code(), 6); // PAM_PERM_DENIED
}

// Cert host/user binding scope is exhaustively unit-tested in
// `tessera_core::host_binding`; the on-disk fixtures all carry
// `["*"]` for both extensions so end-to-end mismatch tests would need
// new restrictive fixtures and are deferred.

#[test]
fn uncovered_leaf_fails_closed_perm_denied() {
    // Pure-CRL revocation checking requires that every non-anchor certificate
    // be covered by a fresh, authentic, in-scope CRL. Here we present
    // `leaf_rsa.p12` while supplying only `crl_foreign.pem` — a CRL signed by
    // a foreign CA that does not cover leaf_rsa's issuer. With no covering
    // CRL for the leaf, the flow cannot prove the certificate is unrevoked
    // and must fail closed rather than admit it.
    let _serial = leaf_serial("leaf_rsa.pem");
    let err = run_flow_with(
        "leaf_rsa.p12",
        vec![cn_mapping("alice", "alice")],
        (),
        "alice",
        "correct-pin",
        vec![read_fixture("crl_foreign.pem")],
        "host-T-hash",
    )
    .unwrap_err();
    assert!(
        matches!(err, FlowError::Trust(TrustError::CrlNotCovered(_))),
        "expected Trust(CrlNotCovered) for a leaf with no covering CRL, got {err:?}"
    );
    assert_eq!(err.pam_code(), 6); // PAM_PERM_DENIED
}

#[test]
fn revoked_cert_with_matching_crl_returns_perm_denied() {
    // The fixture pile ships `revoked_leaf.p12` (CN=mallory, serial 0x99,
    // signed by int.pem) and `crl_valid.pem` — a CRL also signed by
    // int.pem that lists serial 0x99 as revoked.  Driving the flow with
    // both must surface `TrustError::Revoked`.
    let _serial = leaf_serial("revoked_leaf.pem");
    let err = run_flow_with(
        "revoked_leaf.p12",
        vec![cn_mapping("mallory", "mallory")],
        (),
        "mallory",
        "correct-pin",
        vec![read_fixture("crl_valid.pem")],
        "host-T-hash",
    )
    .unwrap_err();
    assert!(
        matches!(err, FlowError::Trust(TrustError::Revoked(_))),
        "expected Trust(Revoked), got {err:?}"
    );
    assert_eq!(err.pam_code(), 6); // PAM_PERM_DENIED
}

#[test]
fn expired_cert_returns_perm_denied() {
    // `expired_leaf.p12` is signed by int.pem with notBefore + notAfter
    // both in 2020 — `pre_validate_end_entity` must reject it as expired.
    let _serial = leaf_serial("expired_leaf.pem");
    let err = run_flow_with(
        "expired_leaf.p12",
        vec![cn_mapping("alice", "alice")],
        (),
        "alice",
        "correct-pin",
        vec![],
        "host-T-hash",
    )
    .unwrap_err();
    assert!(
        matches!(err, FlowError::Trust(TrustError::Validity(_))),
        "expected Trust(Validity), got {err:?}"
    );
    assert_eq!(err.pam_code(), 6); // PAM_PERM_DENIED
}

//! Orchestrator decision-tree tests, driven by the `MockMacBackend`.

#![cfg(feature = "mac-tests")]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants
)]

use tessera_core::config::validated::{CertIntegrityMode, MacPolicy, MacRuntimeMode};
use tessera_core::mac::backend::{MacError, MacRuntime, MockMacBackend};
use tessera_core::mac::orchestrator::{
    apply_session_policy, OrchestratorError, OutcomeKind, SessionContext,
};
use tessera_core::mac::IntegrityLabel;
use tessera_core::x509::CertIdent;

fn ident() -> CertIdent {
    CertIdent {
        serial: "01".into(),
        issuer: "CN=Test".into(),
        cn: "alice".into(),
        fingerprint: "deadbeef".into(),
    }
}

fn ctx(service: &str) -> SessionContext {
    SessionContext {
        pam_user: "alice".into(),
        pam_service: service.into(),
        cert_ident: ident(),
        home_dir: None,
    }
}

fn policy(mode: CertIntegrityMode) -> MacPolicy {
    MacPolicy {
        cert_integrity: mode,
        fallback_max_integrity: None,
        warn_on_homedir_label_mismatch: true,
        runtime: MacRuntimeMode::Auto,
    }
}

#[test]
fn ignore_mode_skips_without_probing_backend() {
    // No backend expectations set — orchestrator must not call anything.
    let backend = MockMacBackend::new();
    let p = policy(CertIntegrityMode::Ignore);
    let out = apply_session_policy(&backend, &p, None, None, &ctx("login")).unwrap();
    match out.kind {
        OutcomeKind::Skipped("policy_ignore") => {}
        other => panic!("expected Skipped(policy_ignore), got {other:?}"),
    }
}

#[test]
fn required_with_inactive_runtime_returns_runtime_required() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Unavailable);
    let p = policy(CertIntegrityMode::Required);
    let err = apply_session_policy(&backend, &p, None, None, &ctx("login")).unwrap_err();
    matches!(
        err,
        OrchestratorError::RuntimeRequired(MacRuntime::Unavailable)
    );
}

#[test]
fn optional_with_inactive_runtime_skips() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Disabled);
    let p = policy(CertIntegrityMode::Optional);
    let out = apply_session_policy(&backend, &p, None, None, &ctx("login")).unwrap();
    match out.kind {
        OutcomeKind::Skipped("runtime_inactive") => {}
        other => panic!("expected Skipped(runtime_inactive), got {other:?}"),
    }
}

#[test]
fn required_active_runtime_but_cert_no_ext_returns_cert_lacks_ext() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    let p = policy(CertIntegrityMode::Required);
    let err = apply_session_policy(&backend, &p, None, None, &ctx("login")).unwrap_err();
    matches!(err, OrchestratorError::CertLacksExt);
}

#[test]
fn required_active_runtime_applies_intersection_with_user_mnkc() {
    let cert = IntegrityLabel {
        level: 5,
        categories: 0x0F,
    };
    let user = IntegrityLabel {
        level: 3,
        categories: 0xFF,
    };
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(move |_| Ok(user));
    backend.expect_apply_session().returning(|_| Ok(()));

    let p = policy(CertIntegrityMode::Required);
    let out = apply_session_policy(&backend, &p, Some(cert), None, &ctx("login")).unwrap();
    match out.kind {
        OutcomeKind::Applied(lab) => {
            assert_eq!(lab.level, 3);
            assert_eq!(lab.categories, 0x0F);
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

#[test]
fn optional_no_ext_uses_fallback_when_configured() {
    let user = IntegrityLabel {
        level: 7,
        categories: 0xFF,
    };
    let fallback = IntegrityLabel {
        level: 2,
        categories: 0,
    };
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(move |_| Ok(user));
    backend.expect_apply_session().returning(|_| Ok(()));

    let p = MacPolicy {
        cert_integrity: CertIntegrityMode::Optional,
        fallback_max_integrity: Some(fallback),
        warn_on_homedir_label_mismatch: false,
        runtime: MacRuntimeMode::Auto,
    };
    let out = apply_session_policy(&backend, &p, None, None, &ctx("login")).unwrap();
    match out.kind {
        OutcomeKind::Applied(lab) => {
            assert_eq!(lab.level, 2);
            // intersect_cert_with_user: fallback.categories == 0 → user.categories preserved.
            assert_eq!(lab.categories, 0xFF);
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

#[test]
fn apply_session_error_translates_to_apply_failed() {
    let user = IntegrityLabel {
        level: 1,
        categories: 0,
    };
    let cert = IntegrityLabel {
        level: 1,
        categories: 0,
    };
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(move |_| Ok(user));
    backend.expect_apply_session().returning(|_| {
        Err(MacError::Parsec {
            op: "set_proc",
            rc: -1,
        })
    });

    let p = policy(CertIntegrityMode::Required);
    let err = apply_session_policy(&backend, &p, Some(cert), None, &ctx("login")).unwrap_err();
    matches!(err, OrchestratorError::ApplyFailed(_));
}

// ---- 5.1: role mac_mask threaded as the requested label -----------------

#[test]
fn role_mask_covered_applies_mask_intersection() {
    // Ceiling grants categories 0b111 at level 5; user МНКЦ grants 0b110 at
    // level 3; role requests mask 0b100 (a category-only label, level 0).
    // effective = mask ∩ ceiling ∩ user = level min(0,5,3)=0, cats
    // 0b100 & 0b111 & 0b110 = 0b100.
    let cert = IntegrityLabel {
        level: 5,
        categories: 0b111,
    };
    let user = IntegrityLabel {
        level: 3,
        categories: 0b110,
    };
    let mask = IntegrityLabel::from_mac_mask(0b100);
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(move |_| Ok(user));
    backend.expect_apply_session().returning(|_| Ok(()));

    let p = policy(CertIntegrityMode::Required);
    let out = apply_session_policy(&backend, &p, Some(cert), Some(mask), &ctx("login")).unwrap();
    match out.kind {
        OutcomeKind::Applied(lab) => {
            assert_eq!(lab.level, 0);
            assert_eq!(lab.categories, 0b100);
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

#[test]
fn role_mask_exceeds_ceiling_denies() {
    // Spec scenario: mask = 0b110, ceiling = 0b100 → deny (not narrowing).
    let cert = IntegrityLabel {
        level: 5,
        categories: 0b100,
    };
    let mask = IntegrityLabel::from_mac_mask(0b110);
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    // get_user_mnkc is called before the mask check; apply_session must not be.
    backend.expect_get_user_mnkc().returning(move |_| {
        Ok(IntegrityLabel {
            level: 5,
            categories: 0b111,
        })
    });

    let p = policy(CertIntegrityMode::Required);
    let err =
        apply_session_policy(&backend, &p, Some(cert), Some(mask), &ctx("login")).unwrap_err();
    assert!(matches!(err, OrchestratorError::MaskExceedsCeiling));
}

#[test]
fn no_role_mask_uses_prior_min_semantics() {
    // Without a role mask, effective = min(ceiling, user МНКЦ) as before.
    let cert = IntegrityLabel {
        level: 5,
        categories: 0x0F,
    };
    let user = IntegrityLabel {
        level: 3,
        categories: 0xFF,
    };
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(move |_| Ok(user));
    backend.expect_apply_session().returning(|_| Ok(()));

    let p = policy(CertIntegrityMode::Required);
    let out = apply_session_policy(&backend, &p, Some(cert), None, &ctx("login")).unwrap();
    match out.kind {
        OutcomeKind::Applied(lab) => {
            assert_eq!(lab.level, 3);
            assert_eq!(lab.categories, 0x0F);
        }
        other => panic!("expected Applied, got {other:?}"),
    }
}

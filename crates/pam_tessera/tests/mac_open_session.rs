//! Smoke test for the open-session MAC pipeline.  Drives
//! [`pam_tessera::session::run_open_session_pipeline_with_backend`]
//! through the same code path the cdylib's `pam_sm_open_session`
//! invokes, using a `MockMacBackend` to assert the orchestrator was
//! wired up correctly.

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Mutex;

use pam_tessera::session::{
    run_open_session_pipeline_with_backend, run_open_session_pipeline_with_backend_and_monitor,
};
use tessera_core::config::validated::{
    CertIntegrityMode, MacPolicy, MacRuntimeMode, ValidatedConfig,
};
use tessera_core::error::IpcError;
use tessera_core::ipc::{MonitorClient, OpenSessionInfo};
use tessera_core::mac::backend::{MacRuntime, MockMacBackend};
use tessera_core::mac::IntegrityLabel;
use tessera_core::pam_data::AuthContext;
use tessera_core::x509::CertIdent;

/// Records every `close_session` invocation so tests can assert that the
/// MAC-denial cleanup path fires with the right `session_id`.
#[derive(Default)]
struct RecordingMonitor {
    closes: Mutex<Vec<(String, String)>>,
}

impl MonitorClient for RecordingMonitor {
    fn hello(&self) -> Result<(), IpcError> {
        Ok(())
    }
    fn open_session(&self, _info: &OpenSessionInfo<'_>) -> Result<(), IpcError> {
        Ok(())
    }
    fn close_session(&self, session_id: &str, reason: &str) -> Result<(), IpcError> {
        self.closes
            .lock()
            .unwrap()
            .push((session_id.to_string(), reason.to_string()));
        Ok(())
    }
    fn ping(&self) -> Result<(), IpcError> {
        Ok(())
    }
}

mod common;

fn make_ctx() -> AuthContext {
    let mut ctx = AuthContext::new("sess-1".into(), "login".into());
    ctx.cert_cn = Some("alice".into());
    ctx.cert_serial = Some("01".into());
    ctx.cert_max_integrity = Some(IntegrityLabel {
        level: 3,
        categories: 0,
    });
    ctx.cert_ident = Some(CertIdent {
        serial: "01".into(),
        issuer: "CN=Test".into(),
        cn: "alice".into(),
        fingerprint: "deadbeef".into(),
    });
    ctx
}

fn cfg_with_mac(mode: CertIntegrityMode) -> ValidatedConfig {
    let mut cfg = common::minimal_cfg();
    cfg.mac = MacPolicy {
        backend: None,
        cert_integrity: mode,
        fallback_max_integrity: None,
        warn_on_homedir_label_mismatch: false,
        runtime: MacRuntimeMode::Auto,
    };
    cfg
}

#[test]
fn open_session_applies_when_runtime_active() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(|_| {
        Ok(IntegrityLabel {
            level: 5,
            categories: 0,
        })
    });
    backend.expect_apply_session().returning(|_| Ok(()));

    let cfg = cfg_with_mac(CertIntegrityMode::Required);
    let ctx = make_ctx();
    let r = run_open_session_pipeline_with_backend(&backend, &cfg, &ctx, "alice");
    assert!(r.is_ok(), "expected Ok, got {r:?}");
}

#[test]
fn open_session_skips_when_runtime_unavailable_optional() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Unavailable);
    let cfg = cfg_with_mac(CertIntegrityMode::Optional);
    let ctx = make_ctx();
    let r = run_open_session_pipeline_with_backend(&backend, &cfg, &ctx, "alice");
    assert!(r.is_ok(), "expected Ok (skipped), got {r:?}");
}

#[test]
fn open_session_fails_when_required_but_runtime_unavailable() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Unavailable);
    let cfg = cfg_with_mac(CertIntegrityMode::Required);
    let ctx = make_ctx();
    let r = run_open_session_pipeline_with_backend(&backend, &cfg, &ctx, "alice");
    // PAM_AUTH_ERR == 7.
    assert_eq!(r, Err(7));
}

#[test]
fn open_session_fails_when_required_but_cert_lacks_ext() {
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    let cfg = cfg_with_mac(CertIntegrityMode::Required);
    let mut ctx = make_ctx();
    ctx.cert_max_integrity = None;
    let r = run_open_session_pipeline_with_backend(&backend, &cfg, &ctx, "alice");
    assert_eq!(r, Err(7));
}

#[test]
fn mac_denial_invokes_close_session_for_cleanup() {
    // Orchestrator rejects: cert_max_integrity is None but mode is Required
    // → OrchestratorError::CertLacksExt → PAM_AUTH_ERR (7).  The
    // upstream `pam_sm_authenticate` already registered an `open_session`
    // with monitord; pair it with `close_session` so the registry entry
    // does not stick as "active".
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    let cfg = cfg_with_mac(CertIntegrityMode::Required);
    let mut ctx = make_ctx();
    ctx.cert_max_integrity = None;

    let monitor = RecordingMonitor::default();
    let r = run_open_session_pipeline_with_backend_and_monitor(
        &backend,
        Some(&monitor),
        &cfg,
        &ctx,
        "alice",
    );
    assert_eq!(r, Err(7));

    let closes = monitor.closes.lock().unwrap();
    assert_eq!(closes.len(), 1, "expected exactly one close_session call");
    assert_eq!(
        closes[0].0, "sess-1",
        "close_session must carry ctx.session_id"
    );
    assert_eq!(
        closes[0].1, "mac_denied",
        "close_session reason must identify the MAC denial cause",
    );
}

#[test]
fn mac_success_does_not_invoke_close_session() {
    // Happy path must not double-close: `pam_sm_close_session` is the
    // canonical pair for the authenticate-time `open_session`.
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(|_| {
        Ok(IntegrityLabel {
            level: 5,
            categories: 0,
        })
    });
    backend.expect_apply_session().returning(|_| Ok(()));

    let cfg = cfg_with_mac(CertIntegrityMode::Required);
    let ctx = make_ctx();
    let monitor = RecordingMonitor::default();
    let r = run_open_session_pipeline_with_backend_and_monitor(
        &backend,
        Some(&monitor),
        &cfg,
        &ctx,
        "alice",
    );
    assert!(r.is_ok(), "expected Ok, got {r:?}");
    assert!(
        monitor.closes.lock().unwrap().is_empty(),
        "close_session must not fire on the happy path",
    );
}

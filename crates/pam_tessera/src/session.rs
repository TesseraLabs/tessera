//! Session-open glue between PAM, the MAC orchestrator, and the
//! configured [`tessera_core::mac::backend::MacBackend`].
//!
//! Kept in its own module so the orchestrator wiring can be exercised
//! by tests under `--features mac-tests` without dragging in the cdylib
//! PAM symbols.

use tessera_core::config::validated::MacRuntimeMode;
use tessera_core::config::ValidatedConfig;
use tessera_core::ipc::{
    ConnectPerCall, FailModeWrapper, MonitorClient, MonitorClientFactory,
};
#[cfg(feature = "astra-mac")]
use tessera_core::mac::audit::{
    emit_mac_runtime_required, emit_runtime_disabled, emit_runtime_fallback,
};
use tessera_core::mac::backend::MacBackend;
use tessera_core::mac::backend::StubBackend;
#[cfg(feature = "astra-mac")]
use tessera_core::mac::backend::MacRuntime;
#[cfg(feature = "astra-mac")]
use tessera_mac_parsec::ParsecBackend;
use tessera_core::mac::orchestrator::{
    apply_session_policy, OrchestratorError, SessionContext,
};
use tessera_core::pam_data::AuthContext;
use tessera_core::x509::CertIdent;

/// `PAM_AUTH_ERR` — same numeric value as in `entry.rs`.
const PAM_AUTH_ERR: i32 = 7;
/// `PAM_SESSION_ERR` — keep in lock-step with `entry.rs`.
const PAM_SESSION_ERR: i32 = 14;

/// Build the active backend, honouring `[mac].runtime` at runtime
/// (independent of the compile-time `astra-mac` feature).
///
/// Selection matrix (a — compile-time astra-mac feature, k — kernel МКЦ
/// active per `parsec_strict_mode`):
///
/// | runtime    | a=no             | a=yes, k=no                       | a=yes, k=yes |
/// |------------|------------------|-----------------------------------|--------------|
/// | required   | rejected at cfg  | `Err(PAM_AUTH_ERR)` (fail-closed) | Parsec       |
/// | auto       | Stub             | Stub + `mac_runtime_fallback`     | Parsec       |
/// | disabled   | Stub             | Stub + `mac_runtime_disabled`     | Stub + log   |
///
/// Returns `Err(PAM_AUTH_ERR)` only in the `required` + kernel-missing
/// combination; everything else degrades to a working backend.
#[cfg_attr(not(feature = "astra-mac"), allow(clippy::unnecessary_wraps))]
fn build_backend(mac_runtime: MacRuntimeMode) -> Result<Box<dyn MacBackend>, i32> {
    #[cfg(feature = "astra-mac")]
    {
        match mac_runtime {
            MacRuntimeMode::Disabled => {
                emit_runtime_disabled();
                Ok(Box::new(StubBackend::new()))
            }
            MacRuntimeMode::Required => {
                let backend = ParsecBackend::new();
                if matches!(backend.probe(), MacRuntime::Active) {
                    Ok(Box::new(backend))
                } else {
                    emit_mac_runtime_required("kernel parsec subsystem not active");
                    Err(PAM_AUTH_ERR)
                }
            }
            MacRuntimeMode::Auto => {
                let backend = ParsecBackend::new();
                if matches!(backend.probe(), MacRuntime::Active) {
                    Ok(Box::new(backend))
                } else {
                    emit_runtime_fallback(
                        "kernel parsec subsystem not active (parsec_strict_mode != 1)",
                    );
                    Ok(Box::new(StubBackend::new()))
                }
            }
        }
    }
    #[cfg(not(feature = "astra-mac"))]
    {
        // Stub-only builds always use the stub backend. `runtime = "required"`
        // is rejected by validate_mac() in this configuration, so we should
        // only see `Auto` or `Disabled` here.
        let _ = mac_runtime;
        Ok(Box::new(StubBackend::new()))
    }
}

/// Run the MAC orchestrator for an open-session call.  Maps orchestrator
/// failures onto PAM return codes:
///
/// * `RuntimeRequired` / `CertLacksExt` → `PAM_AUTH_ERR` (cert/policy
///   contract violated — refuse to open a session).
/// * `ApplyFailed` → `PAM_SESSION_ERR` (the runtime decided we cannot
///   safely apply the label).
///
/// # Errors
///
/// On failure returns the PAM return code the cdylib should propagate.
pub fn run_open_session_pipeline(
    cfg: &ValidatedConfig,
    ctx: &AuthContext,
    pam_user: &str,
) -> Result<(), i32> {
    let backend = build_backend(cfg.mac.runtime)?;
    // Build a production monitor client matching `di::wire`'s policy so we
    // can pair the `open_session` registered during `pam_sm_authenticate`
    // with a `close_session` on MAC denial. Without this, a session whose
    // open-session pipeline is rejected stays "active" in monitord's
    // registry — see entry.rs `pam_sm_open_session` for the upstream
    // `open_session` call site.
    let factory = MonitorClientFactory::new(cfg.monitor.socket_path.clone(), cfg.monitor.timeout);
    let connect_per_call = ConnectPerCall::new(factory);
    let monitor: Box<dyn MonitorClient> = Box::new(FailModeWrapper::new(
        connect_per_call,
        cfg.monitor.fail_mode.into(),
    ));
    run_open_session_pipeline_with_backend_and_monitor(
        backend.as_ref(),
        Some(monitor.as_ref()),
        cfg,
        ctx,
        pam_user,
    )
}

/// Test-friendly variant accepting a `&dyn MacBackend`.
///
/// Cleanup of an upstream `monitor.open_session` is not performed by this
/// overload; tests that want to observe `close_session` on MAC denial
/// should call [`run_open_session_pipeline_with_backend_and_monitor`].
///
/// # Errors
///
/// See [`run_open_session_pipeline`].
pub fn run_open_session_pipeline_with_backend(
    backend: &dyn MacBackend,
    cfg: &ValidatedConfig,
    ctx: &AuthContext,
    pam_user: &str,
) -> Result<(), i32> {
    run_open_session_pipeline_with_backend_and_monitor(backend, None, cfg, ctx, pam_user)
}

/// Test-friendly variant accepting both a `&dyn MacBackend` and an
/// optional `&dyn MonitorClient`. On a MAC orchestrator error, before
/// returning the PAM code, we call `monitor.close_session(session_id,
/// "mac_denied")` to release the registry entry that
/// `pam_sm_authenticate` opened. A monitor cleanup failure is logged
/// at warn level and does **not** override the original MAC error
/// (don't mask the root cause).
///
/// # Errors
///
/// See [`run_open_session_pipeline`].
pub fn run_open_session_pipeline_with_backend_and_monitor(
    backend: &dyn MacBackend,
    monitor: Option<&dyn MonitorClient>,
    cfg: &ValidatedConfig,
    ctx: &AuthContext,
    pam_user: &str,
) -> Result<(), i32> {
    let cert_ident = ctx.cert_ident.clone().unwrap_or(CertIdent {
        serial: ctx.cert_serial.clone().unwrap_or_default(),
        issuer: String::new(),
        cn: ctx.cert_cn.clone().unwrap_or_default(),
        fingerprint: String::new(),
    });
    let sctx = SessionContext {
        pam_user: pam_user.to_string(),
        pam_service: ctx.pam_service.clone(),
        cert_ident,
        home_dir: ctx.home_dir.clone(),
    };

    let result = match apply_session_policy(backend, &cfg.mac, ctx.cert_max_integrity, &sctx) {
        Ok(_) => Ok(()),
        Err(OrchestratorError::CertLacksExt | OrchestratorError::RuntimeRequired(_)) => {
            tracing::error!(
                target: "tessera.session",
                pam_user = %pam_user,
                "MAC orchestrator refused session (policy violation)",
            );
            Err(PAM_AUTH_ERR)
        }
        Err(OrchestratorError::ApplyFailed(e)) => {
            tracing::error!(
                target: "tessera.session",
                pam_user = %pam_user,
                error = %e,
                "MAC orchestrator apply failed",
            );
            Err(PAM_SESSION_ERR)
        }
    };

    // Pair the upstream `monitor.open_session` (registered during
    // `pam_sm_authenticate`) with a `close_session` on any MAC denial so
    // we don't leak an "active" session entry in monitord's registry.
    // A cleanup failure is logged but never masks the underlying MAC
    // error — the root cause must reach PAM unaltered.
    if result.is_err() {
        if let Some(m) = monitor {
            if let Err(e) = m.close_session(&ctx.session_id, "mac_denied") {
                tracing::warn!(
                    target: "tessera.session",
                    session_id = %ctx.session_id,
                    error = %e,
                    "monitor close_session cleanup failed after MAC denial (non-fatal)",
                );
            }
        }
    }
    result
}

/// Test-only re-exports.  Available only under `mac-tests`.
#[cfg(feature = "mac-tests")]
pub mod test_only {
    /// `PAM_AUTH_ERR` numeric value.
    pub const PAM_AUTH_ERR: i32 = super::PAM_AUTH_ERR;
    /// `PAM_SESSION_ERR` numeric value.
    pub const PAM_SESSION_ERR: i32 = super::PAM_SESSION_ERR;
    pub use super::{
        run_open_session_pipeline_with_backend, run_open_session_pipeline_with_backend_and_monitor,
    };
}

//! PAM entry points (`pam_sm_*`) for the cdylib.
//!
//! Stage 2 wires up the full authentication flow:
//!
//! 1. Load + validate config.
//! 2. Run config self-check (hooks placeholders, paths, etc.).
//! 3. Read `PAM_USER` / `PAM_SERVICE` off the live handle.
//! 4. Wire dependencies via [`crate::di::wire`].
//! 5. Resolve host identity.
//! 6. Load + parse the host ACL (signature verification will follow in
//!    a later stage; today we accept the file as-is when present).
//! 7. Drive [`crate::flow::authenticate`].
//! 8. Map success / [`crate::flow::FlowError`] to PAM return codes.
//!
//! The other `pam_sm_*` hooks (`acct_mgmt`, `open_session`, `close_session`,
//! `setcred`) are wired to the [`AuthContext`] stored in PAM data by
//! `pam_sm_authenticate`.
#![allow(
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::must_use_candidate,
    clippy::cast_sign_loss
)]

pub use crate::panic_guard::{PAM_AUTHINFO_UNAVAIL, PAM_SUCCESS};

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
const PAM_AUTH_ERR: i32 = 7;
#[cfg(target_os = "linux")]
const PAM_SYSTEM_ERR: i32 = 4;
#[cfg(target_os = "linux")]
const PAM_ACCT_EXPIRED: i32 = 13;

/// Parse `key=value` PAM module args.
#[cfg(target_os = "linux")]
///
/// # Safety
///
/// `argv` must point to `argc` valid C string pointers, as provided by PAM.
pub unsafe fn collect_args(
    argc: i32,
    argv: *const *const std::ffi::c_char,
) -> std::collections::BTreeMap<String, String> {
    let mut args = std::collections::BTreeMap::new();
    if argc <= 0 || argv.is_null() {
        return args;
    }
    for i in 0..argc {
        let ptr = unsafe { *argv.add(i as usize) };
        if ptr.is_null() {
            continue;
        }
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy();
        if let Some((k, v)) = s.split_once('=') {
            args.insert(k.to_string(), v.to_string());
        }
    }
    args
}

#[cfg(target_os = "linux")]
fn config_path_from_args(args: &BTreeMap<String, String>) -> PathBuf {
    args.get("config").map_or_else(
        || PathBuf::from("/etc/tessera/config.toml"),
        PathBuf::from,
    )
}

/// Map a PAM_TTY string into a [`tessera_proto::SessionTarget`].
///
/// PAM stores either a tty path (`/dev/tty1`, `/dev/pts/0`) or an X11/Wayland
/// display name prefixed with `:` (e.g. `:0`, `:1.0`). We classify by leading
/// `:` because tty paths always start with `/`.
#[cfg(target_os = "linux")]
fn parse_pam_tty(tty: Option<&str>) -> tessera_proto::SessionTarget {
    match tty {
        None => tessera_proto::SessionTarget::Unknown,
        Some(s) if s.starts_with(':') => tessera_proto::SessionTarget::display(s),
        Some(s) => tessera_proto::SessionTarget::tty(s),
    }
}

/// Generate a cryptographically random session id by hex-encoding 16 bytes
/// from the OS RNG (`getrandom`/`OsRng`).
///
/// # Errors
///
/// Returns the underlying I/O error if the OS RNG cannot supply randomness.
/// Callers MUST fail closed (return `PAM_AUTHINFO_UNAVAIL`) — there is
/// deliberately no SystemTime fallback because session ids are used as
/// security-relevant correlation tokens (mountpoint segment, IPC handshake).
#[cfg(target_os = "linux")]
fn fresh_session_id() -> Result<String, std::io::Error> {
    use rand::rngs::SysRng;
    use rand::TryRng;
    let mut buf = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| std::io::Error::other(format!("SysRng: {e}")))?;
    let mut s = String::with_capacity(5 + 32);
    s.push_str("sess-");
    s.push_str(&hex::encode(buf));
    Ok(s)
}

#[cfg(target_os = "linux")]
#[no_mangle]
/// PAM authenticate entry.
///
/// # Safety
///
/// Called by PAM with a valid handle and argument vector.
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_sys::pam_handle_t,
    _flags: i32,
    argc: i32,
    argv: *const *const std::ffi::c_char,
) -> i32 {
    crate::panic_guard::run_pam(|| {
        crate::logging::init_once();
        // 1. Args + config.
        let args = unsafe { collect_args(argc, argv) };
        let cfg_path = config_path_from_args(&args);
        let cfg = match tessera_core::config::load_validated_config(&cfg_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(target: "tessera.auth", error = %err, "config load failed");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };
        if let Err(err) = tessera_core::self_check::self_check(&cfg) {
            tracing::error!(target: "tessera.auth", error = %err, "self-check failed");
            return PAM_AUTHINFO_UNAVAIL;
        }

        // 2. PAM_USER / PAM_SERVICE.
        let pam_user = match unsafe { crate::pam_helpers::pam_get_user_string(pamh) } {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(target: "tessera.auth", error = %err, "pam_get_user failed");
                return PAM_AUTH_ERR;
            }
        };
        let pam_service = unsafe { crate::pam_helpers::pam_get_service_string(pamh) }
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tessera.auth", error = %err, "pam_get_item(PAM_SERVICE) failed; using 'unknown'");
                "unknown".to_string()
            });
        let pam_tty_value =
            unsafe { crate::pam_helpers::pam_get_tty_string(pamh) }.unwrap_or_else(|err| {
                tracing::debug!(
                    target: "tessera.auth",
                    error = %err,
                    "pam_get_item(PAM_TTY) failed; session target will be Unknown"
                );
                None
            });
        let pam_target = parse_pam_tty(pam_tty_value.as_deref());

        // 3. Resolve host identity (before wire so we fail fast on misconfig).
        let (host_id_source, _host_id_raw, host_id_hash) = match crate::resolve_host_identity(&cfg)
        {
            Ok(t) => t,
            Err(err) => {
                tracing::error!(target: "tessera.auth", error = %err, "host identity unresolved");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };

        // 4. Wire trust verifier + monitor (consumes cfg; we keep wired.cfg).
        let wired = match crate::di::wire(cfg) {
            Ok(w) => w,
            Err(err) => {
                tracing::error!(target: "tessera.auth", error = %err, "wiring failed");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };

        // 5. (Removed) Host ACL loading is gone — the cert's
        // `pam_cert_host_binding` and `pam_cert_user_binding` extensions
        // are the sole source of authorisation. See docs/cert-issuance.md.

        // 6. Build the PIN prompter against the live PAM handle.
        let mut prompt_pin = unsafe { crate::pam_conv::closure_from_pamh(pamh) };

        // 7. RealFlowIo wires udev + mount(2).
        let session_id = match fresh_session_id() {
            Ok(s) => s,
            Err(err) => {
                tracing::error!(target: "tessera.auth", error = %err, "OS RNG unavailable; cannot mint session id");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };
        let usb_wait = wired.cfg.usb_wait;
        let mountpoint_base = PathBuf::from("/run/tessera/mounts");
        if let Err(err) = std::fs::create_dir_all(&mountpoint_base) {
            tracing::warn!(target: "tessera.auth", error = %err, base = %mountpoint_base.display(), "create mountpoint base failed");
        }
        let real_io = crate::flow::RealFlowIo::new(
            usb_wait,
            None,
            wired.cfg.max_usb_partitions as usize,
            mountpoint_base,
            session_id.clone(),
        )
        .with_pamh(pamh);

        // 8. Drive the flow.
        // Stage 5: real fork+execve hook executor. The struct is stateless;
        // we instantiate it on the stack per call.
        let hook_executor = tessera_core::hooks::ForkExecExecutor::new();
        let deps = crate::flow::Deps {
            cfg: &wired.cfg,
            trust: &wired.trust,
            monitor: &*wired.monitor,
            hook_executor: &hook_executor,
            host_id_hash: &host_id_hash,
            host_id_source,
            user_mappings: &wired.cfg.user_mappings,
            pam_target,
        };
        let outcome = crate::flow::authenticate(
            deps,
            &real_io,
            &pam_user,
            &pam_service,
            session_id,
            |prompt| prompt_pin(prompt),
        );

        // 9. Map outcome → PAM rc.
        match outcome {
            Ok(out) => {
                let crate::flow::FlowOutcome { auth_ctx, mount } = out;
                // For PKCS#11 mode `mount` is `None`; for PKCS#12 it
                // owns the USB mountpoint.
                if let Err(err) = unsafe { crate::data_handle::set_auth_context(pamh, auth_ctx) } {
                    tracing::error!(target: "tessera.auth", error = %err, "set_auth_context failed");
                    return PAM_SYSTEM_ERR;
                }
                // Drop the mount guard at end of `pam_sm_authenticate`; the
                // session cleanup will re-mount on `pam_sm_open_session`
                // via a future stage.  For now we explicitly drop to keep
                // semantics obvious.
                drop(mount);
                PAM_SUCCESS
            }
            Err(err) => {
                tracing::warn!(target: "tessera.auth", error = %err, "authentication failed");
                err.pam_code()
            }
        }
    })
}

#[cfg(target_os = "linux")]
#[no_mangle]
/// PAM setcred entry.
///
/// # Safety
///
/// Called by PAM with a valid handle.
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_sys::pam_handle_t,
    _flags: i32,
    _argc: i32,
    _argv: *const *const std::ffi::c_char,
) -> i32 {
    crate::panic_guard::run_pam(|| {
        crate::logging::init_once();
        PAM_SUCCESS
    })
}

#[cfg(target_os = "linux")]
#[no_mangle]
/// PAM account management entry.
///
/// # Safety
///
/// Called by PAM with a valid handle.
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut pam_sys::pam_handle_t,
    _flags: i32,
    _argc: i32,
    _argv: *const *const std::ffi::c_char,
) -> i32 {
    crate::panic_guard::run_pam(|| {
        crate::logging::init_once();
        let Some(ctx) = (unsafe { crate::data_handle::get_auth_context(pamh) }) else {
            return PAM_AUTHINFO_UNAVAIL;
        };
        match crate::acct_mgmt_core(ctx, std::time::SystemTime::now()) {
            PAM_SUCCESS => PAM_SUCCESS,
            PAM_ACCT_EXPIRED => PAM_ACCT_EXPIRED,
            _ => PAM_SYSTEM_ERR,
        }
    })
}

/// PAM_SESSION_ERR literal — kept here so we don't pull `pam-sys` into the
/// non-Linux build.
#[cfg(target_os = "linux")]
const PAM_SESSION_ERR: i32 = 14;

#[cfg(target_os = "linux")]
#[no_mangle]
/// PAM open session entry.
///
/// Stage 5: runs every `session_open` hook configured in the validated
/// config.  A non-recoverable hook failure (executor error, or
/// `on_failure = abort` plus non-zero exit / timeout) maps to
/// `PAM_SESSION_ERR`.  A missing config or absent [`AuthContext`] is
/// surfaced as `PAM_AUTHINFO_UNAVAIL`.
///
/// # Safety
///
/// Called by PAM with a valid handle.
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut pam_sys::pam_handle_t,
    _flags: i32,
    argc: i32,
    argv: *const *const std::ffi::c_char,
) -> i32 {
    crate::panic_guard::run_pam(|| {
        crate::logging::init_once();
        // 1. Args + config.
        let args = unsafe { collect_args(argc, argv) };
        let cfg_path = config_path_from_args(&args);
        let cfg = match tessera_core::config::load_validated_config(&cfg_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(target: "tessera.session", error = %err, "config load failed");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };

        let Some(ctx) = (unsafe { crate::data_handle::get_auth_context(pamh) }) else {
            return PAM_AUTHINFO_UNAVAIL;
        };

        // PAM user (best-effort: fall back to cert_cn if PAM_USER is gone).
        let pam_user = unsafe { crate::pam_helpers::pam_get_user_string(pamh) }
            .unwrap_or_else(|_| ctx.cert_cn.clone().unwrap_or_default());

        // MAC integrity — orchestrator decides whether to apply a label,
        // skip (runtime inactive / policy ignore), or fail closed.  We
        // always invoke it; the orchestrator honours the policy.
        match crate::session::run_open_session_pipeline(&cfg, ctx, &pam_user) {
            Ok(()) => {}
            Err(rc) => return rc,
        }

        // Capture XDG_SESSION_ID (set by pam_systemd.so in the session
        // phase) and push it to monitord so the action handler can call
        // terminate_session / lock with a real logind id on USB removal.
        //
        // Called twice per login (see integrate-pam.sh): the first
        // invocation usually sees XDG = NULL because pam_systemd has
        // not yet run, the second invocation (after @include
        // common-session) sees it set. Both are best-effort: an IPC
        // failure logs WARN but never breaks PAM auth.
        {
            let xdg = match unsafe {
                crate::pam_helpers::pam_get_env_string(pamh, "XDG_SESSION_ID")
            } {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(
                        target: "tessera.session",
                        session_id = %ctx.session_id,
                        error = %err,
                        "pam_getenv(XDG_SESSION_ID) failed",
                    );
                    None
                }
            };
            let session_uuid =
                crate::xdg_capture::session_uuid_from_string(&ctx.session_id);
            let socket_path = cfg.monitor.socket_path.clone();
            let timeout = cfg.monitor.timeout;
            let _ = crate::xdg_capture::capture_xdg(
                session_uuid,
                xdg.as_deref(),
                |target| {
                    let mut client =
                        tessera_core::ipc::MonitordClient::connect(&socket_path, timeout)?;
                    client.send_update_session_target(session_uuid, target)
                },
            );
        }

        let vars = tessera_core::hooks::HookVars::for_session_open(&pam_user, ctx);
        let executor = tessera_core::hooks::ForkExecExecutor::new();

        tracing::info!(
            target: "tessera.session",
            session_id = %ctx.session_id,
            pam_user = %pam_user,
            "open_session: running session_open hooks",
        );

        match tessera_core::hooks::run_hooks_for_stage(
            &cfg,
            tessera_core::hooks::HookStage::SessionOpen,
            &executor,
            &vars,
        ) {
            Ok(()) => PAM_SUCCESS,
            Err(err) => {
                tracing::error!(
                    target: "tessera.session",
                    error = %err,
                    "session_open hook failed",
                );
                PAM_SESSION_ERR
            }
        }
    })
}

#[cfg(target_os = "linux")]
#[no_mangle]
/// PAM close session entry.
///
/// Stage 5: runs every `session_close` hook configured in the validated
/// config.  Unlike `session_open`, hook errors are **logged but not
/// surfaced** — close-session failures cannot block user logout because
/// the user is already authenticated and gone; an irreversible error
/// here just produces noise without recourse.  This asymmetry is
/// documented in `docs/stage-5-hooks.md`.
///
/// # Safety
///
/// Called by PAM with a valid handle.
pub unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut pam_sys::pam_handle_t,
    _flags: i32,
    argc: i32,
    argv: *const *const std::ffi::c_char,
) -> i32 {
    crate::panic_guard::run_pam(|| {
        crate::logging::init_once();
        let args = unsafe { collect_args(argc, argv) };
        let cfg_path = config_path_from_args(&args);
        let cfg = match tessera_core::config::load_validated_config(&cfg_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(target: "tessera.session", error = %err, "config load failed (close)");
                return PAM_SUCCESS;
            }
        };

        if let Some(ctx) = unsafe { crate::data_handle::get_auth_context(pamh) } {
            let pam_user = unsafe { crate::pam_helpers::pam_get_user_string(pamh) }
                .unwrap_or_else(|_| ctx.cert_cn.clone().unwrap_or_default());

            let vars = tessera_core::hooks::HookVars::for_session_close(&pam_user, ctx);
            let executor = tessera_core::hooks::ForkExecExecutor::new();

            tracing::info!(
                target: "tessera.session",
                session_id = %ctx.session_id,
                "close_session: running session_close hooks",
            );

            if let Err(err) = tessera_core::hooks::run_hooks_for_stage(
                &cfg,
                tessera_core::hooks::HookStage::SessionClose,
                &executor,
                &vars,
            ) {
                tracing::error!(
                    target: "tessera.session",
                    error = %err,
                    "session_close hook failed (best-effort, ignored)",
                );
            }
        }
        PAM_SUCCESS
    })
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod session_id_tests {
    use super::fresh_session_id;

    #[test]
    fn fresh_session_id_is_unique_and_well_formed() {
        let a = fresh_session_id().expect("getrandom available in tests");
        let b = fresh_session_id().expect("getrandom available in tests");
        assert!(a.starts_with("sess-"));
        assert_eq!(a.len(), 5 + 32, "sess- + 32 hex chars");
        assert!(a[5..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two ids must differ with overwhelming probability");
    }
}

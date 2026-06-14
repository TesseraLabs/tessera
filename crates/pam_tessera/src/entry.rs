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

/// `PAM_PROMPT_ECHO_ON` literal (security/_pam_types.h) — used for the role
/// prompt where the typed value is not a secret.
#[cfg(target_os = "linux")]
const PAM_PROMPT_ECHO_ON: i32 = 2;

/// Owned holder for the role-selection stage: keeps the loaded
/// [`tessera_core::role::RoleStore`] alive for the lifetime of the flow so
/// [`crate::flow::Deps`] can borrow it. Built by [`build_role_stage`].
#[cfg(target_os = "linux")]
struct RoleStageOwned {
    /// Requested role parsed from the suffix / prompt (`None` = none given).
    requested: Option<tessera_core::role::RoleId>,
    /// Loaded role store (`None` when enforcement is disabled).
    store: Option<tessera_core::role::RoleStore>,
    /// Enforcement mode mapped from `[roles].enforce`.
    enforce: tessera_core::role::RoleEnforce,
    /// Global default TTL from `[roles].default_session_ttl`.
    default_session_ttl: std::time::Duration,
}

#[cfg(target_os = "linux")]
impl RoleStageOwned {
    /// Borrow this owned stage as the flow's [`crate::flow::RoleStage`].
    fn as_deps(&self) -> crate::flow::RoleStage<'_> {
        crate::flow::RoleStage {
            requested: self.requested.clone(),
            store: self.store.as_ref(),
            enforce: self.enforce,
            default_session_ttl: self.default_session_ttl,
        }
    }
}

/// Build the role-selection stage from config + the parsed suffix.
///
/// When enforcement is disabled this is a cheap no-op stage (no prompt, no
/// store load) preserving pre-role behaviour. When enforced and no role came
/// from the suffix, prompt for one via the PAM conversation
/// (`PAM_PROMPT_ECHO_ON`, input only — no role listing). The on-device store
/// is loaded in standalone mode (filesystem-permission trust).
///
/// Returns the owned stage, or a PAM return code on a hard failure (no role
/// supplied where one is required, or store load error under `require`).
///
/// # Safety
///
/// `pamh` must be the live PAM handle for the current callback.
#[cfg(target_os = "linux")]
fn build_role_stage(
    pamh: *mut pam_sys::pam_handle_t,
    roles_cfg: &tessera_core::config::validated::RolesSection,
    suffix_role: Option<tessera_core::role::RoleId>,
) -> Result<RoleStageOwned, i32> {
    use tessera_core::role::{RoleDenyReason, RoleEnforce, RoleId, RoleStore, RoleOs, TrustMode};

    let enforce = roles_cfg.enforce_mode();
    if enforce == RoleEnforce::Disabled {
        return Ok(RoleStageOwned {
            requested: suffix_role,
            store: None,
            enforce,
            default_session_ttl: roles_cfg.default_session_ttl,
        });
    }

    // Resolve the requested role: prefer the suffix; otherwise prompt.
    let requested: Option<RoleId> = match suffix_role {
        Some(r) => Some(r),
        None => {
            // SAFETY: `pamh` is the live PAM handle for this callback.
            match unsafe { prompt_for_role(pamh) } {
                Ok(Some(raw)) => match RoleId::new(&raw) {
                    Ok(r) => Some(r),
                    Err(_) => {
                        tracing::warn!(
                            target: "role.audit",
                            event = "role_deny",
                            reason = "syntax",
                            raw_role = %raw,
                            "role prompt returned an invalid role_id",
                        );
                        // Under enforcement a bad prompt value is fatal.
                        if matches!(enforce, RoleEnforce::Require) {
                            return Err(PAM_AUTH_ERR);
                        }
                        None
                    }
                },
                // No conversation / empty input: deny "role not specified"
                // under require; benign under warn.
                Ok(None) | Err(()) => {
                    tracing::warn!(
                        target: "role.audit",
                        event = "role_deny",
                        reason = "syntax",
                        "role not specified and no usable conversation prompt",
                    );
                    if matches!(enforce, RoleEnforce::Require) {
                        return Err(PAM_AUTH_ERR);
                    }
                    None
                }
            }
        }
    };

    // Load the on-device role store (standalone trust = filesystem perms).
    // On Astra the device OS is astra; otherwise linux. We compile per-OS
    // for the open build (linux); the orchestration of astra slices happens
    // on the real device which is built with the astra-mac feature.
    let device_os = if cfg!(feature = "astra-mac") {
        RoleOs::Astra
    } else {
        RoleOs::Linux
    };
    let store = match RoleStore::load(&roles_cfg.dir, device_os, TrustMode::Standalone) {
        Ok(s) => Some(s),
        Err(err) => {
            // Under `require` a store that cannot be loaded is fail-closed
            // ("roles not configured"); under `warn` we proceed without it.
            tracing::error!(
                target: "role.audit",
                event = "role_deny",
                reason = %RoleDenyReason::NotFound,
                dir = %roles_cfg.dir.display(),
                error = %err,
                "role store load failed",
            );
            if matches!(enforce, RoleEnforce::Require) {
                return Err(PAM_AUTH_ERR);
            }
            None
        }
    };

    Ok(RoleStageOwned {
        requested,
        store,
        enforce,
        default_session_ttl: roles_cfg.default_session_ttl,
    })
}

/// Prompt the engineer for a role via the PAM conversation
/// (`PAM_PROMPT_ECHO_ON`). Returns `Ok(Some(role))` on input, `Ok(None)` on
/// empty input, `Err(())` when no usable conversation is available. The
/// prompt is input-only: available roles are deliberately NOT listed (avoids
/// leaking role names before authentication — design Open Question).
///
/// # Safety
///
/// `pamh` must be the live PAM handle for the current callback.
#[cfg(target_os = "linux")]
unsafe fn prompt_for_role(pamh: *mut pam_sys::pam_handle_t) -> Result<Option<String>, ()> {
    // SAFETY: forwarded to the conv helper, which upholds the live-handle
    // contract documented on `prompt_value`.
    match unsafe {
        crate::pam_conv::prompt_value(pamh, "Роль (role): ", PAM_PROMPT_ECHO_ON)
    } {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_owned()))
            }
        }
        Err(_) => Err(()),
    }
}

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
        // SAFETY: `argv` points to `argc` valid pointers (caller contract);
        // `i` is in `0..argc`, so `add` stays in bounds.
        let slot = unsafe { argv.add(i as usize) };
        // SAFETY: `slot` is a valid pointer within the `argv` array.
        let ptr = unsafe { *slot };
        if ptr.is_null() {
            continue;
        }
        // SAFETY: non-null `ptr` is a NUL-terminated C string from PAM.
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
        // SAFETY: `argc`/`argv` are the PAM-supplied module argument vector.
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
        // SAFETY: `pamh` is the live PAM handle for this callback.
        let raw_pam_user = match unsafe { crate::pam_helpers::pam_get_user_string(pamh) } {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(target: "tessera.auth", error = %err, "pam_get_user failed");
                return PAM_AUTH_ERR;
            }
        };

        // 2a. Role selection (role-format): parse the `<user>+<role>` suffix
        // RIGHT AFTER pam_get_user and BEFORE any other work — canonicalise
        // PAM_USER so every subsequent step and every other stack module sees
        // the canonical account name (design Decision 6; CVE-2021-3560: no
        // swap window). Syntax errors abort before authentication, with a
        // `role_deny reason=syntax` carrying the raw login string. A stray
        // `+` is illegal in canonical account names regardless of the
        // enforcement stage, so malformed login strings are always fatal.
        let (pam_user, requested_role) =
            match crate::role_selection::parse_user_role(&raw_pam_user) {
                Ok((canonical, role)) => (canonical, role),
                Err(err) => {
                    tracing::warn!(
                        target: "role.audit",
                        event = "role_deny",
                        reason = "syntax",
                        raw_user = %raw_pam_user,
                        error = %err,
                        "login string rejected before authentication",
                    );
                    return PAM_AUTH_ERR;
                }
            };
        // Rewrite PAM_USER to the canonical name when a suffix was stripped.
        if pam_user != raw_pam_user {
            // SAFETY: `pamh` is the live PAM handle for this callback.
            if let Err(err) = unsafe { crate::pam_helpers::pam_set_user(pamh, &pam_user) } {
                tracing::error!(
                    target: "tessera.auth",
                    error = %err,
                    "pam_set_item(PAM_USER) failed; cannot canonicalise user",
                );
                return PAM_SYSTEM_ERR;
            }
        }
        // SAFETY: `pamh` is the live PAM handle for this callback.
        let pam_service = unsafe { crate::pam_helpers::pam_get_service_string(pamh) }
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tessera.auth", error = %err, "pam_get_item(PAM_SERVICE) failed; using 'unknown'");
                "unknown".to_string()
            });
        // SAFETY: `pamh` is the live PAM handle for this callback.
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
        // SAFETY: `pamh` is the live PAM handle; the closure does not outlive
        // this `pam_sm_authenticate` frame (see `closure_from_pamh` contract).
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
        let mountpoint_base = PathBuf::from(tessera_core::mount::usb::MOUNTPOINT_BASE);
        if let Err(err) = std::fs::create_dir_all(&mountpoint_base) {
            tracing::warn!(target: "tessera.auth", error = %err, base = %mountpoint_base.display(), "create mountpoint base failed");
        }
        let real_io = crate::flow::RealFlowIo::new(
            usb_wait,
            wired.cfg.usb_allowed_devices.clone(),
            wired.cfg.max_usb_partitions as usize,
            mountpoint_base,
            session_id.clone(),
        )
        .with_pamh(pamh);

        // 7b. Role-format stage (role-format). When enforcement is on and no
        // suffix supplied a role, prompt for one via the PAM conversation
        // (PAM_PROMPT_ECHO_ON; input only, no role listing — see design
        // Open Question). Then load the on-device role store. The requested
        // role + store + enforce mode travel atomically through Deps so the
        // role is resolved together with cert verification (no swap window).
        let role_stage = match build_role_stage(
            pamh,
            &wired.cfg.roles,
            requested_role,
        ) {
            Ok(s) => s,
            Err(rc) => return rc,
        };

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
            role_stage: role_stage.as_deps(),
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
                // SAFETY: `pamh` is the live PAM handle for this callback.
                if let Err(err) = unsafe { crate::data_handle::set_auth_context(pamh, auth_ctx) } {
                    tracing::error!(target: "tessera.auth", error = %err, "set_auth_context failed");
                    return PAM_SYSTEM_ERR;
                }
                // Drop the mount guard here: the USB stick is only needed
                // during the auth phase (the .p12 has been read and the
                // chain verified), so it is unmounted before
                // `pam_sm_authenticate` returns. The session phase never
                // re-mounts — by design, the auth context travels via
                // pam_data instead (see
                // openspec/specs/cert-authentication-flow/spec.md).
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
        // SAFETY: `pamh` is the live PAM handle for this callback.
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
        // SAFETY: `argc`/`argv` are the PAM-supplied module argument vector.
        let args = unsafe { collect_args(argc, argv) };
        let cfg_path = config_path_from_args(&args);
        let cfg = match tessera_core::config::load_validated_config(&cfg_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(target: "tessera.session", error = %err, "config load failed");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };

        // SAFETY: `pamh` is the live PAM handle for this callback.
        let Some(ctx) = (unsafe { crate::data_handle::get_auth_context(pamh) }) else {
            return PAM_AUTHINFO_UNAVAIL;
        };

        // PAM user (best-effort: fall back to cert_cn if PAM_USER is gone).
        // SAFETY: `pamh` is the live PAM handle for this callback.
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
            // SAFETY: `pamh` is the live PAM handle for this callback.
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
        // SAFETY: `argc`/`argv` are the PAM-supplied module argument vector.
        let args = unsafe { collect_args(argc, argv) };
        let cfg_path = config_path_from_args(&args);
        let cfg = match tessera_core::config::load_validated_config(&cfg_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(target: "tessera.session", error = %err, "config load failed (close)");
                return PAM_SUCCESS;
            }
        };

        // SAFETY: `pamh` is the live PAM handle for this callback.
        if let Some(ctx) = unsafe { crate::data_handle::get_auth_context(pamh) } {
            // SAFETY: `pamh` is the live PAM handle for this callback.
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

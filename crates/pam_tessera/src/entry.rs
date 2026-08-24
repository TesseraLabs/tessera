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
//! `pam_sm_authenticate`. Each of them re-reads `PAM_USER` only to check it
//! against the account fixed in that context — see
//! `verified_session_account`. `PAM_USER` is application-owned mutable
//! state, so between the authentication and session phases it can name a
//! different account than the certificate admitted; acting on the new name
//! would grant that account the MAC label and the privileged hooks of a login
//! it never passed.
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

/// `PAM_AUTH_ERR` — the generic "authentication did not succeed" code.
///
/// Compiled outside the Linux module body as well so the store-load verdict it
/// belongs to can be exercised on a development host: the cdylib itself only
/// builds on Linux, which would otherwise leave that mapping untested until CI.
#[cfg(any(target_os = "linux", test))]
const PAM_AUTH_ERR: i32 = 7;
#[cfg(target_os = "linux")]
const PAM_SYSTEM_ERR: i32 = 4;
#[cfg(target_os = "linux")]
const PAM_ACCT_EXPIRED: i32 = 13;
/// `PAM_PERM_DENIED` — the verdict code for "the credential does not authorise
/// this", which is what a `PAM_USER` that the certificate was never checked
/// against amounts to. Matches the role-denial row of the
/// [`crate::flow::FlowError::pam_code`] table.
#[cfg(any(target_os = "linux", test))]
const PAM_PERM_DENIED: i32 = 6;

/// Owned holder for the role-selection stage: keeps the loaded
/// [`tessera_core::role::RoleStore`] alive for the lifetime of the flow so
/// [`crate::flow::Deps`] can borrow it. Built by [`build_role_stage`].
#[cfg(target_os = "linux")]
struct RoleStageOwned {
    /// Loaded role store.
    store: tessera_core::role::RoleStore,
    /// Global default TTL from `[roles].default_session_ttl`.
    default_session_ttl: std::time::Duration,
}

#[cfg(target_os = "linux")]
impl RoleStageOwned {
    /// Borrow this owned stage as the flow's [`crate::flow::RoleStage`].
    fn as_deps(&self) -> crate::flow::RoleStage<'_> {
        crate::flow::RoleStage {
            store: &self.store,
            default_session_ttl: self.default_session_ttl,
            // View and verdicts both come from the store's own load, so what it
            // asked both account sources about every slice name is what this
            // stage would ask again — at the cost of another resolver run, and
            // of another wait on a directory that is not answering.
            accounts: tessera_core::role::AccountCheck::from_store(&self.store),
        }
    }
}

/// Build the role-selection stage from config.
///
/// Only the on-device store is loaded here (standalone mode, filesystem-
/// permission trust). The requested role is *not* part of the stage: the flow
/// derives it from the same `PAM_USER` string it authenticates with, so this
/// entry point has no way to hand it a different one.
///
/// Returns the owned stage, or a PAM return code when the store could not be
/// loaded. That is fail-closed: coverage cannot be proven without a store, and
/// there is no configuration under which the login proceeds without a role.
#[cfg(target_os = "linux")]
fn build_role_stage(
    roles_cfg: &tessera_core::config::validated::RolesSection,
    device_os: tessera_core::role::RoleOs,
) -> Result<RoleStageOwned, i32> {
    use tessera_core::role::{RoleStore, SystemAccounts, TrustMode};

    // The device's real passwd database: on a live device that is the only
    // honest source for "is this account the system's own". Name resolution is
    // consulted on top of it under the configured bound, so a directory that
    // stops answering costs the login that bound once and nothing after it.
    let accounts = SystemAccounts::device(roles_cfg.account_lookup_timeout);

    // Load the on-device role store through the privileged-path validator.
    // OS selection is runtime state now: the same open PAM binary serves
    // Linux and Astra, with the Parsec plugin identifying the Astra contour.
    let store = match RoleStore::load_privileged(
        &roles_cfg.dir,
        device_os,
        TrustMode::Standalone,
        accounts,
    ) {
        Ok(s) => s,
        Err(err) => {
            // Fail-closed either way — coverage cannot be proven without a
            // store — but the two failures are audited apart, and this is the
            // place where that distinction is decided in a real login: the
            // store is loaded before the flow runs, so an unusable account
            // database surfaces here and never reaches the flow's own check.
            let (reason, code) = store_load_denial(&err);
            tracing::error!(
                target: "role.audit",
                event = "role_deny",
                reason = %reason,
                dir = %roles_cfg.dir.display(),
                error = %err,
                "role store load failed",
            );
            return Err(code);
        }
    };

    Ok(RoleStageOwned {
        store,
        default_session_ttl: roles_cfg.default_session_ttl,
    })
}

/// The audit reason and PAM code a failed role-store load is refused under.
///
/// A device whose account database cannot be consulted is not a device without
/// roles. Reporting it as "not configured" would tell the administrator to go
/// look for a missing base while the real fault — an unreadable `/etc/passwd`,
/// a name service that answers with an error — repeats on every login and says
/// nothing about itself. The distinction has to be made here rather than deeper
/// in the flow: the store is loaded before authentication starts, so this is
/// the first thing an unusable account database breaks.
///
/// `PAM_PERM_DENIED` matches the code the flow returns for a role denial, so
/// the same fault reads the same way whichever stage catches it.
#[cfg(any(target_os = "linux", test))]
fn store_load_denial(
    error: &tessera_core::role::RoleStoreError,
) -> (tessera_core::role::RoleDenyReason, i32) {
    use tessera_core::role::{RoleDenyReason, RoleStoreError};

    match error {
        RoleStoreError::AccountsUnavailable { .. } => {
            (RoleDenyReason::BackendUnavailable, PAM_PERM_DENIED)
        }
        _ => (RoleDenyReason::NotFound, PAM_AUTH_ERR),
    }
}

/// Load this device's trusted tag set from the configured `[tags]` source
/// (tags-delegation §5.2).
///
/// Fail-closed: when `[tags].enforce = false` the device has no applied tags
/// (an empty set), so any group-delegation `requireTags` envelope in a chain is
/// unsatisfiable and rejects. A configured-but-broken source (bad signature,
/// rollback, malformed file) is also treated as "no tags" — never as "all tags
/// allowed" — and the per-source audit event has already been emitted by the
/// loader. A missing standalone file is benign (empty set).
#[cfg(target_os = "linux")]
fn build_device_tags(
    tags_cfg: &tessera_core::config::validated::TagsSection,
    roles_cfg: &tessera_core::config::validated::RolesSection,
) -> tessera_core::tags::DeviceTags {
    use tessera_core::config::validated::TagsMode;
    use tessera_core::tags::{load_standalone_optional_privileged, DeviceTags};

    let _ = roles_cfg; // reserved for managed-mode wiring (see below)
    if !tags_cfg.enforce {
        return DeviceTags::empty();
    }
    match tags_cfg.mode {
        TagsMode::Standalone => match load_standalone_optional_privileged(&tags_cfg.source) {
            Ok(tags) => tags,
            Err(err) => {
                tracing::error!(
                    target: "tags.audit",
                    error = %err,
                    source = %tags_cfg.source.display(),
                    "device-tags standalone load failed; treating as no tags (fail-closed)"
                );
                DeviceTags::empty()
            }
        },
        TagsMode::Managed => {
            // Managed tags ride in the SAME signed role-store manifest. The
            // enrollment verification key the manifest is signed under is not
            // exposed as its own config key in the open build (the standalone
            // role-store / tags model is the supported path here), so managed
            // device-tags loading has no trusted pubkey to verify against yet.
            // Fail-closed: no tags applied. Wiring the enrollment-key source is
            // a serverside/enrollment concern (design Non-Goals) tracked
            // separately; until then `mode = "managed"` yields no tags rather
            // than an unverified read.
            tracing::error!(
                target: "tags.audit",
                source = %tags_cfg.source.display(),
                "device-tags mode = managed is not wired to an enrollment key in this build; \
                 treating as no tags (fail-closed)"
            );
            DeviceTags::empty()
        }
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
    args.get("config")
        .map_or_else(|| PathBuf::from("/etc/tessera/config.toml"), PathBuf::from)
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

/// Read `PAM_USER` off the live handle and check it against the account the
/// stored [`AuthContext`] was authorised for.
///
/// Returns the authorised account name — taken from the context, not from the
/// handle — so callers physically cannot keep using the unverified value.
///
/// Every post-authentication phase goes through here. `PAM_USER` is mutable
/// state owned by the application, not by this module, so by the time a
/// session or account callback runs it may name a different account than the
/// one the certificate admitted. Acting on it unchecked would apply a MAC
/// label and run privileged hooks for an account no credential ever covered.
/// Both failure modes — a name that changed, and a `PAM_USER` that cannot be
/// read at all — are refused; there is deliberately no fallback name, least of
/// all the certificate CN, which identifies the engineer rather than the role
/// account.
///
/// # Safety
///
/// `pamh` must be the live PAM handle for the current callback.
#[cfg(target_os = "linux")]
unsafe fn verified_session_account(
    pamh: *mut pam_sys::pam_handle_t,
    ctx: &tessera_core::pam_data::AuthContext,
) -> Option<&str> {
    // SAFETY: `pamh` is the live PAM handle (caller contract).
    let observed = match unsafe { crate::pam_helpers::pam_get_user_string(pamh) } {
        Ok(user) => user,
        Err(err) => {
            tracing::error!(
                target: "tessera.session",
                session_id = %ctx.session_id,
                error = %err,
                "pam_get_user failed after authentication; refusing to act under an unverified name",
            );
            return None;
        }
    };
    match crate::session_identity::verify_session_account(ctx, &observed) {
        Ok(account) => Some(account),
        Err(err) => {
            tracing::error!(
                target: "tessera.session",
                session_id = %ctx.session_id,
                error = %err,
                "PAM_USER does not match the authenticated account",
            );
            None
        }
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
        // An unrecognised `method=` is a broken stack line, not an unavailable
        // credential: answering `PAM_AUTHINFO_UNAVAIL` would let a stack
        // configured to step over that code fall through to whatever follows,
        // which is the password this module exists to replace.
        let auth_method = match crate::pam_args::method_from_args(&args) {
            Ok(method) => method,
            Err(unknown) => {
                tracing::error!(
                    target: "tessera.auth",
                    method = %unknown,
                    "unrecognised method= module argument; refusing the login",
                );
                return PAM_SYSTEM_ERR;
            }
        };
        let cfg_path = config_path_from_args(&args);
        let cfg = match tessera_core::config::load_privileged_validated_config(&cfg_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(target: "tessera.auth", error = %err, "config load failed");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };
        // Only what every method depends on. The certificate preconditions —
        // trust anchors, CRLs, the PKCS#11 module, the GOST engine the trust
        // configuration asks for — are checked inside the certificate branch
        // below, because the code method exists for the device where exactly
        // those are missing. Gating it here closed the last way into such a
        // device for the reason that way exists.
        if let Err(err) = tessera_core::self_check::self_check_common(&cfg) {
            tracing::error!(target: "tessera.auth", error = %err, "self-check failed");
            return PAM_AUTHINFO_UNAVAIL;
        }

        // The audit chain, before anybody is authenticated. It has to be here
        // and not later: the record of a successful login is part of granting
        // it, and a journal opened after the decision could only report one.
        //
        // A device configured to keep a journal that cannot be opened is
        // refused rather than let through without one. That is the same
        // fail-closed rule the login itself follows, applied one level up: the
        // alternative is a device that believes it is accountable and is not,
        // which is worse than one that says so.
        match tessera_core::audit::sink::install_from_config(&cfg) {
            // Either a journal is open, or this device keeps none — the second
            // is a configuration, not a failure, and `install_from_config` has
            // already said which of the two it is in the system journal.
            Ok(_) => {}
            Err(err) => {
                tracing::error!(
                    target: "tessera.auth",
                    error = %err,
                    "this device is configured to keep an audit journal and it could not be \
                     opened; refusing to authenticate without one",
                );
                return PAM_AUTHINFO_UNAVAIL;
            }
        }

        // 2. PAM_USER / PAM_SERVICE.
        // SAFETY: `pamh` is the live PAM handle for this callback.
        let pam_user = match unsafe { crate::pam_helpers::pam_get_user_string(pamh) } {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(target: "tessera.auth", error = %err, "pam_get_user failed");
                return PAM_AUTH_ERR;
            }
        };

        // Role selection happens inside the flow: the account being logged
        // into IS the requested role, so `pam_user` below is its only source
        // and the module never rewrites `PAM_USER`. The name the rest of the
        // stack sees is the name we act on, with no window between the two
        // (polkit CVE-2021-3560 class). A name that cannot be a role id at all
        // is refused by the flow before any credential material is touched.
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
        let (host_id_source, host_id_raw, host_id_hash) = match crate::resolve_host_identity(&cfg) {
            Ok(t) => t,
            Err(err) => {
                tracing::error!(target: "tessera.auth", error = %err, "host identity unresolved");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };

        // 3b. The code login method, when this stack line names it. It shares
        // the configuration, the host identity and the role store with the
        // certificate path and nothing else: there is no USB bus to wait on,
        // no trust anchor to build a chain against, and no token whose removal
        // the daemon would have to watch. Branching here, before `di::wire`
        // consumes the config, keeps that separation honest.
        if auth_method == crate::pam_args::AuthMethod::Code {
            // SAFETY: `pamh` is the live PAM handle for this callback, and the
            // call does not outlive this frame.
            return unsafe {
                authenticate_by_code_entry(
                    pamh,
                    &cfg,
                    CodeEntryInputs {
                        pam_user: &pam_user,
                        pam_service: &pam_service,
                        host_id_source,
                        host_id_hash: &host_id_hash,
                        pam_target,
                    },
                )
            };
        }

        // 3c. The preconditions of the certificate method, checked now that it
        // is certain this login is one. Everything below reads material only a
        // certificate login uses, and a device missing it has no certificate
        // path — which is a refusal of this method, not of the module.
        if let Err(err) = tessera_core::self_check::self_check_certificate(&cfg) {
            tracing::error!(
                target: "tessera.auth",
                error = %err,
                "certificate self-check failed",
            );
            return PAM_AUTHINFO_UNAVAIL;
        }

        // 4. Wire trust verifier + monitor (consumes cfg; we keep wired.cfg).
        // The resolved raw host id selects any per-host `[[trust_override]]`
        // that narrows the accepted trust anchors for this device.
        let wired = match crate::di::wire(cfg, &host_id_raw) {
            Ok(w) => w,
            Err(err) => {
                tracing::error!(target: "tessera.auth", error = %err, "wiring failed");
                return PAM_AUTHINFO_UNAVAIL;
            }
        };

        // 5. (Removed) Host ACL loading is gone — the cert's
        // `pam_cert_host_binding` (which device) and `pam_cert_allowed_roles`
        // (which login account, since the account name is the role name)
        // extensions are the sole source of authorisation.
        // See docs/ru/cert-issuance.md.

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

        // 7b. Role stage: load the on-device role store. The store travels
        // through Deps so the role is resolved together with cert verification
        // — `PAM_USER` is never re-read, so there is no swap window.
        let device_os = if wired.cfg.mac.backend.as_deref() == Some("parsec") {
            tessera_core::role::RoleOs::Astra
        } else {
            tessera_core::role::RoleOs::Linux
        };
        let role_stage = match build_role_stage(&wired.cfg.roles, device_os) {
            Ok(s) => s,
            Err(rc) => return rc,
        };

        // 7c. Device-tags stage (tags-delegation §5). Loaded once per attempt
        // from the configured `[tags]` source; an absent/disabled source yields
        // an empty set (fail-closed: group-delegation envelopes then reject).
        let device_tags = build_device_tags(&wired.cfg.tags, &wired.cfg.roles);

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
            pam_target,
            role_stage: role_stage.as_deps(),
            device_tags: &device_tags,
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

/// What `pam_sm_authenticate` has already established about this login.
///
/// Gathered into one value because both methods derive it identically and
/// neither may derive it twice: `PAM_USER` in particular is application-owned
/// mutable state, so a second read could name a different account than the one
/// the rest of the attempt is running under.
#[cfg(target_os = "linux")]
struct CodeEntryInputs<'a> {
    /// The login account, which is also the role being asked for.
    pam_user: &'a str,
    /// The PAM service that drove the stack.
    pam_service: &'a str,
    /// Source kind that produced the host id.
    host_id_source: tessera_core::host_identity::HostIdSourceKind,
    /// Resolved host id hash.
    host_id_hash: &'a str,
    /// Where the session lives, derived from `PAM_TTY`.
    pam_target: tessera_proto::SessionTarget,
}

/// Drive the code login method against the live PAM handle.
///
/// Split out of [`pam_sm_authenticate`] because the two methods share almost
/// nothing: this one waits on no bus, mounts nothing and builds no chain. It
/// does register the session with the daemon, but for the other of the two
/// reasons the certificate path does: there is no carrier here whose removal
/// would have to be watched, and the daemon is also what ends a session when
/// its term runs out.
///
/// # Safety
///
/// `pamh` must be the live PAM handle of the enclosing `pam_sm_authenticate`
/// callback.
#[cfg(target_os = "linux")]
unsafe fn authenticate_by_code_entry(
    pamh: *mut pam_sys::pam_handle_t,
    cfg: &tessera_core::config::ValidatedConfig,
    inputs: CodeEntryInputs<'_>,
) -> i32 {
    use crate::codes_flow::{
        authenticate_by_code, open_method, withdraw_code_session, CodeDeps, CodeLogin,
        CodeLoginOutcome, Registration, SystemProbe, CLOSE_REASON_CONTEXT_LOST,
    };

    let CodeEntryInputs {
        pam_user,
        pam_service,
        host_id_source,
        host_id_hash,
        pam_target,
    } = inputs;

    // Before anything that can refuse, and once. libpam applies this only when
    // the transaction ends in a refusal, so a successful login pays nothing
    // and every refusal below is covered — including the ones added later,
    // which a per-branch list would quietly miss.
    //
    // What it buys is not brute-force resistance: the issuance window already
    // bounds that far harder. It is that the refusals of this method are many
    // and of different cost — no ticket, a scope that does not cover, a
    // revoked ticket, a code that does not meet, a spent budget, a role
    // briefly locked — and without a randomised wait the response time tells
    // a caller which of them happened. Several of those answers would give
    // away that a role and a ticket exist before anything is authenticated.
    //
    // SAFETY: `pamh` is the live PAM handle of the enclosing callback.
    if let Err(err) = unsafe {
        crate::pam_helpers::set_fail_delay(pamh, tessera_core::codes::throttle::FAILURE_DELAY)
    } {
        // Best-effort: a refusal that could not be slowed down is still a
        // refusal, and failing the login over it would turn a hardening
        // measure into an outage.
        tracing::warn!(
            target: "tessera.codes",
            error = %err,
            "pam_fail_delay was refused; refusals of this attempt will not be delayed",
        );
    }

    // One configured fact — whether this device runs a mandatory mechanism —
    // decides both which role slices it accepts and where the level of a
    // session comes from. A device with no such mechanism has no label to read
    // and one level by construction; deriving that from the emptiness of the
    // label file instead would refuse the method on the whole non-Astra fleet.
    let (device_os, level_source) = if cfg.mac.backend.as_deref() == Some("parsec") {
        (
            tessera_core::role::RoleOs::Astra,
            crate::codes_level::LevelSource::ProcessLabel,
        )
    } else {
        (
            tessera_core::role::RoleOs::Linux,
            crate::codes_level::LevelSource::NoMandatoryMechanism,
        )
    };
    let role_stage = match build_role_stage(&cfg.roles, device_os) {
        Ok(stage) => stage,
        Err(rc) => return rc,
    };

    // The artefacts are looked for before a single prompt is shown: a device
    // that was never given a key container and a ticket set has no method
    // here, and the stack should move on rather than ask an engineer for a
    // code nobody can compute. The same configuration then travels into the
    // flow for the attempt budget it counts. The epoch is not taken from it:
    // opening the method may select a persisted epoch ahead of the configured
    // one, and the flow reads that back off the method itself.
    let codes_config = cfg.codes.method.as_ref();
    let method = match open_method(codes_config, &role_stage.store) {
        Ok(method) => method,
        Err(err) => {
            tracing::info!(
                target: "tessera.codes",
                error = %err,
                pam_user = %pam_user,
                "the code login method is not usable on this device",
            );
            return err.pam_code();
        }
    };
    let Some(codes_config) = codes_config else {
        // Unreachable: `open_method` refuses a `None` configuration above.
        return crate::codes_flow::CodeFlowError::Unavailable.pam_code();
    };

    let session_id = match fresh_session_id() {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(
                target: "tessera.codes",
                error = %err,
                "OS RNG unavailable; cannot mint session id",
            );
            return PAM_AUTHINFO_UNAVAIL;
        }
    };

    // The daemon, reached the same way the certificate path reaches it, but
    // handed over unwrapped: the fail-mode policy is applied inside the flow,
    // which is the only place that can say what a swallowed failure costs
    // here — see `codes_flow::register_code_session`.
    let monitor =
        tessera_core::ipc::ConnectPerCall::new(tessera_core::ipc::MonitorClientFactory::new(
            cfg.monitor.socket_path.clone(),
            cfg.monitor.timeout,
        ));

    let deps = CodeDeps {
        config: codes_config,

        store: &role_stage.store,
        accounts: tessera_core::role::AccountCheck::from_store(&role_stage.store),
        default_session_ttl: role_stage.default_session_ttl,
        host_id_hash,
        host_id_source,
        monitor: &monitor,
        monitor_fail_mode: cfg.monitor.fail_mode.into(),
        pam_target,
    };
    // SAFETY: `pamh` is the live PAM handle of the enclosing callback, and the
    // conversation is dropped before this function returns.
    let mut conv = unsafe { crate::codes_flow::PamCodeConversation::new(pamh) };

    let login = CodeLogin {
        pam_user,
        pam_service,
        session_id,
        now: std::time::SystemTime::now(),
    };

    let probe = SystemProbe::new(level_source);
    match authenticate_by_code(&deps, login, &method, &mut conv, &probe) {
        Ok(outcome) => {
            let CodeLoginOutcome {
                auth_ctx,
                registration,
            } = outcome;
            // Kept before the context is moved: it is the only handle on the
            // session the daemon is holding.
            let session_id = auth_ctx.session_id.clone();
            // SAFETY: `pamh` is the live PAM handle for this callback.
            if let Err(err) = unsafe { crate::data_handle::set_auth_context(pamh, auth_ctx) } {
                tracing::error!(
                    target: "tessera.codes",
                    error = %err,
                    "set_auth_context failed",
                );
                // The same phantom the journal path leaves behind, by a
                // different door: the session is registered, PAM will not
                // carry the context, so no session phase ever runs for it —
                // and the daemon would keep it to the end of its term. Every
                // refusal after the registration has to give it back, not just
                // the one inside the flow.
                if registration == Registration::Recorded {
                    withdraw_code_session(
                        &monitor,
                        &session_id,
                        pam_user,
                        CLOSE_REASON_CONTEXT_LOST,
                    );
                }
                return PAM_SYSTEM_ERR;
            }
            PAM_SUCCESS
        }
        Err(err) => {
            tracing::warn!(
                target: "tessera.codes",
                error = %err,
                pam_user = %pam_user,
                "code login failed",
            );
            err.pam_code()
        }
    }
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
/// Re-checks certificate expiry against the stored [`AuthContext`]. A
/// `PAM_USER` that does not match the account that context was authorised for
/// maps to `PAM_PERM_DENIED`: the verdict belongs to the account the
/// certificate admitted, and cannot be transferred to another one.
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
        // Account management decides about an account, so it must be the same
        // account the certificate admitted.
        // SAFETY: `pamh` is the live PAM handle for this callback.
        if unsafe { verified_session_account(pamh, ctx) }.is_none() {
            return PAM_PERM_DENIED;
        }
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
/// A `PAM_USER` that no longer names the authenticated account — or that
/// cannot be read at all — also maps to `PAM_SESSION_ERR`: the session simply
/// cannot be opened, because there is no name it may legitimately act under.
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
        let cfg = match tessera_core::config::load_privileged_validated_config(&cfg_path) {
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

        // The name this session may act under. Fail-closed: the MAC label and
        // the privileged `session_open` hooks below both take it, and neither
        // may run for an account the certificate was not checked against.
        // SAFETY: `pamh` is the live PAM handle for this callback.
        let Some(pam_user) = (unsafe { verified_session_account(pamh, ctx) }) else {
            return PAM_SESSION_ERR;
        };

        // MAC integrity — orchestrator decides whether to apply a label,
        // skip (runtime inactive / policy ignore), or fail closed.  We
        // always invoke it; the orchestrator honours the policy.
        match crate::session::run_open_session_pipeline(&cfg, ctx, pam_user) {
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
            let xdg =
                match unsafe { crate::pam_helpers::pam_get_env_string(pamh, "XDG_SESSION_ID") } {
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
            let session_uuid = crate::xdg_capture::session_uuid_from_string(&ctx.session_id);
            let socket_path = cfg.monitor.socket_path.clone();
            let timeout = cfg.monitor.timeout;
            let _ = crate::xdg_capture::capture_xdg(session_uuid, xdg.as_deref(), |target| {
                let mut client = tessera_core::ipc::MonitordClient::connect(&socket_path, timeout)?;
                client.send_update_session_target(session_uuid, target)
            });
        }

        let vars = tessera_core::hooks::HookVars::for_session_open(pam_user, ctx);
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
        let cfg = match tessera_core::config::load_privileged_validated_config(&cfg_path) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(target: "tessera.session", error = %err, "config load failed (close)");
                return PAM_SUCCESS;
            }
        };

        // SAFETY: `pamh` is the live PAM handle for this callback.
        if let Some(ctx) = unsafe { crate::data_handle::get_auth_context(pamh) } {
            // Close-session hooks are privileged too, so they are subject to
            // the same rule as the open side: no name, no hooks. Unlike
            // open_session the failure is not surfaced — the return code stays
            // PAM_SUCCESS because a logout cannot be blocked — but the hooks
            // are skipped rather than run under an unverified account.
            // SAFETY: `pamh` is the live PAM handle for this callback.
            let Some(pam_user) = (unsafe { verified_session_account(pamh, ctx) }) else {
                return PAM_SUCCESS;
            };

            let vars = tessera_core::hooks::HookVars::for_session_close(pam_user, ctx);
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::missing_docs_in_private_items)]
mod store_load_denial_tests {
    use super::{store_load_denial, PAM_AUTH_ERR, PAM_PERM_DENIED};

    use tessera_core::role::store::RoleStoreError;
    use tessera_core::role::{RoleDenyReason, RoleOs, RoleStore, SystemAccounts, TrustMode};

    /// The error a real load produces when the account database cannot be
    /// consulted, taken from the loader rather than constructed here: the
    /// mapping is only worth anything if it names the variant this path
    /// actually yields.
    fn accounts_unavailable_error() -> RoleStoreError {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("serv.toml"),
            b"role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"serv\"\nlevel = 1\n"
                .as_slice(),
        )
        .expect("write slice");

        RoleStore::load(
            dir.path(),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::with_lookup(|_| tessera_core::role::PasswdLookup::Unavailable),
        )
        .expect_err("an unusable account database must fail the load")
    }

    #[test]
    fn an_unusable_account_database_is_not_reported_as_a_missing_base() {
        let (reason, code) = store_load_denial(&accounts_unavailable_error());

        assert_eq!(reason.as_str(), "backend_unavailable");
        assert_eq!(code, PAM_PERM_DENIED);
    }

    #[test]
    fn every_other_load_failure_keeps_the_previous_verdict() {
        let missing_dir = RoleStore::load(
            std::path::Path::new("/nonexistent/role/base"),
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .expect_err("a missing directory must fail the load");

        let (reason, code) = store_load_denial(&missing_dir);

        assert_eq!(reason, RoleDenyReason::NotFound);
        assert_eq!(code, PAM_AUTH_ERR);
    }
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

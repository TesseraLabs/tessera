//! Stage-2 authentication flow: orchestrates the USB → PKCS#12 → challenge →
//! trust → mapping → host-binding pipeline.
//!
//! The high-level [`authenticate`] entry point is the heart of
//! `pam_sm_authenticate`.  It is split out from the cdylib boundary so that
//! unit tests can drive the full flow against mock fixtures (no real udev /
//! mount / PAM handle required).
//!
//! # Architecture
//!
//! Side effects that are awkward to fake — discovering the USB device,
//! mounting it, prompting the user for a PIN, talking to the monitor IPC —
//! live behind the [`FlowIo`] trait.  Production callers wire up
//! [`RealFlowIo`] which delegates to the real udev/mount/IPC machinery.
//! Tests inject [`InMemoryFlowIo`] which serves credentials from a `tempdir`.
//!
//! # Errors
//!
//! All failure paths converge on [`FlowError`].  See [`FlowError::pam_code`]
//! for the canonical mapping to PAM return codes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use secrecy::SecretString;
use tessera_core::challenge::{challenge_response, CryptoError};
use tessera_core::config::ValidatedConfig;
use tessera_core::discovery::{discover_credentials, DiscoveredCreds, DiscoveryError};
use tessera_core::hooks::{run_hooks_for_stage, HookError, HookExecutor, HookStage, HookVars};
use tessera_core::host_binding::{verify_host_binding, verify_user_binding, HostBindingError};
use tessera_core::host_identity::HostIdSourceKind;
use tessera_core::ipc::{MonitorClient, OpenSessionInfo};
use tessera_core::mapping::{match_user, MappingError, MatchedMapping};
use tessera_core::mount::usb::MountError;
use tessera_core::mount_guard::{MountGuard, MountOps};
use tessera_core::pam_conv::PamConvError;
use tessera_core::pam_data::AuthContext;
use tessera_core::pkcs12::{
    acquire_p12_material_with_prompter, validate_p12_envelope, AcquireError, LoadedKeyMaterial,
    P12EnvelopeError, Pkcs12Error,
};
use tessera_core::tags::DeviceTags;
use tessera_core::trust::openssl_verifier::Stage2TrustVerifier;
use tessera_core::usb::{UsbDevice, UsbError};
use tessera_core::x509::{Certificate, TrustError};

/// Errors raised by [`authenticate`].
///
/// Every variant maps to a stable PAM return code via
/// [`FlowError::pam_code`]; the cdylib boundary is the only place where
/// integers are produced, keeping this enum easy to test without pulling in
/// `pam-sys` constants.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FlowError {
    /// USB enumeration failed or timed out.
    #[error("usb: {0}")]
    Usb(#[from] UsbError),

    /// `mount(2)` (or pre-checks) failed.
    #[error("mount: {0}")]
    Mount(#[from] MountError),

    /// `discover_credentials` failed (missing `user.p12`, oversized files,
    /// I/O error).
    #[error("discovery: {0}")]
    Discovery(#[from] DiscoveryError),

    /// PAM conversation function failed (no conv item, non-utf8 PIN, ...).
    #[error("pam conversation: {0}")]
    Conv(#[from] PamConvError),

    /// No USB partition produced a syntactically valid PKCS#12 envelope.
    ///
    /// Distinct from [`Self::Discovery`] (no file at the expected path)
    /// and from [`Self::Pkcs12`] (file is a valid envelope but PIN /
    /// chain rejected): this is the "found a file with the right name,
    /// but it is not actually a PKCS#12 bundle" case, and we already
    /// burned every USB partition trying to find one.
    #[error("invalid PKCS#12 envelope on USB: {0}")]
    P12Envelope(#[from] P12EnvelopeError),

    /// PIN-retry loop exhausted its attempts.
    #[error("max PIN tries")]
    MaxTries,

    /// PKCS#12 bundle was structurally broken (corrupt / missing material).
    #[error("p12 acquire: {0}")]
    Pkcs12(String),

    /// Challenge-response failed.
    #[error("challenge-response: {0}")]
    Crypto(#[from] CryptoError),

    /// X.509 trust verification failed.
    #[error("trust: {0}")]
    Trust(#[from] TrustError),

    /// `pam_user` does not match any subject in the cert.
    #[error("subject mapping: {0}")]
    Mapping(#[from] MappingError),

    /// Cert scope (host/user binding extension) rejected the auth.
    #[error("cert scope: {0}")]
    CertScope(#[from] HostBindingError),

    /// An internal invariant broke (e.g. `PAM_SET_DATA` failed).
    #[error("internal: {0}")]
    Internal(&'static str),

    /// PKCS#11-side error (module load, slot lookup, attribute read,
    /// ...).
    #[error("pkcs11: {0}")]
    Pkcs11(#[from] tessera_core::token::pkcs11::Pkcs11Error),

    /// PKCS#11 PIN-acquire loop returned a non-PIN error or exhausted
    /// its attempts.
    #[error("pkcs11 acquire: {0}")]
    Pkcs11Acquire(#[from] tessera_core::token::pkcs11::AcquireError),

    /// `crypto_backend = "openssl"` combined with `mode = "pkcs11"`
    /// would require the `pkcs11` OpenSSL engine (libp11) which is
    /// scheduled for a later stage.  Surface as a typed error so PAM
    /// returns `PAM_AUTHINFO_UNAVAIL`.
    #[error("pkcs11 + openssl-engine path not implemented yet")]
    Pkcs11OpensslEngineNotImplemented,

    /// `cfg.pkcs11_module` is `None` even though `mode = "pkcs11"`.
    /// Validation should catch this; included for safety.
    #[error("pkcs11 module path missing in config")]
    Pkcs11ModulePathMissingInConfig,

    /// A `pre_auth` hook returned a fatal error (executor failure or
    /// `on_failure = abort` policy hit a non-zero exit / timeout).
    #[error("pre_auth hook failed: {0}")]
    PreAuthHook(#[source] HookError),

    /// A `post_auth_success` hook returned a fatal error.
    #[error("post_auth_success hook failed: {0}")]
    PostAuthHook(#[source] HookError),

    /// Role selection denied the login (role-format): the requested role was
    /// not found / not covered by the cert / needs an absent backend, and
    /// `[roles].enforce = require`. Carries the audit deny reason.
    #[error("role denied: {0}")]
    RoleDenied(tessera_core::role::RoleDenyReason),

    /// The delegation envelope on the verified chain rejected this device,
    /// role, level, or TTL (tags-delegation §4). The full reason vector is in
    /// the `delegation_denied` audit event; the engineer sees only a generic
    /// message (envelope structure is not leaked pre-auth).
    #[error("delegation denied")]
    DelegationDenied(#[source] tessera_core::trust::DelegationError),

    /// Strict monitoring was configured but the session could not be
    /// registered with monitord. In permissive mode the `FailModeWrapper`
    /// converts transport errors to success, so this variant is only reached
    /// under `monitor_fail_mode = "strict"`: continuous-presence enforcement
    /// (the lock/logout on token or USB removal) cannot be guaranteed for a
    /// session the daemon never learned about, so authentication fails closed.
    #[error("monitor session registration failed (strict fail mode): {0}")]
    MonitorRegistration(#[source] tessera_core::error::IpcError),
}

impl From<AcquireError> for FlowError {
    fn from(value: AcquireError) -> Self {
        match value {
            AcquireError::MaxTries => Self::MaxTries,
            AcquireError::Conv(c) => Self::Conv(c),
            AcquireError::Corrupt(m) => Self::Pkcs12(m),
            AcquireError::Missing(s) => Self::Pkcs12(format!("missing: {s}")),
            // `AcquireError` is `non_exhaustive`; future variants fall through
            // to a generic "p12 acquire" message rather than panicking.
            other => Self::Pkcs12(format!("{other}")),
        }
    }
}

impl From<Pkcs12Error> for FlowError {
    fn from(value: Pkcs12Error) -> Self {
        match value {
            Pkcs12Error::WrongPin => Self::MaxTries,
            Pkcs12Error::MissingKey => Self::Pkcs12("missing key".into()),
            Pkcs12Error::MissingCert => Self::Pkcs12("missing cert".into()),
            Pkcs12Error::Corrupt(m) => Self::Pkcs12(m),
            // `Pkcs12Error` is `non_exhaustive`.
            other => Self::Pkcs12(format!("{other}")),
        }
    }
}

impl FlowError {
    /// Map a flow error to its canonical PAM return code.
    ///
    /// The numeric values mirror `<security/_pam_types.h>`:
    ///
    /// | Variant                                                | Code                       |
    /// | ------------------------------------------------------ | -------------------------- |
    /// | `Usb` / `Mount` / `Discovery`                          | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `Pkcs11` (module load / wait / serial / config)        | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `Pkcs11OpensslEngineNotImplemented`                    | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `Pkcs11ModulePathMissingInConfig`                      | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `MaxTries` / `Pkcs11Acquire(PinLocked|MaxAttempts)`    | `PAM_MAXTRIES` (8)         |
    /// | `Conv` / `Pkcs11Acquire(Conv)` / `Pkcs11(PinIncorrect)`| `PAM_AUTH_ERR` (7)         |
    /// | `CertScope`                                            | `PAM_AUTH_ERR` (7)         |
    /// | `Pkcs12` / `Crypto` / `Trust`                          | `PAM_PERM_DENIED` (6)      |
    /// | `Mapping` / `MonitorRegistration`                      | `PAM_PERM_DENIED` (6)      |
    /// | other `Pkcs11(...)` / `Pkcs11Acquire(Pkcs11)`          | `PAM_AUTH_ERR` (7)         |
    /// | `Internal`                                             | `PAM_SYSTEM_ERR` (4)       |
    #[must_use]
    pub fn pam_code(&self) -> i32 {
        use tessera_core::token::pkcs11::{AcquireError as P11Acquire, Pkcs11Error};
        match self {
            // PAM_AUTHINFO_UNAVAIL — config / discovery / module load failures.
            Self::Usb(_)
            | Self::Mount(_)
            | Self::Discovery(_)
            | Self::P12Envelope(_)
            | Self::Pkcs11OpensslEngineNotImplemented
            | Self::Pkcs11ModulePathMissingInConfig
            | Self::Pkcs11(
                Pkcs11Error::ModuleLoadFailed { .. }
                | Pkcs11Error::InitFailed { .. }
                | Pkcs11Error::ModulePathMissing(_)
                | Pkcs11Error::TokenWaitTimeout { .. }
                | Pkcs11Error::NoTokenAvailable
                | Pkcs11Error::TokenNotFound { .. }
                | Pkcs11Error::TokenSerialMissing,
            ) => 9,
            // PAM_MAXTRIES — exhausted PIN-retry budget on either path.
            Self::MaxTries
            | Self::Pkcs11Acquire(P11Acquire::PinLocked | P11Acquire::MaxAttemptsExceeded) => 8,
            // PAM_PERM_DENIED — cert chain rejected the auth, the requested
            // role was denied (not found / not covered / needs an absent
            // backend) under `[roles].enforce = require`, or a strict-mode
            // monitord registration failure denied a session that could not
            // be placed under continuous-presence enforcement.
            Self::Pkcs12(_)
            | Self::Crypto(_)
            | Self::Trust(_)
            | Self::Mapping(_)
            | Self::RoleDenied(_)
            | Self::DelegationDenied(_)
            | Self::MonitorRegistration(_) => 6,
            // PAM_SYSTEM_ERR — internal invariants.
            Self::Internal(_) => 4,
            // PAM_AUTH_ERR — every other authentication-side failure
            // (PAM conv, single PIN error, generic PKCS#11 error, cert
            // host/user binding scope, ...).
            //
            // Hook failures are mapped to PAM_AUTH_ERR per the Stage 5
            // brief — operators can lower the impact via on_failure=warn
            // / ignore in the config.
            Self::Conv(_)
            | Self::Pkcs11Acquire(_)
            | Self::Pkcs11(_)
            | Self::CertScope(_)
            | Self::PreAuthHook(_)
            | Self::PostAuthHook(_) => 7,
        }
    }
}

/// Tuple capturing the USB candidate that won the `.p12` race during the
/// per-partition retry loop in [`authenticate_pkcs12`]: the device record,
/// its mountpoint, the live RAII guard, and the discovered credentials.
type BoundUsb<O> = (UsbDevice, PathBuf, MountGuard<O>, DiscoveredCreds);

/// Where credentials live on the mounted USB device.
///
/// Holds the RAII mount guard so the mount stays alive until this struct
/// (or the enclosing [`FlowOutcome`]) is dropped.
pub struct MountSession<O: MountOps + 'static> {
    /// The mountpoint.
    pub mountpoint: PathBuf,
    /// RAII guard that unmounts/cleans up on Drop.
    pub guard: MountGuard<O>,
}

/// Side-effecting I/O the flow needs to drive.
///
/// Production wires this to udev + `nix::mount::mount`; tests inject an
/// in-memory implementation that just serves files from a `tempdir`.
pub trait FlowIo {
    /// Mount-ops type used by the returned guard.
    type Ops: MountOps + 'static;

    /// Wait for one or more USB devices to appear, optionally filtered by
    /// `(vid, pid)`.  When the discovered whole-disk has a partition table,
    /// the returned slice contains one [`UsbDevice`] per viable partition
    /// (FS in the allow-list).  The caller iterates the slice until one of
    /// the partitions yields a readable `.p12`.
    ///
    /// # Errors
    ///
    /// Propagates [`UsbError::Timeout`] / [`UsbError::TooManyPartitions`]
    /// or any underlying udev/io failure.
    fn wait_for_usb(&self) -> Result<Vec<UsbDevice>, UsbError>;

    /// Mount `dev` at a freshly-created mountpoint and return a guard that
    /// cleans up on Drop.
    ///
    /// # Errors
    ///
    /// Propagates [`MountError`].
    fn mount(&self, dev: &UsbDevice) -> Result<MountSession<Self::Ops>, MountError>;

    /// Discover credentials under the mountpoint.
    ///
    /// `pattern` is the validated `pkcs12_path_pattern` (relative path,
    /// possibly with `${user}`); the caller resolves `pam_user` from
    /// the PAM context.
    ///
    /// Default impl delegates to [`discover_credentials`]; tests may override.
    ///
    /// # Errors
    ///
    /// Propagates [`DiscoveryError`].
    fn discover(
        &self,
        mountpoint: &Path,
        pattern: &str,
        pam_user: &str,
    ) -> Result<DiscoveredCreds, DiscoveryError> {
        discover_credentials(mountpoint, pattern, pam_user)
    }

    /// Surface an admin-actionable diagnostic message to the user via
    /// `PAM_TEXT_INFO` (lock screen / terminal). Best-effort: if the PAM
    /// conv item is unavailable or the application rejects the message,
    /// the flow MUST continue — this never changes the auth verdict.
    ///
    /// Default impl is a no-op so test fakes don't need updating unless
    /// they want to capture the messages.
    fn show_info(&self, _msg: &str) {}
}

/// A process-wide empty [`DeviceTags`] (no applied tags).
///
/// Returned as the fail-closed default when no `[tags]` source is configured,
/// and used by tests that do not exercise delegation. A `&'static` shared
/// instance avoids threading an owned empty set through every call site.
#[must_use]
pub fn empty_device_tags() -> &'static DeviceTags {
    static EMPTY: std::sync::OnceLock<DeviceTags> = std::sync::OnceLock::new();
    EMPTY.get_or_init(DeviceTags::empty)
}

/// All runtime collaborators required by [`authenticate`].
pub struct Deps<'a> {
    /// Validated configuration (used for logging defaults; the heavy lifting
    /// is in the wired collaborators below).
    pub cfg: &'a ValidatedConfig,
    /// Stage-2 trust verifier (anchors + intermediates + CRLs already loaded).
    pub trust: &'a dyn Stage2TrustVerifier,
    /// Monitord IPC client (stub in stage 2; real client lands in stage 6).
    pub monitor: &'a dyn MonitorClient,
    /// Hook executor used for `pre_auth` / `post_auth_success` callbacks.
    /// Production callers wire [`tessera_core::hooks::ForkExecExecutor`];
    /// tests inject a `NoopExecutor` or a custom mock.
    pub hook_executor: &'a dyn HookExecutor,
    /// Resolved host id hash (hex string, 64 chars typical).  When `*`-only
    /// host binding is configured this can be any non-empty placeholder.
    pub host_id_hash: &'a str,
    /// Source kind that produced the host id, recorded into [`AuthContext`].
    pub host_id_source: HostIdSourceKind,
    /// Subject mapping table from validated config.
    pub user_mappings: &'a [tessera_core::config::validated::UserMapping],
    /// Where the active session lives — passed to monitord on a successful
    /// authentication so the daemon knows which logind session, tty, or X
    /// display to act on. The cdylib derives this from `PAM_TTY`; tests
    /// that don't care can use [`tessera_proto::SessionTarget::Unknown`].
    pub pam_target: tessera_proto::SessionTarget,
    /// Role-selection stage (role-format). Carries the requested role, the
    /// loaded role store, the enforcement mode, and the global default TTL.
    /// `enforce = Disabled` (the default migration stage) makes the whole
    /// stage a no-op, preserving pre-role behaviour.
    pub role_stage: RoleStage<'a>,
    /// This device's trusted, applied tag set (tags-delegation §5). Loaded
    /// once per attempt from the configured `[tags]` source. When no source is
    /// configured (or `[tags].enforce = false`) this is an empty set, so any
    /// group-delegation `requireTags` envelope in the chain is unsatisfiable
    /// and rejects (fail-closed). Per-host chains without an envelope are
    /// unaffected.
    pub device_tags: &'a DeviceTags,
}

/// Inputs to the atomic resolve + coverage stage (role-format, task 4.3/4.4).
///
/// Built once per `pam_sm_authenticate` and threaded through [`Deps`] so the
/// requested role travels with the cert verification — there is no later
/// re-read of `PAM_USER` and no swap window (polkit CVE-2021-3560).
pub struct RoleStage<'a> {
    /// The role parsed from the `<user>+<role>` login suffix / prompt, or
    /// `None` when none was supplied.
    pub requested: Option<tessera_core::role::RoleId>,
    /// The on-device role store (already loaded by the cdylib). `None` when
    /// enforcement is disabled (the store is not loaded in that case).
    pub store: Option<&'a tessera_core::role::RoleStore>,
    /// Enforcement mode mapped from `[roles].enforce`.
    pub enforce: tessera_core::role::RoleEnforce,
    /// Global default session TTL from `[roles].default_session_ttl`.
    pub default_session_ttl: std::time::Duration,
}

impl RoleStage<'_> {
    /// A disabled stage (pre-role behaviour) — convenient default for tests
    /// and the `enforce = false` migration phase.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            requested: None,
            store: None,
            enforce: tessera_core::role::RoleEnforce::Disabled,
            default_session_ttl: std::time::Duration::from_secs(
                tessera_core::config::validated::DEFAULT_ROLE_SESSION_TTL_SECONDS,
            ),
        }
    }
}

/// Outcome of a successful authentication.
///
/// The mount guard is returned alongside the [`AuthContext`] so the caller
/// (typically the cdylib `pam_sm_authenticate` entry) can hold the mount
/// alive for the remainder of the session.  Dropping the guard runs umount
/// + rmdir.
///
/// In PKCS#11 mode (`mode = "pkcs11"`) the USB mount step is skipped, so
/// `mount` will be `None`.  Existing callers that always destructure the
/// guard remain backwards compatible because the PKCS#12 flow still
/// populates the field.
pub struct FlowOutcome<O: MountOps + 'static> {
    /// Authenticated session context (later stored in PAM data).
    pub auth_ctx: AuthContext,
    /// Owns the lifetime of the USB mount.  `None` for PKCS#11 mode.
    pub mount: Option<MountGuard<O>>,
}

impl<O: MountOps + 'static> std::fmt::Debug for FlowOutcome<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowOutcome")
            .field("auth_ctx", &self.auth_ctx)
            .field("mount", &self.mount.as_ref().map(|_| "<MountGuard>"))
            .finish()
    }
}

/// Drive the full authentication flow.
///
/// Dispatches based on `cfg.mode`:
///
/// - `Pkcs12` → [`authenticate_pkcs12`] (USB-mount + PKCS#12 file).
/// - `Pkcs11` → [`authenticate_pkcs11`] (cryptographic operations on a
///   PKCS#11 token; `crypto_backend` selects native vs OpenSSL-engine).
///
/// The PIN prompter is supplied separately from [`FlowIo`] because in
/// production it captures a raw `*mut PamHandle`, which the cdylib must own
/// directly; in tests it is just a closure returning a fixed string.
///
/// # Errors
///
/// Propagates [`FlowError`] for every failure path — see
/// [`FlowError::pam_code`] for the PAM return-code mapping.
#[allow(clippy::needless_pass_by_value)]
pub fn authenticate<I: FlowIo, P>(
    deps: Deps<'_>,
    io: &I,
    pam_user: &str,
    pam_service: &str,
    session_id: String,
    prompt_pin: P,
) -> Result<FlowOutcome<I::Ops>, FlowError>
where
    P: FnMut(&str) -> Result<SecretString, PamConvError>,
{
    use tessera_core::config::validated::{CryptoBackend, Mode};
    // Show a one-line greeter banner identifying THIS device before any
    // prompt. fly-dm forwards `PAM_TEXT_INFO` to the greeter UI when
    // `greeter-show-messages` is enabled, so the operator and the
    // engineer at the device see the same prefix that the cert is bound to.
    // Best-effort: if the conv layer drops it, auth continues unchanged.
    let prefix_len = deps.host_id_hash.len().min(8);
    let prefix = &deps.host_id_hash[..prefix_len];
    io.show_info(&format!(
        "Это устройство: host_id={prefix} (source={source:?})",
        prefix = prefix,
        source = deps.host_id_source,
    ));
    match deps.cfg.mode {
        Mode::Pkcs12 => {
            authenticate_pkcs12(deps, io, pam_user, pam_service, session_id, prompt_pin)
        }
        Mode::Pkcs11 => match deps.cfg.crypto_backend {
            CryptoBackend::Pkcs11Native => {
                let pkcs11_io = real_pkcs11_io(deps.cfg)?;
                authenticate_pkcs11(
                    deps,
                    &pkcs11_io,
                    pam_user,
                    pam_service,
                    session_id,
                    prompt_pin,
                )
            }
            CryptoBackend::Openssl => Err(FlowError::Pkcs11OpensslEngineNotImplemented),
        },
    }
}

/// PKCS#12 (USB) authentication path — was the entire body of
/// `authenticate` until T13.
///
/// # Errors
///
/// Propagates [`FlowError`] for every failure path — see
/// [`FlowError::pam_code`] for the PAM return-code mapping.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn authenticate_pkcs12<I: FlowIo, P>(
    deps: Deps<'_>,
    io: &I,
    pam_user: &str,
    pam_service: &str,
    session_id: String,
    mut prompt_pin: P,
) -> Result<FlowOutcome<I::Ops>, FlowError>
where
    P: FnMut(&str) -> Result<SecretString, PamConvError>,
{
    // Step 1 — pre_auth hooks (Stage 5). Run BEFORE we touch the USB
    // bus / mount(2). They get only the PAM identity + the resolved host
    // identity; cert / USB / session fields are not yet known.
    //
    // The monitord IPC notification used to live here, but it ran with
    // synthetic placeholder fields (no USB serial, no cert metadata,
    // SessionTarget::Unknown) — useless for the daemon's USB-removal
    // enforcement. It now happens AFTER all verification steps succeed
    // and before we hand back the FlowOutcome, so every field is real.
    let pre_auth_vars = HookVars::for_pre_auth(
        pam_user,
        pam_service,
        deps.host_id_hash,
        deps.host_id_hash,
        deps.host_id_source.to_string(),
    );
    run_hooks_for_stage(
        deps.cfg,
        HookStage::PreAuth,
        deps.hook_executor,
        &pre_auth_vars,
    )
    .map_err(FlowError::PreAuthHook)?;

    // Step 2 — wait for one or more USB block devices.  On flashes with
    // a partition table this can return multiple `UsbDevice`s (one per
    // viable partition).  We try them in order until one of them yields
    // a readable `.p12`.  The first hit "binds" — if its `.p12` decrypts
    // or its chain doesn't validate we surface the failure as-is (we do
    // NOT continue probing the remaining partitions, since that would
    // turn auth into a guessing oracle).
    let usb_devices = io.wait_for_usb()?;
    tracing::info!(
        target: "tessera.flow",
        count = usb_devices.len(),
        "usb devices/partitions enumerated"
    );

    // Step 3+4 — mount each candidate and look for `.p12` until one matches.
    let pkcs12_pattern = deps
        .cfg
        .pkcs12_path_pattern
        .as_deref()
        .unwrap_or(tessera_core::discovery::DEFAULT_PKCS12_PATH_PATTERN);
    let mut last_discovery_err: Option<DiscoveryError> = None;
    let mut last_envelope_err: Option<P12EnvelopeError> = None;
    let mut bound: Option<BoundUsb<I::Ops>> = None;
    let mut candidates_tried: usize = 0;
    for candidate in usb_devices {
        candidates_tried += 1;
        tracing::info!(
            target: "tessera.flow",
            devnode = ?candidate.devnode,
            vid = format!("{:04x}", candidate.vid),
            pid = format!("{:04x}", candidate.pid),
            fs_type = ?candidate.fs_type,
            "trying USB candidate"
        );
        let MountSession {
            mountpoint,
            guard: mount,
        } = io.mount(&candidate)?;
        tracing::info!(
            target: "tessera.flow",
            devnode = ?candidate.devnode,
            mountpoint = %mountpoint.display(),
            "candidate mounted"
        );
        match io.discover(&mountpoint, pkcs12_pattern, pam_user) {
            Ok(creds) => {
                tracing::info!(
                    target: "tessera.flow",
                    devnode = ?candidate.devnode,
                    p12_path = %creds.p12_path.display(),
                    p12_bytes = creds.p12_bytes.len(),
                    "p12 found"
                );
                // Pre-parse the outer ASN.1 envelope WITHOUT the PIN.
                // A file at the expected path that is not actually a
                // PKCS#12 bundle (typical for multi-partition Apple-
                // formatted USB media where filenames coincidentally
                // collide) is a safe fallback signal: no password was
                // touched, no MAC was verified, no chain was probed —
                // so trying the next partition cannot create a PIN-
                // oracle.  Failures that DO require the password
                // (wrong PIN / MAC verify / decrypt / chain validation)
                // happen later in `acquire_p12_material_with_prompter`
                // and remain fail-closed without partition iteration.
                match validate_p12_envelope(&creds.p12_bytes) {
                    Ok(()) => {
                        tracing::info!(
                            target: "tessera.flow",
                            devnode = ?candidate.devnode,
                            "p12 envelope parsed (pre-PIN ASN.1 check ok)"
                        );
                        bound = Some((candidate, mountpoint, mount, creds));
                        break;
                    }
                    Err(env_err) => {
                        tracing::warn!(
                            target: "tessera.flow",
                            mountpoint = %mountpoint.display(),
                            error = %env_err,
                            ".p12 found but ASN.1 envelope is invalid, trying next partition",
                        );
                        // `mount` guard drops here → umount + rmdir.
                        drop(mount);
                        last_envelope_err = Some(env_err);
                    }
                }
            }
            Err(DiscoveryError::P12NotFound { path }) => {
                tracing::info!(
                    target: "tessera.flow",
                    mountpoint = %mountpoint.display(),
                    missing = %path.display(),
                    "no .p12 on this partition, trying next",
                );
                // `mount` guard drops here → umount + rmdir.
                drop(mount);
                last_discovery_err = Some(DiscoveryError::P12NotFound { path });
            }
            Err(other) => return Err(FlowError::Discovery(other)),
        }
    }
    let Some((dev, _mountpoint, mount, creds)) = bound else {
        // Prefer the more informative envelope error when present —
        // it tells the operator "we DID see a .p12 but it was junk",
        // which is a different fix than "no .p12 anywhere".
        if let Some(env_err) = last_envelope_err {
            return Err(FlowError::P12Envelope(env_err));
        }
        return Err(FlowError::Discovery(last_discovery_err.unwrap_or_else(
            || DiscoveryError::P12NotFound {
                path: PathBuf::from(pkcs12_pattern),
            },
        )));
    };

    // Step 5 — PIN-retry loop.  When the operator configured
    // `pkcs12_pin_prompt` it replaces the default "Smart-card PIN: "
    // prompt, mirroring `pkcs11_pin_prompt` on the PKCS#11 path.
    let loaded: LoadedKeyMaterial = match acquire_p12_material_with_prompter(
        &creds.p12_bytes,
        3,
        deps.cfg.pkcs12_pin_prompt.as_deref(),
        &mut prompt_pin,
    ) {
        Ok(m) => m,
        Err(AcquireError::MaxTries) => {
            // Try to read the cert plaintext from the .p12 (newer issuance
            // tooling embeds the leaf cert outside the encrypted SafeContents
            // so it can be inspected without the PIN). When that works, we
            // can surface the host/user binding the cert is bound to so the
            // engineer can match it against the deployment registry. If the
            // .p12 predates that change and the cert is still encrypted,
            // parsing fails gracefully and we fall back to a generic message.
            io.show_info(&p12_wrong_pin_diagnostic(&creds.p12_bytes));
            return Err(FlowError::MaxTries);
        }
        Err(e) => return Err(FlowError::from(e)),
    };

    // Step 6 — challenge-response (proves we hold the private key).
    let priv_key = loaded.private_key()?;
    challenge_response(
        &loaded.end_entity,
        &priv_key,
        deps.cfg.gost_engine_path.as_deref(),
    )?;

    // Step 7 — assemble the chain.  `chain.pem` is appended AFTER the p12's
    // own presented chain so that whichever the bundle had wins ties.
    let mut presented = loaded.presented_chain.clone();
    if let Some(chain_pem) = creds.chain_pem.as_deref() {
        presented.extend(parse_chain_pem(chain_pem)?);
    }

    // Step 8 — trust verification (path build, signatures, CRLs, pinning).
    let verified = deps.trust.verify(&loaded.end_entity, &presented)?;
    tracing::info!(
        target: "tessera.flow",
        devnode = ?dev.devnode,
        cert_subject = ?loaded.end_entity.subject_cn().ok(),
        cert_serial = %loaded.end_entity.serial_hex().to_lowercase(),
        "cert chain validated"
    );

    // Step 9 — cert scope (cert authorises this host).
    //
    // `pam_cert_host_binding` is mandatory: the cert MUST authorise the
    // running host. `pam_cert_user_binding`, if present, also takes
    // precedence over the legacy TOML mapping; if absent, Step 10 falls
    // back to `[[user_mapping]]`. Runs BEFORE Step 10 so that cert-
    // extension errors (e.g. missing `pam_cert_host_binding`) surface
    // as the real cause instead of being masked by a stale mapping.
    if let Err(e) = verify_host_binding(loaded.end_entity.x509(), deps.host_id_hash) {
        // Surface an admin-actionable diagnostic on the lock screen /
        // terminal: the host_id_hash of this machine + the source kind
        // is what the cert MUST encode. Logged at warn so syslog has a
        // record even when the conv layer drops the message.
        tracing::warn!(
            target: "tessera.flow",
            error = %e,
            host_id_hash = %deps.host_id_hash,
            host_id_source = ?deps.host_id_source,
            pam_user = %pam_user,
            "host_binding rejected; surfacing diagnostic to user"
        );
        // Show the short prefix on-screen (8 hex chars are eyeballable
        // on a small terminal); the full hash already lives in syslog
        // via the warn! above.
        let prefix_len = deps.host_id_hash.len().min(8);
        let prefix = &deps.host_id_hash[..prefix_len];
        io.show_info(&format!(
            "Сертификат выпущен для другого устройства.\n\
             host_id этой машины: {prefix} (source={source:?})\n\
             Передайте администратору для перевыпуска.",
            prefix = prefix,
            source = deps.host_id_source,
        ));
        return Err(FlowError::CertScope(e));
    }

    // Step 10 — user authorisation. Cert-driven path (user_binding
    // extension present) wins over the legacy `[[user_mapping]]`. Only
    // certs without `pam_cert_user_binding` fall through to TOML; a
    // present-but-broken extension fails closed (see `authorize_user`).
    authorize_user(&loaded.end_entity, pam_user, deps.user_mappings)?;

    // Step 11 — assemble AuthContext.
    let cert_cn = loaded.end_entity.subject_cn().ok();
    let cert_serial = Some(loaded.end_entity.serial_hex().to_lowercase());
    let cert_not_after = Some(loaded.end_entity.not_after());
    let usb_vid_pid = Some(format!("{:04x}:{:04x}", dev.vid, dev.pid));

    // MAC integrity inputs captured for `pam_sm_open_session`.
    let verified_leaf = verified.verified_leaf();
    let cert_ident_value = tessera_core::x509::CertIdent::from(&verified_leaf);
    let cert_max_integrity =
        match tessera_core::x509::max_integrity_ext::extract_max_integrity(&verified_leaf) {
            Ok(label) => label,
            Err(e) => {
                tessera_core::mac::audit::emit_cert_ext_parse_failed(
                    pam_user,
                    &cert_ident_value,
                    &e.to_string(),
                );
                None
            }
        };
    let cert_ident = Some(cert_ident_value);
    let home_dir = resolve_home_dir(pam_user);

    // Step 10b — atomic role resolve + coverage (role-format). Runs right
    // after cert verification and before the session payload is fixed, with
    // no swap window (CVE-2021-3560). A `require`-mode denial aborts here.
    let role = resolve_role_stage(
        &verified_leaf,
        &deps.role_stage,
        pam_user,
        cert_remaining_ttl(cert_not_after),
    )?;

    // Step 10c — LIVE delegation-envelope enforcement (tags-delegation §4).
    // For every CA in the verified chain carrying delegation_constraints,
    // device.tags ⊇ requireTags AND role/level/TTL ceilings must hold. A
    // chain with no constraints is a no-op. Fail-closed: a generic message to
    // the engineer, the full reason vector only to the `delegation_denied`
    // audit event.
    if let Err(e) = enforce_delegation_stage(
        &verified,
        deps.device_tags,
        role.as_ref(),
        cert_max_integrity,
        &verified_leaf,
    ) {
        io.show_info(tessera_core::trust::delegation_audit::GENERIC_DELEGATION_DENIED_MESSAGE);
        return Err(e);
    }

    let auth_ctx = AuthContext {
        session_id,
        cert_cn,
        cert_serial,
        usb_serial: dev.serial.clone(),
        usb_vid_pid,
        pam_service: pam_service.to_string(),
        host_id: deps.host_id_hash.to_string(),
        host_id_source: deps.host_id_source,
        authenticated_at: SystemTime::now(),
        cert_not_after,
        clock_skew_seconds: deps.cfg.trust.clock_skew_seconds,
        cert_max_integrity,
        cert_ident,
        home_dir,
        role,
    };

    // Step 11b — post_auth_success hooks (Stage 5). Run after every
    // verification step has succeeded but before set_pam_data, so a hook
    // failure can still abort the session by returning PAM_AUTH_ERR.
    let post_vars = HookVars::for_post_auth_success(pam_user, &auth_ctx);
    run_hooks_for_stage(
        deps.cfg,
        HookStage::PostAuthSuccess,
        deps.hook_executor,
        &post_vars,
    )
    .map_err(FlowError::PostAuthHook)?;

    // Step 11c — notify monitord with the FULL post-auth payload (USB
    // serial from the discovered device, cert CN/serial from the
    // validated leaf, target from PAM_TTY). Under strict fail mode a
    // registration failure denies the login: a cert-authenticated session
    // monitord never recorded can never have its token/USB removal enforced.
    // Under permissive mode the FailModeWrapper has already converted the
    // transport error to Ok, so this branch fires only in strict mode.
    let cert_cn_str = auth_ctx.cert_cn.as_deref().unwrap_or("");
    let cert_serial_str = auth_ctx.cert_serial.as_deref().unwrap_or("");
    let extras = session_open_extras(&loaded.end_entity, pam_user);
    let info = OpenSessionInfo {
        session_id: &auth_ctx.session_id,
        pam_user,
        pam_service,
        host_id_hash: deps.host_id_hash,
        target: deps.pam_target.clone(),
        usb_serial: dev.serial.as_deref(),
        cert_cn: cert_cn_str,
        cert_serial: cert_serial_str,
        engineer_ski: &extras.engineer_ski,
        engineer_cert_sha256: &extras.engineer_cert_sha256,
        uid: extras.uid,
        role: auth_ctx.role.as_ref().map(|r| r.role.as_str()),
        role_version: auth_ctx.role.as_ref().map(|r| r.role_version),
        // Only role sessions carry a time-bound ceiling. The absolute expiry is
        // clamped to the certificate's notAfter so the enforced deadline can
        // never outlive the certificate.
        session_expiry: session_expiry(
            auth_ctx.role.as_ref(),
            auth_ctx.authenticated_at,
            auth_ctx.cert_not_after,
        ),
    };
    register_session_or_deny(deps.monitor, &info)?;

    tracing::info!(
        target: "tessera.flow",
        pam_user = %pam_user,
        candidates_tried,
        cert_serial = %loaded.end_entity.serial_hex().to_lowercase(),
        "auth result: success (pkcs12)"
    );

    Ok(FlowOutcome {
        auth_ctx,
        mount: Some(mount),
    })
}

// ---------------------------------------------------------------------------
// PKCS#11 (Stage 4) authentication path
// ---------------------------------------------------------------------------

/// Type alias for the closure-style PIN prompter passed through to
/// [`Pkcs11Io::acquire_session`].  The trait object form avoids
/// re-genericising the trait at every level of the dispatcher.
pub type PinPrompterFn<'a> = dyn FnMut(&str) -> Result<SecretString, PamConvError> + 'a;

/// Side-effecting collaborators that the PKCS#11 path needs.
///
/// Production wires this to [`RealPkcs11Io`] which talks to a live
/// `cryptoki::Pkcs11` context; tests inject a closure-backed stub.
pub trait Pkcs11Io {
    /// Wait for a token to appear in any slot, optionally filtered by
    /// `CKA_LABEL`.  Returns the [`Slot`] that satisfied the search and
    /// keeps a reference to the underlying backend alive for subsequent
    /// `acquire_session` calls.
    ///
    /// # Errors
    ///
    /// Forwards any [`tessera_core::token::pkcs11::Pkcs11Error`].
    fn wait_for_token(
        &self,
    ) -> Result<tessera_core::token::pkcs11::Slot, tessera_core::token::pkcs11::Pkcs11Error>;

    /// Read the token serial number on the supplied slot.  Used to fill
    /// `AuthContext.usb_serial` in mode B.
    ///
    /// # Errors
    ///
    /// Forwards any [`tessera_core::token::pkcs11::Pkcs11Error`].
    fn read_token_serial(
        &self,
        slot: tessera_core::token::pkcs11::Slot,
    ) -> Result<String, tessera_core::token::pkcs11::Pkcs11Error>;

    /// Drive the bounded PIN-retry loop, prompting the user via
    /// `pin_prompter` until either a session is opened or the loop bails.
    ///
    /// # Errors
    ///
    /// Forwards any [`tessera_core::token::pkcs11::AcquireError`].
    fn acquire_session(
        &self,
        slot: tessera_core::token::pkcs11::Slot,
        pin_prompter: &mut PinPrompterFn<'_>,
    ) -> Result<tessera_core::token::pkcs11::Pkcs11Session, tessera_core::token::pkcs11::AcquireError>;
}

/// Production [`Pkcs11Io`] backed by a real [`tessera_core::token::pkcs11::Pkcs11Backend`].
///
/// Construct via [`real_pkcs11_io`]; the backend is shared by reference
/// across the trait methods.  Module/PIN/locking parameters come from
/// the validated config.
pub struct RealPkcs11Io<'a> {
    /// Owned backend (the dynamic library and `Pkcs11` ctx).
    backend: tessera_core::token::pkcs11::Pkcs11Backend,
    /// Token wait timeout.
    timeout: std::time::Duration,
    /// Optional `CKA_LABEL` filter for token discovery.
    token_label: Option<String>,
    /// Number of PIN attempts allowed.
    max_pin_attempts: u32,
    /// Lifetime tie-back to the validated config to avoid a `'static` bound.
    _cfg: std::marker::PhantomData<&'a ValidatedConfig>,
}

impl Pkcs11Io for RealPkcs11Io<'_> {
    fn wait_for_token(
        &self,
    ) -> Result<tessera_core::token::pkcs11::Slot, tessera_core::token::pkcs11::Pkcs11Error> {
        self.backend
            .wait_for_token(self.timeout, self.token_label.as_deref())
    }

    fn read_token_serial(
        &self,
        slot: tessera_core::token::pkcs11::Slot,
    ) -> Result<String, tessera_core::token::pkcs11::Pkcs11Error> {
        tessera_core::token::pkcs11::read_token_serial(&self.backend, slot)
    }

    fn acquire_session(
        &self,
        slot: tessera_core::token::pkcs11::Slot,
        pin_prompter: &mut PinPrompterFn<'_>,
    ) -> Result<tessera_core::token::pkcs11::Pkcs11Session, tessera_core::token::pkcs11::AcquireError>
    {
        tessera_core::token::pkcs11::acquire_pkcs11_session(
            &self.backend,
            slot,
            self.max_pin_attempts,
            |prompt| pin_prompter(prompt),
        )
    }
}

/// Construct a [`RealPkcs11Io`] from the validated config.  Loads the
/// PKCS#11 module right away so configuration mistakes surface as
/// [`FlowError::Pkcs11`] before any USB device or PIN prompt is touched.
///
/// # Errors
///
/// - [`FlowError::Pkcs11ModulePathMissingInConfig`] — `cfg.pkcs11_module`
///   is `None` (config-validation should normally catch this).
/// - [`FlowError::Pkcs11`] for any backend load / init error.
pub fn real_pkcs11_io(cfg: &ValidatedConfig) -> Result<RealPkcs11Io<'_>, FlowError> {
    let module_path = cfg
        .pkcs11_module
        .as_deref()
        .ok_or(FlowError::Pkcs11ModulePathMissingInConfig)?;
    let backend =
        tessera_core::token::pkcs11::Pkcs11Backend::load(module_path, cfg.pkcs11_locking_mode)?;
    Ok(RealPkcs11Io {
        backend,
        timeout: cfg.pkcs11_slot_wait,
        token_label: cfg.pkcs11_token_label.clone(),
        max_pin_attempts: cfg.pkcs11_max_pin_attempts,
        _cfg: std::marker::PhantomData,
    })
}

/// Drive the PKCS#11 (Stage 4 mode B) authentication path.
///
/// This function is intentionally generic over the I/O abstraction
/// ([`Pkcs11Io`]) — the production callers wire [`RealPkcs11Io`] while
/// tests inject a stub.  No USB / mount step happens; the token is
/// discovered through [`Pkcs11Io::wait_for_token`] and the on-token
/// signature is verified locally via [`tessera_core::token::pkcs11::pkcs11_challenge_response`].
///
/// `intermediates_from_config` is the only chain the verifier sees in
/// T13: pulling intermediates **off the token** is left for T18.  This
/// is a documented OPEN QUESTION.
///
/// # Errors
///
/// Propagates [`FlowError`] for every failure path — see
/// [`FlowError::pam_code`] for the PAM return-code mapping.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn authenticate_pkcs11<O, T, P>(
    deps: Deps<'_>,
    io: &T,
    pam_user: &str,
    pam_service: &str,
    session_id: String,
    mut prompt_pin: P,
) -> Result<FlowOutcome<O>, FlowError>
where
    O: MountOps + 'static,
    T: Pkcs11Io,
    P: FnMut(&str) -> Result<SecretString, PamConvError>,
{
    use tessera_core::token::pkcs11::{
        pkcs11_challenge_response, select_mechanism, FoundCertificate, FoundPrivateKey,
    };

    // Step 1 — pre_auth hooks (Stage 5). Same gate as the PKCS#12 path.
    //
    // Pre-auth IPC notification was deliberately removed: it used to fire
    // with synthetic placeholders (Unknown target, no serial, no cert
    // metadata), which defeated monitord's USB-removal enforcement. The
    // notification now happens post-auth with real fields.
    let pre_auth_vars = HookVars::for_pre_auth(
        pam_user,
        pam_service,
        deps.host_id_hash,
        deps.host_id_hash,
        deps.host_id_source.to_string(),
    );
    run_hooks_for_stage(
        deps.cfg,
        HookStage::PreAuth,
        deps.hook_executor,
        &pre_auth_vars,
    )
    .map_err(FlowError::PreAuthHook)?;

    // Step 2 — wait for a token to appear.
    let slot = io.wait_for_token()?;
    tracing::info!(
        target: "tessera.flow",
        ?slot,
        token_label = ?deps.cfg.pkcs11_token_label,
        "pkcs11 token found"
    );

    // Step 3 — read serial early so we still have a useful AuthContext
    //          even if subsequent steps fail (used for telemetry only).
    let token_serial = io.read_token_serial(slot)?;

    // Step 4 — bounded PIN loop → authenticated session.  When the
    // operator configured `pkcs11_pin_prompt` we substitute the
    // default Russian "Введите PIN токена: " prompt with that value.
    // The prompter receives the substituted string verbatim and feeds
    // it to `pam_conv` (production) or ignores it (tests).
    let prompt_override = deps.cfg.pkcs11_pin_prompt.clone();
    let session = io.acquire_session(slot, &mut |default_prompt| {
        let p = prompt_override.as_deref().unwrap_or(default_prompt);
        prompt_pin(p)
    })?;

    // Step 5 — find the end-entity certificate object on the token.  The
    // `CKA_LABEL` filter, when set, comes from `pkcs11_object_label`
    // (the per-user certificate object) — *not* from the token label,
    // which is used earlier in `wait_for_token` to disambiguate slots.
    let cert: FoundCertificate =
        session.find_certificate(deps.cfg.pkcs11_object_label.as_deref())?;
    tracing::info!(
        target: "tessera.flow",
        cka_label = ?cert.cka_label,
        "pkcs11 certificate found"
    );

    // Step 6 — find the matching private key (paired by CKA_ID).  An
    // extractable key is rejected here unless the operator opted in via
    // `pkcs11_allow_extractable_keys` (mode-B invariant, fail-closed).
    let key: FoundPrivateKey =
        session.find_private_key_for_cert(&cert, deps.cfg.pkcs11_allow_extractable_keys)?;

    // Step 7 — pick a signing mechanism, then challenge-response.
    let pubkey = cert.certificate.public_key().map_err(FlowError::Trust)?;
    let mechanism = select_mechanism(key.key_type, &pubkey)?;
    pkcs11_challenge_response(
        &session,
        key.object,
        key.key_type,
        &mechanism,
        &cert.certificate,
    )?;

    // Step 8 — assemble the chain from config-only intermediates.
    //
    // OPEN QUESTION: we do **not** harvest intermediates
    // from the token in T13 — the verifier only sees what the operator
    // configured under `[trust]`.  T18 will add an on-token chain
    // pull-up.  This is intentional: the trust verifier still works as
    // long as the cert chains to a configured anchor, which is the
    // common case for both Rutoken and JaCarta deployments.
    let presented_chain: Vec<Certificate> = Vec::new();
    let verified = deps.trust.verify(&cert.certificate, &presented_chain)?;

    // Step 9 — cert scope (cert authorises this host).
    // `pam_cert_host_binding` is mandatory; user_binding is checked in
    // Step 10. Runs BEFORE the legacy TOML mapping so cert-extension
    // errors (e.g. missing `pam_cert_host_binding`) surface as the real
    // cause.
    verify_host_binding(cert.certificate.x509(), deps.host_id_hash)?;

    // Step 10 — user authorisation. Cert path (user_binding present)
    // wins over `[[user_mapping]]`; legacy path used when ext absent; a
    // present-but-broken extension fails closed (see `authorize_user`).
    authorize_user(&cert.certificate, pam_user, deps.user_mappings)?;

    // Step 11 — assemble AuthContext.  The token serial replaces the
    // USB serial in this mode (monitord uses the same field).
    let cert_cn = cert.certificate.subject_cn().ok();
    let cert_serial = Some(cert.certificate.serial_hex().to_lowercase());
    let cert_not_after = Some(cert.certificate.not_after());
    let verified_leaf = verified.verified_leaf();
    let cert_ident_value = tessera_core::x509::CertIdent::from(&verified_leaf);
    let cert_max_integrity =
        match tessera_core::x509::max_integrity_ext::extract_max_integrity(&verified_leaf) {
            Ok(label) => label,
            Err(e) => {
                tessera_core::mac::audit::emit_cert_ext_parse_failed(
                    pam_user,
                    &cert_ident_value,
                    &e.to_string(),
                );
                None
            }
        };
    let cert_ident = Some(cert_ident_value);
    let home_dir = resolve_home_dir(pam_user);

    // Step 10b — atomic role resolve + coverage (role-format). Same gate as
    // the PKCS#12 path; runs before the session payload is fixed.
    let role = resolve_role_stage(
        &verified_leaf,
        &deps.role_stage,
        pam_user,
        cert_remaining_ttl(cert_not_after),
    )?;

    // Step 10c — LIVE delegation-envelope enforcement (tags-delegation §4),
    // identical gate to the PKCS#12 path. Fail-closed; the full reason vector
    // goes only to the `delegation_denied` audit event.
    enforce_delegation_stage(
        &verified,
        deps.device_tags,
        role.as_ref(),
        cert_max_integrity,
        &verified_leaf,
    )?;

    let auth_ctx = AuthContext {
        session_id,
        cert_cn,
        cert_serial,
        usb_serial: Some(token_serial),
        usb_vid_pid: None,
        pam_service: pam_service.to_string(),
        host_id: deps.host_id_hash.to_string(),
        host_id_source: deps.host_id_source,
        authenticated_at: SystemTime::now(),
        cert_not_after,
        clock_skew_seconds: deps.cfg.trust.clock_skew_seconds,
        cert_max_integrity,
        cert_ident,
        home_dir,
        role,
    };

    // Drop the session here so `C_Logout` runs before we return.
    drop(session);

    // Step 11b — post_auth_success hooks (Stage 5).
    let post_vars = HookVars::for_post_auth_success(pam_user, &auth_ctx);
    run_hooks_for_stage(
        deps.cfg,
        HookStage::PostAuthSuccess,
        deps.hook_executor,
        &post_vars,
    )
    .map_err(FlowError::PostAuthHook)?;

    // Step 11c — notify monitord with the FULL post-auth payload. In
    // PKCS#11 mode the token serial occupies the `usb_serial` slot the
    // daemon keys removal enforcement on. Under strict fail mode a
    // registration failure denies the login: without a recorded session the
    // token's removal could never trigger the configured lock/logout. Under
    // permissive mode the FailModeWrapper absorbs the transport error, so
    // this branch fires only in strict mode.
    let cert_cn_str = auth_ctx.cert_cn.as_deref().unwrap_or("");
    let cert_serial_str = auth_ctx.cert_serial.as_deref().unwrap_or("");
    let extras = session_open_extras(&cert.certificate, pam_user);
    let info = OpenSessionInfo {
        session_id: &auth_ctx.session_id,
        pam_user,
        pam_service,
        host_id_hash: deps.host_id_hash,
        target: deps.pam_target.clone(),
        usb_serial: auth_ctx.usb_serial.as_deref(),
        cert_cn: cert_cn_str,
        cert_serial: cert_serial_str,
        engineer_ski: &extras.engineer_ski,
        engineer_cert_sha256: &extras.engineer_cert_sha256,
        uid: extras.uid,
        role: auth_ctx.role.as_ref().map(|r| r.role.as_str()),
        role_version: auth_ctx.role.as_ref().map(|r| r.role_version),
        // Only role sessions carry a time-bound ceiling. The absolute expiry is
        // clamped to the certificate's notAfter so the enforced deadline can
        // never outlive the certificate.
        session_expiry: session_expiry(
            auth_ctx.role.as_ref(),
            auth_ctx.authenticated_at,
            auth_ctx.cert_not_after,
        ),
    };
    register_session_or_deny(deps.monitor, &info)?;

    Ok(FlowOutcome {
        auth_ctx,
        mount: None,
    })
}

/// Registers a freshly authenticated session with monitord, failing closed
/// when the configured fail mode demands it.
///
/// `monitor` is already wrapped in a [`tessera_core::ipc::FailModeWrapper`]:
/// in permissive mode that wrapper turns transport failures (connect / timeout
/// / decode) into `Ok(())` before they reach this function, so the login is
/// unaffected. A returned `Err` therefore means either the fail mode is strict
/// or the error is one that changes the verdict regardless of mode (the device
/// backing the session is gone, or the daemon rejected us). In every such case
/// the session cannot be placed under continuous-presence enforcement — later
/// token or USB removal could never trigger the configured lock/logout — so we
/// deny rather than grant a session monitord never recorded.
fn register_session_or_deny(
    monitor: &dyn MonitorClient,
    info: &OpenSessionInfo<'_>,
) -> Result<(), FlowError> {
    monitor.open_session(info).map_err(|e| {
        tracing::warn!(
            target: "tessera.flow",
            error = %e,
            "monitor open_session failed under strict fail mode; denying auth"
        );
        FlowError::MonitorRegistration(e)
    })
}

/// IPC fields derived from the validated engineer cert.
///
/// Bundled together so the two emission sites in this module (USB-PKCS#12
/// and PKCS#11) build them identically. Owned strings so the consumer can
/// borrow with the right lifetime when constructing [`OpenSessionInfo`].
#[derive(Debug, Default)]
pub(crate) struct SessionOpenExtras {
    pub engineer_ski: String,
    pub engineer_cert_sha256: String,
    pub uid: u32,
}

/// Best-effort extraction of `SessionOpen` engineer-cert fields. Logs at
/// `warn` and returns defaults on failure — the daemon will see empty
/// strings and the IPC will continue to work for the legacy fields. This
/// matches the existing "monitor failures are non-fatal" policy.
pub(crate) fn session_open_extras(cert: &Certificate, pam_user: &str) -> SessionOpenExtras {
    use sha2::Digest;
    let mut out = SessionOpenExtras::default();
    let x = cert.x509();
    if let Some(ski) = x.subject_key_id() {
        out.engineer_ski = hex::encode(ski.as_slice());
    }
    match x.to_der() {
        Ok(der) => {
            out.engineer_cert_sha256 = hex::encode(sha2::Sha256::digest(&der));
        }
        Err(e) => {
            tracing::warn!(
                target: "tessera.flow",
                error = %e,
                "failed to encode engineer cert as DER for SessionOpen sha256 (non-fatal)"
            );
        }
    }
    out.uid = resolve_uid(pam_user);
    out
}

/// Resolve `pam_user` to a Unix uid for IPC payload purposes. Returns 0
/// when the lookup fails — monitord stores the uid as-is and the
/// active-session lookup will simply miss for uid 0 (root is never the
/// PAM-target user in production).
fn resolve_uid(pam_user: &str) -> u32 {
    match nix::unistd::User::from_name(pam_user) {
        Ok(Some(u)) => u.uid.as_raw(),
        Ok(None) => {
            tracing::warn!(
                target: "tessera.flow",
                pam_user,
                "uid lookup returned None — defaulting to 0 in SessionOpen"
            );
            0
        }
        Err(errno) => {
            tracing::warn!(
                target: "tessera.flow",
                pam_user,
                errno = errno as i32,
                "uid lookup failed — defaulting to 0 in SessionOpen"
            );
            0
        }
    }
}

/// Resolve `pam_user`'s `$HOME` via NSS.  Returns `None` when the user
/// is not in passwd or has no home set; the MAC orchestrator's
/// home-label advisory tolerates `None`.
fn resolve_home_dir(pam_user: &str) -> Option<PathBuf> {
    match nix::unistd::User::from_name(pam_user) {
        Ok(Some(u)) => Some(u.dir),
        _ => None,
    }
}

/// Helper to keep `flow::authenticate` body short.  Public so tests can
/// reuse it.
///
/// # Errors
///
/// Returns [`TrustError::CertParse`] if the input is not a sequence of
/// PEM-encoded X.509 certificates.
pub fn parse_chain_pem(pem: &[u8]) -> Result<Vec<Certificate>, TrustError> {
    let stack = openssl::x509::X509::stack_from_pem(pem)
        .map_err(|e| TrustError::CertParse(e.to_string()))?;
    let mut out = Vec::with_capacity(stack.len());
    for x in &stack {
        let der = x
            .to_der()
            .map_err(|e| TrustError::CertParse(e.to_string()))?;
        out.push(Certificate::from_der(&der)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Production FlowIo adapter
// ---------------------------------------------------------------------------

/// Production [`FlowIo`] — wires udev + mount(2).
#[cfg(target_os = "linux")]
pub struct RealFlowIo {
    /// Wait timeout.
    pub timeout: std::time::Duration,
    /// Allow-list of `(vid, pid)` pairs from `usb_allowed_devices`
    /// (empty → accept any USB block device).
    pub vid_pid_filter: Vec<(u16, u16)>,
    /// Maximum number of USB partitions inspected per whole-disk.
    pub max_usb_partitions: usize,
    /// Base directory under which session-specific mountpoints are created.
    pub mountpoint_base: PathBuf,
    /// Session id used to derive the per-session mountpoint subdirectory.
    pub session_id: String,
    /// Monotonically incrementing counter that disambiguates mountpoints
    /// when the flow tries multiple partitions for the same session id.
    /// `Cell` is fine — we run single-threaded inside `pam_sm_authenticate`.
    mount_seq: std::cell::Cell<u32>,
    /// Optional live PAM handle (as `usize` to avoid raw-ptr Send/Sync
    /// linting; we never share across threads). When `Some`, `show_info`
    /// drives `PAM_TEXT_INFO` via the conv callback; when `None` it is a
    /// silent no-op (tests / e2e on tmpfs).
    pamh: Option<usize>,
}

#[cfg(target_os = "linux")]
impl RealFlowIo {
    /// Build a [`RealFlowIo`] with the standard `mount_seq` starting at 0.
    ///
    /// `show_info` is a silent no-op for instances built this way; use
    /// [`Self::with_pamh`] from `pam_sm_authenticate` to wire the live
    /// PAM conversation handle for `PAM_TEXT_INFO` diagnostics.
    #[must_use]
    pub fn new(
        timeout: std::time::Duration,
        vid_pid_filter: Vec<(u16, u16)>,
        max_usb_partitions: usize,
        mountpoint_base: PathBuf,
        session_id: String,
    ) -> Self {
        Self {
            timeout,
            vid_pid_filter,
            max_usb_partitions,
            mountpoint_base,
            session_id,
            mount_seq: std::cell::Cell::new(0),
            pamh: None,
        }
    }

    /// Attach the live PAM handle so [`FlowIo::show_info`] can deliver
    /// diagnostics via `PAM_TEXT_INFO`. The handle is stored as `usize`
    /// to keep the struct `Send`-friendly; the caller MUST ensure the
    /// `RealFlowIo` does not outlive the `pam_sm_*` stack frame that
    /// owns `pamh`.
    #[must_use]
    pub fn with_pamh(mut self, pamh: *mut pam_sys::pam_handle_t) -> Self {
        self.pamh = Some(pamh as usize);
        self
    }
}

#[cfg(target_os = "linux")]
impl FlowIo for RealFlowIo {
    type Ops = tessera_core::mount_guard::RealMountOps;

    fn wait_for_usb(&self) -> Result<Vec<UsbDevice>, UsbError> {
        tessera_core::usb::wait_for_usb_devices(
            self.timeout,
            &self.vid_pid_filter,
            self.max_usb_partitions,
        )
    }

    fn mount(&self, dev: &UsbDevice) -> Result<MountSession<Self::Ops>, MountError> {
        // Derive a per-attempt mountpoint so retries across partitions do
        // not collide on the same directory.
        let seq = self.mount_seq.get();
        self.mount_seq.set(seq.wrapping_add(1));
        let subdir = if seq == 0 {
            self.session_id.clone()
        } else {
            format!("{}-{seq}", self.session_id)
        };
        let target = self.mountpoint_base.join(subdir);
        // Caller must ensure `target.parent()` exists; we create the leaf.
        std::fs::create_dir_all(&target).map_err(MountError::MountSyscall)?;
        let guard = tessera_core::mount::usb::mount_usb_device(dev, &target)?;
        Ok(MountSession {
            mountpoint: target,
            guard,
        })
    }

    fn show_info(&self, msg: &str) {
        // Best-effort: PAM_TEXT_INFO failures MUST NOT change the auth
        // verdict. We log conv failures at warn so admins still see them
        // even if the lock screen swallows the message.
        let Some(pamh_addr) = self.pamh else {
            return;
        };
        let pamh = pamh_addr as *mut pam_sys::pam_handle_t;
        // SAFETY: `pamh` was attached via `with_pamh` from the cdylib
        // entry, which guarantees the handle is live for the entire
        // `pam_sm_authenticate` call (and thus the entire flow). The
        // call is single-threaded.
        if let Err(e) = unsafe { crate::pam_conv::show_info(pamh, msg) } {
            tracing::warn!(
                target: "tessera.flow",
                error = %e,
                "PAM_TEXT_INFO conv failed; admin diagnostic not delivered to user"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory FlowIo (tests / e2e on tmpfs)
// ---------------------------------------------------------------------------

/// Test-only [`MountOps`] that does nothing on Drop — used to wrap an
/// already-staged tempdir as if it were a real mount.
#[derive(Debug, Default)]
pub struct NoopMountOps;

impl MountOps for NoopMountOps {
    fn mount(
        &self,
        _source: &Path,
        _target: &Path,
        _fs_type: &str,
        _flags: tessera_core::mount_guard::MountFlags,
        _data: Option<&str>,
    ) -> Result<(), tessera_core::error::MountGuardError> {
        Ok(())
    }
    fn umount(&self, _target: &Path) -> Result<(), tessera_core::error::MountGuardError> {
        Ok(())
    }
    fn mkdir_mode_0700(&self, _path: &Path) -> Result<(), tessera_core::error::MountGuardError> {
        Ok(())
    }
    fn rmdir(&self, _path: &Path) -> Result<(), tessera_core::error::MountGuardError> {
        Ok(())
    }
}

/// In-memory [`FlowIo`] for tests and e2e on tmpfs.  No real mount happens —
/// the caller pre-stages `mountpoint/certs/{user.p12,chain.pem}` files.
pub struct InMemoryFlowIo {
    /// Synthetic device record returned by [`Self::wait_for_usb`].
    pub device: UsbDevice,
    /// Pre-staged mountpoint (typically a `tempfile::TempDir`).
    pub mountpoint: PathBuf,
    /// Optional canned error to return from `wait_for_usb` (one-shot).
    pub usb_error: Option<UsbError>,
    /// Optional canned error to return from `mount` (one-shot).
    pub mount_error: Option<MountError>,
}

impl InMemoryFlowIo {
    /// Build a synthetic flow-io serving `mountpoint`.
    #[must_use]
    pub fn new(mountpoint: PathBuf) -> Self {
        Self {
            device: UsbDevice {
                devnode: PathBuf::from("/dev/sdz1"),
                serial: Some("MOCK".into()),
                vid: 0x1234,
                pid: 0x5678,
                fs_type: Some("vfat".into()),
            },
            mountpoint,
            usb_error: None,
            mount_error: None,
        }
    }
}

impl FlowIo for InMemoryFlowIo {
    type Ops = NoopMountOps;

    fn wait_for_usb(&self) -> Result<Vec<UsbDevice>, UsbError> {
        if let Some(e) = &self.usb_error {
            // UsbError doesn't implement Clone; rebuild the most useful variants.
            return Err(match e {
                UsbError::Timeout => UsbError::Timeout,
                UsbError::Udev(s) => UsbError::Udev(s.clone()),
                UsbError::UnsupportedPlatform => UsbError::UnsupportedPlatform,
                UsbError::MissingProperty(s) => UsbError::MissingProperty(s.clone()),
                UsbError::NoMatchingDevice => UsbError::NoMatchingDevice,
                UsbError::Io(io) => UsbError::Udev(format!("io: {io}")),
                UsbError::TooManyPartitions {
                    devnode,
                    count,
                    limit,
                } => UsbError::TooManyPartitions {
                    devnode: devnode.clone(),
                    count: *count,
                    limit: *limit,
                },
            });
        }
        Ok(vec![self.device.clone()])
    }

    fn mount(&self, _dev: &UsbDevice) -> Result<MountSession<Self::Ops>, MountError> {
        if let Some(e) = &self.mount_error {
            return Err(match e {
                MountError::UnsupportedFs(s) => MountError::UnsupportedFs(s.clone()),
                MountError::MountpointInvalid(p) => MountError::MountpointInvalid(p.clone()),
                MountError::UnsupportedPlatform => MountError::UnsupportedPlatform,
                _ => MountError::UnsupportedFs("(replay)".into()),
            });
        }
        let guard = MountGuard::adopt(Arc::new(NoopMountOps), self.mountpoint.clone());
        Ok(MountSession {
            mountpoint: self.mountpoint.clone(),
            guard,
        })
    }
}

/// Build the user-facing diagnostic shown when the .p12 PIN-retry loop
/// is exhausted (MAC verify failure).
///
/// Tries to read the leaf cert from the .p12 without a password — newer
/// issuance tooling embeds the cert in an unencrypted `SafeBag` so this
/// path succeeds and we can tell the engineer which host and which user
/// the cert was issued for, which is the actionable information for a
/// "wrong flash" mix-up. When the cert is also encrypted (legacy bundles)
/// we degrade gracefully to a generic password-wrong message.
/// Step 10 user authorisation, shared by the PKCS#12 and PKCS#11 paths.
///
/// The cert-driven path (`pam_cert_user_binding` extension present and
/// well-formed) takes precedence over the legacy `[[user_mapping]]`
/// TOML; only certs *without* the extension fall through to the legacy
/// mapping. An extension that is present but malformed (or empty) fails
/// closed: silently routing such a cert through the legacy mapping
/// would let a certificate that was meant to restrict users
/// authenticate via a stale TOML entry instead.
// Role selection (the `user+role` suffix, PAM_USER canonicalisation, store
// resolve + allowed-roles coverage) runs separately in `resolve_role_stage`,
// invoked after cert verification; this function only handles the legacy
// user↔cert authorisation (user_binding extension or `[[user_mapping]]`).
fn authorize_user(
    cert: &Certificate,
    pam_user: &str,
    user_mappings: &[tessera_core::config::validated::UserMapping],
) -> Result<(), FlowError> {
    use tessera_core::x509::user_binding_ext::UserBindingExtError;
    match tessera_core::x509::user_binding_ext::parse(cert.x509()) {
        Ok(_) => verify_user_binding(cert.x509(), pam_user)?,
        Err(UserBindingExtError::Missing) => {
            let _matched: MatchedMapping = match_user(cert, pam_user, user_mappings)?;
        }
        Err(e) => {
            tracing::warn!(
                target: "tessera.flow",
                event = "user_binding_unparseable",
                error = %e,
                pam_user = %pam_user,
                cert_serial = %cert.serial_hex().to_lowercase(),
                "pam_cert_user_binding present but unparseable; failing closed \
                 (legacy mapping fallback is not allowed for broken extensions)"
            );
            return Err(FlowError::CertScope(e.into()));
        }
    }
    Ok(())
}

/// Atomic resolve + coverage stage (role-format, tasks 4.3/4.4).
///
/// Runs **after** the cert chain is verified and **before** the session
/// payload is fixed, in one uninterrupted step (polkit CVE-2021-3560
/// lesson): the requested role is resolved from the store, checked for
/// membership in the cert's `allowed_roles` extension, and — when allowed —
/// snapshotted into a [`SessionRolePayload`] with a bounded TTL and a
/// backend-availability gate.
///
/// Returns:
/// - `Ok(None)` — enforcement disabled, or warn-mode with no usable role:
///   behave as before (no role attached to the session).
/// - `Ok(Some(payload))` — role resolved, covered, and enforceable.
/// - `Err(FlowError::RoleDenied)` — `require` mode and the role was denied.
///
/// `cert_ttl` is `notAfter - now` (saturating); `None` means the cert has no
/// usable expiry, in which case the global default bounds the session.
fn resolve_role_stage(
    verified_leaf: &tessera_core::x509::VerifiedX509,
    stage: &RoleStage<'_>,
    user: &str,
    cert_ttl: Option<std::time::Duration>,
) -> Result<Option<tessera_core::role::SessionRolePayload>, FlowError> {
    use tessera_core::role::{
        self, resolve_and_cover, CoverageMethod, Resolution, RoleDenyReason, RoleEnforce,
        SessionRolePayload,
    };

    if stage.enforce == RoleEnforce::Disabled {
        return Ok(None);
    }
    // Enforcement on but no store loaded → fail-closed under `require`
    // ("roles not configured"), benign skip under `warn`.
    let Some(store) = stage.store else {
        return match stage.enforce {
            RoleEnforce::Require => {
                role::audit::emit_role_deny(
                    user,
                    stage.requested.as_ref().map_or("", role::RoleId::as_str),
                    RoleDenyReason::NotFound.as_str(),
                );
                Err(FlowError::RoleDenied(RoleDenyReason::NotFound))
            }
            _ => Ok(None),
        };
    };

    // Extract the cert's allowed_roles extension (fail-closed on malformed).
    let allowed: Option<Vec<role::RoleId>> =
        match tessera_core::x509::allowed_roles_ext::extract_allowed_roles(verified_leaf) {
            Ok(roles) => roles,
            Err(e) => {
                // A malformed extension is fail-closed: treat as "no roles"
                // so coverage fails. Emit the stable role.audit event (keyed by
                // cert subject) and a tessera.flow warn for the operator.
                let subject = cert_subject(verified_leaf);
                role::audit::emit_cert_allowed_roles_parse_failed(&subject);
                tracing::warn!(
                    target: "tessera.flow",
                    error = %e,
                    pam_user = %user,
                    subject = %subject,
                    "pam_cert_allowed_roles malformed; treating as no roles (fail-closed)"
                );
                Some(Vec::new())
            }
        };

    let resolution = resolve_and_cover(
        store,
        stage.requested.as_ref(),
        allowed.as_deref(),
        stage.enforce,
        user,
    );

    let (slice, method) = match resolution {
        Resolution::Skipped => return Ok(None),
        Resolution::Denied { reason } => return Err(FlowError::RoleDenied(reason)),
        Resolution::Allowed { slice, method } => (slice, method),
    };

    // Fix the session payload: snapshot + bounded TTL + backend gate.
    let payload: SessionRolePayload =
        match SessionRolePayload::fix(&slice, cert_ttl, stage.default_session_ttl) {
            Ok(p) => p,
            Err(fix_err) => {
                let reason = fix_err.deny_reason();
                // Backend unavailable is an explicit deny in both warn and
                // require: silently narrowing privileges is forbidden by the
                // spec. Under warn we still proceed without the role.
                role::audit::emit_role_deny(user, slice.role.as_str(), reason.as_str());
                return match stage.enforce {
                    RoleEnforce::Require => Err(FlowError::RoleDenied(reason)),
                    _ => Ok(None),
                };
            }
        };

    // Success: emit role_session_open with the bounded TTL.
    let method_str = match method {
        CoverageMethod::Cert => "cert",
        CoverageMethod::Code => "code",
    };
    role::audit::emit_role_session_open(
        user,
        payload.role.as_str(),
        payload.role_version,
        method_str,
        payload.ttl.as_secs(),
    );
    Ok(Some(payload))
}

/// Live delegation-envelope enforcement (tags-delegation §4, wired in §5).
///
/// Runs AFTER trust verification and role resolution on BOTH auth paths. For
/// every CA in the verified chain carrying `pam_cert_delegation_constraints`,
/// [`tessera_core::trust::enforce_delegation_opt`] checks
/// `device.tags ⊇ requireTags`, role ∈ `allowRoles`, level ≤ `maxLevel`, and
/// link TTL ≤ parent `maxTtl` (AND/MIN across all links). A chain carrying NO
/// constraints is a no-op (prior per-host semantics preserved).
///
/// Inputs:
/// * `verified` — the stage-2 verified chain (full `[leaf]++mids++[anchor]`).
/// * `device_tags` — this device's trusted, applied tag set.
/// * `role` — the resolved session role (`None` when role enforcement is off);
///   an envelope-scoped chain with no role rejects fail-closed.
/// * `cert_max_integrity` — the leaf `max_integrity` label, if present. Its
///   `level` is BOTH the requested integrity level (the level the session
///   assumes) and the leaf ceiling.
/// * `verified_leaf` — used to extract the leaf `allowed_roles` list.
///
/// On `Err`, emits the `delegation_denied` audit event with the culprit serial,
/// the violated check, and a device-tags snapshot, then returns
/// [`FlowError::DelegationDenied`]. The caller surfaces only a GENERIC message
/// to the engineer (envelope structure is not leaked pre-auth).
///
/// # Errors
///
/// [`FlowError::DelegationDenied`] on any envelope/ceiling violation.
fn enforce_delegation_stage(
    verified: &tessera_core::trust::Stage2VerifiedChain,
    device_tags: &DeviceTags,
    role: Option<&tessera_core::role::SessionRolePayload>,
    cert_max_integrity: Option<tessera_core::mac::IntegrityLabel>,
    verified_leaf: &tessera_core::x509::VerifiedX509,
) -> Result<(), FlowError> {
    let chain = verified.full_chain();

    // Whether this chain is envelope-scoped (any CA carries
    // delegation_constraints). A malformed/mis-placed extension is itself
    // fail-closed here. For a non-envelope (per-host) chain the delegation
    // ceilings do not apply, so a malformed *non-critical* leaf max_integrity
    // is tolerated exactly as before; for an envelope-scoped chain it must
    // fail closed (the leaf level is a security ceiling input — see below).
    let scoped = match tessera_core::trust::chain_carries_constraints(&chain) {
        Ok(s) => s,
        Err(err) => {
            let culprit_serial = chain.get(err.culprit_index()).map_or_else(
                || verified.end_entity.serial_hex().to_lowercase(),
                |c| c.serial_hex().to_lowercase(),
            );
            tessera_core::trust::delegation_audit::emit_delegation_denied(
                &culprit_serial,
                &err,
                device_tags,
            );
            return Err(FlowError::DelegationDenied(err));
        }
    };

    // Requested role = the resolved session role (if any).
    let requested_role = role.map(|r| &r.role);

    // Requested integrity level = the leaf's max_integrity level (the level the
    // session assumes); leaf ceiling = the same value. Absent extension =
    // baseline 0 with no leaf level ceiling.
    //
    // A leaf max_integrity that was present-but-malformed reaches here as
    // `None` (the caller's MAC parse failed). Because the leaf level is a
    // security ceiling input to the CA `maxLevel` checks, treating a malformed
    // ceiling as "baseline 0, no leaf cap" would be fail-OPEN under an
    // envelope. So when the chain is envelope-scoped and the leaf carries a
    // malformed max_integrity, reject fail-closed.
    if scoped
        && cert_max_integrity.is_none()
        && tessera_core::x509::max_integrity_ext::extract_max_integrity(verified_leaf).is_err()
    {
        // Present-but-malformed leaf max_integrity under an envelope: the leaf
        // level is a ceiling input, so a malformed value must reject rather
        // than degrade to baseline 0 (which would be fail-open). A genuinely
        // absent extension (`Ok(None)`) is fine — no leaf ceiling.
        let err = tessera_core::trust::DelegationError::LevelCeiling {
            requested: i8::MAX,
            ceiling: 0,
            scope: "leaf max_integrity malformed (fail-closed)".to_owned(),
        };
        tessera_core::trust::delegation_audit::emit_delegation_denied(
            &verified.end_entity.serial_hex().to_lowercase(),
            &err,
            device_tags,
        );
        return Err(FlowError::DelegationDenied(err));
    }

    let requested_level = cert_max_integrity.map_or(0, |l| l.level);
    let leaf_max_integrity_level = cert_max_integrity.map(|l| l.level);

    // Leaf allowed-roles (fail-closed on malformed → empty list grants none).
    let leaf_allowed: Option<Vec<tessera_core::role::RoleId>> =
        match tessera_core::x509::allowed_roles_ext::extract_allowed_roles(verified_leaf) {
            Ok(roles) => roles,
            Err(_) => Some(Vec::new()),
        };

    if let Err(err) = tessera_core::trust::enforce_delegation_opt(
        &chain,
        device_tags,
        requested_role,
        requested_level,
        leaf_max_integrity_level,
        leaf_allowed.as_deref(),
    ) {
        // Resolve the culprit serial from the offending chain index. Fall back
        // to the leaf serial if the index is somehow out of range.
        let culprit_serial = chain.get(err.culprit_index()).map_or_else(
            || verified.end_entity.serial_hex().to_lowercase(),
            |c| c.serial_hex().to_lowercase(),
        );
        tessera_core::trust::delegation_audit::emit_delegation_denied(
            &culprit_serial,
            &err,
            device_tags,
        );
        return Err(FlowError::DelegationDenied(err));
    }
    Ok(())
}

/// Build a stable subject identifier for a verified leaf, used as the
/// `subject` field of the `cert_allowed_roles_parse_failed` audit event.
/// Combines the subject CN and serial so the offending cert is identifiable
/// without logging the raw extension bytes.
fn cert_subject(verified_leaf: &tessera_core::x509::VerifiedX509) -> String {
    let ident = tessera_core::x509::CertIdent::from(verified_leaf);
    format!("CN={} serial={}", ident.cn, ident.serial.to_lowercase())
}

/// Compute the certificate's remaining lifetime as a TTL (`notAfter - now`),
/// saturating to zero. Returns `None` when `notAfter` is absent.
fn cert_remaining_ttl(cert_not_after: Option<SystemTime>) -> Option<std::time::Duration> {
    let not_after = cert_not_after?;
    Some(
        not_after
            .duration_since(SystemTime::now())
            .unwrap_or(std::time::Duration::ZERO),
    )
}

/// Absolute wall-clock instant at which a bounded role session must end.
///
/// The deadline is the earliest of the role/default TTL measured from the
/// authentication instant (`authenticated_at + role.ttl`) and the
/// certificate's own `notAfter`. Anchoring the role/default component at
/// `authenticated_at` and then clamping against `notAfter` is what guarantees
/// the enforced deadline can never outlive the certificate — even though the
/// daemon records its own `opened_at` a moment later and the role TTL was
/// itself derived from a cert-remaining value sampled slightly earlier still.
/// Because the daemon schedules termination directly against this absolute
/// instant (no re-anchoring), the drift that a relative TTL would introduce is
/// eliminated.
///
/// Returns `None` when the session has no role (hence no time ceiling). A role
/// TTL so large that `authenticated_at + ttl` overflows the clock falls back to
/// the certificate's `notAfter`, or to `None` when the certificate is
/// non-expiring — never a panic.
fn session_expiry(
    role: Option<&tessera_core::role::SessionRolePayload>,
    authenticated_at: SystemTime,
    cert_not_after: Option<SystemTime>,
) -> Option<SystemTime> {
    let ttl = role?.ttl;
    let role_deadline = authenticated_at.checked_add(ttl);
    match (role_deadline, cert_not_after) {
        (Some(rd), Some(na)) => Some(rd.min(na)),
        (Some(rd), None) => Some(rd),
        (None, Some(na)) => Some(na),
        (None, None) => None,
    }
}

fn p12_wrong_pin_diagnostic(p12_bytes: &[u8]) -> String {
    let Some(cert) = tessera_core::pkcs12::try_extract_cert_without_pin(p12_bytes) else {
        return "Пароль .p12 неверный. Проверьте флешку и попробуйте ещё раз.".to_string();
    };
    let host = match tessera_core::x509::host_binding_ext::parse(cert.x509()) {
        Ok(entries) => entries
            .iter()
            .map(|e| match e {
                tessera_core::x509::host_binding_ext::HostDescriptor::Wildcard => "*".to_string(),
                tessera_core::x509::host_binding_ext::HostDescriptor::Sha256Hex(h) => {
                    format!("sha256:{h}")
                }
                tessera_core::x509::host_binding_ext::HostDescriptor::Raw(r) => r.clone(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        Err(_) => "<не указан>".to_string(),
    };
    let user = match tessera_core::x509::user_binding_ext::parse(cert.x509()) {
        Ok(entries) => entries
            .iter()
            .map(|e| match e {
                tessera_core::x509::user_binding_ext::UserDescriptor::Wildcard => "*".to_string(),
                tessera_core::x509::user_binding_ext::UserDescriptor::Exact(u) => u.clone(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        Err(_) => "<не указан>".to_string(),
    };
    format!(
        "Пароль .p12 неверный.\n\
         Этот сертификат выпущен для:\n\
           host_id_hash: {host}\n\
           пользователь: {user}\n\
         Проверьте, что вставлена нужная флешка."
    )
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::err_expect,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::duration_suboptimal_units
)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tessera_core::config::validated::{UserMapping, UserMatchCriteria};
    use tessera_core::host_identity::HostIdSourceKind;
    use tessera_core::ipc::{FailModeWrapper, MonitorFailMode, StubClient};
    use tessera_core::trust::openssl_verifier::{OpensslVerifier, OpensslVerifierConfig};

    /// Loads a fixture under `crates/tessera_core/tests/fixtures/`.
    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tessera_core/tests/fixtures")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    fn stage_p12_mount(p12_name: &str, with_chain: bool) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let certs_dir = tmp.path().join("certs");
        std::fs::create_dir(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("user.p12"), fixture_bytes(p12_name)).unwrap();
        if with_chain {
            std::fs::write(certs_dir.join("chain.pem"), fixture_bytes("int.pem")).unwrap();
        }
        tmp
    }

    fn build_verifier() -> OpensslVerifier {
        let ca = Certificate::from_pem(&fixture_bytes("ca.pem")).unwrap();
        let int_ = Certificate::from_pem(&fixture_bytes("int.pem")).unwrap();
        OpensslVerifier::new(OpensslVerifierConfig {
            anchors: vec![ca],
            intermediates: vec![int_],
            crl_pems: vec![],
            crl_strict: false,
            crl_max_age: None,
            max_supported_profile_version:
                tessera_core::trust::openssl_verifier::DEFAULT_MAX_SUPPORTED_PROFILE_VERSION,
            clock_skew: Duration::from_secs(60),
            signature_alg_whitelist: vec![
                "sha256WithRSAEncryption".into(),
                "ecdsa-with-SHA256".into(),
            ],
            spki_pins: vec![],
            max_depth: 4,
            gost_engine_path: None,
            revocation_mode: tessera_core::config::validated::RevocationMode::None,
            ocsp_responder_url: None,
            ocsp_timeout: Duration::from_secs(5),
            ocsp_cache_dir: std::path::PathBuf::from("/var/cache/tessera/ocsp"),
            ocsp_cache_ttl: Duration::ZERO,
        })
        .unwrap()
    }

    fn cn_mapping(user: &str, cn: &str) -> UserMapping {
        UserMapping {
            pam_user: user.to_string(),
            criteria: UserMatchCriteria::SubjectCn(cn.to_string()),
        }
    }

    /// Path to a real PEM fixture usable as a `[trust].anchors` entry —
    /// config validation rejects empty anchor lists.
    fn anchor_path_toml() -> String {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tessera_core/tests/fixtures/ca.pem");
        format!("{:?}", path.to_string_lossy())
    }

    fn minimal_cfg() -> ValidatedConfig {
        // Build via toml + try_from to avoid restating every default in code.
        let raw_toml = r#"
crypto_backend = "openssl"
mode = "pkcs12"
pkcs12_path_pattern = "certs/user.p12"
pkcs12_pin_prompt = "PIN: "
usb_wait_seconds = 5
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 30
monitor_fail_mode = "permissive"

[trust]
anchors = [@ANCHOR@]
intermediates = []
allowed_signature_algorithms = []
max_chain_depth = 4
clock_skew_seconds = 60

[trust.revocation]
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[host_identity]
sources = ["override"]
fallback = "deny"
override = "host-T"
custom_command_timeout_seconds = 5

[logging]
level = "info"
"#;
        let raw_toml = raw_toml.replace("@ANCHOR@", &anchor_path_toml());
        let raw: tessera_core::config::raw::RawConfig = toml::from_str(&raw_toml).unwrap();
        ValidatedConfig::try_from(&raw).unwrap()
    }

    #[test]
    fn happy_path_rsa() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let leaf = Certificate::from_pem(&fixture_bytes("leaf_rsa.pem")).unwrap();
        let serial = leaf.serial_hex().to_lowercase();

        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let outcome = authenticate(deps, &io, "alice", "ssh", "sess-1".into(), |_| {
            Ok(SecretString::from("correct-pin".to_string()))
        })
        .expect("happy path");
        assert_eq!(outcome.auth_ctx.cert_cn.as_deref(), Some("alice"));
        assert_eq!(
            outcome.auth_ctx.cert_serial.as_deref(),
            Some(serial.as_str())
        );
        assert!(outcome.auth_ctx.cert_not_after.is_some());
    }

    #[test]
    fn happy_path_ecdsa() {
        let tmp = stage_p12_mount("leaf_ecdsa.p12", false);
        let leaf = Certificate::from_pem(&fixture_bytes("leaf_ecdsa.pem")).unwrap();
        let serial = leaf.serial_hex().to_lowercase();

        let verifier = build_verifier();
        let cfg = minimal_cfg();
        let mappings = vec![cn_mapping("bob", "bob")];

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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let outcome = authenticate(deps, &io, "bob", "ssh", "sess-2".into(), |_| {
            Ok(SecretString::from("correct-pin".to_string()))
        })
        .expect("happy path ecdsa");
        assert_eq!(outcome.auth_ctx.cert_cn.as_deref(), Some("bob"));
        assert_eq!(
            outcome.auth_ctx.cert_serial.as_deref(),
            Some(serial.as_str())
        );
    }

    #[test]
    fn wrong_pin_three_times_returns_max_tries() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg();
        let leaf = Certificate::from_pem(&fixture_bytes("leaf_rsa.pem")).unwrap();
        let _serial = leaf.serial_hex().to_lowercase();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let attempts = std::cell::Cell::new(0_u32);
        let err = authenticate(deps, &io, "alice", "ssh", "sess-3".into(), |_| {
            attempts.set(attempts.get() + 1);
            Ok(SecretString::from("badpin".to_string()))
        })
        .unwrap_err();
        assert!(matches!(err, FlowError::MaxTries));
        assert_eq!(attempts.get(), 3);
        assert_eq!(err.pam_code(), 8); // PAM_MAXTRIES
    }

    #[test]
    fn missing_p12_returns_authinfo_unavail() {
        let tmp = tempfile::tempdir().unwrap();
        // Note: certs/ directory not created.
        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };
        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let err = authenticate(deps, &io, "alice", "ssh", "sess-4".into(), |_| {
            Ok(SecretString::from("correct-pin".to_string()))
        })
        .unwrap_err();
        assert!(matches!(
            err,
            FlowError::Discovery(DiscoveryError::P12NotFound { .. })
        ));
        assert_eq!(err.pam_code(), 9); // PAM_AUTHINFO_UNAVAIL
    }

    #[test]
    fn subject_mismatch_is_perm_denied() {
        let tmp = stage_p12_mount("leaf_no_user_binding.p12", false);
        let leaf = Certificate::from_pem(&fixture_bytes("leaf_no_user_binding.pem")).unwrap();
        let _serial = leaf.serial_hex().to_lowercase();

        let verifier = build_verifier();
        let cfg = minimal_cfg();
        // mapping says alice's CN should be "ghost" — does not match
        let mappings = vec![cn_mapping("alice", "ghost")];

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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };
        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let err = authenticate(deps, &io, "alice", "ssh", "sess-5".into(), |_| {
            Ok(SecretString::from("correct-pin".to_string()))
        })
        .unwrap_err();
        assert!(matches!(err, FlowError::Mapping(_)));
        assert_eq!(err.pam_code(), 6); // PAM_PERM_DENIED
    }

    // Cert host/user binding scope is exhaustively tested in
    // `tessera_core::host_binding::tests`; we don't re-test the
    // matrix end-to-end here because every fixture cert has `["*"]` for
    // both extensions (max-permissive). The `authorize_user` dispatch
    // (cert path vs legacy mapping vs fail-closed) is unit-tested below
    // with locally built certs.

    /// Builds a self-signed cert whose `pam_cert_user_binding` extension
    /// carries `der_value` verbatim (possibly garbage DER).
    fn cert_with_user_binding_ext(der_value: &[u8]) -> Certificate {
        use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509Extension, X509Name};

        let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut nb = X509Name::builder().unwrap();
        nb.append_entry_by_text("CN", "alice").unwrap();
        let name = nb.build();

        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let serial = {
            let mut bn = BigNum::new().unwrap();
            bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
                .unwrap();
            Asn1Integer::from_bn(&bn).unwrap()
        };
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&pkey).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let oid = Asn1Object::from_str(tessera_core::x509::oids::USER_BINDING_OID).unwrap();
        let octet = Asn1OctetString::new_from_bytes(der_value).unwrap();
        b.append_extension(X509Extension::new_from_der(&oid, false, &octet).unwrap())
            .unwrap();
        b.sign(&pkey, MessageDigest::sha256()).unwrap();
        Certificate::from_der(&b.build().to_der().unwrap()).unwrap()
    }

    #[test]
    fn malformed_user_binding_fails_closed() {
        // 0x04 0x00 is an OCTET STRING, not the `SEQUENCE OF UTF8String`
        // the extension requires → parse() yields Malformed, not Missing.
        let cert = cert_with_user_binding_ext(&[0x04, 0x00]);
        // A legacy mapping that WOULD authorise alice — it must NOT be
        // consulted when the extension is present but broken.
        let mappings = vec![cn_mapping("alice", "alice")];
        let err = authorize_user(&cert, "alice", &mappings).unwrap_err();
        assert!(
            matches!(
                err,
                FlowError::CertScope(HostBindingError::UserExtensionMalformed(_))
            ),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 7); // PAM_AUTH_ERR — denied, no fallback
    }

    #[test]
    fn empty_user_binding_fails_closed() {
        // Well-formed but empty SEQUENCE — present yet authorises nobody;
        // must not fall back to the legacy mapping either.
        let cert = cert_with_user_binding_ext(&[0x30, 0x00]);
        let mappings = vec![cn_mapping("alice", "alice")];
        let err = authorize_user(&cert, "alice", &mappings).unwrap_err();
        assert!(
            matches!(
                err,
                FlowError::CertScope(HostBindingError::UserExtensionMalformed(_))
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn valid_user_binding_wins_over_legacy_mapping() {
        // SEQUENCE { UTF8String "alice" }
        let cert =
            cert_with_user_binding_ext(&[0x30, 0x07, 0x0C, 0x05, b'a', b'l', b'i', b'c', b'e']);
        // No mappings at all: the cert path must authorise alice on its own.
        authorize_user(&cert, "alice", &[]).expect("alice allowed by cert");
        // ...and deny bob even though a mapping would have allowed him.
        let mappings = vec![cn_mapping("bob", "alice")];
        let err = authorize_user(&cert, "bob", &mappings).unwrap_err();
        assert!(
            matches!(
                err,
                FlowError::CertScope(HostBindingError::UserNotAllowed { .. })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn pkcs12_pin_prompt_from_config_reaches_prompter() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg(); // sets pkcs12_pin_prompt = "PIN: "
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let seen = std::cell::RefCell::new(Vec::new());
        authenticate(deps, &io, "alice", "ssh", "sess-prompt".into(), |p| {
            seen.borrow_mut().push(p.to_string());
            Ok(SecretString::from("correct-pin".to_string()))
        })
        .expect("happy path with custom prompt");
        assert_eq!(seen.borrow().as_slice(), ["PIN: "]);
    }

    // -----------------------------------------------------------------
    // PKCS#11 dispatch tests (T13)
    //
    // We can't synthesize a real `Pkcs11Session`, so the stub returns an
    // `AcquireError` from `acquire_session`.  That's enough to assert the
    // dispatcher routes to the PKCS#11 path and propagates errors through
    // the right `FlowError` variants.
    // -----------------------------------------------------------------

    use tessera_core::token::pkcs11::{
        AcquireError as P11Acquire, Pkcs11Error, Pkcs11Session, Slot,
    };

    fn pkcs11_native_cfg() -> ValidatedConfig {
        let raw_toml = r#"
crypto_backend = "pkcs11_native"
mode = "pkcs11"
pkcs11_module = "/nonexistent/dummy.so"
pkcs11_token_label = "Test Token"
pkcs11_max_pin_attempts = 2
pkcs11_locking_mode = "os"
usb_wait_seconds = 1
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 30
monitor_fail_mode = "permissive"

[trust]
anchors = [@ANCHOR@]
intermediates = []
allowed_signature_algorithms = []
max_chain_depth = 4
clock_skew_seconds = 60

[trust.revocation]
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[host_identity]
sources = ["override"]
fallback = "deny"
override = "host-T"
custom_command_timeout_seconds = 5

[logging]
level = "info"
"#;
        let raw_toml = raw_toml.replace("@ANCHOR@", &anchor_path_toml());
        let raw: tessera_core::config::raw::RawConfig = toml::from_str(&raw_toml).unwrap();
        ValidatedConfig::try_from(&raw).unwrap()
    }

    fn pkcs11_openssl_cfg() -> ValidatedConfig {
        let mut cfg = pkcs11_native_cfg();
        cfg.crypto_backend = tessera_core::config::validated::CryptoBackend::Openssl;
        cfg
    }

    /// Stub [`Pkcs11Io`] used in the dispatch tests.  Every method
    /// returns a scripted error.
    #[allow(clippy::struct_field_names)]
    struct StubPkcs11Io {
        on_wait: std::cell::RefCell<Option<Result<Slot, Pkcs11Error>>>,
        on_serial: std::cell::RefCell<Option<Result<String, Pkcs11Error>>>,
        on_acquire: std::cell::RefCell<Option<Result<Pkcs11Session, P11Acquire>>>,
    }

    impl StubPkcs11Io {
        fn new() -> Self {
            Self {
                on_wait: std::cell::RefCell::new(None),
                on_serial: std::cell::RefCell::new(None),
                on_acquire: std::cell::RefCell::new(None),
            }
        }
        fn slot() -> Slot {
            Slot::try_from(0_u64).unwrap()
        }
    }

    impl Pkcs11Io for StubPkcs11Io {
        fn wait_for_token(&self) -> Result<Slot, Pkcs11Error> {
            self.on_wait
                .borrow_mut()
                .take()
                .unwrap_or_else(|| Ok(Self::slot()))
        }
        fn read_token_serial(&self, _slot: Slot) -> Result<String, Pkcs11Error> {
            self.on_serial
                .borrow_mut()
                .take()
                .unwrap_or_else(|| Ok("FAKE-SERIAL".into()))
        }
        fn acquire_session(
            &self,
            _slot: Slot,
            _pin_prompter: &mut PinPrompterFn<'_>,
        ) -> Result<Pkcs11Session, P11Acquire> {
            self.on_acquire
                .borrow_mut()
                .take()
                .unwrap_or_else(|| Err(P11Acquire::MaxAttemptsExceeded))
        }
    }

    /// Build a no-op `InMemoryFlowIo` purely to satisfy the generic
    /// signature of [`authenticate`] when we know the dispatcher will
    /// never touch it (the PKCS#11 branch builds its own `Pkcs11Io`).
    fn dummy_flow_io() -> InMemoryFlowIo {
        InMemoryFlowIo::new(std::path::PathBuf::from("/tmp/never-used"))
    }

    #[test]
    fn dispatcher_routes_pkcs11_openssl_to_not_implemented() {
        let cfg = pkcs11_openssl_cfg();
        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };
        let io = dummy_flow_io();
        let err = authenticate(deps, &io, "alice", "ssh", "sess-p11-1".into(), |_| {
            Ok(SecretString::from("any"))
        })
        .err()
        .expect("must fail");
        assert!(matches!(err, FlowError::Pkcs11OpensslEngineNotImplemented));
        assert_eq!(err.pam_code(), 9); // PAM_AUTHINFO_UNAVAIL
    }

    #[test]
    fn dispatcher_routes_pkcs11_native_with_missing_module_to_pkcs11_error() {
        // `pkcs11_native_cfg()` references `/nonexistent/dummy.so`; the
        // dispatcher tries to load it and surfaces `Pkcs11(ModulePathMissing)`.
        let cfg = pkcs11_native_cfg();
        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };
        let io = dummy_flow_io();
        let err = authenticate(deps, &io, "alice", "ssh", "sess-p11-2".into(), |_| {
            Ok(SecretString::from("any"))
        })
        .err()
        .expect("must fail");
        assert!(
            matches!(err, FlowError::Pkcs11(Pkcs11Error::ModulePathMissing(_))),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 9);
    }

    #[test]
    fn pkcs11_path_propagates_acquire_max_attempts_as_max_tries() {
        let cfg = pkcs11_native_cfg();
        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        // We exercise `authenticate_pkcs11` directly with the stub, since
        // the dispatcher's `RealPkcs11Io` would need a real provider.
        let stub = StubPkcs11Io::new();
        // Default behaviour: wait_for_token Ok, read_serial Ok, acquire MaxAttemptsExceeded.
        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            "alice",
            "ssh",
            "sess-p11-3".into(),
            |_| Ok(SecretString::from("badpin")),
        )
        .err()
        .expect("must fail");
        assert!(
            matches!(
                err,
                FlowError::Pkcs11Acquire(P11Acquire::MaxAttemptsExceeded)
            ),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 8); // PAM_MAXTRIES
    }

    #[test]
    fn pkcs11_path_propagates_token_wait_timeout_as_authinfo_unavail() {
        let cfg = pkcs11_native_cfg();
        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let stub = StubPkcs11Io::new();
        *stub.on_wait.borrow_mut() = Some(Err(Pkcs11Error::TokenWaitTimeout { seconds: 1 }));

        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            "alice",
            "ssh",
            "sess-p11-4".into(),
            |_| Ok(SecretString::from("any")),
        )
        .err()
        .expect("must fail");
        assert!(
            matches!(err, FlowError::Pkcs11(Pkcs11Error::TokenWaitTimeout { .. })),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 9); // PAM_AUTHINFO_UNAVAIL
    }

    #[test]
    fn pkcs11_path_propagates_serial_missing_after_wait_ok() {
        let cfg = pkcs11_native_cfg();
        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let stub = StubPkcs11Io::new();
        *stub.on_serial.borrow_mut() = Some(Err(Pkcs11Error::TokenSerialMissing));

        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            "alice",
            "ssh",
            "sess-p11-5".into(),
            |_| Ok(SecretString::from("any")),
        )
        .err()
        .expect("must fail");
        assert!(
            matches!(err, FlowError::Pkcs11(Pkcs11Error::TokenSerialMissing)),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 9);
    }

    // -----------------------------------------------------------------
    // Stage 5: hook executor wiring tests
    //
    // The flow now invokes pre_auth (before USB) and post_auth_success
    // (after cert verification) hooks via a `&dyn HookExecutor`.  The
    // tests below confirm:
    //
    // 1. A successful executor lets the flow continue.
    // 2. A pre_auth Abort failure short-circuits to `PreAuthHook` BEFORE
    //    the USB device is touched (so the in-memory IO would not even
    //    have to be staged).
    // 3. A post_auth_success Warn failure does not abort (matches the
    //    on_failure=warn semantics from `apply_on_failure`).
    // 4. The PKCS#11 path also calls the same hook stages.
    // -----------------------------------------------------------------

    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tessera_core::hooks::{
        HookConfig as Stage5HookConfig, HookOutcome, HookStage as Stage5HookStage, OnFailure, RunAs,
    };

    /// Mock executor used by the Stage 5 wiring tests.
    struct MockExec {
        scripted:
            Mutex<std::collections::VecDeque<Result<HookOutcome, tessera_core::hooks::HookError>>>,
        calls: Mutex<Vec<(Stage5HookStage, Vec<String>)>>,
    }
    impl MockExec {
        fn new(scripted: Vec<Result<HookOutcome, tessera_core::hooks::HookError>>) -> Self {
            Self {
                scripted: Mutex::new(scripted.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<(Stage5HookStage, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl tessera_core::hooks::HookExecutor for MockExec {
        fn execute(
            &self,
            hook: &Stage5HookConfig,
            _vars: &tessera_core::hooks::HookVars,
        ) -> Result<HookOutcome, tessera_core::hooks::HookError> {
            self.calls
                .lock()
                .unwrap()
                .push((hook.stage, hook.command.clone()));
            self.scripted
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Ok(HookOutcome {
                        stage: hook.stage,
                        command: hook.command.clone(),
                        exit_code: 0,
                        killed_by_timeout: false,
                        duration: std::time::Duration::ZERO,
                        stdout_lines: 0,
                        stderr_lines: 0,
                    })
                })
        }
    }

    fn dummy_stage5_hook(stage: Stage5HookStage, on_failure: OnFailure) -> Stage5HookConfig {
        Stage5HookConfig {
            stage,
            command: vec![format!("/hook/{stage:?}").to_lowercase()],
            timeout: std::time::Duration::from_secs(5),
            on_failure,
            run_as: RunAs::Root,
            env: BTreeMap::<String, tessera_core::hooks::Template>::new(),
        }
    }

    fn nonzero_outcome(stage: Stage5HookStage, code: i32) -> HookOutcome {
        HookOutcome {
            stage,
            command: vec!["/x".into()],
            exit_code: code,
            killed_by_timeout: false,
            duration: std::time::Duration::from_millis(1),
            stdout_lines: 0,
            stderr_lines: 0,
        }
    }

    #[test]
    fn pkcs12_calls_pre_auth_and_post_auth_hooks_on_happy_path() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let leaf = Certificate::from_pem(&fixture_bytes("leaf_rsa.pem")).unwrap();
        let _serial = leaf.serial_hex().to_lowercase();

        let verifier = build_verifier();
        let mut cfg = minimal_cfg();
        cfg.hooks = vec![
            dummy_stage5_hook(Stage5HookStage::PreAuth, OnFailure::Abort),
            dummy_stage5_hook(Stage5HookStage::PostAuthSuccess, OnFailure::Abort),
        ];
        let mappings = vec![cn_mapping("alice", "alice")];

        let monitor = StubClient;
        let exec = MockExec::new(Vec::new());
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            user_mappings: &mappings,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        authenticate(deps, &io, "alice", "ssh", "sess-h1".into(), |_| {
            Ok(SecretString::from("correct-pin"))
        })
        .expect("happy path with hooks");

        let calls = exec.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, Stage5HookStage::PreAuth);
        assert_eq!(calls[1].0, Stage5HookStage::PostAuthSuccess);
    }

    #[test]
    fn pkcs12_pre_auth_abort_short_circuits_with_preauthhook_error() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let mut cfg = minimal_cfg();
        cfg.hooks = vec![dummy_stage5_hook(
            Stage5HookStage::PreAuth,
            OnFailure::Abort,
        )];
        let mappings = vec![cn_mapping("alice", "alice")];

        let monitor = StubClient;
        let exec = MockExec::new(vec![Ok(nonzero_outcome(Stage5HookStage::PreAuth, 7))]);
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            user_mappings: &mappings,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let err = authenticate(deps, &io, "alice", "ssh", "sess-h2".into(), |_| {
            Ok(SecretString::from("correct-pin"))
        })
        .unwrap_err();
        assert!(matches!(err, FlowError::PreAuthHook(_)), "got {err:?}");
        assert_eq!(err.pam_code(), 7); // PAM_AUTH_ERR
                                       // Only the pre_auth hook ran; post-auth was never reached.
        let calls = exec.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Stage5HookStage::PreAuth);
    }

    #[test]
    fn pkcs12_post_auth_warn_does_not_block_success() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let leaf = Certificate::from_pem(&fixture_bytes("leaf_rsa.pem")).unwrap();
        let _serial = leaf.serial_hex().to_lowercase();

        let verifier = build_verifier();
        let mut cfg = minimal_cfg();
        cfg.hooks = vec![dummy_stage5_hook(
            Stage5HookStage::PostAuthSuccess,
            OnFailure::Warn,
        )];
        let mappings = vec![cn_mapping("alice", "alice")];

        let monitor = StubClient;
        let exec = MockExec::new(vec![Ok(nonzero_outcome(
            Stage5HookStage::PostAuthSuccess,
            42,
        ))]);
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            user_mappings: &mappings,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let outcome = authenticate(deps, &io, "alice", "ssh", "sess-h3".into(), |_| {
            Ok(SecretString::from("correct-pin"))
        })
        .expect("warn must not abort");
        assert_eq!(outcome.auth_ctx.cert_cn.as_deref(), Some("alice"));
        // Hook was indeed invoked.
        let calls = exec.calls();
        assert!(calls
            .iter()
            .any(|c| c.0 == Stage5HookStage::PostAuthSuccess));
    }

    #[test]
    fn pkcs11_pre_auth_abort_short_circuits_before_token_wait() {
        // A PreAuth Abort must fire before `wait_for_token` is called,
        // so the stub's wait result is irrelevant.
        let mut cfg = pkcs11_native_cfg();
        cfg.hooks = vec![dummy_stage5_hook(
            Stage5HookStage::PreAuth,
            OnFailure::Abort,
        )];

        let verifier = build_verifier();
        let mappings = vec![cn_mapping("alice", "alice")];
        let monitor = StubClient;
        let exec = MockExec::new(vec![Ok(nonzero_outcome(Stage5HookStage::PreAuth, 1))]);
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            user_mappings: &mappings,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let stub = StubPkcs11Io::new();
        // If pre_auth ran AFTER wait_for_token we'd hit MaxAttemptsExceeded.
        // Asserting PreAuthHook proves the hook ran first.
        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            "alice",
            "ssh",
            "sess-h4".into(),
            |_| Ok(SecretString::from("any")),
        )
        .unwrap_err();
        assert!(matches!(err, FlowError::PreAuthHook(_)), "got {err:?}");
    }

    // -----------------------------------------------------------------
    // Multi-partition USB iteration with PKCS#12 ASN.1-envelope fallback
    // (regression test for the 0.3.5 bugfix: Apple-formatted USB with a
    // foreign file at the expected path was breaking auth instead of
    // probing the next partition).
    // -----------------------------------------------------------------

    /// A test-only [`MountOps`] that counts umount/rmdir calls so the
    /// multi-partition tests can verify the previous partition was
    /// torn down before moving on.
    #[derive(Debug, Default)]
    struct CountingMountOps {
        umount_calls: std::sync::atomic::AtomicUsize,
        rmdir_calls: std::sync::atomic::AtomicUsize,
    }

    impl MountOps for CountingMountOps {
        fn mount(
            &self,
            _source: &Path,
            _target: &Path,
            _fs_type: &str,
            _flags: tessera_core::mount_guard::MountFlags,
            _data: Option<&str>,
        ) -> Result<(), tessera_core::error::MountGuardError> {
            Ok(())
        }
        fn umount(&self, _target: &Path) -> Result<(), tessera_core::error::MountGuardError> {
            self.umount_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn mkdir_mode_0700(
            &self,
            _path: &Path,
        ) -> Result<(), tessera_core::error::MountGuardError> {
            Ok(())
        }
        fn rmdir(&self, _path: &Path) -> Result<(), tessera_core::error::MountGuardError> {
            self.rmdir_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// `FlowIo` that returns a configurable list of `(UsbDevice, mountpoint)`
    /// pairs.  Each partition has its own mountpoint already pre-staged
    /// (the test populates `certs/user.p12` ahead of time).  Mounts go
    /// through a shared [`CountingMountOps`] so the test can verify
    /// failed partitions were unmounted before the next one was tried.
    struct MultiPartFlowIo {
        partitions: Vec<(UsbDevice, PathBuf)>,
        ops: Arc<CountingMountOps>,
        // Per-partition mount-call counter (used as index into `partitions`).
        mount_idx: std::cell::Cell<usize>,
    }

    impl MultiPartFlowIo {
        fn new(partitions: Vec<(UsbDevice, PathBuf)>) -> Self {
            Self {
                partitions,
                ops: Arc::new(CountingMountOps::default()),
                mount_idx: std::cell::Cell::new(0),
            }
        }
    }

    impl FlowIo for MultiPartFlowIo {
        type Ops = CountingMountOps;

        fn wait_for_usb(&self) -> Result<Vec<UsbDevice>, UsbError> {
            Ok(self.partitions.iter().map(|(d, _)| d.clone()).collect())
        }

        fn mount(&self, _dev: &UsbDevice) -> Result<MountSession<Self::Ops>, MountError> {
            let i = self.mount_idx.get();
            self.mount_idx.set(i + 1);
            let mp = self.partitions[i].1.clone();
            let guard = MountGuard::adopt(self.ops.clone(), mp.clone());
            Ok(MountSession {
                mountpoint: mp,
                guard,
            })
        }
    }

    fn synth_dev(devnode: &str) -> UsbDevice {
        UsbDevice {
            devnode: PathBuf::from(devnode),
            serial: Some("MULTI".into()),
            vid: 0x1234,
            pid: 0x5678,
            fs_type: Some("vfat".into()),
        }
    }

    /// Stage a directory that contains a `certs/user.p12` whose bytes
    /// are not a valid PKCS#12 envelope (the "Apple plist with a
    /// colliding name" case from the bug report).
    fn stage_junk_mount() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let certs_dir = tmp.path().join("certs");
        std::fs::create_dir(&certs_dir).unwrap();
        // Bytes that look like an Apple binary plist — definitely not
        // an ASN.1 SEQUENCE.
        let mut blob = Vec::from(&b"bplist00\xDE\xAD\xBE\xEF"[..]);
        blob.extend(std::iter::repeat_n(0xA5_u8, 256));
        std::fs::write(certs_dir.join("user.p12"), &blob).unwrap();
        tmp
    }

    #[test]
    fn falls_back_to_next_partition_on_p12_asn1_envelope_failure() {
        // Partition 0: junk file at the expected path (ASN.1 parse fails).
        // Partition 1: real PKCS#12 bundle — must be picked up.
        let junk_tmp = stage_junk_mount();
        let good_tmp = stage_p12_mount("leaf_rsa.p12", false);

        let partitions = vec![
            (synth_dev("/dev/sdz1"), junk_tmp.path().to_path_buf()),
            (synth_dev("/dev/sdz2"), good_tmp.path().to_path_buf()),
        ];
        let io = MultiPartFlowIo::new(partitions);
        let ops = io.ops.clone();

        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let outcome = authenticate(deps, &io, "alice", "ssh", "sess-fb1".into(), |_| {
            Ok(SecretString::from("correct-pin"))
        })
        .expect("must fall back to partition 2 and authenticate");

        assert_eq!(outcome.auth_ctx.cert_cn.as_deref(), Some("alice"));

        // Partition 1 (junk) must have been unmounted before we moved
        // on.  Partition 2 (good) stays mounted in the FlowOutcome.
        let umounts = ops.umount_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            umounts, 1,
            "expected exactly one umount (the junk partition); got {umounts}"
        );
        // rmdir fires from the MountGuard drop, paired with umount —
        // junk partition was torn down completely, not just unmounted.
        let rmdirs = ops.rmdir_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            rmdirs, 1,
            "expected exactly one rmdir (the junk partition); got {rmdirs}"
        );
    }

    #[test]
    fn returns_p12_envelope_error_when_all_partitions_are_junk() {
        // Both partitions have a file at the expected path but neither
        // is a real PKCS#12 — auth must surface FlowError::P12Envelope
        // (not Discovery::P12NotFound, since the file *was* found).
        let junk1 = stage_junk_mount();
        let junk2 = stage_junk_mount();

        let partitions = vec![
            (synth_dev("/dev/sdz1"), junk1.path().to_path_buf()),
            (synth_dev("/dev/sdz2"), junk2.path().to_path_buf()),
        ];
        let io = MultiPartFlowIo::new(partitions);
        let ops = io.ops.clone();

        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let err = authenticate(deps, &io, "alice", "ssh", "sess-fb2".into(), |_| {
            Ok(SecretString::from("correct-pin"))
        })
        .unwrap_err();
        assert!(
            matches!(err, FlowError::P12Envelope(_)),
            "expected P12Envelope, got {err:?}"
        );
        // Maps to PAM_AUTHINFO_UNAVAIL (9) — same bucket as Discovery
        // failures (no usable credentials on the bus).
        assert_eq!(err.pam_code(), 9);

        // Both junk partitions must have been unmounted on their way out.
        let umounts = ops.umount_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(umounts, 2, "expected both junk partitions to umount");
        // rmdir fires from the MountGuard drop, paired with umount —
        // both junk partitions were torn down completely (no leaked
        // mountpoint dirs in tmpfs).
        let rmdirs = ops.rmdir_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(rmdirs, 2, "expected both junk partitions to rmdir");
    }

    /// `wait_for_usb` returning an empty list must NOT iterate / mount
    /// anything — it bubbles up as `Discovery::P12NotFound` (no usable
    /// credential on the bus). Lock-down test against a future regression
    /// where someone tries to "try anyway" on an empty device list.
    #[test]
    fn empty_usb_device_list_returns_p12_not_found() {
        struct EmptyUsbFlowIo {
            ops: Arc<CountingMountOps>,
        }
        impl FlowIo for EmptyUsbFlowIo {
            type Ops = CountingMountOps;
            fn wait_for_usb(&self) -> Result<Vec<UsbDevice>, UsbError> {
                Ok(Vec::new())
            }
            fn mount(&self, _dev: &UsbDevice) -> Result<MountSession<Self::Ops>, MountError> {
                panic!("mount() must not be called when wait_for_usb returned empty");
            }
        }

        let io = EmptyUsbFlowIo {
            ops: Arc::new(CountingMountOps::default()),
        };
        let ops = io.ops.clone();

        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let err = authenticate(deps, &io, "alice", "ssh", "sess-empty".into(), |_| {
            Ok(SecretString::from("any"))
        })
        .unwrap_err();
        assert!(
            matches!(err, FlowError::Discovery(_)),
            "expected Discovery error on empty USB list, got {err:?}"
        );
        // Nothing was mounted, so nothing should have been umount/rmdir'd.
        assert_eq!(
            ops.umount_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(ops.rmdir_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// Fail-closed invariant: a wrong PIN exhausts the per-partition
    /// retry loop and returns `FlowError::MaxTries` **without** falling
    /// back to the next USB partition. Multi-partition fallback is
    /// restricted to pre-password failures (ASN.1 envelope) so we never
    /// create a PIN oracle nor enable chain-probing across removable
    /// media. Locks the boundary against future regressions where
    /// someone adds `if pin_fail { try_next_partition() }`.
    #[test]
    fn wrong_pin_does_not_fall_back_to_next_partition() {
        // Two partitions, both with valid PKCS#12 bundles. We only
        // ever mount the first — the second exists to prove we did
        // NOT iterate to it on PIN failure.
        let part0 = stage_p12_mount("leaf_rsa.p12", false);
        let part1 = stage_p12_mount("leaf_rsa.p12", false);

        let partitions = vec![
            (synth_dev("/dev/sdz1"), part0.path().to_path_buf()),
            (synth_dev("/dev/sdz2"), part1.path().to_path_buf()),
        ];
        let io = MultiPartFlowIo::new(partitions);

        let verifier = build_verifier();
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let err = authenticate(deps, &io, "alice", "ssh", "sess-wpin".into(), |_| {
            Ok(SecretString::from("definitely-wrong-pin"))
        })
        .unwrap_err();
        assert!(
            matches!(err, FlowError::MaxTries),
            "wrong PIN must yield MaxTries, not partition fallback; got {err:?}"
        );
        // Only partition 0 was touched. mount_idx is the next index that
        // *would* be returned, i.e. the number of mount() calls so far.
        assert_eq!(
            io.mount_idx.get(),
            1,
            "PIN failure must NOT iterate to partition 1 (would be a PIN oracle)"
        );
    }

    // ---- role-format glue (tasks 4.3/4.4) --------------------------------

    #[test]
    fn role_stage_disabled_is_pre_role_default() {
        let stage = RoleStage::disabled();
        assert_eq!(stage.enforce, tessera_core::role::RoleEnforce::Disabled);
        assert!(stage.requested.is_none());
        assert!(stage.store.is_none());
        assert_eq!(
            stage.default_session_ttl,
            Duration::from_secs(tessera_core::config::validated::DEFAULT_ROLE_SESSION_TTL_SECONDS)
        );
    }

    #[test]
    fn cert_remaining_ttl_future_and_past() {
        // notAfter in the future → positive remaining TTL.
        let future = SystemTime::now() + Duration::from_secs(3600);
        let ttl = cert_remaining_ttl(Some(future)).expect("some");
        assert!(ttl > Duration::from_secs(3000) && ttl <= Duration::from_secs(3600));
        // notAfter in the past → saturates to zero.
        let past = SystemTime::UNIX_EPOCH;
        assert_eq!(cert_remaining_ttl(Some(past)), Some(Duration::ZERO));
        // No notAfter → None (global default bounds the session).
        assert_eq!(cert_remaining_ttl(None), None);
    }

    #[test]
    fn session_expiry_never_exceeds_cert_not_after_under_delay() {
        use tessera_core::role::{bounded_ttl, RoleId, SessionRolePayload};

        // Reference instant at which cert-remaining is sampled (the earlier
        // instant in the flow). The cert expires one hour later.
        let ttl_sampled_at = SystemTime::now();
        let not_after = ttl_sampled_at + Duration::from_secs(3600);

        // The role TTL folds in the cert-remaining sampled at `ttl_sampled_at`
        // together with a very large global default, so the certificate is the
        // binding constraint (as it is for a short-lived cert).
        let cert_ttl_at_sample = cert_remaining_ttl(Some(not_after));
        let ttl = bounded_ttl(cert_ttl_at_sample, None, Duration::from_secs(100_000));
        let payload = SessionRolePayload {
            role: RoleId::new("serv").expect("valid role id"),
            role_version: 1,
            ttl,
            mac_mask: None,
        };

        // `authenticated_at` lands LATER than the cert-ttl sample — the exact
        // drift the fix must absorb. A naive `authenticated_at + ttl` would push
        // the deadline past `not_after`; clamping must pin it to `not_after`.
        let authenticated_at = ttl_sampled_at + Duration::from_secs(30);
        let expiry = session_expiry(Some(&payload), authenticated_at, Some(not_after))
            .expect("role session has an expiry");

        assert!(
            expiry <= not_after,
            "enforced deadline {expiry:?} must not exceed cert notAfter {not_after:?}"
        );
        assert_eq!(
            expiry, not_after,
            "when the cert binds, the deadline must equal notAfter exactly"
        );
    }

    #[test]
    fn session_expiry_uses_role_deadline_when_shorter_than_cert() {
        use tessera_core::role::{bounded_ttl, RoleId, SessionRolePayload};

        // Cert valid for an hour, but the role/default TTL is only 10 minutes,
        // so the role component binds and the deadline sits before notAfter.
        let authenticated_at = SystemTime::now();
        let not_after = authenticated_at + Duration::from_secs(3600);
        let ttl = bounded_ttl(
            cert_remaining_ttl(Some(not_after)),
            Some(Duration::from_secs(600)),
            Duration::from_secs(100_000),
        );
        let payload = SessionRolePayload {
            role: RoleId::new("serv").expect("valid role id"),
            role_version: 1,
            ttl,
            mac_mask: None,
        };

        let expiry = session_expiry(Some(&payload), authenticated_at, Some(not_after))
            .expect("role session has an expiry");
        assert_eq!(expiry, authenticated_at + Duration::from_secs(600));
        assert!(expiry < not_after);
    }

    #[test]
    fn session_expiry_is_none_without_role() {
        let authenticated_at = SystemTime::now();
        let not_after = authenticated_at + Duration::from_secs(3600);
        assert_eq!(
            session_expiry(None, authenticated_at, Some(not_after)),
            None
        );
    }

    #[test]
    fn role_denied_maps_to_perm_denied() {
        let err = FlowError::RoleDenied(tessera_core::role::RoleDenyReason::NotCovered);
        assert_eq!(err.pam_code(), 6); // PAM_PERM_DENIED
    }

    // -----------------------------------------------------------------
    // Strict monitor-registration fail-closed (continuous-presence
    // enforcement).
    //
    // A cert-authenticated session that monitord never records is a
    // session whose token / USB removal can never trigger the configured
    // lock or logout. Under `monitor_fail_mode = "strict"` a registration
    // failure must therefore deny the login; under `permissive` the
    // `FailModeWrapper` absorbs transport errors and the login proceeds.
    // -----------------------------------------------------------------

    /// [`MonitorClient`] whose `open_session` always fails with a transport
    /// error (`monitord unavailable`). That error is *not* one of the
    /// verdict-changing kinds (`DeviceGone` / `Unauthorized`), so the
    /// `FailModeWrapper` propagates it only in strict mode — exactly the
    /// distinction under test. All other methods succeed.
    struct FailingMonitor;

    impl MonitorClient for FailingMonitor {
        fn hello(&self) -> Result<(), tessera_core::error::IpcError> {
            Ok(())
        }
        fn open_session(
            &self,
            _info: &OpenSessionInfo<'_>,
        ) -> Result<(), tessera_core::error::IpcError> {
            Err(tessera_core::error::IpcError::Unavailable)
        }
        fn close_session(
            &self,
            _session_id: &str,
            _reason: &str,
        ) -> Result<(), tessera_core::error::IpcError> {
            Ok(())
        }
        fn ping(&self) -> Result<(), tessera_core::error::IpcError> {
            Ok(())
        }
    }

    #[test]
    fn pkcs12_strict_monitor_failure_denies_auth() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg();
        let mappings = vec![cn_mapping("alice", "alice")];

        // Strict fail mode: a monitord that cannot record the session must
        // turn the otherwise-successful cert auth into a definitive denial.
        let monitor = FailModeWrapper::new(FailingMonitor, MonitorFailMode::Strict);
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let err = authenticate(deps, &io, "alice", "ssh", "sess-mon-strict".into(), |_| {
            Ok(SecretString::from("correct-pin".to_string()))
        })
        .expect_err("strict monitor failure must deny auth");
        assert!(
            matches!(err, FlowError::MonitorRegistration(_)),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 6); // PAM_PERM_DENIED
    }

    #[test]
    fn pkcs12_permissive_monitor_failure_succeeds() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg();
        let mappings = vec![cn_mapping("alice", "alice")];

        // Permissive fail mode: the wrapper converts the transport error to
        // Ok(()) before the flow ever sees it, so auth still succeeds.
        let monitor = FailModeWrapper::new(FailingMonitor, MonitorFailMode::Permissive);
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
            role_stage: RoleStage::disabled(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let outcome = authenticate(deps, &io, "alice", "ssh", "sess-mon-perm".into(), |_| {
            Ok(SecretString::from("correct-pin".to_string()))
        })
        .expect("permissive monitor failure must not block auth");
        assert_eq!(outcome.auth_ctx.cert_cn.as_deref(), Some("alice"));
    }

    /// Minimal [`OpenSessionInfo`] for exercising the registration
    /// chokepoint directly.
    fn sample_open_session_info(session_id: &str) -> OpenSessionInfo<'_> {
        OpenSessionInfo {
            session_id,
            pam_user: "alice",
            pam_service: "ssh",
            host_id_hash: "host-T-hash",
            target: tessera_proto::SessionTarget::Unknown,
            usb_serial: Some("TOKEN-SERIAL"),
            cert_cn: "alice",
            cert_serial: "00",
            engineer_ski: "",
            engineer_cert_sha256: "",
            uid: 1000,
            role: None,
            role_version: None,
            session_expiry: None,
        }
    }

    #[test]
    fn pkcs11_strict_monitor_registration_denies() {
        // The PKCS#11 success path ends by registering the session with
        // monitord through the same `register_session_or_deny` chokepoint the
        // PKCS#12 path uses. A full `authenticate_pkcs11` cannot run without a
        // live token (a `Pkcs11Session` is not synthesizable), so we drive that
        // final registration step directly under strict fail mode.
        let monitor = FailModeWrapper::new(FailingMonitor, MonitorFailMode::Strict);
        let info = sample_open_session_info("sess-p11-strict");
        let err = register_session_or_deny(&monitor, &info)
            .expect_err("strict monitor failure must deny the pkcs11 session");
        assert!(
            matches!(err, FlowError::MonitorRegistration(_)),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 6); // PAM_PERM_DENIED
    }

    #[test]
    fn pkcs11_permissive_monitor_registration_absorbed() {
        // Under permissive fail mode the wrapper absorbs the transport error,
        // so the PKCS#11 registration step (and thus the login) succeeds.
        let monitor = FailModeWrapper::new(FailingMonitor, MonitorFailMode::Permissive);
        let info = sample_open_session_info("sess-p11-perm");
        register_session_or_deny(&monitor, &info)
            .expect("permissive monitor failure must not block the pkcs11 session");
    }
}

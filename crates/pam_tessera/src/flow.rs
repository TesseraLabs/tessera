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
use tessera_core::config::validated::Pkcs12Source;
use tessera_core::config::ValidatedConfig;
use tessera_core::discovery::{discover_credentials, DiscoveredCreds, DiscoveryError};
use tessera_core::hooks::{run_hooks_for_stage, HookError, HookExecutor, HookStage, HookVars};
use tessera_core::host_binding::{verify_host_binding, HostBindingError};
use tessera_core::host_identity::HostIdSourceKind;
use tessera_core::ipc::{MonitorClient, OpenSessionInfo};
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

    /// The carrier produced no syntactically valid PKCS#12 envelope.
    ///
    /// Distinct from [`Self::Discovery`] (no file at the expected path)
    /// and from [`Self::Pkcs12`] (file is a valid envelope but PIN /
    /// chain rejected): this is the "found something with the right name,
    /// but it is not actually a PKCS#12 bundle" case. On the USB carrier we
    /// already burned every partition trying to find one; on a token carrier
    /// it is the single named data object that turned out not to be one.
    #[error("invalid PKCS#12 envelope: {0}")]
    P12Envelope(#[from] P12EnvelopeError),

    /// The authenticating USB device exposes no stable descriptor serial,
    /// so the daemon could never match a removal event against the session.
    ///
    /// Continuous-presence enforcement keys sessions by the USB serial; a
    /// device with `serial = None` would authenticate but stay permanently
    /// invisible to removal enforcement (fail-open loss of the presence
    /// guarantee). Under strict monitoring we refuse it fail-closed,
    /// mirroring the PKCS#11 path's `TokenSerialMissing`. Permissive
    /// monitoring is the documented escape hatch (see [`authenticate_pkcs12`]).
    #[error("usb device exposes no stable serial; cannot enforce continuous presence")]
    UsbSerialMissing,

    /// More than one connected token satisfies the configured selection, so
    /// which one carries the credential is not determined.
    ///
    /// Taking the first would let a second token an engineer happens to have
    /// plugged in — a personal one, a CA token — stand in for the carrier, and
    /// the session would then be bound to that device's presence. Naming a
    /// token in `pkcs11_token_label` resolves it; so does unplugging the
    /// other one.
    #[error(
        "{count} connected tokens match the configured selection; set pkcs11_token_label to \
         name the carrier"
    )]
    TokenCarrierAmbiguous {
        /// How many tokens matched.
        count: usize,
    },

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

    /// Cert scope (host binding extension) rejected the auth.
    #[error("cert scope: {0}")]
    CertScope(#[from] HostBindingError),

    /// A present `MAX_INTEGRITY` certificate extension was malformed.
    ///
    /// Treating this as absence would let optional MAC policy apply a broader
    /// fallback ceiling. Both credential backends therefore reject it before
    /// role/delegation/session policy.
    #[error("malformed MAX_INTEGRITY certificate extension: {0}")]
    MaxIntegrityMalformed(#[source] tessera_core::x509::max_integrity_ext::MaxIntegrityExtError),

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
    /// not found / not covered by the cert / needs an absent backend. Every
    /// login resolves a role and the check is unconditional — there is no
    /// configuration that turns it off or downgrades it to a warning.
    /// Carries the audit deny reason.
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
    /// | `UsbSerialMissing` / `TokenCarrierAmbiguous`           | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `Pkcs11` (module load / wait / serial / config)        | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `Pkcs11(DataObject*)` — carrier holds no usable envelope | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `Pkcs11OpensslEngineNotImplemented`                    | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `Pkcs11ModulePathMissingInConfig`                      | `PAM_AUTHINFO_UNAVAIL` (9) |
    /// | `MaxTries` / `Pkcs11Acquire(PinLocked|MaxAttempts)`    | `PAM_MAXTRIES` (11)        |
    /// | `Conv` / `Pkcs11Acquire(Conv)` / `Pkcs11(PinIncorrect)`| `PAM_AUTH_ERR` (7)         |
    /// | `CertScope`                                            | `PAM_AUTH_ERR` (7)         |
    /// | `MaxIntegrityMalformed`                                | `PAM_PERM_DENIED` (6)      |
    /// | `Pkcs12` / `Crypto` / `Trust`                          | `PAM_PERM_DENIED` (6)      |
    /// | `MonitorRegistration`                                  | `PAM_PERM_DENIED` (6)      |
    /// | `Pkcs11(ExtractableKeyRejected)`                       | `PAM_AUTH_ERR` (7)         |
    /// | `Pkcs11(ExtractableAttributeUnavailable)`              | `PAM_AUTH_ERR` (7)         |
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
            | Self::UsbSerialMissing
            | Self::TokenCarrierAmbiguous { .. }
            | Self::Pkcs11OpensslEngineNotImplemented
            | Self::Pkcs11ModulePathMissingInConfig
            | Self::Pkcs11(
                Pkcs11Error::ModuleLoadFailed { .. }
                | Pkcs11Error::InitFailed { .. }
                | Pkcs11Error::ModulePathMissing(_)
                | Pkcs11Error::TokenWaitTimeout { .. }
                | Pkcs11Error::NoTokenAvailable
                | Pkcs11Error::TokenNotFound { .. }
                | Pkcs11Error::TokenSerialMissing
                // The carrier did not yield a usable credential. The USB
                // carrier answers the same situations with 9 — no `.p12` at
                // the expected path is `Discovery`, a file that is not a
                // container is `P12Envelope` — and a stack configured with
                // `authinfo_unavail=ignore` would otherwise fall back to a
                // password on one carrier and refuse the login outright on
                // the other, for the same mistake at issuance.
                | Pkcs11Error::DataObjectNotFound { .. }
                | Pkcs11Error::DataObjectUnreadable { .. }
                | Pkcs11Error::DataObjectNotPrivate { .. }
                | Pkcs11Error::DataObjectAmbiguous { .. },
            ) => 9,
            // PAM_MAXTRIES — exhausted PIN-retry budget on either path.
            // 11 per `<security/_pam_types.h>`; 8 is PAM_CRED_INSUFFICIENT,
            // which tells the application the wrong story ("cannot reach the
            // authentication data" instead of "stop asking, the budget is
            // spent").
            Self::MaxTries
            | Self::Pkcs11Acquire(P11Acquire::PinLocked | P11Acquire::MaxAttemptsExceeded) => 11,
            // PAM_PERM_DENIED — cert chain rejected the auth, the requested
            // role was denied (not found / not covered / needs an absent
            // backend) — the role check is unconditional, no config relaxes
            // it — or a strict-mode monitord registration failure denied a
            // session that could not be placed under continuous-presence
            // enforcement.
            Self::Pkcs12(_)
            | Self::Crypto(_)
            | Self::Trust(_)
            | Self::MaxIntegrityMalformed(_)
            | Self::RoleDenied(_)
            | Self::DelegationDenied(_)
            | Self::MonitorRegistration(_) => 6,
            // PAM_SYSTEM_ERR — internal invariants.
            Self::Internal(_) => 4,
            // PAM_AUTH_ERR — every other authentication-side failure
            // (PAM conv, single PIN error, generic PKCS#11 error, cert
            // host-binding scope, ...).
            //
            // Hook failures land here too. A hook error only survives to
            // this point under `on_failure = abort` (`warn` / `ignore`
            // swallow it), so it is a site-policy refusal of the attempt —
            // not a verdict on what the certificate is authorised for
            // (PAM_PERM_DENIED) and not a broken internal invariant
            // (PAM_SYSTEM_ERR). It therefore shares the generic
            // authentication-failure code with the arms above.
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

    /// Read the PKCS#12 envelope out of a data object on a PKCS#11 token.
    ///
    /// Only reached when `pkcs12_source = "token_object"`. The default impl
    /// loads the configured provider and talks to a real token; tests
    /// override it to serve a canned envelope.
    ///
    /// # Errors
    ///
    /// Propagates whatever [`read_token_carrier_with`] returns, plus
    /// [`FlowError::Pkcs11ModulePathMissingInConfig`] when no provider is
    /// configured (configuration validation normally catches that first).
    fn read_token_carrier(
        &self,
        cfg: &ValidatedConfig,
        object_label: &str,
        prompt_pin: &mut PinPrompterFn<'_>,
    ) -> Result<TokenCarrier, FlowError> {
        let io = real_pkcs11_io(cfg)?;
        read_token_carrier_with(&io, cfg, object_label, prompt_pin)
    }
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
    /// Where the active session lives — passed to monitord on a successful
    /// authentication so the daemon knows which logind session, tty, or X
    /// display to act on. The cdylib derives this from `PAM_TTY`; tests
    /// that don't care can use [`tessera_proto::SessionTarget::Unknown`].
    pub pam_target: tessera_proto::SessionTarget,
    /// Role-selection stage. Carries the requested role (the login account
    /// name), the loaded role store, and the global default TTL. Every login
    /// carries a role — there is no configuration that disables the stage.
    pub role_stage: RoleStage<'a>,
    /// This device's trusted, applied tag set (tags-delegation §5). Loaded
    /// once per attempt from the configured `[tags]` source. When no source is
    /// configured (or `[tags].enforce = false`) this is an empty set, so any
    /// group-delegation `requireTags` envelope in the chain is unsatisfiable
    /// and rejects (fail-closed). Per-host chains without an envelope are
    /// unaffected.
    pub device_tags: &'a DeviceTags,
}

/// Inputs to the atomic resolve + coverage stage.
///
/// Built once per `pam_sm_authenticate` and threaded through [`Deps`].
///
/// The stage deliberately does **not** carry the requested role. The role is
/// the login account name, so it is derived inside the flow from the same
/// `pam_user` string every other step uses: a role that disagreed with
/// `PAM_USER` would be an escalation (polkit CVE-2021-3560 class), and the
/// cheapest way to guarantee it cannot happen is to leave no place to put it.
/// A store is mandatory — a login without one is rejected before the stage is
/// built, because coverage cannot be proven without it.
pub struct RoleStage<'a> {
    /// The on-device role store (already loaded by the cdylib).
    pub store: &'a tessera_core::role::RoleStore,
    /// Global default session TTL from `[roles].default_session_ttl`.
    pub default_session_ttl: std::time::Duration,
    /// How this stage decides whether a name is an account the system already
    /// owns: the device's account view, plus whatever verdicts that same view
    /// has already reached.
    ///
    /// It travels with the stage because the role and the login account are the
    /// same name, so "which accounts exist here" is an input to role selection
    /// like the store itself. The pairing of view and verdicts lives inside
    /// [`tessera_core::role::AccountCheck`], which is what keeps a load run
    /// against a view that knows no accounts from clearing a name the device
    /// itself refuses.
    pub accounts: tessera_core::role::AccountCheck<'a>,
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
    // A login account name that cannot be a role id at all is refused here,
    // before any credential material is touched — no PIN prompt, no USB mount,
    // no token session. The derived value is discarded: the resolve stage
    // re-derives it from the same `pam_user` string, so the two cannot
    // disagree, and no caller gets a chance to supply a different role.
    requested_role(pam_user)?;
    // An account the system already owns is refused just as early, and for the
    // same reason: the role is the account, so a login into `root` or any other
    // account below the regular-uid boundary would hand out privileges the role
    // model never issued. The refusal precedes the store entirely — what the
    // store holds and what the certificate allows never enter into it.
    ensure_role_account(pam_user, deps.role_stage.accounts)?;
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

    // Step 2 — get the envelope from the configured carrier. Everything
    // below this point is deliberately the same code for both carriers: the
    // choice is where the container comes from, not what is done with it.
    let carried = match &deps.cfg.pkcs12_source {
        Pkcs12Source::UsbPartition => usb_envelope(deps.cfg, io, pam_user)?,
        Pkcs12Source::TokenObject { object_label } => {
            token_envelope(deps.cfg, io, object_label, &mut |prompt| prompt_pin(prompt))?
        }
    };
    let CarriedEnvelope {
        p12_bytes,
        chain_pem,
        carrier_serial,
        usb_vid_pid,
        usb_devnode,
        mount,
        candidates_tried,
    } = carried;

    // Step 5 — PIN-retry loop.  When the operator configured
    // `pkcs12_pin_prompt` it replaces the default "Smart-card PIN: "
    // prompt, mirroring `pkcs11_pin_prompt` on the PKCS#11 path.
    let loaded: LoadedKeyMaterial = match acquire_p12_material_with_prompter(
        &p12_bytes,
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
            io.show_info(&p12_wrong_pin_diagnostic(&p12_bytes));
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
    if let Some(chain_pem) = chain_pem.as_deref() {
        presented.extend(parse_chain_pem(chain_pem)?);
    }

    // Step 8 — trust verification (path build, signatures, CRLs, pinning).
    let verified = deps.trust.verify(&loaded.end_entity, &presented)?;
    tracing::info!(
        target: "tessera.flow",
        devnode = ?usb_devnode,
        cert_subject = ?loaded.end_entity.subject_cn().ok(),
        cert_serial = %loaded.end_entity.serial_hex().to_lowercase(),
        "cert chain validated"
    );

    // Step 9 — cert scope (cert authorises this host).
    //
    // `pam_cert_host_binding` is mandatory: the cert MUST authorise the
    // running host. The other axis — which account may be entered — is the
    // role coverage check in Step 10b, since the account name IS the role.
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

    // Step 11 — assemble AuthContext.
    let cert_cn = loaded.end_entity.subject_cn().ok();
    let cert_serial = Some(loaded.end_entity.serial_hex().to_lowercase());
    let cert_not_after = Some(loaded.end_entity.not_after());

    // MAC integrity inputs captured for `pam_sm_open_session`.
    let verified_leaf = verified.verified_leaf();
    let cert_ident_value = tessera_core::x509::CertIdent::from(&verified_leaf);
    let cert_max_integrity =
        extract_cert_max_integrity(&verified_leaf, pam_user, &cert_ident_value)?;
    let cert_ident = Some(cert_ident_value);
    let home_dir = resolve_home_dir(pam_user);

    // Step 10b — atomic role resolve + coverage (role-format). Runs right
    // after cert verification and before the session payload is fixed, with
    // no swap window (CVE-2021-3560). A denial always aborts here — the
    // stage has no advisory mode.
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
        &role,
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
        usb_serial: carrier_serial,
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
        role: Some(role),
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

    // Step 11c — notify monitord with the FULL post-auth payload (carrier
    // serial from the device that actually held the envelope, cert CN/serial
    // from the validated leaf, target from PAM_TTY). Under strict fail mode a
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
        usb_serial: auth_ctx.usb_serial.as_deref(),
        // Device-topology binding: the daemon uses VID/PID + devnode to
        // decide whether a later udev `add` is really the same physical
        // device before cancelling a pending removal action. The USB
        // descriptor serial alone is attacker-controlled and cloneable.
        // A token carrier has neither — it is not a USB block device — so
        // both stay `None` there and the serial is the only identifier.
        usb_vid_pid: auth_ctx.usb_vid_pid.as_deref(),
        usb_devnode: usb_devnode.as_deref().and_then(Path::to_str),
        // Which namespace the serial above lives in. The daemon cannot infer
        // it from its own configuration: a host switched from one carrier to
        // the other would judge sessions opened under the previous one in the
        // wrong namespace, where their serial matches nothing.
        carrier: match deps.cfg.pkcs12_source {
            Pkcs12Source::UsbPartition => tessera_proto::CarrierKind::UsbPartition,
            Pkcs12Source::TokenObject { .. } => tessera_proto::CarrierKind::Token,
        },
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

    Ok(FlowOutcome { auth_ctx, mount })
}

/// The PKCS#12 envelope together with whatever identifies the medium that
/// carried it.
///
/// The carrier identity is not decoration: `carrier_serial` is the field the
/// daemon keys removal enforcement on, so a carrier that produced no
/// identifier leaves a session nothing can match a removal event against.
struct CarriedEnvelope<O: MountOps + 'static> {
    /// The envelope bytes, exactly as the carrier held them.
    p12_bytes: Vec<u8>,
    /// Intermediates found beside the envelope, when the carrier had a place
    /// to put them. A token object holds the envelope and nothing else.
    chain_pem: Option<Vec<u8>>,
    /// Identifier of the medium: the USB descriptor serial, or the token
    /// serial when the envelope came off a token.
    carrier_serial: Option<String>,
    /// USB VID/PID, absent for a token — it is not a USB block device.
    usb_vid_pid: Option<String>,
    /// USB devnode, absent for a token for the same reason.
    usb_devnode: Option<PathBuf>,
    /// Live mount guard, absent for a token: nothing was mounted.
    mount: Option<MountGuard<O>>,
    /// How many USB partitions were inspected (0 for a token).
    candidates_tried: usize,
}

/// Read the envelope off a partition of a USB medium.
///
/// Steps 2 through 4b of [`authenticate_pkcs12`], moved here unchanged apart
/// from taking the config directly, so the carrier choice has one place to
/// branch and the checks after the envelope have one place to live.
#[allow(clippy::too_many_lines)]
fn usb_envelope<I: FlowIo>(
    cfg: &ValidatedConfig,
    io: &I,
    pam_user: &str,
) -> Result<CarriedEnvelope<I::Ops>, FlowError> {
    // Wait for one or more USB block devices.  On flashes with
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
    let pkcs12_pattern = cfg
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

    // Step 4b — continuous-presence precondition. The daemon keys removal
    // enforcement on the USB descriptor serial; a device that exposes none
    // authenticates but can never be matched by a removal event, silently
    // losing the continuous-presence guarantee (fail-open). Refuse it here
    // — before the PIN prompt — mirroring the PKCS#11 path, which requires
    // a non-empty token serial.
    //
    // The escape hatch is the monitor fail mode. `on_usb_removed` has no
    // non-enforcing variant (every value locks/logs-out/runs-hook/shuts-
    // down), so the meaningful "monitoring is best-effort" signal is
    // `fail_mode = permissive`: there the admin has accepted that presence
    // checks may not hold, so a serial-less device is allowed. Strict mode
    // (continuous presence is a hard requirement) denies it fail-closed.
    if dev.serial.is_none()
        && cfg.monitor.fail_mode == tessera_core::config::validated::MonitorFailMode::Strict
    {
        tracing::warn!(
            target: "tessera.flow",
            devnode = ?dev.devnode,
            vid = format!("{:04x}", dev.vid),
            pid = format!("{:04x}", dev.pid),
            "pkcs12 device exposes no stable USB serial; refusing auth under strict monitoring"
        );
        return Err(FlowError::UsbSerialMissing);
    }

    Ok(CarriedEnvelope {
        p12_bytes: creds.p12_bytes,
        chain_pem: creds.chain_pem,
        carrier_serial: dev.serial.clone(),
        usb_vid_pid: Some(format!("{:04x}:{:04x}", dev.vid, dev.pid)),
        usb_devnode: Some(dev.devnode.clone()),
        mount: Some(mount),
        candidates_tried,
    })
}

/// Read the envelope out of a data object on a PKCS#11 token.
///
/// No mass storage is involved: a CCID token has no filesystem, so nothing is
/// waited for on the USB bus and nothing is mounted.
///
/// The object is read through `read_private_data_object`, which refuses an
/// object stored without `CKA_PRIVATE`. The envelope holds a private key that
/// comes out with the container password, and a public data object is readable
/// off the token by anyone who holds it for a moment — that is a different
/// thing from a carrier, not a weaker one.
fn token_envelope<I: FlowIo>(
    cfg: &ValidatedConfig,
    io: &I,
    object_label: &str,
    prompt_pin: &mut PinPrompterFn<'_>,
) -> Result<CarriedEnvelope<I::Ops>, FlowError> {
    let carrier = io.read_token_carrier(cfg, object_label, prompt_pin)?;

    // The same pre-PIN ASN.1 check the USB carrier applies to a candidate
    // file. Nothing about the container password is touched by it, and
    // without it an object that is not a PKCS#12 bundle at all would spend
    // the engineer's three PIN attempts before saying so.
    validate_p12_envelope(&carrier.p12_bytes)?;

    tracing::info!(
        target: "tessera.flow",
        object_label,
        p12_bytes = carrier.p12_bytes.len(),
        "p12 envelope read from token data object (pre-PIN ASN.1 check ok)"
    );

    Ok(CarriedEnvelope {
        p12_bytes: carrier.p12_bytes,
        // A token object carries the envelope and nothing else; intermediates
        // for this carrier come from `[trust]`.
        chain_pem: None,
        // The serial the daemon keys removal enforcement on. `read_token_serial`
        // has already refused an empty one, so a session is never opened without
        // an identifier for the medium that carried the credential.
        carrier_serial: Some(carrier.token_serial),
        // Not a USB block device: there is no VID/PID and no devnode to bind
        // removal cancellation to.
        usb_vid_pid: None,
        usb_devnode: None,
        // Nothing was mounted.
        mount: None,
        candidates_tried: 0,
    })
}

/// The envelope as it came off a PKCS#11 token, with the identity of the
/// token that carried it.
pub struct TokenCarrier {
    /// `CKA_VALUE` of the data object, uninterpreted.
    pub p12_bytes: Vec<u8>,
    /// Trimmed `CK_TOKEN_INFO.serialNumber` of the token it came from.
    pub token_serial: String,
}

// Manual `Debug`: the bytes are a PKCS#12 container whose private key comes
// out with the container password, and this type is handled on the
// authentication path, where a `?carrier` in a log line would put it into the
// journal of `sshd` or the display manager.
impl std::fmt::Debug for TokenCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCarrier")
            .field("bytes", &self.p12_bytes.len())
            .field("token_serial", &self.token_serial)
            .finish()
    }
}

/// Read the carrier object off a token through the given PKCS#11 I/O.
///
/// The serial is read **before** the PIN prompt on purpose: a token that
/// reports none can never be matched by a removal event, and refusing it after
/// the engineer has typed a PIN would spend an attempt on a token that was
/// never going to be usable.
///
/// The session is dropped on every exit path, including the error ones —
/// `Pkcs11Session::Drop` runs `C_Logout` before `C_CloseSession`. That matters
/// here more than elsewhere: `fly-dm` serves every login of the machine's
/// uptime from one process, so a login left behind would hand the next person
/// at the console a token that is already authenticated.
///
/// # Errors
///
/// - [`FlowError::Pkcs11`] — module load, no token, or an empty token serial
///   ([`tessera_core::token::pkcs11::Pkcs11Error::TokenSerialMissing`]).
/// - [`FlowError::Pkcs11Acquire`] — the token PIN loop failed or ran out.
/// - [`FlowError::Pkcs11`] — the object is absent, ambiguous, unreadable, or
///   stored without `CKA_PRIVATE`.
pub fn read_token_carrier_with<T: Pkcs11Io>(
    io: &T,
    cfg: &ValidatedConfig,
    object_label: &str,
    prompt_pin: &mut PinPrompterFn<'_>,
) -> Result<TokenCarrier, FlowError> {
    // Waiting and choosing are separate questions. This call answers only the
    // first — whether a token the configuration could accept has turned up
    // yet — and its return value is deliberately discarded: the slot it hands
    // back is whichever the provider enumerated first, which is not an answer
    // to "which token carries the credential".
    io.wait_for_token()?;

    // That question is answered here, and the token that gets used is the one
    // this check passed. An engineer with a second token plugged in — their
    // own, a CA token, one left in the reader — must not have it stand in for
    // the carrier, and the session's presence would otherwise be bound to that
    // device.
    //
    // Refusing is the only honest answer. Trying each candidate in turn is
    // worse than picking one: reading a private object needs a login, so a
    // search would present the PIN to tokens that were never meant to receive
    // it and spend their on-device retry counters.
    let matching = io.matching_tokens()?;
    let slot = match matching.as_slice() {
        [only] => *only,
        [] => {
            // The token was there when the wait returned and is gone now.
            // Saying so beats carrying the stale slot into the PIN prompt and
            // surfacing the removal as whatever FFI error the provider
            // happens to raise on a dead handle.
            tracing::warn!(
                target: "tessera.flow",
                token_label = ?cfg.pkcs11_token_label,
                "the token disappeared between the wait and the carrier check"
            );
            return Err(FlowError::Pkcs11(
                tessera_core::token::pkcs11::Pkcs11Error::NoTokenAvailable,
            ));
        }
        several => {
            tracing::warn!(
                target: "tessera.flow",
                count = several.len(),
                token_label = ?cfg.pkcs11_token_label,
                "more than one connected token matches the configured selection; refusing to \
                 choose which one carries the credential"
            );
            return Err(FlowError::TokenCarrierAmbiguous {
                count: several.len(),
            });
        }
    };

    tracing::info!(
        target: "tessera.flow",
        ?slot,
        token_label = ?cfg.pkcs11_token_label,
        "token found for the pkcs12 carrier"
    );

    let token_serial = io.read_token_serial(slot)?;

    let prompt_override = cfg.pkcs11_pin_prompt.clone();
    let session = io.acquire_session(slot, &mut |default_prompt| {
        prompt_pin(prompt_override.as_deref().unwrap_or(default_prompt))
    })?;

    let p12_bytes = session.read_private_data_object(object_label)?;
    drop(session);

    Ok(TokenCarrier {
        p12_bytes,
        token_serial,
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

    /// Every slot whose token satisfies the configured `pkcs11_token_label`.
    ///
    /// The carrier path uses the count: with more than one candidate the
    /// configuration has not said which device holds the credential, and
    /// taking the first would decide it on the operator's behalf.
    ///
    /// # Errors
    ///
    /// Forwards any [`tessera_core::token::pkcs11::Pkcs11Error`].
    fn matching_tokens(
        &self,
    ) -> Result<Vec<tessera_core::token::pkcs11::Slot>, tessera_core::token::pkcs11::Pkcs11Error>;

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

    fn matching_tokens(
        &self,
    ) -> Result<Vec<tessera_core::token::pkcs11::Slot>, tessera_core::token::pkcs11::Pkcs11Error>
    {
        self.backend.find_slots(self.token_label.as_deref())
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
        pkcs11_challenge_response, select_mechanism, ExtractableKeyPolicy, FoundCertificate,
        FoundPrivateKey,
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

    // Step 6 — find the matching private key (paired by CKA_ID).  A key
    // that reports itself extractable, and a key whose token will not
    // report the attribute at all, are each rejected here unless the
    // operator opted into that specific case (mode-B invariant,
    // fail-closed).
    let key: FoundPrivateKey = session.find_private_key_for_cert(
        &cert,
        ExtractableKeyPolicy {
            allow_extractable: deps.cfg.pkcs11_allow_extractable_keys,
            allow_unreported: deps.cfg.pkcs11_allow_unreported_extractable,
        },
    )?;

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
    // `pam_cert_host_binding` is mandatory. Admission to the login account is
    // the role coverage check in Step 10b — the account name IS the role.
    verify_host_binding(cert.certificate.x509(), deps.host_id_hash)?;

    // Step 11 — assemble AuthContext.  The token serial replaces the
    // USB serial in this mode (monitord uses the same field).
    let cert_cn = cert.certificate.subject_cn().ok();
    let cert_serial = Some(cert.certificate.serial_hex().to_lowercase());
    let cert_not_after = Some(cert.certificate.not_after());
    let verified_leaf = verified.verified_leaf();
    let cert_ident_value = tessera_core::x509::CertIdent::from(&verified_leaf);
    let cert_max_integrity =
        extract_cert_max_integrity(&verified_leaf, pam_user, &cert_ident_value)?;
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
        &role,
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
        role: Some(role),
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
        // PKCS#11 tokens are not enumerated as USB block devices, so there
        // is no VID/PID or devnode to bind removal cancellation to; the
        // token serial in `usb_serial` is the only identifier available.
        usb_vid_pid: None,
        usb_devnode: None,
        carrier: tessera_proto::CarrierKind::Token,
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
#[cfg(unix)]
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

/// Resolve `pam_user` to a Unix uid — there is no passwd database off Unix,
/// so the caller gets the same value a failed lookup yields.
#[cfg(not(unix))]
fn resolve_uid(_pam_user: &str) -> u32 {
    0
}

/// Resolve `pam_user`'s `$HOME` via NSS.  Returns `None` when the user
/// is not in passwd or has no home set; the MAC orchestrator's
/// home-label advisory tolerates `None`.
#[cfg(unix)]
fn resolve_home_dir(pam_user: &str) -> Option<PathBuf> {
    match nix::unistd::User::from_name(pam_user) {
        Ok(Some(u)) => Some(u.dir),
        _ => None,
    }
}

/// Resolve the login account's home directory — there is no passwd database
/// off Unix, so the caller gets the same value a failed lookup yields.
#[cfg(not(unix))]
fn resolve_home_dir(_pam_user: &str) -> Option<PathBuf> {
    None
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
    /// Canned answer for the token carrier (one-shot). When absent the
    /// default trait method runs and tries to load a real provider.
    pub token_carrier: std::cell::RefCell<Option<Result<TokenCarrier, FlowError>>>,
    /// How many times the flow asked for USB devices. A carrier that is
    /// supposed to leave mass storage alone is only proven to do so by a
    /// counter that stayed at zero.
    pub usb_waits: std::cell::Cell<usize>,
    /// How many times the flow mounted something.
    pub mounts: std::cell::Cell<usize>,
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
            token_carrier: std::cell::RefCell::new(None),
            usb_waits: std::cell::Cell::new(0),
            mounts: std::cell::Cell::new(0),
        }
    }
}

impl FlowIo for InMemoryFlowIo {
    type Ops = NoopMountOps;

    fn read_token_carrier(
        &self,
        _cfg: &ValidatedConfig,
        _object_label: &str,
        _prompt_pin: &mut PinPrompterFn<'_>,
    ) -> Result<TokenCarrier, FlowError> {
        self.token_carrier
            .borrow_mut()
            .take()
            .unwrap_or(Err(FlowError::Internal(
                "no token carrier was staged for this test",
            )))
    }

    fn wait_for_usb(&self) -> Result<Vec<UsbDevice>, UsbError> {
        self.usb_waits.set(self.usb_waits.get() + 1);
        if let Some(e) = &self.usb_error {
            // UsbError doesn't implement Clone; rebuild the most useful variants.
            return Err(match e {
                UsbError::Timeout => UsbError::Timeout,
                UsbError::Udev(s) => UsbError::Udev(s.clone()),
                UsbError::UnsupportedPlatform => UsbError::UnsupportedPlatform,
                UsbError::MissingProperty(s) => UsbError::MissingProperty(s.clone()),
                UsbError::NoMatchingDevice => UsbError::NoMatchingDevice,
                UsbError::WaitCancelled => UsbError::WaitCancelled,
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
        self.mounts.set(self.mounts.get() + 1);
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
/// the cert names, which is the actionable information when one carrier has
/// been brought in place of another. When the cert is also encrypted (legacy
/// bundles) we degrade gracefully to a generic password-wrong message.
/// Derive the requested role from the login account name.
///
/// The account being logged into IS the role (`ssh oper@device`), so
/// `pam_user` is the single source. Every caller in this module goes through
/// here, which is what makes "requested role ≠ `PAM_USER`" unrepresentable
/// rather than merely checked.
///
/// # Errors
///
/// Returns [`FlowError::RoleDenied`] with [`RoleDenyReason::Syntax`] when the
/// name cannot be a role id. The `role_deny` audit event is emitted here so
/// the refusal is visible regardless of which caller triggered it.
fn requested_role(pam_user: &str) -> Result<tessera_core::role::RoleId, FlowError> {
    use tessera_core::role::RoleDenyReason;

    crate::role_selection::role_from_account(pam_user).map_err(|error| {
        tracing::warn!(
            target: "tessera.flow",
            error = %error,
            pam_user = %pam_user,
            "login account name is not a role; refused before any credential is touched"
        );
        tessera_core::role::audit::emit_role_deny(
            pam_user,
            pam_user,
            RoleDenyReason::Syntax.as_str(),
        );
        FlowError::RoleDenied(RoleDenyReason::Syntax)
    })
}

/// Refuse a login into an account that belongs to the system rather than to a
/// role.
///
/// The account being logged into IS the role, so an account the distribution
/// created for its own use (`root`, `daemon`, `mail`, …) would otherwise become
/// a role the moment a slice with that name appeared in the store. The verdict
/// comes from the uid the account carries on this device, so it does not depend
/// on guessing which names a distribution reserves.
///
/// The refusal is deliberately blind to the store: it happens before any
/// lookup, and its message says nothing about whether a slice with this name
/// exists — that fact is the oracle an early store-existence check would have
/// created, and the reason such a check was rejected.
///
/// Both refusals are equally final, but they are audited apart:
/// `system_account` means somebody tried to log into an account the system
/// owns, which is an attack signal worth alerting on, while
/// `backend_unavailable` means the local account database did not answer, which is a
/// device fault and will repeat for every login while it lasts. Merging them
/// would bury the first under the second on any device with a flaky name
/// service.
///
/// # Errors
///
/// Returns [`FlowError::RoleDenied`] with
/// [`tessera_core::role::RoleDenyReason::SystemAccount`] when the account is a
/// system account, and with
/// [`tessera_core::role::RoleDenyReason::BackendUnavailable`] when the passwd
/// database could not be consulted to establish otherwise (fail-closed).
fn ensure_role_account(
    pam_user: &str,
    accounts: tessera_core::role::AccountCheck<'_>,
) -> Result<(), FlowError> {
    use tessera_core::role::{RoleDenyReason, SystemAccountError};

    // Whether the verdict comes from the store's load or from a fresh lookup is
    // decided inside the check, which holds the view and that view's own
    // verdicts as one thing: a name the load already asked about is not paid
    // for twice, and a name it never saw is asked about in full.
    accounts.check(pam_user).map_err(|error| {
        let reason = match error {
            SystemAccountError::SystemAccount { .. }
            | SystemAccountError::SystemPrincipal { .. } => RoleDenyReason::SystemAccount,
            // `LookupFailed`, and — since `SystemAccountError` is
            // `non_exhaustive` — any future refusal this module has not been
            // taught about: still a denial, under the reason that claims the
            // least about why.
            _ => RoleDenyReason::BackendUnavailable,
        };
        tracing::warn!(
            target: "tessera.flow",
            error = %error,
            pam_user = %pam_user,
            reason = %reason,
            "login account is not a role account; refused before any credential is touched"
        );
        tessera_core::role::audit::emit_role_deny(pam_user, pam_user, reason.as_str());
        FlowError::RoleDenied(reason)
    })
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
/// Returns the fixed session payload, or `Err(FlowError::RoleDenied)` when the
/// role does not resolve, is not covered, or cannot be enforced. There is no
/// success path without a role.
///
/// `cert_ttl` is `notAfter - now` (saturating); `None` means the cert has no
/// usable expiry, in which case the global default bounds the session.
fn resolve_role_stage(
    verified_leaf: &tessera_core::x509::VerifiedX509,
    stage: &RoleStage<'_>,
    user: &str,
    cert_ttl: Option<std::time::Duration>,
) -> Result<tessera_core::role::SessionRolePayload, FlowError> {
    use tessera_core::role::{
        self, resolve_and_cover, CoverageMethod, Resolution, SessionRolePayload,
    };

    // The requested role is the login account name and nothing else. Deriving
    // it here — from the same string the whole flow was driven with — is what
    // keeps the resolved role and `PAM_USER` in lockstep.
    let requested = requested_role(user)?;

    // Repeated at the one stage both credential backends must pass through, so
    // the refusal does not depend on which entry point drove the flow. On the
    // normal path `authenticate` has already refused such an account long
    // before this point.
    ensure_role_account(user, stage.accounts)?;

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

    let resolution = resolve_and_cover(stage.store, Some(&requested), allowed.as_deref(), user);

    let (slice, method) = match resolution {
        Resolution::Denied { reason } => return Err(FlowError::RoleDenied(reason)),
        Resolution::Allowed { slice, method } => (slice, method),
    };

    // Fix the session payload: snapshot + bounded TTL + backend gate.
    let payload: SessionRolePayload =
        match SessionRolePayload::fix(&slice, cert_ttl, stage.default_session_ttl) {
            Ok(p) => p,
            Err(fix_err) => {
                let reason = fix_err.deny_reason();
                // A role whose payload cannot be enforced denies: silently
                // narrowing the granted privileges is forbidden by the spec.
                role::audit::emit_role_deny(user, slice.role.as_str(), reason.as_str());
                return Err(FlowError::RoleDenied(reason));
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
    Ok(payload)
}

/// Extract `MAX_INTEGRITY` without collapsing a malformed present extension
/// into the optional/absent state.
///
/// Both credential backends call this shared chokepoint before role,
/// delegation, and session policy. The parse failure is audited once and
/// returned fail-closed.
fn extract_cert_max_integrity(
    verified_leaf: &tessera_core::x509::VerifiedX509,
    pam_user: &str,
    cert_ident: &tessera_core::x509::CertIdent,
) -> Result<Option<tessera_core::mac::IntegrityLabel>, FlowError> {
    tessera_core::x509::max_integrity_ext::extract_max_integrity(verified_leaf).map_err(|error| {
        tessera_core::mac::audit::emit_cert_ext_parse_failed(
            pam_user,
            cert_ident,
            &error.to_string(),
        );
        FlowError::MaxIntegrityMalformed(error)
    })
}

/// Live delegation-envelope enforcement (tags-delegation §4, wired in §5).
///
/// Runs AFTER trust verification and role resolution on BOTH auth paths. For
/// every CA in the verified chain carrying `pam_cert_delegation_constraints`,
/// [`tessera_core::trust::enforce_delegation`] checks
/// `device.tags ⊇ requireTags`, role ∈ `allowRoles`, level ≤ `maxLevel`, and
/// link TTL ≤ parent `maxTtl` (AND/MIN across all links). A chain carrying NO
/// constraints is a no-op (prior per-host semantics preserved).
///
/// Inputs:
/// * `verified` — the stage-2 verified chain (full `[leaf]++mids++[anchor]`).
/// * `device_tags` — this device's trusted, applied tag set.
/// * `role` — the resolved session role; always present, since a login that
///   resolves no role never reaches this stage.
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
    role: &tessera_core::role::SessionRolePayload,
    cert_max_integrity: Option<tessera_core::mac::IntegrityLabel>,
    verified_leaf: &tessera_core::x509::VerifiedX509,
) -> Result<(), FlowError> {
    let chain = verified.full_chain();

    // Whether this chain is envelope-scoped (any CA carries
    // delegation_constraints). A malformed/mis-placed extension is itself
    // fail-closed here. Production authentication has already rejected a
    // malformed leaf `MAX_INTEGRITY` through `extract_cert_max_integrity`; the
    // scoped re-check below remains defense-in-depth for direct/internal
    // callers.
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

    // Requested role = the resolved session role.
    let requested_role = &role.role;

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

    if let Err(err) = tessera_core::trust::enforce_delegation(
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

/// Host descriptors the diagnostic prints before it falls back to a count.
///
/// A certificate may carry any number of them; the message is a hint on a login
/// screen, not a dump.
const MAX_SHOWN_HOST_DESCRIPTORS: usize = 4;

/// Characters kept from one descriptor before it is cut short.
///
/// Only raw descriptors reach the cut — a wildcard and a `sha256:` digest are
/// both fixed-length forms the parser has already constrained and are rendered
/// whole. A raw descriptor is a host name or a `machine_id`, which fit several
/// times over, so the cut costs nothing an engineer needed to read; what it buys
/// is that a descriptor of arbitrary length cannot push the rest of the message
/// off the screen.
const MAX_HOST_DESCRIPTOR_CHARS: usize = 96;

/// Whether a character may be shown on the login screen as it stands.
///
/// The set is printable ASCII less the double quote, because that is all a host
/// identifier is made of: a `machine_id` is hex, and a host name is letters,
/// digits, hyphens and dots (an international name reaches a certificate in
/// punycode). Naming the allowed characters rather than the dangerous ones is
/// what makes the answer complete: a list of dangerous ones would have to keep
/// up with every character that a renderer draws as nothing (the format
/// characters, the tag block, the blank braille pattern) or draws as something
/// else (a combining mark, a look-alike letter from another script), and any
/// one it missed would let a descriptor read on screen as a host it is not.
///
/// The double quote is out because the quote is what separates one descriptor
/// from the next on screen: a descriptor free to write one could show itself as
/// two entries, or as fewer entries than the certificate really carries.
fn is_displayable(c: char) -> bool {
    matches!(c, ' '..='~') && c != '"'
}

/// One descriptor rendered so that it cannot do anything but occupy its line.
///
/// A raw descriptor is an arbitrary UTF-8 string lifted out of a certificate on
/// a device that has authenticated nothing — the container is unopened and the
/// certificate unverified, so its content is chosen by whoever handed over the
/// drive. Printed as-is on a text console it could break the line and forge
/// further message lines (a reassuring "device trusted", an administrator's
/// phone number), or move the cursor and repaint the screen through an escape
/// sequence; printed in a greeter it could reorder the text around it or hide
/// inside a host name an engineer then reads as their own. Anything outside
/// printable ASCII therefore becomes a visible placeholder, and the length is
/// capped so one descriptor cannot crowd out the rest.
fn render_host_descriptor(
    descriptor: &tessera_core::x509::host_binding_ext::HostDescriptor,
) -> String {
    use tessera_core::x509::host_binding_ext::HostDescriptor;
    let raw = match descriptor {
        // Both of these are constrained by the parser: the wildcard is a
        // literal and the digest is 64 lowercase hex characters.
        HostDescriptor::Wildcard => return "*".to_owned(),
        HostDescriptor::Sha256Hex(h) => return format!("sha256:{h}"),
        HostDescriptor::Raw(r) => r,
    };
    let mut out = String::new();
    for c in raw.chars().take(MAX_HOST_DESCRIPTOR_CHARS) {
        if is_displayable(c) {
            out.push(c);
        } else {
            out.push('\u{fffd}');
        }
    }
    if raw.chars().nth(MAX_HOST_DESCRIPTOR_CHARS).is_some() {
        out.push('…');
    }
    out
}

/// The descriptors of a certificate as one line of the diagnostic.
///
/// A certificate issued for a fleet carries more descriptors than fit on the
/// line, and the engineer whose machine is the seventh has to learn something
/// from the cut: how many were left out tells them whether the list could hold
/// their host at all, which a bare ellipsis does not.
///
/// Each descriptor is quoted, because the comma between them is a character a
/// descriptor is otherwise free to contain: unquoted, one entry reading
/// `expected-host, *` is indistinguishable from two, and the count that follows
/// the list would be counting something other than what the reader sees. The
/// quote itself is the one printable character a descriptor may not carry, so
/// the boundary cannot be written from inside one.
fn render_host_descriptors(
    entries: &[tessera_core::x509::host_binding_ext::HostDescriptor],
) -> String {
    let mut shown = entries
        .iter()
        .take(MAX_SHOWN_HOST_DESCRIPTORS)
        .map(|entry| format!("\"{}\"", render_host_descriptor(entry)))
        .collect::<Vec<_>>()
        .join(", ");
    let hidden = entries.len().saturating_sub(MAX_SHOWN_HOST_DESCRIPTORS);
    if hidden > 0 {
        shown = format!("{shown} и ещё {hidden}");
    }
    shown
}

fn p12_wrong_pin_diagnostic(p12_bytes: &[u8]) -> String {
    let Some(cert) = tessera_core::pkcs12::try_extract_cert_without_pin(p12_bytes) else {
        return "Пароль .p12 неверный. Проверьте носитель и попробуйте ещё раз.".to_string();
    };
    let host = match tessera_core::x509::host_binding_ext::parse(cert.x509()) {
        Ok(entries) => render_host_descriptors(&entries),
        Err(_) => "<не указан>".to_string(),
    };
    // Only host_binding is shown. The admission list (`pam_cert_allowed_roles`)
    // may be read only from a verified certificate, and nothing here is
    // verified yet — this is a pre-authentication hint for a mix-up between one
    // carrier and another, and the host descriptor already identifies the
    // bundle.
    //
    // The certificate has not been verified and the container has not been
    // opened, so the binding below is what the carrier says about itself, not
    // something established about it. The wording has to carry that difference:
    // an engineer who reads it as a fact about the carrier would trust a claim
    // anyone could have written. It says "carrier" rather than naming a kind of
    // one, because the same container is read from a USB partition today and
    // from a passive token next.
    //
    // The label is the name of the extension the value comes from: a descriptor
    // may be a raw host identifier and not a digest of anything, which the
    // earlier `host_id_hash` promised it was.
    //
    // The indentation is written into the string rather than laid out in the
    // source: a `\n\` continuation eats the leading whitespace of the next
    // line, so an indent that only exists in the source never reaches a screen.
    format!(
        "Пароль .p12 неверный.\n\
         Сертификат на носителе заявляет привязку к:\n  \
         host_binding: {host}\n\
         Проверьте, что вставлен нужный носитель."
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

    #[test]
    fn wrong_pin_diagnostic_names_the_binding_of_a_container_it_cannot_open() {
        // The container's key is encrypted, as every issued one is, and no
        // password is supplied — the case the diagnostic exists for.
        let text = p12_wrong_pin_diagnostic(&fixture_bytes("leaf_rsa_plaincert.p12"));
        // The binding itself is what the engineer acts on, so the value is
        // asserted alongside the label — the fixture's certificate is bound to
        // any host, and that is what has to reach the screen.
        assert!(
            text.contains("host_binding: \"*\""),
            "the engineer must learn which device the credential names, got: {text}"
        );
        assert!(
            !text.contains("host_id_hash"),
            "a raw host identifier is no digest, and the label must not say it is: {text}"
        );
        assert!(
            !text.contains("<не указан>"),
            "the fixture carries a host binding, so it must be named: {text}"
        );
        // A container of this layout is read from a USB partition today and
        // from a passive token next; the message may not name one of them.
        assert!(
            !text.contains("флешк"),
            "the message must speak of a carrier, not of one kind of it: {text}"
        );
        assert!(
            text.contains("\n  host_binding"),
            "the binding is indented under the line that introduces it: {text:?}"
        );
        // Nothing here has been verified, so the message may report what the
        // certificate says about itself and must not report it as established.
        assert!(
            text.contains("заявляет"),
            "the message must name the source of the binding, got: {text}"
        );
        assert!(
            !text.contains("выпущен для"),
            "an unverified certificate's claim must not be stated as a fact: {text}"
        );
    }

    #[test]
    fn wrong_pin_diagnostic_falls_back_when_the_container_hides_its_certificate() {
        // A container of the older layout keeps its certificates encrypted;
        // there is nothing to show and the generic message stands.
        let text = p12_wrong_pin_diagnostic(&fixture_bytes("leaf_rsa.p12"));
        assert!(!text.contains("host_binding"), "got: {text}");
        assert!(text.contains("Пароль .p12 неверный"), "got: {text}");
        // The fallback names no kind of carrier either.
        assert!(!text.contains("флешк"), "got: {text}");
    }

    #[test]
    fn a_raw_descriptor_cannot_add_lines_to_the_diagnostic() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        // What a certificate on an unopened container may carry: a newline that
        // would let the drive write its own line of the login screen, and an
        // escape sequence that would repaint the screen on a text console.
        let hostile = HostDescriptor::Raw(
            "ws-42\r\n  Устройство доверено, обратитесь к администратору: +7 000\n\u{1b}[2J\u{1b}[H"
                .to_owned(),
        );
        let rendered = render_host_descriptor(&hostile);
        assert!(!rendered.contains('\n'), "got: {rendered:?}");
        assert!(!rendered.contains('\r'), "got: {rendered:?}");
        assert!(!rendered.contains('\u{1b}'), "got: {rendered:?}");
        assert!(
            rendered.starts_with("ws-42"),
            "the part an engineer can act on is kept: {rendered:?}"
        );
    }

    #[test]
    fn a_raw_descriptor_cannot_reorder_the_text_around_it() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        // A graphical greeter acts on these where a console would not: a line
        // separator and a right-to-left override.
        let hostile = HostDescriptor::Raw("ws-42\u{2028}\u{202e}drowssap".to_owned());
        let rendered = render_host_descriptor(&hostile);
        assert!(!rendered.contains('\u{2028}'), "got: {rendered:?}");
        assert!(!rendered.contains('\u{202e}'), "got: {rendered:?}");
    }

    #[test]
    fn a_raw_descriptor_cannot_fill_the_screen() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        let long = HostDescriptor::Raw("ы".repeat(100_000));
        let rendered = render_host_descriptor(&long);
        assert!(
            rendered.chars().count() <= MAX_HOST_DESCRIPTOR_CHARS + 1,
            "a descriptor may not outgrow the message: {} chars",
            rendered.chars().count()
        );
        assert!(rendered.ends_with('…'), "the cut is visible: {rendered:?}");
    }

    #[test]
    fn a_certificate_full_of_descriptors_does_not_fill_the_screen() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        let many: Vec<HostDescriptor> = (0..1000)
            .map(|i| HostDescriptor::Raw(format!("ws-{i}")))
            .collect();
        let rendered = render_host_descriptors(&many);
        assert_eq!(rendered.matches("ws-").count(), MAX_SHOWN_HOST_DESCRIPTORS);
        // The engineer whose machine is not among the four shown has to be able
        // to tell that the list goes on, and how far.
        assert!(
            rendered.ends_with(&format!(" и ещё {}", 1000 - MAX_SHOWN_HOST_DESCRIPTORS)),
            "got: {rendered:?}"
        );
    }

    #[test]
    fn the_last_descriptor_that_fits_is_shown_without_a_remainder() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        let exactly: Vec<HostDescriptor> = (0..MAX_SHOWN_HOST_DESCRIPTORS)
            .map(|i| HostDescriptor::Raw(format!("ws-{i}")))
            .collect();
        let rendered = render_host_descriptors(&exactly);
        assert!(!rendered.contains("и ещё"), "got: {rendered:?}");

        let one_more: Vec<HostDescriptor> = (0..=MAX_SHOWN_HOST_DESCRIPTORS)
            .map(|i| HostDescriptor::Raw(format!("ws-{i}")))
            .collect();
        assert!(
            render_host_descriptors(&one_more).ends_with(" и ещё 1"),
            "got: {:?}",
            render_host_descriptors(&one_more)
        );
    }

    #[test]
    fn a_raw_descriptor_cannot_hide_what_it_really_says() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        // Characters a renderer draws as nothing at all, or draws as a
        // different character than the one that is there. A descriptor that
        // reads on screen as a host it is not would have an engineer confirm
        // the drive against the deployment register and conclude it is theirs —
        // the one conclusion this message exists to make safe.
        for (what, raw) in [
            ("tag characters", "ws-42\u{e0020}\u{e0074}\u{e0067}"),
            ("a soft hyphen", "ws\u{00ad}-42"),
            ("an arabic letter mark", "ws-42\u{061c}"),
            ("mongolian vowel separator", "ws-42\u{180e}"),
            ("inhibit symmetric swapping", "ws-42\u{206a}\u{206f}"),
            ("interlinear annotation", "ws-42\u{fff9}\u{fffb}"),
            ("a combining acute", "ws-42\u{0301}"),
            ("a blank braille pattern", "ws-42\u{2800}"),
            ("a cyrillic look-alike", "\u{0440}s-42"),
            ("a zero-width space", "ws-\u{200b}42"),
        ] {
            let rendered = render_host_descriptor(&HostDescriptor::Raw(raw.to_owned()));
            assert!(
                rendered
                    .chars()
                    .all(|c| c == '\u{fffd}' || c.is_ascii_graphic() || c == ' '),
                "{what}: something outside printable ASCII survived: {rendered:?}"
            );
            assert_ne!(
                rendered, "ws-42",
                "{what}: a descriptor that is not `ws-42` must not read as `ws-42`"
            );
        }
    }

    #[test]
    fn a_raw_descriptor_cannot_pass_itself_off_as_several() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        // One entry that reads as two, and one that reads as five: unquoted,
        // neither is distinguishable from a certificate that really carries
        // that many, and the count after the list would contradict what the
        // engineer counts on screen.
        for raw in [
            "expected-host, *",
            "a, b, c, d, e",
            // The quote is the boundary, so a descriptor trying to write one
            // has to lose it.
            "a\", \"b",
        ] {
            let rendered = render_host_descriptors(&[HostDescriptor::Raw(raw.to_owned())]);
            assert_eq!(
                rendered.matches('"').count(),
                2,
                "one descriptor must show as one quoted entry: {rendered:?}"
            );
            assert!(
                rendered.starts_with('"') && rendered.ends_with('"'),
                "the quotes belong to the list, not to the descriptor: {rendered:?}"
            );
        }
    }

    #[test]
    fn a_raw_descriptor_cannot_forge_the_remainder_or_the_cut() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        // The tail that says how many entries were left out, and the ellipsis
        // that marks a descriptor cut short, are both outside printable ASCII —
        // a descriptor claiming either has to show placeholders instead.
        let rendered =
            render_host_descriptors(&[HostDescriptor::Raw("ws-42\" и ещё 7, \"other…".to_owned())]);
        assert!(!rendered.contains("и ещё"), "got: {rendered:?}");
        assert!(!rendered.contains('…'), "got: {rendered:?}");
        assert_eq!(rendered.matches('"').count(), 2, "got: {rendered:?}");
    }

    #[test]
    fn a_legitimate_descriptor_survives_unchanged() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        // What issuance actually writes: a machine-id digest and a host name.
        // The filter is worth nothing if it garbles these.
        for raw in [
            "ws-42.lab.example.org",
            "0123456789abcdef0123456789abcdef",
            "WS-42_build-node",
        ] {
            assert_eq!(
                render_host_descriptor(&HostDescriptor::Raw(raw.to_owned())),
                raw
            );
        }
    }

    #[test]
    fn the_descriptors_the_parser_constrains_are_shown_verbatim() {
        use tessera_core::x509::host_binding_ext::HostDescriptor;

        let digest = "a".repeat(64);
        assert_eq!(render_host_descriptor(&HostDescriptor::Wildcard), "*");
        assert_eq!(
            render_host_descriptor(&HostDescriptor::Sha256Hex(digest.clone())),
            format!("sha256:{digest}")
        );
    }

    /// A complete role stage for flow tests: an on-disk store holding the
    /// `serv` role.
    ///
    /// Every authentication resolves a role, so there is no "no role" stage to
    /// fall back on. The requested role is not part of the stage — it is the
    /// login account name, so flow tests must authenticate as `serv` for this
    /// store to resolve. The `leaf_rsa` / `leaf_ecdsa` fixtures carry
    /// `pam_cert_allowed_roles = [serv, oper]`, which is what proves coverage.
    struct RoleFixture {
        _dir: tempfile::TempDir,
        store: tessera_core::role::RoleStore,
        requested: tessera_core::role::RoleId,
        /// The account view this fixture's stage authenticates against, when it
        /// is not the one the store was loaded through.
        ///
        /// `None` means the two are the same and the stage may take both from
        /// the store; `Some` names the device view a login is judged by while
        /// the base on disk got in under a different one.
        authenticating_view: Option<tessera_core::role::SystemAccounts>,
    }

    impl RoleFixture {
        fn serv() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("serv.toml"),
                b"role = \"serv\"\nversion = 4\nos = \"linux\"\nname = \"serv\"\nlevel = 1\n\
                  [payload]\ngroups = [\"wheel\"]\n"
                    .as_slice(),
            )
            .unwrap();
            let store = tessera_core::role::RoleStore::load(
                dir.path(),
                tessera_core::role::RoleOs::Linux,
                tessera_core::role::TrustMode::Standalone,
                test_accounts(),
            )
            .unwrap();
            Self {
                _dir: dir,
                store,
                requested: tessera_core::role::RoleId::new("serv").unwrap(),
                authenticating_view: None,
            }
        }

        /// A store that holds a `root` slice — the provisioning mistake the
        /// login gate exists for.
        ///
        /// The slice is loaded through a account view that knows no accounts,
        /// because the store loader refuses such a slice on a real device.
        /// That is the point: the login must be refused even where the slice
        /// did get in.
        fn with_root_slice() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("root.toml"),
                b"role = \"root\"\nversion = 1\nos = \"linux\"\nname = \"root\"\nlevel = 1\n\
                  [payload]\ngroups = [\"wheel\"]\n"
                    .as_slice(),
            )
            .unwrap();
            let store = tessera_core::role::RoleStore::load(
                dir.path(),
                tessera_core::role::RoleOs::Linux,
                tessera_core::role::TrustMode::Standalone,
                tessera_core::role::SystemAccounts::empty(),
            )
            .unwrap();
            assert!(
                store
                    .get(&tessera_core::role::RoleId::new("root").unwrap())
                    .is_some(),
                "the fixture must actually hold the root slice"
            );
            Self {
                _dir: dir,
                store,
                requested: tessera_core::role::RoleId::new("root").unwrap(),
                // The load ran against a view that knows no accounts, which is
                // what let the `root` slice in. The login is judged by the
                // device's own view instead, and that view has not been asked
                // about anything yet — so the stage asks it afresh.
                authenticating_view: Some(test_accounts()),
            }
        }

        /// The login account name that resolves this fixture's role.
        const ACCOUNT: &'static str = "serv";

        fn stage(&self) -> RoleStage<'_> {
            RoleStage {
                store: &self.store,
                default_session_ttl: Duration::from_secs(
                    tessera_core::config::validated::DEFAULT_ROLE_SESSION_TTL_SECONDS,
                ),
                accounts: self.authenticating_view.map_or_else(
                    || tessera_core::role::AccountCheck::from_store(&self.store),
                    tessera_core::role::AccountCheck::from_view,
                ),
            }
        }
    }

    /// The device's account view these tests authenticate against.
    ///
    /// The real passwd file of the machine running the tests is never
    /// consulted: `root` must be a system account and `serv` a provisioned
    /// role account regardless of where the suite runs.
    fn test_accounts() -> tessera_core::role::SystemAccounts {
        tessera_core::role::SystemAccounts::with_lookup(|account| match account {
            "root" => tessera_core::role::PasswdLookup::Uid(0),
            "serv" => tessera_core::role::PasswdLookup::Uid(4000),
            _ => tessera_core::role::PasswdLookup::NoEntry,
        })
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

    /// Path to a real PEM fixture usable as a `[trust].anchors` entry —
    /// config validation rejects empty anchor lists.
    fn anchor_path_toml() -> String {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tessera_core/tests/fixtures/ca.pem");
        crate::test_support::toml_path(&path)
    }

    /// Fill in the placeholders every config fixture in this module shares:
    /// the anchor path and the `[monitor]` paths, both of which must be
    /// absolute for the platform the test runs on.
    fn fill_fixture_placeholders(raw_toml: &str) -> String {
        raw_toml
            .replace("@ANCHOR@", &anchor_path_toml())
            .replace("@MONITOR@", &crate::test_support::monitor_section_toml())
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

@MONITOR@
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
        let raw_toml = fill_fixture_placeholders(raw_toml);
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

        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let outcome = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-1".into(),
            |_| Ok(SecretString::from("correct-pin".to_string())),
        )
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

        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let outcome = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-2".into(),
            |_| Ok(SecretString::from("correct-pin".to_string())),
        )
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

        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let attempts = std::cell::Cell::new(0_u32);
        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-3".into(),
            |_| {
                attempts.set(attempts.get() + 1);
                Ok(SecretString::from("badpin".to_string()))
            },
        )
        .unwrap_err();
        assert!(matches!(err, FlowError::MaxTries));
        assert_eq!(attempts.get(), 3);
        assert_eq!(err.pam_code(), 11, "PAM_MAXTRIES");
    }

    #[test]
    fn missing_p12_returns_authinfo_unavail() {
        let tmp = tempfile::tempdir().unwrap();
        // Note: certs/ directory not created.
        let verifier = build_verifier();
        let cfg = minimal_cfg();

        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };
        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-4".into(),
            |_| Ok(SecretString::from("correct-pin".to_string())),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FlowError::Discovery(DiscoveryError::P12NotFound { .. })
        ));
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
    }

    #[test]
    fn serial_less_pkcs12_device_denied_under_strict_monitoring() {
        // A USB device that exposes no stable descriptor serial can never be
        // matched by a removal event, so under strict monitoring (continuous
        // presence is a hard requirement) it must be refused fail-closed —
        // mirroring the PKCS#11 `TokenSerialMissing` path.
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let mut cfg = minimal_cfg();
        cfg.monitor.fail_mode = tessera_core::config::validated::MonitorFailMode::Strict;

        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let mut io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        io.device.serial = None;
        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-noserial".into(),
            |_| Ok(SecretString::from("correct-pin".to_string())),
        )
        .unwrap_err();
        assert!(matches!(err, FlowError::UsbSerialMissing), "got {err:?}");
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
    }

    #[test]
    fn serial_less_pkcs12_device_allowed_under_permissive_monitoring() {
        // Permissive monitoring is the documented escape hatch: the admin has
        // accepted that presence checks may be best-effort, so a serial-less
        // device is allowed to authenticate. `minimal_cfg` is permissive.
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg();
        assert_eq!(
            cfg.monitor.fail_mode,
            tessera_core::config::validated::MonitorFailMode::Permissive
        );

        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let mut io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        io.device.serial = None;
        let outcome = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-noserial-ok".into(),
            |_| Ok(SecretString::from("correct-pin".to_string())),
        )
        .expect("permissive monitoring allows a serial-less device");
        assert_eq!(outcome.auth_ctx.cert_cn.as_deref(), Some("alice"));
        assert!(outcome.auth_ctx.usb_serial.is_none());
    }

    // Cert host-binding scope is exhaustively tested in
    // `tessera_core::host_binding::tests`; every fixture cert carries `["*"]`,
    // so the matrix is not re-tested end-to-end here.
    //
    // Admission to the login account has no separate check: the account name IS
    // the role name, so the `allowed_roles` coverage below is the whole
    // decision. The tests use the same `resolve_and_cover` call the flow makes.

    #[test]
    fn login_into_a_covered_role_account_is_admitted() {
        let roles = RoleFixture::serv();
        let resolution = tessera_core::role::resolve_and_cover(
            &roles.store,
            Some(&roles.requested),
            Some(std::slice::from_ref(&roles.requested)),
            "serv",
        );
        assert!(
            matches!(resolution, tessera_core::role::Resolution::Allowed { .. }),
            "got {resolution:?}"
        );
    }

    #[test]
    fn login_into_an_account_the_cert_does_not_name_is_refused() {
        // `ssh serv@device` against a certificate granting only `oper`.
        let roles = RoleFixture::serv();
        let oper = tessera_core::role::RoleId::new("oper").unwrap();
        let resolution = tessera_core::role::resolve_and_cover(
            &roles.store,
            Some(&roles.requested),
            Some(&[oper]),
            "serv",
        );
        assert!(
            matches!(
                resolution,
                tessera_core::role::Resolution::Denied {
                    reason: tessera_core::role::RoleDenyReason::NotCovered
                }
            ),
            "got {resolution:?}"
        );
    }

    #[test]
    fn certificate_without_allowed_roles_admits_no_account() {
        // The extension is absent, which the flow passes down as `None`. There
        // is no device-side list to fall back on, so the login is refused.
        let roles = RoleFixture::serv();
        let resolution = tessera_core::role::resolve_and_cover(
            &roles.store,
            Some(&roles.requested),
            None,
            "serv",
        );
        assert!(
            matches!(
                resolution,
                tessera_core::role::Resolution::Denied {
                    reason: tessera_core::role::RoleDenyReason::NotCovered
                }
            ),
            "got {resolution:?}"
        );
    }

    /// Self-signed leaf carrying a `pam_cert_allowed_roles` extension whose
    /// DER body is truncated: the outer SEQUENCE claims five content bytes
    /// but only three follow.
    fn malformed_allowed_roles_leaf() -> tessera_core::x509::VerifiedX509 {
        use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_text("CN", "malformed-allowed-roles")
            .expect("subject CN");
        let name = name.build();
        let mut cert = X509Builder::new().expect("cert builder");
        cert.set_version(2).expect("version");
        let serial = BigNum::from_u32(1).expect("serial");
        cert.set_serial_number(&Asn1Integer::from_bn(&serial).expect("asn1 serial"))
            .expect("set serial");
        cert.set_subject_name(&name).expect("subject");
        cert.set_issuer_name(&name).expect("issuer");
        cert.set_pubkey(&key).expect("pubkey");
        cert.set_not_before(&Asn1Time::days_from_now(0).expect("not before"))
            .expect("set not before");
        cert.set_not_after(&Asn1Time::days_from_now(365).expect("not after"))
            .expect("set not after");

        let malformed_der = [0x30_u8, 0x05, 0x02, 0x01, 0x02];
        let oid = Asn1Object::from_str(tessera_core::x509::oids::ALLOWED_ROLES_OID).expect("OID");
        let octets = Asn1OctetString::new_from_bytes(&malformed_der).expect("octets");
        let extension =
            X509Extension::new_from_der(&oid, false, &octets).expect("allowed_roles extension");
        cert.append_extension(extension)
            .expect("append allowed_roles");
        cert.sign(&key, MessageDigest::sha256()).expect("sign");
        tessera_core::x509::VerifiedX509::from_trusted_for_test(cert.build())
    }

    #[test]
    fn malformed_allowed_roles_denies_every_account() {
        // The parser and the coverage check are each tested on their own; this
        // covers the seam between them, where a malformed extension is turned
        // into an empty admission list. "Empty" and "absent" must behave the
        // same — the alternative, skipping the check when the list cannot be
        // read, would make a corrupted extension grant everything.
        let roles = RoleFixture::serv();
        let leaf = malformed_allowed_roles_leaf();

        let err = resolve_role_stage(&leaf, &roles.stage(), RoleFixture::ACCOUNT, None)
            .expect_err("a malformed admission list must not admit anything");

        assert!(
            matches!(
                err,
                FlowError::RoleDenied(tessera_core::role::RoleDenyReason::NotCovered)
            ),
            "unexpected error: {err:?}"
        );
        assert_eq!(err.pam_code(), 6, "PAM_PERM_DENIED");
    }

    #[test]
    fn pkcs12_pin_prompt_from_config_reaches_prompter() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg(); // sets pkcs12_pin_prompt = "PIN: "

        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let seen = std::cell::RefCell::new(Vec::new());
        authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-prompt".into(),
            |p| {
                seen.borrow_mut().push(p.to_string());
                Ok(SecretString::from("correct-pin".to_string()))
            },
        )
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
pkcs11_module = @MISSING_MODULE@
pkcs11_token_label = "Test Token"
pkcs11_max_pin_attempts = 2
pkcs11_locking_mode = "os"
usb_wait_seconds = 1
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 30
monitor_fail_mode = "permissive"

@MONITOR@
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
        let raw_toml = fill_fixture_placeholders(raw_toml).replace(
            "@MISSING_MODULE@",
            &crate::test_support::toml_path(std::path::Path::new(
                crate::test_support::MISSING_PKCS11_MODULE_PATH,
            )),
        );
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
        /// The slots that satisfy the configured selection.
        ///
        /// Deliberately independent of what `wait_for_token` hands back: the
        /// two can disagree on real hardware — a token removed between the
        /// wait and the check, or a second one whose slot came first — and a
        /// stub that could not express the disagreement would let a flow that
        /// uses the arrival slot pass.
        matching: std::cell::RefCell<Vec<Slot>>,
        /// Slots the flow actually operated on, in order.
        used_slots: std::cell::RefCell<Vec<Slot>>,
    }

    impl StubPkcs11Io {
        fn new() -> Self {
            Self {
                on_wait: std::cell::RefCell::new(None),
                on_serial: std::cell::RefCell::new(None),
                on_acquire: std::cell::RefCell::new(None),
                matching: std::cell::RefCell::new(vec![Self::slot()]),
                used_slots: std::cell::RefCell::new(Vec::new()),
            }
        }
        fn slot() -> Slot {
            Slot::try_from(0_u64).unwrap()
        }
        fn slot_n(n: u64) -> Slot {
            Slot::try_from(n).unwrap()
        }
    }

    impl Pkcs11Io for StubPkcs11Io {
        fn wait_for_token(&self) -> Result<Slot, Pkcs11Error> {
            self.on_wait
                .borrow_mut()
                .take()
                .unwrap_or_else(|| Ok(Self::slot()))
        }
        fn matching_tokens(&self) -> Result<Vec<Slot>, Pkcs11Error> {
            Ok(self.matching.borrow().clone())
        }
        fn read_token_serial(&self, slot: Slot) -> Result<String, Pkcs11Error> {
            self.used_slots.borrow_mut().push(slot);
            self.on_serial
                .borrow_mut()
                .take()
                .unwrap_or_else(|| Ok("FAKE-SERIAL".into()))
        }
        fn acquire_session(
            &self,
            slot: Slot,
            _pin_prompter: &mut PinPrompterFn<'_>,
        ) -> Result<Pkcs11Session, P11Acquire> {
            self.used_slots.borrow_mut().push(slot);
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
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };
        let io = dummy_flow_io();
        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-p11-1".into(),
            |_| Ok(SecretString::from("any")),
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, FlowError::Pkcs11OpensslEngineNotImplemented));
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
    }

    #[test]
    fn dispatcher_routes_pkcs11_native_with_missing_module_to_pkcs11_error() {
        // `pkcs11_native_cfg()` references `/nonexistent/dummy.so`; the
        // dispatcher tries to load it and surfaces `Pkcs11(ModulePathMissing)`.
        let cfg = pkcs11_native_cfg();
        let verifier = build_verifier();
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };
        let io = dummy_flow_io();
        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-p11-2".into(),
            |_| Ok(SecretString::from("any")),
        )
        .err()
        .expect("must fail");
        assert!(
            matches!(err, FlowError::Pkcs11(Pkcs11Error::ModulePathMissing(_))),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
    }

    /// The signing token has the same presence hole as the token carrier and
    /// is closed by the same poller, so strict monitoring no longer stops the
    /// dispatcher before it reaches the provider. What stops this particular
    /// login is the module path, which is where an unloadable provider
    /// belongs.
    #[test]
    fn dispatcher_no_longer_refuses_strict_pkcs11_before_loading_module() {
        let mut cfg = pkcs11_native_cfg();
        cfg.monitor.fail_mode = tessera_core::config::validated::MonitorFailMode::Strict;
        let verifier = build_verifier();
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };
        let io = dummy_flow_io();

        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-p11-strict-dispatch".into(),
            |_| Ok(SecretString::from("unused")),
        )
        .expect_err("the fixture's module path loads nothing");

        assert!(
            matches!(
                err,
                FlowError::Pkcs11(
                    Pkcs11Error::ModulePathMissing(_) | Pkcs11Error::ModuleLoadFailed { .. }
                )
            ),
            "the refusal must come from the provider, not from the monitoring mode: got {err:?}"
        );
    }

    /// Under strict monitoring the PKCS#11 path now reaches token discovery
    /// instead of being refused ahead of it, and fails on whatever discovery
    /// reports.
    #[test]
    fn strict_pkcs11_presence_reaches_token_discovery() {
        let mut cfg = pkcs11_native_cfg();
        cfg.monitor.fail_mode = tessera_core::config::validated::MonitorFailMode::Strict;
        let verifier = build_verifier();
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };
        let stub = StubPkcs11Io::new();
        *stub.on_wait.borrow_mut() = Some(Err(Pkcs11Error::TokenWaitTimeout { seconds: 1 }));

        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-p11-strict".into(),
            |_| Ok(SecretString::from("unused")),
        )
        .expect_err("the stub has no token to find");

        assert!(
            matches!(err, FlowError::Pkcs11(Pkcs11Error::TokenWaitTimeout { .. })),
            "the refusal must come from discovery, not from the monitoring mode: got {err:?}"
        );
        assert!(
            stub.on_wait.borrow().is_none(),
            "token discovery must have been reached and consumed the stubbed answer"
        );
    }

    #[test]
    fn pkcs11_path_propagates_acquire_max_attempts_as_max_tries() {
        let cfg = pkcs11_native_cfg();
        let verifier = build_verifier();
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        // We exercise `authenticate_pkcs11` directly with the stub, since
        // the dispatcher's `RealPkcs11Io` would need a real provider.
        let stub = StubPkcs11Io::new();
        // Default behaviour: wait_for_token Ok, read_serial Ok, acquire MaxAttemptsExceeded.
        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            RoleFixture::ACCOUNT,
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
        assert_eq!(err.pam_code(), 11, "PAM_MAXTRIES");
    }

    #[test]
    fn pkcs11_path_propagates_token_wait_timeout_as_authinfo_unavail() {
        let cfg = pkcs11_native_cfg();
        let verifier = build_verifier();
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let stub = StubPkcs11Io::new();
        *stub.on_wait.borrow_mut() = Some(Err(Pkcs11Error::TokenWaitTimeout { seconds: 1 }));

        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            RoleFixture::ACCOUNT,
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
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
    }

    #[test]
    fn pkcs11_path_propagates_serial_missing_after_wait_ok() {
        let cfg = pkcs11_native_cfg();
        let verifier = build_verifier();
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let stub = StubPkcs11Io::new();
        *stub.on_serial.borrow_mut() = Some(Err(Pkcs11Error::TokenSerialMissing));

        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            RoleFixture::ACCOUNT,
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
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
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

        let monitor = StubClient;
        let exec = MockExec::new(Vec::new());
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-h1".into(),
            |_| Ok(SecretString::from("correct-pin")),
        )
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

        let monitor = StubClient;
        let exec = MockExec::new(vec![Ok(nonzero_outcome(Stage5HookStage::PreAuth, 7))]);
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-h2".into(),
            |_| Ok(SecretString::from("correct-pin")),
        )
        .unwrap_err();
        assert!(matches!(err, FlowError::PreAuthHook(_)), "got {err:?}");
        assert_eq!(err.pam_code(), 7, "PAM_AUTH_ERR");
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

        let monitor = StubClient;
        let exec = MockExec::new(vec![Ok(nonzero_outcome(
            Stage5HookStage::PostAuthSuccess,
            42,
        ))]);
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let outcome = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-h3".into(),
            |_| Ok(SecretString::from("correct-pin")),
        )
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
        let monitor = StubClient;
        let exec = MockExec::new(vec![Ok(nonzero_outcome(Stage5HookStage::PreAuth, 1))]);
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let stub = StubPkcs11Io::new();
        // If pre_auth ran AFTER wait_for_token we'd hit MaxAttemptsExceeded.
        // Asserting PreAuthHook proves the hook ran first.
        let err = authenticate_pkcs11::<NoopMountOps, _, _>(
            deps,
            &stub,
            RoleFixture::ACCOUNT,
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
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let outcome = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-fb1".into(),
            |_| Ok(SecretString::from("correct-pin")),
        )
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
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-fb2".into(),
            |_| Ok(SecretString::from("correct-pin")),
        )
        .unwrap_err();
        assert!(
            matches!(err, FlowError::P12Envelope(_)),
            "expected P12Envelope, got {err:?}"
        );
        // Maps to PAM_AUTHINFO_UNAVAIL (9) — same bucket as Discovery
        // failures (no usable credentials on the bus).
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");

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
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-empty".into(),
            |_| Ok(SecretString::from("any")),
        )
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
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-wpin".into(),
            |_| Ok(SecretString::from("definitely-wrong-pin")),
        )
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

    // -----------------------------------------------------------------
    // A login account the system already owns is never a role.
    //
    // The role IS the login account, so `root` and every other account
    // below the regular-uid boundary must be refused whatever the store
    // holds and whatever the certificate allows.
    // -----------------------------------------------------------------

    #[test]
    fn system_account_login_denied_even_with_a_matching_slice() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg();
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        // The store holds `root`, so nothing but the account check can be
        // what stops this login.
        let roles = RoleFixture::with_root_slice();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let err = authenticate(deps, &io, "root", "ssh", "sess-root".into(), |_| {
            panic!("the PIN must never be prompted for a system account")
        })
        .expect_err("a login into a system account must be refused");

        assert!(
            matches!(
                err,
                FlowError::RoleDenied(tessera_core::role::RoleDenyReason::SystemAccount)
            ),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 6, "PAM_PERM_DENIED");
    }

    #[test]
    fn system_account_refused_before_any_credential_is_touched() {
        // The USB layer is armed to fail: reaching it at all would surface as
        // `FlowError::Usb`, so a role denial proves the account check ran
        // first — before mount, discovery, PIN prompt or certificate.
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg();
        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::with_root_slice();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let mut io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        io.usb_error = Some(UsbError::Timeout);

        let err = authenticate(deps, &io, "root", "ssh", "sess-root-early".into(), |_| {
            panic!("the PIN must never be prompted for a system account")
        })
        .expect_err("a login into a system account must be refused");

        assert!(
            matches!(
                err,
                FlowError::RoleDenied(tessera_core::role::RoleDenyReason::SystemAccount)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn role_account_outside_the_system_range_passes_the_account_check() {
        ensure_role_account(
            RoleFixture::ACCOUNT,
            tessera_core::role::AccountCheck::from_view(test_accounts()),
        )
        .expect("a provisioned role account must pass");
    }

    #[test]
    fn absent_account_is_not_refused_by_the_account_check() {
        // An account with no passwd entry is refused later, on its own terms
        // (no such role, no such user); this gate must not pre-empt that.
        ensure_role_account(
            "ghost",
            tessera_core::role::AccountCheck::from_view(test_accounts()),
        )
        .expect("an absent account must not be refused here");
    }

    #[test]
    fn unusable_passwd_database_fails_closed_as_a_backend_failure() {
        let accounts = tessera_core::role::SystemAccounts::with_lookup(|_| {
            tessera_core::role::PasswdLookup::Unavailable
        });
        let err = ensure_role_account(
            "serv",
            tessera_core::role::AccountCheck::from_view(accounts),
        )
        .expect_err("an unusable passwd database must fail closed");
        // Denied like any other undecidable login, but audited as a backend
        // failure: `system_account` means somebody tried to enter an account
        // the system owns, and a name service that keeps dropping must not
        // bury that signal under its own noise.
        assert!(
            matches!(
                err,
                FlowError::RoleDenied(tessera_core::role::RoleDenyReason::BackendUnavailable)
            ),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 6, "PAM_PERM_DENIED");
    }

    #[test]
    fn a_system_account_and_a_broken_name_service_audit_apart() {
        let accounts = tessera_core::role::SystemAccounts::with_lookup(|account| match account {
            "root" => tessera_core::role::PasswdLookup::Uid(0),
            _ => tessera_core::role::PasswdLookup::Unavailable,
        });

        let attack = ensure_role_account(
            "root",
            tessera_core::role::AccountCheck::from_view(accounts),
        )
        .expect_err("root must be refused");
        let outage = ensure_role_account(
            "serv",
            tessera_core::role::AccountCheck::from_view(accounts),
        )
        .expect_err("an unusable passwd database must fail closed");

        assert!(
            matches!(
                attack,
                FlowError::RoleDenied(tessera_core::role::RoleDenyReason::SystemAccount)
            ),
            "got {attack:?}"
        );
        assert!(
            matches!(
                outage,
                FlowError::RoleDenied(tessera_core::role::RoleDenyReason::BackendUnavailable)
            ),
            "got {outage:?}"
        );
    }

    /// How many times [`reused_names`] was asked. A counter per test: the
    /// suite runs them in parallel, and a shared one would count the other
    /// test's questions.
    static REUSED_NAME_LOOKUPS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    /// The same, for the test that asks about a name outside the base.
    static FRESH_NAME_LOOKUPS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// The additive source of the account view below, counting its questions.
    ///
    /// It stands for the source whose cost is the one worth not paying twice:
    /// on a device it is a process, and on a slow directory it is the whole
    /// configured bound.
    fn reused_names(_account: &str, _timeout: Duration) -> tessera_core::role::PasswdLookup {
        REUSED_NAME_LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tessera_core::role::PasswdLookup::NoEntry
    }

    /// The same source for the other test.
    fn fresh_names(_account: &str, _timeout: Duration) -> tessera_core::role::PasswdLookup {
        FRESH_NAME_LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tessera_core::role::PasswdLookup::NoEntry
    }

    /// The local source paired with it: `serv` is a role account, `root` is the
    /// system's.
    fn counted_local(account: &str) -> tessera_core::role::PasswdLookup {
        match account {
            "root" => tessera_core::role::PasswdLookup::Uid(0),
            _ => tessera_core::role::PasswdLookup::Uid(4000),
        }
    }

    #[test]
    fn a_login_into_a_role_asks_the_name_service_once() {
        use std::sync::atomic::Ordering::Relaxed;

        // Loading the store already asked about every slice name, waiting out
        // the additive source's bound if it came to that. A login into one of
        // those names must not pay that wait a second time — the bound the
        // configuration states is the bound one login attempt may cost.
        let accounts =
            tessera_core::role::SystemAccounts::with_sources(counted_local, reused_names);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("serv.toml"),
            b"role = \"serv\"\nversion = 4\nos = \"linux\"\nname = \"serv\"\nlevel = 1\n\
              [payload]\ngroups = [\"wheel\"]\n"
                .as_slice(),
        )
        .unwrap();

        REUSED_NAME_LOOKUPS.store(0, Relaxed);
        let store = tessera_core::role::RoleStore::load(
            dir.path(),
            tessera_core::role::RoleOs::Linux,
            tessera_core::role::TrustMode::Standalone,
            accounts,
        )
        .unwrap();
        assert_eq!(
            REUSED_NAME_LOOKUPS.load(Relaxed),
            1,
            "the load asks about the one slice name"
        );

        ensure_role_account("serv", tessera_core::role::AccountCheck::from_store(&store))
            .expect("a provisioned role account must pass");

        assert_eq!(
            REUSED_NAME_LOOKUPS.load(Relaxed),
            1,
            "the verdict the load already reached is the verdict the login uses"
        );
    }

    #[test]
    fn a_login_into_an_account_no_slice_is_named_after_is_still_asked_about() {
        use std::sync::atomic::Ordering::Relaxed;

        // The other half: the snapshot's local source would answer about such
        // a name, but its additive source was never asked — and that is the
        // one source that sees an account no local file holds. Reusing the
        // snapshot here would drop it silently.
        let accounts = tessera_core::role::SystemAccounts::with_sources(counted_local, fresh_names);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("serv.toml"),
            b"role = \"serv\"\nversion = 4\nos = \"linux\"\nname = \"serv\"\nlevel = 1\n\
              [payload]\ngroups = [\"wheel\"]\n"
                .as_slice(),
        )
        .unwrap();
        let store = tessera_core::role::RoleStore::load(
            dir.path(),
            tessera_core::role::RoleOs::Linux,
            tessera_core::role::TrustMode::Standalone,
            accounts,
        )
        .unwrap();
        assert!(!store
            .account_snapshot()
            .expect("a store loaded from a directory carries its snapshot")
            .covers("oper"));

        FRESH_NAME_LOOKUPS.store(0, Relaxed);
        ensure_role_account("oper", tessera_core::role::AccountCheck::from_store(&store))
            .expect("an account outside the base is not a system account here");

        assert_eq!(
            FRESH_NAME_LOOKUPS.load(Relaxed),
            1,
            "a name the snapshot was not taken for has to be asked about"
        );
    }

    #[test]
    fn system_account_denial_says_nothing_about_the_store() {
        // The message must not become the store oracle that an early
        // role-existence check would have been.
        let err = ensure_role_account(
            "root",
            tessera_core::role::AccountCheck::from_view(test_accounts()),
        )
        .expect_err("root must be refused")
        .to_string();
        assert!(!err.contains("slice"), "{err}");
        assert!(!err.contains("store"), "{err}");
    }

    #[test]
    fn role_denied_maps_to_perm_denied() {
        let err = FlowError::RoleDenied(tessera_core::role::RoleDenyReason::NotCovered);
        assert_eq!(err.pam_code(), 6, "PAM_PERM_DENIED");
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

        // Strict fail mode: a monitord that cannot record the session must
        // turn the otherwise-successful cert auth into a definitive denial.
        let monitor = FailModeWrapper::new(FailingMonitor, MonitorFailMode::Strict);
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let err = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-mon-strict".into(),
            |_| Ok(SecretString::from("correct-pin".to_string())),
        )
        .expect_err("strict monitor failure must deny auth");
        assert!(
            matches!(err, FlowError::MonitorRegistration(_)),
            "got {err:?}"
        );
        assert_eq!(err.pam_code(), 6, "PAM_PERM_DENIED");
    }

    #[test]
    fn pkcs12_permissive_monitor_failure_succeeds() {
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let verifier = build_verifier();
        let cfg = minimal_cfg();

        // Permissive fail mode: the wrapper converts the transport error to
        // Ok(()) before the flow ever sees it, so auth still succeeds.
        let monitor = FailModeWrapper::new(FailingMonitor, MonitorFailMode::Permissive);
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };

        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let outcome = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-mon-perm".into(),
            |_| Ok(SecretString::from("correct-pin".to_string())),
        )
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
            usb_vid_pid: None,
            usb_devnode: None,
            carrier: tessera_proto::CarrierKind::UsbPartition,
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
        assert_eq!(err.pam_code(), 6, "PAM_PERM_DENIED");
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

    #[cfg(feature = "mac-tests")]
    fn malformed_max_integrity_leaf() -> tessera_core::x509::VerifiedX509 {
        use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::BasicConstraints;
        use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_text("CN", "malformed-max-integrity")
            .expect("subject CN");
        let name = name.build();
        let mut cert = X509Builder::new().expect("cert builder");
        cert.set_version(2).expect("version");
        let serial = BigNum::from_u32(1).expect("serial");
        cert.set_serial_number(&Asn1Integer::from_bn(&serial).expect("asn1 serial"))
            .expect("set serial");
        cert.set_subject_name(&name).expect("subject");
        cert.set_issuer_name(&name).expect("issuer");
        cert.set_pubkey(&key).expect("pubkey");
        cert.set_not_before(&Asn1Time::days_from_now(0).expect("not before"))
            .expect("set not before");
        cert.set_not_after(&Asn1Time::days_from_now(365).expect("not after"))
            .expect("set not after");
        cert.append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .expect("basic constraints"),
        )
        .expect("append basic constraints");

        // SEQUENCE claims five body bytes but contains only three.
        let malformed_der = [0x30_u8, 0x05, 0x02, 0x01, 0x02];
        let oid = Asn1Object::from_str(tessera_core::x509::oids::MAX_INTEGRITY_OID).expect("OID");
        let octets = Asn1OctetString::new_from_bytes(&malformed_der).expect("octets");
        let extension =
            X509Extension::new_from_der(&oid, false, &octets).expect("MAX_INTEGRITY extension");
        cert.append_extension(extension)
            .expect("append MAX_INTEGRITY");
        cert.sign(&key, MessageDigest::sha256()).expect("sign");
        tessera_core::x509::VerifiedX509::from_trusted_for_test(cert.build())
    }

    #[cfg(feature = "mac-tests")]
    fn assert_malformed_max_integrity_denied_for_backend(backend: &str) {
        let cert = malformed_max_integrity_leaf();
        let ident = tessera_core::x509::CertIdent::from(&cert);

        let error = extract_cert_max_integrity(&cert, "alice", &ident)
            .expect_err("malformed MAX_INTEGRITY must fail closed");

        assert!(
            matches!(error, FlowError::MaxIntegrityMalformed(_)),
            "{backend}: unexpected error: {error:?}"
        );
        assert_eq!(error.pam_code(), 6, "{backend}: PAM_PERM_DENIED");
    }

    #[cfg(feature = "mac-tests")]
    #[test]
    fn pkcs12_malformed_max_integrity_fails_closed() {
        assert_malformed_max_integrity_denied_for_backend("pkcs12");
    }

    #[cfg(feature = "mac-tests")]
    #[test]
    fn pkcs11_malformed_max_integrity_fails_closed() {
        assert_malformed_max_integrity_denied_for_backend("pkcs11");
    }

    // -----------------------------------------------------------------
    // Envelope carrier: USB partition (default) vs data object on a token
    // -----------------------------------------------------------------

    /// The label the carrier tests read the envelope under.
    const CARRIER_LABEL: &str = "tessera-credential";

    /// Serial the fake token reports.
    const CARRIER_TOKEN_SERIAL: &str = "483d4e1a";

    fn token_carrier_cfg() -> ValidatedConfig {
        let mut cfg = minimal_cfg();
        cfg.pkcs12_source = tessera_core::config::validated::Pkcs12Source::TokenObject {
            object_label: CARRIER_LABEL.to_owned(),
        };
        cfg
    }

    /// A flow-io that serves the envelope off a token and would notice any
    /// touch of mass storage.
    fn token_carrier_io(p12_name: &str) -> InMemoryFlowIo {
        let io = InMemoryFlowIo::new(std::path::PathBuf::from("/nonexistent/never-mounted"));
        *io.token_carrier.borrow_mut() = Some(Ok(TokenCarrier {
            p12_bytes: fixture_bytes(p12_name),
            token_serial: CARRIER_TOKEN_SERIAL.to_owned(),
        }));
        io
    }

    /// Monitor client that keeps what it was told to register.
    ///
    /// Removal enforcement is keyed on the fields recorded here, so "the flow
    /// filled in an `AuthContext`" is not the property under test — what the
    /// daemon received is.
    /// What monitord was told about the medium: serial, VID/PID, devnode.
    type RegisteredMedium = (Option<String>, Option<String>, Option<String>);

    #[derive(Default)]
    struct RecordingMonitor {
        opened: std::sync::Mutex<Vec<RegisteredMedium>>,
    }

    impl tessera_core::ipc::MonitorClient for RecordingMonitor {
        fn hello(&self) -> Result<(), tessera_core::error::IpcError> {
            Ok(())
        }
        fn open_session(
            &self,
            info: &OpenSessionInfo<'_>,
        ) -> Result<(), tessera_core::error::IpcError> {
            #[allow(clippy::unwrap_used)]
            self.opened.lock().unwrap().push((
                info.usb_serial.map(str::to_owned),
                info.usb_vid_pid.map(str::to_owned),
                info.usb_devnode.map(str::to_owned),
            ));
            Ok(())
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

    /// What one authentication attempt did, beyond its verdict.
    struct CarrierRun {
        outcome: Result<FlowOutcome<NoopMountOps>, FlowError>,
        prompts: Vec<String>,
        usb_waits: usize,
        mounts: usize,
        registered: Vec<RegisteredMedium>,
    }

    /// Drive one authentication over the given carrier.
    fn run_carrier(
        cfg: &ValidatedConfig,
        io: &InMemoryFlowIo,
        verifier: &dyn Stage2TrustVerifier,
        host_id_hash: &str,
        pin: &str,
    ) -> CarrierRun {
        let monitor = RecordingMonitor::default();
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg,
            trust: verifier,
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash,
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };
        let prompts = std::cell::RefCell::new(Vec::new());
        let outcome = authenticate(
            deps,
            io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-carrier".into(),
            |prompt| {
                prompts.borrow_mut().push(prompt.to_owned());
                Ok(SecretString::from(pin.to_string()))
            },
        );
        #[allow(clippy::unwrap_used)]
        let registered = monitor.opened.lock().unwrap().clone();
        CarrierRun {
            outcome,
            prompts: prompts.into_inner(),
            usb_waits: io.usb_waits.get(),
            mounts: io.mounts.get(),
            registered,
        }
    }

    /// A configuration that says nothing about the carrier keeps mounting the
    /// USB partition it always mounted.
    #[test]
    fn an_absent_source_key_still_reads_the_usb_partition() {
        let cfg = minimal_cfg();
        assert_eq!(
            cfg.pkcs12_source,
            tessera_core::config::validated::Pkcs12Source::UsbPartition,
            "an installation that predates the token carrier must not change behaviour"
        );

        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let run = run_carrier(&cfg, &io, &build_verifier(), "host-T-hash", "correct-pin");

        let outcome = run.outcome.expect("the USB carrier still authenticates");
        assert!(outcome.mount.is_some(), "the mount guard is still returned");
        assert_eq!(outcome.auth_ctx.usb_serial.as_deref(), Some("MOCK"));
        assert_eq!(run.usb_waits, 1, "the USB bus is still consulted");
        assert_eq!(run.mounts, 1, "the partition is still mounted");
    }

    /// A CCID token has no filesystem, so the token carrier must not wait on
    /// the USB bus or mount anything at all.
    #[test]
    fn the_token_carrier_never_touches_mass_storage() {
        let cfg = token_carrier_cfg();
        let io = token_carrier_io("leaf_rsa.p12");
        let run = run_carrier(&cfg, &io, &build_verifier(), "host-T-hash", "correct-pin");

        let outcome = run.outcome.expect("the token carrier authenticates");
        assert_eq!(run.usb_waits, 0, "wait_for_usb must not be called");
        assert_eq!(run.mounts, 0, "nothing may be mounted");
        assert!(
            outcome.mount.is_none(),
            "there is no mount to hand back to the caller"
        );
    }

    /// The serial in `usb_serial` is what the daemon matches a removal event
    /// against. An empty one there means the session outlives the carrier
    /// being pulled out, and nothing else in the flow would notice.
    #[test]
    fn the_token_carrier_records_the_token_serial_for_removal_enforcement() {
        let cfg = token_carrier_cfg();
        let io = token_carrier_io("leaf_rsa.p12");
        let run = run_carrier(&cfg, &io, &build_verifier(), "host-T-hash", "correct-pin");

        let outcome = run.outcome.expect("the token carrier authenticates");
        assert_eq!(
            outcome.auth_ctx.usb_serial.as_deref(),
            Some(CARRIER_TOKEN_SERIAL),
            "the carrier identity must be the token's serial, not empty"
        );
        assert_eq!(
            run.registered,
            vec![(Some(CARRIER_TOKEN_SERIAL.to_owned()), None, None)],
            "the daemon has to receive that same serial, and a token has no \
             VID/PID or devnode to bind to"
        );
    }

    /// Trust verifier that records what each attempt presented to it.
    ///
    /// The presented chain is the one input to verification that differs
    /// between the carriers, and nothing downstream reports it, so a test that
    /// wanted to see the difference had to look here.
    struct RecordingVerifier {
        inner: OpensslVerifier,
        presented: std::sync::Mutex<Vec<usize>>,
    }

    impl RecordingVerifier {
        fn new() -> Self {
            Self {
                inner: build_verifier(),
                presented: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn presented_counts(&self) -> Vec<usize> {
            self.presented.lock().unwrap().clone()
        }
    }

    impl Stage2TrustVerifier for RecordingVerifier {
        fn verify(
            &self,
            leaf: &Certificate,
            presented: &[Certificate],
        ) -> Result<tessera_core::trust::openssl_verifier::Stage2VerifiedChain, TrustError>
        {
            self.presented.lock().unwrap().push(presented.len());
            self.inner.verify(leaf, presented)
        }
    }

    /// The one place where the input to verification depends on the carrier.
    ///
    /// A USB medium can hold `certs/chain.pem` beside the container and the
    /// flow appends it to what the bundle itself presented; a token object
    /// holds the envelope and nothing else, so nothing is appended and the
    /// path must be built from `[trust]` alone.
    ///
    /// The difference goes in the strict direction — the token presents fewer
    /// intermediates, never more — which is why it is checked rather than
    /// removed. An installation whose path only closed because of the file on
    /// the flash drive will stop authenticating when it moves to a token,
    /// until those intermediates are in the device's trust configuration.
    #[test]
    fn only_the_usb_carrier_adds_intermediates_from_beside_the_container() {
        let usb_cfg = minimal_cfg();
        let tmp = stage_p12_mount("leaf_rsa.p12", true);
        assert!(
            tmp.path().join("certs/chain.pem").exists(),
            "this pair is only honest if the USB side really carries a chain file"
        );
        let usb_io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let usb_verifier = RecordingVerifier::new();
        let usb = run_carrier(
            &usb_cfg,
            &usb_io,
            &usb_verifier,
            "host-T-hash",
            "correct-pin",
        );
        usb.outcome.expect("usb carrier authenticates");

        let token_cfg = token_carrier_cfg();
        let token_io = token_carrier_io("leaf_rsa.p12");
        let token_verifier = RecordingVerifier::new();
        let token = run_carrier(
            &token_cfg,
            &token_io,
            &token_verifier,
            "host-T-hash",
            "correct-pin",
        );
        token.outcome.expect("token carrier authenticates");

        let usb_presented = usb_verifier.presented_counts();
        let token_presented = token_verifier.presented_counts();
        assert_eq!(usb_presented.len(), 1, "one verification each");
        assert_eq!(token_presented.len(), 1);
        assert!(
            usb_presented[0] > token_presented[0],
            "the chain file beside the container must reach the verifier: usb presented \
             {usb_presented:?}, token presented {token_presented:?}"
        );
    }

    /// Everything after the envelope is the same code for both carriers, so
    /// the same container must produce the same verdict, the same prompts and
    /// the same session payload — differing only in what carried it.
    #[test]
    fn both_carriers_run_the_same_checks_after_the_envelope() {
        let verifier = build_verifier();

        let usb_cfg = minimal_cfg();
        // With the chain file present, so that the one input that legitimately
        // differs between the carriers is exercised rather than avoided by the
        // choice of fixture. The intermediates are in `[trust]` as well, which
        // is what the token carrier requires and what keeps the two outcomes
        // comparable at all.
        let tmp = stage_p12_mount("leaf_rsa.p12", true);
        let usb_io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let usb = run_carrier(&usb_cfg, &usb_io, &verifier, "host-T-hash", "correct-pin");

        let token_cfg = token_carrier_cfg();
        let token_io = token_carrier_io("leaf_rsa.p12");
        let token = run_carrier(
            &token_cfg,
            &token_io,
            &verifier,
            "host-T-hash",
            "correct-pin",
        );

        let usb_ctx = usb.outcome.expect("usb carrier").auth_ctx;
        let token_ctx = token.outcome.expect("token carrier").auth_ctx;

        assert_eq!(usb_ctx.cert_cn, token_ctx.cert_cn);
        assert_eq!(usb_ctx.cert_serial, token_ctx.cert_serial);
        assert_eq!(usb_ctx.cert_not_after, token_ctx.cert_not_after);
        assert_eq!(usb_ctx.cert_max_integrity, token_ctx.cert_max_integrity);
        assert_eq!(
            format!("{:?}", usb_ctx.cert_ident),
            format!("{:?}", token_ctx.cert_ident)
        );
        assert_eq!(usb_ctx.home_dir, token_ctx.home_dir);
        assert_eq!(usb_ctx.host_id, token_ctx.host_id);
        assert_eq!(
            usb_ctx.role.as_ref().map(|r| r.role.as_str()),
            token_ctx.role.as_ref().map(|r| r.role.as_str())
        );
        assert_eq!(
            usb_ctx.role.as_ref().map(|r| r.role_version),
            token_ctx.role.as_ref().map(|r| r.role_version)
        );
        assert_eq!(
            usb.prompts, token.prompts,
            "the container PIN is asked for the same way either side"
        );

        // What legitimately differs is the medium.
        assert_eq!(usb_ctx.usb_serial.as_deref(), Some("MOCK"));
        assert_eq!(token_ctx.usb_serial.as_deref(), Some(CARRIER_TOKEN_SERIAL));
        assert!(usb_ctx.usb_vid_pid.is_some());
        assert!(token_ctx.usb_vid_pid.is_none());
    }

    /// The PIN budget and the trust check must fail identically on both
    /// carriers: the checks after the envelope do not know where it came from.
    #[test]
    fn both_carriers_fail_the_same_way_after_the_envelope() {
        let verifier = build_verifier();

        let usb_cfg = minimal_cfg();
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let usb_io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let usb = run_carrier(&usb_cfg, &usb_io, &verifier, "host-T-hash", "wrong-pin");

        let token_cfg = token_carrier_cfg();
        let token_io = token_carrier_io("leaf_rsa.p12");
        let token = run_carrier(&token_cfg, &token_io, &verifier, "host-T-hash", "wrong-pin");

        let usb_err = usb.outcome.err().expect("a wrong PIN denies the login");
        let token_err = token.outcome.err().expect("a wrong PIN denies the login");
        assert!(matches!(usb_err, FlowError::MaxTries), "got {usb_err:?}");
        assert!(
            matches!(token_err, FlowError::MaxTries),
            "got {token_err:?}"
        );
        assert_eq!(usb.prompts.len(), 3, "the budget is three attempts");
        assert_eq!(
            usb.prompts, token.prompts,
            "the same prompts in the same order"
        );

        // The chain check is likewise unaware of the carrier.
        let foreign = build_verifier_with_a_foreign_anchor();
        let tmp = stage_p12_mount("leaf_rsa.p12", false);
        let usb_io = InMemoryFlowIo::new(tmp.path().to_path_buf());
        let usb = run_carrier(&usb_cfg, &usb_io, &foreign, "host-T-hash", "correct-pin");
        let token_io = token_carrier_io("leaf_rsa.p12");
        let token = run_carrier(
            &token_cfg,
            &token_io,
            &foreign,
            "host-T-hash",
            "correct-pin",
        );
        let usb_err = usb.outcome.err().expect("an unbuildable chain denies");
        let token_err = token.outcome.err().expect("an unbuildable chain denies");
        assert!(matches!(usb_err, FlowError::Trust(_)), "got {usb_err:?}");
        assert!(
            matches!(token_err, FlowError::Trust(_)),
            "got {token_err:?}"
        );
        assert_eq!(usb_err.pam_code(), token_err.pam_code());
    }

    /// Same verifier as [`build_verifier`] but anchored at an unrelated CA, so
    /// the fixture leaf has no path to a trusted root.
    fn build_verifier_with_a_foreign_anchor() -> OpensslVerifier {
        let ca = Certificate::from_pem(&fixture_bytes("ca_site.pem")).unwrap();
        OpensslVerifier::new(OpensslVerifierConfig {
            anchors: vec![ca],
            intermediates: vec![],
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

    /// A carrier that holds no usable credential must answer the same on both
    /// media. In a stack written as `[success=done authinfo_unavail=ignore
    /// default=die]` the difference between 9 and 7 is the difference between
    /// falling through to the next module and refusing the login, and a
    /// mistake made at issuance should not decide that by carrier type.
    #[test]
    fn a_carrier_without_a_usable_credential_answers_alike_on_both_media() {
        let usb_missing = FlowError::Discovery(DiscoveryError::P12NotFound {
            path: PathBuf::from("certs/user.p12"),
        });
        let label = || "tessera-credential".to_owned();
        let token_cases = [
            FlowError::Pkcs11(Pkcs11Error::DataObjectNotFound { label: label() }),
            FlowError::Pkcs11(Pkcs11Error::DataObjectNotPrivate { label: label() }),
            FlowError::Pkcs11(Pkcs11Error::DataObjectUnreadable {
                label: label(),
                attribute: "CKA_VALUE",
            }),
            FlowError::Pkcs11(Pkcs11Error::DataObjectAmbiguous {
                label: label(),
                count: 2,
            }),
        ];
        for token_case in token_cases {
            assert_eq!(
                token_case.pam_code(),
                usb_missing.pam_code(),
                "{token_case:?} must map like the USB carrier's missing credential"
            );
            assert_eq!(token_case.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
        }
    }

    /// The token that gets used is the one the ambiguity check passed, not the
    /// one the provider enumerated first. A flow that kept the arrival slot
    /// would present the PIN to a device the check never looked at.
    #[test]
    fn the_token_used_is_the_one_the_check_passed() {
        let cfg = token_carrier_cfg();
        let stub = StubPkcs11Io::new();
        // Arrival says slot 0; the configured selection matches only slot 3.
        *stub.on_wait.borrow_mut() = Some(Ok(StubPkcs11Io::slot_n(0)));
        *stub.matching.borrow_mut() = vec![StubPkcs11Io::slot_n(3)];

        // The stub cannot hand back a real session, so the read fails; which
        // slot it failed on is the point.
        let outcome = read_token_carrier_with(&stub, &cfg, CARRIER_LABEL, &mut |_| {
            Ok(SecretString::from("pin".to_string()))
        });
        assert!(outcome.is_err(), "the stub has no session to give");

        let used = stub.used_slots.borrow().clone();
        assert!(
            !used.is_empty(),
            "the flow must have operated on some slot: {used:?}"
        );
        assert!(
            used.iter().all(|s| *s == StubPkcs11Io::slot_n(3)),
            "every operation must use the checked slot, got {used:?}"
        );
    }

    /// A token present when the wait returned and gone by the time the
    /// selection is checked leaves nothing to read. Carrying the stale slot
    /// onward would surface the removal as whatever the provider raises on a
    /// dead handle, after the engineer has been asked for a PIN.
    #[test]
    fn a_token_that_vanished_between_the_wait_and_the_check_is_not_used() {
        let cfg = token_carrier_cfg();
        let stub = StubPkcs11Io::new();
        *stub.on_wait.borrow_mut() = Some(Ok(StubPkcs11Io::slot_n(0)));
        stub.matching.borrow_mut().clear();

        let prompts = std::cell::Cell::new(0_usize);
        let err = read_token_carrier_with(&stub, &cfg, CARRIER_LABEL, &mut |_| {
            prompts.set(prompts.get() + 1);
            Ok(SecretString::from("pin".to_string()))
        })
        .expect_err("there is no token left to read the carrier from");

        assert!(
            matches!(err, FlowError::Pkcs11(Pkcs11Error::NoTokenAvailable)),
            "got {err:?}"
        );
        assert_eq!(
            prompts.get(),
            0,
            "no PIN may be asked for a token that left"
        );
        assert!(
            stub.used_slots.borrow().is_empty(),
            "the stale slot must not be touched: {:?}",
            stub.used_slots.borrow()
        );
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
    }

    /// Which token carries the credential must come from the configuration.
    /// With a second token connected the flow has nothing to go on, and
    /// picking the first would let that token stand in for the carrier.
    #[test]
    fn two_matching_tokens_are_refused_before_the_pin_prompt() {
        let cfg = token_carrier_cfg();
        let stub = StubPkcs11Io::new();
        *stub.matching.borrow_mut() = vec![StubPkcs11Io::slot_n(0), StubPkcs11Io::slot_n(1)];

        let prompts = std::cell::Cell::new(0_usize);
        let err = read_token_carrier_with(&stub, &cfg, CARRIER_LABEL, &mut |_| {
            prompts.set(prompts.get() + 1);
            Ok(SecretString::from("unused".to_string()))
        })
        .expect_err("an ambiguous carrier must not be chosen for the operator");

        assert!(
            matches!(err, FlowError::TokenCarrierAmbiguous { count: 2 }),
            "got {err:?}"
        );
        assert_eq!(
            prompts.get(),
            0,
            "a search across tokens would present the PIN to a device that was never meant \
             to receive it"
        );
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
    }

    /// The refusal names what to do about it: the message is the only thing
    /// an engineer at a locked screen has to go on.
    #[test]
    fn the_ambiguity_refusal_names_the_key_that_resolves_it() {
        let shown = FlowError::TokenCarrierAmbiguous { count: 3 }.to_string();
        assert!(shown.contains("pkcs11_token_label"), "{shown}");
        assert!(shown.contains('3'), "{shown}");
    }

    /// One matching token is the unambiguous case and must go through: the
    /// guard is a check on the selection, not a new precondition on the flow.
    #[test]
    fn a_single_matching_token_is_read_without_complaint() {
        let cfg = token_carrier_cfg();
        let stub = StubPkcs11Io::new();
        assert_eq!(stub.matching.borrow().len(), 1);

        let err = read_token_carrier_with(&stub, &cfg, CARRIER_LABEL, &mut |_| {
            Ok(SecretString::from("pin".to_string()))
        })
        .expect_err("the stub cannot hand back a real session");
        assert!(
            !matches!(err, FlowError::TokenCarrierAmbiguous { .. }),
            "a single candidate is not ambiguous: got {err:?}"
        );
    }

    /// A token that reports no serial is refused before the engineer is asked
    /// for a PIN: it could never be matched by a removal event, so a session
    /// opened on it would survive the carrier being taken away.
    #[test]
    fn a_token_without_a_serial_is_refused_before_the_pin_prompt() {
        let cfg = token_carrier_cfg();
        let stub = StubPkcs11Io::new();
        *stub.on_serial.borrow_mut() = Some(Err(Pkcs11Error::TokenSerialMissing));

        let prompts = std::cell::Cell::new(0_usize);
        let err = read_token_carrier_with(&stub, &cfg, CARRIER_LABEL, &mut |_| {
            prompts.set(prompts.get() + 1);
            Ok(SecretString::from("unused".to_string()))
        })
        .expect_err("a serial-less token cannot carry a session");

        assert!(
            matches!(err, FlowError::Pkcs11(Pkcs11Error::TokenSerialMissing)),
            "got {err:?}"
        );
        assert_eq!(
            prompts.get(),
            0,
            "the PIN must not be spent on a token that was never usable"
        );
        assert_eq!(err.pam_code(), 9, "PAM_AUTHINFO_UNAVAIL");
    }

    /// And the refusal stops the whole authentication rather than falling
    /// back to another carrier.
    #[test]
    fn a_serial_less_token_stops_the_authentication() {
        let cfg = token_carrier_cfg();
        let io = InMemoryFlowIo::new(std::path::PathBuf::from("/nonexistent/never-mounted"));
        *io.token_carrier.borrow_mut() =
            Some(Err(FlowError::Pkcs11(Pkcs11Error::TokenSerialMissing)));

        let run = run_carrier(&cfg, &io, &build_verifier(), "host-T-hash", "correct-pin");
        let err = run.outcome.err().expect("authentication must not continue");
        assert!(
            matches!(err, FlowError::Pkcs11(Pkcs11Error::TokenSerialMissing)),
            "got {err:?}"
        );
        assert!(run.registered.is_empty(), "no session may be registered");
        assert_eq!(run.usb_waits, 0, "and no fallback to mass storage");
        assert_eq!(run.mounts, 0);
    }

    /// Strict monitoring promises that a session dies with its carrier. The
    /// daemon establishes a token's presence by polling the provider for its
    /// serial, so the promise is one this carrier can keep and the login is
    /// no longer refused at the dispatcher.
    #[test]
    fn strict_monitoring_is_accepted_for_the_token_carrier() {
        let mut cfg = token_carrier_cfg();
        cfg.monitor.fail_mode = tessera_core::config::validated::MonitorFailMode::Strict;
        let io = token_carrier_io("leaf_rsa.p12");

        let monitor = StubClient;
        let exec = tessera_core::hooks::NoopExecutor::new();
        let roles = RoleFixture::serv();
        let deps = Deps {
            cfg: &cfg,
            trust: &build_verifier(),
            monitor: &monitor,
            hook_executor: &exec,
            host_id_hash: "host-T-hash",
            host_id_source: HostIdSourceKind::Override,
            pam_target: tessera_proto::SessionTarget::Unknown,
            role_stage: roles.stage(),
            device_tags: empty_device_tags(),
        };
        let outcome = authenticate(
            deps,
            &io,
            RoleFixture::ACCOUNT,
            "ssh",
            "sess-strict-token".into(),
            |_| Ok(SecretString::from("correct-pin".to_string())),
        )
        .expect("strict presence is enforceable on a token carrier");

        assert!(
            io.token_carrier.borrow().is_none(),
            "the carrier object must actually be read, or the login was refused elsewhere"
        );
        assert_eq!(
            outcome.auth_ctx.usb_serial.as_deref(),
            Some(CARRIER_TOKEN_SERIAL),
            "the session must carry the token serial the presence monitor matches on"
        );
    }
}

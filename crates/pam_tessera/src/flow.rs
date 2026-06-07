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
use tessera_core::trust::openssl_verifier::Stage2TrustVerifier;
use tessera_core::usb::{UsbDevice, UsbError};
use tessera_core::x509::{Certificate, TrustError};
use secrecy::SecretString;

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
    /// | `Mapping`                                              | `PAM_PERM_DENIED` (6)      |
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
            // PAM_PERM_DENIED — cert chain rejected the auth.
            Self::Pkcs12(_) | Self::Crypto(_) | Self::Trust(_) | Self::Mapping(_) => 6,
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

    // Step 5 — PIN-retry loop.
    let loaded: LoadedKeyMaterial =
        match acquire_p12_material_with_prompter(&creds.p12_bytes, 3, &mut prompt_pin) {
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
    // certs without `pam_cert_user_binding` fall through to TOML.
    if tessera_core::x509::user_binding_ext::parse(loaded.end_entity.x509()).is_ok() {
        verify_user_binding(loaded.end_entity.x509(), pam_user)?;
    } else {
        let _matched: MatchedMapping =
            match_user(&loaded.end_entity, pam_user, deps.user_mappings)?;
    }

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
        cert_max_integrity,
        cert_ident,
        home_dir,
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
    // validated leaf, target from PAM_TTY). Failure stays non-fatal:
    // the auth itself already succeeded, and the FailModeWrapper around
    // the production client decides whether to swallow IPC errors.
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
    };
    if let Err(e) = deps.monitor.open_session(&info) {
        tracing::warn!(
            target: "tessera.flow",
            error = %e,
            "monitor open_session failed (non-fatal)"
        );
    }

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
    ) -> Result<
        tessera_core::token::pkcs11::Pkcs11Session,
        tessera_core::token::pkcs11::AcquireError,
    >;
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
    ) -> Result<tessera_core::token::pkcs11::Slot, tessera_core::token::pkcs11::Pkcs11Error>
    {
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
    ) -> Result<
        tessera_core::token::pkcs11::Pkcs11Session,
        tessera_core::token::pkcs11::AcquireError,
    > {
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
    let backend = tessera_core::token::pkcs11::Pkcs11Backend::load(
        module_path,
        cfg.pkcs11_locking_mode,
    )?;
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

    // Step 6 — find the matching private key (paired by CKA_ID).
    let key: FoundPrivateKey = session.find_private_key_for_cert(&cert)?;

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
    // wins over `[[user_mapping]]`; legacy path used when ext absent.
    if tessera_core::x509::user_binding_ext::parse(cert.certificate.x509()).is_ok() {
        verify_user_binding(cert.certificate.x509(), pam_user)?;
    } else {
        let _matched: MatchedMapping = match_user(&cert.certificate, pam_user, deps.user_mappings)?;
    }

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
        cert_max_integrity,
        cert_ident,
        home_dir,
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
    // daemon keys removal enforcement on.
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
    };
    if let Err(e) = deps.monitor.open_session(&info) {
        tracing::warn!(
            target: "tessera.flow",
            error = %e,
            "monitor open_session failed (non-fatal)"
        );
    }

    Ok(FlowOutcome {
        auth_ctx,
        mount: None,
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
    /// Optional VID/PID filter (none → accept any USB block device).
    pub vid_pid_filter: Option<(u16, u16)>,
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
        vid_pid_filter: Option<(u16, u16)>,
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
            self.vid_pid_filter,
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
    fn mkdir_mode_0700(
        &self,
        _path: &Path,
    ) -> Result<(), tessera_core::error::MountGuardError> {
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
fn p12_wrong_pin_diagnostic(p12_bytes: &[u8]) -> String {
    let Some(cert) = tessera_core::pkcs12::try_extract_cert_without_pin(p12_bytes) else {
        return "Пароль .p12 неверный. Проверьте флешку и попробуйте ещё раз.".to_string();
    };
    let host = match tessera_core::x509::host_binding_ext::parse(cert.x509()) {
        Ok(entries) => entries
            .iter()
            .map(|e| match e {
                tessera_core::x509::host_binding_ext::HostDescriptor::Wildcard => {
                    "*".to_string()
                }
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
                tessera_core::x509::user_binding_ext::UserDescriptor::Wildcard => {
                    "*".to_string()
                }
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
    use tessera_core::config::validated::{UserMapping, UserMatchCriteria};
    use tessera_core::host_identity::HostIdSourceKind;
    use tessera_core::ipc::StubClient;
    use tessera_core::trust::openssl_verifier::{OpensslVerifier, OpensslVerifierConfig};
    use std::time::Duration;

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
            clock_skew: Duration::from_secs(60),
            signature_alg_whitelist: vec![
                "sha256WithRSAEncryption".into(),
                "ecdsa-with-SHA256".into(),
            ],
            spki_pins: vec![],
            max_depth: 4,
            gost_engine_path: None,
        })
        .unwrap()
    }

    fn cn_mapping(user: &str, cn: &str) -> UserMapping {
        UserMapping {
            pam_user: user.to_string(),
            criteria: UserMatchCriteria::SubjectCn(cn.to_string()),
        }
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
anchors = []
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
syslog_facility = "auth"
journald_priority = false
"#;
        let raw: tessera_core::config::raw::RawConfig = toml::from_str(raw_toml).unwrap();
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
    // both extensions (max-permissive).

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
anchors = []
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
syslog_facility = "auth"
journald_priority = false
"#;
        let raw: tessera_core::config::raw::RawConfig = toml::from_str(raw_toml).unwrap();
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

    use tessera_core::hooks::{
        HookConfig as Stage5HookConfig, HookOutcome, HookStage as Stage5HookStage, OnFailure, RunAs,
    };
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Mock executor used by the Stage 5 wiring tests.
    struct MockExec {
        scripted: Mutex<
            std::collections::VecDeque<Result<HookOutcome, tessera_core::hooks::HookError>>,
        >,
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
}

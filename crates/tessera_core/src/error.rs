//! Error types used by the core crate.

use std::path::PathBuf;

/// Core result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level core error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error with human context.
    #[error("{context}: {source}")]
    Io {
        /// Operation context.
        context: String,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// TOML parse error.
    #[error("failed to parse config {path:?}: {source}")]
    ConfigParse {
        /// Config path.
        path: PathBuf,
        /// TOML error.
        #[source]
        source: toml::de::Error,
    },
    /// Invalid config.
    #[error("invalid config: {reason}")]
    ConfigInvalid {
        /// Reason.
        reason: String,
    },
    /// A file consumed by a privileged authentication path failed the
    /// root-ownership and path-integrity policy.
    #[error("{context}: {source}")]
    PrivilegedPath {
        /// What configuration input was being validated.
        context: String,
        /// Underlying ownership, mode, type, or race failure.
        #[source]
        source: crate::privileged_path::PrivilegedPathError,
    },
    /// `gost_engine_path` does not point to a readable file.
    #[error("gost_engine_path {path:?} is not a readable file: {source}")]
    GostEnginePathUnreadable {
        /// Configured path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `gost_engine_path` is configured but `crypto_backend` is not `openssl`.
    #[error("gost_engine_path is only meaningful with crypto_backend = \"openssl\"")]
    GostEnginePathRequiresOpenssl,
    /// Host identity error.
    #[error(transparent)]
    HostIdentity(#[from] HostIdentityError),
    /// Mount guard error.
    #[error(transparent)]
    MountGuard(#[from] MountGuardError),
    /// Hook validation error.
    #[error(transparent)]
    HookValidation(#[from] HookValidationError),
    /// Self-check error.
    #[error(transparent)]
    SelfCheck(#[from] SelfCheckError),
    /// Trust error.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// IPC error.
    #[error(transparent)]
    Ipc(#[from] IpcError),
    /// Other error.
    #[error("{reason}")]
    Other {
        /// Reason.
        reason: String,
    },
}

/// Host identity resolution errors.
#[derive(Debug, thiserror::Error)]
pub enum HostIdentityError {
    /// Read failed.
    #[error("failed to read {path:?}: {source}")]
    Read {
        /// Path read.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Source yielded an empty value.
    #[error("host identity source {source_kind:?} yielded empty value")]
    Empty {
        /// Source kind.
        source_kind: crate::host_identity::HostIdSourceKind,
    },
    /// All configured sources failed.
    #[error("all host identity sources failed")]
    AllSourcesFailed {
        /// Attempt summaries.
        attempts: Vec<(crate::host_identity::HostIdSourceKind, String)>,
    },
    /// Command failed.
    #[error("host identity command failed with code {code:?}: {stderr}")]
    CommandFailed {
        /// Captured stderr.
        stderr: String,
        /// Exit code.
        code: Option<i32>,
    },
    /// Command timed out.
    #[error("host identity command timed out")]
    CommandTimeout,
    /// The custom command path failed the privileged-execution ownership and
    /// integrity walk (not root-owned, group/other-writable, or swapped).
    /// Fail closed: a command root could be tricked into running as a
    /// non-root-controlled binary is refused rather than executed.
    #[error("host identity command failed path validation: {source}")]
    CommandUntrusted {
        /// Underlying validation failure.
        #[source]
        source: crate::privileged_path::PrivilegedPathError,
    },
    /// Command missing.
    #[error("custom command is not configured")]
    CommandNotConfigured,
    /// Override is forbidden.
    #[error("host identity override is forbidden")]
    OverrideForbidden,
}

/// Mount lifecycle errors.
#[derive(Debug, thiserror::Error)]
pub enum MountGuardError {
    /// Mount failed.
    #[error("failed to mount {target:?}: {source}")]
    Mount {
        /// Target path.
        target: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Umount failed.
    #[error("failed to umount {target:?}: {source}")]
    Umount {
        /// Target path.
        target: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Mkdir failed.
    #[error("failed to create {path:?}: {source}")]
    Mkdir {
        /// Path.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Rmdir failed.
    #[error("failed to remove {path:?}: {source}")]
    Rmdir {
        /// Path.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// Session id rejected.
    #[error("invalid session id: {reason}")]
    InvalidSessionId {
        /// Reason.
        reason: String,
    },
}

/// Hook validation errors.
#[derive(Debug, thiserror::Error)]
pub enum HookValidationError {
    /// Placeholder is not available at the hook stage.
    #[error("placeholder {var:?} is not allowed at {stage:?}")]
    PlaceholderNotAllowedAtStage {
        /// Stage.
        stage: crate::hooks::HookStage,
        /// Placeholder.
        var: crate::hooks::PlaceholderVar,
    },
    /// Command is empty.
    #[error("hook command is empty")]
    EmptyCommand,
    /// Command path is invalid.
    #[error("hook command path is invalid: {path}")]
    InvalidCommandPath {
        /// Path.
        path: String,
    },
    /// Timeout is invalid.
    #[error("hook timeout must be in 1..=120")]
    InvalidTimeout,
    /// `run_as` names an identity the module cannot map to a concrete UID.
    /// Only `root` and `user` (the authenticating PAM user) are recognized;
    /// anything else — a typo, or an account name the module does not resolve —
    /// is rejected rather than silently amplified to root.
    #[error("invalid run_as {value:?}: expected \"root\" or \"user\"")]
    InvalidRunAs {
        /// The unrecognized value from config.
        value: String,
    },
    /// Template error.
    #[error("{reason}")]
    Template {
        /// Reason.
        reason: String,
    },
}

/// Self-check errors.
#[derive(Debug, thiserror::Error)]
pub enum SelfCheckError {
    /// Anchor unreadable.
    #[error("anchor unreadable: {path:?}")]
    AnchorUnreadable {
        /// Path.
        path: PathBuf,
    },
    /// Anchor is not PEM-looking.
    #[error("anchor is not PEM-looking: {path:?}")]
    AnchorNotPem {
        /// Path.
        path: PathBuf,
    },
    /// CRL unreadable.
    #[error("CRL unreadable: {path:?}")]
    CrlUnreadable {
        /// Path.
        path: PathBuf,
    },
    /// CRL is not PEM-looking.
    #[error("CRL is not PEM-looking: {path:?}")]
    CrlNotPem {
        /// Path.
        path: PathBuf,
    },
    /// GOST engine is required by config but failed to load.
    ///
    /// Self-check fails closed: the PAM module will return
    /// `PAM_AUTHINFO_UNAVAIL` for every call, which is the correct
    /// behaviour when the trust whitelist mandates GOST signatures and
    /// the engine cannot service them.
    #[error("gost-engine is required but unavailable: {0}")]
    GostEngineUnavailable(#[from] crate::gost::GostEngineError),
    /// Hook command is missing.
    #[error("hook command missing for {stage:?}: {path:?}")]
    HookCommandMissing {
        /// Stage.
        stage: crate::hooks::HookStage,
        /// Path.
        path: PathBuf,
    },
    /// PKCS#11 module file is missing or unreadable.
    ///
    /// The wrapped string is human-readable context: either a path that
    /// doesn't exist on disk, or the [`crate::token::pkcs11::Pkcs11Error`]
    /// surface text from a `dlopen()` / `C_Initialize` failure.
    /// Self-check fails closed: the PAM module will return
    /// `PAM_AUTHINFO_UNAVAIL`, refusing the call rather than silently
    /// downgrading to PKCS#12.
    #[error("pkcs11 module unavailable: {0}")]
    Pkcs11ModuleMissing(String),
    /// PKCS#11 backend loaded successfully but no slot reports a
    /// present token at self-check time.
    ///
    /// **Not** fail-closed: in practice the user inserts the token after
    /// the PAM module starts (e.g. before typing their PIN), so a token
    /// being absent during `self_check` is informational, not fatal.  We
    /// log a WARN and return `Ok(())` — the actual auth flow will block
    /// on `wait_for_token` and surface a hard error there if the timeout
    /// elapses without a token appearing.
    ///
    /// Documented as a separate variant so future deployments can
    /// switch to fail-closed by editing one match arm.
    #[error("pkcs11 has no token present (self-check)")]
    Pkcs11NoToken,
}

/// Trust errors.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// Verifier is not implemented.
    #[error("trust verification is not implemented")]
    NotImplemented,
    /// No trust anchors configured.
    #[error("trust.anchors must not be empty: at least one trust anchor is required")]
    AnchorsEmpty,
    /// Anchor missing.
    #[error("anchor missing: {path:?}")]
    AnchorMissing {
        /// Path.
        path: PathBuf,
    },
    /// Anchor is not PEM-looking.
    #[error("anchor is not PEM-looking: {path:?}")]
    AnchorNotPem {
        /// Path.
        path: PathBuf,
    },
    /// Max chain depth is zero.
    #[error("max_chain_depth must be at least 1")]
    MaxChainDepthZero,
    /// Clock skew too large.
    #[error("clock skew is too large")]
    ClockSkewTooLarge,
    /// CRL path missing.
    #[error("CRL path missing: {path:?}")]
    CrlPathMissing {
        /// Path.
        path: PathBuf,
    },
    /// CRL revocation mode selected with no CRLs configured.
    #[error(
        "trust.revocation.mode = \"crl\" requires at least one entry in crl_paths; \
         an empty CRL set would make every certificate pass the revocation check"
    )]
    CrlPathsEmpty,
    /// OCSP responder invalid.
    #[error("OCSP responder invalid: {reason}")]
    OcspResponderInvalid {
        /// Reason.
        reason: String,
    },
    /// OCSP request could not be built.
    #[error("OCSP request build failed: {reason}")]
    OcspRequestBuild {
        /// Reason.
        reason: String,
    },
    /// OCSP transport failure (connect, write, read, premature close).
    #[error("OCSP transport error: {reason}")]
    OcspTransport {
        /// Reason.
        reason: String,
    },
    /// The overall OCSP exchange deadline (`ocsp_timeout_seconds`) elapsed.
    #[error("OCSP request timed out")]
    OcspTimeout,
    /// HTTP-level refusal: status != 200, chunked transfer encoding,
    /// missing/oversized `Content-Length`, or malformed response framing.
    #[error("OCSP HTTP error: {reason}")]
    OcspHttp {
        /// Reason.
        reason: String,
    },
    /// `OCSPResponse` failed to parse or is structurally unusable.
    #[error("OCSP response malformed: {reason}")]
    OcspMalformed {
        /// Reason.
        reason: String,
    },
    /// `OCSPResponseStatus` is not `successful`.
    #[error("OCSP responder refused the request: {status}")]
    OcspResponderRefused {
        /// Responder status as reported.
        status: String,
    },
    /// Responder signature does not verify against the trust anchors.
    #[error("OCSP response signature invalid: {reason}")]
    OcspSignatureInvalid {
        /// Reason.
        reason: String,
    },
    /// Response carries a nonce that does not match the request nonce.
    #[error("OCSP nonce mismatch")]
    OcspNonceMismatch,
    /// `thisUpdate`/`nextUpdate` window is invalid at verification time
    /// (with `clock_skew_seconds` tolerance already applied).
    #[error("OCSP response validity window check failed: {reason}")]
    OcspValidityWindow {
        /// Reason.
        reason: String,
    },
    /// Responder reported certificate status `unknown`.  Fail-closed:
    /// an undeterminable revocation status refuses authentication.
    #[error("OCSP status unknown for serial {serial}")]
    OcspStatusUnknown {
        /// Certificate serial (lowercase hex).
        serial: String,
    },
    /// gost-engine could not be loaded for OCSP response verification.
    /// Fail-closed: a GOST responder chain cannot be verified without the
    /// engine, so the revocation status stays undeterminable and
    /// authentication is refused.
    #[error("gost-engine unavailable for OCSP response verification: {source}")]
    OcspEngineUnavailable {
        /// Underlying engine load failure.
        #[source]
        source: crate::gost::GostEngineError,
    },
    /// Pinning hash invalid.
    #[error("pinning hash invalid: {entry}")]
    PinningHashInvalid {
        /// Entry.
        entry: String,
    },
    /// A `[[trust_override]]` entry lists no anchors. An override replaces the
    /// global trust anchors for the hosts it names; an empty replacement would
    /// either silently widen trust back to the global set or leave the verifier
    /// with no anchors at all. Both defeat the purpose of narrowing trust, so
    /// the entry is rejected at configuration time.
    #[error(
        "trust_override.anchors must not be empty: an override that narrows trust \
         to no anchor cannot be satisfied; give it at least one anchor or remove it"
    )]
    TrustOverrideAnchorsEmpty,
    /// Two `[[trust_override]]` entries both claim the same host id. The
    /// applicable anchor set would be ambiguous for that host at runtime, so
    /// the overlap is rejected at configuration time rather than resolved by
    /// silently picking one entry.
    #[error(
        "trust_override.when_host_id_in overlap: host id {host_id:?} appears in more \
         than one [[trust_override]] entry; each host may match at most one override"
    )]
    TrustOverrideHostIdOverlap {
        /// The normalized host id claimed by more than one override.
        host_id: String,
    },
    /// A `[[trust_override]]` entry lists a host id that is empty once
    /// normalized (e.g. only whitespace or colons). The runtime host-id
    /// resolver rejects an empty normalized id, so such a candidate can never
    /// match a real host: the override would silently never fire and the host
    /// would fall back to the broader global anchors — the opposite of the
    /// narrowing the operator intended. Reject it at load time.
    #[error(
        "trust_override.when_host_id_in contains {raw:?}, which is empty after \
         normalization and can never match a host; remove it or give a real host id"
    )]
    TrustOverrideHostIdEmpty {
        /// The offending raw host id as written in the config.
        raw: String,
    },
}

/// IPC errors.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Not connected.
    #[error("not connected")]
    NotConnected,
    /// Legacy framing error (newline-delimited JSON encode failure).
    #[error(transparent)]
    Encode(#[from] tessera_proto::FramingError),
    /// New wire-layer error (`encode_message` / `decode_line`).
    #[error(transparent)]
    Wire(#[from] tessera_proto::WireError),
    /// JSON decode failed.
    #[error("decode: {0}")]
    Decode(serde_json::Error),
    /// I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Connect/send/recv exceeded the configured time budget.
    #[error("monitord timeout")]
    Timeout,
    /// Daemon is not reachable (socket missing / connect refused).
    #[error("monitord unavailable")]
    Unavailable,
    /// Daemon refused our protocol version.
    #[error("protocol mismatch server={server}")]
    ProtocolMismatch {
        /// Version the server reports.
        server: u32,
    },
    /// `SessionOpen` race lost: the USB device referenced by the session is
    /// no longer plugged in.
    #[error("device gone")]
    DeviceGone,
    /// Daemon rejected our connection (likely `SCM_CREDENTIALS` uid != 0).
    #[error("unauthorized")]
    Unauthorized,
    /// PAM module's monitor is disabled in config (`monitor.enabled = false`).
    #[error("monitor disabled")]
    Disabled,
    /// Daemon returned an unexpected message in response to our request.
    #[error("unexpected reply: {0}")]
    UnexpectedReply(String),
    /// Peer returned a typed protocol error (legacy enum form).
    #[error("protocol error {code:?}: {message}")]
    Protocol {
        /// Code.
        code: tessera_proto::ServerErrorCode,
        /// Message.
        message: String,
    },
    /// Server returned a generic error frame.
    #[error("server error {code}: {message}")]
    Server {
        /// Numeric code (see [`tessera_proto::error_codes`]).
        code: u32,
        /// Human-readable message.
        message: String,
    },
}

impl From<serde_json::Error> for IpcError {
    fn from(value: serde_json::Error) -> Self {
        IpcError::Decode(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_includes_source_chain() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err = Error::Io {
            context: "anchor".into(),
            source: inner,
        };
        let s = format!("{err}");
        assert!(s.contains("anchor"));
        assert!(s.contains("missing"));
    }
}

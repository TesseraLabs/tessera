//! Typed error enum for the PKCS#11 backend.
//!
//! `cryptoki` exposes a single `cryptoki::error::Error` variant that
//! conflates library-loading, FFI null-pointer and PIN-related failures.
//! We narrow that surface into [`Pkcs11Error`] so the PAM layer can map
//! token states (locked / wrong PIN / device removed) onto the right PAM
//! return codes without string-matching the upstream `Display` output.
//!
//! No PIN, nonce, signature byte, or `CKA_VALUE` payload is ever stored in
//! these variants — we only carry typed source errors and metadata that is
//! safe to log (paths, labels, durations).

use std::path::PathBuf;

use thiserror::Error;

/// Errors raised by the `tessera_core::token::pkcs11` module.
///
/// Each variant has a documented mapping to a PAM return code; the
/// high-level rules are:
///
/// - [`Pkcs11Error::PinIncorrect`] — drives the retry loop in
///   [`super::pin_loop::acquire_pkcs11_session`]; never reaches PAM directly.
/// - [`Pkcs11Error::PinLocked`] — short-circuits to `PAM_MAXTRIES` with an
///   ALERT log line.
/// - [`Pkcs11Error::TokenWaitTimeout`] — maps to `PAM_AUTHTOK_RECOVER_ERR`
///   so PAM can advise the user to re-insert the token.
/// - Everything else — `PAM_AUTH_ERR`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Pkcs11Error {
    /// The configured `pkcs11_module_path` does not exist on disk.  We
    /// distinguish this from a generic `dlopen()` failure so configuration
    /// validation can produce a clearer error message.
    #[error("pkcs#11 module path missing: {0}")]
    ModulePathMissing(PathBuf),
    /// `cryptoki::Pkcs11::new()` failed to load the dynamic library.  This
    /// covers missing dependencies, ABI mismatch and permission errors.
    #[error("pkcs#11 module load failed for {path}: {source}")]
    ModuleLoadFailed {
        /// Module path passed to `Pkcs11Backend::load`, kept for log
        /// correlation.
        path: PathBuf,
        /// Underlying `cryptoki` error (typically a `LibraryLoading` variant).
        #[source]
        source: cryptoki::error::Error,
    },
    /// `C_Initialize` failed.  Usually means the library has already been
    /// initialized in this process by another consumer.
    #[error("pkcs#11 C_Initialize failed: {source}")]
    InitFailed {
        /// Underlying `cryptoki` error.
        #[source]
        source: cryptoki::error::Error,
    },
    /// No slot with a present token was reported by `C_GetSlotList`.
    #[error("no pkcs#11 slot with present token")]
    NoTokenAvailable,
    /// At least one slot was present but none matched the requested label.
    #[error("pkcs#11 token with label {label:?} not found")]
    TokenNotFound {
        /// User-supplied `pkcs11_token_label` value.
        label: String,
    },
    /// `Pkcs11Backend::wait_for_token` exhausted its polling deadline
    /// without finding a matching token.
    #[error("pkcs#11 token wait timed out after {seconds}s")]
    TokenWaitTimeout {
        /// Configured timeout in seconds, for log correlation.
        seconds: u64,
    },
    /// `C_OpenSession` (or any subsequent setup before `C_Login`) failed.
    #[error("pkcs#11 session open failed: {source}")]
    SessionOpenFailed {
        /// Underlying `cryptoki` error.
        #[source]
        source: cryptoki::error::Error,
    },
    /// The PIN supplied to `C_Login` was rejected (`CKR_PIN_INCORRECT`).
    /// Caller is expected to drive a bounded retry loop on this variant.
    #[error("pkcs#11 PIN incorrect")]
    PinIncorrect,
    /// The token has locked itself out (`CKR_PIN_LOCKED`).  No further PIN
    /// attempts are possible until the user goes through unblock.
    #[error("pkcs#11 PIN locked")]
    PinLocked,
    /// `C_Logout` failed during normal cleanup.  Surfaced from RAII tests;
    /// production `Drop` swallows the error and logs a WARN.
    #[error("pkcs#11 C_Logout failed: {source}")]
    LogoutFailed {
        /// Underlying `cryptoki` error.
        #[source]
        source: cryptoki::error::Error,
    },
    /// `C_CloseSession` failed during normal cleanup.  Surfaced from RAII
    /// tests; production `Drop` swallows the error and logs a WARN.
    #[error("pkcs#11 C_CloseSession failed: {source}")]
    CloseSessionFailed {
        /// Underlying `cryptoki` error.
        #[source]
        source: cryptoki::error::Error,
    },
    /// `find_certificate` (T08) returned zero parseable certificate
    /// objects from the token.  `label_filter` echoes the user-supplied
    /// `pkcs11_token_label` when set, for log correlation.
    #[error("pkcs#11 certificate not found (label_filter={label_filter:?})")]
    CertificateNotFound {
        /// Optional label that was used to narrow the search.
        label_filter: Option<String>,
    },
    /// A certificate object had no `CKA_VALUE` attribute readable.
    /// Surfaced from the pure parse path; production callers also log
    /// a WARN and try the next candidate.
    #[error("pkcs#11 certificate object has no CKA_VALUE")]
    CertificateValueMissing,
    /// `Certificate::from_der` rejected the bytes returned by the
    /// token.  The inner string is the formatted parse error from
    /// OpenSSL; we keep it un-typed because the upstream
    /// [`crate::x509::TrustError::CertParse`] already wraps it.
    #[error("pkcs#11 certificate value did not parse: {0}")]
    CertificateParseFailed(String),
    /// `find_private_key_for_cert` (T09) returned no match for the
    /// supplied `CKA_ID`.  `cka_id_hex` is a short hex prefix used for
    /// log correlation — never the full identifier.
    #[error("pkcs#11 private key not found for cka_id prefix {cka_id_hex}")]
    PrivateKeyNotFound {
        /// Short hex prefix of the searched-for `CKA_ID` (no full bytes).
        cka_id_hex: String,
    },
    /// A matched private-key object had no `CKA_KEY_TYPE` attribute,
    /// which makes mechanism selection impossible.
    #[error("pkcs#11 private key has no CKA_KEY_TYPE")]
    KeyTypeAttributeMissing,
    /// The matched private key reports `CKA_EXTRACTABLE = TRUE` and the
    /// operator did not opt in via `pkcs11_allow_extractable_keys`.  An
    /// extractable key breaks the mode-B invariant (key never leaves the
    /// token), so the default is to refuse it (fail-closed).  Carries only
    /// log-safe metadata: the key type and a short `CKA_ID` hex prefix —
    /// never key material.
    #[error(
        "pkcs#11 private key is extractable (CKA_EXTRACTABLE=TRUE), rejected: \
         key_type={key_type}, cka_id prefix {cka_id_hex}; \
         set pkcs11_allow_extractable_keys = true to override"
    )]
    ExtractableKeyRejected {
        /// Stringified `CKA_KEY_TYPE` of the offending key.
        key_type: String,
        /// Short hex prefix of the key's `CKA_ID` (never the full bytes).
        cka_id_hex: String,
    },
    /// `read_token_serial` (T10) found `CK_TOKEN_INFO.serialNumber`
    /// empty after trimming.  Some providers blank this on cleared
    /// tokens; we abort because the serial is required to populate
    /// `AuthContext.usb_serial` in mode B.
    #[error("pkcs#11 token serial empty")]
    TokenSerialMissing,
    /// `select_mechanism` (T11) saw a key type outside the supported
    /// matrix (RSA / EC P-256/P-384 / GOSTR3410).
    #[error("pkcs#11 unsupported key type: {key_type}")]
    UnsupportedKeyType {
        /// Stringified `KeyType`, kept for log correlation.
        key_type: String,
    },
    /// A supported key type maps to a PKCS#11 mechanism that the
    /// binding crate does not expose (e.g. cryptoki 0.7 has no GOST
    /// signing variant).
    #[error("pkcs#11 mechanism not supported: {mechanism}")]
    MechanismNotSupported {
        /// Stringified mechanism identifier.
        mechanism: String,
    },
    /// The token's public key is below the minimum accepted strength (e.g.
    /// sub-2048-bit RSA).  Refused during mechanism selection so a weak key is
    /// never driven through the token's `C_Sign`.
    #[error("pkcs#11 weak public key: {detail}")]
    WeakKey {
        /// Human-readable reason the key was rejected (algorithm and size).
        detail: String,
    },
    /// Bridge variant for OpenSSL errors during mechanism selection
    /// (e.g. `pubkey.ec_key()` when the leaf cert is malformed).
    #[error("pkcs#11 openssl error: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    /// Catch-all for any other `cryptoki` error that has no first-class
    /// variant in this enum.  Subsequent stage-4 tasks may promote
    /// additional variants out of this bucket as the surface grows.
    #[error("pkcs#11 cryptoki error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),
}

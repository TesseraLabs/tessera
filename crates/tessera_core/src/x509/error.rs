//! Error type emitted by X.509 parsing, pre-validation, path building,
//! and signature verification.
//!
//! This is a richer enum than the stage-1 `crate::error::TrustError` and is
//! intentionally kept separate so that the legacy stub interface can keep
//! returning the simpler variant set while the new stage-2 code uses this
//! one.

use thiserror::Error;

/// Errors raised by the trust-verification subsystem (stage 2).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TrustError {
    /// Failed to decode the certificate from PEM/DER.
    #[error("certificate parse error: {0}")]
    CertParse(String),

    /// A required certificate field is missing.
    #[error("certificate field missing: {0}")]
    FieldMissing(&'static str),

    /// Certificate validity window mismatch (not yet valid / expired / etc.).
    #[error("validity error: {0}")]
    Validity(&'static str),

    /// Signature algorithm OID not in the configured whitelist.
    #[error("signature algorithm not allowed: {0}")]
    SignatureAlgorithm(String),

    /// `keyUsage` extension lacks a required bit.
    #[error("key usage missing required bit")]
    KeyUsage,

    /// `extendedKeyUsage` extension lacks `clientAuth`.
    #[error("extended key usage does not include clientAuth")]
    Eku,

    /// `basicConstraints` extension is incompatible with this position
    /// in the chain (e.g. CA=TRUE on a leaf or CA=FALSE on an intermediate).
    #[error("basic constraints violation: {0}")]
    BasicConstraints(&'static str),

    /// Path building could not assemble a chain to a known anchor.
    #[error("path building failed: {0}")]
    PathBuild(&'static str),

    /// Chain depth exceeded the configured maximum.
    #[error("chain depth exceeded: {0} > {1}")]
    DepthExceeded(usize, usize),

    /// Anchor presented by chain assembly is not in the configured trust store.
    #[error("anchor mismatch: presented anchor not in trust store")]
    AnchorMismatch,

    /// Signature verification of an inner chain link failed.
    #[error("signature verification failed at depth {0}")]
    BadSignature(usize),

    /// CRL parsing or processing failure (parse error, malformed time, etc.).
    #[error("CRL error: {0}")]
    Crl(String),

    /// A certificate's serial appears in a configured CRL.
    #[error("certificate revoked: serial={0}")]
    Revoked(String),

    /// A CRL's signature failed to verify under its issuer's public key.
    ///
    /// Treated as the same class of refusal as [`TrustError::Revoked`]:
    /// a CRL whose signature cannot be proven authentic must not be
    /// trusted, and authentication fails closed rather than silently
    /// skipping the revocation check.
    #[error("CRL signature invalid: {0}")]
    CrlSignatureInvalid(String),

    /// No fresh, authentic, in-scope CRL covers this non-anchor certificate.
    /// Treated as the same class of refusal as [`TrustError::Revoked`]: in pure
    /// `crl` revocation mode an indeterminable status must fail closed, never
    /// pass. Carries the certificate serial (lowercase hex).
    #[error("no in-scope CRL covers certificate: serial={0}")]
    CrlNotCovered(String),

    /// SPKI pin mismatch — the trust anchor's `SubjectPublicKeyInfo` SHA-256
    /// is not in the configured set of pinned hashes.
    #[error("SPKI pin mismatch")]
    PinMismatch,

    /// Underlying OpenSSL error.
    #[error("openssl error: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),

    /// gost-engine could not be loaded for chain verification.
    ///
    /// Surfaced when at least one certificate in the verified chain (or one
    /// of the configured anchors) carries a GOST signature algorithm and the
    /// engine has not been pinned successfully.
    #[error("gost-engine unavailable for chain verification: {source}")]
    EngineLoadFailed {
        /// Underlying engine load failure.
        #[source]
        source: crate::gost::GostEngineError,
    },

    /// An OCSP revocation check could not determine the certificate status
    /// (responder unreachable, malformed/`unknown` answer, signature or
    /// nonce failure, etc.).  Carries the stringified
    /// [`crate::error::TrustError`] from the OCSP subsystem.  Fail-closed:
    /// any inability to determine OCSP status refuses authentication.
    #[error("OCSP error: {0}")]
    Ocsp(String),

    /// A certificate in the chain declares a `pam_cert_profile_version`
    /// greater than the Engine's `max_supported_profile_version`.  Fail-closed
    /// version gate: a newer-format certificate is refused rather than
    /// interpreted with stale rules (design decision 5, layer 2).
    #[error("profile_version {found} exceeds supported maximum {max}")]
    ProfileVersionUnsupported {
        /// The version declared by the certificate.
        found: u32,
        /// The maximum version this Engine understands.
        max: u32,
    },

    /// A certificate in the chain carries a `pam_cert_profile_version`
    /// extension whose body is malformed.  Fail-closed.
    #[error("malformed profile_version extension: {0}")]
    ProfileVersionMalformed(String),

    /// A certificate in the chain carries a `critical` extension whose OID is
    /// not in the Engine's known-critical allowlist.  Per RFC 5280 §4.2 an
    /// unrecognised critical extension MUST cause rejection (`PwnKit`
    /// fail-closed; design decision 5, layer 1).
    #[error("unhandled critical extension: {0}")]
    UnhandledCriticalExtension(String),
}

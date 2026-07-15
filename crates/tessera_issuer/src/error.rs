//! The issuance error type.

use tessera_ext::delegation::ScopeDimension;

use crate::sign::{SignError, SignatureAlgorithm};

/// Everything that can stop an issuance before an artifact is returned.
///
/// Every variant is fail-closed: the issuer produces a certificate or CRL only
/// when none of these apply. The scope/monotonicity and self-check variants
/// name the exact dimension or reason so an operator can correct the request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssueError {
    /// A leaf request had an empty `host_binding` — the extension is mandatory
    /// and must bind at least one host descriptor.
    #[error("leaf profile is missing a host_binding entry")]
    MissingHostBinding,
    /// A leaf request had an empty `user_binding` — the extension is mandatory.
    #[error("leaf profile is missing a user_binding entry")]
    MissingUserBinding,
    /// `not_after` was not strictly after `not_before`.
    #[error("validity is empty or inverted: not_before {not_before} .. not_after {not_after}")]
    InvalidValidity {
        /// The requested `not_before`, Unix seconds.
        not_before: u64,
        /// The requested `not_after`, Unix seconds.
        not_after: u64,
    },
    /// The subject distinguished name could not be parsed (RFC 4514).
    #[error("invalid subject distinguished name: {0}")]
    InvalidSubject(String),
    /// The supplied subject public key info was not valid DER.
    #[error("invalid subject public key info: {0}")]
    InvalidSpki(String),
    /// The parent certificate could not be walked for its name or envelope.
    #[error("invalid parent certificate: {0}")]
    InvalidParentCertificate(String),
    /// A leaf issuance was requested under a CA that carries no delegation
    /// envelope, so the leaf cannot be bounded.
    #[error("parent CA carries no delegation envelope to bound the leaf")]
    ParentEnvelopeMissing,
    /// The child envelope widens the parent along the named dimension (CA
    /// issuance), or a leaf field exceeds the parent envelope.
    #[error("requested scope widens the parent envelope along {0}")]
    ScopeWidened(ScopeDimension),
    /// A leaf `max_integrity` level exceeds the parent CA's ceiling.
    #[error("leaf max_integrity level {requested} exceeds parent ceiling {ceiling}")]
    IntegrityExceedsParent {
        /// The requested integrity level.
        requested: i8,
        /// The parent CA's `max_level` ceiling.
        ceiling: i8,
    },
    /// A leaf validity is longer than the parent CA's `max_ttl`.
    #[error("leaf validity {requested_secs}s exceeds parent max_ttl {max_ttl}s")]
    ValidityExceedsParent {
        /// The leaf's validity duration in seconds.
        requested_secs: u64,
        /// The parent CA's `max_ttl` ceiling in seconds.
        max_ttl: u64,
    },
    /// The proposed `crlNumber` did not exceed the last one issued.
    #[error("crlNumber {proposed} does not exceed last issued; minimum is {minimum}")]
    CrlNumberNotIncreasing {
        /// The `crlNumber` the request proposed.
        proposed: u64,
        /// The smallest acceptable next `crlNumber`.
        minimum: u64,
    },
    /// A DER build or standard-component encoding failed.
    #[error("der encoding: {0}")]
    Encoding(String),
    /// A shared-extension parse failed while reading the parent or self-checking
    /// the artifact.
    #[error("extension codec: {0}")]
    ExtCodec(#[from] tessera_ext::der::DerError),
    /// The signing backend failed.
    #[error("signing: {0}")]
    Sign(#[from] SignError),
    /// The backend signed with a different algorithm than it declared, so the
    /// TBS `signature` field and the outer signature would disagree.
    #[error("backend signed with {returned:?} but declared {declared:?}")]
    AlgorithmMismatch {
        /// The algorithm the TBS was built for.
        declared: SignatureAlgorithm,
        /// The algorithm the signature came back with.
        returned: SignatureAlgorithm,
    },
    /// The assembled artifact failed the post-sign self-check against the shared
    /// parsers — it is discarded rather than returned.
    #[error("self-check rejected the assembled artifact: {0}")]
    SelfCheckFailed(String),
    /// A CSR (PKCS#10) could not be parsed as PEM or DER.
    #[error("invalid CSR: {0}")]
    CsrParse(String),
    /// A CSR was signed with an algorithm the issuer does not verify (only
    /// ECDSA-P256/SHA-256 and RSA-PKCS1v1.5/SHA-256 are supported).
    #[error("unsupported CSR signature algorithm: {0}")]
    CsrUnsupportedAlgorithm(String),
    /// A CSR's public key could not be read as the algorithm its signature
    /// declared.
    #[error("invalid CSR public key: {0}")]
    CsrInvalidKey(String),
    /// A CSR's RSA public key is below the minimum accepted modulus size, so it
    /// is refused before issuance.
    #[error("CSR RSA key too weak: {bits}-bit modulus, minimum is {minimum}")]
    CsrWeakRsaKey {
        /// The CSR key's modulus size in bits.
        bits: u64,
        /// The smallest accepted modulus size in bits.
        minimum: u64,
    },
    /// A CSR's self-signature did not verify under its own public key, so
    /// proof of possession failed and no certificate is issued.
    #[error("CSR proof-of-possession failed: self-signature does not verify")]
    CsrProofOfPossession,
    /// The issuance could not be journaled, so the artifact is withheld
    /// (fail-closed).
    #[error("journal: {0}")]
    Journal(#[from] crate::journal::JournalError),
}

impl From<der::Error> for IssueError {
    fn from(err: der::Error) -> Self {
        IssueError::Encoding(err.to_string())
    }
}

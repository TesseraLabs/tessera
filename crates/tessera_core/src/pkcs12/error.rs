//! Errors raised when loading PKCS#12 bundles or driving the PIN-retry
//! acquisition loop.

use thiserror::Error;

use crate::pam_conv::PamConvError;

/// Errors raised by [`crate::pkcs12::LoadedKeyMaterial::from_p12`].
///
/// `WrongPin` is intentionally distinct from `Corrupt` so the caller can drive
/// a bounded retry loop on `WrongPin` while bailing out on every other variant.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Pkcs12Error {
    /// MAC verification failed — the supplied PIN does not match the bundle.
    #[error("wrong PIN")]
    WrongPin,
    /// The bundle does not contain a private key.
    #[error("missing private key in p12")]
    MissingKey,
    /// The bundle does not contain an end-entity certificate.
    #[error("missing leaf certificate in p12")]
    MissingCert,
    /// Any other parse failure (truncated DER, unsupported algorithm, ...).
    #[error("corrupt p12: {0}")]
    Corrupt(String),
}

/// Errors raised by the bounded PIN-retry acquisition loop.
///
/// The PAM layer maps `MaxTries` to `PAM_MAXTRIES` and `Conv` / `Corrupt` /
/// `Missing` to `PAM_AUTH_ERR` / `PAM_CRED_INSUFFICIENT` per the threat model.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AcquireError {
    /// All allowed PIN attempts were exhausted.
    #[error("max PIN tries exceeded")]
    MaxTries,
    /// The PAM conversation function failed or is unavailable.
    #[error("PAM conversation error: {0}")]
    Conv(#[from] PamConvError),
    /// The bundle is structurally invalid — retrying the PIN will not help.
    #[error("p12 corrupt: {0}")]
    Corrupt(String),
    /// The bundle is well-formed but missing a required field (key/cert).
    #[error("p12 missing data: {0}")]
    Missing(&'static str),
}

/// Error raised when the outer ASN.1 envelope of a `.p12` file fails to
/// parse — i.e. the bytes are not actually a PKCS#12 bundle.
///
/// This is intentionally separate from [`Pkcs12Error`] / [`AcquireError`]:
/// "this is not a P12" is decided without ever touching the user's PIN, so
/// it is safe to use as a signal for "skip this partition and try the next
/// one" without creating a PIN-oracle.  Errors that require the password
/// (MAC verify failure, decrypt failure) stay in [`Pkcs12Error`] and must
/// remain fail-closed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum P12EnvelopeError {
    /// The buffer is not a syntactically valid PKCS#12 ASN.1 structure.
    #[error("PKCS#12 ASN.1 parse failed: {0}")]
    Asn1(String),
}

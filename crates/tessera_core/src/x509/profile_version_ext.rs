//! Extracts the `pam_cert_profile_version` X.509 extension from a verified
//! certificate.  Trust boundary: the caller must already have validated the
//! chain — see [`VerifiedX509`].
//!
//! ASN.1: `extnValue ::= INTEGER` — the certificate-format version.  The
//! version-gate comparison against `max_supported_profile_version` lives in
//! `trust-chain-validation`; this module covers only the wire format and
//! extraction.  Parsing is fail-closed: an extension that is present but whose
//! body is not a well-formed, in-range DER `INTEGER` rejects the certificate.

use super::der_helpers::{extract_extension_by_oid, parse_integer_only_i64};
use super::oids::PROFILE_VERSION_OID;
use super::VerifiedX509;

/// Errors returned from [`extract_profile_version`].
#[derive(Debug, thiserror::Error)]
pub enum ProfileVersionExtError {
    /// Cert DER could not be re-serialised by `openssl`.
    #[error("cert DER serialisation: {0}")]
    CertDer(String),
    /// Extension lookup encountered malformed cert DER.
    #[error("cert extension scan: {0}")]
    Scan(String),
    /// Extension present but DER body unparseable.
    #[error("parse: {0}")]
    Parse(String),
    /// The version integer is negative — versions are unsigned.
    #[error("negative profile_version: {0}")]
    Negative(i64),
}

/// Returns `Ok(Some(version))` if the cert carries a valid
/// `pam_cert_profile_version` extension, `Ok(None)` if it is absent, or `Err`
/// if present but malformed.
///
/// The version is a DER `INTEGER`; it is decoded fail-closed and must be
/// non-negative (a negative version is malformed).  The upper-bound comparison
/// against `max_supported_profile_version` is performed elsewhere (the chain
/// verifier in `trust-chain-validation`).
///
/// # Errors
/// See [`ProfileVersionExtError`].
pub fn extract_profile_version(cert: &VerifiedX509) -> Result<Option<u32>, ProfileVersionExtError> {
    let der = cert
        .as_x509()
        .to_der()
        .map_err(|e| ProfileVersionExtError::CertDer(e.to_string()))?;
    let value = match extract_extension_by_oid(&der, PROFILE_VERSION_OID) {
        Ok(Some(v)) => v,
        Ok(None) => return Ok(None),
        Err(e) => return Err(ProfileVersionExtError::Scan(e.to_string())),
    };
    let version =
        parse_integer_only_i64(&value).map_err(|e| ProfileVersionExtError::Parse(e.to_string()))?;
    let version = u32::try_from(version).map_err(|_| ProfileVersionExtError::Negative(version))?;
    Ok(Some(version))
}

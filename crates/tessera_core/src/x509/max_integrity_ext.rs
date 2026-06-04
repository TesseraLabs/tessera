//! Extracts the `MAX_INTEGRITY` X.509 extension from a verified leaf
//! certificate.  Trust boundary: caller must already have validated the
//! chain — see [`VerifiedX509`].

use super::der_helpers::extract_extension_by_oid;
use super::oids::MAX_INTEGRITY_OID;
use super::VerifiedX509;
use crate::mac::label::LabelDerError;
use crate::mac::IntegrityLabel;

/// Errors returned from [`extract_max_integrity`].
#[derive(Debug, thiserror::Error)]
pub enum MaxIntegrityExtError {
    /// Cert DER could not be re-serialised by `openssl`.
    #[error("cert DER serialisation: {0}")]
    CertDer(String),
    /// Extension lookup encountered malformed cert DER.
    #[error("cert extension scan: {0}")]
    Scan(String),
    /// Extension present but DER body unparseable.
    #[error("parse: {0}")]
    Parse(#[from] LabelDerError),
}

/// Returns `Ok(Some(label))` if the cert carries a valid `MAX_INTEGRITY`
/// extension, `Ok(None)` if it is absent, or `Err` if present but malformed.
///
/// # Errors
/// See [`MaxIntegrityExtError`].
pub fn extract_max_integrity(
    cert: &VerifiedX509,
) -> Result<Option<IntegrityLabel>, MaxIntegrityExtError> {
    let der = cert
        .as_x509()
        .to_der()
        .map_err(|e| MaxIntegrityExtError::CertDer(e.to_string()))?;
    let value = match extract_extension_by_oid(&der, MAX_INTEGRITY_OID) {
        Ok(Some(v)) => v,
        Ok(None) => return Ok(None),
        Err(e) => return Err(MaxIntegrityExtError::Scan(e.to_string())),
    };
    let label = IntegrityLabel::from_der(&value)?;
    Ok(Some(label))
}

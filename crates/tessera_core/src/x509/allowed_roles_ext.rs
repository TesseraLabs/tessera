//! Extracts the `pam_cert_allowed_roles` X.509 extension from a verified leaf
//! certificate.  Trust boundary: caller must already have validated the
//! chain — see [`VerifiedX509`].
//!
//! ASN.1: `extnValue ::= SEQUENCE OF UTF8String`, each entry a `role_id` the
//! leaf is allowed to activate.  Parsing is fail-closed: a malformed DER body
//! or *any* invalid `role_id` rejects the whole extension (it is not a
//! best-effort skip-one-string parse).  An empty `SEQUENCE` is a valid empty
//! list — the cert grants no roles.

use super::der_helpers::{extract_extension_by_oid, parse_seq_of_utf8};
use super::oids::ALLOWED_ROLES_OID;
use super::VerifiedX509;
use crate::role::RoleId;

/// Errors returned from [`extract_allowed_roles`].
#[derive(Debug, thiserror::Error)]
pub enum AllowedRolesExtError {
    /// Cert DER could not be re-serialised by `openssl`.
    #[error("cert DER serialisation: {0}")]
    CertDer(String),
    /// Extension lookup encountered malformed cert DER.
    #[error("cert extension scan: {0}")]
    Scan(String),
    /// Extension present but DER body unparseable.
    #[error("parse: {0}")]
    Parse(String),
    /// A decoded entry is not a valid `role_id`.
    #[error("invalid role_id in allowed_roles: {0}")]
    InvalidRoleId(String),
}

/// Returns `Ok(Some(roles))` if the cert carries a valid `pam_cert_allowed_roles`
/// extension, `Ok(None)` if it is absent, or `Err` if present but malformed.
///
/// An empty `SEQUENCE` yields `Ok(Some(vec![]))`: a valid empty list that
/// grants no roles.  Parsing is fail-closed — a malformed DER body or any
/// invalid `role_id` rejects the whole extension.
///
/// # Errors
/// See [`AllowedRolesExtError`].
pub fn extract_allowed_roles(
    cert: &VerifiedX509,
) -> Result<Option<Vec<RoleId>>, AllowedRolesExtError> {
    let der = cert
        .as_x509()
        .to_der()
        .map_err(|e| AllowedRolesExtError::CertDer(e.to_string()))?;
    let value = match extract_extension_by_oid(&der, ALLOWED_ROLES_OID) {
        Ok(Some(v)) => v,
        Ok(None) => return Ok(None),
        Err(e) => return Err(AllowedRolesExtError::Scan(e.to_string())),
    };
    let strings =
        parse_seq_of_utf8(&value).map_err(|e| AllowedRolesExtError::Parse(e.to_string()))?;
    let mut roles: Vec<RoleId> = Vec::with_capacity(strings.len());
    for s in strings {
        let role =
            RoleId::new(&s).map_err(|e| AllowedRolesExtError::InvalidRoleId(e.to_string()))?;
        roles.push(role);
    }
    Ok(Some(roles))
}

//! Parser for the `pam_cert_user_binding` X.509 extension.
//!
//! ASN.1: `extnValue ::= SEQUENCE OF UTF8String`.
//!
//! Each entry is either `"*"` (matches any user) or an exact PAM username.

use super::der_helpers::{extract_extension_by_oid, parse_seq_of_utf8};
use super::oids::USER_BINDING_OID;
use openssl::x509::X509Ref;
use thiserror::Error;

/// One entry from the user-binding extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserDescriptor {
    /// `"*"` — matches any PAM username.
    Wildcard,
    /// Exact PAM username.
    Exact(String),
}

/// Errors produced while parsing the `pam_cert_user_binding` extension.
#[derive(Debug, Error)]
pub enum UserBindingExtError {
    /// The extension is not present in the certificate.
    #[error("extension missing")]
    Missing,
    /// The extension is present but its DER content is invalid.
    #[error("extension malformed: {0}")]
    Malformed(String),
    /// The extension is present but contains zero entries.
    #[error("extension has no entries")]
    Empty,
}

/// Parses the user-binding extension from `cert`.
///
/// # Errors
///
/// - [`UserBindingExtError::Missing`]   — the extension is not in the cert.
/// - [`UserBindingExtError::Empty`]     — the extension is present but the
///   `SEQUENCE OF UTF8String` is empty.
/// - [`UserBindingExtError::Malformed`] — DER decoding failed.
pub fn parse(cert: &X509Ref) -> Result<Vec<UserDescriptor>, UserBindingExtError> {
    let der = cert
        .to_der()
        .map_err(|e| UserBindingExtError::Malformed(format!("openssl: {e}")))?;

    let value = match extract_extension_by_oid(&der, USER_BINDING_OID) {
        Ok(Some(v)) => v,
        Ok(None) => return Err(UserBindingExtError::Missing),
        Err(e) => return Err(UserBindingExtError::Malformed(e.to_string())),
    };

    let strings =
        parse_seq_of_utf8(&value).map_err(|e| UserBindingExtError::Malformed(e.to_string()))?;

    if strings.is_empty() {
        return Err(UserBindingExtError::Empty);
    }

    Ok(strings
        .into_iter()
        .map(|s| {
            if s == "*" {
                UserDescriptor::Wildcard
            } else {
                UserDescriptor::Exact(s)
            }
        })
        .collect())
}

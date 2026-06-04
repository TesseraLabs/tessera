//! Parser for the `pam_cert_host_binding` X.509 extension.
//!
//! ASN.1: `extnValue ::= SEQUENCE OF UTF8String`.
//!
//! Each entry is interpreted as a host descriptor:
//! - `"*"`               — the certificate is valid on any host;
//! - `"sha256:<HEX>"`    — bound to a host whose `machine_id` hashes to
//!   the given lowercase 64-char hex digest;
//! - any other string    — bound to a host with this raw `machine_id`.

use super::der_helpers::{extract_extension_by_oid, parse_seq_of_utf8};
use super::oids::HOST_BINDING_OID;
use openssl::x509::X509Ref;
use thiserror::Error;

/// One entry from the host-binding extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostDescriptor {
    /// `"*"` — matches any host.
    Wildcard,
    /// `"sha256:<HEX>"` — `HEX` is a 64-character lowercase hex digest.
    Sha256Hex(String),
    /// Any other UTF-8 string — interpreted as a raw `machine_id`.
    Raw(String),
}

/// Errors produced while parsing the `pam_cert_host_binding` extension.
#[derive(Debug, Error)]
pub enum HostBindingExtError {
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

/// Parses the host-binding extension from `cert`.
///
/// # Errors
///
/// - [`HostBindingExtError::Missing`]  — the extension is not in the cert.
/// - [`HostBindingExtError::Empty`]    — the extension is present but the
///   `SEQUENCE OF UTF8String` is empty.
/// - [`HostBindingExtError::Malformed`] — DER decoding failed, or a
///   `sha256:` entry was not a valid 64-char lowercase hex string.
pub fn parse(cert: &X509Ref) -> Result<Vec<HostDescriptor>, HostBindingExtError> {
    let der = cert
        .to_der()
        .map_err(|e| HostBindingExtError::Malformed(format!("openssl: {e}")))?;

    let value = match extract_extension_by_oid(&der, HOST_BINDING_OID) {
        Ok(Some(v)) => v,
        Ok(None) => return Err(HostBindingExtError::Missing),
        Err(e) => return Err(HostBindingExtError::Malformed(e.to_string())),
    };

    let strings =
        parse_seq_of_utf8(&value).map_err(|e| HostBindingExtError::Malformed(e.to_string()))?;

    if strings.is_empty() {
        return Err(HostBindingExtError::Empty);
    }

    let mut out: Vec<HostDescriptor> = Vec::with_capacity(strings.len());
    for s in strings {
        out.push(classify(&s)?);
    }
    Ok(out)
}

fn classify(s: &str) -> Result<HostDescriptor, HostBindingExtError> {
    if s == "*" {
        return Ok(HostDescriptor::Wildcard);
    }
    // Case-insensitive `"sha256:"` prefix.
    if s.len() >= 7 && s[..7].eq_ignore_ascii_case("sha256:") {
        let rest = &s[7..];
        let lowered = rest.to_ascii_lowercase();
        if lowered.len() != 64 || !lowered.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(HostBindingExtError::Malformed(format!(
                "sha256 digest must be 64 lowercase hex chars, got {rest:?}"
            )));
        }
        return Ok(HostDescriptor::Sha256Hex(lowered));
    }
    Ok(HostDescriptor::Raw(s.to_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn classifies_wildcard() {
        assert_eq!(classify("*").unwrap(), HostDescriptor::Wildcard);
    }

    #[test]
    fn classifies_sha256_lowercases_hex() {
        let hex = "0".repeat(64);
        let upper = format!("SHA256:{}", hex.to_uppercase());
        match classify(&upper).unwrap() {
            HostDescriptor::Sha256Hex(h) => assert_eq!(h, hex),
            other => panic!("expected Sha256Hex, got {other:?}"),
        }
    }

    #[test]
    fn rejects_short_sha256() {
        let s = format!("sha256:{}", "a".repeat(63));
        let err = classify(&s).unwrap_err();
        assert!(matches!(err, HostBindingExtError::Malformed(_)));
    }

    #[test]
    fn rejects_non_hex_sha256() {
        let s = format!("sha256:{}", "z".repeat(64));
        let err = classify(&s).unwrap_err();
        assert!(matches!(err, HostBindingExtError::Malformed(_)));
    }

    #[test]
    fn classifies_raw() {
        assert_eq!(
            classify("some-machine-id").unwrap(),
            HostDescriptor::Raw("some-machine-id".to_owned())
        );
    }
}

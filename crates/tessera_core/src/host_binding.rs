//! Cert-driven host authorisation scope.
//!
//! The certificate alone decides which devices its holder may use: the
//! previous TOML host ACL and signed-ACL verifier were retired in favour of
//! the `pam_cert_host_binding` X.509 extension parsed by
//! [`crate::x509::host_binding_ext`].
//!
//! The other axis — which account the holder may log into — lives in
//! `pam_cert_allowed_roles` (see [`crate::x509::allowed_roles_ext`]): a login
//! account name IS a role name, so one list answers both "which role may be
//! activated" and "which account may be entered".
//!
//! Wildcard semantics:
//! - `Wildcard` (`"*"`) → any host;
//! - `Sha256Hex(hex)` → case-insensitive hex equality with the resolved host
//!   id hash;
//! - `Raw(s)` → SHA-256 of `s` is compared against the host id hash,
//!   case-insensitively.

use crate::x509::host_binding_ext::{self, HostBindingExtError, HostDescriptor};
use openssl::x509::X509Ref;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use thiserror::Error;
use tracing::warn;

/// Errors raised by [`verify_host_binding`].
#[derive(Debug, Error)]
pub enum HostBindingError {
    /// The certificate does not carry the `pam_cert_host_binding` extension.
    #[error("cert lacks host_binding extension")]
    HostExtensionMissing,
    /// The `host_binding` extension is present but its DER content is invalid.
    #[error("host_binding extension malformed: {0}")]
    HostExtensionMalformed(String),
    /// The cert is well-formed but no host descriptor matches this host.
    ///
    /// `host_id_hash_prefix` is the first 8 hex chars of the resolved
    /// host id hash — full hash is intentionally omitted from the error.
    #[error("host {host_id_hash_prefix} not in cert host_binding")]
    HostNotAllowed {
        /// First 8 chars of the host id hash.
        host_id_hash_prefix: String,
    },
}

impl From<HostBindingExtError> for HostBindingError {
    fn from(value: HostBindingExtError) -> Self {
        match value {
            HostBindingExtError::Missing => Self::HostExtensionMissing,
            HostBindingExtError::Malformed(m) => Self::HostExtensionMalformed(m),
            HostBindingExtError::Empty => {
                Self::HostExtensionMalformed("extension has no entries".into())
            }
        }
    }
}

/// Hex-encode the SHA-256 of `input`.
#[must_use]
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        // write! into String never fails.
        #[allow(clippy::let_underscore_must_use)]
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Verify that the cert's `host_binding` extension authorises `host_id_hash`.
///
/// # Errors
///
/// - [`HostBindingError::HostExtensionMissing`] — extension absent.
/// - [`HostBindingError::HostExtensionMalformed`] — extension malformed.
/// - [`HostBindingError::HostNotAllowed`] — extension present and well
///   formed but no descriptor matches.
pub fn verify_host_binding(cert: &X509Ref, host_id_hash: &str) -> Result<(), HostBindingError> {
    let descriptors = host_binding_ext::parse(cert)?;
    for d in &descriptors {
        let matched = match d {
            HostDescriptor::Wildcard => true,
            HostDescriptor::Sha256Hex(hex) => hex.eq_ignore_ascii_case(host_id_hash),
            HostDescriptor::Raw(s) => sha256_hex(s).eq_ignore_ascii_case(host_id_hash),
        };
        if matched {
            return Ok(());
        }
    }
    let host_id_hash_prefix: String = host_id_hash.chars().take(8).collect();
    warn!(
        target: "tessera.host_binding",
        event = "host_binding_violation",
        host_id_hash_prefix = %host_id_hash_prefix,
        "cert host_binding does not authorise this host"
    );
    Err(HostBindingError::HostNotAllowed {
        host_id_hash_prefix,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants
)]
mod tests {
    use super::*;
    use openssl::x509::X509;

    use crate::x509::oids::{ALLOWED_ROLES_OID, HOST_BINDING_OID};
    use crate::x509::test_utils::{build_cert, encode_seq_of_utf8};

    fn cert_with(host: &[&str]) -> X509 {
        build_cert(&[(HOST_BINDING_OID, encode_seq_of_utf8(host))])
    }

    #[test]
    fn exact_host_match_ok() {
        let host_hash = sha256_hex("machine-A");
        let cert = cert_with(&["machine-A"]);
        verify_host_binding(&cert, &host_hash).unwrap();
    }

    #[test]
    fn wildcard_host_ok() {
        let cert = cert_with(&["*"]);
        verify_host_binding(&cert, "any-host-hash").unwrap();
    }

    #[test]
    fn host_mismatch_rejected() {
        let host_hash = sha256_hex("machine-A");
        let cert = cert_with(&["machine-B"]);
        let err = verify_host_binding(&cert, &host_hash).unwrap_err();
        match err {
            HostBindingError::HostNotAllowed {
                host_id_hash_prefix,
            } => {
                assert_eq!(host_id_hash_prefix.len(), 8);
                assert!(host_hash.starts_with(&host_id_hash_prefix));
            }
            other => panic!("expected HostNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn missing_host_extension_rejected() {
        // A certificate carrying only the admission list still has to name the
        // devices it is valid on: the two axes are independent.
        let cert = build_cert(&[(ALLOWED_ROLES_OID, encode_seq_of_utf8(&["oper"]))]);
        let err = verify_host_binding(&cert, "h").unwrap_err();
        assert!(matches!(err, HostBindingError::HostExtensionMissing));
    }

    #[test]
    fn raw_machine_id_is_hashed_and_matched() {
        let raw = "raw-machine-id-xyz";
        let host_hash = sha256_hex(raw);
        let cert = cert_with(&[raw]);
        verify_host_binding(&cert, &host_hash).unwrap();
    }

    #[test]
    fn sha256_hex_descriptor_matches_case_insensitively() {
        let host_hash = sha256_hex("zzz");
        let cert = cert_with(&[&format!("sha256:{}", host_hash.to_uppercase())]);
        verify_host_binding(&cert, &host_hash).unwrap();
    }
}

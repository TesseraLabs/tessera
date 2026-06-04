//! Cert-driven host & user authorisation scope.
//!
//! As of 1.0.2 the certificate alone decides "which user on which host":
//! the previous TOML host ACL, signed-ACL verifier, roles, and
//! `cert_roles` field have been retired in favour of two X.509
//! extensions parsed by [`crate::x509::host_binding_ext`] and
//! [`crate::x509::user_binding_ext`].
//!
//! [`verify_cert_scope`] is the single entry point: it requires both
//! extensions to be present and demands at least one descriptor in each
//! to match the running host's id hash and the requested PAM user.
//!
//! Wildcard semantics:
//! - `host_binding` `Wildcard` (`"*"`) → any host;
//! - `host_binding` `Sha256Hex(hex)` → case-insensitive hex equality with
//!   the resolved host id hash;
//! - `host_binding` `Raw(s)` → SHA-256 of `s` is compared against the host
//!   id hash, case-insensitively;
//! - `user_binding` `Wildcard` (`"*"`) → any PAM user;
//! - `user_binding` `Exact(s)` → byte-equality with the PAM user
//!   (case-sensitive — Linux usernames are case-sensitive).

use crate::x509::host_binding_ext::{self, HostBindingExtError, HostDescriptor};
use crate::x509::user_binding_ext::{self, UserBindingExtError, UserDescriptor};
use openssl::x509::X509Ref;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use thiserror::Error;
use tracing::warn;

/// Errors raised by [`verify_host_binding`], [`verify_user_binding`] and
/// [`verify_cert_scope`].
#[derive(Debug, Error)]
pub enum HostBindingError {
    /// The certificate does not carry the `pam_cert_host_binding` extension.
    #[error("cert lacks host_binding extension")]
    HostExtensionMissing,
    /// The certificate does not carry the `pam_cert_user_binding` extension.
    #[error("cert lacks user_binding extension")]
    UserExtensionMissing,
    /// The `host_binding` extension is present but its DER content is invalid.
    #[error("host_binding extension malformed: {0}")]
    HostExtensionMalformed(String),
    /// The `user_binding` extension is present but its DER content is invalid.
    #[error("user_binding extension malformed: {0}")]
    UserExtensionMalformed(String),
    /// The cert is well-formed but no host descriptor matches this host.
    ///
    /// `host_id_hash_prefix` is the first 8 hex chars of the resolved
    /// host id hash — full hash is intentionally omitted from the error.
    #[error("host {host_id_hash_prefix} not in cert host_binding")]
    HostNotAllowed {
        /// First 8 chars of the host id hash.
        host_id_hash_prefix: String,
    },
    /// The cert is well-formed but no user descriptor matches `pam_user`.
    #[error("user {pam_user} not in cert user_binding")]
    UserNotAllowed {
        /// PAM user we attempted to authenticate.
        pam_user: String,
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

impl From<UserBindingExtError> for HostBindingError {
    fn from(value: UserBindingExtError) -> Self {
        match value {
            UserBindingExtError::Missing => Self::UserExtensionMissing,
            UserBindingExtError::Malformed(m) => Self::UserExtensionMalformed(m),
            UserBindingExtError::Empty => {
                Self::UserExtensionMalformed("extension has no entries".into())
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

/// Verify that the cert's `user_binding` extension authorises `pam_user`.
///
/// # Errors
///
/// - [`HostBindingError::UserExtensionMissing`] — extension absent.
/// - [`HostBindingError::UserExtensionMalformed`] — extension malformed.
/// - [`HostBindingError::UserNotAllowed`] — extension present and well
///   formed but no descriptor matches `pam_user`.
pub fn verify_user_binding(cert: &X509Ref, pam_user: &str) -> Result<(), HostBindingError> {
    let descriptors = user_binding_ext::parse(cert)?;
    for d in &descriptors {
        let matched = match d {
            UserDescriptor::Wildcard => true,
            UserDescriptor::Exact(s) => s == pam_user,
        };
        if matched {
            return Ok(());
        }
    }
    warn!(
        target: "tessera.host_binding",
        event = "user_binding_violation",
        pam_user = %pam_user,
        "cert user_binding does not authorise this user"
    );
    Err(HostBindingError::UserNotAllowed {
        pam_user: pam_user.to_owned(),
    })
}

/// Verify both extensions; combined cert authorisation gate.
///
/// Calls [`verify_host_binding`] first, then [`verify_user_binding`].
/// Returns the first error encountered.
///
/// # Errors
///
/// Any [`HostBindingError`] variant.
pub fn verify_cert_scope(
    cert: &X509Ref,
    host_id_hash: &str,
    pam_user: &str,
) -> Result<(), HostBindingError> {
    verify_host_binding(cert, host_id_hash)?;
    verify_user_binding(cert, pam_user)?;
    Ok(())
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

    use crate::x509::oids::{HOST_BINDING_OID, USER_BINDING_OID};
    use crate::x509::test_utils::{build_cert, encode_seq_of_utf8};

    fn cert_with(host: &[&str], user: &[&str]) -> X509 {
        build_cert(&[
            (HOST_BINDING_OID, encode_seq_of_utf8(host)),
            (USER_BINDING_OID, encode_seq_of_utf8(user)),
        ])
    }

    #[test]
    fn exact_host_match_with_exact_user_match_ok() {
        let host_hash = sha256_hex("machine-A");
        let cert = cert_with(&["machine-A"], &["alice"]);
        verify_cert_scope(&cert, &host_hash, "alice").unwrap();
    }

    #[test]
    fn wildcard_host_with_exact_user_ok() {
        let cert = cert_with(&["*"], &["alice"]);
        verify_cert_scope(&cert, "any-host-hash", "alice").unwrap();
    }

    #[test]
    fn exact_host_with_wildcard_user_ok() {
        let host_hash = sha256_hex("machine-A");
        let cert = cert_with(&["machine-A"], &["*"]);
        verify_cert_scope(&cert, &host_hash, "any-user").unwrap();
    }

    #[test]
    fn host_mismatch_rejected() {
        let host_hash = sha256_hex("machine-A");
        let cert = cert_with(&["machine-B"], &["*"]);
        let err = verify_cert_scope(&cert, &host_hash, "alice").unwrap_err();
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
    fn user_mismatch_rejected() {
        let host_hash = sha256_hex("machine-A");
        let cert = cert_with(&["machine-A"], &["bob"]);
        let err = verify_cert_scope(&cert, &host_hash, "alice").unwrap_err();
        match err {
            HostBindingError::UserNotAllowed { pam_user } => {
                assert_eq!(pam_user, "alice");
            }
            other => panic!("expected UserNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn missing_host_extension_rejected() {
        let cert = build_cert(&[(USER_BINDING_OID, encode_seq_of_utf8(&["alice"]))]);
        let err = verify_cert_scope(&cert, "h", "alice").unwrap_err();
        assert!(matches!(err, HostBindingError::HostExtensionMissing));
    }

    #[test]
    fn missing_user_extension_rejected() {
        let cert = build_cert(&[(HOST_BINDING_OID, encode_seq_of_utf8(&["*"]))]);
        let err = verify_cert_scope(&cert, "h", "alice").unwrap_err();
        assert!(matches!(err, HostBindingError::UserExtensionMissing));
    }

    #[test]
    fn raw_machine_id_is_hashed_and_matched() {
        let raw = "raw-machine-id-xyz";
        let host_hash = sha256_hex(raw);
        let cert = cert_with(&[raw], &["alice"]);
        verify_cert_scope(&cert, &host_hash, "alice").unwrap();
    }

    #[test]
    fn sha256_hex_descriptor_matches_case_insensitively() {
        let host_hash = sha256_hex("zzz");
        let cert = cert_with(
            &[&format!("sha256:{}", host_hash.to_uppercase())],
            &["alice"],
        );
        verify_cert_scope(&cert, &host_hash, "alice").unwrap();
    }

    #[test]
    fn user_match_is_case_sensitive() {
        let cert = cert_with(&["*"], &["Alice"]);
        let err = verify_cert_scope(&cert, "h", "alice").unwrap_err();
        assert!(matches!(err, HostBindingError::UserNotAllowed { .. }));
    }

    #[test]
    fn verify_host_binding_alone_succeeds() {
        let host_hash = sha256_hex("m");
        let cert = cert_with(&["m"], &["alice"]);
        verify_host_binding(&cert, &host_hash).unwrap();
    }

    #[test]
    fn verify_user_binding_alone_succeeds() {
        let cert = cert_with(&["*"], &["alice"]);
        verify_user_binding(&cert, "alice").unwrap();
    }
}

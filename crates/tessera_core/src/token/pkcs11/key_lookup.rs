//! PKCS#11 private-key object lookup (Task T09).
//!
//! [`Pkcs11Session::find_private_key_for_cert`] runs a `C_FindObjects`
//! query for `CKO_PRIVATE_KEY` constrained by the `CKA_ID` of the
//! certificate object discovered earlier (T08).  The convention in
//! PKCS#11 is to set the same `CKA_ID` on every key/cert pair belonging
//! to the same identity, which is how we find the right private key
//! without ever leaving the token.
//!
//! The function then reads back `CKA_KEY_TYPE` and `CKA_EXTRACTABLE` so
//! the next step (mechanism selection — T11) can decide which signing
//! mechanism to use, and so the mode-B invariant ("private key never
//! leaves the token") can be enforced when a misconfigured token ships
//! with an extractable private key.
//!
//! # Extractable-key policy
//!
//! `CKA_EXTRACTABLE = TRUE` breaks the mode-B invariant, so by default
//! the lookup fails closed with [`Pkcs11Error::ExtractableKeyRejected`].
//! Operators who knowingly run such tokens can opt out with
//! `pkcs11_allow_extractable_keys = true`, which downgrades the refusal
//! to the WARN below.
//!
//! # Logging
//!
//! - `pkcs11_extractable_key`: WARN — the matched private key has
//!   `CKA_EXTRACTABLE = TRUE` but `pkcs11_allow_extractable_keys = true`
//!   lets it through.  Production deployments should treat this line as
//!   an audit finding.
//! - `pkcs11_multiple_private_keys`: WARN — more than one private key
//!   shares the same `CKA_ID`.  We pick the first and continue.
//!
//! No raw bytes (`CKA_ID`, key material) ever land in log lines — only
//! lengths and a short hex prefix when needed for correlation.

use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use tracing::warn;

use super::cert_lookup::FoundCertificate;
use super::error::Pkcs11Error;
use super::locking::with_global_lock;
use super::session::Pkcs11Session;

/// A private-key object discovered on the token.
#[derive(Debug)]
pub struct FoundPrivateKey {
    /// Raw `CK_OBJECT_HANDLE` of the private-key object.
    pub object: ObjectHandle,
    /// `CKA_KEY_TYPE` (RSA, EC, GOSTR3410, ...).
    pub key_type: KeyType,
    /// `CKA_EXTRACTABLE` value — can only be `true` here when the
    /// operator opted in via `pkcs11_allow_extractable_keys`; with the
    /// default policy an extractable key never reaches the caller.
    pub extractable: bool,
}

/// Pure-attribute view used by [`Pkcs11Session::find_private_key_for_cert`].
///
/// Excludes the [`ObjectHandle`] (which the live caller already owns)
/// so the parser can be unit-tested without a real PKCS#11 provider —
/// cryptoki 0.7 keeps `ObjectHandle::new` crate-private, so we cannot
/// synthesize a handle from outside the crate.
#[derive(Debug)]
pub(crate) struct ParsedPrivateKey {
    /// `CKA_KEY_TYPE`.
    pub key_type: KeyType,
    /// `CKA_EXTRACTABLE`; defaults to `false` if the attribute is absent.
    pub extractable: bool,
}

/// Pure attribute parser used by [`Pkcs11Session::find_private_key_for_cert`].
///
/// # Errors
///
/// - [`Pkcs11Error::KeyTypeAttributeMissing`] when `CKA_KEY_TYPE` is not
///   present in `attrs`.
fn parse_private_key_attributes(attrs: Vec<Attribute>) -> Result<ParsedPrivateKey, Pkcs11Error> {
    let mut key_type: Option<KeyType> = None;
    let mut extractable = false;
    for attr in attrs {
        match attr {
            Attribute::KeyType(kt) => key_type = Some(kt),
            Attribute::Extractable(b) => extractable = b,
            _ => {}
        }
    }
    let key_type = key_type.ok_or(Pkcs11Error::KeyTypeAttributeMissing)?;
    Ok(ParsedPrivateKey {
        key_type,
        extractable,
    })
}

/// Enforce the mode-B non-extractable invariant on a matched key.
///
/// Non-extractable keys always pass.  Extractable keys are rejected
/// (fail-closed) unless the operator opted in via
/// `pkcs11_allow_extractable_keys`, in which case the violation is only
/// logged at WARN (`pkcs11_extractable_key`).
///
/// # Errors
///
/// - [`Pkcs11Error::ExtractableKeyRejected`] when `CKA_EXTRACTABLE = TRUE`
///   and `allow_extractable_keys` is `false`.
fn enforce_extractable_policy(
    parsed: &ParsedPrivateKey,
    allow_extractable_keys: bool,
    cka_id: &[u8],
) -> Result<(), Pkcs11Error> {
    if !parsed.extractable {
        return Ok(());
    }
    if !allow_extractable_keys {
        return Err(Pkcs11Error::ExtractableKeyRejected {
            key_type: parsed.key_type.to_string(),
            cka_id_hex: cka_id_log_prefix(cka_id),
        });
    }
    warn!(
        target: "tessera.pkcs11",
        key_type = %parsed.key_type,
        cka_id_prefix = %cka_id_log_prefix(cka_id),
        "pkcs11_extractable_key"
    );
    Ok(())
}

/// Hex-encode (lowercase) the leading 4 bytes of `id` for log correlation.
///
/// Matches the policy in `secret.rs` of *not* logging full identifiers
/// even when the underlying spec considers them public — the PAM event
/// log is shipped to operators who don't need raw token internals.
fn cka_id_log_prefix(id: &[u8]) -> String {
    use std::fmt::Write as _;
    let take = id.len().min(4);
    let mut out = String::with_capacity(take * 2 + 4);
    for byte in id.iter().take(take) {
        // Hex formatting into a String never errors.
        #[allow(clippy::let_underscore_must_use)]
        let _ = write!(out, "{byte:02x}");
    }
    if id.len() > take {
        out.push_str("...");
    }
    out
}

impl Pkcs11Session {
    /// Find the private key object that pairs with `cert` (matched by
    /// `CKA_ID`).
    ///
    /// `allow_extractable_keys` mirrors the `pkcs11_allow_extractable_keys`
    /// config key: with the default `false` an extractable key is rejected
    /// (fail-closed); `true` downgrades the rejection to a WARN.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::PrivateKeyNotFound`] when no private-key object
    ///   matches the certificate's `CKA_ID`.
    /// - [`Pkcs11Error::KeyTypeAttributeMissing`] when the matched object
    ///   reports no `CKA_KEY_TYPE`.
    /// - [`Pkcs11Error::ExtractableKeyRejected`] when the matched key has
    ///   `CKA_EXTRACTABLE = TRUE` and `allow_extractable_keys` is `false`.
    /// - [`Pkcs11Error::Cryptoki`] for any FFI failure from
    ///   `C_FindObjects` / `C_GetAttributeValue`.
    pub fn find_private_key_for_cert(
        &self,
        cert: &FoundCertificate,
        allow_extractable_keys: bool,
    ) -> Result<FoundPrivateKey, Pkcs11Error> {
        let session = self.raw().ok_or(Pkcs11Error::PrivateKeyNotFound {
            cka_id_hex: cka_id_log_prefix(&cert.cka_id),
        })?;

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(cert.cka_id.clone()),
        ];

        let mode = self.locking_mode();
        let handles = with_global_lock(mode, || session.find_objects(&template))?;
        if handles.is_empty() {
            return Err(Pkcs11Error::PrivateKeyNotFound {
                cka_id_hex: cka_id_log_prefix(&cert.cka_id),
            });
        }
        if handles.len() > 1 {
            warn!(
                target: "tessera.pkcs11",
                count = handles.len(),
                cka_id_prefix = %cka_id_log_prefix(&cert.cka_id),
                "pkcs11_multiple_private_keys"
            );
        }
        // Safe: just verified handles is non-empty.
        let Some(handle) = handles.into_iter().next() else {
            return Err(Pkcs11Error::PrivateKeyNotFound {
                cka_id_hex: cka_id_log_prefix(&cert.cka_id),
            });
        };

        let attrs = with_global_lock(mode, || {
            session.get_attributes(
                handle,
                &[AttributeType::KeyType, AttributeType::Extractable],
            )
        })?;
        let parsed = parse_private_key_attributes(attrs)?;
        enforce_extractable_policy(&parsed, allow_extractable_keys, &cert.cka_id)?;
        Ok(FoundPrivateKey {
            object: handle,
            key_type: parsed.key_type,
            extractable: parsed.extractable,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::err_expect,
        clippy::panic,
        clippy::unwrap_used
    )]

    use super::*;
    use cryptoki::object::{Attribute, KeyType};

    #[test]
    fn parses_rsa_with_extractable_false() {
        let attrs = vec![
            Attribute::KeyType(KeyType::RSA),
            Attribute::Extractable(false),
        ];
        let parsed = parse_private_key_attributes(attrs).expect("parse");
        assert_eq!(parsed.key_type, KeyType::RSA);
        assert!(!parsed.extractable);
    }

    #[test]
    fn parses_ec_with_extractable_true() {
        let attrs = vec![
            Attribute::KeyType(KeyType::EC),
            Attribute::Extractable(true),
        ];
        let parsed = parse_private_key_attributes(attrs).expect("parse");
        assert_eq!(parsed.key_type, KeyType::EC);
        assert!(parsed.extractable);
    }

    #[test]
    fn parses_gostr3410() {
        let attrs = vec![Attribute::KeyType(KeyType::GOSTR3410)];
        let parsed = parse_private_key_attributes(attrs).expect("parse");
        assert_eq!(parsed.key_type, KeyType::GOSTR3410);
        // CKA_EXTRACTABLE absent → defaults to false.
        assert!(!parsed.extractable);
    }

    #[test]
    fn missing_key_type_is_error() {
        let attrs = vec![Attribute::Extractable(false)];
        let err = parse_private_key_attributes(attrs)
            .err()
            .expect("must fail");
        assert!(matches!(err, Pkcs11Error::KeyTypeAttributeMissing));
    }

    #[test]
    fn ignores_unrelated_attributes() {
        let attrs = vec![
            Attribute::KeyType(KeyType::EC),
            Attribute::Sign(true),
            Attribute::Token(true),
            Attribute::Extractable(false),
        ];
        let parsed = parse_private_key_attributes(attrs).expect("parse");
        assert_eq!(parsed.key_type, KeyType::EC);
        assert!(!parsed.extractable);
    }

    #[test]
    fn extractable_key_rejected_by_default() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::RSA,
            extractable: true,
        };
        let err = enforce_extractable_policy(&parsed, false, b"\xde\xad\xbe\xef\xca\xfe")
            .err()
            .expect("must fail closed");
        match err {
            Pkcs11Error::ExtractableKeyRejected {
                key_type,
                cka_id_hex,
            } => {
                assert_eq!(key_type, KeyType::RSA.to_string());
                // Short prefix only — never the full CKA_ID bytes.
                assert_eq!(cka_id_hex, "deadbeef...");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn extractable_key_allowed_when_operator_opted_in() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::EC,
            extractable: true,
        };
        // Opt-out path: WARN only, lookup continues.
        enforce_extractable_policy(&parsed, true, b"\x01\x02").expect("opt-in must pass");
    }

    #[test]
    fn non_extractable_key_passes_regardless_of_policy() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::EC,
            extractable: false,
        };
        enforce_extractable_policy(&parsed, false, b"\x01\x02").expect("default must pass");
        enforce_extractable_policy(&parsed, true, b"\x01\x02").expect("opt-in must pass");
    }

    #[test]
    fn cka_id_log_prefix_truncates_long_ids() {
        let id = b"\xde\xad\xbe\xef\xca\xfe\x00\x01";
        let log = cka_id_log_prefix(id);
        assert_eq!(log, "deadbeef...");
    }

    #[test]
    fn cka_id_log_prefix_short_id_no_ellipsis() {
        let id = b"\xab\xcd";
        let log = cka_id_log_prefix(id);
        assert_eq!(log, "abcd");
    }

    #[test]
    fn cka_id_log_prefix_empty() {
        assert_eq!(cka_id_log_prefix(&[]), "");
    }
}

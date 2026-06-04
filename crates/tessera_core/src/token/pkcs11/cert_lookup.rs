//! PKCS#11 certificate object lookup (Task T08).
//!
//! [`Pkcs11Session::find_certificate`] runs a `C_FindObjects` query for
//! `CKO_CERTIFICATE` + `CKC_X_509` (optionally narrowed by `CKA_LABEL`),
//! then for every returned handle pulls `CKA_VALUE`, `CKA_ID` and
//! `CKA_LABEL`.  The first object whose `CKA_VALUE` parses as a valid
//! X.509 DER blob is wrapped in a [`FoundCertificate`] and returned.
//!
//! Per the OPEN QUESTION recorded in the PKCS#11 module docs we do
//! **not** cherry-pick on subject CN here — caller logic (subject mapping, host
//! binding) is responsible for binding the cert to a `pam_user`.  This
//! function only ensures we hand back **a** parseable end-entity cert,
//! together with its on-token `CKA_ID` so [`super::key_lookup`] can find
//! the matching private key.
//!
//! # Logging
//!
//! Any non-fatal parse failure is emitted at WARN with the on-token
//! label (truncated) and **no** byte payload — `CKA_VALUE` may legally
//! contain anything (we don't trust the token to have well-formed DER).
//! On total failure (every candidate rejected, or the search returned
//! zero handles) the function emits a single INFO line summarising the
//! outcome and returns [`Pkcs11Error::CertificateNotFound`].
//!
//! # Test strategy
//!
//! The pure parsing logic is split into [`parse_certificate_object_attributes`]
//! so unit tests can drive every error path without a live PKCS#11
//! provider.  Round-trip tests against softhsm2 live in
//! `tests/pkcs11_cert_lookup.rs` behind the `pkcs11-tests` feature.

use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use tracing::{info, warn};

use super::error::Pkcs11Error;
use super::locking::with_global_lock;
use super::session::Pkcs11Session;
use crate::x509::Certificate;

/// A certificate object successfully read from a PKCS#11 token.
#[derive(Debug)]
pub struct FoundCertificate {
    /// Raw `CK_OBJECT_HANDLE` of the certificate object.  Re-used in
    /// [`super::key_lookup::find_private_key_for_cert`] only as a
    /// breadcrumb (the actual matching is done by `CKA_ID`).
    pub object: ObjectHandle,
    /// `CKA_ID` value, used as the join key for the matching private key.
    pub cka_id: Vec<u8>,
    /// `CKA_LABEL` value, decoded as UTF-8.  `None` when absent or non-UTF-8.
    pub cka_label: Option<String>,
    /// Parsed end-entity certificate.
    pub certificate: Certificate,
}

/// Parsed attribute payload — everything that comes from the on-token
/// attributes for a certificate object **except** the [`ObjectHandle`],
/// which the live caller supplies separately.
///
/// Splitting the handle out makes the parser pure, which is the only way
/// to unit-test it: cryptoki 0.7 keeps `ObjectHandle::new` crate-private,
/// so we can't synthesize one in tests.
#[derive(Debug)]
pub(crate) struct ParsedCertificate {
    /// `CKA_ID`, normalised to an owned `Vec` (empty when the attribute
    /// was absent on the object).
    pub cka_id: Vec<u8>,
    /// `CKA_LABEL` decoded as UTF-8 — `None` when absent or non-UTF-8.
    pub cka_label: Option<String>,
    /// Parsed end-entity certificate.
    pub certificate: Certificate,
}

/// Parse `(CKA_VALUE, CKA_ID, CKA_LABEL)` triple into a
/// [`ParsedCertificate`].
///
/// Pure function: no PKCS#11 calls.  Used directly by
/// [`Pkcs11Session::find_certificate`] and unit-tested with synthetic DER
/// fixtures.
///
/// # Errors
///
/// - [`Pkcs11Error::CertificateValueMissing`] when `value` is `None`.
/// - [`Pkcs11Error::CertificateParseFailed`] when [`Certificate::from_der`]
///   rejects the bytes.  Caller is expected to log a WARN and try the
///   next candidate rather than propagate.
pub(crate) fn parse_certificate_object_attributes(
    value: Option<&[u8]>,
    id: Option<&[u8]>,
    label: Option<&[u8]>,
) -> Result<ParsedCertificate, Pkcs11Error> {
    let Some(value_bytes) = value else {
        return Err(Pkcs11Error::CertificateValueMissing);
    };
    let certificate = Certificate::from_der(value_bytes)
        .map_err(|e| Pkcs11Error::CertificateParseFailed(e.to_string()))?;
    let cka_id = id.unwrap_or(&[]).to_vec();
    let cka_label = label.and_then(|raw| std::str::from_utf8(raw).ok().map(str::to_owned));
    Ok(ParsedCertificate {
        cka_id,
        cka_label,
        certificate,
    })
}

impl Pkcs11Session {
    /// Look up an X.509 certificate object on the token.
    ///
    /// `label_filter`, when set, is appended to the search template as
    /// `CKA_LABEL`.  When `None` every X.509 certificate object is
    /// considered.
    ///
    /// Returns the **first** candidate whose `CKA_VALUE` parses as
    /// well-formed DER.  Candidates with missing or unparseable values
    /// are skipped with a WARN log.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::Cryptoki`] for any FFI failure from
    ///   `C_FindObjectsInit`/`C_FindObjects`/`C_GetAttributeValue`.
    /// - [`Pkcs11Error::CertificateNotFound`] when zero candidates
    ///   matched, or every candidate had a missing/unparseable value.
    pub fn find_certificate(
        &self,
        label_filter: Option<&str>,
    ) -> Result<FoundCertificate, Pkcs11Error> {
        let session = self.raw().ok_or_else(|| Pkcs11Error::CertificateNotFound {
            label_filter: label_filter.map(str::to_owned),
        })?;

        let mut template: Vec<Attribute> = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
        ];
        if let Some(label) = label_filter {
            template.push(Attribute::Label(label.as_bytes().to_vec()));
        }

        let mode = self.locking_mode();
        let handles = with_global_lock(mode, || session.find_objects(&template))?;
        if handles.is_empty() {
            info!(
                target: "tessera.pkcs11",
                label_filter = label_filter,
                "pkcs11_cert_search_empty"
            );
            return Err(Pkcs11Error::CertificateNotFound {
                label_filter: label_filter.map(str::to_owned),
            });
        }

        let want_attrs = [
            AttributeType::Value,
            AttributeType::Id,
            AttributeType::Label,
        ];
        let mut rejected = 0_usize;
        for handle in handles {
            let attrs = match with_global_lock(mode, || session.get_attributes(handle, &want_attrs))
            {
                Ok(attrs) => attrs,
                Err(e) => {
                    warn!(
                        target: "tessera.pkcs11",
                        error = %e,
                        "pkcs11_cert_get_attrs_failed"
                    );
                    rejected += 1;
                    continue;
                }
            };
            let mut value: Option<Vec<u8>> = None;
            let mut id: Option<Vec<u8>> = None;
            let mut label: Option<Vec<u8>> = None;
            for attr in attrs {
                match attr {
                    Attribute::Value(v) => value = Some(v),
                    Attribute::Id(v) => id = Some(v),
                    Attribute::Label(v) => label = Some(v),
                    _ => {}
                }
            }

            match parse_certificate_object_attributes(
                value.as_deref(),
                id.as_deref(),
                label.as_deref(),
            ) {
                Ok(parsed) => {
                    return Ok(FoundCertificate {
                        object: handle,
                        cka_id: parsed.cka_id,
                        cka_label: parsed.cka_label,
                        certificate: parsed.certificate,
                    })
                }
                Err(Pkcs11Error::CertificateValueMissing) => {
                    warn!(
                        target: "tessera.pkcs11",
                        "pkcs11_cert_value_missing"
                    );
                    rejected += 1;
                }
                Err(Pkcs11Error::CertificateParseFailed(reason)) => {
                    warn!(
                        target: "tessera.pkcs11",
                        reason = %reason,
                        "pkcs11_cert_parse_failed"
                    );
                    rejected += 1;
                }
                Err(other) => return Err(other),
            }
        }

        info!(
            target: "tessera.pkcs11",
            rejected,
            label_filter = label_filter,
            "pkcs11_cert_no_valid_candidates"
        );
        Err(Pkcs11Error::CertificateNotFound {
            label_filter: label_filter.map(str::to_owned),
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

    /// PEM helper — the `tessera_core/tests/fixtures` directory
    /// already ships a `leaf_rsa.pem`.  We reach for it via
    /// `CARGO_MANIFEST_DIR` to keep this unit test self-contained.
    fn leaf_der() -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("leaf_rsa.pem");
        let pem = std::fs::read(&path).expect("read leaf_rsa.pem");
        let stack = openssl::x509::X509::stack_from_pem(&pem).expect("parse pem");
        stack
            .first()
            .expect("at least one cert")
            .to_der()
            .expect("der encode")
    }

    #[test]
    fn parses_valid_der_with_full_attributes() {
        let der = leaf_der();
        let id = b"\x00\x01\x02\x03".to_vec();
        let label = b"alice's leaf".to_vec();
        let parsed = parse_certificate_object_attributes(Some(&der), Some(&id), Some(&label))
            .expect("parse");
        assert_eq!(parsed.cka_id, id);
        assert_eq!(parsed.cka_label.as_deref(), Some("alice's leaf"));
        assert_eq!(parsed.certificate.der(), der.as_slice());
    }

    #[test]
    fn parses_valid_der_without_id_or_label() {
        let der = leaf_der();
        let parsed = parse_certificate_object_attributes(Some(&der), None, None).expect("parse");
        assert!(parsed.cka_id.is_empty());
        assert!(parsed.cka_label.is_none());
    }

    #[test]
    fn rejects_missing_value() {
        let err = parse_certificate_object_attributes(None, None, None)
            .err()
            .expect("must fail");
        assert!(matches!(err, Pkcs11Error::CertificateValueMissing));
    }

    #[test]
    fn rejects_unparseable_value() {
        let err = parse_certificate_object_attributes(
            Some(&[0x00, 0x01, 0x02, 0x03]),
            Some(b"id"),
            Some(b"label"),
        )
        .err()
        .expect("must fail");
        assert!(matches!(err, Pkcs11Error::CertificateParseFailed(_)));
    }

    #[test]
    fn label_falls_back_to_none_on_non_utf8() {
        let der = leaf_der();
        // 0xFF is not valid UTF-8 in any position.
        let bad_label = vec![0xFF, 0xFE];
        let parsed =
            parse_certificate_object_attributes(Some(&der), None, Some(&bad_label)).expect("parse");
        assert!(
            parsed.cka_label.is_none(),
            "non-UTF8 label must yield None, got {:?}",
            parsed.cka_label
        );
    }
}

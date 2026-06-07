//! X.509 wrappers and trust verification primitives (stage 2).
//!
//! This module provides a typed, parse-don't-validate facade on top of the
//! `openssl` crate's lower-level types.  The general pattern is:
//!
//! 1. Parse PEM/DER into a [`Certificate`] (this rejects gibberish up front).
//! 2. Run [`pre_validate::pre_validate_end_entity`] on the leaf.
//! 3. Build a chain with [`chain::build_chain`].
//! 4. Verify signatures with [`signatures::verify_chain_signatures`].
//!
//! The richer [`TrustError`] enum here is independent from the legacy
//! `crate::error::TrustError` used by stage-1 stubs; they will be unified
//! in a later stage.

pub mod basic_constraints;
pub mod chain;
pub(crate) mod der;
pub(crate) mod der_helpers;
pub mod error;
pub(crate) mod ext;
pub mod host_binding_ext;
pub mod max_integrity_ext;
pub mod oids;
pub mod pinning;
pub mod pre_validate;
pub mod sig_alg;
pub mod signatures;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod user_binding_ext;

pub use error::TrustError;
pub use ext::BasicConstraintsView;
pub use sig_alg::SignatureAlg;

use openssl::asn1::Asn1TimeRef;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::x509::{X509NameRef, X509};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Identifiers extracted from a verified cert for audit purposes.
///
/// All four fields appear in every cert-related MAC audit event
/// (spec §4.1.3) and can be cheaply cloned into log records.
#[derive(Debug, Clone)]
pub struct CertIdent {
    /// Serial number (uppercase hex, no separators).
    pub serial: String,
    /// Issuer DN in RFC 4514-style `attr=value,attr=value` form.
    pub issuer: String,
    /// Subject Common Name, or empty string if absent.
    pub cn: String,
    /// SHA-256 fingerprint of the DER (lowercase hex).
    pub fingerprint: String,
}

impl From<&VerifiedX509> for CertIdent {
    fn from(v: &VerifiedX509) -> Self {
        use openssl::hash::MessageDigest;
        let x = v.as_x509();
        let serial = x
            .serial_number()
            .to_bn()
            .ok()
            .and_then(|bn| bn.to_hex_str().ok().map(|s| s.to_string()))
            .unwrap_or_default();
        let issuer = x
            .issuer_name()
            .entries()
            .map(|e| {
                let nid = e.object().nid().short_name().unwrap_or("").to_string();
                let val = e
                    .data()
                    .as_utf8()
                    .map(|u| u.to_string())
                    .unwrap_or_default();
                format!("{nid}={val}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let cn = x
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok().map(|u| u.to_string()))
            .unwrap_or_default();
        let fingerprint = x
            .digest(MessageDigest::sha256())
            .ok()
            .map(|d| {
                use std::fmt::Write as _;
                d.iter()
                    .fold(String::with_capacity(d.len() * 2), |mut acc, b| {
                        // Запись в String инфаллибельна, результат игнорируем намеренно.
                        #[allow(clippy::let_underscore_must_use)]
                        let _ = write!(&mut acc, "{b:02x}");
                        acc
                    })
            })
            .unwrap_or_default();
        Self {
            serial,
            issuer,
            cn,
            fingerprint,
        }
    }
}

/// A leaf certificate whose trust chain, EKU, and signature have already
/// been validated by the main authentication flow.
///
/// This is a trust-boundary marker: callers that consume a `VerifiedX509`
/// (e.g. `max_integrity_ext::extract_max_integrity`) can assume the
/// underlying [`X509`] is safe to inspect for extension values.  Production
/// callers must construct it via the verifier pipeline; tests can use the
/// `from_trusted_for_test` escape hatch.
pub struct VerifiedX509(X509);

impl VerifiedX509 {
    /// Production constructor — calls only from the verifier pipeline after
    /// successful validation.
    #[allow(dead_code)]
    pub(crate) fn new(cert: X509) -> Self {
        Self(cert)
    }

    /// Read-only access to the underlying [`X509`].
    #[must_use]
    pub fn as_x509(&self) -> &X509 {
        &self.0
    }

    /// Test-only escape hatch.  Use ONLY in unit tests with self-signed
    /// fixtures or under the `mac-tests` feature for cross-crate test helpers.
    #[cfg(any(test, feature = "mac-tests"))]
    pub fn from_trusted_for_test(cert: X509) -> Self {
        Self(cert)
    }
}

/// A parsed X.509 certificate plus a cached DER serialization.
///
/// Only constructible via [`Certificate::from_der`] or [`Certificate::from_pem`].
/// Both constructors immediately reject malformed input — internal accessors
/// can therefore assume the underlying `X509` is well-formed.
#[derive(Clone)]
pub struct Certificate {
    inner: X509,
    der_cache: Vec<u8>,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("subject_cn", &self.subject_cn().ok())
            .field("der_len", &self.der_cache.len())
            .finish_non_exhaustive()
    }
}

impl Certificate {
    /// Parses a certificate from DER-encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] when the input is not valid DER.
    pub fn from_der(der: &[u8]) -> Result<Self, TrustError> {
        let inner = X509::from_der(der).map_err(|e| TrustError::CertParse(e.to_string()))?;
        Ok(Self {
            inner,
            der_cache: der.to_vec(),
        })
    }

    /// Parses a certificate from PEM-encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] when the input cannot be decoded
    /// or re-encoded to DER (e.g. malformed PEM or unsupported encoding).
    pub fn from_pem(pem: &[u8]) -> Result<Self, TrustError> {
        let inner = X509::from_pem(pem).map_err(|e| TrustError::CertParse(e.to_string()))?;
        let der = inner
            .to_der()
            .map_err(|e| TrustError::CertParse(e.to_string()))?;
        Ok(Self {
            inner,
            der_cache: der,
        })
    }

    /// DER serialization of the certificate.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der_cache
    }

    /// Borrows the underlying `openssl::x509::X509`.
    #[must_use]
    pub fn x509(&self) -> &X509 {
        &self.inner
    }

    /// Returns the subject Common Name, when present.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::FieldMissing`] if the subject DN has no CN attribute.
    pub fn subject_cn(&self) -> Result<String, TrustError> {
        first_text_by_nid(self.inner.subject_name(), Nid::COMMONNAME)
            .ok_or(TrustError::FieldMissing("subject CN"))
    }

    /// Returns all RFC822 (email) values from the subject alternative name extension.
    #[must_use]
    pub fn san_emails(&self) -> Vec<String> {
        self.inner
            .subject_alt_names()
            .map(|stack| {
                stack
                    .iter()
                    .filter_map(|gn| gn.email().map(std::string::ToString::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Hex-encoded serial number (uppercase, no separators).  Empty string on
    /// the (extremely unlikely) failure to render the integer.
    #[must_use]
    pub fn serial_hex(&self) -> String {
        self.inner
            .serial_number()
            .to_bn()
            .ok()
            .and_then(|bn| bn.to_hex_str().ok().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// `notBefore` as `SystemTime`.
    #[must_use]
    pub fn not_before(&self) -> SystemTime {
        asn1_to_system(self.inner.not_before())
    }

    /// `notAfter` as `SystemTime`.
    #[must_use]
    pub fn not_after(&self) -> SystemTime {
        asn1_to_system(self.inner.not_after())
    }

    /// Dotted OID of the certificate's signature algorithm.
    #[must_use]
    pub fn signature_algorithm(&self) -> String {
        self.inner.signature_algorithm().object().to_string()
    }

    /// Classified signature algorithm.  Wrapper over
    /// [`Self::signature_algorithm`] that maps known OIDs onto
    /// [`SignatureAlg`] variants.
    #[must_use]
    pub fn signature_alg(&self) -> SignatureAlg {
        SignatureAlg::from_oid_string(&self.signature_algorithm())
    }

    /// Returns the X.509 version field (`0` for v1, `1` for v2, `2` for v3).
    #[must_use]
    pub fn version(&self) -> i32 {
        self.inner.version()
    }

    /// Whether the `keyUsage` extension asserts `digitalSignature`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] if the extension is malformed.
    pub fn key_usage_digital_signature(&self) -> Result<bool, TrustError> {
        ext::key_usage_bit(&self.inner, 0)
    }

    /// Whether the `keyUsage` extension asserts `keyCertSign`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] if the extension is malformed.
    pub fn key_usage_key_cert_sign(&self) -> Result<bool, TrustError> {
        ext::key_usage_bit(&self.inner, 5)
    }

    /// Whether `extendedKeyUsage` includes the `clientAuth` OID
    /// (1.3.6.1.5.5.7.3.2).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] if the extension is malformed.
    pub fn eku_client_auth(&self) -> Result<bool, TrustError> {
        Ok(self.eku_oids()?.iter().any(|o| o == "1.3.6.1.5.5.7.3.2"))
    }

    /// Returns the dotted OIDs declared in `extendedKeyUsage`,
    /// or an empty vector if the extension is absent.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] if the extension is malformed.
    pub fn eku_oids(&self) -> Result<Vec<String>, TrustError> {
        ext::eku_oids(&self.inner)
    }

    /// Returns the Subject Key Identifier (SKI) bytes, if the extension
    /// is present.
    #[must_use]
    pub fn ski(&self) -> Option<Vec<u8>> {
        ext::ski(&self.inner)
    }

    /// Returns the Authority Key Identifier `keyIdentifier` field, if present.
    #[must_use]
    pub fn aki(&self) -> Option<Vec<u8>> {
        ext::aki_key_id(&self.inner)
    }

    /// Returns the `basicConstraints` view if the extension is present.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] if the extension is malformed.
    pub fn basic_constraints(&self) -> Result<Option<BasicConstraintsView>, TrustError> {
        ext::basic_constraints(&self.inner)
    }

    /// Returns the certificate's public key.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::Openssl`] if the public key cannot be extracted.
    pub fn public_key(&self) -> Result<PKey<Public>, TrustError> {
        Ok(self.inner.public_key()?)
    }
}

fn first_text_by_nid(name: &X509NameRef, nid: Nid) -> Option<String> {
    name.entries_by_nid(nid)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|d| d.to_string())
}

fn asn1_to_system(t: &Asn1TimeRef) -> SystemTime {
    // Compute the offset relative to UNIX epoch.  If anything goes wrong
    // (which would mean OpenSSL itself is broken or the cert encoding is
    // wildly out of range) we conservatively return UNIX_EPOCH.
    let Ok(epoch) = openssl::asn1::Asn1Time::from_unix(0) else {
        return UNIX_EPOCH;
    };
    let Ok(diff) = epoch.diff(t) else {
        return UNIX_EPOCH;
    };
    let secs = i64::from(diff.days) * 86_400 + i64::from(diff.secs);
    if secs >= 0 {
        let unsigned = u64::try_from(secs).unwrap_or(0);
        UNIX_EPOCH + Duration::from_secs(unsigned)
    } else {
        let unsigned = u64::try_from(-secs).unwrap_or(0);
        UNIX_EPOCH - Duration::from_secs(unsigned)
    }
}

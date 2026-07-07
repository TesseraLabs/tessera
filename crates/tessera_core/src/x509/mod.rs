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

pub mod allowed_roles_ext;
pub mod basic_constraints;
pub mod chain;
pub mod delegation_constraints_ext;
pub(crate) mod der;
pub(crate) mod der_helpers;
pub mod error;
pub(crate) mod ext;
pub mod host_binding_ext;
pub mod max_integrity_ext;
pub mod oids;
pub mod pinning;
pub mod pre_validate;
pub mod profile_validation;
pub mod profile_version_ext;
pub mod sig_alg;
pub mod signatures;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod user_binding_ext;

pub use error::TrustError;
pub use ext::BasicConstraintsView;
pub use sig_alg::SignatureAlg;

use foreign_types::ForeignTypeRef;
use openssl::asn1::{Asn1StringRef, Asn1TimeRef};
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
                let val = asn1_str_strict(e.data()).unwrap_or_default();
                format!("{nid}={val}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let cn = x
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| asn1_str_strict(e.data()))
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

    /// Returns the `basicConstraints` view if the extension is present.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] if the extension is malformed.
    pub fn basic_constraints(&self) -> Result<Option<BasicConstraintsView>, TrustError> {
        ext::basic_constraints(&self.0)
    }

    /// Whether this certificate asserts `basicConstraints` `cA = TRUE`.
    ///
    /// A missing `basicConstraints` extension is treated as `cA = FALSE`
    /// (the RFC 5280 default).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] if the extension is malformed.
    pub fn is_ca(&self) -> Result<bool, TrustError> {
        Ok(self.basic_constraints()?.is_some_and(|bc| bc.is_ca))
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

    /// Returns the dotted OIDs of every extension marked `critical`.
    ///
    /// Used by the chain verifier to fail closed on any critical extension it
    /// does not understand (RFC 5280 §4.2).
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::CertParse`] when the certificate structure is
    /// malformed.
    pub fn critical_extension_oids(&self) -> Result<Vec<String>, TrustError> {
        ext::critical_extension_oids(&self.inner)
    }
}

/// Strictly decodes an ASN.1 string field to a Rust `String`, or `None`.
///
/// Only the string types this module explicitly supports are decoded, each
/// fail-closed:
///
/// * `UTF8String`, `PrintableString`, `IA5String` — the raw bytes are already
///   UTF-8-compatible, so they are accepted only when valid UTF-8 with no
///   interior NUL.
/// * `BMPString` — the raw bytes are UTF-16BE, decoded strictly (see
///   [`strict_utf16be_no_nul`]) and likewise rejected on any interior NUL.
///
/// Every other type tag (`TeletexString`/T61, `UniversalString`/UTF-32,
/// numeric/visible, …) is rejected outright rather than decoded: those
/// encodings are legacy or ambiguous, and guessing at them on attacker-supplied
/// input has no place in an authentication path.
///
/// The fail-closed discipline exists because these fields feed identity
/// matching (`subject_cn` -> `mapping::match_user`): a crafted subject such as
/// `"engineer\0evil"` must never be silently truncated to `"engineer"`
/// (openssl's `Asn1StringRef::as_utf8` truncates at the first NUL) nor lossily
/// transformed (`to_string` substitutes U+FFFD for invalid bytes), since either
/// could let one certificate impersonate a shorter legitimate identity. A
/// rejected field simply behaves as absent, which the callers already handle
/// (empty audit value / `FieldMissing`).
fn asn1_str_strict(s: &Asn1StringRef) -> Option<String> {
    let bytes = s.as_slice();
    match asn1_string_type(s) {
        openssl_sys::V_ASN1_UTF8STRING
        | openssl_sys::V_ASN1_PRINTABLESTRING
        | openssl_sys::V_ASN1_IA5STRING => strict_utf8_no_nul(bytes),
        openssl_sys::V_ASN1_BMPSTRING => strict_utf16be_no_nul(bytes),
        _ => None,
    }
}

/// Returns the ASN.1 string type tag (`V_ASN1_*`) of `s`.
///
/// The safe `openssl` API deliberately hides the tag (`to_string` decodes by
/// it internally but never exposes it), so the tag is read via the same
/// `ASN1_STRING_type` accessor the crate itself uses. Distinguishing the type
/// is mandatory here: `as_slice` hands back the raw value octets, whose meaning
/// (UTF-8 vs UTF-16BE …) is defined entirely by the tag.
#[expect(
    unsafe_code,
    reason = "the safe openssl API exposes no ASN.1 type-tag accessor; \
              reading the tag requires the same FFI call the crate uses internally"
)]
fn asn1_string_type(s: &Asn1StringRef) -> std::os::raw::c_int {
    // SAFETY: `s.as_ptr()` yields the non-null `ASN1_STRING` pointer backing
    // this borrowed reference and stays valid for the borrow, which outlives
    // this call. `ASN1_STRING_type` only reads the tag field; it neither
    // mutates nor frees the object, and the `*mut` coerces to the expected
    // `*const` argument.
    unsafe { openssl_sys::ASN1_STRING_type(s.as_ptr()) }
}

/// Byte-level core for UTF-8-compatible ASN.1 string types
/// (`UTF8String`/`PrintableString`/`IA5String`): accepts `bytes` only if they
/// are valid UTF-8 with no interior NUL. Extracted so the fail-closed rule can
/// be unit-tested without fabricating an [`Asn1StringRef`].
fn strict_utf8_no_nul(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text.contains('\0') {
        return None;
    }
    Some(text.to_owned())
}

/// Byte-level core for `BMPString`: interprets `bytes` as UTF-16BE and decodes
/// them strictly. Extracted so the fail-closed rule can be unit-tested without
/// fabricating an [`Asn1StringRef`].
///
/// Returns `None` (fail-closed) on any of: an odd byte count (a truncated code
/// unit), an unpaired/lone surrogate, or an interior NUL (`U+0000`) in the
/// decoded text — the last mirrors the UTF-8 path so a `BMPString` encoding of
/// `"alice\0attacker"` cannot slip past identity matching.
fn strict_utf16be_no_nul(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        // `chunks_exact(2)` only yields 2-byte slices; the slice pattern reads
        // both octets without panicking indexing, and the `else` is unreachable.
        let [hi, lo] = pair else { return None };
        units.push(u16::from_be_bytes([*hi, *lo]));
    }
    let mut text = String::with_capacity(units.len());
    for decoded in char::decode_utf16(units) {
        let ch = decoded.ok()?;
        if ch == '\0' {
            return None;
        }
        text.push(ch);
    }
    Some(text)
}

fn first_text_by_nid(name: &X509NameRef, nid: Nid) -> Option<String> {
    name.entries_by_nid(nid)
        .next()
        .and_then(|e| asn1_str_strict(e.data()))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{strict_utf16be_no_nul, strict_utf8_no_nul};

    /// Encodes `s` as UTF-16BE octets, the on-the-wire form of a `BMPString`.
    fn utf16be(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    #[test]
    fn accepts_plain_ascii() {
        assert_eq!(strict_utf8_no_nul(b"engineer").as_deref(), Some("engineer"));
    }

    #[test]
    fn accepts_valid_multibyte_utf8() {
        assert_eq!(
            strict_utf8_no_nul("инженер".as_bytes()).as_deref(),
            Some("инженер"),
        );
    }

    #[test]
    fn rejects_interior_nul_no_truncation() {
        // The deprecated as_utf8 would truncate this to "engineer"; a strict
        // decode must reject it so it cannot impersonate the shorter name.
        assert_eq!(strict_utf8_no_nul(b"engineer\0evil"), None);
    }

    #[test]
    fn rejects_trailing_nul() {
        assert_eq!(strict_utf8_no_nul(b"engineer\0"), None);
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(strict_utf8_no_nul(&[0xff, 0xfe, 0x00]), None);
        assert_eq!(strict_utf8_no_nul(&[0x80]), None);
    }

    #[test]
    fn accepts_empty() {
        assert_eq!(strict_utf8_no_nul(b"").as_deref(), Some(""));
    }

    #[test]
    fn bmp_accepts_plain_ascii() {
        assert_eq!(
            strict_utf16be_no_nul(&utf16be("alice")).as_deref(),
            Some("alice"),
        );
    }

    #[test]
    fn bmp_accepts_multibyte() {
        // Cyrillic "инженер" round-trips through UTF-16BE unchanged.
        assert_eq!(
            strict_utf16be_no_nul(&utf16be("инженер")).as_deref(),
            Some("инженер"),
        );
    }

    #[test]
    fn bmp_accepts_empty() {
        assert_eq!(strict_utf16be_no_nul(b"").as_deref(), Some(""));
    }

    #[test]
    fn bmp_rejects_odd_length() {
        // A trailing half code unit is a malformed UTF-16 encoding.
        assert_eq!(strict_utf16be_no_nul(&[0x00, 0x61, 0x00]), None);
    }

    #[test]
    fn bmp_rejects_lone_high_surrogate() {
        // 0xD800 with no following low surrogate is unpaired -> reject.
        assert_eq!(strict_utf16be_no_nul(&[0xD8, 0x00]), None);
    }

    #[test]
    fn bmp_rejects_lone_low_surrogate() {
        // 0xDC00 with no preceding high surrogate is unpaired -> reject.
        assert_eq!(strict_utf16be_no_nul(&[0xDC, 0x00]), None);
    }

    #[test]
    fn bmp_rejects_interior_nul() {
        // A u16 0x0000 mid-string decodes to '\0'; it must be rejected the same
        // way the UTF-8 path rejects an interior NUL, so a BMPString encoding of
        // "alice\0attacker" cannot impersonate the shorter "alice".
        let mut bytes = utf16be("alice");
        bytes.extend_from_slice(&[0x00, 0x00]); // interior NUL
        bytes.extend_from_slice(&utf16be("attacker"));
        assert_eq!(strict_utf16be_no_nul(&bytes), None);
    }

    #[test]
    fn bmp_rejects_trailing_nul() {
        let mut bytes = utf16be("alice");
        bytes.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(strict_utf16be_no_nul(&bytes), None);
    }

    /// Builds a single-CN X.509 name whose CN entry carries `wire` verbatim
    /// under the given ASN.1 string type. `X509_NAME_add_entry_by_NID` with a
    /// concrete type (not an `MBSTRING_*` sentinel) stores the input bytes as-is
    /// without transcoding, and `build` DER-round-trips them — so `wire` must
    /// already be the on-the-wire octets for `ty` (UTF-16BE for a `BMPString`).
    /// This exercises the real openssl encoder plus our FFI type detection end
    /// to end.
    fn cn_with_type(wire: &[u8], ty: openssl::asn1::Asn1Type) -> openssl::x509::X509Name {
        use openssl::nid::Nid;
        use openssl::x509::X509Name;
        // The value crosses the FFI boundary as a byte string; passing it as
        // `&str` is only a transport detail, not a claim that it is UTF-8 text.
        let value =
            std::str::from_utf8(wire).expect("test wire bytes are valid utf8 for transport");
        let mut builder = X509Name::builder().expect("name builder");
        builder
            .append_entry_by_nid_with_type(Nid::COMMONNAME, value, ty)
            .expect("append CN");
        builder.build()
    }

    #[test]
    fn ffi_detects_real_bmpstring_ascii() {
        use openssl::asn1::Asn1Type;
        use openssl::nid::Nid;
        let name = cn_with_type(&utf16be("alice"), Asn1Type::BMPSTRING);
        assert_eq!(
            super::first_text_by_nid(&name, Nid::COMMONNAME).as_deref(),
            Some("alice"),
        );
    }

    #[test]
    fn ffi_detects_real_bmpstring_multibyte() {
        use openssl::asn1::Asn1Type;
        use openssl::nid::Nid;
        let name = cn_with_type(&utf16be("инженер"), Asn1Type::BMPSTRING);
        assert_eq!(
            super::first_text_by_nid(&name, Nid::COMMONNAME).as_deref(),
            Some("инженер"),
        );
    }

    #[test]
    fn ffi_detects_real_utf8string() {
        use openssl::asn1::Asn1Type;
        use openssl::nid::Nid;
        let name = cn_with_type(b"alice", Asn1Type::UTF8STRING);
        assert_eq!(
            super::first_text_by_nid(&name, Nid::COMMONNAME).as_deref(),
            Some("alice"),
        );
    }

    #[test]
    fn ffi_rejects_real_unsupported_type() {
        use openssl::asn1::Asn1Type;
        use openssl::nid::Nid;
        // TeletexString (T61) is deliberately unsupported: its encoding is
        // ambiguous/legacy, so the decoder must fail closed rather than guess.
        let name = cn_with_type(b"alice", Asn1Type::TELETEXSTRING);
        assert_eq!(super::first_text_by_nid(&name, Nid::COMMONNAME), None);
    }
}

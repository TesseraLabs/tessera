//! Internal DER helpers for the `host_binding_ext` and `user_binding_ext`
//! parsers.
//!
//! `openssl` 0.10 does not expose raw extension `extnValue` bytes for arbitrary
//! OIDs — only typed accessors for a handful of well-known extensions.  We
//! therefore walk the cert DER ourselves and pull the extension content out by
//! its dotted OID.
//!
//! Encoding strategy for OIDs: our project-private OIDs use the `2.25.<UUID>`
//! arc, whose single arc is ~128 bits wide.  We encode the target OID to its
//! DER content octets with [`tessera_ext::der::encode_oid`] (a pure-Rust
//! wide-integer encoder) and compare against each extension's OID content.
//! This keeps the comparison off OpenSSL's `Asn1Object`, so the same code path
//! is reusable by the wasm/issuer side.

use super::der::{read_tlv, read_tlv_expect, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};
use thiserror::Error;

/// ASN.1 DER tag for `UTF8String`.
pub(crate) const TAG_UTF8_STRING: u8 = 0x0C;

/// Errors produced by the DER helpers in this module.
#[derive(Debug, Error)]
pub(crate) enum DerError {
    /// A TLV element had an unexpected tag.
    #[error("der: unexpected tag 0x{0:02x}")]
    UnexpectedTag(u8),
    /// A `UTF8String` value was not valid UTF-8.
    #[error("der: invalid utf-8 in utf8string")]
    InvalidUtf8,
    /// A buffer was shorter than the minimum required.
    #[error("der: input truncated")]
    Truncated,
    /// Underlying TLV parser reported a problem.
    #[error("der: tlv parse error: {0}")]
    Tlv(String),
    /// `target_oid` could not be encoded to DER content octets.
    #[error("der: invalid target oid: {0}")]
    InvalidOid(String),
    /// A DER `INTEGER` did not fit the target Rust integer type.
    #[error("der: integer out of range")]
    IntegerOutOfRange,
    /// A DER `INTEGER` used a non-minimal (non-canonical) encoding.
    #[error("der: non-minimal integer encoding")]
    NonMinimalInteger,
    /// Bytes remained after a value that should have consumed its whole buffer.
    #[error("der: trailing bytes after value")]
    TrailingBytes,
}

impl From<super::TrustError> for DerError {
    fn from(e: super::TrustError) -> Self {
        DerError::Tlv(e.to_string())
    }
}

/// Locates the `extnValue` content of an extension matching `target_oid`
/// (in dotted notation) inside a DER-encoded certificate.
///
/// Returns:
/// - `Ok(Some(bytes))` — the inner DER inside the OCTET STRING wrapper.
/// - `Ok(None)`        — the extension is absent.
/// - `Err(_)`          — the certificate structure is malformed.
pub(crate) fn extract_extension_by_oid(
    cert_der: &[u8],
    target_oid: &str,
) -> Result<Option<Vec<u8>>, DerError> {
    // Encode the target OID to its DER content octets once and compare against
    // each extension's OID content — this handles the wide (~128-bit) arcs of
    // our `2.25.<UUID>` OIDs without linking OpenSSL for canonicalisation.
    let target_bytes = tessera_ext::der::encode_oid(target_oid)
        .map_err(|e| DerError::InvalidOid(e.to_string()))?;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let outer = read_tlv_expect(cert_der, TAG_SEQUENCE)?;
    // tbsCertificate ::= SEQUENCE { ... extensions [3] EXPLICIT ... OPTIONAL }
    let tbs = read_tlv_expect(outer.value, TAG_SEQUENCE)?;

    // Walk tbsCertificate fields, looking for the [3] EXPLICIT context tag.
    let mut rest = tbs.value;
    let extensions_octets: Option<&[u8]> = loop {
        if rest.is_empty() {
            break None;
        }
        let tlv = read_tlv(rest)?;
        if tlv.tag == 0xA3 {
            break Some(tlv.value);
        }
        rest = tlv.rest;
    };
    let Some(ext_outer) = extensions_octets else {
        return Ok(None);
    };

    let ext_seq = read_tlv_expect(ext_outer, TAG_SEQUENCE)?;
    let mut walker = ext_seq.value;
    while !walker.is_empty() {
        let ext_tlv = read_tlv_expect(walker, TAG_SEQUENCE)?;
        walker = ext_tlv.rest;
        let mut inner = ext_tlv.value;

        let oid = read_tlv_expect(inner, TAG_OID)?;
        inner = oid.rest;

        // Optional `critical BOOLEAN DEFAULT FALSE`.
        if !inner.is_empty() {
            let peek = read_tlv(inner)?;
            if peek.tag == 0x01 {
                inner = peek.rest;
            }
        }

        let octet = read_tlv_expect(inner, TAG_OCTET_STRING)?;
        if oid.value == target_bytes.as_slice() {
            return Ok(Some(octet.value.to_vec()));
        }
    }
    Ok(None)
}

/// Parses an `extnValue` whose ASN.1 type is `SEQUENCE OF UTF8String` and
/// returns the decoded strings, in order.
///
/// Errors out if any inner element has a tag other than `UTF8String`, or the
/// bytes inside a `UTF8String` are not valid UTF-8.
pub(crate) fn parse_seq_of_utf8(value_der: &[u8]) -> Result<Vec<String>, DerError> {
    if value_der.is_empty() {
        return Err(DerError::Truncated);
    }
    let seq = read_tlv_expect(value_der, TAG_SEQUENCE)?;
    let mut rest = seq.value;
    let mut out: Vec<String> = Vec::new();
    while !rest.is_empty() {
        let tlv = read_tlv(rest)?;
        if tlv.tag != TAG_UTF8_STRING {
            return Err(DerError::UnexpectedTag(tlv.tag));
        }
        let s = std::str::from_utf8(tlv.value).map_err(|_| DerError::InvalidUtf8)?;
        out.push(s.to_owned());
        rest = tlv.rest;
    }
    Ok(out)
}

/// Decodes a DER `INTEGER` value (the TLV *content* bytes, big-endian
/// two's-complement) into an [`i64`].
///
/// Fail-closed: rejects empty content, non-minimal (non-canonical) encodings,
/// and any magnitude that does not fit `i64`.
pub(crate) fn parse_der_integer_i64(content: &[u8]) -> Result<i64, DerError> {
    let (&first, tail) = content.split_first().ok_or(DerError::Truncated)?;
    // Reject non-minimal encodings: a leading 0x00 is only legal when the next
    // byte has its high bit set (it disambiguates a positive value), and a
    // leading 0xFF is only legal when the next byte's high bit is clear.
    if let Some(&second) = tail.first() {
        if (first == 0x00 && second & 0x80 == 0) || (first == 0xFF && second & 0x80 != 0) {
            return Err(DerError::NonMinimalInteger);
        }
    }
    if content.len() > 8 {
        return Err(DerError::IntegerOutOfRange);
    }
    // Sign-extend from the most-significant byte across the full i64 width.
    let mut acc: i64 = if first & 0x80 != 0 { -1 } else { 0 };
    for &b in content {
        acc = (acc << 8) | i64::from(b);
    }
    Ok(acc)
}

/// Reads a single DER `INTEGER` from `value_der`, requiring it to consume the
/// entire buffer (no trailing bytes), and decodes it as an [`i64`].
pub(crate) fn parse_integer_only_i64(value_der: &[u8]) -> Result<i64, DerError> {
    let tlv = read_tlv_expect(value_der, TAG_INTEGER)?;
    if !tlv.rest.is_empty() {
        return Err(DerError::TrailingBytes);
    }
    parse_der_integer_i64(tlv.value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Object;

    /// Cross-check the pure-Rust OID encoder against OpenSSL's canonicalisation
    /// for every project OID.  This is the ground truth the encoder replaced:
    /// `encode_oid` must produce exactly `Asn1Object::as_slice()`.
    #[test]
    fn encode_oid_matches_openssl_for_project_oids() {
        for oid in [
            super::super::oids::HOST_BINDING_OID,
            super::super::oids::USER_BINDING_OID,
            super::super::oids::MAX_INTEGRITY_OID,
            super::super::oids::ALLOWED_ROLES_OID,
            super::super::oids::DELEGATION_CONSTRAINTS_OID,
            super::super::oids::PROFILE_VERSION_OID,
        ] {
            let ours = tessera_ext::der::encode_oid(oid).expect("project OID encodes");
            let openssl = Asn1Object::from_str(oid).expect("openssl parses");
            assert_eq!(
                ours.as_slice(),
                openssl.as_slice(),
                "encoder disagrees with OpenSSL for {oid}"
            );
        }
    }

    /// Encodes a `SEQUENCE OF UTF8String` body (without the outer SEQUENCE
    /// header) for use in tests.
    fn encode_utf8_strings(items: &[&str]) -> Vec<u8> {
        let mut inner = Vec::new();
        for s in items {
            inner.push(TAG_UTF8_STRING);
            // Test inputs are short — single-byte short-form length suffices.
            assert!(s.len() < 0x80, "test helper only supports short-form");
            inner.push(u8::try_from(s.len()).unwrap());
            inner.extend_from_slice(s.as_bytes());
        }
        let mut out = Vec::new();
        out.push(TAG_SEQUENCE);
        assert!(inner.len() < 0x80);
        out.push(u8::try_from(inner.len()).unwrap());
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn parses_seq_of_utf8_three_items() {
        let der = encode_utf8_strings(&["*", "sha256:abc", "raw"]);
        let parsed = parse_seq_of_utf8(&der).unwrap();
        assert_eq!(parsed, vec!["*", "sha256:abc", "raw"]);
    }

    #[test]
    fn parses_empty_sequence() {
        let der = encode_utf8_strings(&[]);
        let parsed = parse_seq_of_utf8(&der).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn rejects_wrong_inner_tag() {
        // SEQUENCE { OCTET STRING "x" }
        let der = vec![0x30, 0x03, 0x04, 0x01, b'x'];
        let err = parse_seq_of_utf8(&der).unwrap_err();
        assert!(matches!(err, DerError::UnexpectedTag(0x04)));
    }

    #[test]
    fn rejects_invalid_utf8() {
        // SEQUENCE { UTF8String <0xFF 0xFE> }
        let der = vec![0x30, 0x04, 0x0C, 0x02, 0xFF, 0xFE];
        let err = parse_seq_of_utf8(&der).unwrap_err();
        assert!(matches!(err, DerError::InvalidUtf8));
    }

    #[test]
    fn integer_decodes_small_positive() {
        assert_eq!(parse_der_integer_i64(&[0x07]).unwrap(), 7);
        assert_eq!(parse_der_integer_i64(&[0x00, 0x80]).unwrap(), 128);
        assert_eq!(parse_der_integer_i64(&[0x01, 0x00]).unwrap(), 256);
    }

    #[test]
    fn integer_decodes_negative() {
        assert_eq!(parse_der_integer_i64(&[0xFF]).unwrap(), -1);
        assert_eq!(parse_der_integer_i64(&[0x80]).unwrap(), -128);
    }

    #[test]
    fn integer_rejects_empty() {
        assert!(matches!(
            parse_der_integer_i64(&[]).unwrap_err(),
            DerError::Truncated
        ));
    }

    #[test]
    fn integer_rejects_non_minimal() {
        // Leading 0x00 with next high bit clear is non-minimal.
        assert!(matches!(
            parse_der_integer_i64(&[0x00, 0x07]).unwrap_err(),
            DerError::NonMinimalInteger
        ));
        // Leading 0xFF with next high bit set is non-minimal.
        assert!(matches!(
            parse_der_integer_i64(&[0xFF, 0x80]).unwrap_err(),
            DerError::NonMinimalInteger
        ));
    }

    #[test]
    fn integer_rejects_oversized() {
        assert!(matches!(
            parse_der_integer_i64(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            DerError::IntegerOutOfRange
        ));
    }

    #[test]
    fn integer_only_rejects_trailing() {
        // INTEGER 1, then a stray byte.
        let der = vec![0x02, 0x01, 0x01, 0x00];
        assert!(matches!(
            parse_integer_only_i64(&der).unwrap_err(),
            DerError::TrailingBytes
        ));
    }

    #[test]
    fn integer_only_rejects_wrong_tag() {
        // BOOLEAN, not INTEGER.  `read_tlv_expect` reports the tag mismatch as
        // a `TrustError`, surfaced here through `DerError::Tlv`.
        let der = vec![0x01, 0x01, 0xFF];
        assert!(matches!(
            parse_integer_only_i64(&der).unwrap_err(),
            DerError::Tlv(_)
        ));
    }
}

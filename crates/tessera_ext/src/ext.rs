//! Encoders, decoders, and a raw extension extractor for the Tessera custom
//! X.509 extensions, shared by the issuer and the Engine.
//!
//! The Engine already *parses* these extensions (out of an OpenSSL-verified
//! certificate); the issuer has to *produce* the exact same bytes and then
//! *re-parse* its own output as a contract self-check. Both directions live
//! here so the wire format has one definition:
//!
//! * `SEQUENCE OF UTF8String` — host-binding, user-binding, allowed-roles.
//! * `INTEGER` — profile-version.
//! * `SEQUENCE { level INTEGER, categories BIT STRING }` — max-integrity.
//! * a pure-Rust [`extract_extension`] that walks a certificate's DER and pulls
//!   out an extension's `extnValue` by OID — the same TLV walk the Engine's
//!   `der_helpers` performs, but without the OpenSSL dependency so it runs in
//!   `wasm32` and can back the issuer self-check.
//!
//! The delegation-constraints codec lives in [`crate::delegation`] alongside
//! its parser and the narrowing predicate.

use crate::der::{
    encode_der_integer_i64, encode_tlv, encode_utf8_string, parse_der_integer_i64, read_tlv,
    read_tlv_expect, DerError, TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID,
    TAG_SEQUENCE, TAG_UTF8_STRING,
};

/// The dotted OID of the standard `basicConstraints` extension.
pub const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";

/// Encodes a `SEQUENCE OF UTF8String` `extnValue` body from `items`, in order.
///
/// This is the wire shape of the host-binding, user-binding and allowed-roles
/// extensions. An empty slice yields a valid empty `SEQUENCE`.
#[must_use]
pub fn encode_seq_of_utf8<S: AsRef<str>>(items: &[S]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(&encode_utf8_string(item.as_ref()));
    }
    encode_tlv(TAG_SEQUENCE, &body)
}

/// Parses a `SEQUENCE OF UTF8String` `extnValue` body into its strings, in
/// order.
///
/// Fail-closed: any inner tag other than `UTF8String`, invalid UTF-8, or
/// trailing bytes after the outer `SEQUENCE` rejects the whole value.
///
/// # Errors
///
/// [`DerError`] on any structural problem or invalid UTF-8.
pub fn parse_seq_of_utf8(value_der: &[u8]) -> Result<Vec<String>, DerError> {
    let seq = read_tlv_expect(value_der, TAG_SEQUENCE)?;
    if !seq.rest.is_empty() {
        return Err(DerError::TrailingBytes);
    }
    let mut rest = seq.value;
    let mut out: Vec<String> = Vec::new();
    while !rest.is_empty() {
        let tlv = read_tlv_expect(rest, TAG_UTF8_STRING)?;
        let s = core::str::from_utf8(tlv.value).map_err(|_| DerError::InvalidUtf8)?;
        out.push(s.to_owned());
        rest = tlv.rest;
    }
    Ok(out)
}

/// Encodes a `pam_cert_profile_version` `extnValue`: a single DER `INTEGER`.
#[must_use]
pub fn encode_profile_version(version: u32) -> Vec<u8> {
    encode_der_integer_i64(i64::from(version))
}

/// Parses a `pam_cert_profile_version` `extnValue` back into its version number.
///
/// Fail-closed: rejects a non-`INTEGER`, trailing bytes, a non-minimal encoding,
/// or a negative value (versions are unsigned).
///
/// # Errors
///
/// [`DerError`] on any structural problem or an out-of-range value.
pub fn parse_profile_version(value_der: &[u8]) -> Result<u32, DerError> {
    let tlv = read_tlv_expect(value_der, TAG_INTEGER)?;
    if !tlv.rest.is_empty() {
        return Err(DerError::TrailingBytes);
    }
    let raw = parse_der_integer_i64(tlv.value)?;
    u32::try_from(raw).map_err(|_| DerError::IntegerOutOfRange)
}

/// Encodes a `pam_cert_max_integrity` `extnValue`:
/// `SEQUENCE { level INTEGER, categories BIT STRING }`.
///
/// The byte layout matches the Engine's `IntegrityLabel` DER exactly: `level`
/// is a one-octet two's-complement `INTEGER`, and `categories` is a minimal-
/// length `BIT STRING` (an all-zero mask yields an empty, one-octet body).
#[must_use]
pub fn encode_max_integrity(level: i8, categories: u64) -> Vec<u8> {
    let mut inner = Vec::with_capacity(16);
    inner.push(TAG_INTEGER);
    inner.push(0x01);
    inner.push(level.cast_unsigned());
    if categories == 0 {
        inner.extend_from_slice(&[TAG_BIT_STRING, 0x01, 0x00]);
    } else {
        let bytes = categories.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let payload = bytes.get(start..).unwrap_or(&[]);
        inner.push(TAG_BIT_STRING);
        // `payload` is at most 8 octets, so `payload.len() + 1 <= 9` fits a u8.
        inner.push(u8::try_from(payload.len() + 1).unwrap_or(0));
        inner.push(0x00);
        inner.extend_from_slice(payload);
    }
    encode_tlv(TAG_SEQUENCE, &inner)
}

/// Parses a `pam_cert_max_integrity` `extnValue` into `(level, categories)`.
///
/// Fail-closed on bad tags, a multi-octet level (would not fit `i8`), an
/// oversized `BIT STRING`, or trailing bytes.
///
/// # Errors
///
/// [`DerError`] on any structural problem.
pub fn parse_max_integrity(value_der: &[u8]) -> Result<(i8, u64), DerError> {
    let seq = read_tlv_expect(value_der, TAG_SEQUENCE)?;
    if !seq.rest.is_empty() {
        return Err(DerError::TrailingBytes);
    }
    let int = read_tlv_expect(seq.value, TAG_INTEGER)?;
    let level = match *int.value {
        [b] => i8::from_be_bytes([b]),
        _ => return Err(DerError::IntegerOutOfRange),
    };
    let categories = if int.rest.is_empty() {
        0
    } else {
        let bs = read_tlv_expect(int.rest, TAG_BIT_STRING)?;
        if !bs.rest.is_empty() {
            return Err(DerError::TrailingBytes);
        }
        let (&unused, bits) = bs.value.split_first().ok_or(DerError::MalformedBitString)?;
        if unused > 7 || bits.len() > 8 {
            return Err(DerError::MalformedBitString);
        }
        let mut buf = [0u8; 8];
        buf.get_mut(8 - bits.len()..)
            .ok_or(DerError::MalformedBitString)?
            .copy_from_slice(bits);
        u64::from_be_bytes(buf)
    };
    Ok((level, categories))
}

/// An extension pulled out of a certificate's DER by OID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedExtension {
    /// The `extnValue` content — the bytes *inside* the `OCTET STRING` wrapper.
    pub value: Vec<u8>,
    /// The `critical` flag (`BOOLEAN DEFAULT FALSE`).
    pub critical: bool,
}

/// Locates the extension whose OID equals `target_oid` (dotted) inside a
/// DER-encoded certificate and returns its `extnValue` bytes and `critical`
/// flag.
///
/// This is the pure-Rust twin of the Engine's `der_helpers::extract_extension_
/// by_oid`: it walks `Certificate → tbsCertificate → [3] extensions` and
/// compares each extension's OID against the DER encoding of `target_oid`
/// (via [`crate::der::encode_oid`]), so the project's wide `2.25.<UUID>` arcs
/// match without linking OpenSSL.
///
/// Returns `Ok(None)` when the extension is absent.
///
/// # Errors
///
/// [`DerError`] when `target_oid` is not a valid dotted OID or the certificate
/// structure is malformed.
pub fn extract_extension(
    cert_der: &[u8],
    target_oid: &str,
) -> Result<Option<ExtractedExtension>, DerError> {
    let target_bytes = crate::der::encode_oid(target_oid)?;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let outer = read_tlv_expect(cert_der, TAG_SEQUENCE)?;
    let tbs = read_tlv_expect(outer.value, TAG_SEQUENCE)?;

    // Walk the tbsCertificate fields for the `[3] EXPLICIT` extensions wrapper.
    let mut rest = tbs.value;
    let extensions_octets = loop {
        if rest.is_empty() {
            return Ok(None);
        }
        let tlv = read_tlv(rest)?;
        if tlv.tag == 0xA3 {
            break tlv.value;
        }
        rest = tlv.rest;
    };

    let ext_seq = read_tlv_expect(extensions_octets, TAG_SEQUENCE)?;
    let mut walker = ext_seq.value;
    while !walker.is_empty() {
        let ext_tlv = read_tlv_expect(walker, TAG_SEQUENCE)?;
        walker = ext_tlv.rest;
        let mut inner = ext_tlv.value;

        let oid = read_tlv_expect(inner, TAG_OID)?;
        inner = oid.rest;

        // Optional `critical BOOLEAN DEFAULT FALSE`.
        let mut critical = false;
        if !inner.is_empty() {
            let peek = read_tlv(inner)?;
            if peek.tag == TAG_BOOLEAN {
                critical = peek.value.first().copied().unwrap_or(0) != 0;
                inner = peek.rest;
            }
        }

        let octet = read_tlv_expect(inner, TAG_OCTET_STRING)?;
        if oid.value == target_bytes.as_slice() {
            return Ok(Some(ExtractedExtension {
                value: octet.value.to_vec(),
                critical,
            }));
        }
    }
    Ok(None)
}

/// Like [`extract_extension`] but returns only the `extnValue` bytes.
///
/// # Errors
///
/// See [`extract_extension`].
pub fn extract_extension_value(
    cert_der: &[u8],
    target_oid: &str,
) -> Result<Option<Vec<u8>>, DerError> {
    Ok(extract_extension(cert_der, target_oid)?.map(|ext| ext.value))
}

/// Returns the raw DER of a certificate's `subject` `Name` (the whole
/// `SEQUENCE` element, header included).
///
/// The issuer needs the parent CA's subject verbatim to use as the `issuer`
/// field of a child certificate. A Tessera CA carries the project's wide
/// `2.25.<UUID>` extension OIDs, which the `RustCrypto` `const-oid` parser cannot
/// represent — so the parent cannot be decoded with `x509-cert`, and this
/// byte-level walk extracts the name instead.
///
/// # Errors
///
/// [`DerError`] if the certificate is malformed or ends before the subject.
pub fn extract_subject_der(cert_der: &[u8]) -> Result<Vec<u8>, DerError> {
    let outer = read_tlv_expect(cert_der, TAG_SEQUENCE)?;
    let tbs = read_tlv_expect(outer.value, TAG_SEQUENCE)?;
    let mut rest = tbs.value;

    // Optional `version [0] EXPLICIT`.
    let peek = read_tlv(rest)?;
    if peek.tag == 0xA0 {
        rest = peek.rest;
    }
    // Skip serialNumber, signature, issuer, validity — the four elements before
    // subject in `TBSCertificate`.
    for _ in 0..4 {
        rest = read_tlv(rest)?.rest;
    }
    let subject_start = rest;
    let subject = read_tlv_expect(rest, TAG_SEQUENCE)?;
    let consumed = subject_start
        .len()
        .checked_sub(subject.rest.len())
        .ok_or(DerError::ValueTruncated)?;
    Ok(subject_start.get(..consumed).unwrap_or(&[]).to_vec())
}

/// The decoded `basicConstraints` of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConstraints {
    /// Whether the certificate is a CA (`cA`, `DEFAULT FALSE`).
    pub ca: bool,
    /// The optional `pathLenConstraint`.
    pub path_len: Option<u64>,
}

/// Extracts and decodes the `basicConstraints` extension, if present.
///
/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
/// pathLenConstraint INTEGER (0..MAX) OPTIONAL }`.
///
/// # Errors
///
/// [`DerError`] on a malformed certificate or extension body.
pub fn extract_basic_constraints(cert_der: &[u8]) -> Result<Option<BasicConstraints>, DerError> {
    let Some(value) = extract_extension_value(cert_der, BASIC_CONSTRAINTS_OID)? else {
        return Ok(None);
    };
    let seq = read_tlv_expect(&value, TAG_SEQUENCE)?;
    let mut rest = seq.value;
    let mut ca = false;
    let mut path_len = None;
    if !rest.is_empty() {
        let peek = read_tlv(rest)?;
        if peek.tag == TAG_BOOLEAN {
            ca = peek.value.first().copied().unwrap_or(0) != 0;
            rest = peek.rest;
        }
    }
    if !rest.is_empty() {
        let int = read_tlv_expect(rest, TAG_INTEGER)?;
        let raw = parse_der_integer_i64(int.value)?;
        path_len = u64::try_from(raw).ok();
    }
    Ok(Some(BasicConstraints { ca, path_len }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn seq_of_utf8_round_trips() {
        let items = ["*", "sha256:abc", "raw-machine-id"];
        let der = encode_seq_of_utf8(&items);
        let parsed = parse_seq_of_utf8(&der).expect("re-parses");
        assert_eq!(parsed, items);
    }

    #[test]
    fn seq_of_utf8_empty_round_trips() {
        let empty: [&str; 0] = [];
        let der = encode_seq_of_utf8(&empty);
        assert!(parse_seq_of_utf8(&der).expect("re-parses").is_empty());
    }

    #[test]
    fn seq_of_utf8_long_entry_uses_long_form() {
        // A > 127-octet entry forces the long-form length in the encoder.
        let long = "x".repeat(200);
        let der = encode_seq_of_utf8(&[long.as_str()]);
        let parsed = parse_seq_of_utf8(&der).expect("re-parses");
        assert_eq!(parsed, vec![long]);
    }

    #[test]
    fn profile_version_round_trips() {
        for v in [0u32, 1, 2, 255, 256, 65_535, u32::MAX] {
            let der = encode_profile_version(v);
            assert_eq!(parse_profile_version(&der).expect("re-parses"), v);
        }
    }

    #[test]
    fn max_integrity_round_trips() {
        for (level, cats) in [
            (0i8, 0u64),
            (5, 0),
            (-3, 0b1010),
            (127, u64::MAX),
            (-128, 1),
        ] {
            let der = encode_max_integrity(level, cats);
            assert_eq!(parse_max_integrity(&der).expect("re-parses"), (level, cats));
        }
    }

    #[test]
    fn max_integrity_zero_categories_is_empty_bit_string() {
        let der = encode_max_integrity(1, 0);
        // SEQUENCE { INTEGER 01 01 01, BIT STRING 03 01 00 }
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x00]);
    }
}

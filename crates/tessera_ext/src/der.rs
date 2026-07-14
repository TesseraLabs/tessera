//! Minimal DER primitives shared by the Engine and the issuer tooling.
//!
//! This is intentionally tiny: a byte-at-a-time TLV reader for the handful of
//! tags the Tessera extensions use, an OID encoder/decoder that handles the
//! wide (`~128-bit`) arcs of the project's `2.25.<UUID>` OIDs, and a DER
//! `INTEGER` decoder.  There is no support for indefinite lengths and no
//! allocation-heavy validation.
//!
//! The reader borrows from the source buffer and never copies.  All errors are
//! reported through [`DerError`], which is decoupled from any consumer's error
//! type so this crate stays free of `openssl` and the Engine's `TrustError`.

use thiserror::Error;

/// ASN.1 DER tag for `BOOLEAN`.
pub const TAG_BOOLEAN: u8 = 0x01;
/// ASN.1 DER tag for `INTEGER`.
pub const TAG_INTEGER: u8 = 0x02;
/// ASN.1 DER tag for `BIT STRING`.
pub const TAG_BIT_STRING: u8 = 0x03;
/// ASN.1 DER tag for `OCTET STRING`.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// ASN.1 DER tag for `OBJECT IDENTIFIER`.
pub const TAG_OID: u8 = 0x06;
/// ASN.1 DER tag for `ENUMERATED`.
pub const TAG_ENUMERATED: u8 = 0x0A;
/// ASN.1 DER tag for `UTF8String`.
pub const TAG_UTF8_STRING: u8 = 0x0C;
/// ASN.1 DER tag for `SEQUENCE` (constructed).
pub const TAG_SEQUENCE: u8 = 0x30;

/// Errors produced by the DER primitives in this module.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DerError {
    /// The buffer was too short to hold a TLV header.
    #[error("der: header truncated")]
    HeaderTruncated,
    /// The length field used an indefinite or over-4-byte long form.
    #[error("der: indefinite or oversized length")]
    LengthUnsupported,
    /// The declared long-form length ran past the end of the buffer.
    #[error("der: length truncated")]
    LengthTruncated,
    /// The header length plus content length overflowed [`usize`].
    #[error("der: length overflow")]
    LengthOverflow,
    /// The declared content length ran past the end of the buffer.
    #[error("der: value truncated")]
    ValueTruncated,
    /// A tag-checked read found a tag other than the one required.
    #[error("der: expected tag 0x{expected:02x}, got 0x{found:02x}")]
    UnexpectedTag {
        /// The tag the caller required.
        expected: u8,
        /// The tag actually present.
        found: u8,
    },
    /// An OID had no content octets.
    #[error("der: empty oid")]
    EmptyOid,
    /// An OID arc ran off the end of the content octets (a dangling high bit).
    #[error("der: truncated oid arc")]
    TruncatedOidArc,
    /// An OID arc did not fit in [`u128`].
    #[error("der: oid arc overflow")]
    OidArcOverflow,
    /// A dotted OID string could not be encoded (bad arc, too few arcs, or an
    /// out-of-range top arc).
    #[error("der: invalid oid: {0}")]
    InvalidOid(String),
    /// A DER `INTEGER` had empty content.
    #[error("der: input truncated")]
    IntegerTruncated,
    /// A DER `INTEGER` used a non-minimal (non-canonical) encoding.
    #[error("der: non-minimal integer encoding")]
    NonMinimalInteger,
    /// A DER `INTEGER` did not fit the target Rust integer type.
    #[error("der: integer out of range")]
    IntegerOutOfRange,
    /// A `UTF8String` value was not valid UTF-8.
    #[error("der: invalid utf-8 in utf8string")]
    InvalidUtf8,
    /// Bytes remained after a value that should have consumed its whole buffer.
    #[error("der: trailing bytes after value")]
    TrailingBytes,
    /// A `BIT STRING` had a bad unused-bits count or an over-wide payload.
    #[error("der: malformed bit string")]
    MalformedBitString,
}

/// A parsed TLV element borrowed from the source buffer.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// The tag octet.
    pub tag: u8,
    /// The content octets (the `V` of `TLV`).
    pub value: &'a [u8],
    /// The bytes following this element in the source buffer.
    pub rest: &'a [u8],
}

/// Parses one TLV element from the start of `input`.
///
/// # Errors
///
/// Returns a [`DerError`] if the buffer is truncated or uses an unsupported
/// (indefinite or > 4-byte) length form.
pub fn read_tlv(input: &[u8]) -> Result<Tlv<'_>, DerError> {
    let [tag, len_byte, ..] = *input else {
        return Err(DerError::HeaderTruncated);
    };
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), 2)
    } else {
        let n_bytes = usize::from(len_byte & 0x7F);
        if n_bytes == 0 || n_bytes > 4 {
            return Err(DerError::LengthUnsupported);
        }
        if input.len() < 2 + n_bytes {
            return Err(DerError::LengthTruncated);
        }
        let mut acc: usize = 0;
        let len_bytes = input.get(2..2 + n_bytes).ok_or(DerError::LengthTruncated)?;
        for &b in len_bytes {
            acc = (acc << 8) | usize::from(b);
        }
        (acc, 2 + n_bytes)
    };
    let end = header_len
        .checked_add(len)
        .ok_or(DerError::LengthOverflow)?;
    let value = input.get(header_len..end).ok_or(DerError::ValueTruncated)?;
    let rest = input.get(end..).ok_or(DerError::ValueTruncated)?;
    Ok(Tlv { tag, value, rest })
}

/// Reads a tag-checked TLV from `input`.
///
/// # Errors
///
/// Returns [`DerError::UnexpectedTag`] on a tag mismatch, or any error from
/// [`read_tlv`].
pub fn read_tlv_expect(input: &[u8], tag: u8) -> Result<Tlv<'_>, DerError> {
    let tlv = read_tlv(input)?;
    if tlv.tag != tag {
        return Err(DerError::UnexpectedTag {
            expected: tag,
            found: tlv.tag,
        });
    }
    Ok(tlv)
}

/// Renders an OID's DER *content* octets into the canonical dotted notation
/// (e.g. `1.3.6.1.5.5.7.3.2`).
///
/// The project's UUID-derived OIDs (`2.25.<128-bit UUID>`) fit in 128 bits, so
/// a single arc may be up to ~128 bits wide; the accumulator is [`u128`] and
/// anything that would overflow it is rejected.
///
/// # Errors
///
/// Returns a [`DerError`] when the encoding is malformed.
pub fn oid_to_dotted(content: &[u8]) -> Result<String, DerError> {
    let (&first, rest_bytes) = content.split_first().ok_or(DerError::EmptyOid)?;
    let arc1 = u128::from(first / 40);
    let arc2 = u128::from(first % 40);
    let mut parts: Vec<u128> = Vec::with_capacity(8);
    parts.push(arc1);
    parts.push(arc2);

    let mut iter = rest_bytes.iter();
    while let Some(&byte) = iter.next() {
        let mut value = u128::from(byte & 0x7F);
        let mut more = byte & 0x80 != 0;
        while more {
            let &b = iter.next().ok_or(DerError::TruncatedOidArc)?;
            // Detect overflow before the shift would lose high bits.
            if value > (u128::MAX >> 7) {
                return Err(DerError::OidArcOverflow);
            }
            value = (value << 7) | u128::from(b & 0x7F);
            more = b & 0x80 != 0;
        }
        parts.push(value);
    }

    let mut out = String::with_capacity(parts.len() * 4);
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            out.push('.');
        }
        out.push_str(&part.to_string());
    }
    Ok(out)
}

/// Encodes a dotted OID string (e.g. `2.25.<UUID>`) into its DER *content*
/// octets — the value of the `OBJECT IDENTIFIER`, without the `0x06` tag or the
/// length prefix.
///
/// This replaces the previous strategy of round-tripping the OID through
/// OpenSSL's `Asn1Object`, which the wasm/issuer side cannot link.  The result
/// is byte-for-byte identical to `Asn1Object::from_str(oid).as_slice()` (the
/// Engine cross-checks this against OpenSSL for every project OID).
///
/// # Errors
///
/// Returns [`DerError::InvalidOid`] if the string has fewer than two arcs, a
/// non-numeric or over-128-bit arc, a first arc greater than 2, or a second arc
/// ≥ 40 while the first arc is below 2.
pub fn encode_oid(dotted: &str) -> Result<Vec<u8>, DerError> {
    let mut arcs = dotted.split('.');
    let top = parse_arc(arcs.next())?;
    let second = parse_arc(arcs.next())?;
    if top > 2 {
        return Err(DerError::InvalidOid(format!("first arc {top} exceeds 2")));
    }
    if top < 2 && second >= 40 {
        return Err(DerError::InvalidOid(format!(
            "second arc {second} must be < 40 when first arc is {top}"
        )));
    }
    // `top <= 2`, so `40 * top + second` cannot overflow u128 for any valid second arc.
    let first_subid = (top * 40)
        .checked_add(second)
        .ok_or_else(|| DerError::InvalidOid("first subidentifier overflow".to_owned()))?;

    let mut out = Vec::new();
    encode_base128(first_subid, &mut out);
    for arc in arcs {
        let value = parse_arc(Some(arc))?;
        encode_base128(value, &mut out);
    }
    Ok(out)
}

/// Parses a single dotted-notation arc into a [`u128`].
fn parse_arc(arc: Option<&str>) -> Result<u128, DerError> {
    let arc = arc.ok_or_else(|| DerError::InvalidOid("fewer than two arcs".to_owned()))?;
    arc.parse::<u128>()
        .map_err(|_| DerError::InvalidOid(format!("arc {arc:?} is not a u128")))
}

/// Appends `value` to `out` as base-128 subidentifier octets: 7 bits per octet,
/// most-significant group first, continuation bit (`0x80`) set on every octet
/// but the last.
fn encode_base128(value: u128, out: &mut Vec<u8>) {
    // Collect 7-bit groups least-significant first, then emit reversed.
    let mut groups: Vec<u8> = Vec::new();
    let mut remaining = value;
    loop {
        // `remaining & 0x7F` is at most 127, so the conversion never truncates.
        let group = u8::try_from(remaining & 0x7F).unwrap_or(0);
        groups.push(group);
        remaining >>= 7;
        if remaining == 0 {
            break;
        }
    }
    let last = groups.len() - 1;
    for (idx, &group) in groups.iter().rev().enumerate() {
        let octet = if idx == last { group } else { group | 0x80 };
        out.push(octet);
    }
}

/// Decodes a DER `INTEGER` value (the TLV *content* bytes, big-endian
/// two's-complement) into an [`i64`].
///
/// Fail-closed: rejects empty content, non-minimal (non-canonical) encodings,
/// and any magnitude that does not fit `i64`.
///
/// # Errors
///
/// [`DerError::IntegerTruncated`], [`DerError::NonMinimalInteger`], or
/// [`DerError::IntegerOutOfRange`].
pub fn parse_der_integer_i64(content: &[u8]) -> Result<i64, DerError> {
    let (&first, tail) = content.split_first().ok_or(DerError::IntegerTruncated)?;
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

/// Appends a DER length prefix for a `len`-octet content field to `out`.
///
/// Short form for `len < 128`, otherwise the long form (`0x80 | n`, then the
/// `n` big-endian significant length octets). The issuer produces certificates
/// and CRLs whose inner fields routinely exceed 127 octets, so the long form is
/// required — not just a convenience.
pub fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        // `len < 128`, so the conversion cannot truncate.
        out.push(u8::try_from(len).unwrap_or(0));
        return;
    }
    let be = len.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let significant = be.get(start..).unwrap_or(&[]);
    // A `usize` is at most 8 octets, so `significant.len() <= 8 < 128` and the
    // `0x80 | n` header byte never collides with the short-form range.
    out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
    out.extend_from_slice(significant);
}

/// Encodes one TLV element — `tag`, a DER length, then `content` — into a fresh
/// buffer.
#[must_use]
pub fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// Encodes a `UTF8String` TLV.
#[must_use]
pub fn encode_utf8_string(value: &str) -> Vec<u8> {
    encode_tlv(TAG_UTF8_STRING, value.as_bytes())
}

/// Encodes a signed value as a minimal (canonical) DER `INTEGER` TLV.
///
/// The output is the exact two's-complement minimal encoding
/// [`parse_der_integer_i64`] accepts: redundant leading `0x00`/`0xFF` octets are
/// stripped while preserving the sign, so a round-trip through the decoder
/// returns the input unchanged.
#[must_use]
pub fn encode_der_integer_i64(value: i64) -> Vec<u8> {
    let be = value.to_be_bytes();
    // Drop a leading octet whenever it is redundant with the sign of the next:
    // `0x00` before a clear high bit, or `0xFF` before a set high bit. Stop
    // before consuming the final octet so at least one octet always remains.
    let mut idx = 0;
    while idx + 1 < be.len() {
        let (cur, next) = (be.get(idx).copied(), be.get(idx + 1).copied());
        match (cur, next) {
            (Some(0x00), Some(n)) if n & 0x80 == 0 => idx += 1,
            (Some(0xFF), Some(n)) if n & 0x80 != 0 => idx += 1,
            _ => break,
        }
    }
    encode_tlv(TAG_INTEGER, be.get(idx..).unwrap_or(&[]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_form_length() {
        let buf = [0x30u8, 0x03, 0x02, 0x01, 0x00];
        let tlv = read_tlv(&buf).expect("short form parses");
        assert_eq!(tlv.tag, 0x30);
        assert_eq!(tlv.value, &[0x02, 0x01, 0x00]);
        assert!(tlv.rest.is_empty());
    }

    #[test]
    fn parses_long_form_length() {
        let mut buf = vec![0x04u8, 0x82, 0x01, 0x00];
        buf.extend(std::iter::repeat_n(0xAAu8, 256));
        let tlv = read_tlv(&buf).expect("long form parses");
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.value.len(), 256);
    }

    #[test]
    fn rejects_truncated_value() {
        let buf = [0x04u8, 0x05, 0x01, 0x02]; // claims 5, has 2
        assert!(read_tlv(&buf).is_err());
    }

    #[test]
    fn read_tlv_expect_reports_mismatch() {
        let buf = [0x02u8, 0x01, 0x00];
        let err = read_tlv_expect(&buf, TAG_SEQUENCE).unwrap_err();
        assert_eq!(
            err,
            DerError::UnexpectedTag {
                expected: TAG_SEQUENCE,
                found: TAG_INTEGER,
            }
        );
    }

    #[test]
    fn dotted_oid_round_trip() {
        // 1.3.6.1.5.5.7.3.2 (clientAuth) content octets.
        let oid = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        let dotted = oid_to_dotted(&oid).expect("dotted OID parses");
        assert_eq!(dotted, "1.3.6.1.5.5.7.3.2");
    }

    #[test]
    fn encode_oid_known_vectors() {
        // clientAuth: standard two-arc-plus-tail OID.
        assert_eq!(
            encode_oid("1.3.6.1.5.5.7.3.2").expect("encodes"),
            vec![0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]
        );
        // basicConstraints 2.5.29.19: 40*2 + 5 = 85 = 0x55, then 29, 19.
        assert_eq!(
            encode_oid("2.5.29.19").expect("encodes"),
            vec![0x55, 0x1D, 0x13]
        );
    }

    #[test]
    fn encode_oid_round_trips_through_decoder() {
        for oid in [
            crate::oids::HOST_BINDING_OID,
            crate::oids::USER_BINDING_OID,
            crate::oids::MAX_INTEGRITY_OID,
            crate::oids::ALLOWED_ROLES_OID,
            crate::oids::DELEGATION_CONSTRAINTS_OID,
            crate::oids::PROFILE_VERSION_OID,
        ] {
            let content = encode_oid(oid).expect("project OID encodes");
            let decoded = oid_to_dotted(&content).expect("re-decodes");
            assert_eq!(decoded, oid, "round-trip mismatch for {oid}");
        }
    }

    #[test]
    fn encode_oid_rejects_malformed() {
        assert!(matches!(encode_oid("2"), Err(DerError::InvalidOid(_))));
        assert!(matches!(encode_oid("3.1"), Err(DerError::InvalidOid(_))));
        assert!(matches!(encode_oid("1.40"), Err(DerError::InvalidOid(_))));
        assert!(matches!(encode_oid("2.x"), Err(DerError::InvalidOid(_))));
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
        assert_eq!(
            parse_der_integer_i64(&[]).unwrap_err(),
            DerError::IntegerTruncated
        );
    }

    #[test]
    fn integer_rejects_non_minimal() {
        assert_eq!(
            parse_der_integer_i64(&[0x00, 0x07]).unwrap_err(),
            DerError::NonMinimalInteger
        );
        assert_eq!(
            parse_der_integer_i64(&[0xFF, 0x80]).unwrap_err(),
            DerError::NonMinimalInteger
        );
    }

    #[test]
    fn integer_rejects_oversized() {
        assert_eq!(
            parse_der_integer_i64(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            DerError::IntegerOutOfRange
        );
    }

    #[test]
    fn encode_length_short_and_long_form() {
        let mut short = Vec::new();
        encode_length(5, &mut short);
        assert_eq!(short, vec![0x05]);

        let mut long = Vec::new();
        encode_length(256, &mut long);
        assert_eq!(long, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn encode_tlv_round_trips_through_reader() {
        let content = vec![0xAAu8; 300];
        let tlv_bytes = encode_tlv(TAG_OCTET_STRING, &content);
        let parsed = read_tlv(&tlv_bytes).expect("re-reads");
        assert_eq!(parsed.tag, TAG_OCTET_STRING);
        assert_eq!(parsed.value, content.as_slice());
        assert!(parsed.rest.is_empty());
    }

    #[test]
    fn encode_integer_matches_decoder_for_edge_values() {
        for value in [
            0i64,
            1,
            127,
            128,
            255,
            256,
            -1,
            -128,
            -129,
            i64::MAX,
            i64::MIN,
        ] {
            let tlv_bytes = encode_der_integer_i64(value);
            let tlv = read_tlv_expect(&tlv_bytes, TAG_INTEGER).expect("integer TLV");
            assert!(tlv.rest.is_empty(), "trailing bytes for {value}");
            assert_eq!(
                parse_der_integer_i64(tlv.value).expect("decodes"),
                value,
                "round-trip mismatch for {value}"
            );
        }
    }

    #[test]
    fn encode_integer_128_uses_leading_zero() {
        // 128 needs a leading 0x00 so the high bit does not read as negative.
        let tlv_bytes = encode_der_integer_i64(128);
        assert_eq!(tlv_bytes, vec![TAG_INTEGER, 0x02, 0x00, 0x80]);
    }
}

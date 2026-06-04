//! Minimal safe DER parser used to read X.509 extension contents that the
//! high-level `openssl` 0.10 API does not expose directly (`KeyUsage`,
//! `BasicConstraints`, `ExtendedKeyUsage`).
//!
//! This is intentionally tiny: it covers only the tags and length encodings
//! used by the few extensions consumed in this crate.  No allocation-heavy
//! validation, no support for indefinite lengths.

use super::TrustError;

/// ASN.1 DER tag for `BOOLEAN`.
pub(crate) const TAG_BOOLEAN: u8 = 0x01;
/// ASN.1 DER tag for `INTEGER`.
pub(crate) const TAG_INTEGER: u8 = 0x02;
/// ASN.1 DER tag for `BIT STRING`.
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
/// ASN.1 DER tag for `OCTET STRING`.
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
/// ASN.1 DER tag for `OBJECT IDENTIFIER`.
pub(crate) const TAG_OID: u8 = 0x06;
/// ASN.1 DER tag for `SEQUENCE` (constructed).
pub(crate) const TAG_SEQUENCE: u8 = 0x30;

/// A parsed TLV element borrowed from the source buffer.
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub rest: &'a [u8],
}

/// Parses one TLV element from the start of `input`.
///
/// # Errors
///
/// Returns [`TrustError::CertParse`] if the buffer is truncated or uses an
/// unsupported (indefinite or > 4-byte) length form.
pub(crate) fn read_tlv(input: &[u8]) -> Result<Tlv<'_>, TrustError> {
    if input.len() < 2 {
        return Err(TrustError::CertParse("der: header truncated".into()));
    }
    let tag = input[0];
    let len_byte = input[1];
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), 2)
    } else {
        let n_bytes = usize::from(len_byte & 0x7F);
        if n_bytes == 0 || n_bytes > 4 {
            return Err(TrustError::CertParse(
                "der: indefinite or oversized length".into(),
            ));
        }
        if input.len() < 2 + n_bytes {
            return Err(TrustError::CertParse("der: length truncated".into()));
        }
        let mut acc: usize = 0;
        for &b in &input[2..2 + n_bytes] {
            acc = (acc << 8) | usize::from(b);
        }
        (acc, 2 + n_bytes)
    };
    let end = header_len
        .checked_add(len)
        .ok_or_else(|| TrustError::CertParse("der: length overflow".into()))?;
    if input.len() < end {
        return Err(TrustError::CertParse("der: value truncated".into()));
    }
    Ok(Tlv {
        tag,
        value: &input[header_len..end],
        rest: &input[end..],
    })
}

/// Reads a tag-checked TLV from `input`.
pub(crate) fn read_tlv_expect(input: &[u8], tag: u8) -> Result<Tlv<'_>, TrustError> {
    let tlv = read_tlv(input)?;
    if tlv.tag != tag {
        return Err(TrustError::CertParse(format!(
            "der: expected tag 0x{:02x}, got 0x{:02x}",
            tag, tlv.tag
        )));
    }
    Ok(tlv)
}

/// Renders an OID's DER content into the canonical dotted notation
/// (e.g. `1.3.6.1.5.5.7.3.2`).
///
/// # Errors
///
/// Returns [`TrustError::CertParse`] when the encoding is malformed.
pub(crate) fn oid_to_dotted(content: &[u8]) -> Result<String, TrustError> {
    if content.is_empty() {
        return Err(TrustError::CertParse("der: empty oid".into()));
    }
    let first = content[0];
    let arc1 = u128::from(first / 40);
    let arc2 = u128::from(first % 40);
    let mut parts: Vec<u128> = Vec::with_capacity(8);
    parts.push(arc1);
    parts.push(arc2);

    let mut i = 1usize;
    // Arc bound: the project's UUID-derived OIDs (`2.25.<128-bit UUID>`)
    // fit in 128 bits, so a single arc may be up to ~128 bits.  The
    // accumulator is u128; reject anything that would overflow it.
    while i < content.len() {
        let mut value: u128 = 0;
        loop {
            if i >= content.len() {
                return Err(TrustError::CertParse("der: truncated oid arc".into()));
            }
            let b = content[i];
            i += 1;
            // Detect overflow before the shift would lose high bits.
            if value > (u128::MAX >> 7) {
                return Err(TrustError::CertParse("der: oid arc overflow".into()));
            }
            value = (value << 7) | u128::from(b & 0x7F);
            if b & 0x80 == 0 {
                break;
            }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `read_tlv` parses a 2-byte short-form length and returns the body.
    #[test]
    fn parses_short_form_length() {
        let buf = [0x30u8, 0x03, 0x02, 0x01, 0x00];
        let tlv = read_tlv(&buf).expect("short form parses");
        assert_eq!(tlv.tag, 0x30);
        assert_eq!(tlv.value, &[0x02, 0x01, 0x00]);
        assert!(tlv.rest.is_empty());
    }

    /// `read_tlv` handles the multi-byte long-form length encoding.
    #[test]
    fn parses_long_form_length() {
        let mut buf = vec![0x04u8, 0x82, 0x01, 0x00];
        buf.extend(std::iter::repeat_n(0xAAu8, 256));
        let tlv = read_tlv(&buf).expect("long form parses");
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.value.len(), 256);
    }

    /// `read_tlv` errors when the declared length exceeds the buffer.
    #[test]
    fn rejects_truncated_value() {
        let buf = [0x04u8, 0x05, 0x01, 0x02]; // claims 5, has 2
        assert!(read_tlv(&buf).is_err());
    }

    /// `oid_to_dotted` round-trips a known clientAuth OID encoding.
    #[test]
    fn dotted_oid_round_trip() {
        // 1.3.6.1.5.5.7.3.2  encoded
        let oid = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        let dotted = oid_to_dotted(&oid).expect("dotted OID parses");
        assert_eq!(dotted, "1.3.6.1.5.5.7.3.2");
    }
}

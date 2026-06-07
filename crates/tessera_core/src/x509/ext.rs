//! Low-level X.509 extension accessors.
//!
//! `openssl` 0.10.78 does not expose typed accessors for `keyUsage`,
//! `basicConstraints`, or `extendedKeyUsage`.  We walk the extension stack
//! ourselves and parse just the bits that stage-2 needs.
//!
//! Keep all DER manipulation here so the rest of the crate sees a typed
//! façade only.

use super::der::{
    oid_to_dotted, read_tlv, read_tlv_expect, TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER,
    TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};
use super::TrustError;
use openssl::x509::X509;

/// OID for `keyUsage` (2.5.29.15).
const OID_KEY_USAGE: &str = "2.5.29.15";
/// OID for `basicConstraints` (2.5.29.19).
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
/// OID for `extendedKeyUsage` (2.5.29.37).
const OID_EXT_KEY_USAGE: &str = "2.5.29.37";

/// Parsed view of `basicConstraints`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConstraintsView {
    /// `cA` boolean (default FALSE per RFC 5280).
    pub is_ca: bool,
    /// Optional `pathLenConstraint`.
    pub path_len: Option<u32>,
}

/// Returns the dotted OIDs listed in the `extendedKeyUsage` extension.
pub(crate) fn eku_oids(cert: &X509) -> Result<Vec<String>, TrustError> {
    let Some(value) = extension_value(cert, OID_EXT_KEY_USAGE)? else {
        return Ok(Vec::new());
    };
    let seq = read_tlv_expect(&value, TAG_SEQUENCE)?;
    let mut rest = seq.value;
    let mut out: Vec<String> = Vec::new();
    while !rest.is_empty() {
        let oid = read_tlv_expect(rest, TAG_OID)?;
        out.push(oid_to_dotted(oid.value)?);
        rest = oid.rest;
    }
    Ok(out)
}

/// Returns whether `keyUsage` includes the requested bit.
///
/// Bit numbering matches RFC 5280 (digitalSignature = 0, keyCertSign = 5).
pub(crate) fn key_usage_bit(cert: &X509, bit: u8) -> Result<bool, TrustError> {
    let Some(value) = extension_value(cert, OID_KEY_USAGE)? else {
        return Ok(false);
    };
    let bs = read_tlv_expect(&value, TAG_BIT_STRING)?;
    let Some((&unused, bytes)) = bs.value.split_first() else {
        return Ok(false);
    };
    if bytes.is_empty() {
        return Ok(false);
    }
    let byte_index = usize::from(bit / 8);
    if byte_index >= bytes.len() {
        return Ok(false);
    }
    let bit_in_byte = bit % 8;
    // RFC 5280: bit 0 is the most significant bit of the first byte.
    let mask = 0x80u8 >> bit_in_byte;
    let last_byte = bytes.len() - 1;
    if byte_index == last_byte && bit_in_byte >= (8 - unused) {
        // bit is in the unused portion
        return Ok(false);
    }
    // `byte_index < bytes.len()` проверено выше, поэтому байт всегда есть.
    Ok(bytes.get(byte_index).is_some_and(|b| b & mask != 0))
}

/// Parses the `basicConstraints` extension if present.
pub(crate) fn basic_constraints(cert: &X509) -> Result<Option<BasicConstraintsView>, TrustError> {
    let Some(value) = extension_value(cert, OID_BASIC_CONSTRAINTS)? else {
        return Ok(None);
    };
    let seq = read_tlv_expect(&value, TAG_SEQUENCE)?;
    let mut rest = seq.value;
    let mut is_ca = false;
    let mut path_len: Option<u32> = None;
    if !rest.is_empty() {
        let first = read_tlv(rest)?;
        if first.tag == TAG_BOOLEAN {
            is_ca = first.value.first().copied().unwrap_or(0) != 0;
            rest = first.rest;
        }
    }
    if !rest.is_empty() {
        let next = read_tlv(rest)?;
        if next.tag == TAG_INTEGER {
            let mut acc: u64 = 0;
            for &b in next.value {
                acc = (acc << 8) | u64::from(b);
                if acc > u64::from(u32::MAX) {
                    return Err(TrustError::CertParse(
                        "basicConstraints: pathLen overflow".into(),
                    ));
                }
            }
            let casted = u32::try_from(acc)
                .map_err(|_| TrustError::CertParse("basicConstraints: pathLen overflow".into()))?;
            path_len = Some(casted);
        }
    }
    Ok(Some(BasicConstraintsView { is_ca, path_len }))
}

/// Locates the OCTET STRING value of an extension by its dotted OID.
///
/// Returns the *content* of the OCTET STRING (i.e. the parsed `extnValue`).
fn extension_value(cert: &X509, target_oid: &str) -> Result<Option<Vec<u8>>, TrustError> {
    let stack = match cert.to_der() {
        Ok(b) => b,
        Err(e) => return Err(TrustError::Openssl(e)),
    };
    // Walk: Certificate -> SEQUENCE { tbsCertificate, ... }; tbsCertificate ::= SEQUENCE { ... }
    // tbsCertificate fields end with [3] EXPLICIT extensions OPTIONAL
    let outer = read_tlv_expect(&stack, TAG_SEQUENCE)?;
    let tbs = read_tlv_expect(outer.value, TAG_SEQUENCE)?;
    // Walk through tbsCertificate until we find context-specific [3] EXPLICIT.
    let mut rest = tbs.value;
    let extensions_octets: Option<&[u8]> = loop {
        if rest.is_empty() {
            break None;
        }
        let tlv = read_tlv(rest)?;
        if tlv.tag == 0xA3 {
            // [3] EXPLICIT — wraps a SEQUENCE OF Extension
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
        // optional critical BOOLEAN
        if !inner.is_empty() {
            let peek = read_tlv(inner)?;
            if peek.tag == TAG_BOOLEAN {
                inner = peek.rest;
            }
        }
        let octet = read_tlv_expect(inner, TAG_OCTET_STRING)?;
        let dotted = oid_to_dotted(oid.value)?;
        if dotted == target_oid {
            return Ok(Some(octet.value.to_vec()));
        }
    }
    Ok(None)
}

/// Returns the subject key identifier (the raw octet content of SKI), if present.
pub(crate) fn ski(cert: &X509) -> Option<Vec<u8>> {
    cert.subject_key_id().map(|id| id.as_slice().to_vec())
}

/// Returns the authority key identifier `keyIdentifier` field, if present.
pub(crate) fn aki_key_id(cert: &X509) -> Option<Vec<u8>> {
    cert.authority_key_id().map(|id| id.as_slice().to_vec())
}

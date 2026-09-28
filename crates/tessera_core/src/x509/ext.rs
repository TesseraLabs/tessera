//! Low-level X.509 extension accessors.
//!
//! `openssl` 0.10.78 does not expose typed accessors for `keyUsage`,
//! `basicConstraints`, or `extendedKeyUsage`.  We walk the extension stack
//! ourselves and parse just the bits that stage-2 needs.
//!
//! Keep all DER manipulation here so the rest of the crate sees a typed
//! façade only.

use super::der::{
    oid_to_dotted, read_tlv, read_tlv_expect, TAG_BIT_STRING, TAG_BOOLEAN, TAG_OCTET_STRING,
    TAG_OID, TAG_SEQUENCE,
};
use super::TrustError;
use openssl::x509::X509;

/// OID for `keyUsage` (2.5.29.15).
const OID_KEY_USAGE: &str = "2.5.29.15";
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
    let malformed = || TrustError::CertParse("keyUsage: malformed bit string".to_owned());
    if !bs.rest.is_empty() {
        return Err(malformed());
    }
    let Some((&unused, bytes)) = bs.value.split_first() else {
        return Err(malformed());
    };
    // Validate the whole value before any bit lookup or subtraction. Malformed
    // input must neither panic nor be hidden by a request for an absent bit.
    if unused > 7 || (bytes.is_empty() && unused != 0) {
        return Err(malformed());
    }
    let padding = (1u8 << unused) - 1;
    if bytes.last().is_some_and(|last| last & padding != 0) {
        return Err(malformed());
    }
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
    let der = cert.to_der().map_err(TrustError::Openssl)?;
    // One strict decoding rule is shared with the issuer tooling. The Engine
    // keeps its existing u32 path-length bound on top of the shared u64 view.
    tessera_ext::ext::extract_basic_constraints(&der)?
        .map(|value| {
            let path_len =
                value.path_len.map(u32::try_from).transpose().map_err(|_| {
                    TrustError::CertParse("basicConstraints: pathLen overflow".into())
                })?;
            Ok(BasicConstraintsView {
                is_ca: value.ca,
                path_len,
            })
        })
        .transpose()
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

/// Returns the dotted OIDs of every extension marked `critical` in `cert`.
///
/// Walks the DER directly because `openssl` 0.10 exposes no API to enumerate
/// an arbitrary extension's `critical` bit.  An extension whose
/// `critical BOOLEAN` is present and TRUE is collected; absent (DEFAULT FALSE)
/// or explicitly FALSE is skipped.  The chain verifier compares the result
/// against a known-critical allowlist and rejects any unrecognised critical
/// OID (RFC 5280 §4.2 / `PwnKit` fail-closed).
///
/// # Errors
///
/// Returns [`TrustError::CertParse`] when the certificate structure is
/// malformed (the same fail-closed behaviour as [`extension_value`]).
pub(crate) fn critical_extension_oids(cert: &X509) -> Result<Vec<String>, TrustError> {
    let der = cert.to_der().map_err(TrustError::Openssl)?;
    let outer = read_tlv_expect(&der, TAG_SEQUENCE)?;
    let tbs = read_tlv_expect(outer.value, TAG_SEQUENCE)?;
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
        return Ok(Vec::new());
    };
    let ext_seq = read_tlv_expect(ext_outer, TAG_SEQUENCE)?;
    let mut walker = ext_seq.value;
    let mut out: Vec<String> = Vec::new();
    while !walker.is_empty() {
        let ext_tlv = read_tlv_expect(walker, TAG_SEQUENCE)?;
        walker = ext_tlv.rest;
        let mut inner = ext_tlv.value;
        let oid = read_tlv_expect(inner, TAG_OID)?;
        inner = oid.rest;
        // Optional `critical BOOLEAN DEFAULT FALSE`.  Present-and-nonzero is
        // critical; absent or zero is not.
        let mut critical = false;
        if !inner.is_empty() {
            let peek = read_tlv(inner)?;
            if peek.tag == TAG_BOOLEAN {
                critical = peek.value.first().copied().unwrap_or(0) != 0;
            }
        }
        if critical {
            out.push(oid_to_dotted(oid.value)?);
        }
    }
    Ok(out)
}

/// Returns the subject key identifier (the raw octet content of SKI), if present.
pub(crate) fn ski(cert: &X509) -> Option<Vec<u8>> {
    cert.subject_key_id().map(|id| id.as_slice().to_vec())
}

/// Returns the authority key identifier `keyIdentifier` field, if present.
pub(crate) fn aki_key_id(cert: &X509) -> Option<Vec<u8>> {
    cert.authority_key_id().map(|id| id.as_slice().to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod malformed_extension_tests {
    use super::*;
    use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Extension, X509NameBuilder};

    fn certificate(oid: &str, value: &[u8]) -> X509 {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "extension-test").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.append_extension(
            X509Extension::new_from_der(
                &Asn1Object::from_str(oid).unwrap(),
                true,
                &Asn1OctetString::new_from_bytes(value).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        cert.build()
    }

    #[test]
    fn malformed_key_usage_is_an_error_not_a_panic_or_permission() {
        for value in [
            &[3, 2, 9, 6][..],
            &[3, 2, 8, 6],
            &[3, 2, 255, 6],
            &[3, 2, 1, 7],
            &[3, 2, 1, 6, 5, 0],
            &[3, 0],
            &[3, 1, 1],
        ] {
            let cert = certificate("2.5.29.15", value);
            for bit in [0, 5, 6, 255] {
                assert!(
                    key_usage_bit(&cert, bit).is_err(),
                    "accepted {value:?}, bit {bit}"
                );
            }
        }
    }

    #[test]
    fn valid_key_usage_retains_bits_and_empty_denial() {
        let usage = certificate("2.5.29.15", &[3, 2, 1, 6]);
        assert!(!key_usage_bit(&usage, 0).unwrap());
        assert!(key_usage_bit(&usage, 5).unwrap());
        assert!(key_usage_bit(&usage, 6).unwrap());
        assert!(!key_usage_bit(&usage, 7).unwrap());
        let agreement = certificate("2.5.29.15", &[3, 3, 7, 0, 128]);
        assert!(key_usage_bit(&agreement, 8).unwrap());
        let empty = certificate("2.5.29.15", &[3, 1, 0]);
        assert!(!key_usage_bit(&empty, 0).unwrap());
    }

    #[test]
    fn malformed_basic_constraints_never_become_a_ca_or_unlimited_path() {
        for value in [
            &[48, 6, 1, 1, 255, 2, 1, 255][..],
            &[48, 3, 1, 1, 255, 5, 0],
            &[48, 8, 1, 1, 255, 2, 1, 0, 5, 0],
            &[48, 3, 1, 1, 1],
            &[48, 2, 1, 0],
            &[48, 7, 1, 1, 255, 2, 2, 0, 1],
            &[48, 2, 5, 0],
        ] {
            let cert = certificate("2.5.29.19", value);
            assert!(basic_constraints(&cert).is_err(), "accepted {value:?}");
            assert!(
                tessera_ext::ext::extract_basic_constraints(&cert.to_der().unwrap()).is_err(),
                "shared parser accepted {value:?}"
            );
        }
    }

    #[test]
    fn container_chain_does_not_ignore_malformed_basic_constraints() {
        let malformed = certificate("2.5.29.19", &[48, 6, 1, 1, 255, 2, 1, 255])
            .to_der()
            .unwrap();
        assert!(
            tessera_issuer::pkcs12::check_chain(&malformed, std::slice::from_ref(&malformed))
                .is_err()
        );
        // Container packaging intentionally still permits older CAs with no BC.
        let missing = certificate("2.5.29.15", &[3, 2, 1, 6]).to_der().unwrap();
        assert!(
            tessera_issuer::pkcs12::check_chain(&missing, std::slice::from_ref(&missing)).is_ok()
        );
    }

    #[test]
    fn basic_constraints_preserve_valid_false_zero_and_maximum_paths() {
        for (value, ca, path) in [
            (&[48, 0][..], false, None),
            (&[48, 3, 1, 1, 0][..], false, None),
            (&[48, 3, 1, 1, 255][..], true, None),
            (&[48, 6, 1, 1, 255, 2, 1, 0][..], true, Some(0)),
            (
                &[48, 10, 1, 1, 255, 2, 5, 0, 255, 255, 255, 255][..],
                true,
                Some(u32::MAX),
            ),
        ] {
            let cert = certificate("2.5.29.19", value);
            assert_eq!(
                basic_constraints(&cert).unwrap(),
                Some(BasicConstraintsView {
                    is_ca: ca,
                    path_len: path
                })
            );
        }
    }
}

//! Tests for `extract_delegation_constraints` — parses the
//! `pam_cert_delegation_constraints` X.509 extension out of a verified CA
//! certificate.
//!
//! Requires the `mac-tests` feature, which exposes
//! `VerifiedX509::from_trusted_for_test`.  Run with:
//!
//! ```bash
//! cargo test -p tessera_core --features mac-tests --test delegation_constraints_ext_parse
//! ```

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(missing_docs)]

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};
use tessera_core::role::RoleId;
use tessera_core::x509::delegation_constraints_ext::{
    extract_delegation_constraints, DelegationConstraintsExtError,
};
use tessera_core::x509::oids::DELEGATION_CONSTRAINTS_OID;
use tessera_core::x509::VerifiedX509;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_INTEGER: u8 = 0x02;

/// Encode a short-form (< 0x80) DER TLV.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 0x80, "test helper supports short-form only");
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(tag);
    out.push(u8::try_from(body.len()).unwrap());
    out.extend_from_slice(body);
    out
}

fn utf8(s: &str) -> Vec<u8> {
    tlv(TAG_UTF8_STRING, s.as_bytes())
}

/// One INTEGER from a signed one-byte value (i8 range, used for level/ttl).
fn int_i8(v: i8) -> Vec<u8> {
    tlv(TAG_INTEGER, &v.to_be_bytes())
}

/// Encodes a `requireTags` value: `SEQUENCE OF SEQUENCE { key, value }`.
fn require_tags(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut inner = Vec::new();
    for (k, v) in pairs {
        let mut pair = utf8(k);
        pair.extend_from_slice(&utf8(v));
        inner.extend_from_slice(&tlv(TAG_SEQUENCE, &pair));
    }
    tlv(TAG_SEQUENCE, &inner)
}

/// Encodes an `allowRoles` value: `SEQUENCE OF UTF8String`.
fn allow_roles(roles: &[&str]) -> Vec<u8> {
    let mut inner = Vec::new();
    for r in roles {
        inner.extend_from_slice(&utf8(r));
    }
    tlv(TAG_SEQUENCE, &inner)
}

/// Encodes the full `delegation_constraints` `extnValue`.
fn constraints(tags: &[(&str, &str)], roles: &[&str], max_level: i8, max_ttl: i8) -> Vec<u8> {
    let mut body = require_tags(tags);
    body.extend_from_slice(&allow_roles(roles));
    body.extend_from_slice(&int_i8(max_level));
    body.extend_from_slice(&int_i8(max_ttl));
    tlv(TAG_SEQUENCE, &body)
}

/// Builds a self-signed cert (CA or leaf) with the given `extnValue` under the
/// `pam_cert_delegation_constraints` OID (critical, per spec).
fn build_cert(is_ca: bool, ext_der: Option<&[u8]>) -> VerifiedX509 {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_text("CN", "t").unwrap();
    let name = nb.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&serial).unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    let bc = if is_ca {
        BasicConstraints::new().critical().ca().build().unwrap()
    } else {
        // Explicit CA=FALSE leaf.
        BasicConstraints::new().critical().build().unwrap()
    };
    b.append_extension(bc).unwrap();
    if let Some(der) = ext_der {
        let oid = Asn1Object::from_str(DELEGATION_CONSTRAINTS_OID).unwrap();
        let octet = Asn1OctetString::new_from_bytes(der).unwrap();
        let ext = X509Extension::new_from_der(&oid, true, &octet).unwrap();
        b.append_extension(ext).unwrap();
    }
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    VerifiedX509::from_trusted_for_test(b.build())
}

#[test]
fn returns_none_when_ext_absent() {
    let cert = build_cert(true, None);
    assert!(extract_delegation_constraints(&cert).unwrap().is_none());
}

#[test]
fn parses_valid_constraints() {
    let der = constraints(&[("region", "north")], &["oper", "serv"], 5, 60);
    let cert = build_cert(true, Some(&der));
    let parsed = extract_delegation_constraints(&cert).unwrap().unwrap();
    assert_eq!(
        parsed.require_tags,
        vec![("region".to_owned(), "north".to_owned())]
    );
    assert_eq!(
        parsed.allow_roles,
        vec![RoleId::new("oper").unwrap(), RoleId::new("serv").unwrap()]
    );
    assert_eq!(parsed.max_level, 5);
    assert_eq!(parsed.max_ttl, 60);
}

#[test]
fn empty_require_tags_allowed() {
    let der = constraints(&[], &["oper"], 0, 30);
    let cert = build_cert(true, Some(&der));
    let parsed = extract_delegation_constraints(&cert).unwrap().unwrap();
    assert!(parsed.require_tags.is_empty());
}

#[test]
fn malformed_der_returns_err() {
    // Outer SEQUENCE claiming 5 bytes, truncated inner.
    let bad = [0x30u8, 0x05, 0x30, 0x01];
    let cert = build_cert(true, Some(&bad));
    let err = extract_delegation_constraints(&cert).unwrap_err();
    assert!(
        matches!(err, DelegationConstraintsExtError::Parse(_)),
        "{err:?}"
    );
}

#[test]
fn invalid_role_id_returns_err() {
    let der = constraints(&[("region", "north")], &["Admin"], 5, 60);
    let cert = build_cert(true, Some(&der));
    let err = extract_delegation_constraints(&cert).unwrap_err();
    assert!(
        matches!(err, DelegationConstraintsExtError::InvalidRoleId(_)),
        "{err:?}"
    );
}

#[test]
fn duplicate_tag_key_returns_err() {
    let der = constraints(
        &[("region", "north"), ("region", "south")],
        &["oper"],
        5,
        60,
    );
    let cert = build_cert(true, Some(&der));
    let err = extract_delegation_constraints(&cert).unwrap_err();
    assert!(
        matches!(err, DelegationConstraintsExtError::DuplicateTagKey(_)),
        "{err:?}"
    );
}

#[test]
fn delegation_constraints_on_leaf_rejected() {
    let der = constraints(&[("region", "north")], &["oper"], 5, 60);
    let cert = build_cert(false, Some(&der));
    let err = extract_delegation_constraints(&cert).unwrap_err();
    assert!(
        matches!(err, DelegationConstraintsExtError::NotCa),
        "{err:?}"
    );
}

//! Tests for `extract_allowed_roles` — parses the `pam_cert_allowed_roles`
//! X.509 extension out of a verified leaf certificate.
//!
//! Requires the `mac-tests` feature, which exposes
//! `VerifiedX509::from_trusted_for_test`.  Run with:
//!
//! ```bash
//! cargo test -p tessera_core --features mac-tests --test allowed_roles_ext_parse
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
use tessera_core::x509::allowed_roles_ext::{extract_allowed_roles, AllowedRolesExtError};
use tessera_core::x509::oids::ALLOWED_ROLES_OID;
use tessera_core::x509::VerifiedX509;

/// DER tags reused by the test helpers.
const TAG_SEQUENCE: u8 = 0x30;
const TAG_UTF8_STRING: u8 = 0x0C;

/// Encode a single TLV with a short-form length prefix (test inputs are tiny).
fn encode_short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() < 0x80,
        "test helper only supports short-form length"
    );
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(tag);
    out.push(u8::try_from(body.len()).unwrap());
    out.extend_from_slice(body);
    out
}

/// Encode `SEQUENCE OF UTF8String`.
fn encode_seq_of_utf8(items: &[&str]) -> Vec<u8> {
    let mut inner = Vec::new();
    for s in items {
        inner.extend_from_slice(&encode_short_tlv(TAG_UTF8_STRING, s.as_bytes()));
    }
    encode_short_tlv(TAG_SEQUENCE, &inner)
}

fn build_cert(ext_der: Option<&[u8]>) -> VerifiedX509 {
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
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    if let Some(der) = ext_der {
        let oid = Asn1Object::from_str(ALLOWED_ROLES_OID).unwrap();
        let octet = Asn1OctetString::new_from_bytes(der).unwrap();
        let ext = X509Extension::new_from_der(&oid, false, &octet).unwrap();
        b.append_extension(ext).unwrap();
    }
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    VerifiedX509::from_trusted_for_test(b.build())
}

#[test]
fn returns_none_when_ext_absent() {
    let cert = build_cert(None);
    assert!(extract_allowed_roles(&cert).unwrap().is_none());
}

#[test]
fn returns_roles_when_valid_list() {
    let der = encode_seq_of_utf8(&["oper", "serv"]);
    let cert = build_cert(Some(&der));
    assert_eq!(
        extract_allowed_roles(&cert).unwrap(),
        Some(vec![
            RoleId::new("oper").unwrap(),
            RoleId::new("serv").unwrap()
        ])
    );
}

#[test]
fn empty_sequence_is_valid_empty_list() {
    let der = encode_seq_of_utf8(&[]);
    let cert = build_cert(Some(&der));
    let roles = extract_allowed_roles(&cert).unwrap();
    match roles {
        Some(v) => assert!(v.is_empty()),
        None => panic!("expected Some(empty vec), got None"),
    }
}

#[test]
fn malformed_der_returns_err() {
    // SEQUENCE claiming 5 bytes, then a truncated UTF8String.
    let bad = [0x30u8, 0x05, 0x0c, 0x01];
    let cert = build_cert(Some(&bad));
    let err = extract_allowed_roles(&cert).unwrap_err();
    assert!(matches!(err, AllowedRolesExtError::Parse(_)), "{err:?}");
}

#[test]
fn uppercase_role_id_rejected() {
    let der = encode_seq_of_utf8(&["Admin"]);
    let cert = build_cert(Some(&der));
    let err = extract_allowed_roles(&cert).unwrap_err();
    assert!(
        matches!(err, AllowedRolesExtError::InvalidRoleId(_)),
        "{err:?}"
    );
}

#[test]
fn underscore_role_id_rejected() {
    let der = encode_seq_of_utf8(&["x_y"]);
    let cert = build_cert(Some(&der));
    let err = extract_allowed_roles(&cert).unwrap_err();
    assert!(
        matches!(err, AllowedRolesExtError::InvalidRoleId(_)),
        "{err:?}"
    );
}

#[test]
fn empty_string_role_id_rejected() {
    let der = encode_seq_of_utf8(&[""]);
    let cert = build_cert(Some(&der));
    let err = extract_allowed_roles(&cert).unwrap_err();
    assert!(
        matches!(err, AllowedRolesExtError::InvalidRoleId(_)),
        "{err:?}"
    );
}

#[test]
fn one_bad_role_id_rejects_whole_list() {
    let der = encode_seq_of_utf8(&["oper", "Admin"]);
    let cert = build_cert(Some(&der));
    let err = extract_allowed_roles(&cert).unwrap_err();
    assert!(
        matches!(err, AllowedRolesExtError::InvalidRoleId(_)),
        "{err:?}"
    );
}

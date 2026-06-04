//! Integration tests for [`host_binding_ext`] and [`user_binding_ext`].
//!
//! These tests build self-signed certificates in-memory with explicit raw-DER
//! extensions and verify the parser produces the expected `HostDescriptor` /
//! `UserDescriptor` sequences.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Extension, X509Name, X509};

use tessera_core::x509::host_binding_ext::{self, HostBindingExtError, HostDescriptor};
use tessera_core::x509::oids::{HOST_BINDING_OID, USER_BINDING_OID};
use tessera_core::x509::user_binding_ext::{self, UserBindingExtError, UserDescriptor};

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

fn make_keypair() -> PKey<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn make_name(cn: &str) -> X509Name {
    let mut nb = X509Name::builder().unwrap();
    nb.append_entry_by_text("CN", cn).unwrap();
    nb.build()
}

/// Build a self-signed cert, optionally embedding extensions with the given
/// dotted OIDs and raw DER `extnValue` contents.
fn build_cert(extensions: &[(&str, Vec<u8>)]) -> X509 {
    let pkey = make_keypair();
    let name = make_name("test-leaf");

    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();

    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        Asn1Integer::from_bn(&bn).unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    for (oid, value) in extensions {
        let oid_obj = Asn1Object::from_str(oid).unwrap();
        let octet = Asn1OctetString::new_from_bytes(value).unwrap();
        let ext = X509Extension::new_from_der(&oid_obj, false, &octet).unwrap();
        b.append_extension(ext).unwrap();
    }

    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    b.build()
}

#[test]
fn host_binding_parses_three_descriptors_in_order() {
    let hex64 = "0".repeat(64);
    let host_value = encode_seq_of_utf8(&["*", &format!("sha256:{hex64}"), "raw-machine-id"]);
    let cert = build_cert(&[(HOST_BINDING_OID, host_value)]);

    let parsed = host_binding_ext::parse(&cert).unwrap();
    assert_eq!(
        parsed,
        vec![
            HostDescriptor::Wildcard,
            HostDescriptor::Sha256Hex(hex64),
            HostDescriptor::Raw("raw-machine-id".to_owned()),
        ]
    );
}

#[test]
fn host_binding_missing_when_extension_absent() {
    let cert = build_cert(&[]);
    let err = host_binding_ext::parse(&cert).unwrap_err();
    assert!(matches!(err, HostBindingExtError::Missing), "{err:?}");
}

#[test]
fn host_binding_empty_when_sequence_has_no_entries() {
    let value = encode_seq_of_utf8(&[]);
    let cert = build_cert(&[(HOST_BINDING_OID, value)]);
    let err = host_binding_ext::parse(&cert).unwrap_err();
    assert!(matches!(err, HostBindingExtError::Empty), "{err:?}");
}

#[test]
fn host_binding_rejects_non_hex_sha256() {
    let value = encode_seq_of_utf8(&[&format!("sha256:{}", "z".repeat(64))]);
    let cert = build_cert(&[(HOST_BINDING_OID, value)]);
    let err = host_binding_ext::parse(&cert).unwrap_err();
    assert!(matches!(err, HostBindingExtError::Malformed(_)), "{err:?}");
}

#[test]
fn host_binding_rejects_short_sha256() {
    let value = encode_seq_of_utf8(&[&format!("sha256:{}", "a".repeat(63))]);
    let cert = build_cert(&[(HOST_BINDING_OID, value)]);
    let err = host_binding_ext::parse(&cert).unwrap_err();
    assert!(matches!(err, HostBindingExtError::Malformed(_)), "{err:?}");
}

#[test]
fn user_binding_parses_wildcard_and_two_exact() {
    let value = encode_seq_of_utf8(&["*", "ivanov", "petrov"]);
    let cert = build_cert(&[(USER_BINDING_OID, value)]);

    let parsed = user_binding_ext::parse(&cert).unwrap();
    assert_eq!(
        parsed,
        vec![
            UserDescriptor::Wildcard,
            UserDescriptor::Exact("ivanov".to_owned()),
            UserDescriptor::Exact("petrov".to_owned()),
        ]
    );
}

#[test]
fn user_binding_missing_when_extension_absent() {
    let cert = build_cert(&[]);
    let err = user_binding_ext::parse(&cert).unwrap_err();
    assert!(matches!(err, UserBindingExtError::Missing), "{err:?}");
}

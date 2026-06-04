//! Tests for `extract_max_integrity` — parses the `MAX_INTEGRITY` X.509
//! extension out of a verified leaf certificate.
//!
//! Requires the `mac-tests` feature, which exposes
//! `VerifiedX509::from_trusted_for_test`.  Run with:
//!
//! ```bash
//! cargo test -p tessera_core --features mac-tests --test mac_ext_parse
//! ```

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};
use tessera_core::mac::IntegrityLabel;
use tessera_core::x509::max_integrity_ext::extract_max_integrity;
use tessera_core::x509::oids::MAX_INTEGRITY_OID;
use tessera_core::x509::VerifiedX509;

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
        let oid = Asn1Object::from_str(MAX_INTEGRITY_OID).unwrap();
        let octet = Asn1OctetString::new_from_bytes(der).unwrap();
        let ext = X509Extension::new_from_der(&oid, false, &octet).unwrap();
        b.append_extension(ext).unwrap();
    }
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    VerifiedX509::from_trusted_for_test(b.build())
}

#[test]
fn returns_label_when_ext_present() {
    let der = IntegrityLabel {
        level: 2,
        categories: 0b01,
    }
    .to_der()
    .unwrap();
    let cert = build_cert(Some(&der));
    assert_eq!(
        extract_max_integrity(&cert).unwrap(),
        Some(IntegrityLabel {
            level: 2,
            categories: 0b01
        })
    );
}

#[test]
fn returns_none_when_ext_absent() {
    let cert = build_cert(None);
    assert!(extract_max_integrity(&cert).unwrap().is_none());
}

#[test]
fn malformed_ext_returns_err() {
    // SEQUENCE claiming 5 inner bytes but only providing 3 → INTEGER length
    // walks past the end of the SEQUENCE body.
    let bad = [0x30u8, 0x05, 0x02, 0x01, 0x02];
    let cert = build_cert(Some(&bad));
    assert!(extract_max_integrity(&cert).is_err());
}

//! Tests for `extract_profile_version` — parses the `pam_cert_profile_version`
//! X.509 extension (a DER `INTEGER`) out of a verified certificate.
//!
//! Requires the `mac-tests` feature, which exposes
//! `VerifiedX509::from_trusted_for_test`.  Run with:
//!
//! ```bash
//! cargo test -p tessera_core --features mac-tests --test profile_version_ext_parse
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
use tessera_core::x509::oids::PROFILE_VERSION_OID;
use tessera_core::x509::profile_version_ext::{extract_profile_version, ProfileVersionExtError};
use tessera_core::x509::VerifiedX509;

/// Builds a self-signed cert with the given raw `extnValue` DER appended under
/// the `pam_cert_profile_version` OID (critical, per spec).
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
        let oid = Asn1Object::from_str(PROFILE_VERSION_OID).unwrap();
        let octet = Asn1OctetString::new_from_bytes(der).unwrap();
        // The extension is critical per the wire contract.
        let ext = X509Extension::new_from_der(&oid, true, &octet).unwrap();
        b.append_extension(ext).unwrap();
    }
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    VerifiedX509::from_trusted_for_test(b.build())
}

#[test]
fn returns_version_when_valid_integer() {
    // INTEGER 3
    let der = [0x02u8, 0x01, 0x03];
    let cert = build_cert(Some(&der));
    assert_eq!(extract_profile_version(&cert).unwrap(), Some(3));
}

#[test]
fn returns_multibyte_version() {
    // INTEGER 300 = 0x012C (leading byte high bit clear, minimal)
    let der = [0x02u8, 0x02, 0x01, 0x2C];
    let cert = build_cert(Some(&der));
    assert_eq!(extract_profile_version(&cert).unwrap(), Some(300));
}

#[test]
fn returns_none_when_ext_absent() {
    let cert = build_cert(None);
    assert!(extract_profile_version(&cert).unwrap().is_none());
}

#[test]
fn malformed_not_an_integer_returns_err() {
    // OCTET STRING, not INTEGER → fail-closed reject.
    let der = [0x04u8, 0x01, 0x03];
    let cert = build_cert(Some(&der));
    let err = extract_profile_version(&cert).unwrap_err();
    assert!(matches!(err, ProfileVersionExtError::Parse(_)), "{err:?}");
}

#[test]
fn truncated_integer_returns_err() {
    // INTEGER claiming 2 bytes but only 1 present.
    let der = [0x02u8, 0x02, 0x03];
    let cert = build_cert(Some(&der));
    let err = extract_profile_version(&cert).unwrap_err();
    assert!(matches!(err, ProfileVersionExtError::Parse(_)), "{err:?}");
}

#[test]
fn negative_version_returns_err() {
    // INTEGER -1 (0xFF) → versions are unsigned, reject.
    let der = [0x02u8, 0x01, 0xFF];
    let cert = build_cert(Some(&der));
    let err = extract_profile_version(&cert).unwrap_err();
    assert!(
        matches!(err, ProfileVersionExtError::Negative(-1)),
        "{err:?}"
    );
}

//! Integration tests for [`verify_intermediate_constraints`] (P1-J).
//!
//! Validates per-link RFC 5280 checks on built chains: validity window,
//! `basicConstraints CA=TRUE`, `keyUsage keyCertSign`. Each test builds a
//! synthetic 2-element chain `[leaf, intermediate-as-anchor]` in memory; we
//! only inspect the non-leaf so this is sufficient.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::needless_pass_by_value)]

use std::time::{Duration, SystemTime};

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509Name, X509};

use tessera_core::x509::basic_constraints::verify_intermediate_constraints;
use tessera_core::x509::{Certificate, TrustError};

fn keypair() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

fn name(cn: &str) -> X509Name {
    let mut nb = X509Name::builder().unwrap();
    nb.append_entry_by_text("CN", cn).unwrap();
    nb.build()
}

/// Build a self-signed CA-style cert with configurable validity, BC and KU.
fn build_ca_like(
    cn: &str,
    not_before_days: i32,
    not_after_days: i32,
    is_ca: bool,
    key_cert_sign: bool,
) -> X509 {
    let pkey = keypair();
    let n = name(cn);
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();

    let mut bn = BigNum::new().unwrap();
    bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    let serial = Asn1Integer::from_bn(&bn).unwrap();
    b.set_serial_number(&serial).unwrap();

    b.set_subject_name(&n).unwrap();
    b.set_issuer_name(&n).unwrap();
    b.set_pubkey(&pkey).unwrap();

    let nb = if not_before_days >= 0 {
        Asn1Time::days_from_now(u32::try_from(not_before_days).unwrap()).unwrap()
    } else {
        // negative: use from_unix relative to now
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + i64::from(not_before_days) * 86_400;
        Asn1Time::from_unix(secs).unwrap()
    };
    let na = if not_after_days >= 0 {
        Asn1Time::days_from_now(u32::try_from(not_after_days).unwrap()).unwrap()
    } else {
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + i64::from(not_after_days) * 86_400;
        Asn1Time::from_unix(secs).unwrap()
    };
    b.set_not_before(&nb).unwrap();
    b.set_not_after(&na).unwrap();

    let mut bc = BasicConstraints::new();
    if is_ca {
        bc.critical().ca();
    }
    let bc_ext = bc.build().unwrap();
    b.append_extension(bc_ext).unwrap();

    let mut ku = KeyUsage::new();
    ku.critical().digital_signature();
    if key_cert_sign {
        ku.key_cert_sign();
    }
    let ku_ext = ku.build().unwrap();
    b.append_extension(ku_ext).unwrap();

    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    b.build()
}

fn cert_from(x: X509) -> Certificate {
    let der = x.to_der().unwrap();
    Certificate::from_der(&der).unwrap()
}

fn make_leaf() -> Certificate {
    // A minimal leaf — we only care about index 0; verify_intermediate_constraints
    // does NOT inspect the leaf.
    let pkey = keypair();
    let n = name("leaf");
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let mut bn = BigNum::new().unwrap();
    bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&bn).unwrap())
        .unwrap();
    b.set_subject_name(&n).unwrap();
    b.set_issuer_name(&n).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    cert_from(b.build())
}

#[test]
fn rejects_expired_intermediate() {
    // notBefore = -10d, notAfter = -1d → expired.
    let leaf = make_leaf();
    let int = cert_from(build_ca_like("expired-ca", -10, -1, true, true));
    let chain = vec![leaf, int];
    let err = verify_intermediate_constraints(&chain, SystemTime::now(), Duration::from_secs(0))
        .unwrap_err();
    assert!(matches!(err, TrustError::Validity(_)), "{err:?}");
}

#[test]
fn rejects_intermediate_with_basic_constraints_ca_false() {
    let leaf = make_leaf();
    // BC built without .ca() — defaults to CA=FALSE in openssl crate.
    let int = cert_from(build_ca_like("not-ca", 0, 365, false, true));
    let chain = vec![leaf, int];
    let err = verify_intermediate_constraints(&chain, SystemTime::now(), Duration::from_secs(0))
        .unwrap_err();
    assert!(matches!(err, TrustError::BasicConstraints(_)), "{err:?}");
}

#[test]
fn rejects_intermediate_without_key_cert_sign() {
    let leaf = make_leaf();
    // KU has digitalSignature but NOT keyCertSign.
    let int = cert_from(build_ca_like("no-kcs", 0, 365, true, false));
    let chain = vec![leaf, int];
    let err = verify_intermediate_constraints(&chain, SystemTime::now(), Duration::from_secs(0))
        .unwrap_err();
    assert!(matches!(err, TrustError::KeyUsage), "{err:?}");
}

#[test]
fn accepts_well_formed_intermediate() {
    let leaf = make_leaf();
    let int = cert_from(build_ca_like("good-ca", 0, 365, true, true));
    let chain = vec![leaf, int];
    verify_intermediate_constraints(&chain, SystemTime::now(), Duration::from_secs(0)).unwrap();
}

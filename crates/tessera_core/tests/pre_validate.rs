#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::duration_suboptimal_units)]

use std::time::{Duration, SystemTime};

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Name};

use tessera_core::x509::pre_validate::{pre_validate_end_entity, PreValidateConfig};
use tessera_core::x509::{Certificate, TrustError};

const LEAF: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");

/// Builds a self-signed, SHA-256-signed leaf carrying an RSA key of the given
/// size.  Used to exercise the public-key-strength gate independently of any
/// on-disk fixture.
fn self_signed_rsa_leaf(bits: u32) -> Certificate {
    let key = PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap();
    let mut nb = X509Name::builder().unwrap();
    nb.append_entry_by_text("CN", "weak-leaf").unwrap();
    let name = nb.build();

    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let mut bn = BigNum::new().unwrap();
    bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&bn).unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    Certificate::from_der(&b.build().to_der().unwrap()).unwrap()
}

fn cfg() -> PreValidateConfig {
    PreValidateConfig {
        clock_skew: Duration::from_secs(60),
        signature_alg_whitelist: vec![
            "sha256WithRSAEncryption".into(),
            "ecdsa-with-SHA256".into(),
            "ecdsa-with-SHA384".into(),
        ],
    }
}

#[test]
fn passes_valid_leaf() {
    let cert = Certificate::from_pem(LEAF).unwrap();
    pre_validate_end_entity(&cert, &cfg(), SystemTime::now()).unwrap();
}

#[test]
fn rejects_not_yet_valid() {
    let cert = Certificate::from_pem(LEAF).unwrap();
    let way_back = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let err = pre_validate_end_entity(&cert, &cfg(), way_back).unwrap_err();
    assert!(matches!(err, TrustError::Validity(_)), "{err:?}");
}

#[test]
fn rejects_expired() {
    let cert = Certificate::from_pem(LEAF).unwrap();
    let far_future = SystemTime::now() + Duration::from_secs(10 * 365 * 86_400);
    let err = pre_validate_end_entity(&cert, &cfg(), far_future).unwrap_err();
    assert!(matches!(err, TrustError::Validity(_)), "{err:?}");
}

#[test]
fn rejects_unlisted_signature_alg() {
    let cert = Certificate::from_pem(LEAF).unwrap();
    let mut c = cfg();
    c.signature_alg_whitelist = vec!["ecdsa-with-SHA512".into()];
    let err = pre_validate_end_entity(&cert, &c, SystemTime::now()).unwrap_err();
    assert!(
        matches!(err, TrustError::SignatureAlgorithm(_)),
        "expected SignatureAlgorithm, got {err:?}"
    );
}

#[test]
fn empty_whitelist_means_no_constraint() {
    // P1-A: an empty whitelist must accept any signature algorithm.
    let cert = Certificate::from_pem(LEAF).unwrap();
    let mut c = cfg();
    c.signature_alg_whitelist.clear();
    pre_validate_end_entity(&cert, &c, SystemTime::now()).unwrap();
}

#[test]
fn whitelist_match_is_exact_not_substring() {
    // P1-C: a whitelist entry of `"sha"` must NOT match `sha256WithRSAEncryption`.
    let cert = Certificate::from_pem(LEAF).unwrap();
    let mut c = cfg();
    c.signature_alg_whitelist = vec!["sha".into()];
    let err = pre_validate_end_entity(&cert, &c, SystemTime::now()).unwrap_err();
    assert!(
        matches!(err, TrustError::SignatureAlgorithm(_)),
        "expected SignatureAlgorithm, got {err:?}"
    );
}

#[test]
fn rejects_weak_rsa_leaf() {
    // A 1024-bit RSA leaf signed with SHA-256 passes the signature-algorithm
    // whitelist but must be rejected by the public-key-strength gate before
    // any challenge-response trusts the key.
    let cert = self_signed_rsa_leaf(1024);
    let mut c = cfg();
    // Ensure the sha256 signature is allow-listed so the strength gate, not
    // the algorithm gate, is what rejects the cert.
    c.signature_alg_whitelist = vec!["sha256WithRSAEncryption".into()];
    let err = pre_validate_end_entity(&cert, &c, SystemTime::now()).unwrap_err();
    assert!(matches!(err, TrustError::WeakKey(_)), "{err:?}");
}

#[test]
fn accepts_2048_rsa_leaf_strength() {
    // Companion to `rejects_weak_rsa_leaf`: the same self-signed builder with a
    // 2048-bit key clears the strength gate (it then fails later on the absent
    // clientAuth EKU, which is a different, expected check).
    let cert = self_signed_rsa_leaf(2048);
    let mut c = cfg();
    c.signature_alg_whitelist = vec!["sha256WithRSAEncryption".into()];
    let err = pre_validate_end_entity(&cert, &c, SystemTime::now()).unwrap_err();
    assert!(
        !matches!(err, TrustError::WeakKey(_)),
        "2048-bit key must clear the strength gate, got {err:?}"
    );
}

#[test]
fn rejects_intermediate_as_end_entity() {
    // Intermediate has CA=TRUE; pre_validate_end_entity must reject it.
    let cert = Certificate::from_pem(INT).unwrap();
    let err = pre_validate_end_entity(&cert, &cfg(), SystemTime::now()).unwrap_err();
    // Intermediate has KeyUsage = keyCertSign|cRLSign (no digitalSignature),
    // so we should fail on KeyUsage first.  Either KeyUsage or BasicConstraints
    // is acceptable: both are correct rejection reasons.
    assert!(
        matches!(
            err,
            TrustError::KeyUsage | TrustError::BasicConstraints(_) | TrustError::Eku
        ),
        "expected KeyUsage/Eku/BasicConstraints, got {err:?}"
    );
}

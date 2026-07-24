#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Name};
use secrecy::SecretString;
use tessera_core::challenge::{challenge_response, CryptoError};
use tessera_core::pkcs12::LoadedKeyMaterial;
use tessera_core::x509::Certificate;

const RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.p12");
const ECDSA: &[u8] = include_bytes!("fixtures/leaf_ecdsa.p12");

/// Builds a self-signed leaf certificate plus its private key carrying an RSA
/// key of the requested size.  Used to exercise the weak-key gate on the
/// in-process (PKCS#12) selection path without a fixture.
fn self_signed_rsa(bits: u32) -> (Certificate, PKey<Private>) {
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
    let cert = Certificate::from_der(&b.build().to_der().unwrap()).unwrap();
    (cert, key)
}

#[test]
fn dispatches_rsa() {
    let m =
        LoadedKeyMaterial::from_p12(RSA, &SecretString::from("correct-pin".to_string())).unwrap();
    let priv_k = m.private_key().unwrap();
    challenge_response(&m.end_entity, &priv_k, None).expect("RSA dispatch");
}

#[test]
fn dispatches_ecdsa() {
    let m =
        LoadedKeyMaterial::from_p12(ECDSA, &SecretString::from("correct-pin".to_string())).unwrap();
    let priv_k = m.private_key().unwrap();
    challenge_response(&m.end_entity, &priv_k, None).expect("ECDSA dispatch");
}

#[test]
fn rejects_weak_rsa_key() {
    // The in-process (PKCS#12) selection path must refuse a 1024-bit RSA key
    // before attempting the challenge-response round-trip.
    let (cert, key) = self_signed_rsa(1024);
    let err = challenge_response(&cert, &key, None).unwrap_err();
    assert!(matches!(err, CryptoError::WeakKey(_)), "got {err:?}");
}

#[test]
fn accepts_2048_rsa_key_strength() {
    // Companion check: a 2048-bit self-signed leaf clears the strength gate
    // and completes the round-trip (the key matches the certificate).
    let (cert, key) = self_signed_rsa(2048);
    challenge_response(&cert, &key, None).expect("2048-bit RSA round-trip");
}

#[test]
fn mismatched_key_yields_bad_signature() {
    // RSA cert + ECDSA private key — even before the verifier rejects the
    // signature, OpenSSL's signer may complain that the key type does not
    // match the requested digest/padding.  Either path lands us in
    // `CryptoError::BadSignature` or `CryptoError::Openssl`, both of which
    // mean "this key does not unlock this cert".
    let m_rsa =
        LoadedKeyMaterial::from_p12(RSA, &SecretString::from("correct-pin".to_string())).unwrap();
    let m_ec =
        LoadedKeyMaterial::from_p12(ECDSA, &SecretString::from("correct-pin".to_string())).unwrap();
    let wrong_priv = m_ec.private_key().unwrap();
    let err = challenge_response(&m_rsa.end_entity, &wrong_priv, None).unwrap_err();
    assert!(
        matches!(err, CryptoError::BadSignature | CryptoError::Openssl(_)),
        "got {err:?}"
    );
}

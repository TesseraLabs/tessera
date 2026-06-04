#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use tessera_core::challenge::{challenge_response, CryptoError};
use tessera_core::pkcs12::LoadedKeyMaterial;
use secrecy::SecretString;

const RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.p12");
const ECDSA: &[u8] = include_bytes!("fixtures/leaf_ecdsa.p12");

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

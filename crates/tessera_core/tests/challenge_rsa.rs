#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use secrecy::SecretString;
use tessera_core::challenge::rsa_pss::challenge_response_rsa_pss;
use tessera_core::challenge::CryptoError;
use tessera_core::pkcs12::LoadedKeyMaterial;

const RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.p12");

#[test]
fn round_trip_rsa_pss() {
    let m =
        LoadedKeyMaterial::from_p12(RSA, &SecretString::from("correct-pin".to_string())).unwrap();
    let pk_pub = m.end_entity.public_key().unwrap();
    let pk_priv = m.private_key().unwrap();
    challenge_response_rsa_pss(&pk_pub, &pk_priv).expect("RSA-PSS round-trip");
}

#[test]
fn mismatched_keys_yield_bad_signature() {
    // Generate a fresh, unrelated RSA key.  Signing the nonce with the
    // mismatched key must produce a verification failure under the cert's
    // public key.
    let other = openssl::rsa::Rsa::generate(2048).unwrap();
    let other_priv = openssl::pkey::PKey::from_rsa(other).unwrap();

    let m =
        LoadedKeyMaterial::from_p12(RSA, &SecretString::from("correct-pin".to_string())).unwrap();
    let pk_pub = m.end_entity.public_key().unwrap();

    let err = challenge_response_rsa_pss(&pk_pub, &other_priv).unwrap_err();
    assert!(matches!(err, CryptoError::BadSignature), "got {err:?}");
}

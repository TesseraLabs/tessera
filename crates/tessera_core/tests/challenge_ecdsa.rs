#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use secrecy::SecretString;
use tessera_core::challenge::ecdsa::challenge_response_ecdsa;
use tessera_core::pkcs12::LoadedKeyMaterial;

const ECDSA: &[u8] = include_bytes!("fixtures/leaf_ecdsa.p12");

#[test]
fn round_trip_ecdsa_p256() {
    let m =
        LoadedKeyMaterial::from_p12(ECDSA, &SecretString::from("correct-pin".to_string())).unwrap();
    let pk_pub = m.end_entity.public_key().unwrap();
    let pk_priv = m.private_key().unwrap();
    challenge_response_ecdsa(&pk_pub, &pk_priv).expect("ECDSA round-trip");
}

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use secrecy::SecretString;
use tessera_core::pkcs12::{
    validate_p12_envelope, LoadedKeyMaterial, P12EnvelopeError, Pkcs12Error,
};

const RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.p12");
const ECDSA: &[u8] = include_bytes!("fixtures/leaf_ecdsa.p12");

#[test]
fn loads_rsa_p12() {
    let pin = SecretString::from("correct-pin".to_string());
    let m = LoadedKeyMaterial::from_p12(RSA, &pin).unwrap();
    assert_eq!(m.end_entity.subject_cn().unwrap(), "alice");
    assert!(
        !m.presented_chain.is_empty(),
        "expected at least the intermediate CA to ride along"
    );
    // The chain certificate is the intermediate.
    assert_eq!(
        m.presented_chain[0].subject_cn().unwrap(),
        "CertAuth Test Intermediate"
    );
}

#[test]
fn loads_ecdsa_p12() {
    let pin = SecretString::from("correct-pin".to_string());
    let m = LoadedKeyMaterial::from_p12(ECDSA, &pin).unwrap();
    assert_eq!(m.end_entity.subject_cn().unwrap(), "bob");
    assert!(!m.presented_chain.is_empty());
}

#[test]
fn wrong_pin_returns_wrong_pin() {
    let pin = SecretString::from("nope".to_string());
    let err = LoadedKeyMaterial::from_p12(RSA, &pin).unwrap_err();
    assert!(matches!(err, Pkcs12Error::WrongPin), "got {err:?}");
}

#[test]
fn corrupt_p12_returns_corrupt() {
    let pin = SecretString::from("correct-pin".to_string());
    let err = LoadedKeyMaterial::from_p12(b"not-a-p12-byte-stream", &pin).unwrap_err();
    assert!(matches!(err, Pkcs12Error::Corrupt(_)), "got {err:?}");
}

#[test]
fn empty_input_returns_corrupt() {
    let pin = SecretString::from("correct-pin".to_string());
    let err = LoadedKeyMaterial::from_p12(b"", &pin).unwrap_err();
    assert!(matches!(err, Pkcs12Error::Corrupt(_)), "got {err:?}");
}

#[test]
fn envelope_accepts_valid_rsa_p12() {
    validate_p12_envelope(RSA).expect("valid PKCS#12 must pass envelope check");
}

#[test]
fn envelope_accepts_valid_ecdsa_p12() {
    validate_p12_envelope(ECDSA).expect("valid PKCS#12 must pass envelope check");
}

#[test]
fn envelope_rejects_random_bytes() {
    let err = validate_p12_envelope(b"not a p12").unwrap_err();
    assert!(matches!(err, P12EnvelopeError::Asn1(_)), "got {err:?}");
}

#[test]
fn envelope_rejects_apple_garbage_with_p12_name() {
    // Simulates a real-world case: an Apple-formatted USB partition with
    // a file at `certs/user.p12` that is actually a plist / arbitrary
    // binary blob.  Must not be mistaken for a PKCS#12 envelope.
    let mut blob = Vec::from(&b"bplist00\xDE\xAD\xBE\xEF"[..]);
    blob.extend(std::iter::repeat_n(0xA5_u8, 256));
    let err = validate_p12_envelope(&blob).unwrap_err();
    assert!(matches!(err, P12EnvelopeError::Asn1(_)), "got {err:?}");
}

#[test]
fn envelope_rejects_truncated_p12() {
    // First 10 bytes of a real .p12 — outer SEQUENCE header is there
    // but the body is missing, so ASN.1 parse fails.
    let truncated = &RSA[..10];
    let err = validate_p12_envelope(truncated).unwrap_err();
    assert!(matches!(err, P12EnvelopeError::Asn1(_)), "got {err:?}");
}

#[test]
fn envelope_rejects_empty_buffer() {
    let err = validate_p12_envelope(b"").unwrap_err();
    assert!(matches!(err, P12EnvelopeError::Asn1(_)), "got {err:?}");
}

#[test]
fn envelope_validates_without_pin() {
    // The whole point of `validate_p12_envelope` is that it does not
    // consult the password.  Bytes that are a real PKCS#12 must pass
    // even though the function never sees a PIN — verified implicitly
    // by passing RSA above; this is just a documented sanity check
    // that the function takes only one argument (compile-time check).
    let _: fn(&[u8]) -> Result<(), P12EnvelopeError> = validate_p12_envelope;
}

#[test]
fn private_key_round_trips() {
    let pin = SecretString::from("correct-pin".to_string());
    let m = LoadedKeyMaterial::from_p12(RSA, &pin).unwrap();
    // Materialise the PKey twice — the stored PKCS#8 DER must be reusable.
    let _ = m.private_key().unwrap();
    let _ = m.private_key().unwrap();
}

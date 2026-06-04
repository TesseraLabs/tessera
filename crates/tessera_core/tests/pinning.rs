#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use tessera_core::x509::pinning::{spki_sha256, verify_pinning};
use tessera_core::x509::{Certificate, TrustError};

const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");

#[test]
fn matching_pin_passes() {
    let ca = Certificate::from_pem(CA).unwrap();
    let pin = spki_sha256(&ca).unwrap();
    verify_pinning(&ca, &[pin]).unwrap();
}

#[test]
fn mismatched_pin_rejected() {
    let ca = Certificate::from_pem(CA).unwrap();
    let bad = [0u8; 32];
    let err = verify_pinning(&ca, &[bad]).unwrap_err();
    assert!(matches!(err, TrustError::PinMismatch), "{err:?}");
}

#[test]
fn empty_pin_list_means_disabled() {
    let ca = Certificate::from_pem(CA).unwrap();
    verify_pinning(&ca, &[]).unwrap();
}

#[test]
fn one_of_many_pins_matches() {
    let ca = Certificate::from_pem(CA).unwrap();
    let bad1 = [0u8; 32];
    let bad2 = [0xFFu8; 32];
    let good = spki_sha256(&ca).unwrap();
    verify_pinning(&ca, &[bad1, good, bad2]).unwrap();
}

#[test]
fn pin_for_different_cert_rejected() {
    let ca = Certificate::from_pem(CA).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let pin_for_int = spki_sha256(&int).unwrap();
    // Pinning the *intermediate*'s SPKI but checking the *root* must fail.
    let err = verify_pinning(&ca, &[pin_for_int]).unwrap_err();
    assert!(matches!(err, TrustError::PinMismatch), "{err:?}");
}

#[test]
fn spki_hash_is_deterministic() {
    let ca = Certificate::from_pem(CA).unwrap();
    let h1 = spki_sha256(&ca).unwrap();
    let h2 = spki_sha256(&ca).unwrap();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32);
}

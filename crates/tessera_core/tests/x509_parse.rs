#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use tessera_core::x509::{Certificate, TrustError};

const LEAF_PEM: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const INT_PEM: &[u8] = include_bytes!("fixtures/int.pem");
const CA_PEM: &[u8] = include_bytes!("fixtures/ca.pem");

#[test]
fn parses_pem_and_exposes_subject_cn() {
    let cert = Certificate::from_pem(LEAF_PEM).expect("valid pem");
    assert_eq!(cert.subject_cn().unwrap(), "alice");
}

#[test]
fn exposes_san_emails() {
    let cert = Certificate::from_pem(LEAF_PEM).unwrap();
    assert_eq!(cert.san_emails(), vec!["alice@example.org".to_string()]);
}

#[test]
fn exposes_serial_and_validity() {
    let cert = Certificate::from_pem(LEAF_PEM).unwrap();
    assert!(!cert.serial_hex().is_empty());
    assert!(cert.not_before() < cert.not_after());
}

#[test]
fn exposes_key_usage_and_eku() {
    let cert = Certificate::from_pem(LEAF_PEM).unwrap();
    assert!(cert.key_usage_digital_signature().unwrap());
    assert!(cert.eku_client_auth().unwrap());
    assert!(!cert.key_usage_key_cert_sign().unwrap());
}

#[test]
fn rejects_garbage() {
    let err = Certificate::from_pem(b"-----BEGIN nonsense-----\n").unwrap_err();
    assert!(matches!(err, TrustError::CertParse(_)));
}

#[test]
fn rejects_garbage_der() {
    let err = Certificate::from_der(&[0xFFu8; 4]).unwrap_err();
    assert!(matches!(err, TrustError::CertParse(_)));
}

#[test]
fn ski_aki_present_on_leaf() {
    let cert = Certificate::from_pem(LEAF_PEM).unwrap();
    assert!(cert.ski().is_some());
    assert!(cert.aki().is_some());
}

#[test]
fn basic_constraints_ca_false_on_leaf() {
    let cert = Certificate::from_pem(LEAF_PEM).unwrap();
    let bc = cert.basic_constraints().unwrap().expect("present");
    assert!(!bc.is_ca);
}

#[test]
fn basic_constraints_ca_true_on_intermediate() {
    let cert = Certificate::from_pem(INT_PEM).unwrap();
    let bc = cert.basic_constraints().unwrap().expect("present");
    assert!(bc.is_ca);
    assert_eq!(bc.path_len, Some(0));
}

#[test]
fn ca_root_is_v3_and_self_signed_subject() {
    let cert = Certificate::from_pem(CA_PEM).unwrap();
    assert_eq!(cert.version(), 2); // v3
    let subject = cert.subject_cn().unwrap();
    assert_eq!(subject, "CertAuth Test Root CA");
}

#[test]
fn signature_algorithm_is_dotted_or_named() {
    let cert = Certificate::from_pem(LEAF_PEM).unwrap();
    let alg = cert.signature_algorithm();
    assert!(!alg.is_empty());
    // OpenSSL renders this as either the LN or the dotted OID.
    // For sha256WithRSAEncryption (OID 1.2.840.113549.1.1.11) we accept either.
    assert!(
        alg.contains("sha256") || alg.contains("RSA") || alg.contains("1.2.840.113549.1.1.11"),
        "unexpected signature algorithm: {alg}"
    );
}

#[test]
fn der_round_trip_preserves_subject() {
    let cert = Certificate::from_pem(LEAF_PEM).unwrap();
    let cert2 = Certificate::from_der(cert.der()).unwrap();
    assert_eq!(cert.subject_cn().unwrap(), cert2.subject_cn().unwrap());
}

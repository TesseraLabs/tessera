#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::duration_suboptimal_units)]

use std::time::{Duration, SystemTime};
use tessera_core::x509::pre_validate::{pre_validate_end_entity, PreValidateConfig};
use tessera_core::x509::{Certificate, TrustError};

const LEAF: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");

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

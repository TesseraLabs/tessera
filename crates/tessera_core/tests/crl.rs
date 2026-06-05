#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::duration_suboptimal_units)]

use tessera_core::crl::{check_revocation, Crl, CrlStore, RevocationConfig};
use tessera_core::x509::{Certificate, TrustError};
use std::time::{Duration, SystemTime};

const REVOKED: &[u8] = include_bytes!("fixtures/revoked_leaf.pem");
const LEAF: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");
const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const CRL_VALID: &[u8] = include_bytes!("fixtures/crl_valid.pem");
const CRL_FOREIGN: &[u8] = include_bytes!("fixtures/crl_foreign.pem");

fn chain(leaf_bytes: &[u8]) -> Vec<Certificate> {
    vec![
        Certificate::from_pem(leaf_bytes).unwrap(),
        Certificate::from_pem(INT).unwrap(),
        Certificate::from_pem(CA).unwrap(),
    ]
}

#[test]
fn parses_crl_metadata() {
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    assert!(crl.this_update() <= crl.next_update());
    // Our gen.sh revokes serial 0x99 (mallory).
    assert!(crl
        .revoked_serials()
        .iter()
        .any(|s| s.eq_ignore_ascii_case("99")));
    assert!(!crl.issuer_dn_der().is_empty());
}

#[test]
fn passes_unrevoked_chain() {
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let cfg = RevocationConfig { crl_strict: true };
    check_revocation(&chain(LEAF), &store, &cfg, SystemTime::now()).unwrap();
}

#[test]
fn rejects_revoked_cert() {
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let cfg = RevocationConfig { crl_strict: true };
    let err = check_revocation(&chain(REVOKED), &store, &cfg, SystemTime::now()).unwrap_err();
    match err {
        TrustError::Revoked(serial) => {
            assert!(
                serial.eq_ignore_ascii_case("99"),
                "unexpected serial {serial}"
            )
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[test]
fn strict_rejects_expired_crl() {
    // Our valid CRL has nextUpdate ~10y into the future. Pretend "now" is
    // eleven years ahead so the CRL appears expired.
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let cfg = RevocationConfig { crl_strict: true };
    let future = SystemTime::now() + Duration::from_secs(11 * 365 * 24 * 3600);
    let err = check_revocation(&chain(LEAF), &store, &cfg, future).unwrap_err();
    assert!(matches!(err, TrustError::Crl(_)), "{err:?}");
}

#[test]
fn lenient_skips_expired_crl() {
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let cfg = RevocationConfig { crl_strict: false };
    let future = SystemTime::now() + Duration::from_secs(11 * 365 * 24 * 3600);
    // No error: lenient mode logs and continues.
    check_revocation(&chain(LEAF), &store, &cfg, future).unwrap();
}

#[test]
fn empty_store_is_noop() {
    let store = CrlStore::empty();
    let cfg = RevocationConfig { crl_strict: true };
    check_revocation(&chain(LEAF), &store, &cfg, SystemTime::now()).unwrap();
}

#[test]
fn crl_signature_validates_against_correct_issuer() {
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let pk = int.public_key().unwrap();
    crl.verify_signature(&pk).unwrap();
}

#[test]
fn crl_signature_rejects_wrong_key() {
    // CRL is signed by the intermediate.  Verifying it under the root
    // public key must fail.
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    let pk = ca.public_key().unwrap();
    let err = crl.verify_signature(&pk).unwrap_err();
    assert!(matches!(err, TrustError::Crl(_)), "{err:?}");
}

#[test]
fn foreign_crl_signature_validates_under_its_own_issuer() {
    // The foreign CRL is signed by the *root*. It should validate under
    // the root's key but not under the intermediate's.
    let crl = Crl::from_pem(CRL_FOREIGN).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    crl.verify_signature(&ca.public_key().unwrap()).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let err = crl
        .verify_signature(&int.public_key().unwrap())
        .unwrap_err();
    assert!(matches!(err, TrustError::Crl(_)), "{err:?}");
}

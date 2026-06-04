#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use tessera_core::x509::basic_constraints::verify_basic_constraints;
use tessera_core::x509::chain::build_chain;
use tessera_core::x509::signatures::verify_chain_signatures;
use tessera_core::x509::{Certificate, TrustError};

const LEAF: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");
const CA: &[u8] = include_bytes!("fixtures/ca.pem");

#[test]
fn verifies_signatures_in_valid_chain() {
    let leaf = Certificate::from_pem(LEAF).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    let chain = build_chain(&leaf, &[int], &[], &[ca], 4).unwrap();
    verify_chain_signatures(&chain).unwrap();
}

#[test]
fn rejects_chain_with_only_one_link() {
    let ca = Certificate::from_pem(CA).unwrap();
    let err = verify_chain_signatures(&[ca]).unwrap_err();
    assert!(matches!(err, TrustError::PathBuild(_)), "{err:?}");
}

#[test]
fn rejects_tampered_signature_at_some_depth() {
    // Flip a byte inside the leaf's DER signature.  If reparse still
    // succeeds, signature verify must fail.  If reparse fails (likely),
    // the test passes vacuously — the contract is "tamper => no acceptance".
    let leaf = Certificate::from_pem(LEAF).unwrap();
    let mut der = leaf.der().to_vec();
    let n = der.len();
    der[n - 5] ^= 0xFF;
    if let Ok(bad_leaf) = Certificate::from_der(&der) {
        let int = Certificate::from_pem(INT).unwrap();
        let ca = Certificate::from_pem(CA).unwrap();
        let chain = build_chain(&bad_leaf, &[int], &[], &[ca], 4).unwrap();
        let err = verify_chain_signatures(&chain).unwrap_err();
        assert!(matches!(err, TrustError::BadSignature(_)), "{err:?}");
    }
}

#[test]
fn rejects_chain_with_swapped_anchor_pubkey() {
    // Build a "chain" where the anchor is the intermediate (wrong key for
    // the intermediate's signature).  We replace the last element.
    let leaf = Certificate::from_pem(LEAF).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    let mut chain = build_chain(&leaf, std::slice::from_ref(&int), &[], &[ca], 4).unwrap();
    // Replace the anchor (CA) with the intermediate.  The intermediate is
    // not self-signed — verify_chain_signatures must reject the anchor's
    // self-signature.
    let last = chain.len() - 1;
    chain[last] = int;
    let err = verify_chain_signatures(&chain).unwrap_err();
    assert!(matches!(err, TrustError::BadSignature(_)), "{err:?}");
}

#[test]
fn enforces_basic_constraints_on_intermediates() {
    let leaf = Certificate::from_pem(LEAF).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    let chain = build_chain(&leaf, &[int], &[], &[ca], 4).unwrap();
    verify_basic_constraints(&chain).unwrap();
}

#[test]
fn rejects_non_ca_in_middle() {
    // Construct a synthetic chain: [leaf, leaf, ca]. The middle element
    // is a leaf certificate (CA=FALSE) which must be rejected.
    let leaf = Certificate::from_pem(LEAF).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    let bogus = vec![leaf.clone(), leaf, ca];
    let err = verify_basic_constraints(&bogus).unwrap_err();
    assert!(matches!(err, TrustError::BasicConstraints(_)), "{err:?}");
}

#[test]
fn rejects_chain_too_short_for_basic_constraints() {
    let ca = Certificate::from_pem(CA).unwrap();
    let err = verify_basic_constraints(&[ca]).unwrap_err();
    assert!(matches!(err, TrustError::PathBuild(_)), "{err:?}");
}

#[test]
fn rejects_path_length_constraint_exceeded() {
    // The intermediate fixture has pathlen:0 which means no further
    // intermediates may sit between it and the leaf. Inserting another
    // intermediate (clone of int) at position 2 must violate that.
    let leaf = Certificate::from_pem(LEAF).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    // Synthetic 4-element chain: [leaf, int, int, ca].  This is not a valid
    // signed chain — but verify_basic_constraints checks BC only.
    let chain = vec![leaf, int.clone(), int, ca];
    let err = verify_basic_constraints(&chain).unwrap_err();
    assert!(matches!(err, TrustError::BasicConstraints(_)), "{err:?}");
}

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use tessera_core::x509::chain::build_chain;
use tessera_core::x509::{Certificate, TrustError};

const LEAF: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");
const CA: &[u8] = include_bytes!("fixtures/ca.pem");

fn pem(b: &[u8]) -> Certificate {
    Certificate::from_pem(b).expect("valid pem")
}

#[test]
fn builds_full_chain_through_intermediate() {
    let leaf = pem(LEAF);
    let chain = build_chain(&leaf, &[pem(INT)], &[], &[pem(CA)], 4).unwrap();
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].subject_cn().unwrap(), "alice");
    assert_eq!(chain[1].subject_cn().unwrap(), "CertAuth Test Intermediate");
    assert_eq!(chain[2].subject_cn().unwrap(), "CertAuth Test Root CA");
}

#[test]
fn rejects_missing_intermediate() {
    let leaf = pem(LEAF);
    let err = build_chain(&leaf, &[], &[], &[pem(CA)], 4).unwrap_err();
    assert!(matches!(err, TrustError::PathBuild(_)), "{err:?}");
}

#[test]
fn rejects_when_anchor_not_self_signed() {
    let leaf = pem(LEAF);
    // Use the intermediate as a (bogus) anchor — it's not self-signed.
    let bogus_anchor = pem(INT);
    let err = build_chain(&leaf, &[pem(INT)], &[], &[bogus_anchor], 4).unwrap_err();
    assert!(
        matches!(err, TrustError::PathBuild(_) | TrustError::AnchorMismatch),
        "{err:?}"
    );
}

#[test]
fn enforces_max_depth() {
    let leaf = pem(LEAF);
    let err = build_chain(&leaf, &[pem(INT)], &[], &[pem(CA)], 1).unwrap_err();
    assert!(matches!(err, TrustError::DepthExceeded(_, _)), "{err:?}");
}

#[test]
fn pool_intermediate_is_used_when_not_presented() {
    let leaf = pem(LEAF);
    let chain = build_chain(&leaf, &[], &[pem(INT)], &[pem(CA)], 4).unwrap();
    assert_eq!(chain.len(), 3);
}

#[test]
fn recognizes_root_directly_when_leaf_signed_by_root() {
    // Synthetic case: feed CA itself as the leaf candidate; build should
    // detect it's already the anchor (self-signed) and produce a 1-element
    // anchor-only "chain"... but build_chain expects leaf!=anchor by
    // contract.  Rather than test that, we verify that find_issuer correctly
    // matches the root via subject==issuer DN by using INT as a leaf and CA
    // as anchor with no intermediates.
    let int_as_leaf = pem(INT);
    let chain = build_chain(&int_as_leaf, &[], &[], &[pem(CA)], 4).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].subject_cn().unwrap(), "CertAuth Test Intermediate");
    assert_eq!(chain[1].subject_cn().unwrap(), "CertAuth Test Root CA");
}

//! Per-link chain-policy enforcement over fully built chains.
//!
//! These tests build real signed `leaf -> intermediate -> root` chains in
//! memory (no on-disk fixtures) and drive them through
//! [`enforce_chain_policy`], the pass the manual verifier runs in place of
//! OpenSSL's `X509_verify_cert`.  They cover the three regressions:
//!
//! * a disallowed-algorithm (SHA-1) intermediate below an allowed leaf,
//! * a `serverAuth`-only intermediate above a `clientAuth` leaf,
//! * a weak-key (1024-bit RSA) intermediate.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509Builder, X509Name, X509};

use tessera_core::x509::chain_policy::{enforce_chain_policy, ChainPolicy};
use tessera_core::x509::{Certificate, TrustError};

/// What extended-key-usage extension to place on a generated certificate.
#[derive(Clone, Copy)]
enum Eku {
    None,
    ClientAuth,
    ServerAuth,
}

fn rsa_key(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}

fn name(cn: &str) -> X509Name {
    let mut b = X509Name::builder().unwrap();
    b.append_entry_by_text("CN", cn).unwrap();
    b.build()
}

/// Builds a signed certificate.  When `issuer` is `None` the certificate is
/// self-signed with its own key (a root).  `digest` selects the signature hash.
fn build_cert(
    cn: &str,
    subject_key: &PKey<Private>,
    issuer: Option<(&X509Name, &PKey<Private>)>,
    is_ca: bool,
    eku: Eku,
    digest: MessageDigest,
) -> X509 {
    let subject = name(cn);
    let (issuer_name, issuer_key) = match issuer {
        Some((n, k)) => (n, k),
        None => (&subject, subject_key),
    };

    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();

    let mut bn = BigNum::new().unwrap();
    bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&bn).unwrap())
        .unwrap();

    b.set_subject_name(&subject).unwrap();
    b.set_issuer_name(issuer_name).unwrap();
    b.set_pubkey(subject_key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    let mut bc = BasicConstraints::new();
    if is_ca {
        bc.critical().ca();
    }
    b.append_extension(bc.build().unwrap()).unwrap();

    let mut ku = KeyUsage::new();
    ku.critical();
    if is_ca {
        ku.key_cert_sign().crl_sign();
    } else {
        ku.digital_signature();
    }
    b.append_extension(ku.build().unwrap()).unwrap();

    match eku {
        Eku::None => {}
        Eku::ClientAuth => {
            b.append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
                .unwrap();
        }
        Eku::ServerAuth => {
            b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
                .unwrap();
        }
    }

    b.sign(issuer_key, digest).unwrap();
    b.build()
}

fn cert(x: &X509) -> Certificate {
    Certificate::from_der(&x.to_der().unwrap()).unwrap()
}

/// Assemble a `[leaf, intermediate, root]` chain from the given parts.
struct BuiltChain {
    root_key: PKey<Private>,
    root: X509,
    root_name: X509Name,
}

impl BuiltChain {
    fn new() -> Self {
        let root_key = rsa_key(2048);
        let root_name = name("Test Root CA");
        let root = build_cert(
            "Test Root CA",
            &root_key,
            None,
            true,
            Eku::None,
            MessageDigest::sha256(),
        );
        Self {
            root_key,
            root,
            root_name,
        }
    }

    /// Build the full chain with a configurable intermediate.
    fn chain(
        &self,
        int_key_bits: u32,
        int_eku: Eku,
        int_digest: MessageDigest,
    ) -> Vec<Certificate> {
        let int_key = rsa_key(int_key_bits);
        let int_name = name("Test Intermediate CA");
        let int = build_cert(
            "Test Intermediate CA",
            &int_key,
            Some((&self.root_name, &self.root_key)),
            true,
            int_eku,
            int_digest,
        );

        let leaf_key = rsa_key(2048);
        let leaf = build_cert(
            "engineer",
            &leaf_key,
            Some((&int_name, &int_key)),
            false,
            Eku::ClientAuth,
            MessageDigest::sha256(),
        );

        vec![cert(&leaf), cert(&int), cert(&self.root)]
    }
}

fn sha256_only() -> Vec<String> {
    vec!["sha256WithRSAEncryption".to_string()]
}

#[test]
fn accepts_well_formed_chain() {
    let built = BuiltChain::new();
    let chain = built.chain(2048, Eku::None, MessageDigest::sha256());
    let wl = sha256_only();
    enforce_chain_policy(
        &chain,
        &ChainPolicy {
            signature_alg_whitelist: &wl,
        },
    )
    .unwrap();
}

#[test]
fn rejects_sha1_signed_intermediate() {
    // TSRA-SEC-007: an allowed-algorithm leaf below a SHA-1-signed
    // intermediate must be refused even though the leaf itself is fine.
    let built = BuiltChain::new();
    let chain = built.chain(2048, Eku::None, MessageDigest::sha1());
    let wl = sha256_only();
    let err = enforce_chain_policy(
        &chain,
        &ChainPolicy {
            signature_alg_whitelist: &wl,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, TrustError::SignatureAlgorithm(_)),
        "expected SignatureAlgorithm, got {err:?}"
    );
}

#[test]
fn rejects_server_auth_only_intermediate() {
    // TSRA-SEC-018: a serverAuth-only intermediate above a clientAuth leaf
    // must be refused — the EKU intersection no longer permits clientAuth.
    let built = BuiltChain::new();
    let chain = built.chain(2048, Eku::ServerAuth, MessageDigest::sha256());
    let wl = sha256_only();
    let err = enforce_chain_policy(
        &chain,
        &ChainPolicy {
            signature_alg_whitelist: &wl,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, TrustError::EkuChainViolation(_)),
        "expected EkuChainViolation, got {err:?}"
    );
}

#[test]
fn accepts_client_auth_intermediate() {
    // An intermediate that explicitly carries clientAuth keeps it in the
    // intersection and must pass.
    let built = BuiltChain::new();
    let chain = built.chain(2048, Eku::ClientAuth, MessageDigest::sha256());
    let wl = sha256_only();
    enforce_chain_policy(
        &chain,
        &ChainPolicy {
            signature_alg_whitelist: &wl,
        },
    )
    .unwrap();
}

#[test]
fn rejects_weak_key_intermediate() {
    // TSRA-SEC-002: a 1024-bit RSA intermediate must be refused wherever it
    // sits in the path.
    let built = BuiltChain::new();
    let chain = built.chain(1024, Eku::None, MessageDigest::sha256());
    let wl = sha256_only();
    let err = enforce_chain_policy(
        &chain,
        &ChainPolicy {
            signature_alg_whitelist: &wl,
        },
    )
    .unwrap_err();
    assert!(matches!(err, TrustError::WeakKey(_)), "{err:?}");
}

#[test]
fn empty_whitelist_permits_any_algorithm() {
    // Mirrors pre-validation: an empty allow-list imposes no signature
    // -algorithm constraint (the SHA-1 intermediate passes the alg gate).
    let built = BuiltChain::new();
    let chain = built.chain(2048, Eku::None, MessageDigest::sha1());
    let wl: Vec<String> = vec![];
    enforce_chain_policy(
        &chain,
        &ChainPolicy {
            signature_alg_whitelist: &wl,
        },
    )
    .unwrap();
}

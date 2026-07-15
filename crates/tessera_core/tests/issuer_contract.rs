//! Cross-crate contract: what `tessera_issuer` issues, the Engine parses.
//!
//! This is the executable form of `cert-issuance` task 2.7 — "что выпустил
//! issuer — принял разбор Engine". It builds a root → organisation CA → shift
//! leaf entirely through `tessera_issuer`, then feeds each finished artifact to
//! the *real* Engine parsers in `tessera_core` (the OpenSSL path:
//! [`X509::from_der`] / [`VerifiedX509`] and the extension parsers) and asserts
//! the parsed values equal what was requested.
//!
//! The certificates are signed with a real P-256 key so the `signatureValue` is
//! a well-formed ECDSA signature, but this test does **not** verify the
//! signature: the Engine may require different algorithms per policy, and the
//! contract under test is the byte-level agreement on the custom extensions and
//! certificate structure, not signature validity.
//!
//! Gated on the `mac-tests` feature because constructing a [`VerifiedX509`]
//! outside a real verification pipeline needs
//! [`VerifiedX509::from_trusted_for_test`], which is only available under that
//! feature (or the crate's own `cfg(test)`). Run with:
//! `cargo test -p tessera_core --features mac-tests --test issuer_contract`.

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;

use openssl::x509::X509;

use tessera_core::x509::allowed_roles_ext::extract_allowed_roles;
use tessera_core::x509::delegation_constraints_ext::extract_delegation_constraints;
use tessera_core::x509::max_integrity_ext::extract_max_integrity;
use tessera_core::x509::profile_version_ext::extract_profile_version;
use tessera_core::x509::{host_binding_ext, user_binding_ext, VerifiedX509};

use tessera_ext::delegation::DelegationConstraints;
use tessera_issuer::sign::{KeyId, SignError, Signature, SignatureAlgorithm, SignatureBackend};
use tessera_issuer::test_support::{self_signed_ca, spki_fixture, MemoryStorage};
use tessera_issuer::{
    issue_ca, issue_leaf, CaRequest, IntegrityCeiling, Journal, LeafRequest, Serial, Validity,
};

/// Fixed issuance clock (Unix seconds) for the journal entries this suite mints.
const NOW_UNIX: u64 = 1_700_000_000;

/// A signing backend using a real, fixed P-256 key (RFC 6979 deterministic
/// ECDSA over SHA-256).
struct P256Signer {
    key_id: KeyId,
    signing_key: p256::ecdsa::SigningKey,
    signed: RefCell<bool>,
}

impl P256Signer {
    fn new(key_id: KeyId) -> Self {
        Self {
            key_id,
            signing_key: p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).unwrap(),
            signed: RefCell::new(false),
        }
    }
}

impl SignatureBackend for P256Signer {
    fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
        if key_id == &self.key_id {
            Ok(SignatureAlgorithm::EcdsaWithSha256)
        } else {
            Err(SignError::UnknownKey(key_id.0.clone()))
        }
    }

    fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
        use p256::ecdsa::signature::Signer as _;
        if key_id != &self.key_id {
            return Err(SignError::UnknownKey(key_id.0.clone()));
        }
        *self.signed.borrow_mut() = true;
        let sig: p256::ecdsa::Signature = self.signing_key.sign(tbs_der);
        Ok(Signature {
            algorithm: SignatureAlgorithm::EcdsaWithSha256,
            bytes: sig.to_der().as_bytes().to_vec(),
        })
    }
}

fn validity(secs: u64) -> Validity {
    Validity {
        not_before: 1_600_000_000,
        not_after: 1_600_000_000 + secs,
    }
}

fn envelope(roles: &[&str], max_level: i8, max_ttl: u64) -> DelegationConstraints {
    DelegationConstraints {
        require_tags: vec![("region".to_owned(), "north".to_owned())],
        allow_roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        max_level,
        max_ttl,
    }
}

/// Wraps issued DER as a trusted `VerifiedX509` for the extension parsers.
fn verified(der: &[u8]) -> VerifiedX509 {
    let x509 = X509::from_der(der).expect("Engine's openssl parser accepts the issued DER");
    VerifiedX509::from_trusted_for_test(x509)
}

/// Builds a root → org CA → leaf chain through the issuer, returning the CA and
/// leaf DER (the leaf request is fixed by the caller's expectations below).
fn issue_chain(backend: &P256Signer, key: &KeyId) -> (Vec<u8>, Vec<u8>) {
    let mut journal = Journal::load(MemoryStorage::new()).unwrap();

    let root = self_signed_ca(
        backend,
        key,
        &CaRequest {
            subject: "CN=Tessera Root,O=Tessera Labs".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(9_000_000),
            constraints: envelope(&["oper", "serv"], 5, 86_400),
            profile_version: 1,
        },
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .unwrap()
    .der;

    let org = issue_ca(
        backend,
        key,
        &root,
        &CaRequest {
            subject: "CN=Org CA,O=Some Org".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(5_000_000),
            constraints: envelope(&["oper"], 4, 3_600),
            profile_version: 2,
        },
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .unwrap()
    .der;

    let leaf_req = LeafRequest {
        subject: "CN=ivanov,O=Some Org".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: validity(3_600),
        host_binding: vec!["*".to_owned()],
        user_binding: vec!["ivanov".to_owned()],
        allowed_roles: vec!["oper".to_owned()],
        max_integrity: Some(IntegrityCeiling {
            level: 4,
            categories: 0b1010,
        }),
        profile_version: 2,
    };
    let leaf = issue_leaf(
        backend,
        key,
        &org,
        &leaf_req,
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .unwrap()
    .der;
    (org, leaf)
}

#[test]
fn engine_parsers_accept_issued_ca_and_leaf() {
    let key = KeyId::new("contract-ca");
    let backend = P256Signer::new(key.clone());
    let (org, leaf) = issue_chain(&backend, &key);
    assert!(*backend.signed.borrow(), "artifacts were actually signed");

    // --- CA artifact through the Engine parsers. ---
    let ca_verified = verified(&org);
    assert!(
        ca_verified.is_ca().unwrap(),
        "Engine reads basicConstraints cA=TRUE on the CA"
    );
    let ca_constraints = extract_delegation_constraints(&ca_verified)
        .expect("Engine parses the delegation envelope")
        .expect("the CA carries a delegation envelope");
    assert_eq!(ca_constraints.max_level, 4);
    assert_eq!(ca_constraints.max_ttl, 3_600);
    assert_eq!(
        ca_constraints.require_tags,
        vec![("region".to_owned(), "north".to_owned())]
    );
    let ca_roles: Vec<String> = ca_constraints
        .allow_roles
        .iter()
        .map(|r| r.as_str().to_owned())
        .collect();
    assert_eq!(ca_roles, vec!["oper".to_owned()]);

    // --- Leaf artifact through the Engine parsers. ---
    let leaf_verified = verified(&leaf);
    assert!(
        !leaf_verified.is_ca().unwrap(),
        "Engine reads basicConstraints cA=FALSE on the leaf"
    );

    let leaf_x509 = X509::from_der(&leaf).unwrap();
    let hosts = host_binding_ext::parse(&leaf_x509).expect("Engine parses host_binding");
    assert_eq!(hosts, vec![host_binding_ext::HostDescriptor::Wildcard]);
    let users = user_binding_ext::parse(&leaf_x509).expect("Engine parses user_binding");
    assert_eq!(
        users,
        vec![user_binding_ext::UserDescriptor::Exact("ivanov".to_owned())]
    );

    let roles = extract_allowed_roles(&leaf_verified)
        .expect("Engine parses allowed_roles")
        .expect("leaf carries allowed_roles");
    let role_strings: Vec<String> = roles.iter().map(|r| r.as_str().to_owned()).collect();
    assert_eq!(role_strings, vec!["oper".to_owned()]);

    let version = extract_profile_version(&leaf_verified)
        .expect("Engine parses profile_version")
        .expect("leaf carries profile_version");
    assert_eq!(version, 2);

    let integrity = extract_max_integrity(&leaf_verified)
        .expect("Engine parses max_integrity")
        .expect("leaf carries max_integrity");
    assert_eq!(integrity.level, 4);
    assert_eq!(integrity.categories, 0b1010);

    // A leaf must NOT carry a delegation envelope; the Engine's placement rule
    // (valid only on a CA) means the parser rejects it as non-CA if present.
    // The issuer never emits it on a leaf, so extraction returns absent.
    assert!(extract_delegation_constraints(&leaf_verified)
        .expect("no envelope on a leaf")
        .is_none());
}

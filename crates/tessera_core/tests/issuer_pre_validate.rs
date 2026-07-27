//! Cross-half contract: a certificate the issuer releases is a certificate the
//! Engine accepts.
//!
//! The Engine's first gate on a shift leaf is [`pre_validate_end_entity`]; its
//! gate on every chain link above the leaf is
//! [`verify_intermediate_constraints`]. Both are the functions the PAM module
//! itself calls. This suite feeds them artifacts produced by the real
//! `tessera_issuer` issuance path and asserts nothing about extension contents
//! on its own, so a divergence between what issuance emits and what
//! verification demands fails here rather than at a login prompt.
//!
//! It complements `issuer_contract.rs`, which checks the Tessera-specific
//! extensions: this file checks the standard ones (`keyUsage`,
//! `extendedKeyUsage`, `basicConstraints`) that decide whether the certificate
//! is usable for authentication at all.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::duration_suboptimal_units
)]

use std::time::{Duration, SystemTime};

use tessera_core::x509::basic_constraints::verify_intermediate_constraints;
use tessera_core::x509::pre_validate::{pre_validate_end_entity, PreValidateConfig};
use tessera_core::x509::{Certificate, TrustError};

use tessera_ext::delegation::DelegationConstraints;
use tessera_issuer::sign::{KeyId, SignError, Signature, SignatureAlgorithm, SignatureBackend};
use tessera_issuer::test_support::{self_signed_ca, spki_fixture, MemoryStorage};
use tessera_issuer::{
    issue_ca, issue_leaf, CaRequest, Journal, LeafRequest, Serial, Validity as IssuerValidity,
};

/// Issuance clock, and the start of every certificate's validity window.
const NOW_UNIX: u64 = 1_600_000_000;

/// Lifetime of the issued leaf, in seconds.
const LEAF_TTL: u64 = 3_600;

/// Signs with a fixed P-256 key so the artifacts carry a well-formed ECDSA
/// `signatureValue`; pre-validation does not verify signatures, but the DER
/// must parse.
struct P256Signer {
    key_id: KeyId,
    signing_key: p256::ecdsa::SigningKey,
}

impl P256Signer {
    fn new(key_id: KeyId) -> Self {
        Self {
            key_id,
            signing_key: p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).unwrap(),
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
        let sig: p256::ecdsa::Signature = self.signing_key.sign(tbs_der);
        Ok(Signature {
            algorithm: SignatureAlgorithm::EcdsaWithSha256,
            bytes: sig.to_der().as_bytes().to_vec(),
        })
    }
}

fn validity(secs: u64) -> IssuerValidity {
    IssuerValidity {
        not_before: NOW_UNIX,
        not_after: NOW_UNIX + secs,
    }
}

fn envelope() -> DelegationConstraints {
    DelegationConstraints {
        require_tags: vec![],
        allow_roles: vec!["oper".to_owned()],
        max_level: 5,
        max_ttl: LEAF_TTL,
    }
}

/// The Engine's configuration for this suite: the algorithm the issuer signed
/// with, and the skew the module tolerates by default.
fn cfg() -> PreValidateConfig {
    PreValidateConfig {
        clock_skew: Duration::from_secs(60),
        signature_alg_whitelist: vec!["ecdsa-with-SHA256".to_owned()],
    }
}

/// A moment inside the issued validity window.
fn during_validity() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(NOW_UNIX + LEAF_TTL / 2)
}

/// Issues root → organisation CA → shift leaf through the real issuance path,
/// returning the DER of all three, leaf-first: the order the Engine's chain
/// checks expect.
fn issue_chain() -> [Vec<u8>; 3] {
    let key = KeyId::new("pre-validate-ca");
    let backend = P256Signer::new(key.clone());
    let mut journal = Journal::load(MemoryStorage::new()).unwrap();

    let root = self_signed_ca(
        &backend,
        &key,
        &CaRequest {
            subject: "CN=Tessera Root,O=Tessera Labs".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(9_000_000),
            constraints: envelope(),
            profile_version: 1,
        },
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .unwrap()
    .der;

    let org = issue_ca(
        &backend,
        &key,
        &root,
        &CaRequest {
            subject: "CN=Org CA,O=Some Org".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(5_000_000),
            constraints: envelope(),
            profile_version: 1,
        },
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .unwrap()
    .der;

    let leaf = issue_leaf(
        &backend,
        &key,
        &org,
        &LeafRequest {
            subject: "CN=ivanov,O=Some Org".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(LEAF_TTL),
            host_binding: vec!["*".to_owned()],
            allowed_roles: vec!["oper".to_owned()],
            max_integrity: None,
            profile_version: 1,
        },
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .unwrap()
    .der;

    [leaf, org, root]
}

#[test]
fn issued_leaf_passes_engine_pre_validation() {
    let [leaf, _, _] = issue_chain();
    let cert = Certificate::from_der(&leaf).expect("Engine parses the issued leaf");

    // Everything the module demands of a leaf before it builds a chain —
    // validity window, `basicConstraints` cA=FALSE, `keyUsage`
    // digitalSignature, `extendedKeyUsage` clientAuth — asserted by calling the
    // module's own gate. Restating those conditions here would recreate the
    // very split that let the missing extensions reach a login prompt.
    pre_validate_end_entity(&cert, &cfg(), during_validity())
        .expect("the Engine accepts a leaf issued by the standard path");
}

#[test]
fn issued_cas_pass_engine_chain_link_validation() {
    let chain: Vec<Certificate> = issue_chain()
        .iter()
        .map(|der| Certificate::from_der(der).expect("Engine parses the issued certificate"))
        .collect();

    // The gate every non-leaf link goes through during authentication: validity
    // window, `basicConstraints` cA=TRUE and `keyUsage` keyCertSign, asserted by
    // the Engine's own function rather than by an assertion list here — a copy
    // would be free to drift from the original exactly as issuance drifted from
    // verification.
    verify_intermediate_constraints(&chain, during_validity(), cfg().clock_skew)
        .expect("the Engine accepts the organisation CA and root issued by the standard path");
}

#[test]
fn issued_ca_is_refused_as_an_end_entity() {
    let [_, org, _] = issue_chain();
    let cert = Certificate::from_der(&org).expect("Engine parses the issued CA");

    // Symmetric to the leaf case: a CA offered as an end entity is refused —
    // the signing key of a CA is not a shift credential.
    let err = pre_validate_end_entity(&cert, &cfg(), during_validity()).unwrap_err();
    assert!(
        matches!(err, TrustError::KeyUsage | TrustError::BasicConstraints(_)),
        "{err:?}"
    );
}

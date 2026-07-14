//! Scenario, contract, and realistic-signing tests for the issuance core.
//!
//! Each `cert-issuance` spec scenario is covered by at least one test:
//! incomplete extension set rejected before signing, scope wider than the parent
//! rejected with the dimension named, equal scope accepted, two issuances yield
//! distinct well-formed serials, a `crlNumber` rollback rejected with the
//! expected minimum, and the finished artifact accepted byte-for-byte by the
//! shared (`tessera_ext`) parsers the Engine uses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;

use tessera_ext::delegation::{narrows, DelegationConstraints, ScopeDimension};
use tessera_ext::ext::{
    extract_basic_constraints, extract_extension_value, parse_max_integrity, parse_profile_version,
    parse_seq_of_utf8,
};
use tessera_ext::oids::{
    ALLOWED_ROLES_OID, DELEGATION_CONSTRAINTS_OID, HOST_BINDING_OID, MAX_INTEGRITY_OID,
    PROFILE_VERSION_OID, USER_BINDING_OID,
};

use crate::sign::{KeyId, MockSigner, SignError, Signature, SignatureAlgorithm, SignatureBackend};
use crate::test_support::{self_signed_ca, spki_fixture, MemoryStorage};
use crate::{
    issue_ca, issue_crl, issue_leaf, CaRequest, CrlRequest, IntegrityCeiling, IssueError, Journal,
    LeafRequest, RevokedEntry, Serial, Validity,
};

/// A fixed issuance timestamp for the tests (Unix seconds).
const TS: u64 = 1_600_000_000;

/// A throwaway in-memory journal for tests that do not inspect it. Issuance is
/// mandatory-journaled, so every `issue_*` call needs one; `&mut fresh_journal()`
/// supplies a per-call store.
fn fresh_journal() -> Journal<MemoryStorage> {
    Journal::load(MemoryStorage::new()).expect("empty in-memory journal loads")
}

/// A backend that records whether `sign` was called, wrapping [`MockSigner`], so
/// tests can prove a request was rejected *before* any signing.
struct RecordingSigner {
    inner: MockSigner,
    signed: RefCell<bool>,
}

impl RecordingSigner {
    fn new(key_id: KeyId) -> Self {
        Self {
            inner: MockSigner::ecdsa_sha256(key_id),
            signed: RefCell::new(false),
        }
    }

    fn was_signed(&self) -> bool {
        *self.signed.borrow()
    }
}

impl SignatureBackend for RecordingSigner {
    fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
        self.inner.algorithm(key_id)
    }

    fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
        *self.signed.borrow_mut() = true;
        self.inner.sign(tbs_der, key_id)
    }
}

fn key() -> KeyId {
    KeyId::new("test-ca")
}

fn validity(secs: u64) -> Validity {
    Validity {
        not_before: 1_600_000_000,
        not_after: 1_600_000_000 + secs,
    }
}

fn envelope(roles: &[&str], max_level: i8, max_ttl: u64) -> DelegationConstraints {
    DelegationConstraints {
        require_tags: vec![],
        allow_roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        max_level,
        max_ttl,
    }
}

/// A self-signed root allowing `oper`/`serv`, integrity ≤ 5, TTL ≤ 86400.
fn root_ca(backend: &impl SignatureBackend) -> Vec<u8> {
    let req = CaRequest {
        subject: "CN=Tessera Root".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: validity(9_000_000),
        constraints: envelope(&["oper", "serv"], 5, 86_400),
        profile_version: 1,
    };
    self_signed_ca(
        backend,
        &key(),
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .expect("root issues")
    .der
}

/// An org CA under `root`, narrowing to `oper`, integrity ≤ 5, TTL ≤ 3600.
fn org_ca(backend: &impl SignatureBackend, root: &[u8]) -> Vec<u8> {
    let req = CaRequest {
        subject: "CN=Org CA".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: validity(5_000_000),
        constraints: envelope(&["oper"], 5, 3_600),
        profile_version: 1,
    };
    issue_ca(
        backend,
        &key(),
        root,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .expect("org CA issues")
    .der
}

fn leaf_request() -> LeafRequest {
    LeafRequest {
        subject: "CN=ivanov".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: validity(3_600),
        host_binding: vec!["*".to_owned()],
        user_binding: vec!["ivanov".to_owned()],
        allowed_roles: vec!["oper".to_owned()],
        max_integrity: Some(IntegrityCeiling {
            level: 5,
            categories: 0,
        }),
        profile_version: 1,
    }
}

#[test]
fn incomplete_extension_set_rejected_before_signing() {
    let backend = RecordingSigner::new(key());
    let root = root_ca(&backend);
    let org = org_ca(&backend, &root);

    let mut req = leaf_request();
    req.host_binding.clear();
    let err = issue_leaf(
        &backend,
        &key(),
        &org,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap_err();
    assert_eq!(err, IssueError::MissingHostBinding);
    // The org CA was signed, but the invalid leaf must not have reached signing;
    // reset tracking by using a fresh backend focused on the leaf call.
    let leaf_only = RecordingSigner::new(key());
    let err = issue_leaf(
        &leaf_only,
        &key(),
        &org,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap_err();
    assert_eq!(err, IssueError::MissingHostBinding);
    assert!(
        !leaf_only.was_signed(),
        "leaf must be rejected before signing"
    );
}

#[test]
fn leaf_scope_wider_than_parent_rejected_with_dimension() {
    let backend = MockSigner::ecdsa_sha256(key());
    let root = root_ca(&backend);
    let org = org_ca(&backend, &root); // allows only `oper`

    let mut req = leaf_request();
    req.allowed_roles = vec!["oper".to_owned(), "serv".to_owned()]; // `serv` not allowed by org CA

    let leaf_only = RecordingSigner::new(key());
    let err = issue_leaf(
        &leaf_only,
        &key(),
        &org,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap_err();
    assert_eq!(err, IssueError::ScopeWidened(ScopeDimension::AllowRoles));
    assert!(!leaf_only.was_signed(), "widened leaf must not be signed");
}

#[test]
fn leaf_integrity_above_parent_rejected() {
    let backend = MockSigner::ecdsa_sha256(key());
    let root = root_ca(&backend);
    let mut org_req = CaRequest {
        subject: "CN=Org CA".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: validity(5_000_000),
        constraints: envelope(&["oper"], 3, 3_600), // ceiling 3
        profile_version: 1,
    };
    let org = issue_ca(
        &backend,
        &key(),
        &root,
        &org_req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap()
    .der;
    org_req.constraints.max_level = 3;

    let mut req = leaf_request();
    req.max_integrity = Some(IntegrityCeiling {
        level: 4,
        categories: 0,
    });
    let err = issue_leaf(
        &backend,
        &key(),
        &org,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap_err();
    assert_eq!(
        err,
        IssueError::IntegrityExceedsParent {
            requested: 4,
            ceiling: 3
        }
    );
}

#[test]
fn leaf_ttl_above_parent_rejected() {
    let backend = MockSigner::ecdsa_sha256(key());
    let root = root_ca(&backend);
    let org = org_ca(&backend, &root); // max_ttl 3600

    let mut req = leaf_request();
    req.validity = validity(7_200); // 2h > 1h ceiling
    let err = issue_leaf(
        &backend,
        &key(),
        &org,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap_err();
    assert_eq!(
        err,
        IssueError::ValidityExceedsParent {
            requested_secs: 7_200,
            max_ttl: 3_600
        }
    );
}

#[test]
fn leaf_scope_equal_to_parent_is_accepted() {
    let backend = MockSigner::ecdsa_sha256(key());
    let root = root_ca(&backend);
    let org = org_ca(&backend, &root); // roles [oper], level 5, ttl 3600

    // Exactly the parent's ceilings: roles == {oper}, level 5, duration 3600.
    let req = leaf_request();
    let issued = issue_leaf(
        &backend,
        &key(),
        &org,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .expect("equal scope narrows (non-strict)");
    assert!(!issued.der.is_empty());
}

#[test]
fn ca_scope_wider_than_parent_rejected_with_dimension() {
    let backend = MockSigner::ecdsa_sha256(key());
    let root = root_ca(&backend); // level ceiling 5
    let req = CaRequest {
        subject: "CN=Greedy CA".to_owned(),
        subject_spki_der: spki_fixture(),
        validity: validity(5_000_000),
        constraints: envelope(&["oper"], 6, 3_600), // level 6 > root 5
        profile_version: 1,
    };
    let err = issue_ca(
        &backend,
        &key(),
        &root,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap_err();
    assert_eq!(err, IssueError::ScopeWidened(ScopeDimension::MaxLevel));
}

#[test]
fn two_issuances_get_distinct_well_formed_serials() {
    let backend = MockSigner::ecdsa_sha256(key());
    let root = root_ca(&backend);
    let org = org_ca(&backend, &root);
    let req = leaf_request();

    let a = issue_leaf(
        &backend,
        &key(),
        &org,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap();
    let b = issue_leaf(
        &backend,
        &key(),
        &org,
        &req,
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap();
    assert_ne!(a.serial, b.serial, "independent serials must differ");
    for serial in [&a.serial, &b.serial] {
        assert!(!serial.is_empty() && serial.len() <= 20);
        assert_eq!(serial.first().copied().unwrap() & 0x80, 0, "positive");
    }
}

#[test]
fn crl_number_rollback_rejected_with_expected_minimum() {
    let backend = MockSigner::ecdsa_sha256(key());
    let root = root_ca(&backend);
    let org = org_ca(&backend, &root);

    let req = CrlRequest {
        this_update: 1_600_000_000,
        next_update: Some(1_600_086_400),
        crl_number: 7,
        revoked: vec![RevokedEntry {
            serial: vec![0x2a],
            revocation_date: 1_600_000_500,
            reason: Some(crate::CrlReason::Superseded),
        }],
    };
    // A rollback: proposing 7 when 7 was already issued.
    let err = issue_crl(&backend, &key(), &org, &req, 7, &mut fresh_journal(), TS).unwrap_err();
    assert_eq!(
        err,
        IssueError::CrlNumberNotIncreasing {
            proposed: 7,
            minimum: 8
        }
    );
    // A forward step succeeds and records the number.
    let issued = issue_crl(&backend, &key(), &org, &req, 6, &mut fresh_journal(), TS)
        .expect("monotone CRL issues");
    assert_eq!(issued.crl_number, 7);
    assert!(!issued.der.is_empty());
}

#[test]
fn issued_artifacts_are_accepted_by_shared_parsers() {
    let backend = MockSigner::ecdsa_sha256(key());
    let root = root_ca(&backend);
    let org = org_ca(&backend, &root);
    let leaf = issue_leaf(
        &backend,
        &key(),
        &org,
        &leaf_request(),
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .unwrap()
    .der;

    // --- CA artifact: the Engine's shared parsers accept every extension. ---
    let ca_basic = extract_basic_constraints(&org).unwrap().unwrap();
    assert!(ca_basic.ca, "org CA must assert cA=TRUE");
    let ca_env_der = extract_extension_value(&org, DELEGATION_CONSTRAINTS_OID)
        .unwrap()
        .expect("CA carries a delegation envelope");
    let ca_env = tessera_ext::delegation::parse_constraints(&ca_env_der).unwrap();
    assert_eq!(ca_env, envelope(&["oper"], 5, 3_600));
    // The org CA's envelope narrows the root's — the exact relation the Engine
    // enforces across a chain.
    let root_env_der = extract_extension_value(&root, DELEGATION_CONSTRAINTS_OID)
        .unwrap()
        .unwrap();
    let root_env = tessera_ext::delegation::parse_constraints(&root_env_der).unwrap();
    assert!(narrows(&ca_env, &root_env).is_ok());

    // --- Leaf artifact: every custom extension parses to the requested value. ---
    let req = leaf_request();
    let leaf_basic = extract_basic_constraints(&leaf).unwrap().unwrap();
    assert!(!leaf_basic.ca, "leaf must assert cA=FALSE");
    assert!(
        extract_extension_value(&leaf, DELEGATION_CONSTRAINTS_OID)
            .unwrap()
            .is_none(),
        "a leaf must not carry a delegation envelope"
    );
    let hosts = parse_seq_of_utf8(
        &extract_extension_value(&leaf, HOST_BINDING_OID)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(hosts, req.host_binding);
    let users = parse_seq_of_utf8(
        &extract_extension_value(&leaf, USER_BINDING_OID)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(users, req.user_binding);
    let roles = parse_seq_of_utf8(
        &extract_extension_value(&leaf, ALLOWED_ROLES_OID)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(roles, req.allowed_roles);
    let version = parse_profile_version(
        &extract_extension_value(&leaf, PROFILE_VERSION_OID)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(version, req.profile_version);
    let (level, categories) = parse_max_integrity(
        &extract_extension_value(&leaf, MAX_INTEGRITY_OID)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!((level, categories), (5, 0));
}

/// A backend that signs with a real P-256 key (RFC 6979 deterministic ECDSA over
/// SHA-256), recording the exact TBS it signed so the test can verify the
/// signature the issuer embedded.
struct P256Signer {
    key_id: KeyId,
    signing_key: p256::ecdsa::SigningKey,
    last_tbs: RefCell<Vec<u8>>,
    last_sig: RefCell<Vec<u8>>,
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
        let der = sig.to_der().as_bytes().to_vec();
        *self.last_tbs.borrow_mut() = tbs_der.to_vec();
        *self.last_sig.borrow_mut() = der.clone();
        Ok(Signature {
            algorithm: SignatureAlgorithm::EcdsaWithSha256,
            bytes: der,
        })
    }
}

#[test]
fn real_p256_signature_over_tbs_verifies() {
    use p256::ecdsa::signature::Verifier as _;

    // A fixed non-zero scalar — a valid P-256 private key for the test.
    let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let verifying_key = *signing_key.verifying_key();
    let backend = P256Signer {
        key_id: key(),
        signing_key,
        last_tbs: RefCell::new(Vec::new()),
        last_sig: RefCell::new(Vec::new()),
    };

    let root = root_ca(&backend);
    let org = org_ca(&backend, &root);
    let issued = issue_leaf(
        &backend,
        &key(),
        &org,
        &leaf_request(),
        &Serial::generate(),
        &mut fresh_journal(),
        TS,
    )
    .expect("real signature path issues");
    assert!(!issued.der.is_empty());

    // The signature the issuer embedded was made over the TBS it built.
    let tbs = backend.last_tbs.borrow().clone();
    let sig = p256::ecdsa::Signature::from_der(&backend.last_sig.borrow()).unwrap();
    assert!(verifying_key.verify(&tbs, &sig).is_ok());
}

/// CSR (PKCS#10) issuance scenarios from `cert-issuance`: a valid P-256 and RSA
/// CSR issue with the key/subject from the request, a broken self-signature is
/// refused before any signing, and a CSR's requested extensions never shape the
/// issued certificate.
mod csr {
    use core::str::FromStr as _;

    use der::asn1::{BitString, OctetString, SetOfVec};
    use der::{Any, Decode as _, Encode as _};
    use sha2::{Digest as _, Sha256};
    use spki::SubjectPublicKeyInfoOwned;
    use x509_cert::attr::{Attribute, Attributes};
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::request::{CertReq, CertReqInfo, Version};

    use super::{fresh_journal, key, org_ca, root_ca, RecordingSigner, TS};
    use crate::csr::{issue_leaf_from_csr, Csr, LeafRequestFromCsr, LeafScope};
    use crate::sign::{MockSigner, SignatureAlgorithm};
    use crate::{IssueError, Serial};
    use tessera_ext::der::{encode_tlv, TAG_BOOLEAN, TAG_SEQUENCE};
    use tessera_ext::ext::extract_basic_constraints;

    /// The SHA-256 `DigestInfo` prefix (mirrors the constant under test) for the
    /// RSA signing side of the fixtures.
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    /// PKCS#9 `extensionRequest` attribute OID.
    const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";
    /// `basicConstraints` extension OID.
    const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";

    /// A fixed 2048-bit RSA test key (PKCS#1 DER, base64) so the RSA path needs
    /// no key generation at test time.
    const RSA_TEST_KEY_PKCS1_B64: &str = "MIIEpQIBAAKCAQEA0peEY/71e6xdldkkYa/VWQHC89/hdv9guWbc0v2TkSrKDH4dgYA0eEAGmNtM+t0jwfJjIFicZAgYxtm/FLF5IJ4yBmvIsOw3Ll99hCfxSm3GovtBBUrTfJbUe5p3TLYsoTpxaxbif+NC5wLYMJLvpXTnxyS/0KwCfhoz70146BLfbYx3n2eCb6o+jaXg6u1pnLz6Ef4Q/RKl9A/tU9h2hP6YdfU83GqCgKFsx2bjrVWsy2fIuxTRgw8n3i+9tF2jtkqz+FqCfLXMvxEvqV7e0Oysv55Qrvehxj/k4z1Xm4bSkr5cJ+dlT9aXE1HE+OVaSGg8LhNnzhE/F6InAo2ntQIDAQABAoIBAB8TEYuJ1yJhLEwMxxQNFJ+2JVTEH+plw5mIBqSxm0FL/ZV7VJJD3zoxRGfw0DqiQAEB6cOfn7AZC8Ln5YzBpVx9S2dsJyiIKppSp9xE4pN3gFyTU6Raxrs3LHJyuBDfPtWpoIvLTC/P0pLw9gKw4+DXz82wbAd4IkQGTMyOc31W6w63jUz99mnnBQH+jOQZl7LoIhGVdQ67aJ/FwRl7BazXwwGRjjSl2EdHS346LuD+tWVnD5tS9uccHcp2crlp1AsMEZ05keYbm66Z1XC+ldSiPZfB/zGRBi1JRgHxwvwnxi42/d5dnMJYz89KD+CSC1CB0vcEegSMqFbwIKSLk2ECgYEA6yh1IpeXMmKjIhWW+QrwStbFMoBHnqBGrMSyJpyNVM9X/59n+02YrGDfDeqhKsMMANyVYirjMNKZVhaW8dXjk74Nqkr7tedeNOQXVlokxLHpDXHD8ZlxZGQiQbOWI+SQs1AW1vF8yx+WJ5YTRRYG1v72pq87x1Ohpc4BmnKWKnECgYEA5UGsXtm+uXDG6xkMOMvzHngJunkQ+mX/LK6YYD+3DhIbV/xMsjtPxFTY8bd34LmJa3GLBJernn15YfINUoK4+ZBwDw56muCCjMw0O3rTevbQaz8XpIutc7WY7Jnn2WFbQ4OxMZqMWeNwyG7wdHW9R6uFDhgUGhCONCJy9jICy4UCgYEApIvgut3b/HOsttLom0ceMR/rSJUeiE6aZZYVGpN9CZU0fDfsqJn5dNUr/y7oq2Vj5s5y8QgVhTo39VdFM994qQ7ZvQlO7FADSXs5IUFebQwYiUHL3CiEgbzXg6XIL0FmRzKJaMn9ipyFkxmeTj9FdfdeW/BOIgHRIJXv5US88uECgYEAiu51qzWB45d4tNiFE5ZlSz2rh5n+tABD16wnI4z5Pkmy0GtRf2F6QZy5rCJnP4SwxrAUc0AG/RFFEhpCAJK/zl29yyIXIuyTsQe/T5xrtMUGITgm98y93LVca2YJny7kw9F2/HyQOZkfrBevGKSRhHFpPNVSuUj3JJkL2i8MipECgYEAzPtarbETJ0n6nUmt0olZIZ8sebDfOpZF/TccAGm8lcc0vsIe3A+KQ9hh8QkenRajs3cE1p0tm/nd4DalpWJs0XXckVWjukGupT7Ign9nZZeNXMrF4htOg1/Nn628Dw9KF6be/bOmPpJgpCN8oPd7vw9R5MHjf4o12pPbmVn6PoY=";

    /// A CSR built with a P-256 signing key over the given subject and attributes.
    fn p256_csr(
        signing_key: &p256::ecdsa::SigningKey,
        subject: &str,
        attributes: Attributes,
    ) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        use p256::pkcs8::EncodePublicKey as _;

        let spki_doc = signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("encode P-256 public key");
        let public_key =
            SubjectPublicKeyInfoOwned::from_der(spki_doc.as_bytes()).expect("reparse SPKI");
        let info = CertReqInfo {
            version: Version::V1,
            subject: Name::from_str(subject).expect("parse subject"),
            public_key,
            attributes,
        };
        let info_der = info.to_der().expect("encode CertReqInfo");
        let signature: p256::ecdsa::Signature = signing_key.sign(&info_der);
        assemble_csr(
            info,
            SignatureAlgorithm::EcdsaWithSha256.algorithm_identifier(),
            signature.to_der().as_bytes(),
        )
    }

    /// A CSR built with the fixed RSA test key.
    fn rsa_csr(subject: &str, attributes: Attributes) -> Vec<u8> {
        use base64::Engine as _;
        use rsa::pkcs1::DecodeRsaPrivateKey as _;
        use rsa::pkcs1v15::Pkcs1v15Sign;
        use rsa::pkcs8::EncodePublicKey as _;

        let key_der = base64::engine::general_purpose::STANDARD
            .decode(RSA_TEST_KEY_PKCS1_B64)
            .expect("decode RSA test key");
        let private_key = rsa::RsaPrivateKey::from_pkcs1_der(&key_der).expect("load RSA test key");
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let spki_doc = public_key
            .to_public_key_der()
            .expect("encode RSA public key");
        let public_key_info =
            SubjectPublicKeyInfoOwned::from_der(spki_doc.as_bytes()).expect("reparse SPKI");
        let info = CertReqInfo {
            version: Version::V1,
            subject: Name::from_str(subject).expect("parse subject"),
            public_key: public_key_info,
            attributes,
        };
        let info_der = info.to_der().expect("encode CertReqInfo");
        let mut hashed = [0u8; 32];
        hashed.copy_from_slice(&Sha256::digest(&info_der));
        let scheme = Pkcs1v15Sign {
            hash_len: Some(hashed.len()),
            prefix: Box::from(SHA256_DIGEST_INFO_PREFIX.as_slice()),
        };
        let signature = private_key.sign(scheme, &hashed).expect("RSA sign CSR");
        assemble_csr(
            info,
            SignatureAlgorithm::RsaPkcs1Sha256.algorithm_identifier(),
            &signature,
        )
    }

    /// Wraps a signed `CertReqInfo` into a full `CertReq` DER.
    fn assemble_csr(
        info: CertReqInfo,
        algorithm: spki::AlgorithmIdentifierOwned,
        signature: &[u8],
    ) -> Vec<u8> {
        let certreq = CertReq {
            info,
            algorithm,
            signature: BitString::from_bytes(signature).expect("signature bit string"),
        };
        certreq.to_der().expect("encode CertReq")
    }

    /// Empty request attributes.
    fn no_attributes() -> Attributes {
        SetOfVec::new()
    }

    /// A single `extensionRequest` attribute asking for `basicConstraints`
    /// `cA=TRUE` — a request the issuer must ignore.
    fn attributes_requesting_ca() -> Attributes {
        let bc_value = encode_tlv(TAG_SEQUENCE, &encode_tlv(TAG_BOOLEAN, &[0xFF]));
        let extension = Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap(BASIC_CONSTRAINTS_OID),
            critical: true,
            extn_value: OctetString::new(bc_value).expect("octet string"),
        };
        let extensions_der = vec![extension].to_der().expect("encode extensions");
        let any = Any::from_der(&extensions_der).expect("wrap extensions as Any");
        let mut values = SetOfVec::new();
        values.insert(any).expect("insert value");
        let attribute = Attribute {
            oid: const_oid::ObjectIdentifier::new_unwrap(EXTENSION_REQUEST_OID),
            values,
        };
        let mut attributes = SetOfVec::new();
        attributes.insert(attribute).expect("insert attribute");
        attributes
    }

    /// An operator scope of `oper`, integrity 5, TTL 3600 — inside `org_ca`.
    fn scope() -> LeafScope {
        LeafScope {
            validity: super::validity(3_600),
            host_binding: vec!["*".to_owned()],
            user_binding: vec!["ivanov".to_owned()],
            allowed_roles: vec!["oper".to_owned()],
            max_integrity: Some(crate::IntegrityCeiling {
                level: 5,
                categories: 0,
            }),
            profile_version: 1,
        }
    }

    #[test]
    fn valid_p256_csr_issues_with_csr_key_and_subject() {
        let backend = MockSigner::ecdsa_sha256(key());
        let root = root_ca(&backend);
        let org = org_ca(&backend, &root);

        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        let csr_der = p256_csr(&signing_key, "CN=ivanov,O=Org", no_attributes());

        // The parsed CSR exposes its own subject and key, and self-verifies.
        let csr = Csr::parse(&csr_der).unwrap();
        assert_eq!(csr.subject(), "CN=ivanov,O=Org");
        csr.verify_proof_of_possession()
            .expect("valid self-signature");

        let req = LeafRequestFromCsr {
            csr: csr_der,
            scope: scope(),
        };
        let issued = issue_leaf_from_csr(
            &backend,
            &key(),
            &org,
            &req,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .expect("CSR leaf issues");
        assert!(!issued.der.is_empty());
    }

    #[test]
    fn pem_wrapped_csr_parses() {
        use base64::Engine as _;

        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x33u8; 32]).unwrap();
        let der = p256_csr(&signing_key, "CN=ivanov", no_attributes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{b64}\n-----END CERTIFICATE REQUEST-----\n"
        );

        let csr = Csr::parse(pem.as_bytes()).unwrap();
        assert_eq!(csr.subject(), "CN=ivanov");
        csr.verify_proof_of_possession()
            .expect("PEM CSR self-signature verifies");
    }

    #[test]
    fn valid_rsa_csr_issues() {
        let backend = MockSigner::ecdsa_sha256(key());
        let root = root_ca(&backend);
        let org = org_ca(&backend, &root);

        let csr_der = rsa_csr("CN=petrov", no_attributes());
        let csr = Csr::parse(&csr_der).unwrap();
        csr.verify_proof_of_possession()
            .expect("valid RSA self-signature");

        let req = LeafRequestFromCsr {
            csr: csr_der,
            scope: scope(),
        };
        let issued = issue_leaf_from_csr(
            &backend,
            &key(),
            &org,
            &req,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .expect("RSA CSR leaf issues");
        assert!(!issued.der.is_empty());
    }

    #[test]
    fn broken_self_signature_rejected_before_signing() {
        let leaf_only = RecordingSigner::new(key());
        let root = {
            let backend = MockSigner::ecdsa_sha256(key());
            let root = root_ca(&backend);
            org_ca(&backend, &root)
        };

        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        let good = p256_csr(&signing_key, "CN=ivanov", no_attributes());
        // Flip a bit in the signature so proof of possession fails.
        let mut certreq = CertReq::from_der(&good).unwrap();
        let mut sig = certreq.signature.raw_bytes().to_vec();
        if let Some(byte) = sig.last_mut() {
            *byte ^= 0x01;
        }
        certreq.signature = BitString::from_bytes(&sig).unwrap();
        let tampered = certreq.to_der().unwrap();

        let req = LeafRequestFromCsr {
            csr: tampered,
            scope: scope(),
        };
        let err = issue_leaf_from_csr(
            &leaf_only,
            &key(),
            &root,
            &req,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .unwrap_err();
        assert_eq!(err, IssueError::CsrProofOfPossession);
        assert!(
            !leaf_only.was_signed(),
            "a bad CSR must be refused before signing"
        );
    }

    #[test]
    fn requested_extensions_do_not_shape_the_certificate() {
        let backend = MockSigner::ecdsa_sha256(key());
        let root = root_ca(&backend);
        let org = org_ca(&backend, &root);

        let signing_key = p256::ecdsa::SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        // The CSR asks to be a CA (basicConstraints cA=TRUE).
        let csr_der = p256_csr(&signing_key, "CN=ivanov", attributes_requesting_ca());

        // The advisory helper surfaces the request...
        let csr = Csr::parse(&csr_der).unwrap();
        assert!(
            csr.requested_extensions()
                .iter()
                .any(|e| e.oid == BASIC_CONSTRAINTS_OID),
            "the requested basicConstraints is surfaced for prefill"
        );

        // ...but the issued leaf is a leaf: cA=FALSE, the operator's scope only.
        let req = LeafRequestFromCsr {
            csr: csr_der,
            scope: scope(),
        };
        let issued = issue_leaf_from_csr(
            &backend,
            &key(),
            &org,
            &req,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .expect("CSR leaf issues");

        let basic = extract_basic_constraints(&issued.der).unwrap().unwrap();
        assert!(
            !basic.ca,
            "the CSR asked for cA=TRUE, but the issued leaf is not a CA"
        );
    }
}

/// Issuance-journal scenarios: a successful issuance is recorded before the
/// artifact is released, a journal that cannot be written fails the issuance
/// closed, a tampered record breaks the chain at a reported position, and a
/// tail added after a head signature is reported intact-but-unsigned.
mod journal {
    use super::{envelope, key, leaf_request, spki_fixture, validity, CaRequest, MockSigner, TS};
    use crate::test_support::{self_signed_ca, FailingStorage, MemoryStorage};
    use crate::{issue_leaf, verify_lines, IssueError, Journal, JournalStatus, Serial};

    /// A root [`CaRequest`] allowing `oper`, integrity ≤ 5, TTL ≤ 86400.
    fn root_req() -> CaRequest {
        CaRequest {
            subject: "CN=Tessera Root".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(9_000_000),
            constraints: envelope(&["oper"], 5, 86_400),
            profile_version: 1,
        }
    }

    #[test]
    fn successful_issuance_is_recorded() {
        let backend = MockSigner::ecdsa_sha256(key());
        let mut journal = Journal::load(MemoryStorage::new()).unwrap();

        let root = self_signed_ca(
            &backend,
            &key(),
            &root_req(),
            &Serial::generate(),
            &mut journal,
            TS,
        )
        .unwrap();
        let leaf = issue_leaf(
            &backend,
            &key(),
            &root.der,
            &leaf_request(),
            &Serial::generate(),
            &mut journal,
            TS,
        )
        .unwrap();

        let lines = journal.storage().lines();
        assert_eq!(lines.len(), 2, "the root and the leaf are both recorded");
        // The leaf line names the issued serial (hex), before the artifact is used.
        let leaf_serial_hex = hex::encode(&leaf.serial);
        assert!(
            lines[1].contains(&leaf_serial_hex) && lines[1].contains("issue_leaf"),
            "the leaf record carries its serial and op"
        );
        // No secret ever appears in a record.
        assert!(!lines.iter().any(|line| line.contains("PIN")));
        // The chain is structurally intact; with no head signature yet, the
        // whole thing is an unsigned tail from the first record.
        assert_eq!(
            journal.verify().unwrap().status,
            JournalStatus::IntactUnsignedTail {
                unsigned_from_seq: 0
            }
        );
    }

    #[test]
    fn journal_write_failure_fails_closed() {
        // A valid parent, built with a working journal.
        let backend = MockSigner::ecdsa_sha256(key());
        let mut working = Journal::load(MemoryStorage::new()).unwrap();
        let root = self_signed_ca(
            &backend,
            &key(),
            &root_req(),
            &Serial::generate(),
            &mut working,
            TS,
        )
        .unwrap();

        // The leaf's journal cannot be written: the issuance must fail and yield
        // no artifact.
        let mut failing = Journal::load(FailingStorage).unwrap();
        let err = issue_leaf(
            &backend,
            &key(),
            &root.der,
            &leaf_request(),
            &Serial::generate(),
            &mut failing,
            TS,
        )
        .unwrap_err();
        assert!(
            matches!(err, IssueError::Journal(_)),
            "a failed journal write withholds the artifact: {err:?}"
        );
    }

    #[test]
    fn tampered_record_breaks_chain_at_position() {
        let backend = MockSigner::ecdsa_sha256(key());
        let mut journal = Journal::load(MemoryStorage::new()).unwrap();
        let root = self_signed_ca(
            &backend,
            &key(),
            &root_req(),
            &Serial::generate(),
            &mut journal,
            TS,
        )
        .unwrap();
        for _ in 0..2 {
            issue_leaf(
                &backend,
                &key(),
                &root.der,
                &leaf_request(),
                &Serial::generate(),
                &mut journal,
                TS,
            )
            .unwrap();
        }

        let mut lines = journal.storage().lines();
        assert_eq!(lines.len(), 3);
        // Rewrite the timestamp of the middle record: the bytes change, so its
        // own hash no longer matches the next line's prev_hash.
        lines[1] = lines[1].replace("\"ts\":1600000000", "\"ts\":1600000001");
        let report = verify_lines(&lines);
        assert_eq!(report.status, JournalStatus::Broken { position: 2 });
    }

    #[test]
    fn reordered_records_break_chain() {
        let backend = MockSigner::ecdsa_sha256(key());
        let mut journal = Journal::load(MemoryStorage::new()).unwrap();
        let root = self_signed_ca(
            &backend,
            &key(),
            &root_req(),
            &Serial::generate(),
            &mut journal,
            TS,
        )
        .unwrap();
        for _ in 0..2 {
            issue_leaf(
                &backend,
                &key(),
                &root.der,
                &leaf_request(),
                &Serial::generate(),
                &mut journal,
                TS,
            )
            .unwrap();
        }

        let mut lines = journal.storage().lines();
        lines.swap(1, 2);
        // The swapped line at position 1 no longer carries seq 1.
        assert_eq!(
            verify_lines(&lines).status,
            JournalStatus::Broken { position: 1 }
        );
    }

    #[test]
    fn tail_after_head_signature_is_intact_but_unsigned() {
        let backend = MockSigner::ecdsa_sha256(key());
        let mut journal = Journal::load(MemoryStorage::new()).unwrap();
        let root = self_signed_ca(
            &backend,
            &key(),
            &root_req(),
            &Serial::generate(),
            &mut journal,
            TS,
        )
        .unwrap();

        // Signing the head with no records after it: the chain is fully covered.
        journal.sign_head(&backend, &key(), TS).unwrap();
        let signed = journal.verify().unwrap();
        assert_eq!(signed.status, JournalStatus::Intact);
        assert_eq!(signed.last_signed_seq, Some(1));

        // A record after the last signature: intact chain, but an unsigned tail.
        issue_leaf(
            &backend,
            &key(),
            &root.der,
            &leaf_request(),
            &Serial::generate(),
            &mut journal,
            TS,
        )
        .unwrap();
        let report = journal.verify().unwrap();
        assert_eq!(
            report.status,
            JournalStatus::IntactUnsignedTail {
                unsigned_from_seq: 2
            }
        );
        assert_eq!(report.last_signed_seq, Some(1));
    }
}

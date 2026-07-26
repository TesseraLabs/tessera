//! Cross-crate usability check: a chain issued with the issuer's *default*
//! delegation envelopes is accepted by the Engine's own enforcement.
//!
//! The delegation envelope is a set of closed dimensions: `allowRoles` is a
//! whitelist, `maxTtl` a ceiling on the child link's lifetime. A dimension that
//! admits no value at all (an empty role list, a zero ceiling) yields a
//! certificate that is structurally valid, lands in the issuance journal, and
//! then fails every login. Nothing in issuance notices; the operator finds out
//! on the device, where the diagnosis points at the trust chain rather than at
//! the issuing command.
//!
//! This suite closes that gap from the verification side: it builds a
//! root → organisation CA → shift leaf through the real `tessera_issuer` entry
//! points using the values the CLI supplies when the operator names only the
//! mandatory arguments, then runs the result through
//! [`enforce_delegation`] — the very function the Engine calls during
//! authentication. If the defaults ever drift away from what enforcement
//! considers usable, this test fails at build time instead of at login time.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tessera_core::role::RoleId;
use tessera_core::tags::DeviceTags;
use tessera_core::trust::delegation::enforce_delegation;
use tessera_core::x509::Certificate;

use tessera_ext::delegation::DelegationConstraints;
use tessera_issuer::sign::{KeyId, MockSigner};
use tessera_issuer::test_support::{spki_fixture, MemoryStorage};
use tessera_issuer::{
    issue_ca, issue_leaf, issue_root, CaRequest, Journal, LeafRequest, RootRequest, Serial,
    Validity,
};

/// Mirrors the `issuer issue-root --max-ttl` default: the root's envelope
/// bounds the lifetime of the organisation CA beneath it.
const ROOT_MAX_TTL_SECS: u64 = 31_536_000;

/// Mirrors the `issuer issue-ca --max-ttl` default: this envelope bounds the
/// shift leaf beneath it.
const ORG_CA_MAX_TTL_SECS: u64 = 14_400;

/// Mirrors the `--max-level` default of both issuing subcommands.
const DEFAULT_MAX_LEVEL: i8 = 0;

/// The one role the operator names on the command line. Its concrete spelling
/// is irrelevant — what matters is that the same name is enforceable later.
const NAMED_ROLE: &str = "oper";

/// Fixed issuance clock (Unix seconds) for the journal entries this suite mints.
const NOW_UNIX: u64 = 1_700_000_000;

/// Validity starting at a fixed instant and lasting `secs`.
fn validity(secs: u64) -> Validity {
    Validity {
        not_before: 1_600_000_000,
        not_after: 1_600_000_000 + secs,
    }
}

/// The envelope the CLI builds when the operator names one role and leaves
/// every ceiling at its default.
fn default_envelope(max_ttl: u64) -> DelegationConstraints {
    DelegationConstraints {
        require_tags: vec![],
        allow_roles: vec![NAMED_ROLE.to_owned()],
        max_level: DEFAULT_MAX_LEVEL,
        max_ttl,
    }
}

#[test]
fn a_chain_issued_with_default_envelopes_passes_engine_enforcement() {
    let key = KeyId::new("usability-ca");
    let signer = MockSigner::ecdsa_sha256(key.clone());
    let mut journal = Journal::load(MemoryStorage::new()).unwrap();

    // Nothing above the root constrains its own lifetime, so it may outlive the
    // ceiling it imposes on its children.
    let root = issue_root(
        &signer,
        &key,
        &RootRequest {
            subject: "CN=Tessera Root,O=Tessera Labs".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(10 * ROOT_MAX_TTL_SECS),
            constraints: default_envelope(ROOT_MAX_TTL_SECS),
            profile_version: 0,
        },
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .expect("a root with the CLI's default envelope is issuable")
    .der;

    // The organisation CA lives exactly up to the root's ceiling — the boundary
    // case, so a ceiling that is off by any amount would be caught here.
    let org = issue_ca(
        &signer,
        &key,
        &root,
        &CaRequest {
            subject: "CN=Org CA,O=Some Org".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(ROOT_MAX_TTL_SECS),
            constraints: default_envelope(ORG_CA_MAX_TTL_SECS),
            profile_version: 0,
        },
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .expect("an organisation CA with the CLI's default envelope is issuable")
    .der;

    // Likewise the shift leaf sits exactly on the organisation CA's ceiling.
    let leaf = issue_leaf(
        &signer,
        &key,
        &org,
        &LeafRequest {
            subject: "CN=ivanov,O=Some Org".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: validity(ORG_CA_MAX_TTL_SECS),
            host_binding: vec!["*".to_owned()],
            user_binding: vec!["ivanov".to_owned()],
            allowed_roles: vec![NAMED_ROLE.to_owned()],
            max_integrity: None,
            profile_version: 0,
        },
        &Serial::generate(),
        &mut journal,
        NOW_UNIX,
    )
    .expect("a shift leaf under the default envelope is issuable")
    .der;

    // Leaf → anchor, the ordering the Engine's chain builder produces.
    let chain = [
        Certificate::from_der(&leaf).unwrap(),
        Certificate::from_der(&org).unwrap(),
        Certificate::from_der(&root).unwrap(),
    ];
    let role = RoleId::new(NAMED_ROLE).unwrap();

    enforce_delegation(
        &chain,
        &DeviceTags::empty(),
        &role,
        DEFAULT_MAX_LEVEL,
        None,
        Some(std::slice::from_ref(&role)),
    )
    .expect("the role named at issuance is the role enforcement admits");
}

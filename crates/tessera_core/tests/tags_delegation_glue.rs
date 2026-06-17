//! Glue test for tags-delegation §5: load this device's tags from the
//! configured `[tags]` standalone source, then run the live envelope
//! enforcement (`enforce_delegation_opt`) against a chain whose CA carries
//! `requireTags{region:north}`.
//!
//! Proves the wired path end-to-end at the config→load→enforce boundary:
//! a device whose loaded tags are `region:south` is rejected, and a device
//! whose loaded tags are `region:north` is admitted. Requires `mac-tests` for
//! the raw-DER `delegation_constraints` cert builder:
//!
//! ```bash
//! cargo test -p tessera_core --features mac-tests --test tags_delegation_glue
//! ```

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::panic_in_result_fn)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

use tessera_core::config::validated::{TagsMode, TagsSection};
use tessera_core::role::RoleId;
use tessera_core::tags::{load_standalone_optional, DeviceTags};
use tessera_core::trust::{chain_carries_constraints, enforce_delegation_opt, DelegationError};
use tessera_core::x509::oids::DELEGATION_CONSTRAINTS_OID;
use tessera_core::x509::Certificate;

// ---- minimal DER helpers (mirrors delegation_enforce.rs) -------------------

const TAG_SEQUENCE: u8 = 0x30;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_INTEGER: u8 = 0x02;

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 0x80, "short-form only");
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(tag);
    out.push(u8::try_from(body.len()).unwrap());
    out.extend_from_slice(body);
    out
}
fn utf8(s: &str) -> Vec<u8> {
    tlv(TAG_UTF8_STRING, s.as_bytes())
}
fn int_i8(v: i8) -> Vec<u8> {
    tlv(TAG_INTEGER, &v.to_be_bytes())
}
fn int_u32(v: u32) -> Vec<u8> {
    let mut be = v.to_be_bytes().to_vec();
    while be.len() > 1 && be[0] == 0 {
        be.remove(0);
    }
    if be[0] & 0x80 != 0 {
        be.insert(0, 0x00);
    }
    tlv(TAG_INTEGER, &be)
}
fn require_tags(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut inner = Vec::new();
    for (k, v) in pairs {
        let mut pair = utf8(k);
        pair.extend_from_slice(&utf8(v));
        inner.extend_from_slice(&tlv(TAG_SEQUENCE, &pair));
    }
    tlv(TAG_SEQUENCE, &inner)
}
fn allow_roles(roles: &[&str]) -> Vec<u8> {
    let mut inner = Vec::new();
    for r in roles {
        inner.extend_from_slice(&utf8(r));
    }
    tlv(TAG_SEQUENCE, &inner)
}
fn constraints(tags: &[(&str, &str)], roles: &[&str], max_level: i8, max_ttl: u32) -> Vec<u8> {
    let mut body = require_tags(tags);
    body.extend_from_slice(&allow_roles(roles));
    body.extend_from_slice(&int_i8(max_level));
    body.extend_from_slice(&int_u32(max_ttl));
    tlv(TAG_SEQUENCE, &body)
}

fn build_cert(is_ca: bool, constraints_der: Option<&[u8]>) -> Certificate {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_text("CN", "t").unwrap();
    let name = nb.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    if is_ca {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    } else {
        b.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    }
    if let Some(der) = constraints_der {
        let oid = Asn1Object::from_str(DELEGATION_CONSTRAINTS_OID).unwrap();
        let octet = Asn1OctetString::new_from_bytes(der).unwrap();
        let ext = X509Extension::new_from_der(&oid, true, &octet).unwrap();
        b.append_extension(ext).unwrap();
    }
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    Certificate::from_der(&b.build().to_der().unwrap()).unwrap()
}

/// Write a standalone tags file and return a [`TagsSection`] pointing at it,
/// mirroring what `validate_tags` produces and what `build_device_tags` reads.
fn tags_section_for(dir: &std::path::Path, region: &str) -> (TagsSection, std::path::PathBuf) {
    let path = dir.join("tags.toml");
    std::fs::write(&path, format!("[tags]\nregion = \"{region}\"\n").as_bytes()).unwrap();
    (
        TagsSection {
            enforce: true,
            mode: TagsMode::Standalone,
            source: path.clone(),
        },
        path,
    )
}

/// The flow glue, replayed in-test: load the device tags from the configured
/// standalone source, then enforce the chain envelope with the loaded tags.
fn load_and_enforce(
    tags_cfg: &TagsSection,
    chain: &[Certificate],
    requested_role: Option<&RoleId>,
) -> Result<(), DelegationError> {
    // `build_device_tags` (entry.rs) for the standalone path resolves to
    // exactly this: read the configured source, empty set if absent.
    assert!(tags_cfg.enforce, "test drives the enforce = true path");
    assert_eq!(tags_cfg.mode, TagsMode::Standalone);
    let device_tags: DeviceTags = load_standalone_optional(&tags_cfg.source).unwrap();
    enforce_delegation_opt(chain, &device_tags, requested_role, 0, None, None)
}

#[test]
fn north_ca_admits_north_device_and_rejects_south_device() {
    // CA requires region:north; leaf is the authenticating engineer cert.
    let cons = constraints(&[("region", "north")], &["oper"], 10, 315_360_000);
    let leaf = build_cert(false, None);
    let ca = build_cert(true, Some(&cons));
    let chain = vec![leaf, ca];
    let oper = RoleId::new("oper").unwrap();

    // South device → loaded tags region:south → rejected (fail-closed).
    let south_dir = tempfile::tempdir().unwrap();
    let (south_cfg, _p) = tags_section_for(south_dir.path(), "south");
    let err = load_and_enforce(&south_cfg, &chain, Some(&oper))
        .expect_err("south device must be rejected by the north envelope");
    assert!(
        matches!(err, DelegationError::TagEnvelope { .. }),
        "expected TagEnvelope, got {err:?}"
    );

    // North device → loaded tags region:north → admitted.
    let north_dir = tempfile::tempdir().unwrap();
    let (north_cfg, _p) = tags_section_for(north_dir.path(), "north");
    load_and_enforce(&north_cfg, &chain, Some(&oper))
        .expect("north device must satisfy the north envelope");
}

#[test]
fn no_tags_source_rejects_envelope_but_passes_per_host_chain() {
    let oper = RoleId::new("oper").unwrap();

    // Envelope-scoped chain + no [tags] source (enforce = false → empty set).
    let cons = constraints(&[("region", "north")], &["oper"], 10, 315_360_000);
    let leaf = build_cert(false, None);
    let ca = build_cert(true, Some(&cons));
    let scoped = vec![leaf, ca];
    let empty = DeviceTags::empty();
    let err = enforce_delegation_opt(&scoped, &empty, Some(&oper), 0, None, None)
        .expect_err("no tags + envelope must reject (fail-closed)");
    assert!(
        matches!(err, DelegationError::TagEnvelope { .. }),
        "got {err:?}"
    );

    // Per-host chain (no constraints) + no tags → unaffected.
    let leaf2 = build_cert(false, None);
    let ca2 = build_cert(true, None);
    let per_host = vec![leaf2, ca2];
    enforce_delegation_opt(&per_host, &empty, Some(&oper), 0, None, None)
        .expect("per-host chain without an envelope is unaffected by empty tags");
}

#[test]
fn envelope_chain_with_no_requested_role_rejects() {
    // No role selected + an envelope-scoped chain → fail-closed.
    let cons = constraints(&[("region", "north")], &["oper"], 10, 315_360_000);
    let leaf = build_cert(false, None);
    let ca = build_cert(true, Some(&cons));
    let chain = vec![leaf, ca];

    let north_dir = tempfile::tempdir().unwrap();
    let (north_cfg, _p) = tags_section_for(north_dir.path(), "north");
    let err = load_and_enforce(&north_cfg, &chain, None)
        .expect_err("an envelope chain with no role must reject");
    assert!(
        matches!(err, DelegationError::RoleNotAllowed { .. }),
        "expected RoleNotAllowed, got {err:?}"
    );
}

#[test]
fn chain_carries_constraints_detects_envelope() {
    // Envelope-scoped chain (CA carries delegation_constraints) → true.
    let cons = constraints(&[("region", "north")], &["oper"], 10, 315_360_000);
    let leaf = build_cert(false, None);
    let ca = build_cert(true, Some(&cons));
    assert!(chain_carries_constraints(&[leaf, ca]).unwrap());

    // Per-host chain (no constraints anywhere) → false. This is the predicate
    // the flow uses to decide whether the leaf max_integrity ceiling must be
    // fail-closed on a malformed extension.
    let leaf2 = build_cert(false, None);
    let ca2 = build_cert(true, None);
    assert!(!chain_carries_constraints(&[leaf2, ca2]).unwrap());
}

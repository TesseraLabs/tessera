//! Tests for [`tessera_core::trust::delegation::enforce_delegation`] — the
//! delegation envelope (4.2), role/level/TTL ceilings (4.3), and wildcard
//! group-scoping (4.4) of the `trust-chain-validation` delta spec.
//!
//! Synthetic multi-cert chains (root → CA → leaf) are built in-memory with
//! custom critical extensions added via raw DER, mirroring
//! `delegation_constraints_ext_parse.rs`.  Requires the `mac-tests` feature:
//!
//! ```bash
//! cargo test -p tessera_core --features mac-tests --test delegation_enforce
//! ```

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(missing_docs)]

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};
use tessera_core::role::RoleId;
use tessera_core::tags::DeviceTags;
use tessera_core::trust::delegation::{enforce_delegation, DelegationError};
use tessera_core::x509::oids::DELEGATION_CONSTRAINTS_OID;
use tessera_core::x509::Certificate;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_INTEGER: u8 = 0x02;

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 0x80, "test helper supports short-form only");
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

/// DER INTEGER for a non-negative seconds value: minimal big-endian with a
/// leading `0x00` when the high bit would otherwise make it look negative.
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

/// Full `delegation_constraints` extnValue.
fn constraints(tags: &[(&str, &str)], roles: &[&str], max_level: i8, max_ttl: u32) -> Vec<u8> {
    let mut body = require_tags(tags);
    body.extend_from_slice(&allow_roles(roles));
    body.extend_from_slice(&int_i8(max_level));
    body.extend_from_slice(&int_u32(max_ttl));
    tlv(TAG_SEQUENCE, &body)
}

/// Build a self-signed cert.  `is_ca` sets basicConstraints/keyUsage; if
/// `constraints_der` is `Some`, a critical `delegation_constraints` extension
/// is added.  `validity_days` sets the (notAfter − notBefore) span in days.
fn build_cert(is_ca: bool, constraints_der: Option<&[u8]>, validity_days: u32) -> Certificate {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_text("CN", "t").unwrap();
    let name = nb.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&serial).unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(validity_days).unwrap())
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

fn tags(pairs: &[(&str, &str)]) -> DeviceTags {
    DeviceTags::from_pairs(pairs.iter().map(|(k, v)| (*k, *v))).unwrap()
}

fn role(s: &str) -> RoleId {
    RoleId::new(s).unwrap()
}

// Reasonable default validity for non-TTL-focused tests (1 year).
const DAYS: u32 = 365;
// A maxTtl ceiling (seconds) large enough that 365-day leaves pass it.
// 10 years, comfortably above any 365-day leaf lifetime.
const BIG_TTL: u32 = 315_360_000;

// ---- 4.2 envelope -----------------------------------------------------------

#[test]
fn chain_without_constraints_passes() {
    // No delegation_constraints anywhere → no envelope; prior semantics.
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, None, DAYS);
    let chain = vec![leaf, ca];
    enforce_delegation(&chain, &tags(&[]), &role("oper"), 0, None, None)
        .expect("no constraints → no envelope");
}

#[test]
fn device_tags_satisfy_envelope() {
    let cons = constraints(&[("region", "north")], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    enforce_delegation(
        &chain,
        &tags(&[("region", "north")]),
        &role("oper"),
        0,
        None,
        None,
    )
    .expect("matching device tags satisfy envelope");
}

#[test]
fn device_tags_violate_envelope_rejected() {
    // scenario "Теги устройства не удовлетворяют конверту".
    let cons = constraints(&[("region", "north")], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    let err = enforce_delegation(
        &chain,
        &tags(&[("region", "south")]),
        &role("oper"),
        0,
        None,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, DelegationError::TagEnvelope { .. }),
        "{err:?}"
    );
}

#[test]
fn no_device_tags_with_nonempty_require_rejected() {
    let cons = constraints(&[("region", "north")], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    let err = enforce_delegation(&chain, &tags(&[]), &role("oper"), 0, None, None).unwrap_err();
    assert!(
        matches!(err, DelegationError::TagEnvelope { .. }),
        "{err:?}"
    );
}

#[test]
fn misissued_wider_child_ca_does_not_escape_parent() {
    // scenario "Дочерний CA шире родителя": parent requireTags{region:north},
    // child CA empty requireTags → device region:south still rejected (AND).
    // chain layout: leaf(0) → childCA(1, empty) → parentCA(2, north) → ...
    let child_cons = constraints(&[], &["oper"], 10, BIG_TTL);
    let parent_cons = constraints(&[("region", "north")], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let child_ca = build_cert(true, Some(&child_cons), DAYS);
    let parent_ca = build_cert(true, Some(&parent_cons), DAYS);
    let chain = vec![leaf, child_ca, parent_ca];
    let err = enforce_delegation(
        &chain,
        &tags(&[("region", "south")]),
        &role("oper"),
        0,
        None,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, DelegationError::TagEnvelope { .. }),
        "{err:?}"
    );
}

// ---- 4.3 ceilings -----------------------------------------------------------

#[test]
fn requested_role_not_in_allow_roles_rejected() {
    // scenario "Запрошенная роль вне allowRoles CA".
    let cons = constraints(&[], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    let err = enforce_delegation(&chain, &tags(&[]), &role("serv"), 0, None, None).unwrap_err();
    assert!(
        matches!(err, DelegationError::RoleNotAllowed { .. }),
        "{err:?}"
    );
}

#[test]
fn requested_role_must_be_in_every_ca() {
    // AND across CAs: role in child but not parent → reject.
    let child_cons = constraints(&[], &["oper", "serv"], 10, BIG_TTL);
    let parent_cons = constraints(&[], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let child_ca = build_cert(true, Some(&child_cons), DAYS);
    let parent_ca = build_cert(true, Some(&parent_cons), DAYS);
    let chain = vec![leaf, child_ca, parent_ca];
    let err = enforce_delegation(&chain, &tags(&[]), &role("serv"), 0, None, None).unwrap_err();
    assert!(
        matches!(err, DelegationError::RoleNotAllowed { .. }),
        "{err:?}"
    );
}

#[test]
fn requested_role_not_in_leaf_allowed_roles_rejected() {
    let cons = constraints(&[], &["oper", "serv"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    // Leaf allowed-roles present and does NOT include the requested role.
    let leaf_allowed = vec![role("oper")];
    let err = enforce_delegation(
        &chain,
        &tags(&[]),
        &role("serv"),
        0,
        None,
        Some(&leaf_allowed),
    )
    .unwrap_err();
    assert!(
        matches!(err, DelegationError::RoleNotAllowed { .. }),
        "{err:?}"
    );
}

#[test]
fn requested_level_above_ca_max_rejected() {
    // scenario "уровень > maxLevel".
    let cons = constraints(&[], &["oper"], 5, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    let err = enforce_delegation(&chain, &tags(&[]), &role("oper"), 6, None, None).unwrap_err();
    assert!(
        matches!(err, DelegationError::LevelCeiling { .. }),
        "{err:?}"
    );
}

#[test]
fn requested_level_above_leaf_max_integrity_rejected() {
    let cons = constraints(&[], &["oper"], 50, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    // Leaf max_integrity ceiling = 3; request level 4 → reject.
    let err = enforce_delegation(&chain, &tags(&[]), &role("oper"), 4, Some(3), None).unwrap_err();
    assert!(
        matches!(err, DelegationError::LevelCeiling { .. }),
        "{err:?}"
    );
}

#[test]
fn level_within_all_ceilings_passes() {
    let cons = constraints(&[], &["oper"], 5, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    enforce_delegation(&chain, &tags(&[]), &role("oper"), 5, Some(5), None)
        .expect("level at ceiling passes");
}

#[test]
fn link_lifetime_exceeds_parent_max_ttl_rejected() {
    // scenario "Срок звена превышает maxTtl родителя": leaf valid 10 days,
    // parent CA maxTtl = 5 seconds → 10-day leaf lifetime exceeds it.
    let cons = constraints(&[], &["oper"], 10, 5);
    let leaf = build_cert(false, None, 10);
    let ca = build_cert(true, Some(&cons), 30);
    let chain = vec![leaf, ca];
    let err = enforce_delegation(&chain, &tags(&[]), &role("oper"), 0, None, None).unwrap_err();
    assert!(matches!(err, DelegationError::TtlCeiling { .. }), "{err:?}");
}

// ---- 4.4 wildcard under envelope -------------------------------------------

#[test]
fn wildcard_leaf_under_north_ca_rejects_south_device() {
    // scenario "Wildcard-лист под северным CA на южном устройстве".
    // The wildcard host_binding semantics live in pam_tessera; here we assert
    // that the envelope alone rejects a non-matching device regardless of the
    // leaf's host_binding — the leaf carries no constraints (rules inherited).
    let cons = constraints(&[("region", "north")], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    let err = enforce_delegation(
        &chain,
        &tags(&[("region", "south")]),
        &role("oper"),
        0,
        None,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, DelegationError::TagEnvelope { .. }),
        "{err:?}"
    );
}

#[test]
fn wildcard_leaf_under_north_ca_passes_north_device() {
    let cons = constraints(&[("region", "north")], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];
    enforce_delegation(
        &chain,
        &tags(&[("region", "north")]),
        &role("oper"),
        0,
        None,
        None,
    )
    .expect("north device satisfies the envelope");
}

#[test]
fn canonical_north_ca_wildcard_leaf_end_to_end() {
    // Task 7.2 canonical chain: root → CA(requireTags{region:north}, allowRoles
    // {oper}, maxLevel, maxTtl) → wildcard leaf (leaf carries no constraints;
    // the host_binding=* semantics live in pam_tessera, the group scoping is
    // the envelope enforced here). A region:north device passes; region:south
    // is rejected by the envelope despite the wildcard. The chain is built once
    // and `enforce_delegation` is exercised for both devices.
    let cons = constraints(&[("region", "north")], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, None, DAYS);
    let ca = build_cert(true, Some(&cons), DAYS);
    let chain = vec![leaf, ca];

    enforce_delegation(
        &chain,
        &tags(&[("region", "north")]),
        &role("oper"),
        0,
        None,
        None,
    )
    .expect("north device satisfies the canonical envelope");

    let err = enforce_delegation(
        &chain,
        &tags(&[("region", "south")]),
        &role("oper"),
        0,
        None,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, DelegationError::TagEnvelope { .. }),
        "{err:?}"
    );
}

#[test]
fn delegation_constraints_on_leaf_rejected() {
    // A constraints extension on a CA=FALSE leaf is malformed → reject.
    let cons = constraints(&[], &["oper"], 10, BIG_TTL);
    let leaf = build_cert(false, Some(&cons), DAYS);
    let ca = build_cert(true, None, DAYS);
    let chain = vec![leaf, ca];
    let err = enforce_delegation(&chain, &tags(&[]), &role("oper"), 0, None, None).unwrap_err();
    assert!(matches!(err, DelegationError::Malformed { .. }), "{err:?}");
}

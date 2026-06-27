//! Section 5 integration tests for the `device-enrollment` change (5.2 + 5.3).
//!
//! These prove the full enrollment flow end-to-end across three crate modules,
//! exactly as a real device would experience it after `clone-image-bootstrap`
//! flips it to its per-host identity:
//!
//! 1. **import** ([`tessera_core::enrollment`]) installs an enrollment package
//!    (managed signed manifest, or standalone FS-perms) onto a tempdir-rooted
//!    set of device paths;
//! 2. **trusted tags source** ([`tessera_core::tags::source`]) reads the device
//!    tags back from the SAME path the import wrote — proving the imported tags
//!    are the trusted source, not an arbitrary local config;
//! 3. **delegation enforcement** ([`tessera_core::trust::enforce_delegation`])
//!    runs a login-style check of the LOADED device tags against a synthetic
//!    root→CA(`requireTags{region:north}`)→leaf chain.
//!
//! The cert builder mirrors `tests/tags_delegation_glue.rs` /
//! `tests/delegation_enforce.rs` (raw-DER `delegation_constraints` extension),
//! so this file is gated on `mac-tests` like those. The enrollment-package
//! builders mirror the `#[cfg(test)]`-private helpers in
//! `src/enrollment/import_tests.rs`; they are replicated here (minimally)
//! because that module's helpers are not reachable from a separate
//! integration-test binary, and no production visibility was changed for tests.
//!
//! ```bash
//! cargo test -p tessera_core --features mac-tests --test enrollment_integration
//! ```

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::panic_in_result_fn)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::let_underscore_must_use)]
#![allow(missing_docs)]

use std::fmt::Write as _;
use std::fs;

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use tessera_core::enrollment::{EnrollmentPackage, ImportError, ImportMode, InstallPaths};
use tessera_core::role::manifest::MANIFEST_FILENAME;
use tessera_core::role::{ManifestError, RoleId, RoleOs};
use tessera_core::tags::{self, DeviceTags};
use tessera_core::trust::{enforce_delegation, DelegationError};
use tessera_core::x509::oids::DELEGATION_CONSTRAINTS_OID;
use tessera_core::x509::Certificate;

// ===========================================================================
// Enrollment-package builders — replicated from the `#[cfg(test)]`-private
// helpers in `src/enrollment/import_tests.rs` (unreachable from this separate
// test binary). Kept byte-for-byte compatible with the signing, manifest
// layout, CRL pin, and `.p12` placement that the import core expects.
// ===========================================================================

/// An Ed25519 keypair with the public key exported as PEM (manifest signing).
struct TestKey {
    pkey: PKey<openssl::pkey::Private>,
    pub_pem: Vec<u8>,
}

fn gen_key() -> TestKey {
    let pkey = PKey::generate_ed25519().unwrap();
    let pub_pem = pkey.public_key_to_pem().unwrap();
    TestKey { pkey, pub_pem }
}

fn sign(key: &TestKey, payload: &[u8]) -> String {
    let mut signer = Signer::new_without_digest(&key.pkey).unwrap();
    let sig = signer.sign_oneshot_to_vec(payload).unwrap();
    hex::encode(sig)
}

fn slice_doc(role: &str, version: u32) -> String {
    format!(
        "role = \"{role}\"\nversion = {version}\nos = \"linux\"\nname = \"{role}\"\nlevel = 1\n"
    )
}

/// The opaque per-host `.p12` bytes every test package ships (never decrypted).
const P12_OPAQUE: &[u8] = b"\x30\x82PKCS12-OPAQUE";

/// Install paths rooted at a fresh tempdir (so tests never touch real device
/// paths). Mirrors `import_tests::install_paths`.
fn install_paths(root: &TempDir) -> InstallPaths {
    let base = root.path();
    InstallPaths {
        roles_dir: base.join("roles"),
        tags_file: base.join("tags.toml"),
        crl_path: base.join("device.crl"),
        p12_path: base.join("host.p12"),
        persist_dir: base.join("persist"),
    }
}

/// Build a MANAGED enrollment package directory: a signed `manifest.toml`
/// carrying role pins + a `[tags]` table, the role slices, and a per-host
/// `.p12`. Returns the package `TempDir`.
fn build_managed_pkg(
    key: &TestKey,
    bundle_version: u64,
    slices: &[(&str, u32)],
    tags: &[(&str, &str)],
) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let mut roles_toml = String::new();
    for (role, version) in slices {
        let body = slice_doc(role, *version);
        fs::write(dir.path().join(format!("{role}.toml")), body.as_bytes()).unwrap();
        let sha = hex::encode(Sha256::digest(body.as_bytes()));
        let _ = write!(
            roles_toml,
            "[roles.{role}]\nversion = {version}\nsha256 = \"{sha}\"\n"
        );
    }
    let mut tags_toml = String::new();
    if !tags.is_empty() {
        tags_toml.push_str("[tags]\n");
        for (k, v) in tags {
            let _ = writeln!(tags_toml, "{k} = \"{v}\"");
        }
    }
    // The signed payload is the file minus the signature line.
    let unsigned =
        format!("bundle_version = {bundle_version}\nos = \"linux\"\n{tags_toml}{roles_toml}");
    let sig = sign(key, unsigned.as_bytes());
    let full = format!(
        "bundle_version = {bundle_version}\nos = \"linux\"\nsignature = \"{sig}\"\n{tags_toml}{roles_toml}"
    );
    fs::write(dir.path().join(MANIFEST_FILENAME), full.as_bytes()).unwrap();
    fs::write(dir.path().join("host-abc123.p12"), P12_OPAQUE).unwrap();
    dir
}

/// Build a STANDALONE enrollment package directory (no signature): a plain
/// `tags.toml`, role slices under FS-perms, and a per-host `.p12`.
fn build_standalone_pkg(slices: &[(&str, u32)], tags: &[(&str, &str)]) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (role, version) in slices {
        fs::write(
            dir.path().join(format!("{role}.toml")),
            slice_doc(role, *version).as_bytes(),
        )
        .unwrap();
    }
    let mut tags_toml = String::from("[tags]\n");
    for (k, v) in tags {
        let _ = writeln!(tags_toml, "{k} = \"{v}\"");
    }
    fs::write(dir.path().join("tags.toml"), tags_toml.as_bytes()).unwrap();
    fs::write(dir.path().join("host-xyz.p12"), P12_OPAQUE).unwrap();
    dir
}

// ===========================================================================
// Synthetic CA-chain builder — mirrors `tests/tags_delegation_glue.rs`. Builds
// a leaf + CA, where the CA carries a raw-DER `delegation_constraints`
// extension with `requireTags{...}`. Returns a leaf→CA chain.
// ===========================================================================

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

/// A leaf→CA chain whose CA requires `region:north` and allows the `oper` role.
fn north_ca_chain() -> Vec<Certificate> {
    let cons = constraints(&[("region", "north")], &["oper"], 10, 315_360_000);
    let leaf = build_cert(false, None);
    let ca = build_cert(true, Some(&cons));
    vec![leaf, ca]
}

fn persisted_floor(paths: &InstallPaths) -> Option<u64> {
    let p = paths
        .persist_dir
        .join(tessera_core::role::manifest::BUNDLE_VERSION_FILENAME);
    fs::read_to_string(p)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Load the device tags the managed import wrote, via the trusted source — the
/// SAME path/verification the import used (no re-verification fork).
fn load_managed_tags(paths: &InstallPaths, key: &TestKey) -> DeviceTags {
    tags::source::load_managed(
        &paths.roles_dir,
        RoleOs::Linux,
        &key.pub_pem,
        &paths.persist_dir,
    )
    .unwrap()
}

/// Load the device tags a standalone import wrote, via the trusted file source.
fn load_standalone_tags(paths: &InstallPaths) -> DeviceTags {
    tags::source::load_standalone(&paths.tags_file).unwrap()
}

// ===========================================================================
// 5.2 — managed enrollment → trusted tags → north-CA delegation PASSES, and a
//        smaller-bundle_version re-import is REJECTED (anti-rollback).
// ===========================================================================

#[test]
fn managed_enrollment_then_north_delegation_passes() {
    // clone → flip → import a MANAGED package carrying region:north.
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(&key, 7, &[("oper", 1)], &[("region", "north")]);
    let outcome = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert_eq!(outcome.bundle_version, 7);
    assert!(outcome.baseline_established);

    // The imported tags are readable FROM THE TRUSTED device-tags source (the
    // signed manifest the import published under roles_dir).
    let device_tags = load_managed_tags(&paths, &key);
    assert_eq!(device_tags.get("region"), Some("north"));

    // A login-style delegation check under a north-CA chain PASSES on this
    // device — feeding the tags we LOADED from the imported source.
    let chain = north_ca_chain();
    let oper = RoleId::new("oper").unwrap();
    enforce_delegation(&chain, &device_tags, &oper, 0, None, None)
        .expect("north device must satisfy the north-CA envelope after managed enrollment");
}

#[test]
fn managed_smaller_bundle_version_reimport_rejected() {
    // Baseline import at version N = 10 (region:north).
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    EnrollmentPackage::parse(
        build_managed_pkg(&key, 10, &[("oper", 1)], &[("region", "north")]).path(),
        ImportMode::Managed,
    )
    .unwrap()
    .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
    .unwrap();
    assert_eq!(persisted_floor(&paths), Some(10));

    // A validly-signed but SMALLER bundle (N-1 = 9) that would flip the device
    // to region:south is rejected by the anti-rollback floor.
    let pkg9 = build_managed_pkg(&key, 9, &[("oper", 1)], &[("region", "south")]);
    let err = EnrollmentPackage::parse(pkg9.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap_err();
    assert!(
        matches!(
            err,
            ImportError::Manifest(ManifestError::Rollback {
                found: 9,
                persisted: 10
            })
        ),
        "expected anti-rollback rejection, got {err:?}"
    );

    // The floor is unchanged and the PRIOR tags (region:north) are retained on
    // the trusted source — so the device still passes the north-CA chain (the
    // rollback could not downgrade it to region:south).
    assert_eq!(persisted_floor(&paths), Some(10));
    let device_tags = load_managed_tags(&paths, &key);
    assert_eq!(device_tags.get("region"), Some("north"));

    let chain = north_ca_chain();
    let oper = RoleId::new("oper").unwrap();
    enforce_delegation(&chain, &device_tags, &oper, 0, None, None)
        .expect("retained region:north must still satisfy the north-CA envelope");
}

// ===========================================================================
// 5.3 — STANDALONE (server-less) rollout → trusted tags → delegation works.
// ===========================================================================

#[test]
fn standalone_enrollment_then_delegation_works() {
    // Server-less rollout: import a standalone package (tags file + role slices
    // under FS-perms, no signature).
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_standalone_pkg(&[("oper", 1)], &[("region", "north")]);
    let outcome = EnrollmentPackage::parse(pkg.path(), ImportMode::Standalone)
        .unwrap()
        .install(&paths, RoleOs::Linux, None)
        .unwrap();
    // Standalone never persists a signed bundle_version floor.
    assert_eq!(outcome.bundle_version, 0);
    assert!(!outcome.baseline_established);
    assert_eq!(persisted_floor(&paths), None);

    // The imported tags are readable from the trusted standalone file source.
    let device_tags = load_standalone_tags(&paths);
    assert_eq!(device_tags.get("region"), Some("north"));

    // The north-CA delegation check admits this region:north device.
    let chain = north_ca_chain();
    let oper = RoleId::new("oper").unwrap();
    enforce_delegation(&chain, &device_tags, &oper, 0, None, None)
        .expect("north device must be admitted under the north-CA chain after standalone rollout");
}

// ===========================================================================
// Negative — a device whose IMPORTED tags are region:south is REJECTED under
// the north-CA chain. Proves the imported tags actually gate the login (the
// pass results above are not vacuous).
// ===========================================================================

#[test]
fn imported_south_tags_rejected_under_north_chain() {
    // Managed import carrying region:south.
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    EnrollmentPackage::parse(
        build_managed_pkg(&key, 3, &[("oper", 1)], &[("region", "south")]).path(),
        ImportMode::Managed,
    )
    .unwrap()
    .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
    .unwrap();

    let device_tags = load_managed_tags(&paths, &key);
    assert_eq!(device_tags.get("region"), Some("south"));

    // The north-CA envelope rejects a region:south device fail-closed.
    let chain = north_ca_chain();
    let oper = RoleId::new("oper").unwrap();
    let err = enforce_delegation(&chain, &device_tags, &oper, 0, None, None)
        .expect_err("a region:south device must be rejected by the north-CA envelope");
    assert!(
        matches!(err, DelegationError::TagEnvelope { .. }),
        "expected TagEnvelope rejection, got {err:?}"
    );
}

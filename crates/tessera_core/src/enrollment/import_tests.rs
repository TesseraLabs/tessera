//! Tests for the enrollment-package import core (section 1).
//!
//! Named per the `device-enrollment` tasks:
//! - 1.1 parse + managed/standalone install + CRL pin (signature/FS-perms);
//! - 1.2 baseline anti-rollback (baseline / rollback / repeat=no-op / larger);
//! - 1.3 idempotency + atomic rollback on a mid-import failure (fail-closed);
//! - 1.4 imported tags land in the trusted `device-tags` source; a stray local
//!   file outside the trusted source is ignored.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items,
    clippy::let_underscore_must_use
)]

use super::*;
use crate::role::manifest::{BUNDLE_VERSION_FILENAME, MANIFEST_FILENAME};
use crate::role::RoleOs;
use crate::tags;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// An Ed25519 keypair with the public key exported as PEM.
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

/// Install paths rooted at a fresh tempdir (so tests never touch real device
/// paths). Returns the dir-root `TempDir` (kept alive) and the paths.
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

/// Spec for building a package directory.
struct PkgSpec<'a> {
    bundle_version: u64,
    slices: &'a [(&'a str, u32)],
    tags: &'a [(&'a str, &'a str)],
    /// CRL bytes; when `Some`, a `device.crl` is written and (managed) pinned.
    crl: Option<&'a [u8]>,
    /// When true, the managed manifest carries a `p12_sha256` pin over the
    /// shipped `.p12` bytes (L1). Ignored for standalone packages.
    p12_pin: bool,
}

/// The opaque per-host `.p12` bytes every test package ships.
const P12_OPAQUE: &[u8] = b"\x30\x82PKCS12-OPAQUE";

/// Build a MANAGED enrollment package directory and return it (`TempDir`).
fn build_managed_pkg(key: &TestKey, spec: &PkgSpec<'_>) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    // Role slices.
    let mut roles_toml = String::new();
    for (role, version) in spec.slices {
        let body = slice_doc(role, *version);
        fs::write(dir.path().join(format!("{role}.toml")), body.as_bytes()).unwrap();
        let sha = hex::encode(Sha256::digest(body.as_bytes()));
        let _ = write!(
            roles_toml,
            "[roles.{role}]\nversion = {version}\nsha256 = \"{sha}\"\n"
        );
    }
    // Tags table.
    let mut tags_toml = String::new();
    if !spec.tags.is_empty() {
        tags_toml.push_str("[tags]\n");
        for (k, v) in spec.tags {
            let _ = writeln!(tags_toml, "{k} = \"{v}\"");
        }
    }
    // CRL pin.
    let mut crl_toml = String::new();
    if let Some(crl_bytes) = spec.crl {
        fs::write(dir.path().join("device.crl"), crl_bytes).unwrap();
        let sha = hex::encode(Sha256::digest(crl_bytes));
        let _ = write!(
            crl_toml,
            "[crl]\nfile = \"device.crl\"\nsha256 = \"{sha}\"\n"
        );
    }
    // Optional top-level p12 pin (L1) — a scalar key, so it precedes any table.
    let mut p12_toml = String::new();
    if spec.p12_pin {
        let sha = hex::encode(Sha256::digest(P12_OPAQUE));
        let _ = writeln!(p12_toml, "p12_sha256 = \"{sha}\"");
    }
    let bundle_version = spec.bundle_version;
    let unsigned = format!(
        "bundle_version = {bundle_version}\nos = \"linux\"\n{p12_toml}{tags_toml}{crl_toml}{roles_toml}"
    );
    let sig = sign(key, unsigned.as_bytes());
    let full = format!(
        "bundle_version = {bundle_version}\nos = \"linux\"\nsignature = \"{sig}\"\n{p12_toml}{tags_toml}{crl_toml}{roles_toml}"
    );
    fs::write(dir.path().join(MANIFEST_FILENAME), full.as_bytes()).unwrap();
    // A per-host .p12 (opaque bytes; never decrypted by the import).
    fs::write(dir.path().join("host-abc123.p12"), P12_OPAQUE).unwrap();
    dir
}

/// Build a STANDALONE enrollment package directory (no signature).
fn build_standalone_pkg(spec: &PkgSpec<'_>) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (role, version) in spec.slices {
        fs::write(
            dir.path().join(format!("{role}.toml")),
            slice_doc(role, *version).as_bytes(),
        )
        .unwrap();
    }
    let mut tags_toml = String::from("[tags]\n");
    for (k, v) in spec.tags {
        let _ = writeln!(tags_toml, "{k} = \"{v}\"");
    }
    fs::write(dir.path().join("tags.toml"), tags_toml.as_bytes()).unwrap();
    if let Some(crl_bytes) = spec.crl {
        fs::write(dir.path().join("device.crl"), crl_bytes).unwrap();
    }
    fs::write(dir.path().join("host-xyz.p12"), b"\x30\x82PKCS12-OPAQUE").unwrap();
    dir
}

fn persisted_floor(paths: &InstallPaths) -> Option<u64> {
    let p = paths.persist_dir.join(BUNDLE_VERSION_FILENAME);
    fs::read_to_string(p)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn mode_bits(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

// ---- 1.1 parse -----------------------------------------------------------

#[test]
fn parse_managed_locates_p12_manifest_and_crl() {
    let key = gen_key();
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 1,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: Some(b"CRLBYTES"),
            p12_pin: false,
        },
    );
    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed).unwrap();
    assert_eq!(parsed.mode(), ImportMode::Managed);
    assert_eq!(parsed.p12_file(), "host-abc123.p12");
}

#[test]
fn parse_no_p12_is_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("tags.toml"), b"[tags]\n").unwrap();
    let err = EnrollmentPackage::parse(dir.path(), ImportMode::Standalone).unwrap_err();
    assert!(matches!(err, ImportError::NoP12));
}

#[test]
fn parse_multiple_p12_is_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("tags.toml"), b"[tags]\n").unwrap();
    fs::write(dir.path().join("a.p12"), b"x").unwrap();
    fs::write(dir.path().join("b.p12"), b"y").unwrap();
    let err = EnrollmentPackage::parse(dir.path(), ImportMode::Standalone).unwrap_err();
    assert!(matches!(err, ImportError::MultipleP12 { count: 2 }));
}

#[test]
fn parse_managed_missing_manifest_is_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("host.p12"), b"x").unwrap();
    let err = EnrollmentPackage::parse(dir.path(), ImportMode::Managed).unwrap_err();
    assert!(matches!(err, ImportError::NoManifest));
}

#[test]
fn parse_missing_package_dir_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    let err = EnrollmentPackage::parse(&missing, ImportMode::Managed).unwrap_err();
    assert!(matches!(err, ImportError::PackageMissing { .. }));
}

// ---- 1.1 managed install + CRL ------------------------------------------

#[test]
fn managed_import_with_valid_signature_installs_everything() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 7,
            slices: &[("oper", 1), ("serv", 2)],
            tags: &[("region", "north")],
            crl: Some(b"DEVICE-CRL-PEM"),
            p12_pin: false,
        },
    );
    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed).unwrap();
    let outcome = parsed
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert_eq!(outcome.bundle_version, 7);
    assert!(outcome.baseline_established);
    assert!(!outcome.no_op);

    // Role base swapped into roles_dir.
    assert!(paths.roles_dir.join("oper.toml").exists());
    assert!(paths.roles_dir.join("serv.toml").exists());
    // The signed manifest rode along into the role dir (tags::source reads it).
    assert!(paths.roles_dir.join(MANIFEST_FILENAME).exists());
    // CRL installed at the device path with 0644.
    assert_eq!(fs::read(&paths.crl_path).unwrap(), b"DEVICE-CRL-PEM");
    assert_eq!(mode_bits(&paths.crl_path), 0o644);
    // .p12 placed as-is, mode 0600 (key material).
    assert!(paths.p12_path.exists());
    assert_eq!(mode_bits(&paths.p12_path), 0o600);
    // Anti-rollback floor advanced to 7.
    assert_eq!(persisted_floor(&paths), Some(7));
}

#[test]
fn managed_import_broken_signature_installs_nothing() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 3,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: None,
            p12_pin: false,
        },
    );
    // Tamper with the manifest after signing.
    let mp = pkg.path().join(MANIFEST_FILENAME);
    let body = fs::read_to_string(&mp)
        .unwrap()
        .replace("region = \"north\"", "region = \"south\"");
    fs::write(&mp, body.as_bytes()).unwrap();

    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed).unwrap();
    let err = parsed
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap_err();
    assert!(matches!(
        err,
        ImportError::Manifest(crate::role::ManifestError::BadSignature)
    ));
    // Nothing installed, floor untouched.
    assert!(!paths.roles_dir.exists() || !paths.roles_dir.join("oper.toml").exists());
    assert!(!paths.crl_path.exists());
    assert_eq!(persisted_floor(&paths), None);
}

#[test]
fn managed_import_crl_hash_mismatch_installs_nothing() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 4,
            slices: &[("oper", 1)],
            tags: &[],
            crl: Some(b"ORIGINAL-CRL"),
            p12_pin: false,
        },
    );
    // Swap the CRL bytes after the manifest pinned the original hash.
    fs::write(pkg.path().join("device.crl"), b"TAMPERED-CRL").unwrap();

    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed).unwrap();
    let err = parsed
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap_err();
    assert!(matches!(err, ImportError::CrlHashMismatch));
    // Fail-closed before any persist/swap.
    assert_eq!(persisted_floor(&paths), None);
    assert!(!paths.crl_path.exists());
}

#[test]
fn managed_import_without_key_is_missing_key() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 1,
            slices: &[("oper", 1)],
            tags: &[],
            crl: None,
            p12_pin: false,
        },
    );
    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed).unwrap();
    let err = parsed.install(&paths, RoleOs::Linux, None).unwrap_err();
    assert!(matches!(err, ImportError::MissingKey));
}

// ---- 1.1 standalone install (FS-perms) ----------------------------------

#[test]
fn standalone_import_lays_out_files_under_fs_perms() {
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_standalone_pkg(&PkgSpec {
        bundle_version: 0,
        slices: &[("oper", 1)],
        tags: &[("region", "south")],
        crl: Some(b"STANDALONE-CRL"),
        p12_pin: false,
    });
    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Standalone).unwrap();
    let outcome = parsed.install(&paths, RoleOs::Linux, None).unwrap();
    assert_eq!(outcome.bundle_version, 0);
    assert!(!outcome.baseline_established);

    assert!(paths.roles_dir.join("oper.toml").exists());
    assert_eq!(mode_bits(&paths.roles_dir), 0o755);
    assert_eq!(mode_bits(&paths.roles_dir.join("oper.toml")), 0o644);
    assert_eq!(mode_bits(&paths.tags_file), 0o644);
    assert_eq!(fs::read(&paths.crl_path).unwrap(), b"STANDALONE-CRL");
    assert_eq!(mode_bits(&paths.p12_path), 0o600);
    // Standalone never persists a bundle_version floor.
    assert_eq!(persisted_floor(&paths), None);
}

// ---- 1.2 baseline anti-rollback -----------------------------------------

#[test]
fn baseline_first_import_persists_floor() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    assert_eq!(persisted_floor(&paths), None);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 5,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: None,
            p12_pin: false,
        },
    );
    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed).unwrap();
    let outcome = parsed
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert!(outcome.baseline_established);
    assert_eq!(persisted_floor(&paths), Some(5));
}

#[test]
fn rollback_smaller_version_rejected_prior_state_retained() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    // Baseline at 10 with region=north.
    let pkg10 = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 10,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: None,
            p12_pin: false,
        },
    );
    EnrollmentPackage::parse(pkg10.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert_eq!(persisted_floor(&paths), Some(10));

    // Replay a smaller, validly-signed bundle (v5) that would set region=south.
    let pkg5 = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 5,
            slices: &[("oper", 1)],
            tags: &[("region", "south")],
            crl: None,
            p12_pin: false,
        },
    );
    let err = EnrollmentPackage::parse(pkg5.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap_err();
    assert!(matches!(
        err,
        ImportError::Manifest(crate::role::ManifestError::Rollback {
            found: 5,
            persisted: 10
        })
    ));
    // Floor unchanged; prior tags (region=north) retained on the trusted source.
    assert_eq!(persisted_floor(&paths), Some(10));
    let tags = installed_managed_tags(&paths, RoleOs::Linux, &key.pub_pem).unwrap();
    assert_eq!(tags.get("region"), Some("north"));
}

#[test]
fn repeat_same_version_is_no_op() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 8,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: None,
            p12_pin: false,
        },
    );
    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed).unwrap();
    let first = parsed
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert!(!first.no_op);
    assert!(first.baseline_established);

    // Re-import the SAME manifest → no-op (idempotent).
    let second = parsed
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert!(second.no_op);
    assert_eq!(second.bundle_version, 8);
    assert_eq!(persisted_floor(&paths), Some(8));
}

#[test]
fn larger_version_applied() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    EnrollmentPackage::parse(
        build_managed_pkg(
            &key,
            &PkgSpec {
                bundle_version: 2,
                slices: &[("oper", 1)],
                tags: &[("region", "north")],
                crl: None,
                p12_pin: false,
            },
        )
        .path(),
        ImportMode::Managed,
    )
    .unwrap()
    .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
    .unwrap();
    assert_eq!(persisted_floor(&paths), Some(2));

    // A larger version with region=south is applied and advances the floor.
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 9,
            slices: &[("oper", 1)],
            tags: &[("region", "south")],
            crl: None,
            p12_pin: false,
        },
    );
    let outcome = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert!(!outcome.no_op);
    assert!(!outcome.baseline_established);
    assert_eq!(persisted_floor(&paths), Some(9));
    let tags = installed_managed_tags(&paths, RoleOs::Linux, &key.pub_pem).unwrap();
    assert_eq!(tags.get("region"), Some("south"));
}

// ---- 1.3 idempotency + atomic rollback ----------------------------------

#[test]
fn idempotent_reimport_same_manifest_no_op() {
    // Same as repeat_same_version_is_no_op but explicitly asserts the device
    // files are byte-identical after the second import (no half-write).
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 4,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: Some(b"CRL-A"),
            p12_pin: false,
        },
    );
    let parsed = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed).unwrap();
    parsed
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    let oper_before = fs::read(paths.roles_dir.join("oper.toml")).unwrap();
    let crl_before = fs::read(&paths.crl_path).unwrap();

    let second = parsed
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert!(second.no_op);
    assert_eq!(
        fs::read(paths.roles_dir.join("oper.toml")).unwrap(),
        oper_before
    );
    assert_eq!(fs::read(&paths.crl_path).unwrap(), crl_before);
}

#[test]
fn partial_import_failure_rolls_back_to_prior_state() {
    // Establish a working device (bundle 3, region=north, oper v1).
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg3 = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 3,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: Some(b"CRL-ORIGINAL"),
            p12_pin: false,
        },
    );
    EnrollmentPackage::parse(pkg3.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    let oper_before = fs::read(paths.roles_dir.join("oper.toml")).unwrap();
    let crl_before = fs::read(&paths.crl_path).unwrap();
    let floor_before = persisted_floor(&paths);

    // Build a NEWER bundle (v6) whose manifest pins a CRL that is missing from
    // the package: a mid-import validation failure AFTER staging but BEFORE
    // any device path is mutated. The device must remain in its prior state.
    let pkg6 = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 6,
            slices: &[("oper", 2)],
            tags: &[("region", "south")],
            crl: Some(b"CRL-NEW"),
            p12_pin: false,
        },
    );
    // Remove the CRL file so the signed pin cannot be satisfied → fail-closed.
    fs::remove_file(pkg6.path().join("device.crl")).unwrap();

    let err = EnrollmentPackage::parse(pkg6.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap_err();
    assert!(matches!(err, ImportError::CrlMissing { .. }));

    // Prior state fully retained: old slice, old CRL, old floor, old tags.
    assert_eq!(
        fs::read(paths.roles_dir.join("oper.toml")).unwrap(),
        oper_before
    );
    assert_eq!(fs::read(&paths.crl_path).unwrap(), crl_before);
    assert_eq!(persisted_floor(&paths), floor_before);
    let tags = installed_managed_tags(&paths, RoleOs::Linux, &key.pub_pem).unwrap();
    assert_eq!(tags.get("region"), Some("north"));
    // No leftover staged or .bak directories.
    assert!(!paths.roles_dir.with_extension("bak").exists());
    let leftover_staged: Vec<PathBuf> = fs::read_dir(root.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".staged."))
        })
        .collect();
    assert!(
        leftover_staged.is_empty(),
        "leftover staged dir: {leftover_staged:?}"
    );
}

#[test]
fn phase2_io_failure_does_not_advance_floor_or_roles() {
    // A phase-2 (CRL/.p12) I/O failure AFTER the staged role base is otherwise
    // valid must NOT leave the device half-enrolled. The invariant is: there is
    // no observable state where roles/floor advanced while the CRL or .p12 are
    // stale. Prior state must be fully retained.
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();

    // Put the single-file artefacts (CRL + .p12) under a DEDICATED directory
    // that is separate from roles_dir/persist_dir, so it can be made
    // unwritable WITHOUT also breaking the role swap or floor persist.
    let artefacts = root.path().join("artefacts");
    fs::create_dir(&artefacts).unwrap();
    let paths = InstallPaths {
        roles_dir: root.path().join("roles"),
        tags_file: root.path().join("tags.toml"),
        crl_path: artefacts.join("device.crl"),
        p12_path: artefacts.join("host.p12"),
        persist_dir: root.path().join("persist"),
    };

    // Baseline: bundle 3, region=north, oper v1, CRL-ORIGINAL.
    let pkg3 = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 3,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: Some(b"CRL-ORIGINAL"),
            p12_pin: false,
        },
    );
    EnrollmentPackage::parse(pkg3.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    let oper_before = fs::read(paths.roles_dir.join("oper.toml")).unwrap();
    let crl_before = fs::read(&paths.crl_path).unwrap();
    let p12_before = fs::read(&paths.p12_path).unwrap();
    let floor_before = persisted_floor(&paths);
    assert_eq!(floor_before, Some(3));

    // A LARGER, fully-valid bundle (v6, region=south, oper v2, CRL-NEW). The
    // signature/rollback/CRL-pin all pass; the role base stages cleanly. The
    // ONLY failure is that the artefacts dir is now read-only, so staging the
    // new CRL/.p12 hits an I/O error in phase 2.
    let pkg6 = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 6,
            slices: &[("oper", 2)],
            tags: &[("region", "south")],
            crl: Some(b"CRL-NEW"),
            p12_pin: false,
        },
    );

    // Inject the phase-2 failure structurally, not via permission bits: when the
    // CRL is published, its prior file is first moved aside to a deterministic
    // `<crl>.bak` sibling. Pre-create that sibling as a directory so the
    // `rename(device.crl -> device.crl.bak)` fails with EISDIR. Renaming a
    // regular file onto an existing directory is a filesystem structural error
    // that root cannot bypass (unlike a chmod'd dir, which root ignores), so the
    // failure fires uniformly whether or not the test runs as root. The prior
    // device.crl is left untouched (its rename never completes), and the .p12 /
    // roles / floor are never reached, so every prior-state assertion still holds.
    let crl_bak = artefacts.join("device.crl.bak");
    fs::create_dir(&crl_bak).unwrap();

    let result = EnrollmentPackage::parse(pkg6.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem));

    // The failure must be exactly the CRL-publish I/O error, not some unrelated
    // earlier failure that would leave prior state intact for the wrong reason.
    let err = result.unwrap_err();
    assert!(
        matches!(&err, ImportError::Io { path, .. } if path.ends_with("device.crl")),
        "expected CRL-publish I/O failure, got {err:?}"
    );
    // The obstructing directory must still be present: confirm the rename
    // collision actually happened rather than the decoy being consumed.
    assert!(crl_bak.is_dir());

    // INVARIANT: device fully in its prior state. With the pre-fix ordering
    // (role swap + floor persist BEFORE the CRL/.p12 commit) these assertions
    // fail — roles/floor advanced while the CRL/.p12 are stale.
    assert_eq!(
        fs::read(paths.roles_dir.join("oper.toml")).unwrap(),
        oper_before,
        "roles must remain the prior version"
    );
    assert_eq!(
        fs::read(&paths.crl_path).unwrap(),
        crl_before,
        "CRL must remain the prior bytes"
    );
    assert_eq!(
        fs::read(&paths.p12_path).unwrap(),
        p12_before,
        "the .p12 must remain the prior bytes"
    );
    assert_eq!(
        persisted_floor(&paths),
        floor_before,
        "the anti-rollback floor must NOT advance unless every artefact is durably in place"
    );
    // Tags still read region=north via the trusted source.
    let tags = installed_managed_tags(&paths, RoleOs::Linux, &key.pub_pem).unwrap();
    assert_eq!(tags.get("region"), Some("north"));

    // No leftover staged / .bak directories.
    assert!(!paths.roles_dir.with_extension("bak").exists());
    let leftover_staged: Vec<PathBuf> = fs::read_dir(root.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(".staged."))
        })
        .collect();
    assert!(
        leftover_staged.is_empty(),
        "leftover staged dir: {leftover_staged:?}"
    );
}

// ---- hardening: p12 pin (L1), manifest cap (M2), planted manifest (L2) ----

#[test]
fn managed_import_with_p12_pin_installs_p12() {
    // L1: a managed manifest carrying a matching p12_sha256 pin verifies and
    // installs the .p12 (the pin authenticates the otherwise-opaque bytes).
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 2,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: None,
            p12_pin: true,
        },
    );
    let outcome = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert_eq!(outcome.bundle_version, 2);
    assert!(paths.p12_path.exists());
    assert_eq!(persisted_floor(&paths), Some(2));
}

#[test]
fn managed_import_p12_pin_mismatch_installs_nothing() {
    // L1: a manifest whose signed p12_sha256 pin does NOT match the shipped
    // .p12 is rejected fail-closed before any device path is mutated.
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 2,
            slices: &[("oper", 1)],
            tags: &[("region", "north")],
            crl: None,
            p12_pin: true,
        },
    );
    // Swap the .p12 bytes AFTER the manifest pinned the original hash. The
    // manifest signature still verifies (it covers the manifest, not the .p12),
    // but the p12 pin now fails.
    fs::write(pkg.path().join("host-abc123.p12"), b"TAMPERED-P12").unwrap();

    let err = EnrollmentPackage::parse(pkg.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap_err();
    assert!(matches!(err, ImportError::P12HashMismatch));
    // Fail-closed: nothing installed, floor untouched.
    assert!(!paths.roles_dir.join("oper.toml").exists());
    assert!(!paths.p12_path.exists());
    assert_eq!(persisted_floor(&paths), None);
}

#[test]
fn managed_import_accepts_manifest_between_slice_and_manifest_caps() {
    // M2: a valid manifest larger than MAX_SLICE_BYTES (64 KiB) but within
    // MAX_MANIFEST_BYTES (256 KiB) must NOT be spuriously rejected when the
    // role slices are copied into the role dir.
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);

    // Pad the manifest past the 64 KiB slice cap (but under the 256 KiB
    // manifest cap) using many tag keys. Each padding line is ~35 bytes;
    // 3000 lines ≈ 100 KiB.
    let dir = tempfile::tempdir().unwrap();
    let body = slice_doc("oper", 1);
    fs::write(dir.path().join("oper.toml"), body.as_bytes()).unwrap();
    let sha = hex::encode(Sha256::digest(body.as_bytes()));
    let mut tags_toml = String::from("[tags]\n");
    for i in 0..3000 {
        let _ = writeln!(tags_toml, "pad{i:05} = \"value-padding-{i:05}\"");
    }
    let roles_toml = format!("[roles.oper]\nversion = 1\nsha256 = \"{sha}\"\n");
    let unsigned = format!("bundle_version = 1\nos = \"linux\"\n{tags_toml}{roles_toml}");
    let sig = sign(&key, unsigned.as_bytes());
    let full = format!(
        "bundle_version = 1\nos = \"linux\"\nsignature = \"{sig}\"\n{tags_toml}{roles_toml}"
    );
    assert!(
        full.len() > role::schema::MAX_SLICE_BYTES,
        "manifest must exceed the slice cap to exercise M2 ({} bytes)",
        full.len()
    );
    assert!(full.len() < role::manifest::MAX_MANIFEST_BYTES);
    fs::write(dir.path().join(MANIFEST_FILENAME), full.as_bytes()).unwrap();
    fs::write(dir.path().join("host-abc123.p12"), P12_OPAQUE).unwrap();

    let outcome = EnrollmentPackage::parse(dir.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();
    assert_eq!(outcome.bundle_version, 1);
    assert!(paths.roles_dir.join(MANIFEST_FILENAME).exists());
    assert!(paths.roles_dir.join("oper.toml").exists());
}

#[test]
fn standalone_import_skips_planted_manifest() {
    // L2: a manifest.toml planted in an UNSIGNED standalone package must not be
    // carried into the trusted role dir (where load_managed might later read
    // it). The standalone copy skips it.
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_standalone_pkg(&PkgSpec {
        bundle_version: 0,
        slices: &[("oper", 1)],
        tags: &[("region", "west")],
        crl: None,
        p12_pin: false,
    });
    // Plant an arbitrary manifest.toml into the standalone package.
    fs::write(
        pkg.path().join(MANIFEST_FILENAME),
        b"bundle_version = 999\nos = \"linux\"\nsignature = \"00\"\n",
    )
    .unwrap();

    EnrollmentPackage::parse(pkg.path(), ImportMode::Standalone)
        .unwrap()
        .install(&paths, RoleOs::Linux, None)
        .unwrap();

    // The role slice landed; the planted manifest did NOT.
    assert!(paths.roles_dir.join("oper.toml").exists());
    assert!(
        !paths.roles_dir.join(MANIFEST_FILENAME).exists(),
        "a planted manifest must never reach the trusted role dir"
    );
}

// ---- 1.4 trusted tags source --------------------------------------------

#[test]
fn imported_managed_tags_readable_via_trusted_source() {
    let key = gen_key();
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_managed_pkg(
        &key,
        &PkgSpec {
            bundle_version: 1,
            slices: &[("oper", 1)],
            tags: &[("region", "north"), ("class", "terminal")],
            crl: None,
            p12_pin: false,
        },
    );
    EnrollmentPackage::parse(pkg.path(), ImportMode::Managed)
        .unwrap()
        .install(&paths, RoleOs::Linux, Some(&key.pub_pem))
        .unwrap();

    // tags::source reads the SAME signed manifest now living under roles_dir.
    let tags = tags::source::load_managed(
        &paths.roles_dir,
        RoleOs::Linux,
        &key.pub_pem,
        &paths.persist_dir,
    )
    .unwrap();
    assert_eq!(tags.get("region"), Some("north"));
    assert_eq!(tags.get("class"), Some("terminal"));
}

#[test]
fn imported_standalone_tags_readable_via_trusted_source() {
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_standalone_pkg(&PkgSpec {
        bundle_version: 0,
        slices: &[("oper", 1)],
        tags: &[("region", "west")],
        crl: None,
        p12_pin: false,
    });
    EnrollmentPackage::parse(pkg.path(), ImportMode::Standalone)
        .unwrap()
        .install(&paths, RoleOs::Linux, None)
        .unwrap();

    // tags::source reads the trusted standalone file the import wrote.
    let tags = tags::source::load_standalone(&paths.tags_file).unwrap();
    assert_eq!(tags.get("region"), Some("west"));
}

#[test]
fn stray_local_tag_file_outside_trusted_source_is_ignored() {
    // A tag file placed somewhere OTHER than the trusted source path is never
    // consulted: the trusted source is the only path tags::source reads.
    let root = tempfile::tempdir().unwrap();
    let paths = install_paths(&root);
    let pkg = build_standalone_pkg(&PkgSpec {
        bundle_version: 0,
        slices: &[("oper", 1)],
        tags: &[("region", "trusted")],
        crl: None,
        p12_pin: false,
    });
    EnrollmentPackage::parse(pkg.path(), ImportMode::Standalone)
        .unwrap()
        .install(&paths, RoleOs::Linux, None)
        .unwrap();

    // Attacker drops a stray tags file elsewhere.
    let stray = root.path().join("stray-tags.toml");
    fs::write(&stray, b"[tags]\nregion = \"attacker\"\n").unwrap();

    // The trusted source still yields the imported value; the stray file is
    // never read by the trusted-source loader.
    let trusted = tags::source::load_standalone(&paths.tags_file).unwrap();
    assert_eq!(trusted.get("region"), Some("trusted"));
    // Sanity: the stray file is a real, different value (so the assertion above
    // is meaningful), but it lives outside the trusted path.
    assert_ne!(paths.tags_file, stray);
}

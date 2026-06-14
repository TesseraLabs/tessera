//! Managed-mode role bundle: `manifest.toml` parsing, signature verification,
//! per-slice hashing, and monotonic anti-rollback persistence.
//!
//! # Trust model (design.md «Два режима доверия» + «Модель угроз managed»)
//!
//! In managed mode the device is *enrolled*: the role base is shipped as a
//! signed bundle. The manifest pins, per role, the slice `version` and its
//! SHA-256, plus a monotonic `bundle_version`. Verification is fail-closed —
//! any invalidity rejects the **whole** base (signing individual slices is
//! not enough against mix-and-match; the TUF lesson, see design.md).
//!
//! ## Signature coverage / canonicalization
//!
//! The signature covers the **raw manifest file bytes with the single
//! `signature = "..."` line removed** (including that line's trailing
//! newline). This avoids any TOML re-serialization ambiguity: there is no
//! canonical-form round-trip, the signed payload is a byte-exact slice of
//! the file. The manifest MUST contain exactly one line whose first
//! non-whitespace characters are `signature` followed by `=`.
//!
//! ## Signature algorithm — Ed25519
//!
//! design.md left Ed25519-vs-GOST open «решить при имплементации». Resolved
//! here to **Ed25519** (pure `EdDSA`, no external message digest). GOST is a
//! future extension; [`verify_signature`] is the single pluggable point —
//! swap the algorithm there. The trusted public key is supplied by the
//! caller (from the enrollment package); this module is key-source-agnostic.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use openssl::pkey::PKey;
use openssl::sign::Verifier;
use sha2::{Digest, Sha256};

use super::audit;
use super::schema::RoleId;
use super::schema::RoleOs;

/// Sanity cap on `manifest.toml` size (256 KiB). A real manifest is a few
/// hundred roles at most.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
/// File name (under the persist dir) holding the last accepted
/// `bundle_version` for anti-rollback.
pub const BUNDLE_VERSION_FILENAME: &str = "bundle.version";
/// Default persist directory (`/var/lib/tessera`); `bundle.version` lives at
/// `<DEFAULT_PERSIST_DIR>/bundle.version` (design.md).
pub const DEFAULT_PERSIST_DIR: &str = "/var/lib/tessera";
/// Manifest file name within the role directory.
pub const MANIFEST_FILENAME: &str = "manifest.toml";

/// Per-role pin in the manifest: the slice's version and the SHA-256 of its
/// raw file bytes (lowercase hex).
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestRole {
    /// Pinned slice version (must match the slice's own `version`; the
    /// hash check below subsumes this, but it is carried for audit/clarity).
    pub version: u32,
    /// SHA-256 over the raw slice file bytes, lowercase hex.
    pub sha256: String,
}

/// Parsed `manifest.toml` (strict: `deny_unknown_fields`).
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Monotonic bundle version (anti-rollback baseline).
    pub bundle_version: u64,
    /// OS this bundle targets; must equal the device OS.
    pub os: RoleOs,
    /// Hex-encoded Ed25519 signature over the [`signed_payload`] bytes.
    pub signature: String,
    /// Role → pin map. `BTreeMap` for deterministic iteration order.
    pub roles: BTreeMap<RoleId, ManifestRole>,
}

/// A manifest that has passed full verification (signature + anti-rollback +
/// per-slice hash) and whose `bundle_version` has been persisted.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    /// The verified manifest.
    pub manifest: Manifest,
    /// `true` when this acceptance established the anti-rollback baseline
    /// (no `bundle_version` was previously persisted — TOFU).
    pub baseline_established: bool,
}

/// Errors from parsing or verifying a managed role bundle.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// `manifest.toml` does not exist in the role directory.
    #[error("manifest.toml is missing")]
    Missing,
    /// Manifest file exceeds the size cap.
    #[error("manifest is {size} bytes, exceeds the {max}-byte cap")]
    Oversize {
        /// Actual byte length.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Manifest bytes are not valid UTF-8.
    #[error("manifest is not valid UTF-8: {reason}")]
    NotUtf8 {
        /// Underlying decode error message.
        reason: String,
    },
    /// TOML parse / type / unknown-field error.
    #[error("manifest TOML is invalid: {reason}")]
    TomlParse {
        /// Underlying TOML error message.
        reason: String,
    },
    /// No `signature = "..."` line found (cannot derive the signed payload).
    #[error("manifest has no signature line")]
    NoSignatureLine,
    /// The `signature` value is not valid hex.
    #[error("manifest signature is not valid hex")]
    BadSignatureHex,
    /// Ed25519 signature did not verify against the trusted key.
    #[error("manifest signature did not verify")]
    BadSignature,
    /// `bundle_version` regressed below the persisted value.
    #[error("bundle rollback: manifest version {found} < persisted {persisted}")]
    Rollback {
        /// Version declared by the manifest.
        found: u64,
        /// Last persisted (accepted) version.
        persisted: u64,
    },
    /// A slice's SHA-256 did not match its manifest pin.
    #[error("slice hash mismatch for role {role:?}")]
    HashMismatch {
        /// Offending role id.
        role: String,
    },
    /// Manifest `os` does not equal the device OS.
    #[error("foreign OS: device is {expected} but manifest targets {found}")]
    ForeignOs {
        /// Device OS.
        expected: RoleOs,
        /// Manifest OS.
        found: RoleOs,
    },
    /// A slice listed in the manifest has no file on disk.
    #[error("slice file missing for role {role:?}")]
    SliceMissing {
        /// Role id whose file is absent.
        role: String,
    },
    /// The persisted `bundle.version` file is present but unparseable.
    #[error("persisted bundle.version is corrupt: {reason}")]
    PersistCorrupt {
        /// Why parsing failed.
        reason: String,
    },
    /// Generic I/O error.
    #[error("manifest I/O error: {reason}")]
    Io {
        /// Underlying I/O error message.
        reason: String,
    },
    /// OpenSSL surfaced an error during verification.
    #[error("openssl error during signature verification: {reason}")]
    Openssl {
        /// Stringified OpenSSL error stack.
        reason: String,
    },
}

/// Return the bytes the signature covers: the full manifest file with the
/// single `signature = "..."` line (and its trailing newline) removed.
///
/// See the module doc for the canonicalization rationale. Errors if no
/// signature line exists or the bytes are not UTF-8.
///
/// # Errors
///
/// [`ManifestError::NotUtf8`] if not UTF-8, [`ManifestError::NoSignatureLine`]
/// if there is no `signature` line.
pub fn signed_payload(bytes: &[u8]) -> Result<Vec<u8>, ManifestError> {
    let text = std::str::from_utf8(bytes).map_err(|e| ManifestError::NotUtf8 {
        reason: e.to_string(),
    })?;
    let mut out = String::with_capacity(text.len());
    let mut removed = false;
    // Preserve original line terminators by splitting inclusively.
    for line in split_keep_terminator(text) {
        if !removed && is_signature_line(line) {
            removed = true;
            continue;
        }
        out.push_str(line);
    }
    if !removed {
        return Err(ManifestError::NoSignatureLine);
    }
    Ok(out.into_bytes())
}

/// Split `text` into lines, each slice including its trailing `\n` (the last
/// line may have none). Pure helper for [`signed_payload`].
fn split_keep_terminator(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            // `i + 1` is a valid char boundary (after a single-byte '\n').
            if let Some(slice) = text.get(start..=i) {
                lines.push(slice);
            }
            start = i + 1;
        }
    }
    if start < text.len() {
        if let Some(slice) = text.get(start..) {
            lines.push(slice);
        }
    }
    lines
}

/// True if `line` (which may include a trailing newline) is the manifest
/// signature line: optional leading whitespace, then `signature` followed by
/// optional whitespace and `=`.
fn is_signature_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    let Some(rest) = trimmed.strip_prefix("signature") else {
        return false;
    };
    rest.trim_start().starts_with('=')
}

/// Parse `manifest.toml` bytes into a [`Manifest`] (strict; size-capped).
///
/// Parses the whole file as TOML, so `signature` (a normal TOML key) is read
/// alongside the other fields. The separate [`signed_payload`] derives the
/// signed byte range.
///
/// # Errors
///
/// Size cap, UTF-8, or TOML errors.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::Oversize {
            size: bytes.len(),
            max: MAX_MANIFEST_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|e| ManifestError::NotUtf8 {
        reason: e.to_string(),
    })?;
    toml::from_str(text).map_err(|e| ManifestError::TomlParse {
        reason: e.to_string(),
    })
}

/// Verify an Ed25519 signature over `signed_payload`.
///
/// **This is the single pluggable point for the signature algorithm.** To
/// support GOST (design.md future extension), branch here on a key/algorithm
/// tag rather than threading a new code path through the verifier.
///
/// `trusted_pubkey` is accepted as PEM (`SubjectPublicKeyInfo`) first, with
/// a DER fallback. `signature_hex` is the lowercase/uppercase hex signature.
///
/// # Errors
///
/// [`ManifestError::BadSignatureHex`] for non-hex input,
/// [`ManifestError::BadSignature`] on verification failure,
/// [`ManifestError::Openssl`] for key/verifier construction errors.
pub fn verify_signature(
    signed_payload: &[u8],
    signature_hex: &str,
    trusted_pubkey: &[u8],
) -> Result<(), ManifestError> {
    let sig = hex::decode(signature_hex.trim()).map_err(|_| ManifestError::BadSignatureHex)?;
    let pkey = PKey::public_key_from_pem(trusted_pubkey)
        .or_else(|_| PKey::public_key_from_der(trusted_pubkey))
        .map_err(|e| ManifestError::Openssl {
            reason: e.to_string(),
        })?;
    // Ed25519 is pure EdDSA: no message digest, one-shot verify.
    let mut verifier =
        Verifier::new_without_digest(&pkey).map_err(|e| ManifestError::Openssl {
            reason: e.to_string(),
        })?;
    let ok = verifier
        .verify_oneshot(&sig, signed_payload)
        .map_err(|e| ManifestError::Openssl {
            reason: e.to_string(),
        })?;
    if ok {
        Ok(())
    } else {
        Err(ManifestError::BadSignature)
    }
}

/// Read the last accepted `bundle_version` from `<persist_dir>/bundle.version`.
///
/// `Ok(None)` when the file is absent (TOFU baseline case). A present but
/// unparseable file is [`ManifestError::PersistCorrupt`] — corruption must
/// not silently reset the anti-rollback floor.
///
/// # Errors
///
/// I/O errors other than not-found, or a corrupt file.
pub fn last_accepted_bundle_version(persist_dir: &Path) -> Result<Option<u64>, ManifestError> {
    let path = persist_dir.join(BUNDLE_VERSION_FILENAME);
    match fs::read_to_string(&path) {
        Ok(s) => {
            let trimmed = s.trim();
            trimmed
                .parse::<u64>()
                .map(Some)
                .map_err(|e| ManifestError::PersistCorrupt {
                    reason: e.to_string(),
                })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ManifestError::Io {
            reason: e.to_string(),
        }),
    }
}

/// Persist `v` as the last accepted `bundle_version` (atomic: tmp + fsync +
/// rename), mode `0644`.
///
/// Mirrors the atomic-write idiom in `ocsp/cache.rs` so readers never see a
/// torn file.
///
/// # Errors
///
/// Propagates the underlying I/O error.
pub fn persist_bundle_version(persist_dir: &Path, v: u64) -> Result<(), ManifestError> {
    let path = persist_dir.join(BUNDLE_VERSION_FILENAME);
    let tmp = persist_dir.join(format!(".{BUNDLE_VERSION_FILENAME}.{}.tmp", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&tmp)?;
        file.write_all(format!("{v}\n").as_bytes())?;
        file.sync_all()?;
        // open(2) mode is masked by umask; pin the spec mode before publish.
        fs::set_permissions(&tmp, PermissionsExt::from_mode(0o644))?;
        fs::rename(&tmp, &path)
    })();
    if result.is_err() {
        if let Err(cleanup) = fs::remove_file(&tmp) {
            if cleanup.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    target: "role.audit",
                    path = %tmp.display(),
                    error = %cleanup,
                    "failed to clean up bundle.version tmp file"
                );
            }
        }
    }
    result.map_err(|e| ManifestError::Io {
        reason: e.to_string(),
    })
}

/// Verify the managed role bundle in `dir` against `trusted_pubkey`,
/// enforcing OS match, signature, anti-rollback, and per-slice hashes; then
/// persist the accepted `bundle_version`.
///
/// Order: read+parse manifest → OS match → signature → anti-rollback →
/// per-slice hash → persist `bundle_version`. Any failure is fail-closed
/// (whole base rejected) and emits the corresponding `bundle_rejected`
/// audit event for the security-relevant rejections.
///
/// # Errors
///
/// Any [`ManifestError`]; the base must be treated as unusable on `Err`.
pub fn verify_manifest(
    dir: &Path,
    device_os: RoleOs,
    trusted_pubkey: &[u8],
    persist_dir: &Path,
) -> Result<VerifiedManifest, ManifestError> {
    let manifest_path = dir.join(MANIFEST_FILENAME);
    let bytes = match fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ManifestError::Missing),
        Err(e) => {
            return Err(ManifestError::Io {
                reason: e.to_string(),
            })
        }
    };

    let manifest = parse_manifest(&bytes)?;

    if manifest.os != device_os {
        return Err(ManifestError::ForeignOs {
            expected: device_os,
            found: manifest.os,
        });
    }

    // 1) Signature over the file bytes minus the signature line.
    let payload = signed_payload(&bytes)?;
    if let Err(e) = verify_signature(&payload, &manifest.signature, trusted_pubkey) {
        audit::emit_bundle_rejected(audit::REASON_SIGNATURE, manifest.bundle_version);
        return Err(e);
    }

    // 2) Anti-rollback against the persisted floor.
    let last = last_accepted_bundle_version(persist_dir)?;
    let baseline_established = match last {
        None => {
            audit::emit_bundle_baseline_established(manifest.bundle_version);
            true
        }
        Some(prev) => {
            if manifest.bundle_version < prev {
                audit::emit_bundle_rejected(audit::REASON_ROLLBACK, manifest.bundle_version);
                return Err(ManifestError::Rollback {
                    found: manifest.bundle_version,
                    persisted: prev,
                });
            }
            false
        }
    };

    // 3) Per-slice hash (mix-and-match defence).
    for (role_id, pin) in &manifest.roles {
        let slice_path = dir.join(format!("{role_id}.toml"));
        let slice_bytes = match fs::read(&slice_path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                audit::emit_bundle_rejected(audit::REASON_HASH_MISMATCH, manifest.bundle_version);
                return Err(ManifestError::SliceMissing {
                    role: role_id.to_string(),
                });
            }
            Err(e) => {
                return Err(ManifestError::Io {
                    reason: e.to_string(),
                })
            }
        };
        let actual = hex::encode(Sha256::digest(&slice_bytes));
        if !actual.eq_ignore_ascii_case(pin.sha256.trim()) {
            audit::emit_bundle_rejected(audit::REASON_HASH_MISMATCH, manifest.bundle_version);
            return Err(ManifestError::HashMismatch {
                role: role_id.to_string(),
            });
        }
    }

    // 4) Accept: persist the (baseline or advanced) bundle_version. Idempotent
    // for an equal version.
    persist_bundle_version(persist_dir, manifest.bundle_version)?;

    Ok(VerifiedManifest {
        manifest,
        baseline_established,
    })
}

#[cfg(test)]
mod tests {
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
    use openssl::sign::Signer;
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

    /// Build a role dir with the given slices and a signed manifest. Returns
    /// `(role_dir, persist_dir)` temp dirs.
    fn build_bundle(
        key: &TestKey,
        bundle_version: u64,
        slices: &[(&str, u32)],
    ) -> (TempDir, TempDir) {
        use std::fmt::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let persist = tempfile::tempdir().unwrap();

        let mut roles_toml = String::new();
        for (role, version) in slices {
            let body = slice_doc(role, *version);
            let slice_path = dir.path().join(format!("{role}.toml"));
            fs::write(&slice_path, body.as_bytes()).unwrap();
            let sha = hex::encode(Sha256::digest(body.as_bytes()));
            let _ = write!(
                roles_toml,
                "[roles.{role}]\nversion = {version}\nsha256 = \"{sha}\"\n"
            );
        }

        // First assemble the unsigned manifest (no signature line), sign it,
        // then write the full manifest with the signature line prepended.
        let unsigned = format!("bundle_version = {bundle_version}\nos = \"linux\"\n{roles_toml}");
        let sig = sign(key, unsigned.as_bytes());
        // Full file: insert the signature line. The signed payload is the
        // file minus that exact line, which equals `unsigned`.
        let full = format!(
            "bundle_version = {bundle_version}\nos = \"linux\"\nsignature = \"{sig}\"\n{roles_toml}"
        );
        // Sanity: signed_payload(full) must equal `unsigned`.
        assert_eq!(signed_payload(full.as_bytes()).unwrap(), unsigned.as_bytes());
        fs::write(dir.path().join(MANIFEST_FILENAME), full.as_bytes()).unwrap();

        (dir, persist)
    }

    #[test]
    fn signed_payload_strips_signature_line() {
        let file = "bundle_version = 1\nos = \"linux\"\nsignature = \"deadbeef\"\n[roles.a]\nversion = 1\nsha256 = \"x\"\n";
        let payload = signed_payload(file.as_bytes()).unwrap();
        let expected = "bundle_version = 1\nos = \"linux\"\n[roles.a]\nversion = 1\nsha256 = \"x\"\n";
        assert_eq!(payload, expected.as_bytes());
        assert!(!String::from_utf8(payload).unwrap().contains("signature"));
    }

    #[test]
    fn signed_payload_no_signature_line_errors() {
        let file = "bundle_version = 1\nos = \"linux\"\n";
        assert!(matches!(
            signed_payload(file.as_bytes()),
            Err(ManifestError::NoSignatureLine)
        ));
    }

    #[test]
    fn valid_manifest_verifies_and_persists() {
        let key = gen_key();
        let (dir, persist) = build_bundle(&key, 7, &[("oper", 1), ("serv", 2)]);
        let verified =
            verify_manifest(dir.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap();
        assert_eq!(verified.manifest.bundle_version, 7);
        assert!(verified.baseline_established);
        assert_eq!(verified.manifest.roles.len(), 2);
        // Persisted floor advanced to 7.
        assert_eq!(
            last_accepted_bundle_version(persist.path()).unwrap(),
            Some(7)
        );
    }

    #[test]
    fn tofu_baseline_when_persist_absent() {
        let key = gen_key();
        let (dir, persist) = build_bundle(&key, 3, &[("oper", 1)]);
        // No bundle.version present yet.
        assert_eq!(last_accepted_bundle_version(persist.path()).unwrap(), None);
        let verified =
            verify_manifest(dir.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap();
        assert!(verified.baseline_established);
    }

    #[test]
    fn rollback_rejected() {
        let key = gen_key();
        // Establish baseline at 10.
        let (dir10, persist) = build_bundle(&key, 10, &[("oper", 1)]);
        verify_manifest(dir10.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap();
        // Now present a version-5 bundle against the same persist dir.
        let (dir5, _p) = build_bundle(&key, 5, &[("oper", 1)]);
        let err = verify_manifest(dir5.path(), RoleOs::Linux, &key.pub_pem, persist.path())
            .unwrap_err();
        assert!(matches!(err, ManifestError::Rollback { found: 5, persisted: 10 }));
        // Floor unchanged.
        assert_eq!(
            last_accepted_bundle_version(persist.path()).unwrap(),
            Some(10)
        );
    }

    #[test]
    fn mix_and_match_hash_mismatch_rejected() {
        let key = gen_key();
        let (dir, persist) = build_bundle(&key, 1, &[("oper", 1), ("serv", 1)]);
        // Tamper with a slice AFTER the manifest was signed: the signature
        // still verifies (it covers the manifest, not the slices), but the
        // per-slice hash now fails.
        fs::write(
            dir.path().join("serv.toml"),
            slice_doc("serv", 99).as_bytes(),
        )
        .unwrap();
        let err =
            verify_manifest(dir.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap_err();
        assert!(matches!(err, ManifestError::HashMismatch { .. }));
    }

    #[test]
    fn foreign_signing_key_rejected() {
        let signer = gen_key();
        let attacker_view = gen_key();
        let (dir, persist) = build_bundle(&signer, 1, &[("oper", 1)]);
        // Verify with a DIFFERENT trusted key than the one that signed.
        let err = verify_manifest(dir.path(), RoleOs::Linux, &attacker_view.pub_pem, persist.path())
            .unwrap_err();
        assert!(matches!(err, ManifestError::BadSignature));
    }

    #[test]
    fn foreign_os_rejected() {
        let key = gen_key();
        let (dir, persist) = build_bundle(&key, 1, &[("oper", 1)]);
        let err =
            verify_manifest(dir.path(), RoleOs::Astra, &key.pub_pem, persist.path()).unwrap_err();
        assert!(matches!(err, ManifestError::ForeignOs { .. }));
    }

    #[test]
    fn missing_slice_rejected() {
        let key = gen_key();
        let (dir, persist) = build_bundle(&key, 1, &[("oper", 1)]);
        fs::remove_file(dir.path().join("oper.toml")).unwrap();
        let err =
            verify_manifest(dir.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap_err();
        assert!(matches!(err, ManifestError::SliceMissing { .. }));
    }

    #[test]
    fn persist_roundtrip() {
        let persist = tempfile::tempdir().unwrap();
        assert_eq!(last_accepted_bundle_version(persist.path()).unwrap(), None);
        persist_bundle_version(persist.path(), 42).unwrap();
        assert_eq!(
            last_accepted_bundle_version(persist.path()).unwrap(),
            Some(42)
        );
        // Overwrite (monotonic advance handled by caller; persist is dumb).
        persist_bundle_version(persist.path(), 43).unwrap();
        assert_eq!(
            last_accepted_bundle_version(persist.path()).unwrap(),
            Some(43)
        );
        // Mode is 0644.
        let mode = fs::metadata(persist.path().join(BUNDLE_VERSION_FILENAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn corrupt_persist_is_error() {
        let persist = tempfile::tempdir().unwrap();
        fs::write(
            persist.path().join(BUNDLE_VERSION_FILENAME),
            b"not-a-number",
        )
        .unwrap();
        assert!(matches!(
            last_accepted_bundle_version(persist.path()),
            Err(ManifestError::PersistCorrupt { .. })
        ));
    }

    #[test]
    fn manifest_missing_errors() {
        let key = gen_key();
        let dir = tempfile::tempdir().unwrap();
        let persist = tempfile::tempdir().unwrap();
        assert!(matches!(
            verify_manifest(dir.path(), RoleOs::Linux, &key.pub_pem, persist.path()),
            Err(ManifestError::Missing)
        ));
    }
}

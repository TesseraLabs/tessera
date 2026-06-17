//! Device-tags source: how the Engine obtains its own *trusted* tag set.
//!
//! Two trust modes, in parity with the role-store (`role::store`):
//!
//! - **Managed** ([`load_managed`]): the tags ride in the SAME signed
//!   `manifest.toml` and under the SAME monotonic `bundle_version` as the role
//!   base. Verification reuses [`crate::role::verify_manifest`] wholesale —
//!   signature over the file bytes, anti-rollback against the single persisted
//!   `bundle_version` floor, per-slice hash. There is NO second anti-rollback
//!   counter (design decision 2). A broken signature or a `bundle_version`
//!   rollback rejects the whole manifest (fail-closed) → **no tags applied**,
//!   and the caller retains the previously-applied set.
//! - **Standalone** ([`load_standalone`]): a local tags file whose trust is the
//!   filesystem permissions (the sudoers.d / standalone role-store model). The
//!   Engine reads its own tags ONLY from this trusted path, never from an
//!   arbitrary local config.
//!
//! The tag set is opaque (`tags::schema`). This module does not interpret keys;
//! it only establishes *which* bytes are trusted and turns them into a
//! validated [`DeviceTags`].

use std::fs;
use std::io;
use std::path::Path;

use crate::role::{verify_manifest, ManifestError, RoleOs};

use super::audit;
use super::schema::{parse_tags, DeviceTags, TagsSchemaError};

/// Default on-disk path for the standalone device-tags file.
pub const DEFAULT_TAGS_FILE: &str = "/var/lib/tessera/tags.toml";

/// Errors from loading a device-tags source.
#[derive(Debug, thiserror::Error)]
pub enum TagsSourceError {
    /// The standalone tags file does not exist. Absence of a source means the
    /// device has no applied tags; callers that need the no-tags case as a
    /// non-error should use [`load_standalone_optional`].
    #[error("device-tags file is missing")]
    Missing,
    /// Filesystem / I/O failure reading the source.
    #[error("device-tags I/O error at {path}: {reason}")]
    Io {
        /// Path being read when the error occurred.
        path: String,
        /// Underlying I/O error message.
        reason: String,
    },
    /// The tags payload is malformed (fail-closed; no tags applied).
    #[error(transparent)]
    Schema(#[from] TagsSchemaError),
    /// Managed-manifest verification failed (signature / anti-rollback / hash).
    /// Fail-closed: no tags applied, previous set retained by the caller.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

/// Extract the validated device-tags from a *verified* managed manifest.
///
/// The manifest's `tags` table is raw (its bytes are already covered by the
/// verified signature); this applies the strict device-tags schema
/// (non-empty key/value, no duplicate — a TOML duplicate is already rejected
/// at parse time) to turn it into an opaque [`DeviceTags`].
fn tags_from_raw(
    raw: &std::collections::BTreeMap<String, String>,
) -> Result<DeviceTags, TagsSchemaError> {
    DeviceTags::from_pairs(raw.iter().map(|(k, v)| (k.clone(), v.clone())))
}

/// Load the device's tags from the managed (signed) bundle in `dir`.
///
/// Verifies `manifest.toml` via [`crate::role::verify_manifest`] (signature +
/// anti-rollback + per-slice hash, persisting the accepted `bundle_version`),
/// then extracts and validates the `[tags]` section. Any verification failure
/// is fail-closed: **no tags are applied** and the caller MUST retain the
/// previously-applied set (a rollback leaves the persisted floor untouched).
///
/// A manifest with no `[tags]` section yields an empty [`DeviceTags`] (the
/// device has no managed tags) — this is *not* an error.
///
/// `trusted_pubkey` is the enrollment-provided verification key (PEM or DER);
/// `persist_dir` holds the single shared anti-rollback `bundle.version`.
///
/// # Errors
///
/// [`TagsSourceError::Manifest`] on verification failure (broken signature,
/// rollback, hash mismatch, foreign OS), or [`TagsSourceError::Schema`] if the
/// signed tags payload is itself malformed.
pub fn load_managed(
    dir: &Path,
    device_os: RoleOs,
    trusted_pubkey: &[u8],
    persist_dir: &Path,
) -> Result<DeviceTags, TagsSourceError> {
    let verified = match verify_manifest(dir, device_os, trusted_pubkey, persist_dir) {
        Ok(v) => v,
        Err(e) => {
            // verify_manifest already emits the role-store `bundle_rejected`
            // event for security rejections; record the tags-side decision too.
            audit::emit_tags_source_rejected(audit::REASON_MANIFEST);
            return Err(TagsSourceError::Manifest(e));
        }
    };
    tags_from_raw(&verified.manifest.tags).map_err(|e| {
        audit::emit_tags_source_rejected(audit::REASON_MALFORMED);
        TagsSourceError::Schema(e)
    })
}

/// Load the device's tags from the standalone trusted file at `path`.
///
/// Trust is the filesystem permissions on `path` (parity with the standalone
/// role-store). A missing file is [`TagsSourceError::Missing`]; use
/// [`load_standalone_optional`] when "no tags file" should map to an empty
/// set instead.
///
/// # Errors
///
/// [`TagsSourceError::Missing`] if absent, [`TagsSourceError::Io`] on a read
/// error, [`TagsSourceError::Schema`] if the file is malformed.
pub fn load_standalone(path: &Path) -> Result<DeviceTags, TagsSourceError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(TagsSourceError::Missing),
        Err(e) => {
            return Err(TagsSourceError::Io {
                path: path.display().to_string(),
                reason: e.to_string(),
            })
        }
    };
    parse_tags(&bytes).map_err(|e| {
        audit::emit_tags_source_rejected(audit::REASON_MALFORMED);
        TagsSourceError::Schema(e)
    })
}

/// Like [`load_standalone`], but a missing file yields an empty [`DeviceTags`]
/// (the device has no applied tags) rather than [`TagsSourceError::Missing`].
///
/// A present-but-malformed file is still a hard error (fail-closed): a broken
/// trusted source must not be silently treated as "no tags".
///
/// # Errors
///
/// [`TagsSourceError::Io`] on a read error, [`TagsSourceError::Schema`] if the
/// file is present but malformed.
pub fn load_standalone_optional(path: &Path) -> Result<DeviceTags, TagsSourceError> {
    match load_standalone(path) {
        Ok(tags) => Ok(tags),
        Err(TagsSourceError::Missing) => Ok(DeviceTags::empty()),
        Err(e) => Err(e),
    }
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
    use crate::role::manifest::MANIFEST_FILENAME;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
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

    /// Build a role dir with a signed manifest carrying both role pins and an
    /// optional `[tags]` table. Returns `(role_dir, persist_dir)`.
    fn build_bundle(
        key: &TestKey,
        bundle_version: u64,
        slices: &[(&str, u32)],
        tags: &[(&str, &str)],
    ) -> (TempDir, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let persist = tempfile::tempdir().unwrap();

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
        (dir, persist)
    }

    // ---- 1.2 managed source ----------------------------------------------

    #[test]
    fn managed_tags_apply_from_signed_manifest() {
        let key = gen_key();
        let (dir, persist) = build_bundle(
            &key,
            5,
            &[("oper", 1)],
            &[("region", "north"), ("class", "terminal")],
        );
        let tags = load_managed(dir.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags.get("region"), Some("north"));
        assert_eq!(tags.get("class"), Some("terminal"));
    }

    #[test]
    fn managed_role_only_manifest_yields_empty_tags() {
        // A manifest with no [tags] section still parses (additive optional).
        let key = gen_key();
        let (dir, persist) = build_bundle(&key, 1, &[("oper", 1)], &[]);
        let tags = load_managed(dir.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn managed_rollback_rejected_previous_retained() {
        let key = gen_key();
        // Establish baseline at bundle_version 10 with region=north.
        let (dir10, persist) = build_bundle(&key, 10, &[("oper", 1)], &[("region", "north")]);
        let applied =
            load_managed(dir10.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap();
        assert_eq!(applied.get("region"), Some("north"));

        // Now present a properly-signed but ROLLED-BACK manifest (v5) that
        // would set region=south. It must be rejected (anti-rollback), and the
        // previous set is what the caller keeps.
        let (dir5, _p) = build_bundle(&key, 5, &[("oper", 1)], &[("region", "south")]);
        let err =
            load_managed(dir5.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap_err();
        assert!(matches!(
            err,
            TagsSourceError::Manifest(ManifestError::Rollback {
                found: 5,
                persisted: 10
            })
        ));
        // The previously-applied set (region=north) is what survives.
        assert_eq!(applied.get("region"), Some("north"));
    }

    #[test]
    fn managed_broken_signature_not_applied() {
        let key = gen_key();
        let (dir, persist) = build_bundle(&key, 1, &[("oper", 1)], &[("region", "north")]);
        // Corrupt the manifest body AFTER signing: signature no longer matches.
        let manifest_path = dir.path().join(MANIFEST_FILENAME);
        let mut body = fs::read_to_string(&manifest_path).unwrap();
        body = body.replace("region = \"north\"", "region = \"south\"");
        fs::write(&manifest_path, body.as_bytes()).unwrap();

        let err =
            load_managed(dir.path(), RoleOs::Linux, &key.pub_pem, persist.path()).unwrap_err();
        assert!(matches!(
            err,
            TagsSourceError::Manifest(ManifestError::BadSignature)
        ));
    }

    #[test]
    fn managed_foreign_signing_key_not_applied() {
        let signer = gen_key();
        let attacker = gen_key();
        let (dir, persist) = build_bundle(&signer, 1, &[("oper", 1)], &[("region", "north")]);
        let err =
            load_managed(dir.path(), RoleOs::Linux, &attacker.pub_pem, persist.path()).unwrap_err();
        assert!(matches!(
            err,
            TagsSourceError::Manifest(ManifestError::BadSignature)
        ));
    }

    // ---- 1.2 standalone source -------------------------------------------

    #[test]
    fn standalone_tags_load_from_trusted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tags.toml");
        fs::write(&path, b"[tags]\nregion = \"north\"\n").unwrap();
        let tags = load_standalone(&path).unwrap();
        assert_eq!(tags.get("region"), Some("north"));
    }

    #[test]
    fn standalone_missing_is_missing_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.toml");
        assert!(matches!(
            load_standalone(&path),
            Err(TagsSourceError::Missing)
        ));
        // Optional variant maps missing → empty set.
        assert!(load_standalone_optional(&path).unwrap().is_empty());
    }

    #[test]
    fn standalone_malformed_is_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tags.toml");
        // Duplicate key → fail-closed, not last-wins.
        fs::write(&path, b"[tags]\nregion = \"north\"\nregion = \"south\"\n").unwrap();
        assert!(matches!(
            load_standalone(&path),
            Err(TagsSourceError::Schema(_))
        ));
        // And the optional variant does NOT swallow a malformed file.
        assert!(matches!(
            load_standalone_optional(&path),
            Err(TagsSourceError::Schema(_))
        ));
    }
}

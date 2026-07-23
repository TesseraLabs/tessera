//! On-device role store: a validated `RoleId -> RoleSlice` map loaded from a
//! directory of `*.toml` slices.
//!
//! Two trust modes (design.md «Два режима доверия»):
//!
//! - **Standalone** ([`RoleStore::load`]): trust is the filesystem
//!   permissions (the sudoers.d model — `root:root 0755/0644`). No manifest.
//!   Each slice is parsed independently; a broken or foreign-OS slice is
//!   *skipped* with a `role_slice_invalid` audit event so one bad file never
//!   takes down the rest of the base.
//! - **Managed** ([`RoleStore::load_managed`]): the base is a signed bundle.
//!   [`crate::role::manifest::verify_manifest`] gates the whole set
//!   (signature + anti-rollback + per-slice hash); any invalidity rejects
//!   the entire base (fail-closed). Slices are only loaded after the manifest
//!   verifies.
//!
//! Calling [`RoleStore::load`] with [`TrustMode::Managed`] is a hard error
//! ([`RoleStoreError::ManagedRequiresManifest`]): managed loads need a
//! trusted key and persist dir, so they must go through `load_managed`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::audit;
use super::manifest::{self, ManifestError, MANIFEST_FILENAME};
use super::schema::{parse_slice, RoleId, RoleOs, RoleSlice};

/// Hard cap on the number of roles in a single base. A base larger than this
/// is a validation error, not a silent truncation.
pub const MAX_ROLES: usize = 256;
/// Default on-disk directory for role slices.
pub const DEFAULT_ROLES_DIR: &str = "/var/lib/tessera/roles";

/// Trust mode for loading a role base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    /// Filesystem-permission trust (sudoers.d model); no manifest.
    Standalone,
    /// Signed-manifest trust (enrolled device). Use [`RoleStore::load_managed`].
    Managed,
}

/// A validated set of role slices keyed by [`RoleId`].
#[derive(Debug, Clone, Default)]
pub struct RoleStore {
    /// Validated slices, one per role id.
    roles: HashMap<RoleId, RoleSlice>,
}

/// Errors from loading a role store. Per-slice schema failures in standalone
/// mode are *not* represented here — they are skipped and audited.
#[derive(Debug, thiserror::Error)]
pub enum RoleStoreError {
    /// Directory read / I/O failure (e.g. missing directory).
    #[error("role store I/O error at {path}: {reason}")]
    Io {
        /// Path being read when the error occurred.
        path: String,
        /// Underlying I/O error message.
        reason: String,
    },
    /// The number of successfully loaded slices exceeds [`MAX_ROLES`].
    #[error("role base has {count} roles, exceeds the {max} cap")]
    TooManyRoles {
        /// Number of valid slices found.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// [`RoleStore::load`] was called with [`TrustMode::Managed`]; use
    /// [`RoleStore::load_managed`] (which takes a trusted key + persist dir).
    #[error("managed mode requires a manifest; call load_managed")]
    ManagedRequiresManifest,
    /// Managed-bundle manifest verification failed (fail-closed).
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// A standalone policy directory or slice failed the root-controlled path
    /// policy.
    #[error("standalone role-store path is not root-controlled: {0}")]
    UntrustedPath(#[from] crate::privileged_path::PrivilegedPathError),
}

impl RoleStore {
    /// Load a role base from `dir`.
    ///
    /// Only [`TrustMode::Standalone`] is handled here; [`TrustMode::Managed`]
    /// returns [`RoleStoreError::ManagedRequiresManifest`] (managed loads
    /// need a key + persist dir — see [`RoleStore::load_managed`]).
    ///
    /// Standalone behaviour: iterate `*.toml` files in `dir` (skip subdirs,
    /// non-`.toml`, and `manifest.toml`). The role id is the file stem. Each
    /// slice is parsed via [`parse_slice`]; a per-slice error (bad schema,
    /// foreign OS, non-role-id stem, role/stem mismatch) is skipped with a
    /// `role_slice_invalid` audit event. If the count of *valid* slices
    /// exceeds [`MAX_ROLES`], the whole load fails with
    /// [`RoleStoreError::TooManyRoles`]. An empty directory yields an empty
    /// store. A missing/unreadable directory is [`RoleStoreError::Io`].
    ///
    /// # Errors
    ///
    /// [`RoleStoreError::Io`], [`RoleStoreError::TooManyRoles`], or
    /// [`RoleStoreError::ManagedRequiresManifest`].
    pub fn load(dir: &Path, device_os: RoleOs, trust: TrustMode) -> Result<Self, RoleStoreError> {
        match trust {
            TrustMode::Managed => Err(RoleStoreError::ManagedRequiresManifest),
            TrustMode::Standalone => Self::load_slices(dir, device_os, false),
        }
    }

    /// Load a standalone role base for use by a root authentication path.
    ///
    /// This has the same schema and per-slice behaviour as [`Self::load`], but
    /// additionally requires the directory, every slice, and every ancestor
    /// to be root-owned and non-writable by group/other. A path-integrity
    /// failure rejects the whole base rather than skipping the affected slice.
    ///
    /// # Errors
    ///
    /// Returns [`RoleStoreError::UntrustedPath`] for an unsafe path, plus the
    /// standalone load errors documented by [`Self::load`].
    pub fn load_privileged(
        dir: &Path,
        device_os: RoleOs,
        trust: TrustMode,
    ) -> Result<Self, RoleStoreError> {
        match trust {
            TrustMode::Managed => Err(RoleStoreError::ManagedRequiresManifest),
            TrustMode::Standalone => Self::load_slices(dir, device_os, true),
        }
    }

    /// Load and validate a managed (signed) role bundle from `dir`.
    ///
    /// Verifies `manifest.toml` first via
    /// [`manifest::verify_manifest`] (signature + anti-rollback + per-slice
    /// hash, persisting the accepted `bundle_version`); only on success are
    /// the slices listed in the manifest parsed into the store. Any manifest
    /// invalidity rejects the whole base (fail-closed).
    ///
    /// `trusted_pubkey` is the enrollment-provided verification key (PEM or
    /// DER); `persist_dir` holds the anti-rollback `bundle.version`.
    ///
    /// # Errors
    ///
    /// [`RoleStoreError::Manifest`] on any verification failure,
    /// [`RoleStoreError::Io`] reading a slice, or
    /// [`RoleStoreError::TooManyRoles`].
    pub fn load_managed(
        dir: &Path,
        device_os: RoleOs,
        trusted_pubkey: &[u8],
        persist_dir: &Path,
    ) -> Result<Self, RoleStoreError> {
        let verified = manifest::verify_manifest(dir, device_os, trusted_pubkey, persist_dir)?;
        if verified.manifest.roles.len() > MAX_ROLES {
            return Err(RoleStoreError::TooManyRoles {
                count: verified.manifest.roles.len(),
                max: MAX_ROLES,
            });
        }
        let mut roles = HashMap::with_capacity(verified.manifest.roles.len());
        // The manifest's hashes already matched the on-disk slices, so the
        // schema parse below should succeed; a schema error here is still a
        // hard error (a hash-matching slice that fails schema means the
        // signed bundle is internally inconsistent → fail-closed).
        for role_id in verified.manifest.roles.keys() {
            let slice_path = dir.join(format!("{role_id}.toml"));
            let bytes = fs::read(&slice_path).map_err(|e| RoleStoreError::Io {
                path: slice_path.display().to_string(),
                reason: e.to_string(),
            })?;
            match parse_slice(&bytes, role_id.as_str(), device_os) {
                Ok(slice) => {
                    roles.insert(slice.role.clone(), slice);
                }
                Err(e) => {
                    return Err(RoleStoreError::Manifest(ManifestError::HashMismatch {
                        role: format!("{role_id}: slice schema invalid after hash match: {e}"),
                    }));
                }
            }
        }
        Ok(Self { roles })
    }

    /// Standalone slice iteration (shared by [`Self::load`]).
    fn load_slices(
        dir: &Path,
        device_os: RoleOs,
        privileged: bool,
    ) -> Result<Self, RoleStoreError> {
        let load_dir: PathBuf = if privileged {
            crate::privileged_path::validate_directory(
                dir,
                crate::privileged_path::ExecTrust::Root,
            )?
            .canonical()
            .to_path_buf()
        } else {
            dir.to_path_buf()
        };
        let entries = fs::read_dir(&load_dir).map_err(|e| RoleStoreError::Io {
            path: load_dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let mut roles: HashMap<RoleId, RoleSlice> = HashMap::new();
        for entry in entries {
            let entry = entry.map_err(|e| RoleStoreError::Io {
                path: load_dir.display().to_string(),
                reason: e.to_string(),
            })?;
            let path = entry.path();
            // Skip non-`.toml`, the manifest, and anything that isn't a file.
            if path.extension() != Some(OsStr::new("toml")) {
                continue;
            }
            if path.file_name() == Some(OsStr::new(MANIFEST_FILENAME)) {
                continue;
            }
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    audit::emit_role_slice_invalid(&path.display().to_string(), &e.to_string());
                    continue;
                }
            };
            if !file_type.is_file() {
                continue;
            }
            // Role id = file stem. A non-role-id stem is a per-slice skip.
            let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
                audit::emit_role_slice_invalid(
                    &path.display().to_string(),
                    "file stem is not valid UTF-8",
                );
                continue;
            };
            let bytes = if privileged {
                crate::privileged_path::read_file(&path, crate::privileged_path::ExecTrust::Root)?
            } else {
                match fs::read(&path) {
                    Ok(b) => b,
                    Err(e) => {
                        audit::emit_role_slice_invalid(&path.display().to_string(), &e.to_string());
                        continue;
                    }
                }
            };
            match parse_slice(&bytes, stem, device_os) {
                Ok(slice) => {
                    roles.insert(slice.role.clone(), slice);
                }
                Err(e) => {
                    audit::emit_role_slice_invalid(&path.display().to_string(), &e.to_string());
                }
            }
        }
        if roles.len() > MAX_ROLES {
            return Err(RoleStoreError::TooManyRoles {
                count: roles.len(),
                max: MAX_ROLES,
            });
        }
        Ok(Self { roles })
    }

    /// Look up a role by id.
    #[must_use]
    pub fn get(&self, id: &RoleId) -> Option<&RoleSlice> {
        self.roles.get(id)
    }

    /// Iterate the loaded slices (unordered).
    pub fn list(&self) -> impl Iterator<Item = &RoleSlice> {
        self.roles.values()
    }

    /// Number of loaded roles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roles.len()
    }

    /// Whether the store holds no roles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
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
    use std::fs;
    use tempfile::TempDir;

    fn slice_doc(role: &str, version: u32, os: &str) -> String {
        format!(
            "role = \"{role}\"\nversion = {version}\nos = \"{os}\"\nname = \"{role}\"\nlevel = 1\n"
        )
    }

    fn write_slice(dir: &TempDir, role: &str, version: u32, os: &str) {
        fs::write(
            dir.path().join(format!("{role}.toml")),
            slice_doc(role, version, os).as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn good_and_bad_slice_good_loaded_bad_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        // Broken: unknown field.
        fs::write(
            dir.path().join("serv.toml"),
            b"role = \"serv\"\nversion = 1\nos = \"linux\"\nname = \"s\"\nlevel = 1\nbogus = 1\n",
        )
        .unwrap();
        let store = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Standalone).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get(&RoleId::new("oper").unwrap()).is_some());
        assert!(store.get(&RoleId::new("serv").unwrap()).is_none());
    }

    #[test]
    fn foreign_os_slice_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        write_slice(&dir, "admin", 1, "astra"); // foreign OS for a linux device
        let store = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Standalone).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get(&RoleId::new("admin").unwrap()).is_none());
    }

    #[test]
    fn non_role_id_stem_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        // Stem "Bad-Stem" is not a valid role id; parse_slice rejects on
        // role-mismatch and the slice is skipped.
        fs::write(
            dir.path().join("Bad-Stem.toml"),
            slice_doc("oper", 1, "linux").as_bytes(),
        )
        .unwrap();
        let store = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Standalone).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn more_than_max_roles_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..=MAX_ROLES {
            // role ids must match ^[a-z][a-z0-9-]{0,15}$
            let role = format!("r{i}");
            write_slice(&dir, &role, 1, "linux");
        }
        let err = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Standalone).unwrap_err();
        assert!(matches!(
            err,
            RoleStoreError::TooManyRoles {
                count,
                max: MAX_ROLES
            } if count == MAX_ROLES + 1
        ));
    }

    #[test]
    fn empty_dir_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Standalone).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn missing_dir_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let err = RoleStore::load(&missing, RoleOs::Linux, TrustMode::Standalone).unwrap_err();
        assert!(matches!(err, RoleStoreError::Io { .. }));
    }

    #[test]
    fn get_and_list() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 3, "linux");
        write_slice(&dir, "serv", 7, "linux");
        let store = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Standalone).unwrap();
        assert_eq!(store.len(), 2);
        let oper = store.get(&RoleId::new("oper").unwrap()).unwrap();
        assert_eq!(oper.version, 3);
        let mut versions: Vec<u32> = store.list().map(|s| s.version).collect();
        versions.sort_unstable();
        assert_eq!(versions, vec![3, 7]);
    }

    #[test]
    fn manifest_toml_skipped_in_standalone() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");
        // A stray manifest.toml must be ignored (not parsed as a slice).
        fs::write(dir.path().join(MANIFEST_FILENAME), b"bundle_version = 1\n").unwrap();
        let store = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Standalone).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn managed_via_load_guard_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = RoleStore::load(dir.path(), RoleOs::Linux, TrustMode::Managed).unwrap_err();
        assert!(matches!(err, RoleStoreError::ManagedRequiresManifest));
    }

    #[test]
    fn privileged_standalone_rejects_untrusted_temp_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        write_slice(&dir, "oper", 1, "linux");

        let err = RoleStore::load_privileged(dir.path(), RoleOs::Linux, TrustMode::Standalone)
            .expect_err("temporary user-controlled role base must be rejected");

        assert!(matches!(err, RoleStoreError::UntrustedPath(_)));
    }
}

//! Atomic role-base update: validate a staged directory, then swap it into
//! place with a single `rename(2)` so a half-written set is never observed.
//!
//! The caller writes the new role set into `staged_dir` (a temp directory on
//! the *same filesystem* as `target_dir`). [`atomic_update`] then:
//!
//! 1. Validates/verifies `staged_dir` (standalone schema or managed manifest)
//!    *before touching `target_dir`* — on failure the active base (the old
//!    `target_dir`) is left intact.
//! 2. On success, swaps the directories: `target_dir → target_dir.bak`,
//!    `staged_dir → target_dir`, then removes the `.bak`. If the second
//!    rename fails, the `.bak` is restored.
//!
//! Because validation runs on `staged_dir` and publication is a directory
//! rename, readers see either the whole old base or the whole new base.

use std::fs;
use std::io;
use std::path::Path;

use super::schema::RoleOs;
use super::store::{RoleStore, RoleStoreError};

/// Trust mode + parameters for validating a staged update.
#[derive(Debug, Clone, Copy)]
pub enum UpdateTrust<'a> {
    /// Filesystem-permission trust; validate via [`RoleStore::load`].
    Standalone,
    /// Signed-manifest trust; validate via [`RoleStore::load_managed`].
    Managed {
        /// Enrollment-provided verification key (PEM or DER).
        trusted_pubkey: &'a [u8],
        /// Anti-rollback persist directory.
        persist_dir: &'a Path,
    },
}

/// Validate `staged_dir` then atomically swap it into `target_dir`.
///
/// See the module doc for the swap protocol and crash-safety argument.
/// Returns the loaded [`RoleStore`] (the validated, now-active base) on
/// success. On validation failure, returns the error and leaves `target_dir`
/// untouched.
///
/// # Errors
///
/// [`RoleStoreError`] from validation, or [`RoleStoreError::Io`] if the
/// rename swap fails.
pub fn atomic_update(
    target_dir: &Path,
    staged_dir: &Path,
    device_os: RoleOs,
    trust: &UpdateTrust<'_>,
) -> Result<RoleStore, RoleStoreError> {
    // 1) Validate the staged set first; never touch target_dir on failure.
    let store = match *trust {
        UpdateTrust::Standalone => {
            RoleStore::load(staged_dir, device_os, super::store::TrustMode::Standalone)?
        }
        UpdateTrust::Managed {
            trusted_pubkey,
            persist_dir,
        } => RoleStore::load_managed(staged_dir, device_os, trusted_pubkey, persist_dir)?,
    };

    // 2) Swap into place.
    swap_dirs(target_dir, staged_dir).map_err(|e| RoleStoreError::Io {
        path: target_dir.display().to_string(),
        reason: e.to_string(),
    })?;

    Ok(store)
}

/// Swap `staged` into `target`'s place via renames, restoring on failure.
///
/// POSIX `rename` of a dir onto a non-empty dir fails, so we move the old
/// `target` aside to `target.bak`, move `staged` into `target`, then drop the
/// `.bak`. If moving `staged` in fails, the `.bak` is restored so the old
/// base remains active.
fn swap_dirs(target: &Path, staged: &Path) -> io::Result<()> {
    let bak = backup_path(target);

    // Clean up any leftover .bak from a previous crashed update.
    if bak.exists() {
        fs::remove_dir_all(&bak)?;
    }

    let target_existed = target.exists();
    if target_existed {
        fs::rename(target, &bak)?;
    }

    match fs::rename(staged, target) {
        Ok(()) => {
            if target_existed {
                // Best-effort cleanup of the old base; a leftover .bak is
                // harmless (cleaned next update) but log if it lingers.
                if let Err(e) = fs::remove_dir_all(&bak) {
                    tracing::warn!(
                        target: "role.audit",
                        path = %bak.display(),
                        error = %e,
                        "failed to remove old role base backup after swap"
                    );
                }
            }
            Ok(())
        }
        Err(e) => {
            // Restore the old base so the active set is never lost.
            if target_existed {
                if let Err(restore) = fs::rename(&bak, target) {
                    tracing::error!(
                        target: "role.audit",
                        path = %target.display(),
                        error = %restore,
                        "failed to restore role base backup after failed swap"
                    );
                }
            }
            Err(e)
        }
    }
}

/// The `.bak` sibling path used during a swap.
fn backup_path(target: &Path) -> std::path::PathBuf {
    let mut name = target.file_name().map_or_else(
        || std::ffi::OsString::from("role-base"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(".bak");
    match target.parent() {
        Some(parent) => parent.join(name),
        None => std::path::PathBuf::from(name),
    }
}

/// Best-effort removal of a staged directory (failure-path cleanup).
///
/// Used when an update is abandoned before/after a failed validation so the
/// temp directory does not linger. Errors are swallowed (best-effort).
pub fn cleanup_staged(staged_dir: &Path) {
    if let Err(e) = fs::remove_dir_all(staged_dir) {
        if e.kind() != io::ErrorKind::NotFound {
            tracing::warn!(
                target: "role.audit",
                path = %staged_dir.display(),
                error = %e,
                "failed to clean up staged role directory"
            );
        }
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
    use crate::role::schema::RoleId;
    use std::fs;

    fn slice_doc(role: &str, version: u32) -> String {
        format!(
            "role = \"{role}\"\nversion = {version}\nos = \"linux\"\nname = \"{role}\"\nlevel = 1\n"
        )
    }

    fn write_slice(dir: &Path, role: &str, version: u32) {
        fs::write(
            dir.join(format!("{role}.toml")),
            slice_doc(role, version).as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn atomic_swap_replaces_base() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("roles");
        let staged = root.path().join("roles.staged");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&staged).unwrap();

        // Old base: oper v1.
        write_slice(&target, "oper", 1);
        // Staged base: oper v2 + serv v1.
        write_slice(&staged, "oper", 2);
        write_slice(&staged, "serv", 1);

        let store =
            atomic_update(&target, &staged, RoleOs::Linux, &UpdateTrust::Standalone).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(
            store.get(&RoleId::new("oper").unwrap()).unwrap().version,
            2
        );
        // On disk: target now holds the new set; staged is gone.
        assert!(target.join("serv.toml").exists());
        assert!(!staged.exists());
        // No leftover .bak.
        assert!(!root.path().join("roles.bak").exists());
    }

    #[test]
    fn atomic_swap_when_target_absent() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("roles");
        let staged = root.path().join("roles.staged");
        fs::create_dir(&staged).unwrap();
        write_slice(&staged, "oper", 1);

        let store =
            atomic_update(&target, &staged, RoleOs::Linux, &UpdateTrust::Standalone).unwrap();
        assert_eq!(store.len(), 1);
        assert!(target.join("oper.toml").exists());
    }

    #[test]
    fn failed_validation_keeps_old_base() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("roles");
        let staged = root.path().join("roles.staged");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&staged).unwrap();

        // Old base: oper v1 (good).
        write_slice(&target, "oper", 1);
        // Staged base: too many roles → whole-store validation error.
        for i in 0..=super::super::store::MAX_ROLES {
            write_slice(&staged, &format!("r{i}"), 1);
        }

        let err =
            atomic_update(&target, &staged, RoleOs::Linux, &UpdateTrust::Standalone).unwrap_err();
        assert!(matches!(err, RoleStoreError::TooManyRoles { .. }));

        // Active base unchanged: target still holds the old single slice.
        assert!(target.join("oper.toml").exists());
        let reloaded =
            RoleStore::load(&target, RoleOs::Linux, super::super::store::TrustMode::Standalone)
                .unwrap();
        assert_eq!(reloaded.len(), 1);
        // Staged dir is untouched (caller cleans up).
        assert!(staged.exists());
    }

    #[test]
    fn staged_cleanup_removes_tmp() {
        let root = tempfile::tempdir().unwrap();
        let staged = root.path().join("roles.staged");
        fs::create_dir(&staged).unwrap();
        write_slice(&staged, "oper", 1);
        assert!(staged.exists());
        cleanup_staged(&staged);
        assert!(!staged.exists());
        // Idempotent: removing again is a no-op.
        cleanup_staged(&staged);
    }
}

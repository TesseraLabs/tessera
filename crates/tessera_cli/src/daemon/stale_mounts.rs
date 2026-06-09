//! Startup sweep of stale USB mountpoints.
//!
//! The PAM module's `MountGuard` unmounts and removes
//! `/run/tessera/mounts/<sid>[-seq]` on Drop, but Drop never runs when the
//! PAM process crashes, and `rmdir` can fail with `EBUSY` while something
//! still holds the mount. `/run` is a tmpfs that is only cleared on reboot,
//! while the device fleet runs for weeks — without this sweep leftovers
//! accumulate indefinitely. The daemon therefore walks the base directory
//! once on startup (before binding the IPC socket) and best-effort
//! lazy-unmounts + removes every entry, logging a WARN per leftover.

use std::path::Path;

use tessera_core::mount_guard::MountOps;

/// Sweep `base` for leftover per-session mountpoint directories.
///
/// For every directory entry: WARN-log the leftover, best-effort
/// `umount` (lazy `MNT_DETACH` via [`MountOps::umount`]; the path may not
/// be mounted at all, in which case the failure is expected and logged at
/// DEBUG), then `rmdir`. A missing `base` is not an error — the PAM module
/// creates it lazily on first auth.
///
/// Returns the number of directories actually removed. Failures never
/// propagate: cleanup is best-effort and MUST NOT block daemon startup.
pub(super) fn cleanup_stale_mounts<O: MountOps>(ops: &O, base: &Path) -> usize {
    let entries = match std::fs::read_dir(base) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(err) => {
            tracing::warn!(
                target: "tessera.mount",
                base = %base.display(),
                error = %err,
                "cannot scan stale-mountpoint base directory"
            );
            return 0;
        }
    };

    let mut removed = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(
                    target: "tessera.mount",
                    base = %base.display(),
                    error = %err,
                    "failed to read stale-mountpoint directory entry"
                );
                continue;
            }
        };
        let path = entry.path();
        // Classify via `DirEntry::file_type` (lstat semantics, does not
        // follow symlinks): `Path::is_dir` would follow a symlink and let a
        // planted link redirect the umount/rmdir at an arbitrary directory.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) => {
                tracing::warn!(
                    target: "tessera.mount",
                    path = %path.display(),
                    error = %err,
                    "failed to read file type of stale-mountpoint entry"
                );
                continue;
            }
        };
        if file_type.is_symlink() {
            tracing::warn!(
                target: "tessera.mount",
                path = %path.display(),
                "skipping symlink in stale-mountpoint base directory"
            );
            continue;
        }
        // Only real directories can be (former) mountpoints; anything else
        // under the base is unexpected but not ours to delete.
        if !file_type.is_dir() {
            continue;
        }
        tracing::warn!(
            target: "tessera.mount",
            mountpoint = %path.display(),
            "stale USB mountpoint left over from a previous run; cleaning up"
        );
        // Best-effort lazy unmount: the path may or may not still be
        // mounted. `umount2(MNT_DETACH)` on a plain directory fails with
        // EINVAL, which is the common (already-unmounted) case.
        if let Err(err) = ops.umount(&path) {
            tracing::debug!(
                target: "tessera.mount",
                mountpoint = %path.display(),
                error = %err,
                "stale mountpoint umount failed (likely not mounted)"
            );
        }
        match ops.rmdir(&path) {
            Ok(()) => removed += 1,
            Err(err) => {
                tracing::warn!(
                    target: "tessera.mount",
                    mountpoint = %path.display(),
                    error = %err,
                    "stale mountpoint rmdir failed; leaving for the next sweep"
                );
            }
        }
    }
    removed
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tessera_core::error::MountGuardError;
    use tessera_core::mount_guard::{MountFlags, RealMountOps};

    #[test]
    fn missing_base_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("does-not-exist");
        assert_eq!(cleanup_stale_mounts(&RealMountOps, &base), 0);
    }

    #[test]
    fn empty_base_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(cleanup_stale_mounts(&RealMountOps, tmp.path()), 0);
    }

    #[test]
    fn removes_leftover_directories_and_keeps_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("sid-aaaa")).unwrap();
        std::fs::create_dir(tmp.path().join("sid-bbbb-1")).unwrap();
        std::fs::write(tmp.path().join("not-a-mountpoint.txt"), b"x").unwrap();

        let removed = cleanup_stale_mounts(&RealMountOps, tmp.path());
        assert_eq!(removed, 2);
        assert!(!tmp.path().join("sid-aaaa").exists());
        assert!(!tmp.path().join("sid-bbbb-1").exists());
        assert!(tmp.path().join("not-a-mountpoint.txt").exists());
    }

    #[test]
    fn symlink_to_directory_is_skipped_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        std::fs::create_dir(&base).unwrap();
        // Target lives outside the base: following the link and removing it
        // would be exactly the redirection attack the sweep must resist.
        let target = tmp.path().join("victim-dir");
        std::fs::create_dir(&target).unwrap();
        let link = base.join("sid-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let removed = cleanup_stale_mounts(&RealMountOps, &base);
        assert_eq!(removed, 0);
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(target.is_dir(), "symlink target must survive the sweep");
    }

    /// Records calls and lets `umount`/`rmdir` fail to model an
    /// unprivileged daemon facing a still-active mount.
    #[derive(Default)]
    struct RecordingOps {
        umounts: Mutex<Vec<PathBuf>>,
        rmdirs: Mutex<Vec<PathBuf>>,
        fail_umount: bool,
        fail_rmdir: bool,
    }

    impl MountOps for RecordingOps {
        fn mount(
            &self,
            _source: &Path,
            _target: &Path,
            _fs_type: &str,
            _flags: MountFlags,
            _data: Option<&str>,
        ) -> Result<(), MountGuardError> {
            Ok(())
        }
        fn umount(&self, target: &Path) -> Result<(), MountGuardError> {
            self.umounts.lock().unwrap().push(target.to_path_buf());
            if self.fail_umount {
                return Err(MountGuardError::Umount {
                    target: target.to_path_buf(),
                    source: std::io::Error::from_raw_os_error(libc::EINVAL),
                });
            }
            Ok(())
        }
        fn mkdir_mode_0700(&self, _path: &Path) -> Result<(), MountGuardError> {
            Ok(())
        }
        fn rmdir(&self, path: &Path) -> Result<(), MountGuardError> {
            self.rmdirs.lock().unwrap().push(path.to_path_buf());
            if self.fail_rmdir {
                return Err(MountGuardError::Rmdir {
                    path: path.to_path_buf(),
                    source: std::io::Error::from_raw_os_error(libc::EBUSY),
                });
            }
            std::fs::remove_dir(path).map_err(|source| MountGuardError::Rmdir {
                path: path.to_path_buf(),
                source,
            })
        }
    }

    #[test]
    fn umount_failure_still_attempts_rmdir() {
        let tmp = tempfile::tempdir().unwrap();
        let leftover = tmp.path().join("sid-cccc");
        std::fs::create_dir(&leftover).unwrap();

        let ops = RecordingOps {
            fail_umount: true,
            ..Default::default()
        };
        let removed = cleanup_stale_mounts(&ops, tmp.path());
        assert_eq!(removed, 1);
        assert_eq!(
            ops.umounts.lock().unwrap().as_slice(),
            std::slice::from_ref(&leftover)
        );
        assert_eq!(
            ops.rmdirs.lock().unwrap().as_slice(),
            std::slice::from_ref(&leftover)
        );
        assert!(!leftover.exists());
    }

    #[test]
    fn rmdir_failure_is_best_effort_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let leftover = tmp.path().join("sid-dddd");
        std::fs::create_dir(&leftover).unwrap();

        let ops = RecordingOps {
            fail_rmdir: true,
            ..Default::default()
        };
        let removed = cleanup_stale_mounts(&ops, tmp.path());
        assert_eq!(removed, 0);
        assert!(leftover.exists(), "directory survives a failed rmdir");
    }
}

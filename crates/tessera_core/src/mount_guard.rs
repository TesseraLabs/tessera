//! RAII mount guard.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::MountGuardError;

/// Mount flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountFlags(u32);

impl MountFlags {
    /// NOSUID.
    pub const NOSUID: Self = Self(1);
    /// NODEV.
    pub const NODEV: Self = Self(1 << 1);
    /// NOEXEC.
    pub const NOEXEC: Self = Self(1 << 2);
    /// Read-only.
    pub const RO: Self = Self(1 << 3);
    /// NOATIME.
    pub const NOATIME: Self = Self(1 << 4);

    /// Whether `self` has every bit set in `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for MountFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Mount operations.
pub trait MountOps {
    /// Mount.
    fn mount(
        &self,
        source: &Path,
        target: &Path,
        fs_type: &str,
        flags: MountFlags,
        data: Option<&str>,
    ) -> Result<(), MountGuardError>;
    /// Umount.
    fn umount(&self, target: &Path) -> Result<(), MountGuardError>;
    /// Mkdir mode 0700.
    fn mkdir_mode_0700(&self, path: &Path) -> Result<(), MountGuardError>;
    /// Rmdir.
    fn rmdir(&self, path: &Path) -> Result<(), MountGuardError>;
}

/// RAII mount guard.
pub struct MountGuard<O: MountOps + 'static> {
    ops: Arc<O>,
    target: PathBuf,
    mounted: bool,
}

impl<O: MountOps> MountGuard<O> {
    /// Adopt an *already-mounted* path: the guard will only run umount/rmdir
    /// on Drop, but does not perform the mount itself.  Used when the mount
    /// happens through a different code path (e.g. via the
    /// [`crate::mount::usb`] helpers).
    #[must_use]
    pub fn adopt(ops: Arc<O>, target: PathBuf) -> Self {
        Self {
            ops,
            target,
            mounted: true,
        }
    }

    /// Create tmpfs mount.
    pub fn new_tmpfs(ops: Arc<O>, base: &Path, session_id: &str) -> Result<Self, MountGuardError> {
        if !session_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            || session_id.is_empty()
            || session_id.len() > 64
        {
            return Err(MountGuardError::InvalidSessionId {
                reason: "must match [A-Za-z0-9_-]{1,64}".to_string(),
            });
        }
        let target = base.join(session_id);
        ops.mkdir_mode_0700(&target)?;
        ops.mount(
            Path::new("tmpfs"),
            &target,
            "tmpfs",
            MountFlags::NOSUID
                | MountFlags::NODEV
                | MountFlags::NOEXEC
                | MountFlags::RO
                | MountFlags::NOATIME,
            Some("size=4m,mode=0700"),
        )?;
        Ok(Self {
            ops,
            target,
            mounted: true,
        })
    }
}

/// How many extra `rmdir` attempts `Drop` makes when the kernel still
/// reports the mountpoint busy after the lazy (`MNT_DETACH`) umount.
const RMDIR_BUSY_RETRIES: u32 = 5;
/// Delay between busy-`rmdir` retries.
const RMDIR_BUSY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

/// OS error code reported when a directory cannot be removed because it is
/// still in use: `EBUSY` on Unix, `ERROR_SHARING_VIOLATION` on Windows.
#[cfg(unix)]
pub(crate) const RMDIR_BUSY_ERRNO: i32 = libc::EBUSY;
/// See [`RMDIR_BUSY_ERRNO`].
#[cfg(windows)]
pub(crate) const RMDIR_BUSY_ERRNO: i32 = 32;

/// `true` when the error is a "directory busy" coming from `rmdir`.
fn rmdir_is_busy(err: &MountGuardError) -> bool {
    matches!(
        err,
        MountGuardError::Rmdir { source, .. }
            if source.raw_os_error() == Some(RMDIR_BUSY_ERRNO)
    )
}

impl<O: MountOps> Drop for MountGuard<O> {
    fn drop(&mut self) {
        if self.mounted {
            if let Err(err) = self.ops.umount(&self.target) {
                tracing::warn!(target: "tessera.mount", error = %err, "umount failed");
            }
        }
        // `MNT_DETACH` is lazy: the kernel may finalise the unmount slightly
        // after `umount2` returns (or only once the last open descriptor
        // goes away), so the first `rmdir` can hit `EBUSY` even after a
        // successful umount.  Poll a few times before giving up; a leftover
        // directory is picked up by the daemon's startup sweep of
        // `/run/tessera/mounts` otherwise.
        let mut attempts = 0;
        loop {
            match self.ops.rmdir(&self.target) {
                Ok(()) => break,
                Err(err) if attempts < RMDIR_BUSY_RETRIES && rmdir_is_busy(&err) => {
                    attempts += 1;
                    std::thread::sleep(RMDIR_BUSY_RETRY_DELAY);
                }
                Err(err) => {
                    tracing::warn!(target: "tessera.mount", error = %err, "rmdir failed");
                    break;
                }
            }
        }
    }
}

/// Real mount operations placeholder for Stage 1.
pub struct RealMountOps;

impl MountOps for RealMountOps {
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

    #[cfg(target_os = "linux")]
    fn umount(&self, target: &Path) -> Result<(), MountGuardError> {
        // `MNT_DETACH` (lazy unmount) lets us tear the mount down even if a
        // descriptor is still open elsewhere; the kernel finalises the
        // unmount when the last user of the mount goes away.  This matches
        // the semantics we want for an RAII guard that runs in `Drop`.
        nix::mount::umount2(target, nix::mount::MntFlags::MNT_DETACH).map_err(|errno| {
            MountGuardError::Umount {
                target: target.to_path_buf(),
                source: std::io::Error::from_raw_os_error(errno as i32),
            }
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn umount(&self, _target: &Path) -> Result<(), MountGuardError> {
        // Non-Linux dev paths cannot exercise mount(2); calling code only
        // reaches this on macOS during cargo check / unit tests where the
        // mount itself is a stub, so umount becomes a documented no-op.
        Ok(())
    }

    fn mkdir_mode_0700(&self, path: &Path) -> Result<(), MountGuardError> {
        std::fs::create_dir_all(path).map_err(|source| MountGuardError::Mkdir {
            path: path.to_path_buf(),
            source,
        })
    }

    fn rmdir(&self, path: &Path) -> Result<(), MountGuardError> {
        std::fs::remove_dir(path).map_err(|source| MountGuardError::Rmdir {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Mount operations for a volume the operating system mounted on its own.
///
/// Windows attaches removable media itself, so the flow's mount step has
/// nothing to do: the path is already there, and it must still be there when
/// the attempt ends, whatever the verdict was. Teardown is therefore empty on
/// purpose — an attempt that failed must leave the machine exactly as it found
/// it, and unmounting media the OS owns would be a change no login is entitled
/// to make.
///
/// Pair it with [`MountGuard::adopt`], which is the only constructor that does
/// not mount. [`MountOps::mount`] refuses rather than pretending: reaching it
/// means something tried to *create* a mount through a set of operations that
/// exists precisely because there is nothing to create.
#[derive(Debug, Default)]
pub struct SystemMountedOps;

impl MountOps for SystemMountedOps {
    fn mount(
        &self,
        _source: &Path,
        target: &Path,
        _fs_type: &str,
        _flags: MountFlags,
        _data: Option<&str>,
    ) -> Result<(), MountGuardError> {
        Err(MountGuardError::Mount {
            target: target.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "the volume is mounted by the operating system; adopt it instead",
            ),
        })
    }

    fn umount(&self, _target: &Path) -> Result<(), MountGuardError> {
        Ok(())
    }

    fn mkdir_mode_0700(&self, _path: &Path) -> Result<(), MountGuardError> {
        Ok(())
    }

    fn rmdir(&self, _path: &Path) -> Result<(), MountGuardError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Mock ops whose `rmdir` fails `fail_times` times with the given raw OS
    /// error before succeeding; counts every call.
    struct FlakyRmdirOps {
        rmdir_calls: AtomicU32,
        fail_times: u32,
        raw_os_error: i32,
    }

    impl FlakyRmdirOps {
        fn new(fail_times: u32, raw_os_error: i32) -> Self {
            Self {
                rmdir_calls: AtomicU32::new(0),
                fail_times,
                raw_os_error,
            }
        }
    }

    impl MountOps for FlakyRmdirOps {
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
        fn umount(&self, _target: &Path) -> Result<(), MountGuardError> {
            Ok(())
        }
        fn mkdir_mode_0700(&self, _path: &Path) -> Result<(), MountGuardError> {
            Ok(())
        }
        fn rmdir(&self, path: &Path) -> Result<(), MountGuardError> {
            let n = self.rmdir_calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                return Err(MountGuardError::Rmdir {
                    path: path.to_path_buf(),
                    source: std::io::Error::from_raw_os_error(self.raw_os_error),
                });
            }
            Ok(())
        }
    }

    #[test]
    fn drop_retries_rmdir_on_ebusy_until_success() {
        let ops = Arc::new(FlakyRmdirOps::new(2, RMDIR_BUSY_ERRNO));
        drop(MountGuard::adopt(ops.clone(), PathBuf::from("/tmp/x")));
        assert_eq!(ops.rmdir_calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn drop_gives_up_after_max_ebusy_retries() {
        let ops = Arc::new(FlakyRmdirOps::new(u32::MAX, RMDIR_BUSY_ERRNO));
        drop(MountGuard::adopt(ops.clone(), PathBuf::from("/tmp/x")));
        // Initial attempt + RMDIR_BUSY_RETRIES retries, then WARN (no panic).
        assert_eq!(
            ops.rmdir_calls.load(Ordering::SeqCst),
            1 + RMDIR_BUSY_RETRIES
        );
    }

    #[test]
    fn adopting_a_system_mounted_volume_leaves_it_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let volume = dir.path().join("volume");
        std::fs::create_dir(&volume).unwrap();
        std::fs::write(volume.join("user.p12"), b"payload").unwrap();

        drop(MountGuard::adopt(
            Arc::new(SystemMountedOps),
            volume.clone(),
        ));

        assert!(volume.is_dir(), "the guard must not remove an OS mount");
        assert!(
            volume.join("user.p12").is_file(),
            "the guard must not touch the contents of an OS mount"
        );
    }

    #[test]
    fn system_mounted_ops_refuse_to_mount() {
        let err = SystemMountedOps
            .mount(
                Path::new("E:"),
                Path::new("E:\\"),
                "exfat",
                MountFlags::RO,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, MountGuardError::Mount { .. }));
    }

    #[test]
    fn drop_does_not_retry_non_ebusy_rmdir_errors() {
        // "No such file or directory": ENOENT on Unix, ERROR_FILE_NOT_FOUND
        // on Windows — same numeric value, and on neither platform the code
        // that triggers a retry.
        const NOT_FOUND: i32 = 2;
        let ops = Arc::new(FlakyRmdirOps::new(u32::MAX, NOT_FOUND));
        drop(MountGuard::adopt(ops.clone(), PathBuf::from("/tmp/x")));
        assert_eq!(ops.rmdir_calls.load(Ordering::SeqCst), 1);
    }
}

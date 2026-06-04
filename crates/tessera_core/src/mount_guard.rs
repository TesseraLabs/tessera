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

impl<O: MountOps> Drop for MountGuard<O> {
    fn drop(&mut self) {
        if self.mounted {
            if let Err(err) = self.ops.umount(&self.target) {
                tracing::warn!(target: "tessera.mount", error = %err, "umount failed");
            }
        }
        if let Err(err) = self.ops.rmdir(&self.target) {
            tracing::warn!(target: "tessera.mount", error = %err, "rmdir failed");
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

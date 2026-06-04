//! Mount USB block devices read-only with hardening flags.
//!
//! Architecture:
//!
//! - [`Mounter`] is a small trait that abstracts the actual `mount(2)` call.
//!   Production code wires it to [`NixMounter`] (Linux only); tests inject
//!   a [`MockMounter`] that just records the call.
//! - [`mount_usb_device`] is a high-level helper that
//!   1. validates the filesystem type against a hard-coded allowlist,
//!   2. picks a fixed set of hardening flags (`MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RDONLY|MS_NOATIME`),
//!   3. delegates the actual mount to a [`Mounter`].
//!
//! The result is a [`MountGuard`] reusing the stage-1 RAII guard.

use crate::error::MountGuardError;
use crate::mount_guard::{MountFlags, MountGuard};
use crate::usb::UsbDevice;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Filesystem allowlist.
///
/// `ntfs` is included only because we mount everything `MS_RDONLY`; we never
/// allow ntfs writes.
pub const ALLOWED_FS: &[&str] = &["vfat", "exfat", "ext4", "ntfs"];

/// Errors returned by [`mount_usb_device`].
#[derive(Debug, Error)]
pub enum MountError {
    /// `mount(2)` syscall failure.
    #[error("mount(2) failed: {0}")]
    MountSyscall(#[source] std::io::Error),

    /// Filesystem type is not in the allowlist.
    #[error("filesystem type not in allowlist: {0}")]
    UnsupportedFs(String),

    /// Mountpoint path is unusable.
    #[error("mountpoint invalid: {0}")]
    MountpointInvalid(PathBuf),

    /// Underlying mount-guard infrastructure rejected the request.
    #[error(transparent)]
    Guard(#[from] MountGuardError),

    /// USB mounting is not available on this platform.
    #[error("USB mounting is not supported on this platform")]
    UnsupportedPlatform,
}

/// Trait abstracting the underlying `mount(2)` call, so tests don't need
/// a Linux kernel.
pub trait Mounter {
    /// Mount `source` (a block device path) at `target` with `fs_type`.
    ///
    /// # Errors
    ///
    /// Implementation-defined; production-grade impls return
    /// [`MountError::MountSyscall`].
    fn mount(
        &self,
        source: &Path,
        target: &Path,
        fs_type: &str,
        flags: MountFlags,
    ) -> Result<(), MountError>;
}

/// Production [`Mounter`] backed by `nix::mount::mount` (Linux only).
#[derive(Debug, Default, Clone)]
pub struct NixMounter;

impl Mounter for NixMounter {
    fn mount(
        &self,
        source: &Path,
        target: &Path,
        fs_type: &str,
        flags: MountFlags,
    ) -> Result<(), MountError> {
        #[cfg(target_os = "linux")]
        {
            use nix::mount::MsFlags;
            let mut ms = MsFlags::empty();
            if flags.contains(MountFlags::NOSUID) {
                ms |= MsFlags::MS_NOSUID;
            }
            if flags.contains(MountFlags::NODEV) {
                ms |= MsFlags::MS_NODEV;
            }
            if flags.contains(MountFlags::NOEXEC) {
                ms |= MsFlags::MS_NOEXEC;
            }
            if flags.contains(MountFlags::RO) {
                ms |= MsFlags::MS_RDONLY;
            }
            if flags.contains(MountFlags::NOATIME) {
                ms |= MsFlags::MS_NOATIME;
            }
            nix::mount::mount(Some(source), target, Some(fs_type), ms, None::<&str>).map_err(
                |errno| MountError::MountSyscall(std::io::Error::from_raw_os_error(errno as i32)),
            )?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (source, target, fs_type, flags);
            Err(MountError::UnsupportedPlatform)
        }
    }
}

/// Test [`Mounter`] that records the last invocation and never touches the
/// kernel.
#[derive(Debug, Default)]
pub struct MockMounter {
    /// All mount calls in order, captured for assertions.
    pub calls: std::sync::Mutex<Vec<MockMountCall>>,
    /// If set, the next call returns this error verbatim instead of
    /// recording.  After firing once it is cleared.
    pub fail_with: std::sync::Mutex<Option<std::io::ErrorKind>>,
}

/// A single mock mount invocation.
#[derive(Debug, Clone)]
pub struct MockMountCall {
    /// Source block device path.
    pub source: PathBuf,
    /// Target mountpoint path.
    pub target: PathBuf,
    /// Filesystem type.
    pub fs_type: String,
    /// Mount flags.
    pub flags: MountFlags,
}

impl Mounter for MockMounter {
    fn mount(
        &self,
        source: &Path,
        target: &Path,
        fs_type: &str,
        flags: MountFlags,
    ) -> Result<(), MountError> {
        if let Some(kind) = self
            .fail_with
            .lock()
            .map_err(|e| {
                MountError::MountSyscall(std::io::Error::other(format!("mock lock: {e}")))
            })?
            .take()
        {
            return Err(MountError::MountSyscall(std::io::Error::from(kind)));
        }
        let mut g = self.calls.lock().map_err(|e| {
            MountError::MountSyscall(std::io::Error::other(format!("mock lock: {e}")))
        })?;
        g.push(MockMountCall {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            fs_type: fs_type.to_string(),
            flags,
        });
        Ok(())
    }
}

/// Hardening flags applied to every USB mount.
fn hardened_flags() -> MountFlags {
    MountFlags::NOSUID
        | MountFlags::NODEV
        | MountFlags::NOEXEC
        | MountFlags::RO
        | MountFlags::NOATIME
}

/// Filesystem-type selection: prefer `dev.fs_type`, otherwise hint to the
/// caller that they need to know.
fn select_fs_type(dev: &UsbDevice) -> Result<String, MountError> {
    if let Some(fs) = &dev.fs_type {
        return Ok(fs.clone());
    }
    // No autodetection: udev is the source of truth.  If `ID_FS_TYPE` was
    // empty, the device probably has no filesystem (raw partition table) or
    // udev hasn't finished probing it.
    Err(MountError::UnsupportedFs("(unknown)".to_string()))
}

/// Mount a USB device using the production [`NixMounter`] +
/// [`crate::mount_guard::RealMountOps`] for cleanup.
///
/// On non-Linux this returns [`MountError::UnsupportedPlatform`].
///
/// # Errors
///
/// See [`MountError`].
#[cfg(target_os = "linux")]
pub fn mount_usb_device(
    dev: &UsbDevice,
    mountpoint: &Path,
) -> Result<MountGuard<crate::mount_guard::RealMountOps>, MountError> {
    use crate::mount_guard::RealMountOps;
    use std::sync::Arc;

    if !mountpoint.exists() {
        return Err(MountError::MountpointInvalid(mountpoint.to_path_buf()));
    }
    let fs = select_fs_type(dev)?;
    if !ALLOWED_FS.contains(&fs.as_str()) {
        return Err(MountError::UnsupportedFs(fs));
    }
    // Real mount(2):
    NixMounter.mount(&dev.devnode, mountpoint, &fs, hardened_flags())?;
    // Hand the guard a `RealMountOps` so umount/rmdir on Drop go through the
    // real filesystem.  The guard adopts the existing mount.
    let guard = MountGuard::adopt(Arc::new(RealMountOps), mountpoint.to_path_buf());
    Ok(guard)
}

/// Stub for non-Linux targets — preserves the public API surface so
/// downstream code can be written portably.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::missing_const_for_fn)]
pub fn mount_usb_device(
    _dev: &UsbDevice,
    _mountpoint: &Path,
) -> Result<MountGuard<crate::mount_guard::RealMountOps>, MountError> {
    Err(MountError::UnsupportedPlatform)
}

/// Test-only entry point — same logic as [`mount_usb_device`] but the
/// caller injects the `Mounter`.  Returns `()` (no guard) because tests
/// don't have a real mount to clean up.
///
/// # Errors
///
/// See [`MountError`].
pub fn mount_usb_device_with<M: Mounter>(
    mounter: &M,
    dev: &UsbDevice,
    mountpoint: &Path,
) -> Result<(), MountError> {
    if !mountpoint.exists() {
        return Err(MountError::MountpointInvalid(mountpoint.to_path_buf()));
    }
    let fs = select_fs_type(dev)?;
    if !ALLOWED_FS.contains(&fs.as_str()) {
        return Err(MountError::UnsupportedFs(fs));
    }
    mounter.mount(&dev.devnode, mountpoint, &fs, hardened_flags())?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dev_with_fs(fs: Option<&str>) -> UsbDevice {
        UsbDevice {
            devnode: PathBuf::from("/dev/sdz1"),
            serial: Some("TEST".into()),
            vid: 0x1234,
            pid: 0x5678,
            fs_type: fs.map(str::to_string),
        }
    }

    #[test]
    fn rejects_disallowed_fs() {
        let mp = tempfile::tempdir().unwrap();
        let dev = dev_with_fs(Some("xfs"));
        let m = MockMounter::default();
        let err = mount_usb_device_with(&m, &dev, mp.path()).unwrap_err();
        match err {
            MountError::UnsupportedFs(s) => assert_eq!(s, "xfs"),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(m.calls.lock().unwrap().is_empty(), "must not call mount");
    }

    #[test]
    fn rejects_unknown_fs() {
        let mp = tempfile::tempdir().unwrap();
        let dev = dev_with_fs(None);
        let m = MockMounter::default();
        let err = mount_usb_device_with(&m, &dev, mp.path()).unwrap_err();
        assert!(matches!(err, MountError::UnsupportedFs(_)));
    }

    #[test]
    fn rejects_missing_mountpoint() {
        let dev = dev_with_fs(Some("vfat"));
        let bogus = PathBuf::from("/this/does/not/exist/hopefully/abcxyz");
        let m = MockMounter::default();
        let err = mount_usb_device_with(&m, &dev, &bogus).unwrap_err();
        assert!(matches!(err, MountError::MountpointInvalid(_)));
    }

    #[test]
    fn accepts_vfat_with_hardened_flags() {
        let mp = tempfile::tempdir().unwrap();
        let dev = dev_with_fs(Some("vfat"));
        let m = MockMounter::default();
        mount_usb_device_with(&m, &dev, mp.path()).unwrap();
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.source, PathBuf::from("/dev/sdz1"));
        assert_eq!(call.target, mp.path());
        assert_eq!(call.fs_type, "vfat");
        let want = MountFlags::NOSUID
            | MountFlags::NODEV
            | MountFlags::NOEXEC
            | MountFlags::RO
            | MountFlags::NOATIME;
        assert_eq!(call.flags, want);
    }

    #[test]
    fn accepts_each_allowlisted_fs() {
        for fs in ALLOWED_FS {
            let mp = tempfile::tempdir().unwrap();
            let dev = dev_with_fs(Some(fs));
            let m = MockMounter::default();
            mount_usb_device_with(&m, &dev, mp.path()).unwrap();
            assert_eq!(m.calls.lock().unwrap().len(), 1, "fs={fs}");
        }
    }

    #[test]
    fn propagates_mount_syscall_error() {
        let mp = tempfile::tempdir().unwrap();
        let dev = dev_with_fs(Some("vfat"));
        let m = MockMounter::default();
        *m.fail_with.lock().unwrap() = Some(std::io::ErrorKind::PermissionDenied);
        let err = mount_usb_device_with(&m, &dev, mp.path()).unwrap_err();
        assert!(matches!(err, MountError::MountSyscall(_)));
    }
}

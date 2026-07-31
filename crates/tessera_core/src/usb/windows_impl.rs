//! Removable-volume enumeration on Windows.
//!
//! There is no udev here, and no need for one: Windows mounts removable media
//! itself and exposes it as a drive letter. Enumeration therefore walks the
//! logical drives, keeps the ones the OS classifies as removable, and returns
//! them through the same [`UsbEnumerator`](super::UsbEnumerator) contract the
//! udev implementation satisfies.
//!
//! What is deliberately *not* done here:
//!
//! * No filtering by `vid`/`pid`. A drive letter carries no USB descriptor,
//!   and the values would have to be pulled from the device tree behind the
//!   volume. That work belongs with removal handling, which is what needs the
//!   descriptor identity in the first place; until then both fields are zero
//!   and no allow-list is consulted.
//! * No mounting. The volume is already mounted, and this module never changes
//!   the state of the system — every call below only reads.
//!
//! Anything that is not removable is excluded by construction: `GetDriveTypeW`
//! separates the system disk (`DRIVE_FIXED`), network drives (`DRIVE_REMOTE`)
//! and optical drives (`DRIVE_CDROM`) from removable media, and only
//! `DRIVE_REMOVABLE` is accepted.
//!
//! # FFI
//!
//! All raw Win32 calls live here so the rest of the crate stays under
//! `unsafe_code = "deny"`. Every `unsafe` block wraps exactly one call and
//! carries the reasoning that makes it sound.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::ptr;

use windows_sys::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW,
};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_REMOVABLE;

use super::{UsbDevice, UsbError};

/// Characters reserved for the `\\?\Volume{GUID}\` form, which is 49
/// characters wide, plus the terminator and room to spare.
const VOLUME_NAME_CHARS: u32 = 64;

/// Characters reserved for a file-system name: `MAX_PATH` plus the
/// terminator, as `GetVolumeInformationW` documents for this buffer.
const FS_NAME_CHARS: u32 = 261;

/// Enumerate the removable volumes the operating system currently has mounted.
///
/// Drive letters are visited in alphabetical order, so the result is stable
/// across calls for an unchanged set of volumes — the caller binds its attempt
/// to the first volume that carries a credential, and a non-deterministic
/// order would make which volume that is depend on the run.
pub(super) fn enumerate_removable_volumes() -> Result<Vec<UsbDevice>, UsbError> {
    // SAFETY: the call takes no arguments and only reads kernel state.
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        // Every Windows installation has at least the system volume, so an
        // empty bitmask is the documented failure return and not a machine
        // without drives.
        return Err(UsbError::Io(std::io::Error::last_os_error()));
    }
    let mut out = Vec::new();
    for (letter, bit) in (b'A'..=b'Z').zip(0u32..) {
        if mask & (1u32 << bit) == 0 {
            continue;
        }
        if let Some(device) = inspect_drive(letter) {
            out.push(device);
        }
    }
    Ok(out)
}

/// Describe one drive letter, or `None` when it is not usable removable media.
fn inspect_drive(letter: u8) -> Option<UsbDevice> {
    let root = format!("{}:\\", char::from(letter));
    let root_w = wide(&root);

    // SAFETY: `root_w` is a NUL-terminated UTF-16 buffer owned by this frame,
    // so it stays valid for the duration of the call.
    let drive_type = unsafe { GetDriveTypeW(root_w.as_ptr()) };
    if drive_type != DRIVE_REMOVABLE {
        return None;
    }

    // A removable drive letter with no media in it answers here rather than
    // above: the volume exists as a mount point, but there is nothing to read.
    // It cannot hold a credential, so it is not a candidate.
    let fs_type = volume_filesystem(&root_w)?;

    Some(UsbDevice {
        devnode: PathBuf::from(&root),
        // The volume GUID is the volume's own identity, stable while the
        // volume exists and independent of which letter it was assigned. When
        // it cannot be read the device stays serial-less, and what that costs
        // is decided by the caller's monitoring policy, not here.
        serial: volume_guid(&root_w),
        // See the module docs: no USB descriptor is read in this wave.
        vid: 0,
        pid: 0,
        fs_type: Some(fs_type),
    })
}

/// The `\\?\Volume{GUID}\` name of the volume mounted at `root_w`.
fn volume_guid(root_w: &[u16]) -> Option<String> {
    let mut buf = [0u16; VOLUME_NAME_CHARS as usize];
    // SAFETY: `root_w` is NUL-terminated and `buf` is a live buffer of exactly
    // the character count passed alongside it; the callee writes no further.
    let ok = unsafe {
        GetVolumeNameForVolumeMountPointW(root_w.as_ptr(), buf.as_mut_ptr(), VOLUME_NAME_CHARS)
    };
    if ok == 0 {
        return None;
    }
    from_wide(&buf)
}

/// The file-system name (`FAT32`, `NTFS`, `exFAT`, ...) of the volume mounted
/// at `root_w`, or `None` when the volume cannot be interrogated at all.
fn volume_filesystem(root_w: &[u16]) -> Option<String> {
    let mut buf = [0u16; FS_NAME_CHARS as usize];
    // SAFETY: `root_w` is NUL-terminated; `buf` is a live buffer of exactly
    // the character count passed alongside it. The null pointers are the
    // documented way to decline the optional out-parameters.
    let ok = unsafe {
        GetVolumeInformationW(
            root_w.as_ptr(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            buf.as_mut_ptr(),
            FS_NAME_CHARS,
        )
    };
    if ok == 0 {
        return None;
    }
    from_wide(&buf)
}

/// NUL-terminated UTF-16 encoding of `s`, for the `PCWSTR` parameters above.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decode a NUL-terminated UTF-16 buffer, or `None` when it is empty.
fn from_wide(buf: &[u16]) -> Option<String> {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let slice = buf.get(..len)?;
    if slice.is_empty() {
        return None;
    }
    Some(OsString::from_wide(slice).to_string_lossy().into_owned())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // These exercise the real Win32 surface and therefore run on the bench,
    // not in the cross-platform suite.

    #[test]
    fn enumeration_succeeds_and_excludes_the_system_drive() {
        let devices = enumerate_removable_volumes().unwrap();
        for dev in &devices {
            let path = dev.devnode.to_string_lossy().to_uppercase();
            assert!(
                path.ends_with(":\\") && path.len() == 3,
                "expected a drive root, got {path}"
            );
            assert_ne!(path, "C:\\", "the system drive is not removable media");
            assert_eq!((dev.vid, dev.pid), (0, 0), "no descriptor is read yet");
        }
    }

    #[test]
    fn enumeration_order_is_alphabetical() {
        let devices = enumerate_removable_volumes().unwrap();
        let mut sorted = devices.clone();
        sorted.sort_by(|a, b| a.devnode.cmp(&b.devnode));
        assert_eq!(
            devices, sorted,
            "candidate order must not depend on the run"
        );
    }

    #[test]
    fn wide_round_trips_through_from_wide() {
        let w = wide("E:\\");
        assert_eq!(from_wide(&w).as_deref(), Some("E:\\"));
    }

    #[test]
    fn from_wide_rejects_an_empty_buffer() {
        assert_eq!(from_wide(&[0u16; 8]), None);
    }
}

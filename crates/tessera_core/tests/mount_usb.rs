//! Integration tests for [`tessera_core::mount::usb`].
//!
//! These require Linux + root + a real block device.  Always `#[ignore]`'d.
//!
//! Run manually with:
//!
//! ```bash
//! sudo -E cargo test -p tessera_core --test mount_usb -- --ignored
//! ```

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::manual_let_else
)]

use std::path::PathBuf;
use tessera_core::mount::usb::{mount_usb_device, MountError};
use tessera_core::usb::UsbDevice;

#[test]
#[ignore = "requires root + a real USB device with a vfat partition"]
fn mounts_real_device_and_unmounts_on_drop() {
    // Caller must export e.g. CERTAUTH_TEST_DEVNODE=/dev/sdb1.
    let dev_path =
        std::env::var("CERTAUTH_TEST_DEVNODE").expect("set CERTAUTH_TEST_DEVNODE=/dev/sdX to run");
    let dev = UsbDevice {
        devnode: PathBuf::from(dev_path),
        serial: Some("integration".into()),
        vid: 0,
        pid: 0,
        fs_type: Some("vfat".into()),
    };
    let mp = tempfile::tempdir().unwrap();
    {
        let _g = mount_usb_device(&dev, mp.path()).expect("mount");
        // Drop unmounts.
    }
}

#[test]
#[ignore = "requires root + a USB device with an unsupported fs"]
fn rejects_disallowed_fs_on_real_kernel() {
    let dev = UsbDevice {
        devnode: PathBuf::from("/dev/sdX-bogus"),
        serial: None,
        vid: 0,
        pid: 0,
        fs_type: Some("xfs".into()),
    };
    let mp = tempfile::tempdir().unwrap();
    let err = match mount_usb_device(&dev, mp.path()) {
        Err(e) => e,
        Ok(_) => panic!("expected UnsupportedFs error"),
    };
    assert!(matches!(err, MountError::UnsupportedFs(_)));
}

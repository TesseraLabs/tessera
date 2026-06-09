//! Integration tests against the real udev backend.
//!
//! These are gated by `#[ignore]` because they require Linux + a real USB
//! block device.  Run manually:
//!
//! ```bash
//! cargo test -p tessera_core --test usb_real -- --ignored
//! ```

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use tessera_core::usb::{wait_for_usb_devices, UsbError};
use std::time::Duration;

#[test]
#[ignore = "requires Linux + a real plugged-in USB block device"]
fn waits_and_returns_device() {
    let devs = wait_for_usb_devices(Duration::from_secs(30), &[], 8).expect("device");
    assert!(!devs.is_empty());
    assert!(!devs[0].devnode.as_os_str().is_empty());
}

#[test]
#[ignore = "no device — short timeout exercises the timeout path"]
fn timeouts_when_no_device() {
    let err =
        wait_for_usb_devices(Duration::from_millis(200), &[(0xDEAD, 0xBEEF)], 8).unwrap_err();
    assert!(matches!(err, UsbError::Timeout));
}

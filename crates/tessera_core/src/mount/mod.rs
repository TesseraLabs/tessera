//! USB-specific mount helpers.
//!
//! The lower-level RAII guard lives in [`crate::mount_guard`]; this module
//! adds the USB-specific glue: filesystem allowlist, mount flag policy and
//! a thin wrapper that wires [`crate::usb::UsbDevice`] up to a [`crate::mount_guard::MountGuard`].

pub mod usb;

pub use crate::mount_guard::{MountFlags, MountGuard, MountOps, RealMountOps};

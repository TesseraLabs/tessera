//! Errors raised by USB discovery and enumeration.

use std::path::PathBuf;
use thiserror::Error;

/// Errors returned by [`crate::usb::wait_for_usb_devices`] and the underlying
/// [`crate::usb::UsbEnumerator`] implementations.
#[derive(Debug, Error)]
pub enum UsbError {
    /// Wrapped `udev` failure.
    ///
    /// `udev::Error` is not `Clone` and we want a stable error surface, so we
    /// stringify here.  Callers should treat this as opaque.
    #[error("udev error: {0}")]
    Udev(String),

    /// Generic I/O failure during enumeration / monitor polling.
    #[error("usb i/o error: {0}")]
    Io(#[source] std::io::Error),

    /// No matching device appeared before the timeout elapsed.
    #[error("timeout waiting for USB device")]
    Timeout,

    /// Enumeration completed but no device matched the filter.
    ///
    /// Distinct from [`UsbError::Timeout`] because there was no monitor wait
    /// (used by single-shot enumerators in tests).
    #[error("no matching USB device found")]
    NoMatchingDevice,

    /// A device record was missing a property we require to construct a
    /// [`crate::usb::UsbDevice`].
    #[error("device missing required property: {0}")]
    MissingProperty(String),

    /// USB discovery is not available on the current platform.
    #[error("USB discovery is not supported on this platform")]
    UnsupportedPlatform,

    /// Whole-device has no filesystem and more child partitions with an
    /// allow-listed FS were observed than `max_usb_partitions` permits.
    /// Fail-closed against an attacker with physical access plumbing in a
    /// huge multi-partition device.
    #[error("too many USB partitions on {devnode}: {count} > limit {limit}")]
    TooManyPartitions {
        /// Parent whole-device devnode (e.g. `/dev/sdb`).
        devnode: PathBuf,
        /// Number of candidate child partitions observed.
        count: usize,
        /// Configured upper bound (`max_usb_partitions`).
        limit: usize,
    },
}

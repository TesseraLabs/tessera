//! Markers of the time the device can actually trust.
//!
//! The wall clock of an offline device is set by whoever stands in front of it,
//! so the lifetime of a pending code attempt is measured against two values
//! that a person at the console cannot move forward at will:
//!
//! - the boot identifier, which the kernel draws afresh on every boot, so a
//!   restart is visible as a change of value rather than as a gap in a
//!   timestamp;
//! - the time since that boot, which only ever grows within one boot.
//!
//! Together they answer the one question the one-time nonce depends on: is the
//! attempt that was started still the attempt that is being finished, on the
//! same running system. A reboot answers no; a clock dragged backwards answers
//! no; anything else is measured in whole seconds since boot.
//!
//! Both values come from `/proc`, which is where the running kernel states
//! them. A device that cannot produce them does not get a code login: the
//! method fails closed rather than measure a lifetime against a clock an
//! engineer owns.

use std::io;
use std::time::Duration;

/// Path the kernel publishes the boot identifier at.
#[cfg(target_os = "linux")]
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// Path the kernel publishes the time since boot at.
#[cfg(target_os = "linux")]
const UPTIME_PATH: &str = "/proc/uptime";

/// Longest boot identifier accepted from the kernel.
///
/// The value is a formatted UUID; the bound is here so that a `/proc` path
/// replaced by something else on a device with an unexpected mount layout
/// cannot be read into memory unbounded.
const MAX_BOOT_ID_LEN: usize = 64;

/// The markers of one running system, read at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootMarkers {
    boot_id: String,
    since_boot: Duration,
}

impl BootMarkers {
    /// Reads the markers of the running system.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] when either value cannot be read
    /// or parsed, and [`io::ErrorKind::Unsupported`] on a target whose kernel
    /// publishes neither.
    pub fn read() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let boot_id = std::fs::read_to_string(BOOT_ID_PATH)?;
            let uptime = std::fs::read_to_string(UPTIME_PATH)?;
            Self::from_proc_text(&boot_id, &uptime)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the kernel of this platform publishes no boot markers",
            ))
        }
    }

    /// Builds the markers from explicit values.
    ///
    /// Tests use this to stand in for a reboot (a different identifier) and for
    /// a monotonic clock dragged backwards (a smaller `since_boot`), neither of
    /// which can be produced by reading a real `/proc` twice.
    #[must_use]
    pub fn new(boot_id: impl Into<String>, since_boot: Duration) -> Self {
        Self {
            boot_id: boot_id.into(),
            since_boot,
        }
    }

    /// Parses the two `/proc` texts.
    ///
    /// Kept apart from the read so the parsing is testable without a Linux
    /// `/proc`: the format is the kernel's and does not vary by host.
    #[cfg_attr(
        all(not(target_os = "linux"), not(test)),
        expect(
            dead_code,
            reason = "only the Linux read path and its tests parse a /proc text"
        )
    )]
    fn from_proc_text(boot_id: &str, uptime: &str) -> io::Result<Self> {
        let boot_id = boot_id.trim();
        if boot_id.is_empty() || boot_id.len() > MAX_BOOT_ID_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the boot identifier is empty or longer than the kernel writes",
            ));
        }
        // Whole seconds: the fractional part the kernel writes is dropped rather
        // than rounded, because the value is persisted, read back and compared,
        // and a lifetime measured over a telephone call has no use for a finer
        // scale than the one it can be written down in. Taking the integer part
        // as text also keeps a floating-point conversion out of a value that
        // decides whether a pending attempt is still alive.
        let field = uptime.split_whitespace().next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "the uptime line is empty")
        })?;
        let whole = field.split('.').next().unwrap_or(field);
        let seconds: u64 = whole.parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the uptime is not a moment on a monotonic scale",
            )
        })?;
        Ok(Self {
            boot_id: boot_id.to_owned(),
            since_boot: Duration::from_secs(seconds),
        })
    }

    /// Returns the identifier of the current boot.
    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Returns the whole seconds since that boot.
    #[must_use]
    pub const fn since_boot_secs(&self) -> u64 {
        self.since_boot.as_secs()
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::BootMarkers;

    #[test]
    fn the_kernel_texts_parse_into_markers() {
        let markers = BootMarkers::from_proc_text(
            "6b1f4c5e-0000-4000-8000-000000000001\n",
            "1234.56 987.65\n",
        )
        .unwrap();
        assert_eq!(markers.boot_id(), "6b1f4c5e-0000-4000-8000-000000000001");
        assert_eq!(markers.since_boot_secs(), 1234);
    }

    #[test]
    fn an_empty_boot_identifier_is_refused() {
        assert!(BootMarkers::from_proc_text("  \n", "1.0 1.0").is_err());
    }

    #[test]
    fn an_unparseable_uptime_is_refused() {
        assert!(BootMarkers::from_proc_text("boot", "soon 1.0").is_err());
        assert!(BootMarkers::from_proc_text("boot", "-1.0 1.0").is_err());
        assert!(BootMarkers::from_proc_text("boot", "").is_err());
    }
}

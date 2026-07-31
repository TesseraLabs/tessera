//! USB block-device discovery.
//!
//! Two-phase strategy:
//!
//! 1. **Enumerate** already-attached USB block devices (sync, fast path).
//! 2. **Monitor** for new "add" events until either a match shows up or the
//!    caller-supplied timeout elapses.
//!
//! On Windows the same contract is served by [`RemovableVolumeEnumerator`],
//! which walks the volumes the OS has already mounted; on every other
//! platform the public API surface is preserved but every call returns
//! [`UsbError::UnsupportedPlatform`].
//!
//! Tests that need not bind to real udev should plug a mock implementation
//! of [`UsbEnumerator`] into [`wait_for_usb_with`].

pub mod error;
pub mod partition;

#[cfg(target_os = "linux")]
mod linux_impl;

#[cfg(windows)]
mod windows_impl;

pub use error::UsbError;
pub use partition::{select_partitions, PartitionCandidate};

use std::path::PathBuf;
use std::time::Duration;

/// A USB block device discovered through udev.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDevice {
    /// `/dev/...` device node.
    pub devnode: PathBuf,
    /// Best-effort serial number (`ID_SERIAL_SHORT` or `ID_SERIAL`).
    pub serial: Option<String>,
    /// USB Vendor ID (parsed from hex).
    pub vid: u16,
    /// USB Product ID (parsed from hex).
    pub pid: u16,
    /// Filesystem type as reported by blkid/udev (`vfat`, `ext4`, ...).
    pub fs_type: Option<String>,
}

/// Pluggable USB enumerator.
///
/// The production implementation calls into `udev::Enumerator`.  Tests use
/// [`MockEnumerator`] to inject a fixed list of devices without touching the
/// real udev database.
pub trait UsbEnumerator {
    /// Enumerate USB block devices currently attached to the system.
    ///
    /// `vid_pid_filter`, when non-empty, restricts the result to devices
    /// whose `(vid, pid)` matches one of the entries exactly.  An empty
    /// slice means "no filter".
    ///
    /// # Errors
    ///
    /// Returns [`UsbError::Udev`] on udev failures, [`UsbError::Io`] on raw
    /// I/O failures and [`UsbError::MissingProperty`] when a device record
    /// is too partial to be useful.
    fn enumerate(&self, vid_pid_filter: &[(u16, u16)]) -> Result<Vec<UsbDevice>, UsbError>;
}

/// Default Linux enumerator backed by `udev::Enumerator`.
///
/// On non-Linux platforms `enumerate` always returns
/// [`UsbError::UnsupportedPlatform`].
#[derive(Debug, Default)]
pub struct UdevEnumerator;

impl UsbEnumerator for UdevEnumerator {
    fn enumerate(&self, vid_pid_filter: &[(u16, u16)]) -> Result<Vec<UsbDevice>, UsbError> {
        #[cfg(target_os = "linux")]
        {
            linux_impl::enumerate_once(vid_pid_filter)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = vid_pid_filter;
            Err(UsbError::UnsupportedPlatform)
        }
    }
}

/// Enumerator over the removable volumes the operating system has mounted.
///
/// The Windows counterpart of [`UdevEnumerator`]: instead of a device tree it
/// walks drive letters, keeping only what the OS classifies as removable
/// media. Non-Windows builds return [`UsbError::UnsupportedPlatform`].
///
/// `vid_pid_filter` is accepted for trait compatibility and deliberately
/// ignored: a drive letter carries no USB descriptor, so both fields of every
/// returned [`UsbDevice`] are zero and filtering on them could only ever
/// produce an empty result. The filter becomes meaningful together with
/// removal handling, which is what reads the descriptor identity.
#[derive(Debug, Default)]
pub struct RemovableVolumeEnumerator;

impl UsbEnumerator for RemovableVolumeEnumerator {
    fn enumerate(&self, vid_pid_filter: &[(u16, u16)]) -> Result<Vec<UsbDevice>, UsbError> {
        if !vid_pid_filter.is_empty() {
            tracing::warn!(
                target: "tessera.usb",
                entries = vid_pid_filter.len(),
                "vid/pid allow-list ignored: removable volumes expose no USB descriptor yet"
            );
        }
        #[cfg(windows)]
        {
            windows_impl::enumerate_removable_volumes()
        }
        #[cfg(not(windows))]
        {
            Err(UsbError::UnsupportedPlatform)
        }
    }
}

/// Cooperative cancellation for a bounded wait.
///
/// A wait for media is the one step of the flow that lasts as long as the
/// person in front of the device takes, so its shape decides whether a server
/// can serve anyone else meanwhile. Every waiter here holds only its own
/// borrow of an enumerator and its own deadline — no process-wide handle, no
/// lock, nothing another connection could queue behind — and consults this
/// trait between polls, so a connection that goes away releases its thread
/// instead of pinning it until the deadline.
pub trait WaitCancel: Sync {
    /// `true` once the caller no longer wants the wait to continue.
    fn is_cancelled(&self) -> bool;
}

/// A [`WaitCancel`] that never cancels: the wait ends on its own deadline.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeverCancel;

impl WaitCancel for NeverCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// A cancellation flag shared between a waiting thread and whoever may want
/// to end the wait early.
///
/// Cloning shares the flag; tripping it through any clone ends every wait
/// observing it.
#[derive(Debug, Default, Clone)]
pub struct CancelFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl CancelFlag {
    /// A fresh, untripped flag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trip the flag: every wait observing it returns
    /// [`UsbError::WaitCancelled`] at its next poll.
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl WaitCancel for CancelFlag {
    fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Mock enumerator for unit tests.
///
/// Returns a copy of its `devices` field, applying the optional VID/PID
/// filter.  `mode` controls one-shot failure modes useful for test cases
/// (e.g. simulating a transient udev error).
#[derive(Debug, Clone, Default)]
pub struct MockEnumerator {
    /// Pre-canned device list to return.
    pub devices: Vec<UsbDevice>,
    /// Optional canned error.  When set, [`UsbEnumerator::enumerate`] returns
    /// an error string identical to this value (wrapped in
    /// [`UsbError::Udev`]) instead of the device list.
    pub error: Option<String>,
}

impl UsbEnumerator for MockEnumerator {
    fn enumerate(&self, vid_pid_filter: &[(u16, u16)]) -> Result<Vec<UsbDevice>, UsbError> {
        if let Some(msg) = &self.error {
            return Err(UsbError::Udev(msg.clone()));
        }
        let out: Vec<UsbDevice> = self
            .devices
            .iter()
            .filter(|d| vid_pid_filter.is_empty() || vid_pid_filter.contains(&(d.vid, d.pid)))
            .cloned()
            .collect();
        Ok(out)
    }
}

/// Wait for one or more USB block devices, optionally filtered by an
/// allow-list of `(vid, pid)` pairs (empty slice = no filter).
///
/// On Linux this enumerates currently attached devices and then falls back
/// to a blocking udev monitor with the caller's `timeout` budget.  On
/// non-Linux platforms it returns [`UsbError::UnsupportedPlatform`]
/// immediately.
///
/// When the discovered physical device exposes a partition table, the
/// result contains one [`UsbDevice`] per viable child partition (FS in
/// the [`crate::mount::usb::ALLOWED_FS`] allowlist).  The caller is
/// expected to iterate the returned slice until a mount produces a
/// readable `.p12`.
///
/// `max_usb_partitions` is the inclusive cap on the number of child
/// partitions accepted on a single whole-disk; exceeding it produces
/// [`UsbError::TooManyPartitions`] (fail-closed against a physical
/// adversary attaching a many-partition device).
///
/// # Errors
///
/// - [`UsbError::Timeout`] — no matching device within `timeout`.
/// - [`UsbError::TooManyPartitions`] — too many viable partitions.
/// - [`UsbError::Udev`] / [`UsbError::Io`] — propagated from udev.
/// - [`UsbError::UnsupportedPlatform`] — on non-Linux targets.
pub fn wait_for_usb_devices(
    timeout: Duration,
    vid_pid_filter: &[(u16, u16)],
    max_usb_partitions: usize,
) -> Result<Vec<UsbDevice>, UsbError> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::wait_for_usb_real(timeout, vid_pid_filter, max_usb_partitions)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (timeout, vid_pid_filter, max_usb_partitions);
        Err(UsbError::UnsupportedPlatform)
    }
}

/// Test-friendly sibling of [`wait_for_usb_devices`].
///
/// Polls `enumerator.enumerate(filter)` repeatedly with a short sleep until
/// at least one device shows up or `timeout` expires.  Used by unit tests
/// where the real udev monitor is unavailable.
///
/// # Errors
///
/// As [`wait_for_usb_devices`].  Additionally surfaces enumerator errors
/// verbatim.
pub fn wait_for_usb_with<E: UsbEnumerator>(
    enumerator: &E,
    timeout: Duration,
    vid_pid_filter: &[(u16, u16)],
    poll_interval: Duration,
) -> Result<Vec<UsbDevice>, UsbError> {
    wait_for_devices_cancellable(
        enumerator,
        timeout,
        vid_pid_filter,
        poll_interval,
        &NeverCancel,
    )
}

/// Poll `enumerator` until it reports a device, `timeout` elapses, or `cancel`
/// is tripped.
///
/// This is the wait used where there is no event source to block on — the
/// Windows volume path, and any test driving a mock. It owns nothing beyond
/// its own borrows, so several of these may run at once on different threads
/// without contending; `poll_interval` bounds both how quickly a newly
/// attached volume is noticed and how quickly a cancellation is observed.
///
/// # Errors
///
/// - [`UsbError::Timeout`] — nothing appeared within `timeout`.
/// - [`UsbError::WaitCancelled`] — the caller ended the wait early.
/// - Whatever the enumerator itself returns, verbatim.
pub fn wait_for_devices_cancellable<E: UsbEnumerator>(
    enumerator: &E,
    timeout: Duration,
    vid_pid_filter: &[(u16, u16)],
    poll_interval: Duration,
    cancel: &dyn WaitCancel,
) -> Result<Vec<UsbDevice>, UsbError> {
    use std::time::Instant;
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.is_cancelled() {
            return Err(UsbError::WaitCancelled);
        }
        let now = Instant::now();
        let devs = enumerator.enumerate(vid_pid_filter)?;
        if !devs.is_empty() {
            return Ok(devs);
        }
        if now >= deadline {
            return Err(UsbError::Timeout);
        }
        let remaining = deadline.saturating_duration_since(now);
        std::thread::sleep(std::cmp::min(poll_interval, remaining));
    }
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

    fn device(vid: u16, pid: u16, fs: &str) -> UsbDevice {
        UsbDevice {
            devnode: PathBuf::from(format!("/dev/sd{vid:x}{pid:x}")),
            serial: Some(format!("S-{vid:x}-{pid:x}")),
            vid,
            pid,
            fs_type: Some(fs.to_string()),
        }
    }

    #[test]
    fn mock_enumerator_filters_by_vid_pid() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat"), device(0x3, 0x4, "ext4")],
            error: None,
        };
        let out = m.enumerate(&[(0x3, 0x4)]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].vid, 0x3);
        assert_eq!(out[0].pid, 0x4);
    }

    #[test]
    fn mock_enumerator_no_filter_returns_all() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat"), device(0x3, 0x4, "ext4")],
            error: None,
        };
        let out = m.enumerate(&[]).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn mock_enumerator_filter_matches_any_listed_pair() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat"), device(0x3, 0x4, "ext4")],
            error: None,
        };
        let out = m.enumerate(&[(0x9, 0x9), (0x3, 0x4)]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].vid, 0x3);
    }

    #[test]
    fn wait_for_usb_with_returns_devices_quickly() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat")],
            error: None,
        };
        let start = std::time::Instant::now();
        let devs = wait_for_usb_with(
            &m,
            Duration::from_secs(5),
            &[(0x1, 0x2)],
            Duration::from_millis(10),
        )
        .unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].vid, 0x1);
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn wait_for_usb_with_returns_all_when_multiple_match() {
        let m = MockEnumerator {
            devices: vec![device(0x1, 0x2, "vfat"), device(0x1, 0x2, "ext4")],
            error: None,
        };
        let devs = wait_for_usb_with(
            &m,
            Duration::from_millis(100),
            &[(0x1, 0x2)],
            Duration::from_millis(10),
        )
        .unwrap();
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].fs_type.as_deref(), Some("vfat"));
        assert_eq!(devs[1].fs_type.as_deref(), Some("ext4"));
    }

    #[test]
    fn wait_for_usb_with_times_out_when_empty() {
        let m = MockEnumerator {
            devices: vec![],
            error: None,
        };
        let start = std::time::Instant::now();
        let err = wait_for_usb_with(
            &m,
            Duration::from_millis(100),
            &[],
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(matches!(err, UsbError::Timeout));
        assert!(start.elapsed() >= Duration::from_millis(100));
        // Sanity: should not run forever.
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn wait_for_usb_with_filter_excludes_non_matching() {
        let m = MockEnumerator {
            devices: vec![device(0x9, 0x9, "vfat")],
            error: None,
        };
        let err = wait_for_usb_with(
            &m,
            Duration::from_millis(80),
            &[(0x1, 0x2)],
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert!(matches!(err, UsbError::Timeout));
    }

    #[test]
    fn cancelled_wait_is_distinguishable_from_a_timeout() {
        let m = MockEnumerator {
            devices: vec![],
            error: None,
        };
        let cancel = CancelFlag::new();
        cancel.cancel();
        let start = std::time::Instant::now();
        let err = wait_for_devices_cancellable(
            &m,
            Duration::from_secs(30),
            &[],
            Duration::from_millis(10),
            &cancel,
        )
        .unwrap_err();
        assert!(matches!(err, UsbError::WaitCancelled));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "a cancelled wait must not sit out its budget"
        );
    }

    #[test]
    fn a_cancel_flag_tripped_from_another_thread_ends_the_wait() {
        let m = MockEnumerator {
            devices: vec![],
            error: None,
        };
        let cancel = CancelFlag::new();
        let trigger = cancel.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            trigger.cancel();
        });
        let err = wait_for_devices_cancellable(
            &m,
            Duration::from_secs(30),
            &[],
            Duration::from_millis(10),
            &cancel,
        )
        .unwrap_err();
        handle.join().unwrap();
        assert!(matches!(err, UsbError::WaitCancelled));
    }

    #[test]
    fn removable_volume_enumerator_ignores_the_vid_pid_filter() {
        // On non-Windows hosts the call refuses for want of a platform, which
        // is still the answer that proves the filter never became a reason to
        // return an empty list.
        let out = RemovableVolumeEnumerator.enumerate(&[(0x1, 0x2)]);
        #[cfg(windows)]
        assert!(
            out.is_ok(),
            "enumeration must not fail on a filter: {out:?}"
        );
        #[cfg(not(windows))]
        assert!(matches!(out, Err(UsbError::UnsupportedPlatform)));
    }

    #[test]
    fn wait_for_usb_with_propagates_enumerator_error() {
        let m = MockEnumerator {
            devices: vec![],
            error: Some("simulated".into()),
        };
        let err = wait_for_usb_with(
            &m,
            Duration::from_millis(100),
            &[],
            Duration::from_millis(10),
        )
        .unwrap_err();
        match err {
            UsbError::Udev(s) => assert_eq!(s, "simulated"),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

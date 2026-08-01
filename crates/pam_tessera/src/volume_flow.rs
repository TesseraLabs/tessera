//! [`FlowIo`] over volumes the operating system has already mounted.
//!
//! This is the Windows side of credential discovery, and it is deliberately
//! thin: the difference between Windows and Linux is *where the media comes
//! from*, not what happens to it afterwards. Waiting, candidate order and the
//! rule that binds an attempt to one volume are all decided here; everything
//! from the `.p12` onwards is the same platform-neutral code the PAM module
//! drives, reached through the same trait.
//!
//! Three properties are load-bearing:
//!
//! * **The volume is never mounted or unmounted.** Windows attached it, and
//!   the attempt leaves it attached whatever the verdict — see
//!   [`SystemMountedOps`].
//! * **Candidate order is the enumerator's order**, which for removable
//!   volumes is alphabetical by drive letter. Which volume an attempt binds to
//!   must not depend on the run.
//! * **The wait is cancellable and owns nothing shared**, so a server can hold
//!   several of these at once — one per connection — and let a client that
//!   disconnects release its thread instead of pinning it until the deadline.
//!
//! The type is generic over the enumerator and free of platform code, so the
//! behaviour above is exercised by the ordinary cross-platform test suite;
//! only the enumerator behind `VolumeFlowIo::for_removable_volumes` — which
//! exists on Windows alone, and is therefore left unlinked here — is
//! platform-specific.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tessera_core::mount::usb::MountError;
use tessera_core::mount_guard::{MountGuard, SystemMountedOps};
use tessera_core::usb::{
    wait_for_devices_cancellable, CancelFlag, UsbDevice, UsbEnumerator, UsbError,
};

use crate::flow::{FlowIo, MountSession};

/// How often an unsatisfied wait re-enumerates.
///
/// Also the upper bound on how long a cancelled wait keeps its thread: the
/// flag is read once per turn of the loop.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// [`FlowIo`] backed by an enumerator of already-mounted volumes.
pub struct VolumeFlowIo<E: UsbEnumerator> {
    /// Where candidate volumes come from.
    enumerator: E,
    /// How long [`FlowIo::wait_for_usb`] waits for the first volume.
    timeout: Duration,
    /// Gap between enumeration attempts while waiting.
    poll_interval: Duration,
    /// Ends the wait early; see [`Self::cancel_handle`].
    cancel: CancelFlag,
    /// Shared by every guard this instance hands out; stateless.
    ops: Arc<SystemMountedOps>,
}

impl<E: UsbEnumerator> VolumeFlowIo<E> {
    /// Build an instance waiting up to `timeout` for the first volume.
    #[must_use]
    pub fn new(enumerator: E, timeout: Duration) -> Self {
        Self {
            enumerator,
            timeout,
            poll_interval: DEFAULT_POLL_INTERVAL,
            cancel: CancelFlag::new(),
            ops: Arc::new(SystemMountedOps),
        }
    }

    /// Override the gap between enumeration attempts.
    #[must_use]
    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    /// A handle that ends this instance's wait early.
    ///
    /// Held by whoever knows the attempt has become pointless — the thread
    /// serving the connection that asked for it, when its client goes away.
    /// Tripping it makes the pending [`FlowIo::wait_for_usb`] return
    /// [`UsbError::WaitCancelled`], which the flow reports apart from a
    /// timeout.
    #[must_use]
    pub fn cancel_handle(&self) -> CancelFlag {
        self.cancel.clone()
    }
}

#[cfg(windows)]
impl VolumeFlowIo<tessera_core::usb::RemovableVolumeEnumerator> {
    /// Build an instance over the removable volumes of this machine.
    #[must_use]
    pub fn for_removable_volumes(timeout: Duration) -> Self {
        Self::new(tessera_core::usb::RemovableVolumeEnumerator, timeout)
    }
}

impl<E: UsbEnumerator> FlowIo for VolumeFlowIo<E> {
    type Ops = SystemMountedOps;

    fn wait_for_usb(&self) -> Result<Vec<UsbDevice>, UsbError> {
        // The empty allow-list is not a placeholder for a configured one: a
        // volume exposes no USB descriptor to match against, so passing the
        // configured pairs would reject every candidate rather than filter
        // them. Filtering arrives with the descriptor identity it needs.
        wait_for_devices_cancellable(
            &self.enumerator,
            self.timeout,
            &[],
            self.poll_interval,
            &self.cancel,
        )
    }

    fn mount(&self, dev: &UsbDevice) -> Result<MountSession<Self::Ops>, MountError> {
        let volume: PathBuf = dev.devnode.clone();
        // Enumeration and use are separate moments: media can be pulled
        // between them, and then the path the OS reported is gone. Say so as a
        // mount failure rather than letting credential discovery report the
        // absent volume as an absent credential.
        if !volume.is_dir() {
            return Err(MountError::MountpointInvalid(volume));
        }
        Ok(MountSession {
            mountpoint: volume.clone(),
            guard: MountGuard::adopt(Arc::clone(&self.ops), volume),
        })
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
    use std::sync::Mutex;
    use tessera_core::usb::MockEnumerator;

    /// An enumerator that records the filters it was handed.
    #[derive(Default)]
    struct RecordingEnumerator {
        devices: Vec<UsbDevice>,
        filters: Mutex<Vec<Vec<(u16, u16)>>>,
    }

    impl UsbEnumerator for RecordingEnumerator {
        fn enumerate(&self, vid_pid_filter: &[(u16, u16)]) -> Result<Vec<UsbDevice>, UsbError> {
            self.filters.lock().unwrap().push(vid_pid_filter.to_vec());
            Ok(self.devices.clone())
        }
    }

    fn volume(path: &std::path::Path, serial: &str) -> UsbDevice {
        UsbDevice {
            devnode: path.to_path_buf(),
            serial: Some(serial.to_string()),
            vid: 0,
            pid: 0,
            fs_type: Some("exfat".to_string()),
        }
    }

    #[test]
    fn candidates_keep_the_enumerator_order() {
        let dir = tempfile::tempdir().unwrap();
        let io = VolumeFlowIo::new(
            MockEnumerator {
                devices: vec![
                    volume(&dir.path().join("e"), "E"),
                    volume(&dir.path().join("f"), "F"),
                    volume(&dir.path().join("g"), "G"),
                ],
                error: None,
            },
            Duration::from_secs(1),
        );
        let serials: Vec<Option<String>> = io
            .wait_for_usb()
            .unwrap()
            .into_iter()
            .map(|d| d.serial)
            .collect();
        assert_eq!(
            serials,
            vec![
                Some("E".to_string()),
                Some("F".to_string()),
                Some("G".to_string())
            ]
        );
    }

    #[test]
    fn no_volume_within_the_budget_is_a_timeout() {
        let io = VolumeFlowIo::new(
            MockEnumerator {
                devices: vec![],
                error: None,
            },
            Duration::from_millis(80),
        )
        .with_poll_interval(Duration::from_millis(10));
        assert!(matches!(io.wait_for_usb().unwrap_err(), UsbError::Timeout));
    }

    #[test]
    fn a_cancelled_wait_reports_cancellation_not_a_timeout() {
        let io = VolumeFlowIo::new(
            MockEnumerator {
                devices: vec![],
                error: None,
            },
            Duration::from_secs(30),
        )
        .with_poll_interval(Duration::from_millis(10));
        let handle = io.cancel_handle();
        let waiter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            handle.cancel();
        });
        let err = io.wait_for_usb().unwrap_err();
        waiter.join().unwrap();
        assert!(matches!(err, UsbError::WaitCancelled));
    }

    #[test]
    fn the_configured_allow_list_is_never_handed_to_the_enumerator() {
        let dir = tempfile::tempdir().unwrap();
        let io = VolumeFlowIo::new(
            RecordingEnumerator {
                devices: vec![volume(&dir.path().join("e"), "E")],
                filters: Mutex::new(Vec::new()),
            },
            Duration::from_secs(1),
        );
        io.wait_for_usb().unwrap();
        let filters = io.enumerator.filters.lock().unwrap().clone();
        assert_eq!(filters, vec![Vec::<(u16, u16)>::new()]);
    }

    #[test]
    fn mounting_adopts_the_volume_path_and_leaves_it_alone() {
        let dir = tempfile::tempdir().unwrap();
        let vol = dir.path().join("e");
        std::fs::create_dir(&vol).unwrap();
        std::fs::write(vol.join("user.p12"), b"payload").unwrap();
        let io = VolumeFlowIo::new(
            MockEnumerator {
                devices: vec![],
                error: None,
            },
            Duration::from_secs(1),
        );
        let session = io.mount(&volume(&vol, "E")).unwrap();
        assert_eq!(session.mountpoint, vol);
        drop(session);
        assert!(vol.is_dir(), "the volume must survive the attempt");
        assert!(vol.join("user.p12").is_file());
    }

    #[test]
    fn a_volume_that_went_away_is_a_mount_failure() {
        let dir = tempfile::tempdir().unwrap();
        let vol = dir.path().join("gone");
        let io = VolumeFlowIo::new(
            MockEnumerator {
                devices: vec![],
                error: None,
            },
            Duration::from_secs(1),
        );
        match io.mount(&volume(&vol, "E")) {
            Err(MountError::MountpointInvalid(path)) => assert_eq!(path, vol),
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("a missing volume must not mount"),
        }
    }
}

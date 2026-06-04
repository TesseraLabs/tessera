//! `sd_notify(READY=1)` wrapper.
//!
//! Wrapping the libsystemd call lets us assert "called exactly once" in unit
//! tests without binding to the real systemd socket.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Notify handle.
///
/// Production callers use [`NotifyHandle::system_default`]. Tests construct
/// [`NotifyHandle::test_recorder`] which counts calls.
pub struct NotifyHandle {
    sent: bool,
    sender: NotifySender,
    counter: AtomicUsize,
}

/// Internal sender enum to avoid `Box<dyn FnMut>` and the `unsafe`/`Send`
/// gymnastics that come with it.
enum NotifySender {
    System,
    Test,
}

impl NotifyHandle {
    /// Production handle: dispatches to [`sd_notify::notify`].
    #[must_use]
    pub fn system_default() -> Self {
        Self {
            sent: false,
            sender: NotifySender::System,
            counter: AtomicUsize::new(0),
        }
    }

    /// Test handle: records call count without ever talking to the OS.
    #[must_use]
    pub fn test_recorder() -> Self {
        Self {
            sent: false,
            sender: NotifySender::Test,
            counter: AtomicUsize::new(0),
        }
    }

    /// Recorded call count (only meaningful for [`Self::test_recorder`]).
    #[must_use]
    pub fn calls(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }
}

/// Send the `READY=1` notification — idempotent.
pub fn notify_ready(h: &mut NotifyHandle) {
    if h.sent {
        return;
    }
    let result = match h.sender {
        NotifySender::System => sd_notify::notify(&[sd_notify::NotifyState::Ready]),
        NotifySender::Test => Ok(()),
    };
    if let Err(e) = result {
        tracing::debug!(
            target: "tessera.monitord",
            error = %e,
            "sd_notify(READY=1) failed (no NOTIFY_SOCKET?)"
        );
    }
    h.counter.fetch_add(1, Ordering::SeqCst);
    h.sent = true;
}

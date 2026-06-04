#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Fail-mode wrapper unit tests.

use std::sync::atomic::{AtomicUsize, Ordering};

use tessera_core::error::IpcError;
use tessera_core::ipc::failmode::{FailModeWrapper, MonitorFailMode};
use tessera_core::ipc::{MonitorClient, OpenSessionInfo};
use tessera_proto::SessionTarget;

struct AlwaysFailClient {
    err_factory: fn() -> IpcError,
    calls: AtomicUsize,
}

impl MonitorClient for AlwaysFailClient {
    fn hello(&self) -> Result<(), IpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err((self.err_factory)())
    }
    fn open_session(&self, _info: &OpenSessionInfo<'_>) -> Result<(), IpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err((self.err_factory)())
    }
    fn close_session(&self, _: &str, _: &str) -> Result<(), IpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err((self.err_factory)())
    }
    fn ping(&self) -> Result<(), IpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err((self.err_factory)())
    }
}

fn open_info() -> OpenSessionInfo<'static> {
    OpenSessionInfo {
        session_id: "s",
        pam_user: "u",
        pam_service: "svc",
        host_id_hash: "h",
        target: SessionTarget::Unknown,
        usb_serial: None,
        cert_cn: "",
        cert_serial: "",
        engineer_ski: "",
        engineer_cert_sha256: "",
        uid: 0,
    }
}

#[test]
fn permissive_swallows_unavailable() {
    let inner = AlwaysFailClient {
        err_factory: || IpcError::Unavailable,
        calls: AtomicUsize::new(0),
    };
    let w = FailModeWrapper::new(inner, MonitorFailMode::Permissive);
    assert!(w.ping().is_ok());
    assert!(w.open_session(&open_info()).is_ok());
}

#[test]
fn strict_propagates_unavailable() {
    let inner = AlwaysFailClient {
        err_factory: || IpcError::Unavailable,
        calls: AtomicUsize::new(0),
    };
    let w = FailModeWrapper::new(inner, MonitorFailMode::Strict);
    assert!(matches!(w.ping().unwrap_err(), IpcError::Unavailable));
}

#[test]
fn permissive_still_propagates_device_gone() {
    let inner = AlwaysFailClient {
        err_factory: || IpcError::DeviceGone,
        calls: AtomicUsize::new(0),
    };
    let w = FailModeWrapper::new(inner, MonitorFailMode::Permissive);
    assert!(matches!(
        w.open_session(&open_info()).unwrap_err(),
        IpcError::DeviceGone
    ));
}

#[test]
fn permissive_still_propagates_unauthorized() {
    let inner = AlwaysFailClient {
        err_factory: || IpcError::Unauthorized,
        calls: AtomicUsize::new(0),
    };
    let w = FailModeWrapper::new(inner, MonitorFailMode::Permissive);
    assert!(matches!(w.ping().unwrap_err(), IpcError::Unauthorized));
}

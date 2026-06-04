//! Failure-mode wrapper around a `MonitorClient`.
//!
//! Reading `monitor_fail_mode` from validated config:
//! - [`MonitorFailMode::Strict`] propagates every [`IpcError`] to the caller.
//! - [`MonitorFailMode::Permissive`] turns connect / IO / decode errors into a
//!   warning log and `Ok(())`. Typed errors that change the auth verdict
//!   (currently [`IpcError::DeviceGone`]) are still propagated even in
//!   permissive mode — see [`is_fatal`].

use crate::error::IpcError;
use crate::ipc::{MonitorClient, OpenSessionInfo};

/// Behaviour when the IPC fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorFailMode {
    /// Propagate every error.
    Strict,
    /// Log warning and pretend success for IO/timeout errors.
    Permissive,
}

/// Wraps any `MonitorClient` to apply a [`MonitorFailMode`] policy.
pub struct FailModeWrapper<C: MonitorClient> {
    inner: C,
    mode: MonitorFailMode,
}

impl<C: MonitorClient> FailModeWrapper<C> {
    /// Construct a new wrapper.
    pub fn new(inner: C, mode: MonitorFailMode) -> Self {
        Self { inner, mode }
    }
}

/// Errors that change the auth verdict and must be propagated even when the
/// caller asked for `permissive` fail mode.
fn is_fatal(err: &IpcError) -> bool {
    matches!(err, IpcError::DeviceGone | IpcError::Unauthorized)
}

fn apply<F: FnOnce() -> Result<(), IpcError>>(
    mode: MonitorFailMode,
    op: &'static str,
    f: F,
) -> Result<(), IpcError> {
    match f() {
        Ok(()) => Ok(()),
        Err(e) if is_fatal(&e) => Err(e),
        Err(e) => match mode {
            MonitorFailMode::Strict => Err(e),
            MonitorFailMode::Permissive => {
                tracing::warn!(
                    target: "tessera.ipc",
                    op,
                    error = %e,
                    "monitord call failed (permissive mode, ignoring)"
                );
                Ok(())
            }
        },
    }
}

impl<C: MonitorClient> MonitorClient for FailModeWrapper<C> {
    fn hello(&self) -> Result<(), IpcError> {
        apply(self.mode, "hello", || self.inner.hello())
    }

    fn open_session(&self, info: &OpenSessionInfo<'_>) -> Result<(), IpcError> {
        apply(self.mode, "open_session", || self.inner.open_session(info))
    }

    fn close_session(&self, session_id: &str, reason: &str) -> Result<(), IpcError> {
        apply(self.mode, "close_session", || {
            self.inner.close_session(session_id, reason)
        })
    }

    fn ping(&self) -> Result<(), IpcError> {
        apply(self.mode, "ping", || self.inner.ping())
    }
}

impl From<crate::config::validated::MonitorFailMode> for MonitorFailMode {
    fn from(value: crate::config::validated::MonitorFailMode) -> Self {
        match value {
            crate::config::validated::MonitorFailMode::Strict => MonitorFailMode::Strict,
            crate::config::validated::MonitorFailMode::Permissive => MonitorFailMode::Permissive,
        }
    }
}

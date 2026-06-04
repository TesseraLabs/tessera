//! systemd-logind integration via D-Bus.
//!
//! Two pieces:
//! - [`listener`]: subscribes to `org.freedesktop.login1.Manager` signals and
//!   forwards them as [`LogindSignal`] over a tokio mpsc.
//! - [`actions`]: helpers for `LockSession` / `TerminateSession` / `PowerOff`.
//!
//! Both modules compile only on Linux. On macOS dev hosts the high-level
//! types remain available so that the rest of the crate can compile.

pub mod actions;
pub mod listener;

pub use actions::{LogindActions, LogindActionsTrait, NoopActions};
pub use listener::LogindSignal;

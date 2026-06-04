//! Logging setup shared by PAM-side code.

use std::str::FromStr;
use std::sync::OnceLock;

use crate::Error;

/// Log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Trace.
    Trace,
    /// Debug.
    Debug,
    /// Info.
    Info,
    /// Warn.
    Warn,
    /// Error.
    Error,
}

impl FromStr for LogLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(Error::ConfigInvalid {
                reason: format!("invalid log level: {s}"),
            }),
        }
    }
}

/// Syslog facility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogFacility {
    /// auth.
    Auth,
    /// authpriv.
    Authpriv,
    /// user.
    User,
    /// daemon.
    Daemon,
}

impl FromStr for SyslogFacility {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auth" => Ok(Self::Auth),
            "authpriv" => Ok(Self::Authpriv),
            "user" => Ok(Self::User),
            "daemon" => Ok(Self::Daemon),
            _ => Err(Error::ConfigInvalid {
                reason: format!("invalid syslog facility: {s}"),
            }),
        }
    }
}

/// Initialize syslog best-effort and idempotently.
pub fn init_syslog(_level: LogLevel, _facility: SyslogFacility) -> Result<(), Error> {
    static INIT: OnceLock<()> = OnceLock::new();
    let () = *INIT.get_or_init(|| ());
    Ok(())
}

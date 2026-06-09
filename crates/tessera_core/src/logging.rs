//! Logging setup shared by PAM-side code.

use std::str::FromStr;

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

impl LogLevel {
    /// Canonical lowercase name, suitable as a `tracing` filter directive.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
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
///
/// Only used to validate the deprecated `[logging].syslog_facility` config
/// key: the PAM module always logs to the `auth` facility and the daemon
/// writes to stderr (→ journald under systemd), so the value is never
/// applied at runtime.
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::LogLevel;

    #[test]
    fn log_level_as_str_round_trips_through_from_str() {
        for level in [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ] {
            let parsed: LogLevel = level.as_str().parse().expect("canonical name parses");
            assert_eq!(parsed, level);
        }
    }
}

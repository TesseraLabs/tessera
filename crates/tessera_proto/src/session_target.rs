//! Identifier for the user-visible session being tracked by monitord.
//!
//! On systemd boxes this is normally `LogindSession(id)` — the id matches
//! `XDG_SESSION_ID`. On consoles or remote shells without logind we fall
//! back to `Tty(path)` or `Display(":0")`. `Unknown` is used when the PAM
//! environment exposed nothing identifying.

/// Where the active user session lives.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionTarget {
    /// A TTY/PTY device path.
    Tty {
        /// Device node path, e.g. `/dev/tty1` or `/dev/pts/0`.
        path: String,
    },
    /// An X11 / Wayland display name.
    Display {
        /// Display name, e.g. `:0`.
        name: String,
    },
    /// A logind session id (matches `XDG_SESSION_ID`).
    LogindSession {
        /// Session id assigned by `systemd-logind`.
        id: String,
    },
    /// Nothing identifying was available at PAM time.
    Unknown,
}

impl SessionTarget {
    /// Return the logind session id when this target is one.
    #[must_use]
    pub fn logind_id(&self) -> Option<&str> {
        if let SessionTarget::LogindSession { id } = self {
            Some(id.as_str())
        } else {
            None
        }
    }

    /// Construct a `Tty` target.
    #[must_use]
    pub fn tty(path: impl Into<String>) -> Self {
        SessionTarget::Tty { path: path.into() }
    }

    /// Construct a `Display` target.
    #[must_use]
    pub fn display(name: impl Into<String>) -> Self {
        SessionTarget::Display { name: name.into() }
    }

    /// Construct a `LogindSession` target.
    #[must_use]
    pub fn logind(id: impl Into<String>) -> Self {
        SessionTarget::LogindSession { id: id.into() }
    }
}

//! `MacBackend` trait, error/runtime probe types, and a no-op `StubBackend`.
//!
//! See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md` for the
//! full design.  The trait abstracts over the real Astra МКЦ FFI (provided by
//! the closed `tessera_mac_parsec` crate, selected behind the
//! `astra-mac` feature) and the in-process [`StubBackend`] used on developer
//! hosts and in CI.

use crate::mac::IntegrityLabel;

/// Errors produced by a [`MacBackend`] implementation.
#[derive(Debug, thiserror::Error)]
pub enum MacError {
    /// Underlying `parsec`/`libpdp` syscall returned a non-zero return code.
    #[error("parsec error: op={op} rc={rc}")]
    Parsec {
        /// Name of the FFI operation that failed (e.g. `"pdp_set_attr"`).
        op: &'static str,
        /// Raw return code from the FFI call.
        rc: i32,
    },
    /// The requested user was not found in the МКЦ user database (`mic.db`).
    #[error("user unknown in mic db: {user}")]
    UserUnknown {
        /// Login name that could not be resolved.
        user: String,
    },
    /// The MAC subsystem is not available on the current host (kernel module
    /// missing, library missing, or feature disabled at compile time).
    #[error("MAC subsystem unavailable")]
    Unavailable,
    /// Generic I/O error surfaced from filesystem or device access.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Failure to parse a text-format label or configuration line.
    #[error("text format error: {0}")]
    TextFormat(String),
    /// The current process is missing the `CAP_MAC_ADMIN` (CHMAC) capability
    /// required to modify file labels.
    #[error("missing CHMAC capability")]
    CapMissing,
}

/// Runtime mode of the MAC backend on the current host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacRuntime {
    /// Backend is wired up and operational.
    Active,
    /// Backend is present but explicitly disabled by configuration.
    Disabled,
    /// Backend is not available on this host (no kernel support / no library).
    Unavailable,
}

/// Abstraction over an Astra МКЦ backend.
///
/// Implementations may either talk to the real kernel/userspace via FFI
/// (`astra-mac` feature) or provide an in-process stub for unit tests and
/// non-Astra hosts.  The trait is object-safe and `Send + Sync` so that it can
/// be stored behind `Arc<dyn MacBackend>` inside the PAM module.
#[cfg_attr(feature = "mac-tests", mockall::automock)]
pub trait MacBackend: Send + Sync {
    /// Probe the host for MAC support.  Cheap, side-effect free.
    fn probe(&self) -> MacRuntime;

    /// Resolve the maximum МКЦ label allowed for `user` (the `MNKC` value
    /// from `mic.db`).
    fn get_user_mnkc(&self, user: &str) -> Result<IntegrityLabel, MacError>;

    /// Apply `label` to the current process / PAM session.
    fn apply_session(&self, label: IntegrityLabel) -> Result<(), MacError>;

    /// Read the МКЦ label currently attached to `path`.
    fn get_file_label(&self, path: &std::path::Path) -> Result<IntegrityLabel, MacError>;

    /// Set the МКЦ label on `path`.  If `irelax` is true, the implementation
    /// may attempt the operation in IRELAX (write-down) mode where supported.
    fn set_file_label(
        &self,
        path: &std::path::Path,
        label: IntegrityLabel,
        irelax: bool,
    ) -> Result<(), MacError>;

    /// Set the МКЦ label on an open file descriptor.  Used by callers that
    /// hold an exclusive `fd` (e.g. the sessions.json writer) to close the
    /// path-based TOCTOU window between `open()` and `set_file_label()`.
    fn set_fd_label(
        &self,
        fd: std::os::unix::io::RawFd,
        label: IntegrityLabel,
        irelax: bool,
    ) -> Result<(), MacError>;
}

/// No-op [`MacBackend`] implementation used on hosts without `libpdp`.
///
/// All mutating calls succeed silently; [`MacBackend::probe`] always reports
/// [`MacRuntime::Unavailable`] and label lookups return permissive defaults so
/// that the PAM stack can degrade gracefully when MAC enforcement is
/// configured as advisory.
#[derive(Debug, Default)]
pub struct StubBackend;

impl StubBackend {
    /// Construct a new stub backend.  Equivalent to `StubBackend::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl MacBackend for StubBackend {
    fn probe(&self) -> MacRuntime {
        MacRuntime::Unavailable
    }

    fn get_user_mnkc(&self, _user: &str) -> Result<IntegrityLabel, MacError> {
        Ok(IntegrityLabel {
            level: i8::MAX,
            categories: u64::MAX,
        })
    }

    fn apply_session(&self, _label: IntegrityLabel) -> Result<(), MacError> {
        Ok(())
    }

    fn get_file_label(&self, _p: &std::path::Path) -> Result<IntegrityLabel, MacError> {
        Ok(IntegrityLabel {
            level: 0,
            categories: 0,
        })
    }

    fn set_file_label(
        &self,
        _p: &std::path::Path,
        _label: IntegrityLabel,
        _irelax: bool,
    ) -> Result<(), MacError> {
        Ok(())
    }

    fn set_fd_label(
        &self,
        _fd: std::os::unix::io::RawFd,
        _label: IntegrityLabel,
        _irelax: bool,
    ) -> Result<(), MacError> {
        Ok(())
    }
}

// Planned (openspec/changes/backend-plugins/): `PluginBackend` — bridges a
// C-ABI plugin vtable (`tessera_plugin_entry` envelope with a strict
// abi_version check) onto the `MacBackend` trait, verifying the `.so`
// signature against build-time-embedded keys before dlopen and wrapping
// every FFI boundary in `catch_unwind`.

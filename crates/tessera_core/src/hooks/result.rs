//! Hook execution result types.
//!
//! [`HookOutcome`] is what a successful (in the sense of "ran to completion or
//! to a deterministic timeout") `HookExecutor::execute` call produces.
//! [`HookError`] is what gets returned when the executor itself can't proceed
//! (fork/pipe failure, env unresolved, command path unusable, child setup
//! signalled an error, parent's `waitpid` failed, …) **or** when caller-level
//! policy is `Abort` and the child exited non-zero / was killed by timeout.

use std::path::PathBuf;
use std::time::Duration;

use crate::hooks::placeholder::PlaceholderVar;
use crate::hooks::stage::HookStage;

/// A completed hook execution outcome.
///
/// Note: a non-zero `exit_code` or `killed_by_timeout=true` is **not** by
/// itself an error — the executor returns `Ok(HookOutcome)` and lets the
/// caller's `OnFailure` policy decide via [`crate::hooks::apply_on_failure`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookOutcome {
    /// Stage that produced this outcome.
    pub stage: HookStage,
    /// The command argv that was executed (for log/audit).
    pub command: Vec<String>,
    /// Exit code from `waitpid`. For signaled children, conventionally
    /// `128 + signo`.
    pub exit_code: i32,
    /// Whether the executor escalated to `SIGTERM`/`SIGKILL` because the
    /// per-hook deadline expired.
    pub killed_by_timeout: bool,
    /// Wall-clock duration from `fork` to `waitpid` return.
    pub duration: Duration,
    /// Number of stdout lines the parent forwarded to the line sink.
    pub stdout_lines: u64,
    /// Number of stderr lines the parent forwarded to the line sink.
    pub stderr_lines: u64,
}

/// Hook execution failure surface.
///
/// Variants that wrap `nix::errno::Errno` are kept distinct — `nix::Error`
/// has no `Clone` and `From` would be ambiguous between the three call
/// sites — so callers map the errno to the right variant explicitly.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    /// The configured command path is missing, not executable, or otherwise
    /// unusable.
    #[error("hook command unusable: {path:?}")]
    CommandUnusable {
        /// The path the executor attempted to run.
        path: PathBuf,
    },
    /// The command path (or a directory on the way to it) failed the
    /// privileged-execution ownership/integrity walk: it is not owned by a
    /// trusted UID, is group/other-writable, or was swapped. Running it would
    /// let a local user have the daemon execute their file at the hook's
    /// privilege, so it is refused (fail closed).
    #[error("hook command failed path validation: {0}")]
    CommandUnsafe(#[from] crate::privileged_path::PrivilegedPathError),
    /// Looking up the requested PAM user failed (`getpwnam_r` returned NULL or
    /// errored).
    #[error("user lookup failed for {user:?}: {source}")]
    UserResolution {
        /// Username that was looked up.
        user: String,
        /// Underlying errno mapped to `io::Error`.
        #[source]
        source: std::io::Error,
    },
    /// A placeholder referenced by an env template / argv could not be
    /// resolved against the current [`crate::hooks::HookVars`].
    #[error("hook variable {var:?} is unresolved at this stage")]
    UnresolvedVar {
        /// The placeholder that was missing.
        var: PlaceholderVar,
    },
    /// `pipe(2)` / `pipe2(2)` failed.
    #[error("pipe creation failed: {0}")]
    Pipe(nix::errno::Errno),
    /// `fork(2)` / `vfork(2)` failed.
    #[error("fork failed: {0}")]
    Fork(nix::errno::Errno),
    /// `waitpid(2)` / `kill(2)` failed.
    #[error("waitpid/kill failed: {0}")]
    Wait(nix::errno::Errno),
    /// The hook hit its deadline and was killed via `SIGTERM`/`SIGKILL`
    /// (only surfaced when policy is `Abort`).
    #[error("hook timed out after {timeout_ms} ms")]
    Timeout {
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },
    /// The hook exited with a non-zero status (only surfaced when policy is
    /// `Abort`).
    #[error("hook exited with non-zero status {exit_code}")]
    NonZeroExit {
        /// Exit code from `waitpid`.
        exit_code: i32,
    },
    /// The hook was terminated by a signal not initiated by the executor.
    #[error("hook killed by signal {signal}")]
    Signal {
        /// Signal number.
        signal: i32,
    },
    /// Child-side setup error reported via the dedicated `err_pipe`
    /// (`setpgid`/`dup2`/`prctl`/`setgid`/`setuid`/`setrlimit`/`execve`
    /// failure), or any pre-fork error that has no better fit (e.g. an env
    /// value containing a NUL byte).
    #[error("child setup failed: {message}")]
    ChildSetup {
        /// Human-readable cause, including the error code byte where
        /// applicable.
        message: String,
    },
    /// Generic I/O wrapper for parent-side reads/writes that aren't covered
    /// by the variants above.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// An env-vector value rejected by the pre-fork sanitiser because it
    /// contained a control character that could be abused to inject
    /// additional `KEY=VALUE` pairs across a newline (P1-L).
    #[error("env value rejected for {var:?}: {reason}")]
    EnvValueRejected {
        /// Name of the env var whose value was rejected.
        var: String,
        /// Static reason string (e.g. "contains newline").
        reason: &'static str,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn outcome_is_clone_and_eq() {
        let o = HookOutcome {
            stage: HookStage::PreAuth,
            command: vec!["/bin/true".into()],
            exit_code: 0,
            killed_by_timeout: false,
            duration: Duration::from_millis(7),
            stdout_lines: 3,
            stderr_lines: 1,
        };
        let o2 = o.clone();
        assert_eq!(o, o2);
    }

    #[test]
    fn timeout_error_includes_ms_in_display() {
        let e = HookError::Timeout { timeout_ms: 1234 };
        assert_eq!(format!("{e}"), "hook timed out after 1234 ms");
    }

    #[test]
    fn command_unusable_includes_path() {
        let e = HookError::CommandUnusable {
            path: PathBuf::from("/no/such"),
        };
        let s = format!("{e}");
        assert!(s.contains("/no/such"), "got {s}");
    }

    #[test]
    fn nonzero_exit_includes_code() {
        let e = HookError::NonZeroExit { exit_code: 7 };
        assert_eq!(format!("{e}"), "hook exited with non-zero status 7");
    }

    #[test]
    fn unresolved_var_includes_variant() {
        let e = HookError::UnresolvedVar {
            var: PlaceholderVar::CertCn,
        };
        let s = format!("{e}");
        assert!(s.contains("CertCn"), "got {s}");
    }

    #[test]
    fn signal_variant_displays() {
        let e = HookError::Signal { signal: 15 };
        assert_eq!(format!("{e}"), "hook killed by signal 15");
    }

    #[test]
    fn pipe_fork_wait_render_errno() {
        let e = HookError::Pipe(nix::errno::Errno::EMFILE);
        assert!(format!("{e}").contains("pipe creation failed"));
        let e = HookError::Fork(nix::errno::Errno::EAGAIN);
        assert!(format!("{e}").contains("fork failed"));
        let e = HookError::Wait(nix::errno::Errno::ECHILD);
        assert!(format!("{e}").contains("waitpid/kill failed"));
    }

    #[test]
    fn child_setup_includes_message() {
        let e = HookError::ChildSetup {
            message: "execve failed (code 9)".into(),
        };
        assert!(format!("{e}").contains("execve failed (code 9)"));
    }

    #[test]
    fn user_resolution_includes_username() {
        let e = HookError::UserResolution {
            user: "ghost".into(),
            source: std::io::Error::from_raw_os_error(libc::ENOENT),
        };
        let s = format!("{e}");
        assert!(s.contains("ghost"), "got {s}");
    }

    #[test]
    fn io_from_std_error() {
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no");
        let e: HookError = inner.into();
        assert!(matches!(e, HookError::Io(_)));
    }
}

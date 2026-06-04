//! Per-hook resource caps (`setrlimit`).
//!
//! [`default_caps_for_timeout`] computes the static caps the executor will
//! apply in the child after `fork` (and after dropping privs, but before
//! `execve`). [`apply_caps`] performs the `setrlimit` syscalls themselves.
//!
//! `setrlimit` is async-signal-safe per POSIX, so it is legal in the
//! post-fork child path.

use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use nix::sys::resource::{setrlimit, Resource};

/// Caps applied to the hook child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlimitCaps {
    /// CPU seconds (`RLIMIT_CPU`).
    pub cpu_seconds: u64,
    /// Open file descriptors (`RLIMIT_NOFILE`).
    pub max_open_files: u64,
    /// Process count (`RLIMIT_NPROC`). Skipped on platforms that don't
    /// support `RLIMIT_NPROC`.
    pub max_processes: u64,
    /// Maximum file size in bytes (`RLIMIT_FSIZE`).
    pub max_file_size_bytes: u64,
}

/// Build default caps from the hook's timeout. CPU seconds are 2× the
/// timeout, with a floor of 2 s (so `timeout = 0` doesn't trip CPU=0
/// and instantly kill the hook). Other caps are static defaults.
#[must_use]
pub fn default_caps_for_timeout(timeout: Duration) -> RlimitCaps {
    let secs = timeout.as_secs();
    let cpu = secs.saturating_mul(2).max(2);
    RlimitCaps {
        cpu_seconds: cpu,
        max_open_files: 256,
        max_processes: 64,
        max_file_size_bytes: 1024 * 1024,
    }
}

/// Apply the caps via `setrlimit`. Returns the first errno on failure.
///
/// # Errors
///
/// Any `setrlimit` errno (`EINVAL`, `EPERM`).
///
/// # Notes
///
/// * `RLIMIT_NPROC` does not exist on macOS in the form we want; on macOS
///   we skip that cap (the test host doesn't enforce it the same way Linux
///   does, and the hook itself runs on Linux production).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn apply_caps(caps: &RlimitCaps) -> Result<(), nix::errno::Errno> {
    setrlimit(Resource::RLIMIT_CPU, caps.cpu_seconds, caps.cpu_seconds)?;
    setrlimit(
        Resource::RLIMIT_NOFILE,
        caps.max_open_files,
        caps.max_open_files,
    )?;
    setrlimit(
        Resource::RLIMIT_FSIZE,
        caps.max_file_size_bytes,
        caps.max_file_size_bytes,
    )?;

    // RLIMIT_NPROC is Linux-only in nix 0.27 (also defined on Android,
    // freebsd, netbsd, openbsd, aix). macOS does not expose it via the
    // `Resource` enum. We skip it on non-Linux.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    setrlimit(
        Resource::RLIMIT_NPROC,
        caps.max_processes,
        caps.max_processes,
    )?;

    Ok(())
}

/// Stub for unsupported platforms.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn apply_caps(_caps: &RlimitCaps) -> Result<(), nix::errno::Errno> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cpu_is_double_timeout() {
        let c = default_caps_for_timeout(Duration::from_secs(10));
        assert_eq!(c.cpu_seconds, 20);
    }

    #[test]
    fn cpu_floor_is_two_seconds() {
        let c = default_caps_for_timeout(Duration::from_secs(0));
        assert_eq!(c.cpu_seconds, 2);
    }

    #[test]
    fn defaults_are_constants() {
        let c = default_caps_for_timeout(Duration::from_secs(5));
        assert_eq!(c.max_open_files, 256);
        assert_eq!(c.max_processes, 64);
        assert_eq!(c.max_file_size_bytes, 1024 * 1024);
    }

    /// Tighten our own NOFILE temporarily. We pick a value above the test
    /// process's likely current usage so the test itself doesn't break.
    #[test]
    fn apply_caps_runs_without_panicking() {
        // Save current state via getrlimit so we don't permanently shrink
        // the test runner's limits.
        let cur = nix::sys::resource::getrlimit(Resource::RLIMIT_NOFILE).expect("getrlimit nofile");
        let caps = RlimitCaps {
            cpu_seconds: cur.1.max(60), // hard CPU keeps test runner alive
            max_open_files: cur.0.min(1024),
            max_processes: 1024,
            max_file_size_bytes: 1024 * 1024,
        };
        // Ignore EPERM: an unprivileged test runner may not be able to
        // raise hard limits; we only assert that the helper doesn't panic
        // and either succeeds or returns a clean errno.
        match apply_caps(&caps) {
            Ok(()) => {}
            Err(e) => {
                assert!(
                    matches!(
                        e,
                        nix::errno::Errno::EPERM
                            | nix::errno::Errno::EINVAL
                            | nix::errno::Errno::EFAULT
                    ),
                    "unexpected errno: {e:?}"
                );
            }
        }
        // Restore limits where possible.
        let _ = setrlimit(Resource::RLIMIT_NOFILE, cur.0, cur.1);
    }
}

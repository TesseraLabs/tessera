//! `waitpid` + timeout escalation for hook supervision.
//!
//! [`wait_with_timeout`] polls `waitpid(pid, WNOHANG)` until the child
//! exits or the per-hook timeout expires. On timeout, it sends `SIGTERM`
//! to the *process group* (the child set up its own group via `setpgid`
//! pre-exec — see `child_setup`), waits up to 2 s, then escalates to
//! `SIGKILL`. Group-kill is critical: a hook script may have spawned
//! subprocesses that we need to clean up too.

use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{killpg, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use crate::hooks::result::HookError;

/// Outcome of waiting on a hook child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitOutcome {
    /// Exit status (signaled-children get `128 + signo`).
    pub status: ExitStatus,
    /// Whether the executor escalated to `SIGTERM`/`SIGKILL` because the
    /// per-hook deadline expired.
    pub killed_by_timeout: bool,
    /// Wall-clock from `start` parameter to `waitpid` return.
    pub elapsed: Duration,
}

/// Exit status disambiguation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    /// `Some(code)` when the child called `_exit(code)`.
    pub code: Option<i32>,
    /// `Some(signo)` when the child was killed by signal.
    pub signal: Option<i32>,
}

impl ExitStatus {
    /// Convert a `nix::sys::wait::WaitStatus` to an [`ExitStatus`].
    #[must_use]
    pub const fn from_wait_status(ws: WaitStatus) -> Self {
        match ws {
            WaitStatus::Exited(_, code) => Self {
                code: Some(code),
                signal: None,
            },
            WaitStatus::Signaled(_, sig, _) => Self {
                code: None,
                signal: Some(sig as i32),
            },
            _ => Self {
                code: None,
                signal: None,
            },
        }
    }

    /// Conventionally encoded exit code: real exit code or `128 + signo`.
    /// Returns `-1` for stopped/continued statuses (which don't apply here
    /// since we don't `WUNTRACED`).
    #[must_use]
    pub const fn conventional_code(&self) -> i32 {
        match (self.code, self.signal) {
            (Some(c), _) => c,
            (None, Some(s)) => 128 + s,
            _ => -1,
        }
    }
}

/// Poll `waitpid` non-blocking until exit or timeout, then escalate.
///
/// `pid` is the direct child PID; `pgid` is the process group ID used for
/// `killpg` on timeout escalation. In typical use `pgid == pid` because
/// the child called `setpgid(0, 0)` pre-`execve`.
///
/// # Errors
///
/// * [`HookError::Wait`] — `waitpid`/`killpg` returned an unexpected errno.
pub fn wait_with_timeout(
    pid: Pid,
    process_group_id: Pid,
    timeout: Duration,
) -> Result<WaitOutcome, HookError> {
    let start = Instant::now();
    let deadline = start + timeout;
    let poll_interval = Duration::from_millis(50);

    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if Instant::now() >= deadline {
                    return escalate(pid, process_group_id, start);
                }
                std::thread::sleep(poll_interval);
            }
            Ok(other) => {
                let status = ExitStatus::from_wait_status(other);
                return Ok(WaitOutcome {
                    status,
                    killed_by_timeout: false,
                    elapsed: start.elapsed(),
                });
            }
            // EINTR: retry the loop.
            Err(Errno::EINTR) => {}
            Err(e) => return Err(HookError::Wait(e)),
        }
    }
}

fn escalate(pid: Pid, process_group_id: Pid, start: Instant) -> Result<WaitOutcome, HookError> {
    // SIGTERM the group; ESRCH means the group is already gone.
    match killpg(process_group_id, Signal::SIGTERM) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(e) => return Err(HookError::Wait(e)),
    }

    let term_deadline = Instant::now() + Duration::from_secs(2);
    let poll_interval = Duration::from_millis(50);

    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                if Instant::now() >= term_deadline {
                    break;
                }
                std::thread::sleep(poll_interval);
            }
            Ok(other) => {
                let status = ExitStatus::from_wait_status(other);
                return Ok(WaitOutcome {
                    status,
                    killed_by_timeout: true,
                    elapsed: start.elapsed(),
                });
            }
            Err(Errno::EINTR) => {}
            Err(e) => return Err(HookError::Wait(e)),
        }
    }

    // Escalate to SIGKILL.
    match killpg(process_group_id, Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(e) => return Err(HookError::Wait(e)),
    }

    // Reap the zombie blocking-style.
    loop {
        match waitpid(pid, None) {
            Ok(ws) => {
                let status = ExitStatus::from_wait_status(ws);
                return Ok(WaitOutcome {
                    status,
                    killed_by_timeout: true,
                    elapsed: start.elapsed(),
                });
            }
            Err(Errno::EINTR) => {}
            Err(e) => return Err(HookError::Wait(e)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn from_wait_status_maps_exited() {
        let ws = WaitStatus::Exited(Pid::from_raw(1), 7);
        let s = ExitStatus::from_wait_status(ws);
        assert_eq!(s.code, Some(7));
        assert_eq!(s.signal, None);
    }

    #[test]
    fn from_wait_status_maps_signaled() {
        let ws = WaitStatus::Signaled(Pid::from_raw(1), Signal::SIGKILL, false);
        let s = ExitStatus::from_wait_status(ws);
        assert_eq!(s.code, None);
        assert_eq!(s.signal, Some(Signal::SIGKILL as i32));
    }

    #[test]
    fn conventional_code_for_exit() {
        let s = ExitStatus {
            code: Some(7),
            signal: None,
        };
        assert_eq!(s.conventional_code(), 7);
    }

    #[test]
    fn conventional_code_for_signal() {
        let s = ExitStatus {
            code: None,
            signal: Some(9),
        };
        assert_eq!(s.conventional_code(), 137);
    }

    /// Spawn `/bin/sh -c <script>` with the child placed in its own
    /// process group so the test exercises the same `killpg` path used in
    /// production. We mem-forget the resulting `Child` to reap via our own
    /// `waitpid` calls.
    #[allow(unsafe_code)] // test helper installs a `pre_exec` setpgid hook
    fn spawn_isolated_sh(script: &str) -> Pid {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(script);
        // Defined in a safe context so its body is not lexically nested inside
        // the `pre_exec` unsafe block below; the closure carries its own
        // dedicated unsafe block for the single syscall it performs.
        let set_own_pgid = || {
            // SAFETY: setpgid is async-signal-safe and is called in the child
            // between fork and exec, where performing only this single syscall
            // is permitted.
            let rc = unsafe { libc::setpgid(0, 0) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: the registered closure runs only in the child after fork and
        // before exec, and performs only the async-signal-safe setpgid call,
        // satisfying `pre_exec`'s contract.
        unsafe {
            cmd.pre_exec(set_own_pgid);
        }
        let child = cmd.spawn().expect("spawn child");
        let raw_pid = i32::try_from(child.id()).expect("pid fits in i32");
        let pid = Pid::from_raw(raw_pid);
        // Suppress `Child`'s drop without `mem::forget`: we reap the pid via
        // our own `waitpid` calls, so `Child` must not be dropped (which would
        // close its stdio handles). `ManuallyDrop` leaks it for the test's
        // lifetime exactly as the previous `mem::forget` did.
        let _child = std::mem::ManuallyDrop::new(child);
        pid
    }

    #[test]
    fn waits_for_quick_child() {
        let pid = spawn_isolated_sh("exit 0");
        let result = wait_with_timeout(pid, pid, Duration::from_secs(5)).expect("wait");
        assert_eq!(result.status.code, Some(0));
        assert!(!result.killed_by_timeout);
        assert!(result.elapsed < Duration::from_secs(5));
    }

    #[test]
    fn times_out_long_running_child() {
        let pid = spawn_isolated_sh("sleep 30");
        let result = wait_with_timeout(pid, pid, Duration::from_millis(500)).expect("wait timeout");
        assert!(result.killed_by_timeout, "expected killed_by_timeout");
        // Bounded: 500 ms timeout + 2 s grace + epsilon.
        assert!(
            result.elapsed >= Duration::from_millis(500) && result.elapsed < Duration::from_secs(5),
            "elapsed = {:?}",
            result.elapsed
        );
    }
}

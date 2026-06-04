//! Real `fork`+`execve` hook executor.
//!
//! [`ForkExecExecutor`] implements [`crate::hooks::HookExecutor`] by:
//!
//! 1. Resolving the target user (if `run_as = User`).
//! 2. Building the env vector and argv as `Vec<CString>` in the parent.
//! 3. Computing per-hook resource caps.
//! 4. Creating blocking stdout/stderr pipes.
//! 5. Forking; in the child calling [`crate::hooks::child_setup::child_setup`].
//! 6. In the parent, spawning two reader threads (one per pipe) and using
//!    [`crate::hooks::wait::wait_with_timeout`] for supervision.
//! 7. Joining readers (they exit on EOF when the child closes its write
//!    ends or `_exit`s) and assembling a [`crate::hooks::HookOutcome`].
//!
//! Pipe read ends stay in blocking mode: the reader thread issues a single
//! `read_to_end` that parks on the pipe until the child closes its write end
//! (on `execve` or `_exit`). This prevents data loss for hooks that emit more
//! than the pipe buffer (~64 KB) — a non-blocking reader would race ahead,
//! see `WouldBlock` immediately, and exit while the child still has writes
//! to perform.

use std::ffi::CString;
use std::os::fd::{IntoRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::unistd::{fork, ForkResult, Pid};

use crate::hooks::child_setup::{build_argv_ptrs, child_setup};
use crate::hooks::env::build_env_vector;
use crate::hooks::executor::HookExecutor;
use crate::hooks::pipe_reader::{PipeReader, PipeStream};
use crate::hooks::result::{HookError, HookOutcome};
use crate::hooks::rlimit::default_caps_for_timeout;
use crate::hooks::user::lookup_user;
use crate::hooks::validator::{HookConfig, RunAs};
use crate::hooks::vars::HookVars;
use crate::hooks::wait::wait_with_timeout;

/// Build a stable, parent-owned supplementary groups slice from a resolved
/// [`crate::hooks::user::UserInfo`]. Returns an empty slice when `run_as = Root`
/// (i.e. `user_info` is `None`). Used by [`ForkExecExecutor::execute`] to
/// pre-allocate the groups vector before `fork()` so the post-fork child path
/// performs zero allocations (P0-6).
#[must_use]
pub(crate) fn build_groups_box(
    user_info: Option<&crate::hooks::user::UserInfo>,
) -> Box<[libc::gid_t]> {
    match user_info {
        None => Vec::new().into_boxed_slice(),
        Some(u) => u
            .groups
            .iter()
            .copied()
            .map(|g| g as libc::gid_t)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    }
}

/// Real fork+execve hook executor. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct ForkExecExecutor;

impl ForkExecExecutor {
    /// Construct a new executor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl HookExecutor for ForkExecExecutor {
    fn execute(&self, hook: &HookConfig, vars: &HookVars) -> Result<HookOutcome, HookError> {
        // Step 1: resolve target user (if needed).
        let user_info = match hook.run_as {
            RunAs::Root => None,
            RunAs::User => {
                let name = vars.pam_user.as_deref().ok_or(HookError::ChildSetup {
                    message: "run_as=user but vars.pam_user is None".into(),
                })?;
                Some(lookup_user(name)?)
            }
        };

        // Step 2: build env vector.
        let env_cstrings: Vec<CString> = build_env_vector(hook, vars, user_info.as_ref())?;

        // Pre-build the supplementary groups slice in the **parent** so the
        // child path does not allocate after `fork()`. P0-6: PAM hosts
        // (sshd, gdm, ...) are multi-threaded; a heap allocation between
        // fork() and execve() can deadlock on a malloc mutex held by a
        // sibling parent thread.
        let groups_box: Box<[libc::gid_t]> = build_groups_box(user_info.as_ref());

        // Step 3: build argv.
        if hook.command.is_empty() {
            return Err(HookError::CommandUnusable {
                path: std::path::PathBuf::new(),
            });
        }
        let mut argv_cstrings: Vec<CString> = Vec::with_capacity(hook.command.len());
        for arg in &hook.command {
            let c = CString::new(arg.as_str()).map_err(|_| HookError::ChildSetup {
                message: "argv contains NUL byte".into(),
            })?;
            argv_cstrings.push(c);
        }
        let argv_ptrs = build_argv_ptrs(&argv_cstrings);
        let mut env_ptrs: Vec<*const std::os::raw::c_char> =
            env_cstrings.iter().map(|c| c.as_ptr()).collect();
        env_ptrs.push(std::ptr::null());

        // Step 4: caps.
        let caps = default_caps_for_timeout(hook.timeout);

        // Step 5: pipes. Read ends stay blocking — reader threads call a
        // single `read_to_end` that parks until the child closes the write
        // end (on `execve` or `_exit`). With non-blocking pipes the reader
        // would see `WouldBlock` as soon as the buffer drained and exit
        // permanently, which loses any output the child writes later and
        // can deadlock writers once the pipe buffer (~64 KB) fills.
        // nix 0.30+ returns (OwnedFd, OwnedFd); we manage the lifetime
        // manually across fork/exec so convert into raw fds immediately.
        #[allow(clippy::similar_names)]
        let (stdout_pipe_r, stdout_pipe_w) = nix::unistd::pipe().map_err(HookError::Pipe)?;
        #[allow(clippy::similar_names)]
        let (stderr_pipe_r, stderr_pipe_w) = nix::unistd::pipe().map_err(HookError::Pipe)?;
        let out_r = stdout_pipe_r.into_raw_fd();
        let out_w = stdout_pipe_w.into_raw_fd();
        let err_r = stderr_pipe_r.into_raw_fd();
        let err_w = stderr_pipe_w.into_raw_fd();

        // Compute basename for log tagging.
        let basename = Path::new(&hook.command[0]).file_name().map_or_else(
            || hook.command[0].clone(),
            |s| s.to_string_lossy().into_owned(),
        );

        let stage = hook.stage;
        let command = hook.command.clone();

        let start = Instant::now();
        tracing::info!(
            target: "tessera.hook.start",
            stage = %stage,
            command = ?command,
            "hook starting",
        );

        // Step 6: fork.
        // SAFETY: We are about to fork. The child path calls only
        // async-signal-safe functions via child_setup(). The argv/env
        // CString storage is owned by `argv_cstrings`/`env_cstrings`
        // which live in this stack frame and remain stable across the
        // single-threaded child until execve.
        #[allow(unsafe_code)]
        let fork_result = unsafe { fork() };

        match fork_result {
            Err(e) => Err(HookError::Fork(e)),
            Ok(ForkResult::Child) => {
                // Close our copies of read ends; child only needs write ends.
                // SAFETY: child path; close is async-signal-safe.
                #[allow(unsafe_code)]
                unsafe {
                    libc::close(out_r);
                    libc::close(err_r);
                }
                // Hand off to child_setup. Never returns. The `groups_box`
                // allocation lives in the parent's address space (which the
                // child inherits read/write); we pass a raw pointer + length
                // to avoid any allocation on the child side.
                let groups_ptr = groups_box.as_ptr();
                let groups_len = groups_box.len();
                // SAFETY: see child_setup safety contract; groups_ptr is
                // valid for `groups_len` gid_t values until the child either
                // execve()s (after which the new image owns its memory) or
                // _exit()s.
                #[allow(unsafe_code)]
                unsafe {
                    child_setup(
                        &argv_ptrs,
                        &env_ptrs,
                        user_info.as_ref(),
                        &caps,
                        out_w,
                        err_w,
                        groups_ptr,
                        groups_len,
                    )
                }
            }
            Ok(ForkResult::Parent { child }) => supervise_parent(SuperviseArgs {
                child,
                out_r,
                err_r,
                out_w,
                err_w,
                stage,
                basename,
                command,
                start,
                timeout: hook.timeout,
            }),
        }
    }
}

struct SuperviseArgs {
    child: Pid,
    out_r: RawFd,
    err_r: RawFd,
    out_w: RawFd,
    err_w: RawFd,
    stage: crate::hooks::stage::HookStage,
    basename: String,
    command: Vec<String>,
    start: Instant,
    timeout: Duration,
}

fn supervise_parent(args: SuperviseArgs) -> Result<HookOutcome, HookError> {
    let SuperviseArgs {
        child,
        out_r,
        err_r,
        out_w,
        err_w,
        stage,
        basename,
        command,
        start,
        timeout,
    } = args;

    // Close write ends; spawn readers; supervise.
    // SAFETY: out_w/err_w are pipe write ends owned by parent.
    #[allow(unsafe_code)]
    unsafe {
        libc::close(out_w);
        libc::close(err_w);
    }

    let stdout_reader = PipeReader::from_raw_fd(out_r, stage, basename.clone(), PipeStream::Stdout);
    let stderr_reader = PipeReader::from_raw_fd(err_r, stage, basename, PipeStream::Stderr);

    // Reader threads. They drain until EOF.
    let stdout_state: Arc<Mutex<PipeReader>> = Arc::new(Mutex::new(stdout_reader));
    let stderr_state: Arc<Mutex<PipeReader>> = Arc::new(Mutex::new(stderr_reader));

    let stdout_handle = spawn_reader("tessera.hook.stdout", Arc::clone(&stdout_state))?;
    let stderr_handle = spawn_reader("tessera.hook.stderr", Arc::clone(&stderr_state))?;

    // Best-effort: ensure pgid == child pid (race with child's setpgid).
    let _ = nix::unistd::setpgid(child, child);

    let wait_outcome = wait_with_timeout(child, child, timeout)?;

    // After child exits, write ends are closed; readers see EOF.
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    let stdout_lines = stdout_state.lock().map_or(0, |g| g.line_count());
    let stderr_lines = stderr_state.lock().map_or(0, |g| g.line_count());

    let exit_code = wait_outcome.status.conventional_code();
    let killed_by_timeout = wait_outcome.killed_by_timeout;
    let duration = start.elapsed();
    let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);

    if killed_by_timeout {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        tracing::warn!(
            target: "tessera.hook.timeout",
            stage = %stage,
            command = ?command,
            duration_ms,
            timeout_ms,
            "hook timed out and was killed",
        );
    } else {
        tracing::info!(
            target: "tessera.hook.finish",
            stage = %stage,
            command = ?command,
            exit_code,
            duration_ms,
            "hook finished",
        );
    }

    Ok(HookOutcome {
        stage,
        command,
        exit_code,
        killed_by_timeout,
        duration,
        stdout_lines,
        stderr_lines,
    })
}

fn spawn_reader(
    name: &str,
    state: Arc<Mutex<PipeReader>>,
) -> Result<thread::JoinHandle<()>, HookError> {
    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            if let Ok(mut g) = state.lock() {
                let _ = g.drain();
            }
        })
        .map_err(|_| HookError::ChildSetup {
            message: format!("{name} reader thread spawn failed"),
        })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn executor_constructs_via_new() {
        let _ = ForkExecExecutor::new();
    }

    #[test]
    fn executor_default() {
        let _ = ForkExecExecutor;
    }

    /// P0-6: parent must build a stable groups slice so the child does not
    /// allocate after `fork()`.
    #[test]
    fn build_groups_box_handles_root_run_as() {
        let b = build_groups_box(None);
        assert!(b.is_empty(), "Root run_as ⇒ empty supplementary groups");
    }

    #[test]
    fn build_groups_box_preserves_order_and_layout() {
        use crate::hooks::user::UserInfo;
        let u = UserInfo {
            name: "alice".into(),
            uid: 1000,
            gid: 1000,
            groups: vec![1000, 27, 4, 1001],
            home: std::path::PathBuf::from("/home/alice"),
        };
        let b = build_groups_box(Some(&u));
        assert_eq!(b.len(), 4);
        assert_eq!(&*b, &[1000 as libc::gid_t, 27, 4, 1001]);
        // Boxed slice keeps a stable address; the address may be a non-null
        // dangling sentinel for empty boxes but here len == 4 so the
        // allocation is real and the slice is safe to pass to libc.
        let _addr = b.as_ptr();
    }

    /// End-to-end exercise of the no-alloc child path. Forks a real
    /// `/bin/true` (root-owned) and confirms `exit_code == 0` with the
    /// rewired pre-built groups path active.
    #[cfg(target_os = "linux")]
    #[test]
    fn fork_exec_runs_true_with_no_alloc_child_path() {
        use crate::hooks::stage::HookStage;
        use crate::hooks::validator::{HookConfig, OnFailure, RunAs};
        use crate::hooks::vars::HookVars;

        let hook = HookConfig {
            stage: HookStage::PreAuth,
            command: vec!["/bin/true".to_string()],
            timeout: Duration::from_secs(5),
            on_failure: OnFailure::Warn,
            run_as: RunAs::Root,
            env: std::collections::BTreeMap::new(),
        };
        let vars = HookVars::empty();
        let exec = ForkExecExecutor::new();
        let outcome = exec.execute(&hook, &vars).expect("fork+exec succeeds");
        assert_eq!(outcome.exit_code, 0, "/bin/true exits 0");
        assert!(!outcome.killed_by_timeout);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    #[ignore = "fork+exec hook test only meaningful on Linux"]
    fn fork_exec_runs_true_with_no_alloc_child_path() {}
}

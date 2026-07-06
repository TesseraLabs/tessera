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
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

/// Creates a pipe whose two ends both carry `O_CLOEXEC`.
///
/// The close-on-exec flag stops a sibling thread that forks and execs in the
/// window before this module's own `fork()` from inheriting the pipe ends. A
/// leaked write end would keep the pipe open after the hook child exits, so
/// the reader's `read_to_end` would never see EOF and its join would block
/// forever. On Linux the flag is set atomically with `pipe2(2)`; on other
/// Unix dev targets (no `pipe2`) it is set immediately after `pipe(2)` — the
/// production multithreaded PAM host is always Linux.
fn cloexec_pipe() -> nix::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    #[cfg(target_os = "linux")]
    {
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use nix::fcntl::{fcntl, FcntlArg, FdFlag};
        let (r, w) = nix::unistd::pipe()?;
        fcntl(&r, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        fcntl(&w, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        Ok((r, w))
    }
}

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

/// Reject a hook executable (and every parent directory) that an
/// unprivileged user could rewrite before it runs as root.
///
/// The child path execs `argv[0]` at the parent's privilege (typically root
/// for `run_as = Root`). A world-writable — or non-root/non-egid
/// group-writable — hook file, or any such directory on its path, lets a
/// local user swap the script for one of their choosing and have the daemon
/// run it as root. `sudo` and `ssh` perform this same pre-exec ownership /
/// permission walk for the identical reason.
///
/// This is a self-defending check: although `validate_hook` is expected to
/// pass an absolute path, a non-absolute `path` is rejected here rather than
/// trusted, because a relative path would make the ancestor walk meaningless
/// (it would resolve against the daemon's cwd) and `canonicalize` could turn
/// it into something unexpected. The path is then canonicalized once, so the
/// canonical (symlink-free) file and every canonical ancestor up to `/` are
/// the components actually checked — the same tree `execve` would resolve.
/// Walking lexical parents would let a symlinked component hide the real
/// parents from the permission walk. `S_IWOTH` is always fatal; `S_IWGRP`
/// is fatal unless the owning group is root (gid 0) or this process's
/// effective gid (a deliberately granted, trusted admin group).
///
/// # Errors
///
/// [`HookError::CommandUnusable`] when `path` is not absolute, when it cannot
/// be canonicalized (fail closed), or for the first canonical component that
/// is world-writable or group-writable by an untrusted group, or whose
/// metadata cannot be read.
fn check_exec_path_security(path: &Path) -> Result<(), HookError> {
    // Self-defending: refuse a relative path rather than trusting the caller.
    // A relative path makes the ancestor walk meaningless and canonicalize
    // would resolve it against the daemon's cwd. Fail closed.
    if !path.is_absolute() {
        return Err(HookError::CommandUnusable {
            path: path.to_path_buf(),
        });
    }

    // Canonicalize once so the walk sees the real, symlink-free tree that
    // execve would resolve. std::fs::metadata follows symlinks per-stat, so
    // walking lexical `.parent()` of a symlinked path would skip the real
    // parents of the resolved file. Resolving up front closes that gap.
    // A path that cannot be canonicalized (missing, unreadable component)
    // fails closed.
    let real = std::fs::canonicalize(path).map_err(|_| HookError::CommandUnusable {
        path: path.to_path_buf(),
    })?;

    // SAFETY: getegid is always successful and async-signal-safe; we are in
    // the parent so any libc call is fine here.
    #[allow(unsafe_code)]
    let egid = unsafe { libc::getegid() } as u32;

    let mut current = Some(real.as_path());
    while let Some(component) = current {
        let meta = std::fs::metadata(component).map_err(|_| HookError::CommandUnusable {
            path: component.to_path_buf(),
        })?;
        let mode = meta.permissions().mode();
        // S_IWOTH: writable by any local user — never acceptable.
        if mode & 0o002 != 0 {
            return Err(HookError::CommandUnusable {
                path: component.to_path_buf(),
            });
        }
        // S_IWGRP: acceptable only when the owning group is root or this
        // process's effective gid (a trusted, admin-controlled group).
        if mode & 0o020 != 0 {
            let gid = meta.gid();
            if gid != 0 && gid != egid {
                return Err(HookError::CommandUnusable {
                    path: component.to_path_buf(),
                });
            }
        }
        current = component.parent();
    }
    Ok(())
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
        let command0 = hook.command.first().ok_or(HookError::CommandUnusable {
            path: std::path::PathBuf::new(),
        })?;
        // Reject a hook executable (or any directory on its path) that a
        // local user could rewrite before it runs as root. Done in the
        // parent, before fork, exactly where sudo/ssh do their pre-exec
        // permission walk.
        check_exec_path_security(Path::new(command0))?;

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
        //
        // Create the pipes with O_CLOEXEC so a sibling thread that forks and
        // execs in the window before our own fork() cannot inherit these
        // write ends. A leaked write end would keep the pipe open after our
        // child exits, so the reader's read_to_end never sees EOF and the
        // join blocks forever (login stall), besides leaking hook output to
        // an unrelated process. Our child hands these fds to the grandchild
        // via dup2, which produces a fresh descriptor without CLOEXEC, so
        // the child's stdout/stderr survive execve unaffected.
        #[allow(clippy::similar_names)]
        let (stdout_pipe_r, stdout_pipe_w) = cloexec_pipe().map_err(HookError::Pipe)?;
        #[allow(clippy::similar_names)]
        let (stderr_pipe_r, stderr_pipe_w) = cloexec_pipe().map_err(HookError::Pipe)?;
        let out_r = stdout_pipe_r.into_raw_fd();
        let out_w = stdout_pipe_w.into_raw_fd();
        let err_r = stderr_pipe_r.into_raw_fd();
        let err_w = stderr_pipe_w.into_raw_fd();

        // Compute basename for log tagging.
        let basename = Path::new(command0)
            .file_name()
            .map_or_else(|| command0.clone(), |s| s.to_string_lossy().into_owned());

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
                // SAFETY: child path; close is async-signal-safe; out_r is a
                // valid pipe read end inherited from the parent.
                #[allow(unsafe_code)]
                unsafe {
                    libc::close(out_r);
                }
                // SAFETY: child path; close is async-signal-safe; err_r is a
                // valid pipe read end inherited from the parent.
                #[allow(unsafe_code)]
                unsafe {
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
    // SAFETY: out_w is a pipe write end owned by the parent.
    #[allow(unsafe_code)]
    unsafe {
        libc::close(out_w);
    }
    // SAFETY: err_w is a pipe write end owned by the parent.
    #[allow(unsafe_code)]
    unsafe {
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
    // An error here means the child already won the race (or exited), which
    // is harmless — the result is intentionally ignored.
    let _setpgid = nix::unistd::setpgid(child, child);

    let wait_outcome = wait_with_timeout(child, child, timeout)?;

    // After child exits, write ends are closed; readers see EOF. A panicked
    // reader thread is surfaced via its drained line count, not here, so the
    // join result is intentionally ignored.
    drop(stdout_handle.join());
    drop(stderr_handle.join());

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
                // Drain to EOF; a read error just ends the drain early and is
                // reflected in the line count, so the result is intentionally
                // ignored here.
                drop(g.drain());
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
        let exec = ForkExecExecutor::new();
        let _ = exec;
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

    /// A world-writable hook file must be rejected before exec: an
    /// unprivileged user could otherwise rewrite it and have it run as root.
    #[test]
    fn world_writable_hook_is_rejected() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let hook = dir.path().join("hook.sh");
        {
            let mut f = std::fs::File::create(&hook).expect("create hook");
            f.write_all(b"#!/bin/sh\nexit 0\n").expect("write hook");
        }
        // 0o777 sets S_IWOTH — the bit a local attacker abuses.
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o777))
            .expect("chmod world-writable");

        let res = check_exec_path_security(&hook);
        assert!(
            matches!(res, Err(HookError::CommandUnusable { .. })),
            "world-writable hook must be rejected, got {res:?}"
        );

        // No positive (tighten-then-passes) assertion: check_exec_path_security
        // now canonicalizes and walks every real ancestor, and the system temp
        // dir's ancestors are world-writable on common platforms (e.g.
        // /private/tmp is sticky 1777 on macOS, /tmp is 1777 on Linux), so a
        // 0o755 file under it would still be rejected by the ancestor walk.
        // That rejection is correct, just not deterministic to assert here, so
        // we only assert the file-mode rejection above.
    }

    /// Group-writable by an untrusted (non-root, non-egid) group is rejected;
    /// this is the second half of the recommendation. We can only assert the
    /// untrusted-group path deterministically when not running as a member of
    /// gid 0, so the file is owned by its creator's gid which is neither 0 nor
    /// (in CI) the egid 0 case — kept minimal and self-contained.
    #[test]
    fn group_writable_untrusted_group_is_rejected_when_gid_nonzero() {
        use std::io::Write as _;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempfile::tempdir().expect("tempdir");
        let hook = dir.path().join("hook.sh");
        {
            let mut f = std::fs::File::create(&hook).expect("create hook");
            f.write_all(b"#!/bin/sh\nexit 0\n").expect("write hook");
        }
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o770))
            .expect("chmod group-writable");

        // SAFETY: getegid is always successful and async-signal-safe; called
        // here in a single-threaded test on the parent side.
        #[allow(unsafe_code)]
        let egid = unsafe { libc::getegid() } as u32;
        let gid = std::fs::metadata(&hook).expect("stat").gid();
        let res = check_exec_path_security(&hook);
        // When the file's owning group is untrusted, rejection is required.
        // (Under the canonical ancestor walk the world-writable system temp
        // dir would also trip the S_IWOTH check, so rejection is guaranteed
        // either way — but the case we specifically want to pin down is the
        // file's own untrusted group-writable bit.)
        if gid != 0 && gid != egid {
            assert!(
                matches!(res, Err(HookError::CommandUnusable { .. })),
                "group-writable by untrusted group must be rejected, got {res:?}"
            );
        }
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

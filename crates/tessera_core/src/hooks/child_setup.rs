//! Async-signal-safe child path between `fork()` and `execve()`.
//!
//! After `fork()` returns 0, the child inherits the parent's address space
//! but only one thread (the calling thread). Per POSIX, the child may only
//! call **async-signal-safe** functions until `execve()` succeeds. That
//! excludes `tracing::*`, `syslog::*`, the global allocator, `eprintln!`,
//! `String::push`, `Vec::push`, and `std::process::exit` (which runs `atexit`
//! handlers — including any installed by the parent or its libraries).
//!
//! This module is the *only* place in `tessera_core` where unsafe code
//! is permitted. The crate-level `#![deny(unsafe_code)]` is locally relaxed
//! here via `#![allow(unsafe_code)]`. Every step writes a fixed
//! pre-allocated `&[u8]` to stderr (FD 2) via `libc::write` (async-signal-
//! safe) and calls `libc::_exit(127)` on failure — never returns through
//! Rust's panic machinery.
//!
//! Sequence (each step is async-signal-safe):
//!
//! 1. `setpgid(0, 0)` — own process group; parent uses the pgid for group-
//!    kill on timeout escalation.
//! 2. `setsid()` — best-effort detach from controlling tty; ignore EPERM.
//! 3. Open `/dev/null` and `dup2` over fd 0; `dup2(stdout_w, 1)`,
//!    `dup2(stderr_w, 2)`. Close the original write ends (already dup'd).
//! 4. Close all FDs ≥ 3. On Linux this issues a single
//!    `close_range(3, ~0u32, 0)` syscall (added in 5.9; Astra SE 1.7 ships
//!    5.15+, so this always succeeds in production). On non-Linux dev
//!    targets we fall back to a bounded loop using the current
//!    `RLIMIT_NOFILE` soft limit. Lowering `RLIMIT_NOFILE` later (in
//!    `apply_caps`) does **not** close FDs that were already inherited
//!    from the parent — they must be closed here, before `execve`.
//! 5. Apply `setrlimit` caps (CPU/NOFILE/FSIZE/NPROC).
//! 6. `umask(0o077)`.
//! 7. `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` on Linux; skipped on macOS.
//! 8. If `run_as = Some(user)`: `setgroups`, `setgid`, `setuid` — order
//!    matters (groups → gid → uid).
//! 9. `execve(argv[0], argv, env)`. On success: never returns.
//!    On failure: `_exit(127)` (after writing a short message).
#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::raw::c_char;

use crate::hooks::rlimit::{apply_caps, RlimitCaps};
use crate::hooks::user::UserInfo;

/// Bail-out helper: write a short message to stderr (best-effort), then
/// `_exit(127)`. Never returns.
///
/// # Safety
///
/// May only be called from a child process after `fork()`. Performs
/// async-signal-safe `write(2)` and `_exit(2)` only.
unsafe fn die(msg: &[u8]) -> ! {
    // SAFETY: write is async-signal-safe; we pass a stable byte slice we own
    // and a small length. Результат write игнорируется намеренно — это
    // best-effort диагностика в child-контексте, где логирование запрещено.
    #[allow(clippy::let_underscore_must_use)]
    unsafe {
        let _ = libc::write(
            2,
            msg.as_ptr().cast::<libc::c_void>(),
            msg.len() as libc::size_t,
        );
    }
    // SAFETY: _exit is async-signal-safe and never returns.
    unsafe {
        libc::_exit(127);
    }
}

/// Build a NULL-terminated `Vec<*const c_char>` from a slice of `CString`s.
/// Allocates — must be called in the **parent**, never in the child path.
#[must_use]
pub fn build_argv_ptrs(argv: &[CString]) -> Vec<*const c_char> {
    let mut v: Vec<*const c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    v.push(std::ptr::null());
    v
}

/// Close every file descriptor `>= 3`.
///
/// On Linux this performs a single `close_range(3, ~0u32, 0)` syscall
/// (available since Linux 5.9; Astra SE 1.7 ships kernel 5.15+, so the
/// fast path always succeeds in production). The fallback uses the
/// current `RLIMIT_NOFILE` soft limit and a bounded loop.
///
/// On other Unix-likes (macOS dev path) we always take the rlimit-bounded
/// loop.
///
/// # Safety
///
/// Must only be called in a child process between `fork()` and `execve()`.
/// All operations performed here (`syscall`, `close`, `getrlimit`,
/// `close_range`) are async-signal-safe.
unsafe fn close_high_fds() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: SYS_close_range is the kernel's close_range(2) syscall
        // (since Linux 5.9). On kernels older than 5.9 it returns -ENOSYS;
        // we fall back below. The syscall is async-signal-safe.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                0 as libc::c_uint,
            )
        };
        if rc == 0 {
            return;
        }
        // Fallback: bounded loop using current NOFILE rlimit.
        // SAFETY: getrlimit is async-signal-safe per POSIX; rlim is a stack
        // local owned by this frame.
        unsafe { close_high_fds_via_rlimit() };
    }

    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: getrlimit/close are async-signal-safe.
        unsafe { close_high_fds_via_rlimit() };
    }
}

/// Bounded `close()` loop using `RLIMIT_NOFILE.rlim_cur` as the upper bound.
///
/// Used as the Linux fallback when `close_range` fails (e.g. kernel < 5.9)
/// and as the only path on non-Linux dev targets.
///
/// # Safety
///
/// Must only be called in a child process between `fork()` and `execve()`.
/// `getrlimit` and `close` are async-signal-safe.
unsafe fn close_high_fds_via_rlimit() {
    // SAFETY: zero-init of POD `rlimit`; getrlimit fills both fields on
    // success. Async-signal-safe.
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: &raw mut to a valid local; getrlimit is async-signal-safe.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rlim) };
    // P2-B: cap the loop bound at 65536 even if rlim_cur is larger.
    // On macOS dev hosts (and on a hypothetical Linux box where
    // close_range failed and rlim_cur is unlimited / 2^31-1) we would
    // otherwise iterate through ~2 billion close() calls. 65536 is a
    // generous upper bound — any FD above that in a PAM host is already
    // pathological. On Linux this branch is normally unreachable
    // (close_range succeeds on 5.9+).
    let max_fd: i32 = if rc == 0 {
        const HARD_CAP: u64 = 65_536;
        let capped = rlim.rlim_cur.min(HARD_CAP as libc::rlim_t);
        i32::try_from(capped).unwrap_or(i32::MAX)
    } else {
        // Last-resort bounded fallback if even getrlimit fails.
        1024
    };
    // SAFETY: close is async-signal-safe; closing an unused FD just sets
    // EBADF, which we ignore.
    unsafe {
        for fd in 3..max_fd {
            let _ = libc::close(fd);
        }
    }
}

/// Run the post-fork child path. Never returns.
///
/// This function performs all post-`fork()` setup steps and then calls
/// `execve()`. On any error, it writes a short stderr message and
/// `_exit(127)`s.
///
/// `argv` and `env` slices, plus the pre-built `argv_ptrs` / `env_ptrs`
/// (NULL-terminated), are owned by the parent and must outlive the call to
/// the (single-threaded) child until `execve()` either succeeds or
/// `_exit()` runs.
///
/// `stdout_write_fd`/`stderr_write_fd` are dup'd over FDs 1/2; the parent
/// retains the read ends.
///
/// `groups_ptr` / `groups_len` describe the supplementary group list to apply
/// when `run_as` is `Some(_)`. The parent MUST pre-build the gid array (e.g.
/// from `UserInfo::groups`) into a stable allocation (typically
/// `Box<[libc::gid_t]>`) and pass the raw pointer + length here. The child
/// path performs **zero allocations** — see invariant note below.
///
/// # Invariant: post-fork no-alloc
///
/// `groups + env + argv` MUST be pre-built in the parent; the child path
/// performs zero allocations until `execve()` (P0-6). PAM hosts (sshd, gdm)
/// are multi-threaded; allocating in the child after `fork()` can deadlock on
/// heap mutexes held by sibling parent threads.
///
/// # Safety
///
/// MUST be called only in a child process *immediately* after `fork()` in a
/// single-threaded context. The caller guarantees:
///
/// * `argv_ptrs`, `env_ptrs` are NULL-terminated and point into stable
///   `CString` storage owned by the parent.
/// * `stdout_write_fd`, `stderr_write_fd` are valid open FDs.
/// * `caps` and `run_as` are valid for the current process.
/// * If `run_as.is_some()` and `groups_len > 0`, then `groups_ptr` is non-null
///   and points to `groups_len` valid `gid_t` values for the duration of the
///   child's run.
///
/// The function will not allocate, will not call any non-async-signal-safe
/// libc/nix function, and will either `execve()` or `_exit(127)`.
#[allow(clippy::too_many_arguments)]
// линейная последовательность шагов child-setup; дробление на хелперы ухудшит читаемость signal-safe кода.
#[allow(clippy::too_many_lines)]
pub unsafe fn child_setup(
    argv_ptrs: &[*const c_char],
    env_ptrs: &[*const c_char],
    run_as: Option<&UserInfo>,
    caps: &RlimitCaps,
    stdout_write_fd: i32,
    stderr_write_fd: i32,
    groups_ptr: *const libc::gid_t,
    groups_len: usize,
) -> ! {
    // Step 1: own process group.
    // SAFETY: setpgid is async-signal-safe.
    let setpgid_rc = unsafe { libc::setpgid(0, 0) };
    if setpgid_rc != 0 {
        // SAFETY: die is async-signal-safe.
        unsafe {
            die(b"hook child: setpgid failed\n");
        }
    }

    // Step 2: best-effort session detach. Ignore errors (we may not be a
    // session leader, which is fine).
    // SAFETY: setsid is async-signal-safe.
    unsafe {
        let _ = libc::setsid();
    }

    // Step 3: redirect stdin to /dev/null, stdout/stderr to provided FDs.
    // open(/dev/null) is async-signal-safe.
    let devnull_path = b"/dev/null\0";
    // SAFETY: open is async-signal-safe; devnull_path is a NUL-terminated
    // static byte string we own.
    let dn_fd = unsafe {
        libc::open(
            devnull_path.as_ptr().cast::<c_char>(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if dn_fd < 0 {
        // SAFETY: die is async-signal-safe.
        unsafe {
            die(b"hook child: open(/dev/null) failed\n");
        }
    }
    // SAFETY: dup2 is async-signal-safe; dn_fd is a valid open FD.
    let dup_stdin_rc = unsafe { libc::dup2(dn_fd, 0) };
    if dup_stdin_rc < 0 {
        // SAFETY: die is async-signal-safe.
        unsafe {
            die(b"hook child: dup2(devnull, 0) failed\n");
        }
    }
    // SAFETY: close is async-signal-safe; dn_fd is now duplicated onto FD 0.
    // Результат close игнорируется намеренно — закрытие неиспользуемого FD.
    #[allow(clippy::let_underscore_must_use)]
    unsafe {
        let _ = libc::close(dn_fd);
    }

    // SAFETY: dup2 is async-signal-safe; stdout_write_fd is a valid open FD
    // (caller contract).
    let dup_stdout_rc = unsafe { libc::dup2(stdout_write_fd, 1) };
    if dup_stdout_rc < 0 {
        // SAFETY: die is async-signal-safe.
        unsafe {
            die(b"hook child: dup2(stdout, 1) failed\n");
        }
    }
    // SAFETY: dup2 is async-signal-safe; stderr_write_fd is a valid open FD
    // (caller contract).
    let dup_stderr_rc = unsafe { libc::dup2(stderr_write_fd, 2) };
    if dup_stderr_rc < 0 {
        // SAFETY: die is async-signal-safe.
        unsafe {
            die(b"hook child: dup2(stderr, 2) failed\n");
        }
    }
    // Close original copies if they were not already FD 1/2.
    if stdout_write_fd > 2 {
        // SAFETY: close is async-signal-safe; stdout_write_fd already dup'd
        // onto FD 1. Результат игнорируется намеренно.
        #[allow(clippy::let_underscore_must_use)]
        unsafe {
            let _ = libc::close(stdout_write_fd);
        }
    }
    if stderr_write_fd > 2 && stderr_write_fd != stdout_write_fd {
        // SAFETY: close is async-signal-safe; stderr_write_fd already dup'd
        // onto FD 2. Результат игнорируется намеренно.
        #[allow(clippy::let_underscore_must_use)]
        unsafe {
            let _ = libc::close(stderr_write_fd);
        }
    }

    // Step 4: close all FDs >= 3 inherited from the parent. A long-running
    // PAM host (sshd, gdm, ...) routinely holds FDs above any small cap, so
    // a hard-coded bounded loop leaks descriptors into `execve`. Lowering
    // `RLIMIT_NOFILE` later only restricts future `open(2)` calls; it does
    // not close already-open inherited FDs.
    // SAFETY: every libc/syscall here is async-signal-safe (close,
    // close_range, syscall, getrlimit per POSIX).
    unsafe {
        close_high_fds();
    }

    // Step 5: apply rlimit caps. setrlimit is async-signal-safe per POSIX.
    if apply_caps(caps).is_err() {
        // SAFETY: die is async-signal-safe.
        unsafe {
            die(b"hook child: setrlimit failed\n");
        }
    }

    // Step 6: tighten umask.
    // SAFETY: umask is async-signal-safe.
    unsafe {
        libc::umask(0o077);
    }

    // Step 7: PR_SET_NO_NEW_PRIVS on Linux. macOS has no equivalent.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl is async-signal-safe.
        let prctl_rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
        if prctl_rc != 0 {
            // SAFETY: die is async-signal-safe.
            unsafe {
                die(b"hook child: prctl(NO_NEW_PRIVS) failed\n");
            }
        }
    }

    // Step 8: optional drop privileges. P0-6: groups vector was pre-built in
    // the parent and passed by raw pointer + length. The child path performs
    // NO allocations — Vec::clone here would deadlock on the heap mutex if a
    // sibling parent thread held it at fork() time.
    if let Some(user) = run_as {
        // Always set the supplementary group list, even when it is empty.
        // An empty list means `setgroups(0, ...)`, which clears root's
        // inherited supplementary groups (gid 0, disk, shadow, sudo, ...);
        // skipping the call would leave the dropped-privilege child carrying
        // them. This is the fail-safe: never keep more groups than intended.
        // SAFETY: setgroups is async-signal-safe. `groups_ptr` points into
        // stable parent-owned memory for `groups_len` `gid_t` values (caller
        // contract); with `groups_len == 0` the pointer is not dereferenced.
        #[cfg(target_os = "linux")]
        let rc = unsafe { libc::setgroups(groups_len as libc::size_t, groups_ptr) };
        #[cfg(not(target_os = "linux"))]
        let rc = {
            let len_int = libc::c_int::try_from(groups_len).unwrap_or(libc::c_int::MAX);
            // SAFETY: setgroups is async-signal-safe; `groups_ptr` points
            // into stable parent-owned memory for `groups_len` `gid_t`
            // values (caller contract); with 0 it is not dereferenced.
            unsafe { libc::setgroups(len_int, groups_ptr) }
        };
        if rc != 0 {
            // SAFETY: die is async-signal-safe.
            unsafe {
                die(b"hook child: setgroups failed\n");
            }
        }

        // SAFETY: setgid is async-signal-safe.
        let setgid_rc = unsafe { libc::setgid(user.gid as libc::gid_t) };
        if setgid_rc != 0 {
            // SAFETY: die is async-signal-safe.
            unsafe {
                die(b"hook child: setgid failed\n");
            }
        }
        // SAFETY: setuid is async-signal-safe.
        let setuid_rc = unsafe { libc::setuid(user.uid as libc::uid_t) };
        if setuid_rc != 0 {
            // SAFETY: die is async-signal-safe.
            unsafe {
                die(b"hook child: setuid failed\n");
            }
        }
    }

    // Step 9: execve.
    let argv0 = match argv_ptrs.first() {
        Some(&p) if !p.is_null() => p,
        _ => {
            // SAFETY: die is async-signal-safe.
            unsafe {
                die(b"hook child: empty argv\n");
            }
        }
    };

    // SAFETY: execve is async-signal-safe; argv0 is the non-null first entry
    // and argv_ptrs/env_ptrs are NULL-terminated (caller contract).
    unsafe {
        libc::execve(argv0, argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    // execve returned ⇒ failure.
    // SAFETY: die is async-signal-safe.
    unsafe {
        die(b"hook child: execve failed\n");
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn build_argv_ptrs_appends_null() {
        let cs = vec![
            CString::new("/bin/echo").unwrap(),
            CString::new("hello").unwrap(),
        ];
        let ptrs = build_argv_ptrs(&cs);
        assert_eq!(ptrs.len(), 3);
        assert!(ptrs[0] == cs[0].as_ptr());
        assert!(ptrs[1] == cs[1].as_ptr());
        assert!(ptrs[2].is_null());
    }

    #[test]
    fn build_argv_ptrs_empty_just_null() {
        let cs: Vec<CString> = vec![];
        let ptrs = build_argv_ptrs(&cs);
        assert_eq!(ptrs.len(), 1);
        assert!(ptrs[0].is_null());
    }
}

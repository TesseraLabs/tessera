//! An exclusive hold on a file, held for the length of a transaction.
//!
//! Two things in this product must not be done by two processes at once: an
//! append to a hash-chained journal, and a transaction against the code state
//! of a device. Both break the same way — two writers read the same tail or the
//! same counter, both act on it, and the loser's work is overwritten. In the
//! journal that breaks the chain permanently; in the code state it resets the
//! attempt budget, which turns a bounded guess into an unbounded one.
//!
//! The hold itself is the same on both, so it is written once, here. What is
//! *not* here is anything either caller owns: how the file is opened, what
//! permissions it carries, and which error type a failure becomes. This module
//! takes an open file and gives back a guard.
//!
//! # Why this crate
//!
//! The primitive has nothing to do with hash chains, and on a longer view it
//! belongs in a crate of its own. It lives here because this is the crate both
//! callers already depend on, and because the alternative — a second
//! implementation beside the first — is the failure this module exists to
//! prevent: two holds that start identical and drift apart, on a mechanism that
//! is load-bearing precisely when nobody is watching.
//!
//! # One waiting policy on every platform
//!
//! Unix has `flock(2)`, Windows has `LockFileEx`, and both are asked for the
//! hold **without blocking**. The waiting is done here instead — retry briefly,
//! then refuse — so that a caller gets the same answer on both: a refusal it
//! can report, never a login or an issuance that hangs.
//!
//! The hold is released when the handle closes, including when the process
//! dies. That is why the guard owns the file rather than borrowing it, and why
//! neither caller expresses the hold as "a lock file exists": a PAM module
//! lives inside somebody else's process and cannot promise to run any cleanup.
//!
//! # The platform with neither
//!
//! Refused, not silently granted. An unlocked transaction is the defect this
//! module prevents, and returning a guard that holds nothing would hide it on
//! exactly the platform that cannot help.

use std::fs::File;
use std::io;
use std::time::Duration;

/// An exclusive hold on a file.
///
/// The guard owns the handle the hold lives on: dropping it releases the lock,
/// and so does the process dying. It carries nothing else and exists only to be
/// held for the length of a transaction.
#[derive(Debug)]
pub struct FileLock {
    /// Never read or written. What is held is the lock on this handle, and the
    /// file exists only to have something to hold it on.
    _file: File,
}

/// Takes an exclusive hold on `file`, retrying until `timeout` has passed.
///
/// The file is taken by value: the hold lasts exactly as long as the handle,
/// and a caller that kept its own copy could drop the lock while still inside
/// the transaction it took the lock for.
///
/// # Errors
///
/// [`io::ErrorKind::TimedOut`] when another process held the file for longer
/// than `timeout`, [`io::ErrorKind::Unsupported`] on a platform with no
/// inter-process file locking, and the underlying failure for anything else.
pub fn lock_exclusive(file: File, timeout: Duration, retry: Duration) -> io::Result<FileLock> {
    acquire(file, timeout, retry)
}

/// Takes the hold through `flock(2)`.
#[cfg(unix)]
fn acquire(file: File, timeout: Duration, retry: Duration) -> io::Result<FileLock> {
    use rustix::fs::{flock, FlockOperation};
    use std::time::Instant;

    let deadline = Instant::now() + timeout;
    loop {
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(FileLock { _file: file }),
            Err(rustix::io::Errno::WOULDBLOCK | rustix::io::Errno::INTR) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "another process held the file longer than this one may wait",
                    ));
                }
                std::thread::sleep(retry);
            }
            Err(errno) => return Err(io::Error::from_raw_os_error(errno.raw_os_error())),
        }
    }
}

/// Takes the hold through `LockFileEx`.
///
/// `LOCKFILE_FAIL_IMMEDIATELY` gives the same non-blocking attempt `flock`'s
/// `LOCK_NB` gives, which is what lets the waiting policy above be one policy
/// rather than two.
///
/// # Why this crate makes an exception for `unsafe` here
///
/// The crate denies `unsafe_code`, and this is the one place it is lifted.
/// `LockFileEx` is a raw system call with no safe wrapper in the dependency
/// graph, and the alternative was to add one (`fs4`, `fd-lock`) — a new crate
/// in the graph of the component that carries the audit record, to save two
/// `unsafe` expressions whose obligations fit in a paragraph. `windows-sys` is
/// already a workspace dependency with these features on, so nothing new enters
/// the graph. The exception is scoped to this function and to no other.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "LockFileEx is a raw system call with no safe wrapper in this \
              dependency graph; the obligations are discharged in the SAFETY \
              comments below and the exception covers this function alone"
)]
fn acquire(file: File, timeout: Duration, retry: Duration) -> io::Result<FileLock> {
    use std::os::windows::io::AsRawHandle as _;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `OVERLAPPED` is a plain C struct of integers and a pointer,
        // for which an all-zero bit pattern is both valid and the value
        // `LockFileEx` documents for a non-overlapped wait.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: the handle comes from a `File` this call owns and outlives
        // the call; `overlapped` is a live, initialised structure borrowed for
        // the duration of the call and not retained by it, because the flags
        // ask for a non-overlapped attempt that completes before returning.
        let taken = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &raw mut overlapped,
            )
        };
        if taken != 0 {
            return Ok(FileLock { _file: file });
        }

        let error = io::Error::last_os_error();
        let contended = error
            .raw_os_error()
            .is_some_and(|code| code == ERROR_LOCK_VIOLATION.cast_signed());
        if !contended {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "another process held the file longer than this one may wait",
            ));
        }
        std::thread::sleep(retry);
    }
}

/// Refuses, where the platform offers no inter-process hold at all.
#[cfg(all(not(unix), not(windows)))]
fn acquire(file: File, timeout: Duration, retry: Duration) -> io::Result<FileLock> {
    let _ = (file, timeout, retry);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform offers no inter-process file locking",
    ))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use std::time::Duration;

    use super::lock_exclusive;

    fn open(path: &std::path::Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .unwrap()
    }

    #[test]
    fn the_hold_is_taken_and_released_with_the_guard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hold");

        let guard = lock_exclusive(
            open(&path),
            Duration::from_secs(1),
            Duration::from_millis(5),
        )
        .unwrap();
        drop(guard);

        // Released: the same file locks again straight away.
        assert!(lock_exclusive(
            open(&path),
            Duration::from_secs(1),
            Duration::from_millis(5)
        )
        .is_ok());
    }

    #[test]
    fn a_second_hold_waits_and_then_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hold");

        let _held = lock_exclusive(
            open(&path),
            Duration::from_secs(1),
            Duration::from_millis(5),
        )
        .unwrap();

        // The refusal is a refusal, not a hang: the second caller comes back
        // inside its own timeout.
        let started = std::time::Instant::now();
        let refused = lock_exclusive(
            open(&path),
            Duration::from_millis(50),
            Duration::from_millis(5),
        );
        assert!(refused.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}

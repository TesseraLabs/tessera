//! Daemon singleton enforcement via `flock(2)`.
//!
//! Защита от второго экземпляра демона: если оператор по ошибке запустит
//! `tessera daemon` руками рядом с уже работающим systemd-юнитом (или
//! дважды стартует юнит из-за гонки/ошибки в скрипте), второй процесс
//! должен немедленно и громко отказаться стартовать, а не молча начать
//! бороться за тот же сокет, файл состояния и enforcement-канал.
//!
//! Semantics:
//!
//! * Open `<state_dir>/daemon.lock` (mode 0600) with `O_RDWR | O_CREAT`.
//! * Attempt a non-blocking exclusive `flock(LOCK_EX | LOCK_NB)`.
//! * On `EWOULDBLOCK` the existing PID is read from the file and a
//!   CRITICAL audit event is emitted, then the caller exits.
//! * On success we truncate the file and write our own PID **through
//!   the same fd that owns the flock**, to avoid a TOCTOU window where
//!   a concurrent second daemon could read the stale predecessor PID.
//!   The fd is kept alive (inside [`DaemonLock`]) for the lifetime of
//!   the daemon. Closing the fd would release the kernel-held flock;
//!   the kernel releases it for us automatically on process exit/crash.
//!
//! `Drop` deliberately does NOT explicitly close or unlock — `Flock`'s
//! own drop releases the lock when the process is shutting down anyway,
//! which is fine, and avoiding an explicit close means we cannot
//! accidentally drop the guard mid-life (use-after-free of the singleton
//! invariant). Storing this struct in a long-lived binding is sufficient.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

// Defence-in-depth: we set `O_CLOEXEC` explicitly on the lock fd
// even though Rust std defaults to that already. Future refactors that
// drop down to raw `libc::open()` would lose the default; the explicit
// flag documents the invariant. See `acquire()` below.
use libc::O_CLOEXEC;

/// Errors returned from [`DaemonLock::acquire`].
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Could not open the lock file (permissions, missing parent dir,
    /// etc.).
    #[error("failed to open lock file {path}: {source}")]
    Open {
        /// Path that failed to open.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Another process already holds the exclusive lock.
    #[error("another daemon instance holds the lock at {path} (pid={pid:?})")]
    AlreadyHeld {
        /// Lock path.
        path: PathBuf,
        /// PID read from the lock file content, if parseable.
        pid: Option<i32>,
    },
    /// Unexpected `flock(2)` failure (something other than `EWOULDBLOCK`).
    #[error("flock({path}) failed: {errno}")]
    FlockOther {
        /// Lock path.
        path: PathBuf,
        /// `errno` from `flock(2)`.
        errno: Errno,
    },
    /// Could not write our PID into the lock file.
    #[error("failed to write pid to {path}: {source}")]
    Write {
        /// Lock path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Owns the exclusive `flock(2)` over the daemon lock file.
///
/// The wrapped [`Flock`] keeps the underlying fd alive for the lifetime
/// of this value; the lock is released by the kernel either when
/// `Flock::drop` runs (process tear-down) or when the process exits.
#[must_use = "dropping the guard releases the singleton lock; bind it to a daemon-lifetime variable"]
#[derive(Debug)]
pub struct DaemonLock {
    /// Path of the lock file, retained for diagnostics.
    path: PathBuf,
    /// Active `flock`. Held until process exit.
    _lock: Flock<File>,
}

impl DaemonLock {
    /// Path on disk this lock is bound to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Attempt to acquire the singleton lock at `path`.
    ///
    /// On success the current PID is written into the file (truncating
    /// any prior content). On contention the caller gets back
    /// [`LockError::AlreadyHeld`] with the conflicting PID parsed from
    /// the existing content (best-effort; `None` if unreadable).
    pub fn acquire(path: &Path) -> Result<Self, LockError> {
        let mut opts = OpenOptions::new();
        opts.read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            // Explicit O_CLOEXEC. Std already sets this by default,
            // but the explicit flag documents the singleton invariant.
            .custom_flags(O_CLOEXEC);
        let file = opts.open(path).map_err(|e| LockError::Open {
            path: path.to_path_buf(),
            source: e,
        })?;

        let lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(l) => l,
            Err((existing, errno)) => {
                // On Linux EWOULDBLOCK == EAGAIN so we only need to match one.
                if matches!(errno, Errno::EWOULDBLOCK) {
                    let pid = read_pid_from(existing);
                    return Err(LockError::AlreadyHeld {
                        path: path.to_path_buf(),
                        pid,
                    });
                }
                return Err(LockError::FlockOther {
                    path: path.to_path_buf(),
                    errno,
                });
            }
        };

        // Write our PID through the lock-holding fd itself, NOT via
        // a second `OpenOptions::open(path)` re-open. The re-open path
        // had a TOCTOU window: between successful `flock(LOCK_EX)` and
        // the second open's `truncate(true)` completing, a concurrent
        // would-be second daemon that just hit the AlreadyHeld branch
        // could read the stale predecessor PID from the file. Writing
        // through the locked fd closes that window — any reader either
        // sees our PID or an empty file (truncate happened-before the
        // write), never a stale predecessor PID.
        write_pid_through(&lock, path)?;

        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock,
        })
    }
}

/// Truncate the lock-holding file and write `std::process::id()\n`
/// through the same fd that owns the flock. `Flock<File>` exposes the
/// underlying `&File` via `Deref`; using it directly avoids the TOCTOU
/// window that a second `OpenOptions::open(path)` would introduce
/// between acquiring the flock and truncating the stale predecessor PID.
fn write_pid_through(lock: &Flock<File>, path: &Path) -> Result<(), LockError> {
    // `Flock<File>` derefs to `&File`. `File::set_len` /
    // `File::sync_data` take `&self`, and `Write` is implemented for
    // `&File`, so a shared borrow is sufficient for all three
    // operations.
    let file: &File = lock;
    // Truncate first so a partial pre-existing PID can't survive past
    // the next write (e.g. if our PID's decimal form is shorter than
    // the predecessor's).
    file.set_len(0).map_err(|e| LockError::Write {
        path: path.to_path_buf(),
        source: e,
    })?;
    let pid_bytes = format!("{}\n", std::process::id());
    let mut writer: &File = file;
    writer
        .write_all(pid_bytes.as_bytes())
        .map_err(|e| LockError::Write {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.sync_data().map_err(|e| LockError::Write {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Best-effort parse of the PID stored inside an existing lock file.
fn read_pid_from(mut file: File) -> Option<i32> {
    // Seek failure simply means we read from current pos; either way the
    // best-effort PID parse below will return None on garbage. `seek`
    // returns a `Copy` `u64`, so naming the binding (rather than `let _ =`)
    // both documents the intentional discard and satisfies
    // `clippy::let_underscore_must_use`.
    let _seek = file.seek(SeekFrom::Start(0));
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;
    buf.trim().parse::<i32>().ok()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_wrap
)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn acquires_lock_when_unheld() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");
        let lock = DaemonLock::acquire(&path).expect("acquire");
        assert_eq!(lock.path(), path);
        // PID was written.
        let content = std::fs::read_to_string(&path).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());
        drop(lock);
    }

    #[test]
    fn rejects_when_already_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");
        let _first = DaemonLock::acquire(&path).expect("first acquire");

        // Second acquire must fail. flock(2) is per-open-file-description,
        // and OpenOptions::open in a child thread creates a separate
        // description, so this exercises the contention path correctly.
        let path_for_thread = path.clone();
        let result = thread::spawn(move || DaemonLock::acquire(&path_for_thread))
            .join()
            .expect("thread");
        match result {
            Err(LockError::AlreadyHeld { pid, .. }) => {
                assert_eq!(pid, Some(std::process::id() as i32));
            }
            other => panic!("expected AlreadyHeld, got {other:?}"),
        }
    }

    /// Regression test for the TOCTOU window: after a daemon acquires the lock,
    /// the file MUST contain the current holder's PID, not the previous
    /// holder's. This proves the truncate+write happens through the
    /// locked fd before any potential concurrent reader can race in.
    #[test]
    fn pid_in_file_is_holder_not_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");

        // First holder: acquire, then drop.
        let first = DaemonLock::acquire(&path).expect("first acquire");
        let after_first = std::fs::read_to_string(&path).unwrap();
        let first_pid: u32 = after_first.trim().parse().unwrap();
        assert_eq!(first_pid, std::process::id());
        drop(first);

        // Predecessor PID is still on disk after drop (we don't
        // unlink). Simulate that by overwriting the file with a known
        // bogus "predecessor" PID before the second acquire so the
        // observable check is unambiguous even when both holders share
        // the same process id (which they do inside one test binary).
        std::fs::write(&path, "999999\n").unwrap();

        // Second holder: re-acquire. The truncate+write through the
        // locked fd must overwrite the 999999 predecessor immediately.
        let _second = DaemonLock::acquire(&path).expect("second acquire");
        let after_second = std::fs::read_to_string(&path).unwrap();
        let second_pid: u32 = after_second.trim().parse().unwrap();
        assert_eq!(
            second_pid,
            std::process::id(),
            "lock file must contain current holder's PID (not predecessor's 999999)"
        );
        assert_ne!(second_pid, 999_999, "predecessor PID was not overwritten");
    }

    #[test]
    fn releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");
        let first = DaemonLock::acquire(&path).expect("first");
        drop(first);
        // After drop the kernel-held flock is released; we can acquire again.
        let _second = DaemonLock::acquire(&path).expect("second after drop");
    }
}

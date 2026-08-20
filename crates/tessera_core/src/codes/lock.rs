//! The lock that makes the nonce state a transaction.
//!
//! `pam_tessera` is a shared object loaded into somebody else's process. `sshd`
//! forks per connection, a console login is a process of its own, and a device
//! reachable both ways runs them at the same time. Every one of them opens the
//! same state directory.
//!
//! Without a lock the read-modify-write of that state is not a transaction, and
//! the consequences are not bookkeeping ones:
//!
//! - process **B** loads the state, process **A** spends the whole attempt
//!   budget of a nonce, **B** writes back the snapshot it took before any of
//!   that happened, and the budget is `0` again. Repeat and the budget is
//!   unbounded, which is the only thing standing between a code and a guesser;
//! - the spent-nonce set is lost the same way, and a one-time nonce that
//!   forgets it was used is not one-time;
//! - two processes read the same counter and issue the same nonce, and the
//!   pending attempts — keyed on the counter alone — overwrite each other.
//!
//! So the lock covers the **whole transaction**, load through save, not the
//! individual writes. Atomic renames were never the missing piece: each write
//! was already atomic, and that is precisely why the corruption is invisible —
//! nothing is torn, the state is simply the wrong one.
//!
//! # Why `flock` and not a lock file
//!
//! A lock expressed as "the file exists" leaks on a crash, and a PAM module
//! lives inside a process it does not control. `flock(2)` is held by an open
//! descriptor, so the kernel releases it when the process dies however it dies.
//! The lock file itself is never deleted; only the advisory lock on it moves.
//!
//! # Why the wait is bounded
//!
//! A blocking acquisition would hang a login for as long as some other process
//! misbehaves, and a login that hangs on a device reachable only by telephone
//! is the failure this whole method exists to avoid. The wait is bounded and
//! then refused, which costs an engineer a retry and costs nobody a hung
//! greeter.

use std::fs::File;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

/// Name of the lock file inside the state directory.
pub const LOCK_FILENAME: &str = "nonce.lock";

/// Permissions of the lock file: root alone, like everything beside it.
const LOCK_MODE: u32 = 0o600;

/// Longest a login waits for another process to finish its transaction.
///
/// One transaction is a handful of small file operations plus, on the
/// verification path, one key agreement — milliseconds. A wait that reaches
/// this bound means the holder is not making progress, and waiting longer would
/// only move the failure from "refused" to "hung".
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to sleep between attempts while waiting.
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// An exclusive hold on the state of one device, released on drop.
///
/// The guard owns the descriptor the lock lives on, so dropping it — or the
/// process dying with it — releases the lock. It carries no state of its own
/// and exists only to be held for the length of a transaction.
#[derive(Debug)]
pub struct StateLock {
    /// The locked descriptor. Never read or written: what is held is the lock,
    /// not the file, and the file exists only to have an inode to hold it on.
    #[cfg(unix)]
    _file: nix::fcntl::Flock<File>,
    /// The same, where there is no `flock(2)` to hold — unreachable, because
    /// [`StateLock::acquire`] refuses first.
    #[cfg(not(unix))]
    _file: File,
}

impl StateLock {
    /// Takes the exclusive lock of `state_dir`, waiting up to [`LOCK_TIMEOUT`].
    ///
    /// The directory must already exist: the method creates it when it opens,
    /// so that a device offering the method has somewhere to put its state
    /// before an engineer is asked for anything.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::TimedOut`] when another process held the lock for
    /// longer than the bound, [`io::ErrorKind::Unsupported`] on a target
    /// without `flock(2)`, and the underlying failure when the lock file
    /// cannot be opened.
    pub fn acquire(state_dir: &Path) -> io::Result<Self> {
        let path = state_dir.join(LOCK_FILENAME);
        let file = crate::fs_mode::create_with_mode(&path, LOCK_MODE)?;
        // The mode of `open(2)` is filtered through the umask, and this file
        // names the transaction of every login on the device.
        crate::fs_mode::pin_mode(&path, LOCK_MODE)?;

        acquire_with_deadline(file, Instant::now() + LOCK_TIMEOUT)
    }
}

/// Takes the lock, retrying without blocking until `deadline`.
#[cfg(unix)]
fn acquire_with_deadline(file: File, deadline: Instant) -> io::Result<StateLock> {
    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};

    let mut candidate = file;
    loop {
        match Flock::lock(candidate, FlockArg::LockExclusiveNonblock) {
            Ok(locked) => return Ok(StateLock { _file: locked }),
            // The file comes back on failure so the next attempt reuses the
            // same descriptor: reopening would take a fresh one and, if the
            // path were replaced in between, lock a different inode.
            Err((returned, Errno::EWOULDBLOCK | Errno::EINTR)) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "another login held the code state longer than this one may wait",
                    ));
                }
                candidate = returned;
                std::thread::sleep(LOCK_RETRY_INTERVAL);
            }
            Err((_, errno)) => return Err(io::Error::from(errno)),
        }
    }
}

/// Takes the lock — refused where there is no `flock(2)` to take.
#[cfg(not(unix))]
fn acquire_with_deadline(file: File, deadline: Instant) -> io::Result<StateLock> {
    let _ = (file, deadline);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the code state cannot be locked on this platform",
    ))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{StateLock, LOCK_FILENAME};

    #[test]
    fn the_lock_is_taken_and_released_with_the_guard() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _guard = StateLock::acquire(dir.path()).unwrap();
            // A second acquisition inside the same process would deadlock on
            // some platforms and succeed on others, so the released case is
            // what is checked here; the cross-process case is in `tests.rs`.
        }
        let _again = StateLock::acquire(dir.path()).unwrap();
        assert!(dir.path().join(LOCK_FILENAME).is_file());
    }

    #[test]
    fn the_lock_file_is_not_removed_when_the_guard_drops() {
        // Deleting it would let the next process create a fresh inode and lock
        // that instead, which locks nothing against a process still holding
        // the old one.
        let dir = tempfile::tempdir().unwrap();
        drop(StateLock::acquire(dir.path()).unwrap());
        assert!(dir.path().join(LOCK_FILENAME).is_file());
    }
}

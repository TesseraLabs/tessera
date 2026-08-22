//! The lock that gives a device one attempt at a time.
//!
//! `pam_tessera` is a shared object loaded into somebody else's process. `sshd`
//! forks per connection, a console login is a process of its own, and a device
//! reachable both ways runs them at the same time. Every one of them opens the
//! same state directory.
//!
//! Without a lock the consequences are not bookkeeping ones:
//!
//! - a second login starts a second attempt while the first is being answered,
//!   and a device that is supposed to hold one attempt holds two — twice the
//!   target for a guesser, and two ephemeral pairs where the specification
//!   allows one;
//! - the read-modify-write of the throttle is not a transaction: process **B**
//!   loads it, process **A** records a run of failures, **B** writes back the
//!   snapshot it took before any of that happened, and the lockout is gone.
//!   Repeat, and a limit that can be reset is not a limit.
//!
//! So the hold is taken when an attempt begins and released when the attempt is
//! dropped — see [`super::StartedAttempt`] — rather than around the individual
//! writes. Atomic renames were never the missing piece: each write was already
//! atomic, and that is precisely why the corruption is invisible — nothing is
//! torn, the state is simply the wrong one.
//!
//! # Why a hold on a handle, and not a lock file
//!
//! A lock expressed as "the file exists" leaks on a crash, and a PAM module
//! lives inside a process it does not control. A hold on an open handle —
//! `flock(2)` on Unix, `LockFileEx` on Windows — is released by the system when
//! the process dies however it dies. The lock file itself is never deleted;
//! only the hold on it moves.
//!
//! The hold is [`tessera_hashchain::file_lock`], the same primitive the journal
//! of this product takes for the same reason. One mechanism rather than two is
//! the point: this one keeps codes one-time, and two implementations of it
//! would drift apart exactly where nobody is looking.
//!
//! # What is not closed off Unix
//!
//! The lock file carries mode `0600` on Unix. Off Unix there is no mode word,
//! so it carries whatever the directory grants, and "a file anyone may replace
//! is a lock anyone may take somewhere else" stays open there — as it does for
//! the artefacts of the store and for the journal, and for the same reason:
//! closing it means a DACL, which belongs with the machinery that already does
//! DACL work. Named here so that the absence of the check is not read as a
//! check that passed.
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
use std::time::Duration;

/// Name of the lock file inside the state directory.
pub const LOCK_FILENAME: &str = "nonce.lock";

/// Permissions of the lock file: root alone, like everything beside it.
///
/// Declared only where a mode word exists. Off Unix the file carries what the
/// directory grants — see the module docs, where that gap is named rather than
/// papered over with a constant nothing applies.
#[cfg(unix)]
const LOCK_MODE: u32 = 0o600;

/// Longest a login waits for another process to finish its transaction.
///
/// Public because the caller turns a wait that reached it into the refusal that
/// says how long to wait, and the two numbers have to be one.
///
/// One transaction is a handful of small file operations plus, on the
/// verification path, one key agreement — milliseconds. A wait that reaches
/// this bound means the holder is not making progress, and waiting longer would
/// only move the failure from "refused" to "hung".
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to sleep between attempts while waiting.
///
/// Both values are handed to the shared hold, which does the waiting, so the
/// cadence and the bound are named once here and apply on every platform.
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// An exclusive hold on the state of one device, released on drop.
///
/// The guard owns the descriptor the lock lives on, so dropping it — or the
/// process dying with it — releases the lock. It carries no state of its own
/// and exists only to be held for the length of a transaction.
#[derive(Debug)]
pub struct StateLock {
    /// The hold. Never read or written: what is held is the lock, not the file,
    /// and the file exists only to have something to hold it on.
    _held: tessera_hashchain::file_lock::FileLock,
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
    /// longer than the bound, [`io::ErrorKind::Unsupported`] on a platform with
    /// no inter-process file locking at all, and the underlying failure when
    /// the lock file cannot be opened.
    pub fn acquire(state_dir: &Path) -> io::Result<Self> {
        let path = state_dir.join(LOCK_FILENAME);
        let file = open_lock_file(&path)?;
        let held =
            tessera_hashchain::file_lock::lock_exclusive(file, LOCK_TIMEOUT, LOCK_RETRY_INTERVAL)?;
        Ok(Self { _held: held })
    }
}

/// Opens the lock file with the mode a file naming every login deserves.
#[cfg(unix)]
fn open_lock_file(path: &Path) -> io::Result<File> {
    let file = crate::fs_mode::create_with_mode(path, LOCK_MODE)?;
    // The mode of `open(2)` is filtered through the umask, and this file names
    // the transaction of every login on the device.
    crate::fs_mode::pin_mode(path, LOCK_MODE)?;
    Ok(file)
}

/// The same, where there is no mode word to pin.
///
/// Opened without one rather than refused: the hold is what makes the state a
/// transaction, and refusing here would take the whole code method off the
/// platform to protect a permission the platform does not express. What that
/// leaves open is stated in the module docs, not silently accepted.
#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed setup step in a test should fail the test on the spot, \
              including the child process that reports what it waited for"
)]
mod tests {
    use std::time::Duration;

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
    /// Environment variable naming the state directory the child process locks.
    const CHILD_LOCK_DIR: &str = "TESSERA_CODES_TEST_LOCK_DIR";

    /// The child half of [`the_state_is_locked_against_a_second_process`].
    ///
    /// Runs as an ordinary test — and does nothing — unless the parent set
    /// [`CHILD_LOCK_DIR`], which it only does when it re-executes this binary. The
    /// child takes the lock of that directory and reports, on stdout, how long it
    /// had to wait: the parent holds the lock while the child starts, so a wait it
    /// did not perform is a lock that does not cross a process boundary.
    #[test]
    fn child_process_reports_how_long_the_lock_made_it_wait() {
        let Ok(dir) = std::env::var(CHILD_LOCK_DIR) else {
            return;
        };
        let started = std::time::Instant::now();
        let guard = StateLock::acquire(std::path::Path::new(&dir));
        let waited = started.elapsed();
        drop(guard.unwrap());
        println!("WAITED_MS={}", waited.as_millis());
    }

    /// The state of a device is locked against another **process**, not merely
    /// against another thread.
    ///
    /// Threads would prove nothing here: the hold belongs to an open handle, so
    /// two threads of one process share it and never contend. The defect this
    /// guards lives between processes, which is what a PAM module is — `sshd`
    /// forks per connection, a console login is its own process, and a device
    /// reachable both ways runs them at the same time. Without a lock spanning the
    /// whole load-mutate-save, the second process writes back a snapshot taken
    /// before the first one spent the attempt budget, and the budget resets to zero
    /// as often as an attacker likes.
    ///
    /// So the second party is a real process: this binary, re-executed against the
    /// child test above.
    ///
    /// Runs on every platform that has a hold to take. It was Unix-only while the
    /// other arm refused outright; now that Windows takes a real hold through
    /// `LockFileEx`, the platform where the mechanism is newest is exactly the one
    /// that must not be taken on trust.
    #[test]
    fn the_state_is_locked_against_a_second_process() {
        use std::process::Command;

        /// How long the parent keeps the lock while the child tries for it.
        const HELD: Duration = Duration::from_millis(400);
        /// The wait the child must report at least. Below `HELD` by a margin, so
        /// the assertion turns on the lock and not on scheduler jitter.
        const MIN_REPORTED_WAIT_MS: u128 = 200;

        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_path_buf();

        let exe = std::env::current_exe().unwrap();
        let guard = StateLock::acquire(&state_dir).unwrap();

        let child = Command::new(exe)
            .args([
                "--exact",
                "codes::lock::tests::child_process_reports_how_long_the_lock_made_it_wait",
                "--nocapture",
            ])
            .env(CHILD_LOCK_DIR, &state_dir)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        // Held while the child starts up and blocks on the lock.
        std::thread::sleep(HELD);
        drop(guard);

        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "the child test failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let waited: u128 = stdout
            .lines()
            .find_map(|line| line.strip_prefix("WAITED_MS="))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or_else(|| panic!("the child reported no wait; it printed: {stdout}"));

        assert!(
            waited >= MIN_REPORTED_WAIT_MS,
            "a second process took the lock after {waited}ms without waiting for this one to \
             release it: the state of the device is not locked across processes",
        );
    }
}

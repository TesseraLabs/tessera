//! The persisted nonce counter.
//!
//! One number in one root-owned file, written the way the role bundle version
//! is written — a temporary file, `fsync`, a rename — so a reader never sees a
//! torn value and a power cut never leaves a counter that reads as smaller than
//! the last nonce spoken aloud.
//!
//! The counter is the monotonic half of the hybrid nonce, and the property that
//! matters is what it must never do: repeat inside a key epoch. It is therefore
//! never carried around its modulus. A device that has used up the width its
//! fleet parameters fix owes a key epoch rotation, and the type of the result
//! says so.
//!
//! A file that is present but unparseable is not treated as an absent one. A
//! corrupt counter that reset to zero would re-issue every nonce of the epoch,
//! which is precisely the outcome the counter exists to prevent.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// Name of the counter file inside the state directory.
pub const COUNTER_FILENAME: &str = "nonce.counter";

/// Permissions of the counter file: readable and writable by root alone.
const COUNTER_MODE: u32 = 0o600;

/// The last counter value this device issued, as it is stored on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuedCounter(u64);

impl IssuedCounter {
    /// Returns the value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Reads the last issued counter from `state_dir`.
///
/// `Ok(None)` when the file is absent — a device that has never issued a
/// challenge. A present but unparseable file is an error.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] for a file that does not hold a decimal
/// number, and the underlying failure for any other read error.
pub fn read_issued(state_dir: &Path) -> io::Result<Option<IssuedCounter>> {
    let path = counter_path(state_dir);
    match fs::read_to_string(&path) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map(|value| Some(IssuedCounter(value)))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the persisted nonce counter is not a decimal number",
                )
            }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Writes `value` as the last issued counter, atomically.
///
/// # Errors
///
/// The underlying I/O failure. The temporary file is removed on failure so a
/// half-written value is never left behind under a name a reader looks at.
pub fn write_issued(state_dir: &Path, value: u64) -> io::Result<()> {
    let path = counter_path(state_dir);
    let tmp = state_dir.join(format!(".{COUNTER_FILENAME}.{}.tmp", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = crate::fs_mode::create_with_mode(&tmp, COUNTER_MODE)?;
        file.write_all(format!("{value}\n").as_bytes())?;
        file.sync_all()?;
        // The mode of `open(2)` is filtered through the umask; pin it before
        // the file is published under the name a reader opens.
        crate::fs_mode::pin_mode(&tmp, COUNTER_MODE)?;
        fs::rename(&tmp, &path)?;
        // The rename itself has to reach the disk. Without this the counter can
        // be lost across a power cut while the state file that was written
        // beside it survives, and a counter behind the state is refused as a
        // rollback — on an offline device, until a key epoch rotation is
        // carried out by hand.
        crate::fs_mode::sync_dir(state_dir)
    })();
    if result.is_err() {
        if let Err(cleanup) = fs::remove_file(&tmp) {
            if cleanup.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    target: "codes.audit",
                    path = %tmp.display(),
                    error = %cleanup,
                    "failed to clean up the nonce counter temporary file"
                );
            }
        }
    }
    result
}

/// Returns the path of the counter file inside `state_dir`.
fn counter_path(state_dir: &Path) -> PathBuf {
    state_dir.join(COUNTER_FILENAME)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{read_issued, COUNTER_FILENAME};

    #[test]
    fn an_absent_counter_reads_as_nothing_issued() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_issued(dir.path()).unwrap().is_none());
    }

    #[test]
    fn a_corrupt_counter_is_not_an_absent_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(COUNTER_FILENAME), b"forty-two\n").unwrap();
        assert!(read_issued(dir.path()).is_err());
    }

    /// Tests that write the persisted state of the device.
    ///
    /// They need a platform whose file permissions can be checked, and that is a
    /// property of the method rather than of the harness: the device key is kept
    /// **without a password**, because codes have to be verified after a reboot
    /// with nobody there to type one, so what protects it is the mode of the
    /// files beside it. Outside Unix there is no mode word — the equivalent is a
    /// DACL, and none is written here — so the writes below refuse by design.
    /// See `codes::store`, `codes::lock` and the storage of `tessera_hashchain`,
    /// where the same boundary is stated, and `platform_offers_the_method`,
    /// which is where the product answers it.
    ///
    /// Reading the same state stays outside this group: a device that cannot
    /// write a counter can still parse one, and those tests keep running
    /// everywhere.
    #[cfg(unix)]
    mod persisted {
        use super::super::write_issued;
        use super::*;

        #[test]
        fn a_written_counter_reads_back() {
            let dir = tempfile::tempdir().unwrap();
            write_issued(dir.path(), 41).unwrap();
            assert_eq!(read_issued(dir.path()).unwrap().unwrap().get(), 41);
            write_issued(dir.path(), 42).unwrap();
            assert_eq!(read_issued(dir.path()).unwrap().unwrap().get(), 42);
        }

        #[test]
        fn the_write_leaves_no_temporary_file_behind() {
            let dir = tempfile::tempdir().unwrap();
            write_issued(dir.path(), 7).unwrap();
            let leftovers: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name != COUNTER_FILENAME)
                .collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");
        }
    }
}

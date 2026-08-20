//! The persisted key epoch of the device.
//!
//! The epoch names which device key pair the codes of a fleet are computed
//! against. It arrives with the artefacts — in the enrolment package or in a
//! courier payload — and it is persisted here beside the nonce counter, in the
//! same shape and with the same durability: one number, one root-only file,
//! written through a temporary file, `fsync` and a rename.
//!
//! What the file is for is anti-rollback. A device that has moved to a new key
//! must never be talked back into the old one by re-presenting the medium the
//! old one arrived on: the codes of the previous epoch were computed against a
//! key whose nonces have already been spoken aloud, and a fleet that recovers a
//! stolen medium cannot undo that. So the number only ever grows, exactly as
//! `bundle_version` does for the role bundle, and an import naming a smaller
//! epoch is refused rather than merged.
//!
//! A file that is present but unparseable is not treated as an absent one. An
//! absent epoch means "this device has never received a Codes key" and the next
//! import establishes the floor; a corrupt one means something wrote over the
//! floor, and accepting any epoch after that would be accepting a rollback.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use tessera_codes_contract::key::Epoch;

/// Name of the epoch file inside the state directory.
pub const EPOCH_FILENAME: &str = "key.epoch";

/// Permissions of the epoch file: readable and writable by root alone.
const EPOCH_MODE: u32 = 0o600;

/// Reads the epoch this device last accepted.
///
/// `Ok(None)` when the file is absent — a device that has never been given a
/// Codes key. A present but unparseable file is an error.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] for a file that does not hold a decimal
/// number in the range of an epoch, and the underlying failure for any other
/// read error.
pub fn read(state_dir: &Path) -> io::Result<Option<Epoch>> {
    match fs::read_to_string(epoch_path(state_dir)) {
        Ok(text) => text
            .trim()
            .parse::<u32>()
            .map(|value| Some(Epoch::new(value)))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the persisted key epoch is not a decimal number",
                )
            }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Writes `epoch` as the epoch this device has accepted, atomically.
///
/// # Errors
///
/// The underlying I/O failure. The temporary file is removed on failure, so a
/// half-written value is never left behind under the name a reader opens.
pub fn write(state_dir: &Path, epoch: Epoch) -> io::Result<()> {
    let path = epoch_path(state_dir);
    let tmp = state_dir.join(format!(".{EPOCH_FILENAME}.{}.tmp", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = crate::fs_mode::create_with_mode(&tmp, EPOCH_MODE)?;
        file.write_all(format!("{}\n", epoch.get()).as_bytes())?;
        file.sync_all()?;
        // The mode of `open(2)` is filtered through the umask; pin it before
        // the file is published under the name a reader opens.
        crate::fs_mode::pin_mode(&tmp, EPOCH_MODE)?;
        fs::rename(&tmp, &path)?;
        // The rename itself has to reach the disk: an epoch lost across a power
        // cut is an anti-rollback floor lost, and the medium that carried the
        // previous key would be accepted again.
        crate::fs_mode::sync_dir(state_dir)
    })();
    if result.is_err() {
        if let Err(cleanup) = fs::remove_file(&tmp) {
            if cleanup.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    target: "codes.audit",
                    path = %tmp.display(),
                    error = %cleanup,
                    "failed to clean up the key epoch temporary file"
                );
            }
        }
    }
    result
}

/// Decides which epoch the method computes codes with.
///
/// The key in the store and the number in [`EPOCH_FILENAME`] are written by one
/// transaction, so the persisted value is what the *key on this device* belongs
/// to. The configured value is a fleet parameter that an administrator edits,
/// and it lags: an import that rotates the key moves the store forward without
/// touching `config.toml`. Computing codes against the configured number after
/// such an import would derive a key nobody else derives, and every code an
/// operator read out would be refused with no clue why. So the persisted value
/// wins where there is one.
///
/// A configuration naming an epoch *above* the store is the case that is
/// refused rather than resolved. It says the device was expected to receive a
/// key it does not have — a delivery that did not arrive, or a store that lost
/// its epoch — and quietly falling back to the older key would hide exactly the
/// failure a fleet needs to see.
///
/// A device with no persisted epoch takes the configured one: that is the fleet
/// whose artefacts were placed by hand, which is how devices were provisioned
/// before the enrolment package carried them.
///
/// # Errors
///
/// The two epochs and a description, when the configuration is ahead of the
/// store. The caller turns it into its own refusal.
pub fn effective(configured: Epoch, persisted: Option<Epoch>) -> Result<Epoch, EpochMismatch> {
    match persisted {
        None => Ok(configured),
        Some(persisted) if persisted >= configured => Ok(persisted),
        Some(persisted) => Err(EpochMismatch {
            configured,
            persisted,
        }),
    }
}

/// The configuration names a key epoch the store does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the configuration names key epoch {} but the device holds epoch {}; \
     the key of the configured epoch never arrived",
    configured.get(),
    persisted.get()
)]
pub struct EpochMismatch {
    /// Epoch the configuration names.
    pub configured: Epoch,
    /// Epoch the store holds.
    pub persisted: Epoch,
}

/// Removes the persisted epoch, if there is one.
///
/// Used by the wipe of a device leaving the fleet. A file that is not there is
/// not an error: a fleet of Access-only devices never wrote one.
///
/// # Errors
///
/// The underlying I/O failure of the removal.
pub fn remove(state_dir: &Path) -> io::Result<()> {
    match fs::remove_file(epoch_path(state_dir)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Returns the path of the epoch file inside `state_dir`.
fn epoch_path(state_dir: &Path) -> PathBuf {
    state_dir.join(EPOCH_FILENAME)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use tessera_codes_contract::key::Epoch;

    use super::{effective, read, remove, write, EPOCH_FILENAME};

    #[test]
    fn an_absent_epoch_reads_as_never_provisioned() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path()).unwrap().is_none());
    }

    #[test]
    fn a_written_epoch_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), Epoch::new(3)).unwrap();
        assert_eq!(read(dir.path()).unwrap(), Some(Epoch::new(3)));
        write(dir.path(), Epoch::new(4)).unwrap();
        assert_eq!(read(dir.path()).unwrap(), Some(Epoch::new(4)));
    }

    #[test]
    fn a_corrupt_epoch_is_not_an_absent_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(EPOCH_FILENAME), b"seven\n").unwrap();
        assert!(read(dir.path()).is_err());
    }

    #[test]
    fn a_device_without_a_persisted_epoch_takes_the_configured_one() {
        // The fleet whose artefacts were placed by hand, which is how a device
        // was provisioned before the package carried them.
        assert_eq!(effective(Epoch::new(2), None).unwrap(), Epoch::new(2));
    }

    #[test]
    fn a_rotated_store_wins_over_a_configuration_that_lags() {
        // The import moved the device to a new key without touching
        // `config.toml`; computing codes against the old number would derive a
        // key nobody else derives.
        assert_eq!(
            effective(Epoch::new(2), Some(Epoch::new(5))).unwrap(),
            Epoch::new(5)
        );
        assert_eq!(
            effective(Epoch::new(5), Some(Epoch::new(5))).unwrap(),
            Epoch::new(5)
        );
    }

    #[test]
    fn a_configuration_ahead_of_the_store_is_refused() {
        let error = effective(Epoch::new(6), Some(Epoch::new(5))).unwrap_err();
        assert_eq!(error.configured, Epoch::new(6));
        assert_eq!(error.persisted, Epoch::new(5));
    }

    #[test]
    fn removing_an_epoch_that_was_never_written_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        remove(dir.path()).unwrap();
        write(dir.path(), Epoch::new(1)).unwrap();
        remove(dir.path()).unwrap();
        assert!(read(dir.path()).unwrap().is_none());
    }
}

//! The owner-only gate every file holding secret material passes through.
//!
//! Two inputs of the issuer are secret-bearing files: the file backend's PKCS#8
//! CA key and a secret file named on the command line (`--pin-file`,
//! `--key-passphrase-file`). Both are refused when the filesystem lets anyone
//! but the owner read them.
//!
//! The gate is applied to an *open descriptor*, never to a path: [`open`]
//! opens the file first and checks the metadata of that very handle, so the
//! answer cannot describe a different file than the one whose bytes are read.
//! Checking a path and then opening it leaves a window in which the path is
//! repointed — through a symlink or a rename — at a file the check never saw.
//! Opening does not read, so the requirement that an over-permissive file is
//! refused *before its content is read* still holds.
//!
//! The check lives here rather than beside either reader so the platform
//! difference has a single site: Unix has a permission model to enforce
//! (`mode & 0o077 == 0`, the precedent is `OpenSSH`), Windows does not express
//! access this way and its ACLs are not comparable bit for bit, so there the
//! gate passes and protection rests on the directory the file lives in. That
//! difference is announced rather than assumed — see [`GATE_ENFORCED`].

use std::io::Read as _;
use std::path::Path;

use zeroize::Zeroizing;

/// Whether the owner-only permission gate is enforced on this target.
///
/// `false` means [`open`] admits any file the process can open at all. Callers
/// read this to tell the operator that the check did not run, so "no complaint"
/// is not mistaken for "the permissions were checked and are fine".
pub(crate) const GATE_ENFORCED: bool = cfg!(unix);

/// A file whose permission bits let group or others reach it.
///
/// Carries only the offending mode — never the path (the caller already has it)
/// and never any content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BeyondOwner {
    /// The file's permission bits (`st_mode & 0o7777`).
    pub(crate) mode: u32,
}

/// Why a secret-bearing file could not be opened for reading.
#[derive(Debug)]
pub(crate) enum OpenError {
    /// The file could not be opened or its metadata could not be read.
    Io(std::io::Error),
    /// The file is reachable beyond its owner.
    BeyondOwner(BeyondOwner),
}

/// A secret-bearing file that has passed the owner-only gate.
#[derive(Debug)]
pub(crate) struct SecretFile {
    /// The open handle the gate was applied to.
    file: std::fs::File,
    /// The file's size at the moment of the check, used to size the read buffer
    /// so the content is not copied between growing allocations.
    length: u64,
}

/// Open a secret-bearing file and refuse it if it is group- or world-accessible.
///
/// The gate runs on the metadata of the returned handle (`fstat`, not `stat`),
/// so a path swapped between the check and the read cannot smuggle in a file
/// that was never checked.
///
/// # Errors
///
/// [`OpenError::Io`] when the file cannot be opened or interrogated,
/// [`OpenError::BeyondOwner`] when any group or other permission bit is set. On
/// non-Unix targets the permission check always passes — see the module docs.
pub(crate) fn open(path: &Path) -> Result<SecretFile, OpenError> {
    let file = std::fs::File::open(path).map_err(OpenError::Io)?;
    let metadata = file.metadata().map_err(OpenError::Io)?;
    reject_beyond_owner(&metadata).map_err(OpenError::BeyondOwner)?;
    Ok(SecretFile {
        file,
        length: metadata.len(),
    })
}

impl SecretFile {
    /// Read the whole file into a buffer that is wiped when it is dropped.
    ///
    /// The buffer is reserved from the size seen at the gate, so the usual read
    /// completes without a reallocation — a grown `Vec` would leave the bytes it
    /// moved away from in freed memory, unwiped. A file that grew between the
    /// two moments still reads in full; only the no-copy property is lost.
    ///
    /// # Errors
    ///
    /// The underlying read error.
    pub(crate) fn read_all(mut self) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let reserve = usize::try_from(self.length).unwrap_or(usize::MAX);
        let mut buffer = Zeroizing::new(Vec::with_capacity(reserve.saturating_add(1)));
        self.file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}

/// Refuse a secret-bearing file that is group- or world-accessible.
///
/// `metadata` must belong to an already open handle — see [`open`], the only
/// caller.
///
/// # Errors
///
/// [`BeyondOwner`] with the file's permission bits when any group or other bit
/// is set. On non-Unix targets the check always passes — see the module docs.
fn reject_beyond_owner(metadata: &std::fs::Metadata) -> Result<(), BeyondOwner> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(BeyondOwner {
                mode: mode & 0o7777,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{open, OpenError, GATE_ENFORCED};

    /// The gate runs on the handle that is read, and an owner-only file passes
    /// with its content intact.
    #[test]
    fn an_owner_only_file_opens_and_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, b"s3cret\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let bytes = open(&path).unwrap().read_all().unwrap();
        assert_eq!(&*bytes, b"s3cret\n");
    }

    /// A file group or others can read is refused, and the error carries the
    /// mode rather than anything from the file.
    #[cfg(unix)]
    #[test]
    fn a_group_readable_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, b"s3cret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        match open(&path) {
            Err(OpenError::BeyondOwner(e)) => assert_eq!(e.mode, 0o644),
            other => panic!("expected a permission refusal, got {other:?}"),
        }
    }

    /// The gate's platform reach is what the callers announce to the operator.
    #[test]
    fn the_gate_runs_where_the_platform_has_permissions() {
        assert_eq!(GATE_ENFORCED, cfg!(unix));
    }

    /// A missing file is an I/O error, distinguishable from a refusal.
    #[test]
    fn a_missing_file_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        match open(&dir.path().join("absent")) {
            Err(OpenError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected an I/O error, got {other:?}"),
        }
    }
}

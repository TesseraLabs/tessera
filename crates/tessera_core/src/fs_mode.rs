//! Creating files whose permissions are pinned rather than inherited.
//!
//! Several artefacts this crate writes — the enrolment payload, the role
//! bundle version, the OCSP cache — carry a POSIX mode that is part of their
//! security contract: an attacker who can rewrite them can steer the login
//! path. Both steps matter: `open(2)`'s mode is masked by the process umask,
//! so the mode is pinned again with `chmod(2)` before the file is published
//! under its final name.
//!
//! Windows expresses the same intent through a DACL, which is a different
//! object with a different inheritance model — not a translation of a mode
//! word. Rather than write these files with whatever the parent directory
//! happens to grant, this module refuses on non-Unix targets: the callers all
//! map the returned [`io::Error`] into their own failure type, so the write
//! fails closed. A Windows engine that needs to persist these artefacts has to
//! bring an explicit DACL of its own.

use std::fs::File;
use std::io;
use std::path::Path;

/// Message carried by the refusal on targets without POSIX modes.
#[cfg(not(unix))]
const NO_POSIX_MODES: &str = "file permissions cannot be pinned on this platform";

/// Create (or truncate) `path` for writing with permissions `mode`.
///
/// # Errors
///
/// The underlying `open(2)` failure, or [`io::ErrorKind::Unsupported`] on a
/// target without POSIX modes.
pub(crate) fn create_with_mode(path: &Path, mode: u32) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err(io::Error::new(io::ErrorKind::Unsupported, NO_POSIX_MODES))
    }
}

/// Flush the directory entry a `rename(2)` just created or replaced.
///
/// `sync_all` on the file makes its *contents* durable; it says nothing about
/// the directory entry that names them. On ext4 with the default `data=ordered`
/// the rename can still be lost across a power cut, and the two artefacts that
/// depend on this — the nonce counter and the state that pairs with it — are
/// exactly the pair whose disagreement the device refuses to run with. A lost
/// counter rename beside a surviving state write reads as a rollback, and a
/// rollback on an offline device is refused until somebody drives out to rotate
/// the key epoch.
///
/// # Errors
///
/// The underlying `open(2)`/`fsync(2)` failure, or
/// [`io::ErrorKind::Unsupported`] on a target without POSIX directory
/// semantics — where the writes these calls follow have already failed.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(io::Error::new(io::ErrorKind::Unsupported, NO_POSIX_MODES))
    }
}

/// What a capped read of a file found.
#[derive(Debug)]
pub(crate) enum CappedRead {
    /// The whole file, no larger than the cap it was read under.
    Whole(Vec<u8>),
    /// The file is larger than the cap; the read stopped one byte past it.
    TooLarge,
}

/// Message carried by the refusal of a path that is not a regular file.
const NOT_A_REGULAR_FILE: &str = "the path is not a regular file";

/// Read at most `max` bytes of a regular file, refusing a symlink and anything
/// that is not a regular file.
///
/// Three properties, all of which a plain `fs::read` lacks and all of which
/// matter when the file arrives on somebody's removable medium:
///
/// * the cap bounds the *read*, not the result — `fs::read` sizes its buffer
///   from the metadata and would allocate whatever the medium claims before
///   any cap could refuse it;
/// * the open does not follow a symlink, so a name inside a package cannot
///   redirect the read at a device node or at a file elsewhere on the system;
/// * the file type is decided on the open descriptor rather than on the path,
///   and the open does not block on a FIFO waiting for a writer that never
///   comes.
///
/// # Errors
///
/// The underlying `open(2)`/`read(2)` failure, with the original
/// [`io::ErrorKind`] preserved so a caller can still tell
/// [`io::ErrorKind::NotFound`] apart, and [`io::ErrorKind::InvalidInput`] for
/// a path that is not a regular file.
pub(crate) fn read_capped_regular(path: &Path, max: usize) -> io::Result<CappedRead> {
    use std::io::Read as _;

    let file = open_no_follow(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            NOT_A_REGULAR_FILE,
        ));
    }
    // One byte past the cap: enough to tell "exactly at the cap" from "over
    // it", and never more than that however large the file really is.
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    (&file).take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        Ok(CappedRead::TooLarge)
    } else {
        Ok(CappedRead::Whole(bytes))
    }
}

/// Open an existing regular file for writing, refusing a symlink and anything
/// that is not a regular file.
///
/// For the one caller that overwrites a file in place: the delivered key
/// container, zeroed where it lies before it is unlinked. That write runs as
/// root against a path on somebody's removable medium, so it may not resolve
/// the path a second time — between the read that consumed the container and
/// the overwrite that retires it, the name can have become a link to
/// `/etc/shadow`. The descriptor this returns is the object that was checked,
/// and writing through it cannot land anywhere else.
///
/// # Errors
///
/// The underlying `open(2)` failure, with [`io::ErrorKind::NotFound`] preserved
/// for a caller that treats an absent file as nothing to do, and
/// [`io::ErrorKind::InvalidInput`] for a path that is not a regular file.
pub(crate) fn open_regular_for_overwrite(path: &Path) -> io::Result<(File, u64)> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt as _;

        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new().write(true).open(path)?;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            NOT_A_REGULAR_FILE,
        ));
    }
    Ok((file, metadata.len()))
}

/// Open a file for reading without following a final symlink and without
/// blocking on a FIFO.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        // `O_NOFOLLOW` refuses the symlink; `O_NONBLOCK` is what keeps the
        // open of a FIFO from waiting for a writer, and is a no-op on the
        // regular file this is meant to be.
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
}

/// Open a file for reading on a target without the POSIX open flags; the file
/// type is still decided on the descriptor by the caller.
#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Set the permissions of an existing `path` to exactly `mode`.
///
/// Called after the content is durable and before the file is renamed into
/// place, because the creating `open(2)` had its mode filtered through the
/// umask.
///
/// # Errors
///
/// The underlying `chmod(2)` failure, or [`io::ErrorKind::Unsupported`] on a
/// target without POSIX modes.
pub(crate) fn pin_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err(io::Error::new(io::ErrorKind::Unsupported, NO_POSIX_MODES))
    }
}

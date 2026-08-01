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

//! The owner-only gate every file holding secret material passes through.
//!
//! Two inputs of the issuer are secret-bearing files: the file backend's PKCS#8
//! CA key and a secret file named on the command line (`--pin-file`,
//! `--key-passphrase-file`). Both are refused when the filesystem lets anyone
//! but the owner read them, and both are checked on the file's metadata *before*
//! any content is read, so an over-permissive file never puts its bytes in
//! memory.
//!
//! The check lives here rather than beside either reader so the platform
//! difference has a single site: Unix has a permission model to enforce
//! (`mode & 0o077 == 0`, the precedent is `OpenSSH`), Windows does not express
//! access this way and its ACLs are not comparable bit for bit, so there the
//! gate passes and protection rests on the directory the file lives in.

/// A file whose permission bits let group or others reach it.
///
/// Carries only the offending mode — never the path (the caller already has it)
/// and never any content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BeyondOwner {
    /// The file's permission bits (`st_mode & 0o7777`).
    pub(crate) mode: u32,
}

/// Refuse a secret-bearing file that is group- or world-accessible.
///
/// `metadata` must describe the file that is about to be read; passing metadata
/// obtained before the read is what keeps an over-permissive file from being
/// opened at all.
///
/// # Errors
///
/// [`BeyondOwner`] with the file's permission bits when any group or other bit
/// is set. On non-Unix targets the check always passes — see the module docs.
pub(crate) fn reject_beyond_owner(metadata: &std::fs::Metadata) -> Result<(), BeyondOwner> {
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

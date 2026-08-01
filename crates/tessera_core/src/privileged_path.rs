//! Ownership and integrity checks for paths a privileged process runs or opens.
//!
//! When a process running as root executes a program, or opens a file whose
//! contents it will trust, every component of that path becomes part of its
//! trusted computing base. If an unprivileged local user can rewrite the
//! target executable — or rename/replace any directory on the way to it — they
//! can substitute their own payload and have the root process run or read it.
//! That is a classic local privilege-escalation vector; `sudo`, `ssh`, and
//! `cron` all perform the same pre-use ownership walk to close it.
//!
//! This module centralises that walk so every privileged-execution and
//! privileged-open site enforces the identical policy:
//!
//! * The **executable/file** and **every ancestor directory** up to `/` must be
//!   owned by a trusted UID (root, or — for a path used after dropping to an
//!   unprivileged account — that same account).
//! * No component may be writable by "other".
//! * A component may be group-writable only when its owning group is root or
//!   the account the path will be used as.
//!
//! [`validate_path`] rejects every symlink in the supplied path, validates the
//! original component chain, canonicalizes and walks it again, then re-opens
//! the leaf with `O_NOFOLLOW` and re-checks the opened inode. The returned
//! [`ValidatedPath`] hands back the open descriptor so a caller can act on
//! *exactly* the inode that was validated — reopening it for a read, or (on
//! Linux) `fexecve`-ing it — instead of re-resolving the path and racing a swap
//! in between.
//!
//! The whole policy above is expressed in POSIX ownership and mode bits, and
//! the check/use race is closed with a descriptor. Windows expresses the same
//! questions through owner SIDs and DACLs — a different model that needs its
//! own walk rather than a translation of this one, so it lives in the
//! [`windows`] submodule and is selected by the same entry points. Targets that
//! are neither Unix nor Windows have no walk at all and refuse outright with
//! [`PrivilegedPathError::UnsupportedPlatform`], so a privileged read or exec
//! is never performed against an unverified path.

#[cfg(windows)]
mod windows;

use std::io::Read as _;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

/// `S_IWOTH` — write permission for "other". Never acceptable on a privileged
/// path: it lets any local user rewrite the component.
#[cfg(unix)]
const OTHER_WRITE: u32 = 0o002;

/// `S_IWGRP` — write permission for the owning group. Acceptable only when the
/// owning group is trusted (root, or the target account's own group).
#[cfg(unix)]
const GROUP_WRITE: u32 = 0o020;

/// The privilege level a path will be used at, which sets the ownership policy
/// enforced against every component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecTrust {
    /// The path is used with full root authority (a `run_as = root` hook, a
    /// host-identity helper, a root-read config). Every component must be
    /// owned by UID 0 and carry no group- or other-write bit.
    Root,
    /// The path is used after dropping to an unprivileged account. Every
    /// component must be owned by root or by that account, must not be
    /// other-writable, and may be group-writable only when the owning group is
    /// root or the account's own primary group. This keeps one unprivileged
    /// user from hijacking a path that another user's session will run.
    User {
        /// Effective UID the path will be used as.
        uid: u32,
        /// Primary GID the path will be used as.
        gid: u32,
    },
}

/// A path whose leaf and every ancestor satisfied an [`ExecTrust`] policy,
/// together with an open descriptor to the validated leaf inode.
///
/// The descriptor is opened `O_NOFOLLOW` (and `O_PATH` on Linux). Because it
/// refers to the exact inode that passed validation, a caller that reopens or
/// executes *through the descriptor* is immune to a path swap performed after
/// the check.
#[derive(Debug)]
pub struct ValidatedPath {
    canonical: PathBuf,
    #[cfg(unix)]
    descriptor: OwnedFd,
    trust: ExecTrust,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    is_file: bool,
    is_dir: bool,
}

impl ValidatedPath {
    /// The canonical, symlink-free path that was validated.
    #[must_use]
    pub fn canonical(&self) -> &Path {
        &self.canonical
    }

    /// Borrow the descriptor opened to the validated leaf inode.
    #[cfg(unix)]
    #[must_use]
    pub fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.descriptor.as_fd()
    }

    /// Consume the guard and return the owned descriptor to the validated leaf.
    #[cfg(unix)]
    #[must_use]
    pub fn into_descriptor(self) -> OwnedFd {
        self.descriptor
    }

    /// Open the validated regular file for reading and verify that the newly
    /// opened descriptor still refers to the inode captured by
    /// [`validate_file`].
    ///
    /// The canonical path's ancestors have already passed the ownership walk,
    /// and the final component is opened with `O_NOFOLLOW`. The post-open
    /// `(st_dev, st_ino)` comparison closes the remaining check/use window.
    ///
    /// # Errors
    ///
    /// Returns [`PrivilegedPathError::NotRegularFile`] when this guard was
    /// created for a non-file path, or a path-validation error when the file
    /// cannot be opened safely or changed after validation.
    #[cfg(unix)]
    pub fn open_readonly(&self) -> Result<std::fs::File, PrivilegedPathError> {
        if !self.is_file {
            return Err(PrivilegedPathError::NotRegularFile {
                path: self.canonical.clone(),
            });
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file =
            opts.open(&self.canonical)
                .map_err(|source| PrivilegedPathError::Unresolvable {
                    path: self.canonical.clone(),
                    source,
                })?;
        let meta = file
            .metadata()
            .map_err(|source| PrivilegedPathError::Stat {
                path: self.canonical.clone(),
                source,
            })?;
        check_component(&self.canonical, &meta, self.trust)?;
        if meta.dev() != self.device || meta.ino() != self.inode {
            return Err(PrivilegedPathError::InodeChanged {
                path: self.canonical.clone(),
            });
        }
        Ok(file)
    }

    /// Open the validated regular file for reading.
    ///
    /// Every component of the canonical path passed the owner/DACL walk, and a
    /// leaf that turned into a reparse point after the walk is refused here.
    /// The remaining check/use window is not closed on this platform — see the
    /// [`windows`] module docs for why that threshold is above the model this
    /// check defends.
    ///
    /// # Errors
    ///
    /// Returns [`PrivilegedPathError::NotRegularFile`] when this guard was
    /// created for a non-file path, or a path-validation error when the file
    /// cannot be opened safely.
    #[cfg(windows)]
    pub fn open_readonly(&self) -> Result<std::fs::File, PrivilegedPathError> {
        let _ = self.trust;
        if !self.is_file {
            return Err(PrivilegedPathError::NotRegularFile {
                path: self.canonical.clone(),
            });
        }
        windows::open_readonly(&self.canonical)
    }

    /// See the Unix implementation above; unreachable here because no
    /// [`ValidatedPath`] can be constructed on this platform.
    ///
    /// # Errors
    ///
    /// Always [`PrivilegedPathError::UnsupportedPlatform`].
    #[cfg(not(any(unix, windows)))]
    pub fn open_readonly(&self) -> Result<std::fs::File, PrivilegedPathError> {
        let _ = (self.is_file, self.is_dir, self.trust);
        Err(PrivilegedPathError::UnsupportedPlatform)
    }
}

/// Failure to validate a path for privileged execution or opening.
#[derive(Debug, thiserror::Error)]
pub enum PrivilegedPathError {
    /// The path was not absolute. A relative path resolves against the
    /// process's current directory, which makes the ancestor walk meaningless,
    /// so it is rejected outright (fail closed).
    #[error("path is not absolute: {path:?}")]
    NotAbsolute {
        /// The offending path.
        path: PathBuf,
    },
    /// The supplied path contains a `..` component, so it does not describe a
    /// single unambiguous ancestor chain.
    #[error("path contains a parent-directory component: {path:?}")]
    NotNormalized {
        /// The offending path.
        path: PathBuf,
    },
    /// Symlinks are forbidden in privileged paths, even when their current
    /// target is itself trusted: an unprivileged link owner could otherwise
    /// select which root-controlled input is consumed.
    #[error("symlink component is not allowed in privileged path: {path:?}")]
    SymlinkNotAllowed {
        /// The offending symlink component.
        path: PathBuf,
    },
    /// The path could not be canonicalized: a component is missing, is not a
    /// directory, or is unreadable. Treated as a hard failure (fail closed).
    #[error("cannot resolve {path:?}: {source}")]
    Unresolvable {
        /// The path that failed to resolve.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A component's metadata could not be read during the ownership walk.
    #[error("cannot stat {path:?}: {source}")]
    Stat {
        /// The component whose metadata could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A component is owned by a UID the policy does not trust.
    #[error("{path:?} is owned by untrusted uid {uid}")]
    UntrustedOwner {
        /// The offending component.
        path: PathBuf,
        /// The owning UID that failed the policy.
        uid: u32,
    },
    /// A component is writable by an untrusted party (other, or an untrusted
    /// group).
    #[error("{path:?} is writable by an untrusted party (mode {mode:#o})")]
    UntrustedWritable {
        /// The offending component.
        path: PathBuf,
        /// The component's permission bits.
        mode: u32,
    },
    /// The leaf inode observed through the freshly opened descriptor differs
    /// from the one walked, i.e. the file was swapped between the check and the
    /// open. Fail closed.
    #[error("{path:?} changed between validation and open (possible race)")]
    InodeChanged {
        /// The leaf path that changed underfoot.
        path: PathBuf,
    },
    /// A caller required a regular file but the validated leaf has a
    /// different type.
    #[error("{path:?} is not a regular file")]
    NotRegularFile {
        /// The offending leaf.
        path: PathBuf,
    },
    /// A caller required a directory but the validated leaf has a different
    /// type.
    #[error("{path:?} is not a directory")]
    NotDirectory {
        /// The offending leaf.
        path: PathBuf,
    },
    /// A component's security descriptor could not be read, so nothing can be
    /// said about who may write it. Distinct from a missing file: the path
    /// exists, its trust is simply unknowable. Fail closed.
    #[cfg(windows)]
    #[error("cannot read the security descriptor of {path:?} (win32 error {code})")]
    SecurityDescriptorUnavailable {
        /// The component whose descriptor could not be read.
        path: PathBuf,
        /// The Win32 error code reported by the failing call.
        code: u32,
    },
    /// A component's security descriptor carried no owner, so the implicit
    /// `WRITE_DAC` right that ownership confers cannot be attributed.
    #[cfg(windows)]
    #[error("{path:?} has no resolvable owner")]
    OwnerUnavailable {
        /// The component with no resolvable owner.
        path: PathBuf,
    },
    /// A component has a NULL DACL, which grants every account full access.
    #[cfg(windows)]
    #[error("{path:?} has a NULL DACL, which grants everyone full access")]
    NullDacl {
        /// The offending component.
        path: PathBuf,
    },
    /// A component is owned by a SID the policy does not trust. The owner can
    /// rewrite the DACL at any time, so an untrusted owner is untrusted access.
    #[cfg(windows)]
    #[error("{path:?} is owned by untrusted principal {sid}")]
    UntrustedOwnerSid {
        /// The offending component.
        path: PathBuf,
        /// The owning SID, in string form.
        sid: String,
    },
    /// A component's DACL lets a principal outside the trusted set substitute
    /// it: delete or rename it, delete what is inside it, rewrite its DACL,
    /// take its ownership, or — for a file — change its content.
    #[cfg(windows)]
    #[error("{path:?} may be substituted by untrusted principal {sid} (mask {mask:#010x})")]
    UntrustedSubstitution {
        /// The offending component.
        path: PathBuf,
        /// The SID that holds the offending grant.
        sid: String,
        /// The access mask of the offending entry.
        mask: u32,
    },
    /// A component's DACL contains an allowing entry whose layout this walk
    /// does not parse, so its grants cannot be ruled out. Fail closed.
    #[cfg(windows)]
    #[error("{path:?} has an access-allowed entry of unparsed type {ace_type}")]
    UnanalyzableAce {
        /// The offending component.
        path: PathBuf,
        /// The ACE type byte that could not be analysed.
        ace_type: u8,
    },
    /// A component's DACL contains an allowing entry whose principal SID is not
    /// a well-formed SID, or is longer than the entry that is supposed to
    /// contain it. Such an entry cannot be attributed to any principal, so the
    /// access it grants cannot be ruled out. Fail closed.
    #[cfg(windows)]
    #[error("{path:?} has an access-allowed entry (#{ace_index}) with a malformed principal SID")]
    MalformedAceSid {
        /// The offending component.
        path: PathBuf,
        /// Position of the offending entry in the component's DACL.
        ace_index: u32,
    },
    /// The path resolves onto a network share. Its permissions are asserted by
    /// a remote machine, so no local walk can establish trust in it.
    #[cfg(windows)]
    #[error("{path:?} is on a network share and cannot be trusted")]
    NetworkPath {
        /// The offending path.
        path: PathBuf,
    },
    /// The path resolves onto a volume that is not fixed local storage
    /// (removable, optical, RAM disk, or unidentifiable). Fail closed.
    #[cfg(windows)]
    #[error("{path:?} is on a non-fixed volume (drive type {drive_type})")]
    UntrustedVolume {
        /// The offending path.
        path: PathBuf,
        /// The `GetDriveTypeW` verdict for the path's volume.
        drive_type: u32,
    },
    /// This platform has no implementation of the ownership walk, so no path
    /// can be declared trusted for privileged use. Fail closed.
    #[cfg(not(any(unix, windows)))]
    #[error("privileged path validation is not implemented on this platform")]
    UnsupportedPlatform,
    /// Reading a validated file failed.
    #[error("cannot read validated file {path:?}: {source}")]
    Read {
        /// The file being read.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}

/// Validate that `path` and every canonical ancestor satisfy `trust`, returning
/// a descriptor to the validated leaf inode.
///
/// The original path is walked first and any symlink or `..` component is
/// rejected. It is then canonicalized and walked again, so both the caller's
/// namespace path and the resolved tree must satisfy the ownership policy. The
/// leaf is finally reopened `O_NOFOLLOW` and re-checked against the freshly
/// `fstat`ed inode, closing the window between the walk and the open.
///
/// # Errors
///
/// Returns [`PrivilegedPathError`] when the path is not absolute, cannot be
/// resolved, cannot be `stat`ed, has an untrusted owner or writable bit on any
/// component, or when the leaf changed between validation and open.
///
/// # Examples
///
/// ```no_run
/// use tessera_core::privileged_path::{validate_path, ExecTrust};
/// use std::path::Path;
///
/// // On a correctly installed host this is owned by root all the way up.
/// let validated = validate_path(Path::new("/usr/sbin/hook"), ExecTrust::Root)?;
/// let _fd = validated.descriptor();
/// # Ok::<(), tessera_core::privileged_path::PrivilegedPathError>(())
/// ```
#[cfg(unix)]
pub fn validate_path(path: &Path, trust: ExecTrust) -> Result<ValidatedPath, PrivilegedPathError> {
    if !path.is_absolute() {
        return Err(PrivilegedPathError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }

    let canonical =
        std::fs::canonicalize(path).map_err(|source| PrivilegedPathError::Unresolvable {
            path: path.to_path_buf(),
            source,
        })?;

    validate_original_components(path, trust)?;

    // Walk the canonical leaf and every ancestor. `symlink_metadata` never
    // follows a symlink; on a canonical path there are none, but using the
    // non-following stat keeps the check honest if the tree mutates mid-walk.
    let leaf_meta =
        std::fs::symlink_metadata(&canonical).map_err(|source| PrivilegedPathError::Stat {
            path: canonical.clone(),
            source,
        })?;
    check_component(&canonical, &leaf_meta, trust)?;

    let mut cursor = canonical.parent();
    while let Some(component) = cursor {
        let meta =
            std::fs::symlink_metadata(component).map_err(|source| PrivilegedPathError::Stat {
                path: component.to_path_buf(),
                source,
            })?;
        check_component(component, &meta, trust)?;
        cursor = component.parent();
    }

    // Reopen the leaf without following a final-component symlink and re-check
    // the inode we actually opened. A swap of the leaf to a symlink trips
    // `O_NOFOLLOW`; a swap to a different regular file trips the inode compare.
    let file = open_leaf(&canonical)?;
    let opened_meta = file
        .metadata()
        .map_err(|source| PrivilegedPathError::Stat {
            path: canonical.clone(),
            source,
        })?;
    check_component(&canonical, &opened_meta, trust)?;
    if opened_meta.ino() != leaf_meta.ino() || opened_meta.dev() != leaf_meta.dev() {
        return Err(PrivilegedPathError::InodeChanged {
            path: canonical.clone(),
        });
    }

    Ok(ValidatedPath {
        canonical,
        descriptor: OwnedFd::from(file),
        trust,
        device: opened_meta.dev(),
        inode: opened_meta.ino(),
        is_file: opened_meta.is_file(),
        is_dir: opened_meta.is_dir(),
    })
}

/// Validate that `path` and every canonical ancestor are owned and writable
/// only by principals the Windows policy trusts.
///
/// The caller's component chain is walked first and any reparse point in it is
/// refused; the canonical chain is then walked from the volume root to the leaf
/// with the owner and DACL rules described in the [`windows`] module docs. The
/// path must be on a fixed local volume.
///
/// `trust` is accepted for signature parity with the Unix walk and does not
/// relax the policy: [`ExecTrust::User`] describes a POSIX account, and there
/// is no Windows equivalent that could be trusted with a privileged input, so
/// the strict system policy is applied for every value.
///
/// # Errors
///
/// Returns [`PrivilegedPathError`] when the path is not absolute or normalized,
/// contains a reparse point, cannot be canonicalized, is not on a fixed local
/// volume, or when any component has an untrusted owner, an unreadable
/// security descriptor, a NULL DACL, an unparsed access-allowed entry, or a
/// grant of substitution rights to an untrusted principal.
#[cfg(windows)]
pub fn validate_path(path: &Path, trust: ExecTrust) -> Result<ValidatedPath, PrivilegedPathError> {
    let validated = windows::validate(path)?;
    Ok(ValidatedPath {
        canonical: validated.canonical,
        trust,
        is_file: validated.is_file,
        is_dir: validated.is_dir,
    })
}

/// Refuse every path, because this platform has no ownership walk to run.
///
/// Callers treat a refusal as "this path may not be used at privilege", which
/// is the only safe answer where no equivalent walk exists.
///
/// # Errors
///
/// Always [`PrivilegedPathError::UnsupportedPlatform`].
#[cfg(not(any(unix, windows)))]
pub fn validate_path(path: &Path, trust: ExecTrust) -> Result<ValidatedPath, PrivilegedPathError> {
    let _ = (path, trust);
    Err(PrivilegedPathError::UnsupportedPlatform)
}

/// Reject ambiguous resolution and validate the exact component chain supplied
/// by the caller before canonical resolution is trusted.
#[cfg(unix)]
fn validate_original_components(path: &Path, trust: ExecTrust) -> Result<(), PrivilegedPathError> {
    let mut current = PathBuf::from("/");
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => current.push(name),
            Component::ParentDir => {
                return Err(PrivilegedPathError::NotNormalized {
                    path: path.to_path_buf(),
                });
            }
            Component::Prefix(_) => {
                return Err(PrivilegedPathError::NotAbsolute {
                    path: path.to_path_buf(),
                });
            }
        }
        let meta =
            std::fs::symlink_metadata(&current).map_err(|source| PrivilegedPathError::Stat {
                path: current.clone(),
                source,
            })?;
        if meta.file_type().is_symlink() {
            return Err(PrivilegedPathError::SymlinkNotAllowed {
                path: current.clone(),
            });
        }
        components.push((current.clone(), meta));
    }
    for (component, meta) in components {
        check_component(&component, &meta, trust)?;
    }
    Ok(())
}

/// Validate a root- or user-trusted path and require a regular-file leaf.
///
/// # Errors
///
/// Returns the same failures as [`validate_path`], plus
/// [`PrivilegedPathError::NotRegularFile`] for non-file leaves.
pub fn validate_file(path: &Path, trust: ExecTrust) -> Result<ValidatedPath, PrivilegedPathError> {
    let validated = validate_path(path, trust)?;
    if !validated.is_file {
        return Err(PrivilegedPathError::NotRegularFile {
            path: validated.canonical.clone(),
        });
    }
    Ok(validated)
}

/// Validate a root- or user-trusted path and require a directory leaf.
///
/// # Errors
///
/// Returns the same failures as [`validate_path`], plus
/// [`PrivilegedPathError::NotDirectory`] for non-directory leaves.
pub fn validate_directory(
    path: &Path,
    trust: ExecTrust,
) -> Result<ValidatedPath, PrivilegedPathError> {
    let validated = validate_path(path, trust)?;
    if !validated.is_dir {
        return Err(PrivilegedPathError::NotDirectory {
            path: validated.canonical.clone(),
        });
    }
    Ok(validated)
}

/// Read a regular file only after its complete path passes the requested
/// privileged ownership policy.
///
/// # Errors
///
/// Returns a path-validation error when the file or an ancestor is untrusted,
/// the leaf is not a regular file, the inode changes, or the read fails.
pub fn read_file(path: &Path, trust: ExecTrust) -> Result<Vec<u8>, PrivilegedPathError> {
    let validated = validate_file(path, trust)?;
    let mut file = validated.open_readonly()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| PrivilegedPathError::Read {
            path: validated.canonical.clone(),
            source,
        })?;
    Ok(bytes)
}

/// Read a UTF-8 text file only after its complete path passes the requested
/// privileged ownership policy.
///
/// # Errors
///
/// Returns a path-validation error when the file is untrusted, changes during
/// opening, cannot be read, or is not valid UTF-8.
pub fn read_to_string(path: &Path, trust: ExecTrust) -> Result<String, PrivilegedPathError> {
    let bytes = read_file(path, trust)?;
    String::from_utf8(bytes).map_err(|source| PrivilegedPathError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
    })
}

/// Enforce the [`ExecTrust`] policy against a single component's metadata.
#[cfg(unix)]
fn check_component(
    path: &Path,
    meta: &std::fs::Metadata,
    trust: ExecTrust,
) -> Result<(), PrivilegedPathError> {
    let mode = meta.mode();
    let owner = meta.uid();

    // Other-write is fatal regardless of trust level.
    if mode & OTHER_WRITE != 0 {
        return Err(PrivilegedPathError::UntrustedWritable {
            path: path.to_path_buf(),
            mode,
        });
    }

    match trust {
        ExecTrust::Root => {
            if owner != 0 {
                return Err(PrivilegedPathError::UntrustedOwner {
                    path: path.to_path_buf(),
                    uid: owner,
                });
            }
            if mode & GROUP_WRITE != 0 {
                return Err(PrivilegedPathError::UntrustedWritable {
                    path: path.to_path_buf(),
                    mode,
                });
            }
        }
        ExecTrust::User {
            uid: allowed_uid,
            gid: allowed_group,
        } => {
            if owner != 0 && owner != allowed_uid {
                return Err(PrivilegedPathError::UntrustedOwner {
                    path: path.to_path_buf(),
                    uid: owner,
                });
            }
            if mode & GROUP_WRITE != 0 {
                let group = meta.gid();
                if group != 0 && group != allowed_group {
                    return Err(PrivilegedPathError::UntrustedWritable {
                        path: path.to_path_buf(),
                        mode,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Open the canonical leaf without following a final-component symlink.
///
/// On Linux the handle is `O_PATH`: it needs no read permission (an
/// execute-only hook still validates) and is suitable for `fexecve`/`openat`.
/// On other Unix dev targets `O_PATH` is unavailable, so a read handle is used;
/// dev hooks are readable, and the descriptor is only ever `fstat`ed here.
#[cfg(unix)]
fn open_leaf(canonical: &Path) -> Result<std::fs::File, PrivilegedPathError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(target_os = "linux")]
    opts.custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    #[cfg(not(target_os = "linux"))]
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    opts.open(canonical)
        .map_err(|source| PrivilegedPathError::Unresolvable {
            path: canonical.to_path_buf(),
            source,
        })
}

// Every case here builds a tree with specific owners and mode bits and asserts
// on the walk's verdict; there is no walk to exercise on other platforms.
#[cfg(all(test, unix))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const TRUSTED_SYSTEM_FILE: &str = "/usr/bin/true";

    /// True when the test process is running as root, in which case the
    /// "owned by a non-root uid" rejection cases cannot be asserted (root owns
    /// nothing the tests can create as a non-root uid). Such cases are skipped.
    fn running_as_root() -> bool {
        nix::unistd::Uid::effective().is_root()
    }

    #[test]
    fn relative_path_is_rejected() {
        let err = validate_path(Path::new("bin/hook"), ExecTrust::Root)
            .expect_err("relative path must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::NotAbsolute { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn missing_path_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");
        let err =
            validate_path(&missing, ExecTrust::Root).expect_err("missing path must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::Unresolvable { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn symlink_leaf_is_rejected_even_when_target_is_root_controlled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("trusted");
        std::os::unix::fs::symlink("/bin/sh", &link).expect("symlink");
        let err = validate_path(&link, ExecTrust::Root)
            .expect_err("privileged symlinks must be rejected");
        assert!(
            matches!(err, PrivilegedPathError::SymlinkNotAllowed { .. }),
            "{err:?}"
        );
    }

    /// SEC-004 core: a `0755` executable and its parent owned by a non-root uid
    /// must be rejected for a root-privilege path, because that owner could
    /// rewrite it before root runs it.
    #[test]
    fn nonroot_owned_executable_rejected_for_root() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("bin");
        std::fs::create_dir(&sub).expect("mkdir");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let hook = sub.join("hook.sh");
        std::fs::write(&hook, b"#!/bin/sh\nexit 0\n").expect("write hook");
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let err = validate_path(&hook, ExecTrust::Root)
            .expect_err("non-root-owned executable must be rejected for a root path");
        // The offending component is owned by the test's (non-root) uid, so the
        // owner check fires first; a world-writable temp ancestor would also
        // trip the writable check — either way it is rejected, never accepted.
        assert!(
            matches!(
                err,
                PrivilegedPathError::UntrustedOwner { .. }
                    | PrivilegedPathError::UntrustedWritable { .. }
                    | PrivilegedPathError::SymlinkNotAllowed { .. }
            ),
            "{err:?}"
        );
    }

    /// A file the current user owns is acceptable under `User` trust for that
    /// same user — the lower-privilege policy trusts the account's own files.
    /// (Asserted only on the leaf via a direct component check, since temp-dir
    /// ancestors are typically world-writable and would trip the full walk.)
    #[test]
    fn user_trust_accepts_own_leaf() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let hook = dir.path().join("hook.sh");
        std::fs::write(&hook, b"#!/bin/sh\nexit 0\n").expect("write hook");
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let meta = std::fs::symlink_metadata(&hook).expect("stat");
        let uid = meta.uid();
        let gid = meta.gid();
        check_component(&hook, &meta, ExecTrust::User { uid, gid })
            .expect("own 0750 leaf is acceptable under matching User trust");
    }

    /// A root-owned system binary with clean ancestors passes the full walk and
    /// yields a usable descriptor.
    #[test]
    fn root_owned_system_binary_is_accepted() {
        let candidate = Path::new(TRUSTED_SYSTEM_FILE);
        if !candidate.exists() {
            return;
        }
        match validate_path(candidate, ExecTrust::Root) {
            Ok(validated) => {
                assert!(validated.canonical().is_absolute());
                let _fd = validated.into_descriptor();
            }
            // Extremely unusual permissions on a host's system binary should
            // not fail the suite; the security-relevant assertions are the
            // rejections.
            Err(err) => {
                panic!("expected {TRUSTED_SYSTEM_FILE} to validate under Root trust: {err:?}")
            }
        }
    }

    #[test]
    fn validate_file_rejects_directory_leaf() {
        let err = validate_file(Path::new("/"), ExecTrust::Root)
            .expect_err("directory must not validate as a regular file");
        assert!(matches!(err, PrivilegedPathError::NotRegularFile { .. }));
    }

    #[test]
    fn validate_directory_rejects_regular_file_leaf() {
        let candidate = Path::new(TRUSTED_SYSTEM_FILE);
        if !candidate.exists() {
            return;
        }
        let err = validate_directory(candidate, ExecTrust::Root)
            .expect_err("regular file must not validate as a directory");
        assert!(matches!(err, PrivilegedPathError::NotDirectory { .. }));
    }

    #[test]
    fn read_file_uses_validated_root_owned_inode() {
        let candidate = Path::new(TRUSTED_SYSTEM_FILE);
        if !candidate.exists() {
            return;
        }
        let bytes =
            read_file(candidate, ExecTrust::Root).expect("root-owned system file must be readable");
        assert!(!bytes.is_empty());
    }
}

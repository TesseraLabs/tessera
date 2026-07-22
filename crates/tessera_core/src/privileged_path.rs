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
//! [`validate_path`] resolves symlinks up front (so the walk sees exactly the
//! tree the kernel would resolve), walks it, then re-opens the leaf with
//! `O_NOFOLLOW` and re-checks the opened inode. The returned [`ValidatedPath`]
//! hands back the open descriptor so a caller can act on *exactly* the inode
//! that was validated — reopening it for a read, or (on Linux) `fexecve`-ing it
//! — instead of re-resolving the path and racing a swap in between.

use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// `S_IWOTH` — write permission for "other". Never acceptable on a privileged
/// path: it lets any local user rewrite the component.
const OTHER_WRITE: u32 = 0o002;

/// `S_IWGRP` — write permission for the owning group. Acceptable only when the
/// owning group is trusted (root, or the target account's own group).
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
    descriptor: OwnedFd,
}

impl ValidatedPath {
    /// The canonical, symlink-free path that was validated.
    #[must_use]
    pub fn canonical(&self) -> &Path {
        &self.canonical
    }

    /// Borrow the descriptor opened to the validated leaf inode.
    #[must_use]
    pub fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.descriptor.as_fd()
    }

    /// Consume the guard and return the owned descriptor to the validated leaf.
    #[must_use]
    pub fn into_descriptor(self) -> OwnedFd {
        self.descriptor
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
}

/// Validate that `path` and every canonical ancestor satisfy `trust`, returning
/// a descriptor to the validated leaf inode.
///
/// The path is canonicalized first, so the walk and the descriptor both refer
/// to the real, symlink-free tree the kernel would resolve — a symlinked
/// component cannot hide its true parents from the permission walk. The leaf is
/// then reopened `O_NOFOLLOW` and re-checked against the freshly `fstat`ed
/// inode, closing the window between the walk and the open.
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

    // Walk the leaf and every ancestor. `symlink_metadata` never follows a
    // symlink; on a canonical path there are none, but using the non-following
    // stat keeps the check honest even if the tree mutates mid-walk.
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
    })
}

/// Enforce the [`ExecTrust`] policy against a single component's metadata.
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

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
        let candidate = Path::new("/bin/sh");
        if !candidate.exists() {
            return;
        }
        match validate_path(candidate, ExecTrust::Root) {
            Ok(validated) => {
                assert!(validated.canonical().is_absolute());
                let _fd = validated.into_descriptor();
            }
            // Extremely unusual permissions on a host's /bin/sh should not fail
            // the suite; the security-relevant assertions are the rejections.
            Err(err) => panic!("expected /bin/sh to validate under Root trust: {err:?}"),
        }
    }
}

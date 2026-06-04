//! `getpwnam_r`-based PAM user resolution for hook drop-priv.
//!
//! [`lookup_user`] returns a fully-populated [`UserInfo`] suitable for
//! `setgroups` / `setgid` / `setuid` in the child after `fork`. The lookup is
//! done in the **parent**; the child receives a borrowed reference and never
//! allocates.

use std::path::PathBuf;

use crate::hooks::result::HookError;

/// Resolved POSIX user info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    /// User login name.
    pub name: String,
    /// User ID.
    pub uid: u32,
    /// Primary group ID.
    pub gid: u32,
    /// Supplementary group IDs (includes the primary gid).
    pub groups: Vec<u32>,
    /// Home directory.
    pub home: PathBuf,
}

/// Resolve `name` via `getpwnam_r` and `getgrouplist`.
///
/// # Errors
///
/// * [`HookError::UserResolution`] when the user does not exist
///   (`Ok(None)` from `nix::unistd::User::from_name`, mapped to a synthetic
///   `ENOENT`) or when libc returned a real error (NSS module failure, EIO
///   from a remote authority, …).
/// * [`HookError::ChildSetup`] when the username is invalid (empty or
///   contains a NUL byte).
pub fn lookup_user(name: &str) -> Result<UserInfo, HookError> {
    if name.is_empty() {
        return Err(HookError::ChildSetup {
            message: "empty username".into(),
        });
    }
    if name.contains('\0') {
        return Err(HookError::ChildSetup {
            message: "username contains NUL byte".into(),
        });
    }

    let user = match nix::unistd::User::from_name(name) {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Err(HookError::UserResolution {
                user: name.to_string(),
                source: std::io::Error::from_raw_os_error(libc::ENOENT),
            });
        }
        Err(errno) => {
            return Err(HookError::UserResolution {
                user: name.to_string(),
                source: std::io::Error::from_raw_os_error(errno as i32),
            });
        }
    };

    let primary_gid = user.gid.as_raw();

    let cname = std::ffi::CString::new(name).map_err(|_| HookError::ChildSetup {
        message: "username contains NUL byte".into(),
    })?;
    let groups = group_list(&cname, primary_gid).map_err(|errno| HookError::UserResolution {
        user: name.to_string(),
        source: std::io::Error::from_raw_os_error(errno),
    })?;

    Ok(UserInfo {
        name: user.name,
        uid: user.uid.as_raw(),
        gid: primary_gid,
        groups,
        home: user.dir,
    })
}

/// Linux/Unix-style supplementary group lookup wrapper. On platforms where
/// `nix::unistd::getgrouplist` is gated out (macOS, iOS, illumos, AIX,
/// redox), fall back to the system's `getgrouplist(3)` via libc directly.
#[cfg(not(any(
    target_os = "aix",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "redox"
)))]
fn group_list(name: &std::ffi::CStr, primary_gid: u32) -> Result<Vec<u32>, i32> {
    match nix::unistd::getgrouplist(name, nix::unistd::Gid::from_raw(primary_gid)) {
        Ok(gs) => Ok(gs.into_iter().map(nix::unistd::Gid::as_raw).collect()),
        Err(errno) => Err(errno as i32),
    }
}

/// macOS-style supplementary group lookup. Apple's signature for
/// `getgrouplist(3)` takes `*mut c_int` rather than `*mut gid_t`. Unlike
/// the GNU/BSD variant, Apple's implementation does **not** update
/// `*ngroups` to the required size on failure — it simply returns -1 and
/// leaves the count untouched. We grow the buffer geometrically until the
/// kernel reports success or the buffer hits a sane upper bound.
///
/// # Safety
///
/// The function calls `libc::getgrouplist` directly. We pass a
/// NUL-terminated `name`, a valid `groups` buffer of `ngroups_inout`
/// ints, and a valid pointer to `ngroups_inout`. The kernel writes at
/// most `ngroups_inout` ints. We never read from `groups` past the count
/// returned in `ngroups_inout`. No memory is shared between threads.
#[cfg(any(
    target_os = "aix",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "redox"
))]
#[allow(unsafe_code)]
fn group_list(name: &std::ffi::CStr, primary_gid: u32) -> Result<Vec<u32>, i32> {
    // Hard upper bound. POSIX guarantees NGROUPS_MAX is at most a few
    // hundred; macOS in practice caps at 16 *effective* groups but the
    // total list can be larger. 4096 is paranoid-safe.
    const HARD_CAP: libc::c_int = 4096;
    let basegid: libc::c_int = libc::c_int::try_from(primary_gid).unwrap_or(libc::c_int::MAX);
    let mut ngroups: libc::c_int = 32;
    loop {
        let mut buf: Vec<libc::c_int> = vec![0; usize::try_from(ngroups).unwrap_or(32).max(1)];
        let mut ngroups_inout = ngroups;
        // SAFETY: see fn-level doc-comment.
        let rc = unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                basegid,
                buf.as_mut_ptr(),
                std::ptr::from_mut(&mut ngroups_inout),
            )
        };
        if rc >= 0 {
            buf.truncate(usize::try_from(ngroups_inout).unwrap_or(0));
            let groups: Vec<u32> = buf
                .into_iter()
                .map(|g| u32::try_from(g).unwrap_or(0))
                .collect();
            return Ok(groups);
        }
        if ngroups >= HARD_CAP {
            return Err(libc::EINVAL);
        }
        ngroups = ngroups.saturating_mul(2).min(HARD_CAP);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_name_is_child_setup_error() {
        let r = lookup_user("");
        assert!(matches!(r, Err(HookError::ChildSetup { .. })));
    }

    #[test]
    fn name_with_nul_is_child_setup_error() {
        let r = lookup_user("a\0b");
        assert!(matches!(r, Err(HookError::ChildSetup { .. })));
    }

    #[test]
    fn missing_user_returns_user_resolution() {
        let r = lookup_user("definitely_not_a_user_xx0123456789xx");
        match r {
            Err(HookError::UserResolution { user, .. }) => {
                assert!(user.contains("definitely_not_a_user"));
            }
            other => panic!("expected UserResolution, got {other:?}"),
        }
    }

    #[test]
    fn root_lookup_succeeds() {
        // root is present on every Unix worth talking about, including the
        // dev macOS host. getgrouplist on macOS may return ENGINE-specific
        // results — we only assert the basics.
        let info = lookup_user("root").expect("root lookup");
        assert_eq!(info.name, "root");
        assert_eq!(info.uid, 0);
        assert_eq!(info.gid, 0);
        assert!(!info.home.as_os_str().is_empty());
    }
}

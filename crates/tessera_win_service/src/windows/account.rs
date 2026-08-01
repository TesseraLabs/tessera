//! The local account a successful login is opened under.
//!
//! One shared account, created by `prepare` and never by the service. The
//! engineer's identity is the credential; this account is only the thing
//! Windows needs in order to have a session at all, and the journal is where
//! the question "who was that" is answered.
//!
//! # What makes it usable for an interactive logon
//!
//! Three things, none of them automatic:
//!
//! * It is a normal local account (`USER_PRIV_USER`), which `NetUserAdd` places
//!   in the built-in `Users` group. That group holds `SeInteractiveLogonRight`
//!   on a stock installation, and that right — not membership as such — is what
//!   lets the account log on at the console. A machine whose policy has
//!   narrowed "Allow log on locally" will refuse this account, which is a
//!   deployment fact worth checking on any managed device.
//! * Its password does not expire (`UF_DONT_EXPIRE_PASSWD`). An expired password
//!   turns every login into a forced password change at the logon screen, under
//!   an account nobody is supposed to interact with.
//! * The account cannot change its own password (`UF_PASSWD_CANT_CHANGE`).
//!   Whoever is inside the session must not be able to invalidate the copy the
//!   service holds; that would take the device out of service until `prepare`
//!   ran again.
//!
//! The account is not hidden from the logon screen and is not disabled for
//! network logon. Both are worth doing and neither belongs in the wave that is
//! proving the certificate path.
//!
//! # Unsafe
//!
//! Three calls into `netapi32`. The structures they read borrow UTF-16 buffers
//! that outlive each call; the one buffer an API allocates is released through
//! `NetApiBufferFree`.
#![allow(unsafe_code)]

use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserAdd, NetUserGetInfo, NetUserSetInfo, UF_DONT_EXPIRE_PASSWD,
    UF_NORMAL_ACCOUNT, UF_PASSWD_CANT_CHANGE, UF_SCRIPT, USER_INFO_1, USER_INFO_1003,
    USER_PRIV_USER,
};
use zeroize::Zeroize as _;

use super::sys::{wide, WinError};

/// `NERR_Success`.
const NERR_SUCCESS: u32 = 0;
/// `NERR_UserNotFound`.
const NERR_USER_NOT_FOUND: u32 = 2221;
/// `NERR_UserExists`.
const NERR_USER_EXISTS: u32 = 2224;

/// Whether a local account named `name` exists.
///
/// The query is local by construction: the server name is null, so `netapi32`
/// answers from this machine's own account database and never consults a domain
/// controller.
///
/// # Errors
///
/// [`WinError`] for anything other than "exists" or "does not exist" — a
/// database that cannot answer is not an answer of "no".
pub fn exists(name: &str) -> Result<bool, WinError> {
    let user = wide(name);
    let mut buffer: *mut u8 = std::ptr::null_mut();
    // SAFETY: `user` is a NUL-terminated UTF-16 name that outlives the call and
    // `buffer` is a live local the callee writes on success.
    let status = unsafe { NetUserGetInfo(std::ptr::null(), user.as_ptr(), 0, &raw mut buffer) };
    if !buffer.is_null() {
        // SAFETY: the pointer came from `NetUserGetInfo`, which documents
        // `NetApiBufferFree` as its release, and it is not used afterwards.
        let _freed = unsafe { NetApiBufferFree(buffer.cast()) };
    }
    match status {
        NERR_SUCCESS => Ok(true),
        NERR_USER_NOT_FOUND => Ok(false),
        other => Err(WinError::new("NetUserGetInfo", other)),
    }
}

/// Creates the local account `name` with `password`.
///
/// # Errors
///
/// [`WinError`] when creation fails, including when the account already exists —
/// the caller decides what that means, because "it is already there" is a
/// different situation from "it could not be made".
pub fn create(name: &str, password: &str, comment: &str) -> Result<(), WinError> {
    let mut user = wide(name);
    let mut secret = wide(password);
    let mut note = wide(comment);
    let mut info = USER_INFO_1 {
        usri1_name: user.as_mut_ptr(),
        usri1_password: secret.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: std::ptr::null_mut(),
        usri1_comment: note.as_mut_ptr(),
        usri1_flags: UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
        usri1_script_path: std::ptr::null_mut(),
    };
    let mut parameter: u32 = 0;
    // SAFETY: the three buffers outlive the call, `info` describes level 1 as
    // the level argument says, and `parameter` is a live local.
    let status = unsafe {
        NetUserAdd(
            std::ptr::null(),
            1,
            std::ptr::from_mut(&mut info).cast::<u8>(),
            &raw mut parameter,
        )
    };
    secret.zeroize();
    let result = match status {
        NERR_SUCCESS => Ok(()),
        NERR_USER_EXISTS => Err(WinError::new("NetUserAdd", NERR_USER_EXISTS)),
        other => Err(WinError::new("NetUserAdd", other)),
    };
    drop(user);
    drop(note);
    result
}

/// Replaces the password of the existing local account `name`.
///
/// # Errors
///
/// [`WinError`] when the account does not exist or the change is refused (a
/// password policy the generated value does not satisfy, most plausibly).
pub fn set_password(name: &str, password: &str) -> Result<(), WinError> {
    let user = wide(name);
    let mut secret = wide(password);
    let mut info = USER_INFO_1003 {
        usri1003_password: secret.as_mut_ptr(),
    };
    let mut parameter: u32 = 0;
    // SAFETY: both buffers outlive the call, `info` describes level 1003 as the
    // level argument says, and `parameter` is a live local.
    let status = unsafe {
        NetUserSetInfo(
            std::ptr::null(),
            user.as_ptr(),
            1003,
            std::ptr::from_mut(&mut info).cast::<u8>(),
            &raw mut parameter,
        )
    };
    secret.zeroize();
    if status == NERR_SUCCESS {
        Ok(())
    } else {
        Err(WinError::new("NetUserSetInfo", status))
    }
}

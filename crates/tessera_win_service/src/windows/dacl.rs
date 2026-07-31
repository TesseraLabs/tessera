//! Security descriptors: the data directory's and the pipe's.
//!
//! Both are stated as SDDL and converted once, rather than assembled ACE by
//! ACE. The string is the whole policy in one line, which is the form a reviewer
//! can check against what the machine reports afterwards (`Get-Acl`).
//!
//! # Why the data directory is protected
//!
//! `%ProgramData%` grants `Users` the right to create files, and that right is
//! inherited by anything created under it. A role directory that inherits it is
//! a directory any unprivileged user can drop a file into — and that file
//! belongs to them, so the trust walk refuses it and the whole role store fails
//! to load. One file from an ordinary account would deny every login on the
//! device. Breaking inheritance is therefore not hardening on top of a working
//! configuration; without it the configuration does not work.
//!
//! # Unsafe
//!
//! Four Win32 calls, each wrapped alone. The descriptors they produce are owned
//! by [`super::sys::LocalBlock`] and outlive every pointer taken into them.
#![allow(unsafe_code)]

use std::path::Path;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES,
};

use super::sys::{wide, wide_path, LocalBlock, WinError};

/// `SDDL_REVISION_1`, the only defined revision.
const SDDL_REVISION_1: u32 = 1;

/// The data directory: owned by the administrators group, inheritance broken,
/// full control to `LocalSystem` and to administrators, inherited by everything
/// created inside.
///
/// The owner is set explicitly because the default owner of an object created
/// by an elevated administrator is that administrator's own account, and the
/// trust walk accepts only `LocalSystem`, the administrators group, or
/// `TrustedInstaller`. Left to the default, a directory `prepare` created would
/// be refused by the service that reads it.
const DATA_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The account secret: `LocalSystem` and nothing else, no inheritance.
///
/// The blob is DPAPI machine-scope, so any process on the machine could decrypt
/// it if it could read it — which makes this DACL, not the encryption, the
/// boundary that matters. Administrators can still take ownership; that is the
/// platform's model and not something a file ACL can change.
const ACCOUNT_SECRET_SDDL: &str = "O:BAD:P(A;;FA;;;SY)";

/// The pipe: `LocalSystem` only.
///
/// The credential provider runs in the `winlogon` context, which is SYSTEM; an
/// engineer's session is not, and is refused by the kernel before a single
/// frame is exchanged.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)";

/// A security descriptor parsed from SDDL, kept alive with its allocation.
pub struct Descriptor {
    block: LocalBlock,
}

impl Descriptor {
    /// Parses `sddl`.
    ///
    /// # Errors
    ///
    /// [`WinError`] when the string does not parse — which, for the constants in
    /// this module, means the constant is wrong and the caller must fail rather
    /// than continue with whatever the object already carried.
    pub fn parse(sddl: &str) -> Result<Self, WinError> {
        let text = wide(sddl);
        let mut raw: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `text` is a NUL-terminated UTF-16 string that outlives the
        // call, and `raw` is a live local the callee writes on success.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(WinError::last(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        Ok(Self {
            block: LocalBlock::adopt(raw, "ConvertStringSecurityDescriptorToSecurityDescriptorW")?,
        })
    }

    /// The descriptor pointer, valid while this value lives.
    fn raw(&self) -> PSECURITY_DESCRIPTOR {
        self.block.raw()
    }

    /// The descriptor's DACL.
    ///
    /// # Errors
    ///
    /// [`WinError`] when the descriptor carries no DACL — a NULL DACL grants
    /// everyone everything, so it is refused rather than applied.
    fn dacl(&self) -> Result<*const ACL, WinError> {
        let mut present: i32 = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted: i32 = 0;
        // SAFETY: the descriptor is live and the three out-parameters are live
        // locals the callee writes on success.
        let ok = unsafe {
            GetSecurityDescriptorDacl(
                self.raw(),
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        };
        if ok == 0 {
            return Err(WinError::last("GetSecurityDescriptorDacl"));
        }
        if present == 0 || dacl.is_null() {
            return Err(WinError::new("GetSecurityDescriptorDacl", 0));
        }
        Ok(dacl.cast_const())
    }

    /// The descriptor's owner SID, or null when it carries none.
    fn owner(&self) -> Result<PSID, WinError> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted: i32 = 0;
        // SAFETY: the descriptor is live and both out-parameters are live
        // locals the callee writes on success.
        let ok =
            unsafe { GetSecurityDescriptorOwner(self.raw(), &raw mut owner, &raw mut defaulted) };
        if ok == 0 {
            return Err(WinError::last("GetSecurityDescriptorOwner"));
        }
        Ok(owner)
    }

    /// Security attributes referring to this descriptor.
    ///
    /// The returned value borrows the descriptor, so it cannot outlive it.
    #[must_use]
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: self.raw(),
            bInheritHandle: 0,
        }
    }
}

/// Applies `sddl`'s owner and DACL to `path`, breaking inheritance.
fn apply(path: &Path, sddl: &str) -> Result<(), WinError> {
    let descriptor = Descriptor::parse(sddl)?;
    let dacl = descriptor.dacl()?;
    let owner = descriptor.owner()?;
    let name = wide_path(path);
    let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if !owner.is_null() {
        info |= OWNER_SECURITY_INFORMATION;
    }
    // SAFETY: `name` is a NUL-terminated path, `owner` and `dacl` point into a
    // descriptor that outlives the call, and the unused group and SACL
    // parameters are null with their bits absent from `info`.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            info,
            owner,
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(WinError::new("SetNamedSecurityInfoW", status))
    }
}

/// Applies the data-directory policy to `path`.
///
/// # Errors
///
/// [`WinError`] when the descriptor cannot be built or applied. `prepare` fails
/// in that case: a data directory that still inherits `%ProgramData%` is one an
/// unprivileged account can write into.
pub fn protect_data_dir(path: &Path) -> Result<(), WinError> {
    apply(path, DATA_DIR_SDDL)
}

/// Applies the `LocalSystem`-only policy to the account-secret file.
///
/// # Errors
///
/// [`WinError`] when the descriptor cannot be built or applied.
pub fn protect_account_secret(path: &Path) -> Result<(), WinError> {
    apply(path, ACCOUNT_SECRET_SDDL)
}

/// The pipe's security descriptor.
///
/// # Errors
///
/// [`WinError`] when the descriptor cannot be built. The service refuses to
/// listen in that case rather than fall back to a default descriptor, which
/// would admit every process running as the pipe's creator.
pub fn pipe_descriptor() -> Result<Descriptor, WinError> {
    Descriptor::parse(PIPE_SDDL)
}

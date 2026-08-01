//! Machine-scope DPAPI, used for one value: the technical account's password.
//!
//! Machine scope rather than user scope because the reader is `LocalSystem` and
//! the writer is whoever ran `prepare` — two different logon contexts, one
//! machine. What that buys is narrow and worth stating plainly: the blob is
//! useless on another machine, and it is not a secret from anything running on
//! this one. Any process that can read the file can also ask DPAPI to decrypt
//! it. The boundary is the file's DACL (see [`super::dacl`]); this is
//! defence in depth behind it, not the defence itself.
//!
//! # Unsafe
//!
//! Two calls, each wrapped alone. Both write a blob the caller must release
//! with `LocalFree`; both are copied out and released before returning.
#![allow(unsafe_code)]

use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroizing;

use super::sys::{LocalBlock, WinError};

/// Secondary entropy tying a blob to this use.
///
/// Not a secret — it is in the binary — and not treated as one. It is domain
/// separation: a blob produced here cannot be decrypted by code that asks DPAPI
/// for something else, which keeps one stray `CryptUnprotectData` in an
/// unrelated tool from quietly reading this file.
const ENTROPY: &[u8] = b"tessera-engine/account-password/v1";

/// A blob as the API wants it. The pointer borrows `data`.
fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).unwrap_or(u32::MAX),
        pbData: data.as_ptr().cast_mut(),
    }
}

/// Copies out an API-returned blob, wipes it, and releases it.
///
/// The wipe matters on the decrypt path: `LocalFree` returns the plaintext
/// password to the heap as it stands, where it would sit until something else
/// happened to reuse the block.
fn take(out: &CRYPT_INTEGER_BLOB, operation: &'static str) -> Result<Vec<u8>, WinError> {
    use zeroize::Zeroize as _;

    let owned = LocalBlock::adopt(out.pbData.cast(), operation)?;
    let len = out.cbData as usize;
    // SAFETY: the API reports `cbData` bytes at `pbData`; the block is owned by
    // `owned`, so the slice cannot outlive the allocation, and nothing else
    // aliases it between here and the release.
    let bytes = unsafe { std::slice::from_raw_parts_mut(owned.raw().cast::<u8>(), len) };
    let copy = bytes.to_vec();
    bytes.zeroize();
    Ok(copy)
}

/// Encrypts `plain` for this machine.
///
/// # Errors
///
/// [`WinError`] when DPAPI refuses.
pub fn protect(plain: &[u8]) -> Result<Vec<u8>, WinError> {
    let input = blob(plain);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: the two input blobs borrow live slices for the duration of the
    // call, the unused reserved and prompt parameters are null, and `out` is a
    // live local the callee writes on success.
    let ok = unsafe {
        CryptProtectData(
            &raw const input,
            std::ptr::null(),
            &raw const entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &raw mut out,
        )
    };
    if ok == 0 {
        return Err(WinError::last("CryptProtectData"));
    }
    take(&out, "CryptProtectData")
}

/// Decrypts a blob produced by [`protect`] on this machine.
///
/// The result wipes itself when dropped.
///
/// # Errors
///
/// [`WinError`] when DPAPI refuses — a blob from another machine, a corrupted
/// file, or one written with different entropy.
pub fn unprotect(sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, WinError> {
    let input = blob(sealed);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: as in `protect`; the description out-parameter is not requested.
    let ok = unsafe {
        CryptUnprotectData(
            &raw const input,
            std::ptr::null_mut(),
            &raw const entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &raw mut out,
        )
    };
    if ok == 0 {
        return Err(WinError::last("CryptUnprotectData"));
    }
    Ok(Zeroizing::new(take(&out, "CryptUnprotectData")?))
}

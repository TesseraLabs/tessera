//! Small FFI helpers around `pam_get_user` / `pam_get_item` so the cdylib
//! `pam_sm_*` entry points can lift PAM_USER and PAM_SERVICE off a live
//! handle without scattering `unsafe` blocks across the call sites.
//!
//! Only compiled on Linux (where `pam-sys` is available).

#![cfg(target_os = "linux")]
#![allow(unsafe_code, clippy::doc_markdown)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

/// Errors raised by [`pam_get_user_string`] / [`pam_get_item_string`].
#[derive(Debug, thiserror::Error)]
pub enum PamHelperError {
    /// Underlying PAM call returned a non-success code.
    #[error("pam call returned rc={0}")]
    PamRc(i32),
    /// PAM returned a NULL pointer where we expected a string.
    #[error("pam returned null")]
    Null,
    /// The PAM-supplied bytes were not valid UTF-8.
    #[error("non-utf8 PAM string")]
    NonUtf8,
}

const PAM_SUCCESS: c_int = pam_sys::PAM_SUCCESS as c_int;
const PAM_SERVICE: c_int = pam_sys::PAM_SERVICE as c_int;
const PAM_TTY: c_int = pam_sys::PAM_TTY as c_int;

extern "C" {
    /// Re-declared with a stable signature; bindgen generates this with
    /// types that vary across libpam revisions.
    fn pam_get_user(
        pamh: *mut pam_sys::pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;

    /// Same rationale as [`pam_get_user`] above.
    fn pam_get_item(
        pamh: *mut pam_sys::pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    /// Read a PAM environment variable (`pam_getenv`). Returns a
    /// pointer owned by PAM, valid for the lifetime of `pamh`; the
    /// caller must NOT free it. Returns NULL when the variable is
    /// unset.
    fn pam_getenv(pamh: *mut pam_sys::pam_handle_t, name: *const c_char) -> *const c_char;
}

/// Read PAM_USER off the live handle.
///
/// # Safety
///
/// `pamh` must be the live PAM handle handed to a `pam_sm_*` callback.
///
/// # Errors
///
/// * [`PamHelperError::PamRc`] when the underlying PAM call fails.
/// * [`PamHelperError::Null`] if PAM returned a NULL user pointer.
/// * [`PamHelperError::NonUtf8`] if PAM returned non-UTF-8 bytes.
pub unsafe fn pam_get_user_string(
    pamh: *mut pam_sys::pam_handle_t,
) -> Result<String, PamHelperError> {
    let mut user_ptr: *const c_char = std::ptr::null();
    // SAFETY: `pamh` is owned by PAM; `user_ptr` is a valid out-pointer.
    let rc = unsafe { pam_get_user(pamh, &raw mut user_ptr, std::ptr::null()) };
    if rc != PAM_SUCCESS {
        return Err(PamHelperError::PamRc(rc));
    }
    if user_ptr.is_null() {
        return Err(PamHelperError::Null);
    }
    // SAFETY: PAM guarantees `user_ptr` is a NUL-terminated C string for
    // the lifetime of `pamh`.
    let cstr = unsafe { CStr::from_ptr(user_ptr) };
    cstr.to_str()
        .map(str::to_owned)
        .map_err(|_| PamHelperError::NonUtf8)
}

/// Read the PAM service name off the live handle (`pam_get_item(PAM_SERVICE)`).
///
/// # Safety
///
/// See [`pam_get_user_string`].
///
/// # Errors
///
/// See [`pam_get_user_string`].
pub unsafe fn pam_get_service_string(
    pamh: *mut pam_sys::pam_handle_t,
) -> Result<String, PamHelperError> {
    let mut item_ptr: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is owned by PAM; `item_ptr` is a valid out-pointer.
    let rc = unsafe { pam_get_item(pamh, PAM_SERVICE, &raw mut item_ptr) };
    if rc != PAM_SUCCESS {
        return Err(PamHelperError::PamRc(rc));
    }
    if item_ptr.is_null() {
        return Err(PamHelperError::Null);
    }
    // SAFETY: For PAM_SERVICE the item is a `const char *` valid for the
    // lifetime of `pamh`.
    let cstr = unsafe { CStr::from_ptr(item_ptr.cast::<c_char>()) };
    cstr.to_str()
        .map(str::to_owned)
        .map_err(|_| PamHelperError::NonUtf8)
}

/// Read PAM_TTY off the live handle.
///
/// Returns `Ok(None)` when PAM has no TTY item set (e.g. some greeter
/// stacks). Returns `Ok(Some(_))` for the typical tty path or X display
/// name; the value is whatever PAM stored — usually `/dev/tty1`,
/// `/dev/pts/0`, `:0`, or `:1`.
///
/// # Safety
///
/// See [`pam_get_user_string`].
///
/// # Errors
///
/// * [`PamHelperError::PamRc`] when the underlying PAM call fails with a
///   code other than `PAM_SUCCESS`.
/// * [`PamHelperError::NonUtf8`] if PAM returned non-UTF-8 bytes.
pub unsafe fn pam_get_tty_string(
    pamh: *mut pam_sys::pam_handle_t,
) -> Result<Option<String>, PamHelperError> {
    let mut item_ptr: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is owned by PAM; `item_ptr` is a valid out-pointer.
    let rc = unsafe { pam_get_item(pamh, PAM_TTY, &raw mut item_ptr) };
    if rc != PAM_SUCCESS {
        return Err(PamHelperError::PamRc(rc));
    }
    if item_ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: For PAM_TTY the item is a `const char *` valid for the
    // lifetime of `pamh`.
    let cstr = unsafe { CStr::from_ptr(item_ptr.cast::<c_char>()) };
    let s = cstr
        .to_str()
        .map(str::to_owned)
        .map_err(|_| PamHelperError::NonUtf8)?;
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(s))
    }
}

/// Read a PAM environment variable off the live handle via `pam_getenv`.
///
/// Returns `Ok(None)` when the variable is unset (PAM returns NULL) or
/// when the stored value is the empty string. Returns `Ok(Some(_))` for
/// any other value.
///
/// Used by `pam_sm_open_session` to read `XDG_SESSION_ID` (populated by
/// `pam_systemd.so` in the session phase). When `pam_systemd` has not
/// yet run, this returns `Ok(None)` — callers MUST treat that as a
/// benign condition and skip the IPC push.
///
/// # Safety
///
/// See [`pam_get_user_string`].
///
/// # Errors
///
/// * [`PamHelperError::NonUtf8`] if PAM returned non-UTF-8 bytes.
pub unsafe fn pam_get_env_string(
    pamh: *mut pam_sys::pam_handle_t,
    name: &str,
) -> Result<Option<String>, PamHelperError> {
    let c_name = CString::new(name).map_err(|_| PamHelperError::PamRc(-1))?;
    // SAFETY: `pamh` is owned by PAM; `c_name` is a valid NUL-terminated
    // C string whose lifetime covers this call. `pam_getenv` returns a
    // pointer into PAM-owned storage; we must not free it.
    let ptr = unsafe { pam_getenv(pamh, c_name.as_ptr()) };
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: PAM guarantees `ptr` is a NUL-terminated C string valid
    // for the lifetime of `pamh`.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let s = cstr
        .to_str()
        .map(str::to_owned)
        .map_err(|_| PamHelperError::NonUtf8)?;
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(s))
    }
}

/// Build a NUL-terminated `CString` for a PAM data key, panicking only on
/// programmer error (interior NUL, which never happens for our static keys).
///
/// # Errors
///
/// Returns [`PamHelperError::PamRc`] with rc=-1 if the key contains an
/// interior NUL byte (programmer error).
pub fn data_key_cstring(key: &str) -> Result<CString, PamHelperError> {
    CString::new(key).map_err(|_| PamHelperError::PamRc(-1))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::duration_suboptimal_units
)]
mod tests {
    use super::*;

    #[test]
    fn data_key_round_trip() {
        let c = data_key_cstring("tessera.auth_context").unwrap();
        assert_eq!(c.to_bytes(), b"tessera.auth_context");
    }

    #[test]
    fn data_key_rejects_interior_nul() {
        assert!(data_key_cstring("bad\0key").is_err());
    }
}

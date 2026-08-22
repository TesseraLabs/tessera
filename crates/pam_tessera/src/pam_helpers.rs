//! Small FFI helpers around `pam_get_user` / `pam_get_item` so the cdylib
//! `pam_sm_*` entry points can lift PAM_USER and PAM_SERVICE off a live
//! handle without scattering `unsafe` blocks across the call sites.
//!
//! Read-only about identity by design: there is deliberately no
//! `pam_set_item` binding. The module never rewrites the user name the stack
//! read, because the difference between the name before and after such a
//! rewrite is exactly what other modules in the stack can observe (the polkit
//! CVE-2021-3560 class).
//!
//! [`set_fail_delay`] is the one call here that writes, and it writes nothing
//! the stack reads as identity: it asks libpam to slow a refusal down.
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

    /// Sets the delay libpam applies when this transaction ends in a refusal.
    ///
    /// Re-declared for the same reason as the calls above.
    fn pam_fail_delay(pamh: *mut pam_sys::pam_handle_t, usec: std::os::raw::c_uint) -> c_int;

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

/// The delay in microseconds, as `pam_fail_delay` takes it.
///
/// Saturating rather than wrapping: a delay so long that it leaves the range
/// would otherwise come out as a short one — or none — and a refusal that
/// answers instantly is exactly what the delay exists to prevent.
#[must_use]
pub fn fail_delay_micros(delay: std::time::Duration) -> std::os::raw::c_uint {
    std::os::raw::c_uint::try_from(delay.as_micros()).unwrap_or(std::os::raw::c_uint::MAX)
}

/// Ask libpam to delay this transaction by `delay` if it ends in a refusal.
///
/// libpam applies the delay itself, and **only when the transaction fails** —
/// so this is called once, unconditionally, before anything can refuse, rather
/// than on each refusing branch. Two reasons, and the second is the point:
///
/// - a list of branches to delay is a list the next branch added will not be
///   on, and it fails open;
/// - the refusals of the code method are many and of different cost — no
///   ticket, scope that does not cover, a revoked ticket, a code that does not
///   meet, a spent budget, a role briefly locked. If some answer at once and
///   others after a wait, the wait itself tells a caller which happened, and
///   several of those answers would disclose that a role and a ticket exist
///   before anything has been authenticated.
///
/// The randomisation is libpam's and is the reason for using it rather than
/// sleeping here: a fixed sleep is as good a clock to measure against as no
/// sleep at all.
///
/// A successful login pays nothing: libpam never applies the delay to one.
///
/// # Safety
///
/// `pamh` must be the live PAM handle of the current `pam_sm_*` callback.
///
/// # Errors
///
/// [`PamHelperError::PamRc`] when libpam refuses the call. The caller treats
/// it as best-effort — a refusal that could not be slowed down is still a
/// refusal — but it is worth a line in the journal.
pub unsafe fn set_fail_delay(
    pamh: *mut pam_sys::pam_handle_t,
    delay: std::time::Duration,
) -> Result<(), PamHelperError> {
    // SAFETY: `pamh` is the live PAM handle (caller contract); the second
    // argument is a plain integer.
    let rc = unsafe { pam_fail_delay(pamh, fail_delay_micros(delay)) };
    if rc == PAM_SUCCESS {
        Ok(())
    } else {
        Err(PamHelperError::PamRc(rc))
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod fail_delay_tests {
    use super::fail_delay_micros;
    use std::time::Duration;

    #[test]
    fn the_configured_delay_survives_the_conversion() {
        // The value the throttle publishes is the value libpam is handed:
        // a second constant here would drift from it silently.
        assert_eq!(
            fail_delay_micros(tessera_core::codes::throttle::FAILURE_DELAY),
            u32::try_from(tessera_core::codes::throttle::FAILURE_DELAY.as_micros()).unwrap(),
        );
        assert!(fail_delay_micros(tessera_core::codes::throttle::FAILURE_DELAY) > 0);
    }

    #[test]
    fn a_delay_beyond_the_range_saturates_rather_than_wrapping() {
        // Wrapping would turn a very long delay into a very short one, which
        // is the one outcome a delay must never produce.
        assert_eq!(fail_delay_micros(Duration::MAX), std::os::raw::c_uint::MAX);
        assert_eq!(fail_delay_micros(Duration::ZERO), 0);
    }
}

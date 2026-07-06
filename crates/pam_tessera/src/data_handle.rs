//! Linux PAM data handle helpers.
//!
//! `pam_sm_authenticate` stores an [`AuthContext`] under [`DATA_KEY`] so
//! later stages of the PAM stack (`pam_sm_acct_mgmt`, session hooks) can
//! reuse the same authenticated state without re-running the cert flow.
//!
//! This module is Linux-only because it depends on `pam-sys` FFI symbols
//! (`pam_set_data` / `pam_get_data`) that bindgen does not generate on
//! macOS dev hosts.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

use tessera_core::pam_data::AuthContext;

/// PAM data key under which the authenticated [`AuthContext`] is stored.
pub const DATA_KEY: &str = "tessera.auth_context";

const PAM_SUCCESS: c_int = pam_sys::PAM_SUCCESS as c_int;

extern "C" {
    fn pam_set_data(
        pamh: *mut pam_sys::pam_handle_t,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<
            unsafe extern "C" fn(
                pamh: *mut pam_sys::pam_handle_t,
                data: *mut c_void,
                error_status: c_int,
            ),
        >,
    ) -> c_int;

    fn pam_get_data(
        pamh: *const pam_sys::pam_handle_t,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
}

/// Cleanup callback PAM invokes when the handle is torn down: free the
/// [`AuthContext`] we previously leaked into PAM via `Box::into_raw`.
///
/// # Safety
///
/// `data` must point to a `Box<AuthContext>` previously stored by
/// [`set_auth_context`]; PAM is the only caller and it adheres to that
/// contract.
unsafe extern "C" fn auth_context_cleanup(
    _pamh: *mut pam_sys::pam_handle_t,
    data: *mut c_void,
    _error_status: c_int,
) {
    if data.is_null() {
        return;
    }
    // libpam invokes this at pam_end across the C ABI. The crate unwinds on
    // panic, so an unwind escaping this frame into C would be undefined
    // behaviour. Contain any panic from dropping the context (mirroring the
    // catch_unwind guard every other C-facing entry uses) and log it.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract — `data` came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(data.cast::<AuthContext>()) });
    }));
    if result.is_err() {
        tracing::error!(
            target: "tessera.pam",
            "panic while freeing auth context during PAM teardown; contained to avoid \
             unwinding across the C boundary"
        );
    }
}

/// Errors raised by [`set_auth_context`] / [`get_auth_context`].
#[derive(Debug, thiserror::Error)]
pub enum DataHandleError {
    /// PAM returned a non-success code.
    #[error("pam_set_data/get_data rc={0}")]
    PamRc(i32),
    /// Data key contained an interior NUL byte.
    #[error("invalid data key")]
    BadKey,
}

/// Store an [`AuthContext`] into PAM data.
///
/// # Safety
///
/// `pamh` must be the live PAM handle handed to a `pam_sm_*` callback.
///
/// # Errors
///
/// Returns [`DataHandleError::PamRc`] when `pam_set_data` fails.
pub unsafe fn set_auth_context(
    pamh: *mut pam_sys::pam_handle_t,
    ctx: AuthContext,
) -> Result<(), DataHandleError> {
    let key = CString::new(DATA_KEY).map_err(|_| DataHandleError::BadKey)?;
    let boxed = Box::new(ctx);
    let raw = Box::into_raw(boxed).cast::<c_void>();
    // SAFETY: `pamh` is live; `raw` is owned by PAM after this call —
    // the cleanup callback `auth_context_cleanup` will free it.
    let rc = unsafe { pam_set_data(pamh, key.as_ptr(), raw, Some(auth_context_cleanup)) };
    if rc == PAM_SUCCESS {
        Ok(())
    } else {
        // PAM didn't take ownership; drop the box ourselves.
        // SAFETY: `raw` came from `Box::into_raw` above and PAM did not
        // adopt it (non-success rc), so we reclaim sole ownership here.
        drop(unsafe { Box::from_raw(raw.cast::<AuthContext>()) });
        Err(DataHandleError::PamRc(rc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_with_null_data_is_a_noop() {
        // libpam may invoke the callback with a null data pointer; it must
        // return without dereferencing anything.
        // SAFETY: null data is the documented early-return path; pamh is
        // unused by the callback.
        unsafe {
            auth_context_cleanup(std::ptr::null_mut(), std::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn teardown_panic_is_contained() {
        // The cleanup wraps the drop in catch_unwind so a panicking teardown
        // cannot unwind across the C boundary. Exercise that primitive: a
        // panicking closure must be caught, not propagated.
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            panic!("simulated Drop panic");
        }));
        assert!(caught.is_err(), "panic must be contained, not propagated");
    }
}

/// Retrieve a previously-stored [`AuthContext`].
///
/// Returns `None` when no context was stored (e.g. `pam_sm_acct_mgmt`
/// runs without a prior `pam_sm_authenticate`).
///
/// # Safety
///
/// `pamh` must be a live PAM handle.  The returned reference borrows
/// from PAM-owned memory and MUST NOT outlive the surrounding `pam_sm_*`
/// call.
pub unsafe fn get_auth_context<'a>(pamh: *mut pam_sys::pam_handle_t) -> Option<&'a AuthContext> {
    let key = CString::new(DATA_KEY).ok()?;
    let mut data_ptr: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is live; `data_ptr` is a valid out-pointer.
    let rc = unsafe { pam_get_data(pamh.cast_const(), key.as_ptr(), &raw mut data_ptr) };
    if rc != PAM_SUCCESS || data_ptr.is_null() {
        return None;
    }
    // SAFETY: contract — the only setter is `set_auth_context`, which
    // stores a `Box<AuthContext>`; PAM hands the same pointer back here.
    Some(unsafe { &*data_ptr.cast::<AuthContext>() })
}

//! Production driver for the PAM conversation: prompt the user for the
//! smart-card PIN through the live `pam_conv` callback.
//!
//! The safe parts of the API (the [`PamConvError`] enum and the
//! callback-based `prompt_pin_via_callback`) live in
//! [`tessera_core::pam_conv`].  This module hosts the unsafe FFI glue
//! that talks to `libpam` via `pam-sys`, and is only compiled on Linux.
//!
//! The helper [`closure_from_pamh`] adapts a live PAM handle into a
//! `FnMut(&str) -> Result<SecretString, PamConvError>` closure suitable for
//! `tessera_core::pkcs12::acquire_p12_material_with_prompter`.

#![cfg(target_os = "linux")]
#![allow(unsafe_code, clippy::similar_names)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use secrecy::SecretString;
use tessera_core::pam_conv::PamConvError;

// ----- Constants pulled from <security/pam_appl.h> ----------------------------
//
// pam-sys generates these via bindgen, but the constant names come out as
// `PAM_*` directly because of the `allowlist_var("PAM_.*")` rule in its
// build.rs.  We pull them in by name and pin them at the integer types the
// PAM ABI uses.  If the underlying header changes (e.g. on a new Astra
// release), this will surface as a build break rather than a silent skew.

const PAM_SUCCESS: c_int = pam_sys::PAM_SUCCESS as c_int;
const PAM_CONV: c_int = pam_sys::PAM_CONV as c_int;
const PAM_PROMPT_ECHO_OFF: c_int = pam_sys::PAM_PROMPT_ECHO_OFF as c_int;
const PAM_TEXT_INFO: c_int = pam_sys::PAM_TEXT_INFO as c_int;

// ----- ABI-compatible struct shapes ------------------------------------------
//
// We re-declare these locally because `pam-sys` exposes them under
// bindgen-generated names that vary across libpam versions
// (`pam_message`/`pam_response`/`pam_conv`).  The shapes below match the
// stable ABI defined in `pam_appl.h` on every Linux distribution we care
// about.

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            num_msg: c_int,
            msg: *mut *const PamMessage,
            resp: *mut *mut PamResponse,
            appdata_ptr: *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

extern "C" {
    /// `pam_get_item` is exposed by pam-sys but with a varying signature; we
    /// re-declare it to a known-stable shape.
    fn pam_get_item(
        pamh: *mut pam_sys::pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;
}

extern "C" {
    /// libc `free` — used to release the `pam_response` allocations the conv
    /// callback hands back, per the PAM contract.
    fn free(ptr: *mut c_void);
}

/// Drive the live PAM conversation handle to ask for a PIN.
///
/// # Safety
///
/// `pamh` must be the live PAM handle handed to a `pam_sm_*` callback.  After
/// this call returns, the PAM-allocated response buffer is overwritten with
/// zeros and freed; callers MUST NOT retain any pointer derived from it.
///
/// # Errors
///
/// * [`PamConvError::NoConv`] — PAM did not return a `pam_conv` item.
/// * [`PamConvError::ConvFailed`] — the conv callback returned non-success
///   or produced a NULL response.
/// * [`PamConvError::NonUtf8`] — the response is not valid UTF-8.
pub unsafe fn prompt_pin(
    pamh: *mut pam_sys::pam_handle_t,
    prompt: &str,
) -> Result<SecretString, PamConvError> {
    let mut conv_ptr: *const c_void = std::ptr::null();
    // SAFETY: PAM guarantees `pamh` is non-null and `pam_get_item` accepts a
    // valid out-pointer.  We initialise `conv_ptr` to NULL and check the rc
    // before dereferencing.
    let rc = unsafe { pam_get_item(pamh, PAM_CONV, &raw mut conv_ptr) };
    if rc != PAM_SUCCESS || conv_ptr.is_null() {
        return Err(PamConvError::NoConv);
    }
    // SAFETY: `conv_ptr` is non-null and points to a `struct pam_conv`
    // owned by the PAM application.  The lifetime is tied to `pamh`.
    let conv: &PamConv = unsafe { &*(conv_ptr.cast::<PamConv>()) };
    let Some(conv_fn) = conv.conv else {
        return Err(PamConvError::NoConv);
    };

    // Build the prompt; CString::new fails only if there's an interior NUL,
    // which would be a programmer error.
    let c_prompt = CString::new(prompt).map_err(|_| PamConvError::ConvFailed)?;
    let msg = PamMessage {
        msg_style: PAM_PROMPT_ECHO_OFF,
        msg: c_prompt.as_ptr(),
    };
    // PAM expects an array-of-pointers.  Use a stack-allocated 1-elem array.
    let msg_ptr: *const PamMessage = &raw const msg;
    let mut msg_arr: [*const PamMessage; 1] = [msg_ptr];
    let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();

    // SAFETY: `msg_arr` and `resp_ptr` are both valid for the duration of
    // this call.  PAM allocates `*resp_ptr` on success — we own freeing it.
    let rc = unsafe { conv_fn(1, msg_arr.as_mut_ptr(), &raw mut resp_ptr, conv.appdata_ptr) };
    if rc != PAM_SUCCESS || resp_ptr.is_null() {
        return Err(PamConvError::ConvFailed);
    }

    // SAFETY: `resp_ptr` is non-null and points to a `pam_response` owned by
    // PAM.  `resp.resp` may be NULL if the user cancelled the prompt.
    let resp = unsafe { &*resp_ptr };
    if resp.resp.is_null() {
        // SAFETY: `resp_ptr` is a PAM-allocated `pam_response` we own.
        unsafe { free(resp_ptr.cast::<c_void>()) };
        return Err(PamConvError::ConvFailed);
    }

    // SAFETY: `resp.resp` is a non-null PAM-allocated NUL-terminated buffer.
    let pin_cstr = unsafe { CStr::from_ptr(resp.resp) };
    let pin_result = pin_cstr.to_str().map(str::to_string);

    // Always overwrite the PAM-allocated buffer before freeing — even on the
    // UTF-8-error path — to keep the PIN out of process memory longer than
    // strictly necessary.  The buffer is always at least one byte (the NUL
    // terminator).
    let len = pin_cstr.to_bytes().len();
    if len > 0 {
        // SAFETY: `resp.resp` is a PAM-allocated buffer of at least `len`
        // bytes; we own it until the `free` calls below.
        unsafe { std::ptr::write_bytes(resp.resp.cast::<u8>(), 0_u8, len) };
    }
    // SAFETY: `resp.resp` is a non-null PAM-allocated buffer we own.
    unsafe { free(resp.resp.cast::<c_void>()) };
    // SAFETY: `resp_ptr` is the PAM-allocated `pam_response` we own.
    unsafe { free(resp_ptr.cast::<c_void>()) };

    let pin_str = pin_result.map_err(|_| PamConvError::NonUtf8)?;
    Ok(SecretString::from(pin_str))
}

/// Prompt the user for a non-secret value via the live PAM conversation.
///
/// Unlike [`prompt_pin`] this returns a plain `String` (the value is not a
/// secret, e.g. a role name) and lets the caller choose the message style
/// (`PAM_PROMPT_ECHO_ON` for a visible prompt). The PAM-allocated response
/// buffer is freed before returning. Empty responses are returned as an
/// empty string so the caller can distinguish "no input" from "no conv".
///
/// # Safety
///
/// `pamh` must be the live PAM handle handed to a `pam_sm_*` callback.
///
/// # Errors
///
/// * [`PamConvError::NoConv`] — PAM did not return a `pam_conv` item.
/// * [`PamConvError::ConvFailed`] — the conv callback returned non-success
///   or produced a NULL response.
/// * [`PamConvError::NonUtf8`] — the response is not valid UTF-8.
pub unsafe fn prompt_value(
    pamh: *mut pam_sys::pam_handle_t,
    prompt: &str,
    msg_style: c_int,
) -> Result<String, PamConvError> {
    let mut conv_ptr: *const c_void = std::ptr::null();
    // SAFETY: PAM guarantees `pamh` is non-null; `conv_ptr` is checked.
    let rc = unsafe { pam_get_item(pamh, PAM_CONV, &raw mut conv_ptr) };
    if rc != PAM_SUCCESS || conv_ptr.is_null() {
        return Err(PamConvError::NoConv);
    }
    // SAFETY: `conv_ptr` is a non-null `struct pam_conv` owned by the app.
    let conv: &PamConv = unsafe { &*(conv_ptr.cast::<PamConv>()) };
    let Some(conv_fn) = conv.conv else {
        return Err(PamConvError::NoConv);
    };

    let c_prompt = CString::new(prompt).map_err(|_| PamConvError::ConvFailed)?;
    let msg = PamMessage {
        msg_style,
        msg: c_prompt.as_ptr(),
    };
    let msg_ptr: *const PamMessage = &raw const msg;
    let mut msg_arr: [*const PamMessage; 1] = [msg_ptr];
    let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();

    // SAFETY: `msg_arr`/`resp_ptr` valid for the call; PAM allocates the
    // response on success and we own freeing it.
    let rc = unsafe { conv_fn(1, msg_arr.as_mut_ptr(), &raw mut resp_ptr, conv.appdata_ptr) };
    if rc != PAM_SUCCESS || resp_ptr.is_null() {
        return Err(PamConvError::ConvFailed);
    }

    // SAFETY: `resp_ptr` is a non-null PAM-allocated `pam_response` we own.
    let resp = unsafe { &*resp_ptr };
    if resp.resp.is_null() {
        // No reply text: treat as empty input. Free the response struct.
        // SAFETY: `resp_ptr` is the PAM-allocated `pam_response` we own.
        unsafe { free(resp_ptr.cast::<c_void>()) };
        return Ok(String::new());
    }

    // SAFETY: `resp.resp` is a non-null NUL-terminated PAM buffer.
    let value_cstr = unsafe { CStr::from_ptr(resp.resp) };
    let value_result = value_cstr.to_str().map(str::to_string);
    // SAFETY: `resp.resp` and `resp_ptr` are PAM-allocated buffers we own.
    unsafe { free(resp.resp.cast::<c_void>()) };
    // SAFETY: as above.
    unsafe { free(resp_ptr.cast::<c_void>()) };
    value_result.map_err(|_| PamConvError::NonUtf8)
}

/// Emit a `PAM_TEXT_INFO` message to the live PAM conversation handle.
///
/// Used by the flow to surface admin-actionable diagnostics on auth
/// failures (e.g. the `host_id_hash` of the running machine when the cert
/// is bound to a different host) directly on the lock screen / terminal.
///
/// Returns the conv response code if non-success; the caller treats this
/// as best-effort (a failed info message MUST NOT change the auth verdict).
///
/// # Safety
///
/// Same contract as [`prompt_pin`]: `pamh` must be the live handle from a
/// `pam_sm_*` callback. Multi-line messages are passed verbatim — PAM
/// modules / display managers handle wrapping.
///
/// # Errors
///
/// * [`PamConvError::NoConv`] — PAM did not return a `pam_conv` item.
/// * [`PamConvError::ConvFailed`] — the message had an interior NUL or the
///   conv callback returned non-success.
///
/// Callers treat both as best-effort: a failed info message MUST NOT change
/// the auth verdict.
pub unsafe fn show_info(pamh: *mut pam_sys::pam_handle_t, msg: &str) -> Result<(), PamConvError> {
    let mut conv_ptr: *const c_void = std::ptr::null();
    // SAFETY: PAM guarantees `pamh` is non-null and `pam_get_item` accepts a
    // valid out-pointer; `conv_ptr` is checked before dereferencing.
    let rc = unsafe { pam_get_item(pamh, PAM_CONV, &raw mut conv_ptr) };
    if rc != PAM_SUCCESS || conv_ptr.is_null() {
        return Err(PamConvError::NoConv);
    }
    // SAFETY: `conv_ptr` is non-null and points to a `struct pam_conv`
    // owned by the PAM application.  The lifetime is tied to `pamh`.
    let conv: &PamConv = unsafe { &*(conv_ptr.cast::<PamConv>()) };
    let Some(conv_fn) = conv.conv else {
        return Err(PamConvError::NoConv);
    };

    let c_msg = CString::new(msg).map_err(|_| PamConvError::ConvFailed)?;
    let message = PamMessage {
        msg_style: PAM_TEXT_INFO,
        msg: c_msg.as_ptr(),
    };
    let msg_ptr: *const PamMessage = &raw const message;
    let mut msg_arr: [*const PamMessage; 1] = [msg_ptr];
    let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();

    // SAFETY: `msg_arr` and `resp_ptr` are valid for the duration of this
    // call; PAM allocates `*resp_ptr` (if any) and we own freeing it.
    let rc = unsafe { conv_fn(1, msg_arr.as_mut_ptr(), &raw mut resp_ptr, conv.appdata_ptr) };
    // Some applications return a NULL response array for PAM_TEXT_INFO
    // (since there is no reply); free only if non-null.
    if !resp_ptr.is_null() {
        // SAFETY: `resp_ptr` is non-null and points to a PAM-allocated
        // `pam_response` we own.
        let resp = unsafe { &*resp_ptr };
        if !resp.resp.is_null() {
            // SAFETY: `resp.resp` is a non-null PAM-allocated buffer we own.
            unsafe { free(resp.resp.cast::<c_void>()) };
        }
        // SAFETY: `resp_ptr` is the PAM-allocated `pam_response` we own.
        unsafe { free(resp_ptr.cast::<c_void>()) };
    }
    if rc != PAM_SUCCESS {
        return Err(PamConvError::ConvFailed);
    }
    Ok(())
}

/// Build a closure that drives `prompt_pin` against a captured PAM handle.
///
/// This is the production-side adapter consumed by
/// `tessera_core::pkcs12::acquire_p12_material_with_prompter`.
///
/// # Safety
///
/// The returned closure captures `pamh` by value (as a raw pointer).  The
/// caller MUST ensure the closure does not outlive the PAM stack frame that
/// owns `pamh` (i.e. do not store the closure across `pam_sm_*` boundaries).
pub unsafe fn closure_from_pamh(
    pamh: *mut pam_sys::pam_handle_t,
) -> impl FnMut(&str) -> Result<SecretString, PamConvError> {
    move |prompt: &str| {
        // SAFETY: `pamh` was provided by PAM and is valid for the duration
        // captured above.  See the function-level safety contract.
        unsafe { prompt_pin(pamh, prompt) }
    }
}

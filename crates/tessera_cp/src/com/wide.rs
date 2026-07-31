//! COM-allocated strings and buffers.
//!
//! Every string and buffer this provider hands to `LogonUI` is freed by `LogonUI`
//! with `CoTaskMemFree`, so it must be allocated with `CoTaskMemAlloc` and not
//! by the Rust allocator. These helpers are the only place that happens.
#![allow(unsafe_code)]

use std::ptr;

use windows::core::{Error, Result as WinResult, PWSTR};
use windows::Win32::Foundation::E_OUTOFMEMORY;
use windows::Win32::System::Com::CoTaskMemAlloc;

/// Copies a string into a COM-allocated, NUL-terminated UTF-16 buffer.
///
/// Ownership passes to the caller of the COM method: `LogonUI` frees it.
///
/// # Errors
///
/// `E_OUTOFMEMORY` when the allocation fails.
pub fn alloc_pwstr(value: &str) -> WinResult<PWSTR> {
    let units: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = units.len() * size_of::<u16>();

    // SAFETY: `CoTaskMemAlloc` is safe to call with any size; the result is
    // checked for null before it is used.
    let raw = unsafe { CoTaskMemAlloc(bytes) };
    if raw.is_null() {
        return Err(Error::from_hresult(E_OUTOFMEMORY));
    }

    // SAFETY: `raw` points at `bytes` freshly allocated, writable, unaliased
    // bytes, and `units` holds exactly that many bytes in a separate
    // allocation, so source and destination cannot overlap.
    unsafe { ptr::copy_nonoverlapping(units.as_ptr(), raw.cast::<u16>(), units.len()) };

    Ok(PWSTR(raw.cast()))
}

/// Copies a byte block into COM-allocated memory.
///
/// Used for the serialized credentials. The source is wiped by its own
/// `Zeroizing` wrapper; the copy handed over lives until `LogonUI` frees it,
/// which is the shortest lifetime the interface allows.
///
/// # Errors
///
/// `E_OUTOFMEMORY` when the allocation fails.
pub fn alloc_bytes(value: &[u8]) -> WinResult<*mut u8> {
    // SAFETY: `CoTaskMemAlloc` is safe to call with any size; the result is
    // checked for null before it is used.
    let raw = unsafe { CoTaskMemAlloc(value.len()) };
    if raw.is_null() {
        return Err(Error::from_hresult(E_OUTOFMEMORY));
    }

    // SAFETY: `raw` points at `value.len()` freshly allocated, writable,
    // unaliased bytes in an allocation distinct from `value`.
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), raw.cast::<u8>(), value.len()) };

    Ok(raw.cast())
}

/// Reads a NUL-terminated wide string `LogonUI` passed in.
///
/// # Safety
///
/// `raw` must be null or point at a NUL-terminated UTF-16 string that stays
/// valid for the duration of the call — the contract every `PCWSTR` in-parameter
/// of the credential-provider interfaces already carries.
#[must_use]
pub unsafe fn read_pcwstr(raw: windows::core::PCWSTR) -> String {
    if raw.is_null() {
        return String::new();
    }
    // SAFETY: delegated to the caller by this function's own contract; `PCWSTR`
    // knows how to walk to its terminator.
    unsafe { raw.to_string() }.unwrap_or_default()
}

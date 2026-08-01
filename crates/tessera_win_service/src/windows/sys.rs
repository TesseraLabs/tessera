//! Shared Win32 plumbing: error reporting, string encoding, owned handles.
//!
//! # Unsafe
//!
//! Raw calls are unavoidable here — this is the layer that makes them — and the
//! rest of the crate stays under `unsafe_code = "deny"` because of it. Every
//! block below wraps a single call whose arguments are constructed a line or
//! two above it, and the owned wrappers exist so that no other module has to
//! remember which handle needs which release function.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
};

/// A failed Win32 call.
#[derive(Debug, thiserror::Error)]
#[error("{operation} failed: {code} ({detail})")]
pub struct WinError {
    /// The API that failed, as a bare name.
    pub operation: &'static str,
    /// The value `GetLastError` (or the API's own return) reported.
    pub code: u32,
    /// The system's own description of that code.
    pub detail: String,
}

impl WinError {
    /// A failure of `operation` carrying `code`.
    #[must_use]
    pub fn new(operation: &'static str, code: u32) -> Self {
        let detail = i32::try_from(code).map_or_else(
            |_| "unknown error".to_owned(),
            |raw| std::io::Error::from_raw_os_error(raw).to_string(),
        );
        Self {
            operation,
            code,
            detail,
        }
    }

    /// A failure of `operation` carrying the thread's last error.
    #[must_use]
    pub fn last(operation: &'static str) -> Self {
        Self::new(operation, last_error())
    }
}

/// The calling thread's last error code.
#[must_use]
pub fn last_error() -> u32 {
    // SAFETY: the call reads thread-local state and takes no arguments.
    unsafe { GetLastError() }
}

/// A NUL-terminated UTF-16 copy of `text`.
#[must_use]
pub fn wide(text: &str) -> Vec<u16> {
    let mut buf: Vec<u16> = text.encode_utf16().collect();
    buf.push(0);
    buf
}

/// A NUL-terminated UTF-16 copy of `path`.
#[must_use]
pub fn wide_path(path: &Path) -> Vec<u16> {
    let mut buf: Vec<u16> = path.as_os_str().encode_wide().collect();
    buf.push(0);
    buf
}

/// A kernel handle closed when dropped.
#[derive(Debug)]
pub struct Handle(HANDLE);

impl Handle {
    /// Adopts `raw`, refusing the two values the API uses for "no handle".
    ///
    /// # Errors
    ///
    /// [`WinError`] naming `operation`, carrying the thread's last error, when
    /// `raw` is null or `INVALID_HANDLE_VALUE`.
    pub fn adopt(raw: HANDLE, operation: &'static str) -> Result<Self, WinError> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(WinError::last(operation));
        }
        Ok(Self(raw))
    }

    /// The wrapped handle. Borrowed, never closed by the caller.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.0
    }

    /// Gives up ownership without closing, for handing the handle to something
    /// that will close it (a [`std::fs::File`] built from it).
    #[must_use]
    pub fn into_raw(self) -> HANDLE {
        // `ManuallyDrop` rather than `mem::forget`: the intent is "this value's
        // destructor is now somebody else's business", and that is what the
        // wrapper says.
        let kept = std::mem::ManuallyDrop::new(self);
        kept.0
    }
}

// SAFETY: a Windows kernel handle is a process-wide value with no thread
// affinity — unlike the window and GDI handles that do have it, these may be
// used from, and closed on, any thread of the owning process. `Handle` owns its
// handle exclusively and closes it exactly once, so moving one to another
// thread moves the only owner with it. `Sync` is deliberately not claimed:
// sharing one handle between threads would mean concurrent operations on it,
// which is a different argument and one nothing here needs.
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.0` was checked to be a real handle at construction and
        // this is the only place it is released.
        let _closed = unsafe { CloseHandle(self.0) };
    }
}

/// A block allocated by a Win32 API that releases it with `LocalFree`.
#[derive(Debug)]
pub struct LocalBlock(*mut c_void);

impl LocalBlock {
    /// Adopts `raw`, refusing null.
    ///
    /// # Errors
    ///
    /// [`WinError`] naming `operation` when `raw` is null.
    pub fn adopt(raw: *mut c_void, operation: &'static str) -> Result<Self, WinError> {
        if raw.is_null() {
            return Err(WinError::last(operation));
        }
        Ok(Self(raw))
    }

    /// The wrapped pointer, valid for as long as this value lives.
    #[must_use]
    pub fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalBlock {
    fn drop(&mut self) {
        // SAFETY: the pointer came from an API documented to release with
        // `LocalFree`, and this is the only place it is released.
        let _freed = unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
    }
}

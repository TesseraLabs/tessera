//! Isolated FFI shim around the OpenSSL `ENGINE_*` API used to load and
//! pin the `gost-engine` shared library.
//!
//! All raw FFI lives here; the rest of the crate stays under
//! `#![deny(unsafe_code)]`.  The only `unsafe` blocks are wrapped by the
//! safe types and free functions exposed at the bottom of the module.
//!
//! # Linkage
//!
//! `openssl-sys` already pulls libcrypto into the link-line.  The
//! `ENGINE_*` symbols are a stable part of libcrypto for both OpenSSL
//! 1.1.x and 3.x (the API is "deprecated since 3.0" but still exported
//! unless libcrypto was built with `OPENSSL_NO_DEPRECATED_3_0`, which is
//! not the case for distro builds nor Homebrew's `openssl@3`).
//!
//! `openssl-sys 0.9` exposes the opaque `ENGINE` type but does **not**
//! re-declare any ENGINE_* extern functions, so we declare them locally.
//! `EVP_get_digestbyname` is re-used directly from `openssl_sys`.
//!
//! # Concurrency
//!
//! libcrypto's ENGINE table is process-global mutable state.  All
//! load/finish operations are serialised through [`LOAD_MUTEX`] so that
//! two threads racing through `EngineHandle::by_id` cannot drive
//! libcrypto into an undefined state.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::Mutex;

use libc::{c_int, c_uint};
use openssl_sys::ENGINE;

use super::errors::GostEngineError;

// ---------------------------------------------------------------------
// Raw FFI declarations.
// ---------------------------------------------------------------------
//
// These are not re-exported by `openssl-sys 0.9.x` but are unconditionally
// present in libcrypto for both 1.1.x and 3.x distributions we target.
//
// SAFETY: each function below is declared with the exact prototype from
// `<openssl/engine.h>`.  Mismatching the prototype would be UB; the
// declarations have been cross-checked against
// https://www.openssl.org/docs/man3.0/man3/ENGINE_by_id.html
// and `openssl/engine.h` headers shipping with 1.1.1 and 3.x.
extern "C" {
    fn ENGINE_load_builtin_engines();
    fn ENGINE_by_id(id: *const libc::c_char) -> *mut ENGINE;
    fn ENGINE_init(e: *mut ENGINE) -> c_int;
    fn ENGINE_finish(e: *mut ENGINE) -> c_int;
    fn ENGINE_free(e: *mut ENGINE) -> c_int;
    fn ENGINE_set_default(e: *mut ENGINE, flags: c_uint) -> c_int;
    fn ENGINE_ctrl_cmd_string(
        e: *mut ENGINE,
        cmd_name: *const libc::c_char,
        arg: *const libc::c_char,
        cmd_optional: c_int,
    ) -> c_int;
}

/// `ENGINE_METHOD_ALL` — pin the engine as the default provider for every
/// algorithm class it supports.  Mirrors the constant in `openssl/engine.h`.
const ENGINE_METHOD_ALL: c_uint = 0xFFFF;

/// Serialises ENGINE_* operations across threads.  libcrypto's ENGINE
/// table is global mutable state and not internally synchronised against
/// the patterns we use (load + register + set-default).
static LOAD_MUTEX: Mutex<()> = Mutex::new(());

/// Owned handle to a libcrypto `ENGINE*`.
///
/// On creation the engine has been `ENGINE_init`'d; on `Drop` the handle
/// will run `ENGINE_finish` and `ENGINE_free` to release its share.
pub(crate) struct EngineHandle {
    raw: NonNull<ENGINE>,
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineHandle")
            .field("raw", &self.raw.as_ptr())
            .finish()
    }
}

// SAFETY: `ENGINE*` is documented to be safe to share across threads
// once initialised; libcrypto manages the reference count internally.
// All mutation (load, set_default) is funnelled through `LOAD_MUTEX`.
unsafe impl Send for EngineHandle {}
// SAFETY: same as `Send` — methods on `&EngineHandle` either read the
// pointer (for FFI calls that take `*mut ENGINE` but are documented to
// be safe to call concurrently after init) or are themselves serialised.
unsafe impl Sync for EngineHandle {}

impl EngineHandle {
    /// Look the engine up by ID via libcrypto's standard search path.
    ///
    /// This calls `ENGINE_load_builtin_engines` first (idempotent inside
    /// libcrypto) and then `ENGINE_by_id`.  If the engine is found it is
    /// `ENGINE_init`'d; otherwise an `Err(NotAvailable)` is returned.
    ///
    /// # Errors
    ///
    /// * [`GostEngineError::NotAvailable`] — `ENGINE_by_id` returned NULL.
    /// * [`GostEngineError::LoadFailed`] — `ENGINE_init` returned 0.
    pub(crate) fn by_id(id: &str) -> Result<Self, GostEngineError> {
        let id_c = CString::new(id).map_err(|e| {
            GostEngineError::NotAvailable(format!("engine id contains NUL byte: {e}"))
        })?;

        let _guard = LOAD_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // SAFETY: idempotent libcrypto initialiser; safe to call from any
        // thread, repeatedly, with no preconditions.
        unsafe {
            ENGINE_load_builtin_engines();
        }

        // SAFETY: `id_c.as_ptr()` is a NUL-terminated C string valid for
        // the duration of the call.  `ENGINE_by_id` returns either a
        // valid `*mut ENGINE` (with one reference for us) or NULL.
        let raw = unsafe { ENGINE_by_id(id_c.as_ptr()) };
        let Some(raw) = NonNull::new(raw) else {
            return Err(GostEngineError::NotAvailable(format!(
                "ENGINE_by_id({id:?}) returned NULL — engine not registered \
                 (check OPENSSL_ENGINES and that the .so is installed)"
            )));
        };

        // SAFETY: `raw` is a valid `*mut ENGINE` returned by libcrypto
        // and the LOAD_MUTEX is held; `ENGINE_init` increments the
        // structural reference count.
        let init_rc = unsafe { ENGINE_init(raw.as_ptr()) };
        if init_rc != 1 {
            // Drop the structural reference we got from ENGINE_by_id.
            // SAFETY: `raw` is a valid pointer we own a reference to.
            unsafe {
                let _ = ENGINE_free(raw.as_ptr());
            }
            return Err(GostEngineError::LoadFailed(format!(
                "ENGINE_init({id:?}) returned {init_rc}"
            )));
        }

        Ok(Self { raw })
    }

    /// Load an engine via libcrypto's `dynamic` loader.
    ///
    /// Equivalent to the OpenSSL config snippet:
    /// ```ignore
    /// dynamic_path = /usr/lib/.../gost.so
    /// engine_id = gost
    /// init = 1
    /// ```
    ///
    /// # Errors
    ///
    /// * [`GostEngineError::PathMissing`] — `path` does not exist.
    /// * [`GostEngineError::NotAvailable`] — the `dynamic` engine itself
    ///   could not be located (libcrypto was built without ENGINE
    ///   support).
    /// * [`GostEngineError::LoadFailed`] — any of the `SO_PATH` / `ID` /
    ///   `LOAD` commands failed, or `ENGINE_init` returned 0.
    pub(crate) fn load_dynamic(path: &Path, engine_id: &str) -> Result<Self, GostEngineError> {
        if !path.exists() {
            return Err(GostEngineError::PathMissing(path.to_path_buf()));
        }

        let path_str = path.to_str().ok_or_else(|| {
            GostEngineError::LoadFailed(format!(
                "engine path is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        let path_c = CString::new(path_str).map_err(|e| {
            GostEngineError::LoadFailed(format!("engine path contains NUL byte: {e}"))
        })?;
        let id_c = CString::new(engine_id).map_err(|e| {
            GostEngineError::LoadFailed(format!("engine id contains NUL byte: {e}"))
        })?;
        let dynamic_c = CString::new("dynamic").map_err(|e| {
            GostEngineError::LoadFailed(format!("'dynamic' literal failed CString conv: {e}"))
        })?;
        let so_path_cmd = CString::new("SO_PATH").map_err(|e| {
            GostEngineError::LoadFailed(format!("'SO_PATH' literal failed CString conv: {e}"))
        })?;
        let id_cmd = CString::new("ID").map_err(|e| {
            GostEngineError::LoadFailed(format!("'ID' literal failed CString conv: {e}"))
        })?;
        let load_cmd = CString::new("LOAD").map_err(|e| {
            GostEngineError::LoadFailed(format!("'LOAD' literal failed CString conv: {e}"))
        })?;

        let _guard = LOAD_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // SAFETY: idempotent.
        unsafe {
            ENGINE_load_builtin_engines();
        }

        // SAFETY: `dynamic_c` is a valid NUL-terminated string; the
        // returned pointer is either a valid ENGINE handle or NULL.
        let raw = unsafe { ENGINE_by_id(dynamic_c.as_ptr()) };
        let Some(raw) = NonNull::new(raw) else {
            return Err(GostEngineError::NotAvailable(
                "libcrypto has no `dynamic` engine — built without ENGINE support".to_string(),
            ));
        };

        // Helper: run an ENGINE_ctrl_cmd_string and convert non-1 return
        // into LoadFailed.  We close over `raw` and `_guard` by reference;
        // any failure must drop the engine before returning.
        //
        // SAFETY: every pointer passed to `ENGINE_ctrl_cmd_string` below
        // is a valid NUL-terminated string from a `CString` whose lifetime
        // outlives the call; `raw` is a valid ENGINE handle we hold a
        // reference to.
        let cmd_results = unsafe {
            let r1 = ENGINE_ctrl_cmd_string(raw.as_ptr(), so_path_cmd.as_ptr(), path_c.as_ptr(), 0);
            let r2 = if r1 == 1 {
                ENGINE_ctrl_cmd_string(raw.as_ptr(), id_cmd.as_ptr(), id_c.as_ptr(), 0)
            } else {
                0
            };
            let r3 = if r2 == 1 {
                ENGINE_ctrl_cmd_string(raw.as_ptr(), load_cmd.as_ptr(), std::ptr::null(), 0)
            } else {
                0
            };
            (r1, r2, r3)
        };

        if cmd_results != (1, 1, 1) {
            // SAFETY: `raw` is owned, drop the structural reference.
            unsafe {
                let _ = ENGINE_free(raw.as_ptr());
            }
            return Err(GostEngineError::LoadFailed(format!(
                "ENGINE_ctrl_cmd_string sequence (SO_PATH={}, ID={}, LOAD={}) failed for {}",
                cmd_results.0,
                cmd_results.1,
                cmd_results.2,
                path.display()
            )));
        }

        // SAFETY: `raw` is a valid ENGINE handle, post-LOAD.
        let init_rc = unsafe { ENGINE_init(raw.as_ptr()) };
        if init_rc != 1 {
            // SAFETY: `raw` is owned; release reference.
            unsafe {
                let _ = ENGINE_free(raw.as_ptr());
            }
            return Err(GostEngineError::LoadFailed(format!(
                "ENGINE_init after LOAD returned {init_rc} for {}",
                path.display()
            )));
        }

        Ok(Self { raw })
    }

    /// Pin this engine as the default provider for every algorithm class.
    ///
    /// # Errors
    ///
    /// [`GostEngineError::SetDefaultFailed`] if libcrypto refuses.
    pub(crate) fn set_default_all(&self) -> Result<(), GostEngineError> {
        let _guard = LOAD_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // SAFETY: `self.raw` is a valid ENGINE handle held by `self`;
        // `ENGINE_set_default` reads the engine's method tables and
        // registers them in libcrypto's defaults table.
        let rc = unsafe { ENGINE_set_default(self.raw.as_ptr(), ENGINE_METHOD_ALL) };
        if rc == 1 {
            Ok(())
        } else {
            Err(GostEngineError::SetDefaultFailed(format!(
                "ENGINE_set_default returned {rc}"
            )))
        }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        // Drop never panics: we ignore the rc and any poisoning of the
        // mutex.
        let _guard = LOAD_MUTEX.lock();

        // SAFETY: `self.raw` is a valid ENGINE handle that we initialised;
        // the matching pair of (`ENGINE_finish`, `ENGINE_free`) releases
        // the functional and structural references taken in the
        // constructors.
        unsafe {
            let _ = ENGINE_finish(self.raw.as_ptr());
            let _ = ENGINE_free(self.raw.as_ptr());
        }
    }
}

/// Returns `true` if libcrypto can resolve a digest with the given name
/// via `EVP_get_digestbyname`.
///
/// Free function (not a method) because the digest table is global —
/// after any engine registers a digest, every thread can look it up via
/// the global table.  We intentionally do not require a borrow of an
/// `EngineHandle` here so callers can probe for digest availability
/// without keeping the handle alive in an awkward scope.
#[must_use]
pub(crate) fn digest_available(name: &str) -> bool {
    let Ok(name_c) = CString::new(name) else {
        return false;
    };
    // SAFETY: `name_c.as_ptr()` is a valid NUL-terminated C string
    // valid for the duration of the call.  `EVP_get_digestbyname` is
    // a pure lookup that returns either a valid pointer to a static
    // EVP_MD owned by libcrypto, or NULL.
    let md = unsafe { openssl_sys::EVP_get_digestbyname(name_c.as_ptr()) };
    !md.is_null()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn by_id_returns_not_available_for_unknown_engine() {
        // A name almost certainly not registered on any host.
        let res = EngineHandle::by_id("nonexistent_engine_zzzqwx");
        assert!(
            matches!(res, Err(GostEngineError::NotAvailable(_))),
            "expected NotAvailable, got {res:?}",
        );
    }

    #[test]
    fn by_id_rejects_nul_bytes() {
        let res = EngineHandle::by_id("bad\0engine");
        assert!(matches!(res, Err(GostEngineError::NotAvailable(_))));
    }

    #[test]
    fn load_dynamic_returns_path_missing_for_nonexistent_path() {
        let res = EngineHandle::load_dynamic(Path::new("/dev/null/nope.so"), "gost");
        assert!(
            matches!(
                res,
                Err(GostEngineError::PathMissing(_) | GostEngineError::LoadFailed(_)),
            ),
            "expected PathMissing or LoadFailed, got {res:?}",
        );
    }

    #[test]
    fn digest_available_returns_false_for_unknown_digest() {
        assert!(!digest_available("zzz_definitely_not_a_digest"));
    }

    #[test]
    fn digest_available_returns_true_for_builtin_sha256() {
        // SHA-256 is registered by libcrypto unconditionally.
        assert!(digest_available("SHA256"));
    }

    #[test]
    fn digest_available_handles_nul_byte() {
        assert!(!digest_available("bad\0name"));
    }
}

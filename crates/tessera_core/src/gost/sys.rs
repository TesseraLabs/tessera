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

use std::ffi::{c_char, c_int, c_uint, CStr, CString};
use std::path::Path;
use std::ptr::NonNull;
use std::sync::Mutex;

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
    fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;
    /// Returns a structural reference to the first engine in libcrypto's
    /// global registered-engine list, or NULL if the list is empty.
    /// Side-effect-free: unlike `ENGINE_by_id`, it never triggers the
    /// `dynamic` engine's search-path fallback.
    fn ENGINE_get_first() -> *mut ENGINE;
    /// Releases the structural reference to `e` and returns a new
    /// structural reference to the next engine in the global list, or
    /// NULL when `e` was the last entry (in which case `e`'s reference
    /// has still been released).
    fn ENGINE_get_next(e: *mut ENGINE) -> *mut ENGINE;
    /// Returns a pointer to the engine's id string, owned by the engine
    /// and valid for as long as the caller holds a reference to it.
    fn ENGINE_get_id(e: *const ENGINE) -> *const c_char;
    fn ENGINE_init(e: *mut ENGINE) -> c_int;
    fn ENGINE_finish(e: *mut ENGINE) -> c_int;
    fn ENGINE_free(e: *mut ENGINE) -> c_int;
    fn ENGINE_remove(e: *mut ENGINE) -> c_int;
    fn ENGINE_set_default(e: *mut ENGINE, flags: c_uint) -> c_int;
    fn ENGINE_ctrl_cmd_string(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        arg: *const c_char,
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

/// Clears any preexisting libcrypto registration under `id_c`, if one is
/// present, so that a subsequent explicit `SO_PATH`/`ID`/`LOAD` ctrl
/// sequence against the same id does not collide with it.
///
/// libcrypto refuses to register a second engine under an id that is
/// already taken, so the `LOAD` ctrl command in [`EngineHandle::load_dynamic`]
/// would otherwise fail (return 0) against a pre-existing registration.
///
/// We must never simply *adopt* whatever is already sitting under that
/// id — that could be an attacker-planted engine reachable via some
/// ambient config or engine search path, and tessera's whole point in
/// `load_dynamic` is to load explicitly and only from the specific,
/// root-controlled `path` the operator configured. So instead: if the
/// id is already taken, clear it — `ENGINE_remove` followed by
/// `ENGINE_free` to release the reference — freeing the slot, and let
/// the caller fall through to its own explicit, path-verified
/// `SO_PATH`/`ID`/`LOAD` sequence as if nothing had been registered.
/// This is best-effort: we ignore the return codes of `ENGINE_remove`/
/// `ENGINE_free` themselves, since the only goal is clearing the slot —
/// if it somehow doesn't clear, the caller's `LOAD` command fails
/// exactly as it did before this check existed, surfacing the existing
/// `LoadFailed` error as an acceptable fallback.
///
/// Deliberately NOT `ENGINE_by_id(id_c.as_ptr())` here: per OpenSSL's
/// documented behavior, when `id` is *not* already registered,
/// `ENGINE_by_id` itself falls back to configuring and invoking the
/// `dynamic` engine against the ambient engine search path /
/// `$OPENSSL_ENGINES` — i.e. the probe would `dlopen` and run the init
/// code of whatever `<id>.so` it finds there, which is exactly the
/// untrusted, non-operator-vetted path this whole mechanism exists to
/// avoid touching. Instead we walk libcrypto's global
/// registered-engine list directly via `ENGINE_get_first`/
/// `ENGINE_get_next` — a side-effect-free inspection of what is already
/// registered, with no dynamic-load fallback of its own — and compare
/// each entry's id via `ENGINE_get_id`.
fn clear_ambient_registration(id_c: &CStr) {
    let mut preexisting: Option<NonNull<ENGINE>> = None;
    // SAFETY: `ENGINE_get_first` returns either a valid `*mut ENGINE`
    // carrying a new structural reference for us, or NULL if the
    // global engine list is empty.
    let mut cursor = unsafe { ENGINE_get_first() };
    while let Some(cursor_nn) = NonNull::new(cursor) {
        // SAFETY: `cursor_nn` is a valid ENGINE pointer for which we
        // currently hold a live structural reference (from
        // `ENGINE_get_first`/`ENGINE_get_next` below); `ENGINE_get_id`
        // returns a pointer to a NUL-terminated string owned by the
        // engine, valid as long as we hold that reference.
        let id_ptr = unsafe { ENGINE_get_id(cursor_nn.as_ptr()) };
        let is_match = !id_ptr.is_null() && {
            // SAFETY: `id_ptr` was just checked non-null and is
            // NUL-terminated per the `ENGINE_get_id` contract.
            unsafe { CStr::from_ptr(id_ptr) }.to_bytes() == id_c.to_bytes()
        };
        if is_match {
            // Keep the structural reference we currently hold on
            // `cursor_nn` — do NOT call `ENGINE_get_next` again, as
            // that would release it.
            preexisting = Some(cursor_nn);
            break;
        }
        // SAFETY: `cursor_nn` is a valid ENGINE pointer with a live
        // structural reference; `ENGINE_get_next` releases that
        // reference and returns a new structural reference to the
        // next engine in the list, or NULL at the end (releasing
        // `cursor_nn`'s reference in that case too).
        cursor = unsafe { ENGINE_get_next(cursor_nn.as_ptr()) };
    }
    if let Some(preexisting) = preexisting {
        // SAFETY: `preexisting` is a valid ENGINE pointer for which
        // we hold a live structural reference from the list walk
        // above; `ENGINE_remove` takes it out of libcrypto's global
        // engine list so the id becomes free again.
        unsafe {
            let _ = ENGINE_remove(preexisting.as_ptr());
        }
        // SAFETY: `preexisting` is a valid ENGINE pointer; this
        // releases the structural reference obtained from the list
        // walk above (distinct from whatever reference(s) the
        // ambient registration itself may still be holding).
        unsafe {
            let _ = ENGINE_free(preexisting.as_ptr());
        }
    }
}

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

        // Some hosts already have *something* registered under
        // `engine_id` by the time we get here — e.g. Astra Linux's
        // system `/usr/lib/ssl/openssl.cnf` auto-registers a "gost"
        // engine via `openssl_conf`/`[engine_section]` as soon as any
        // process (including this one) initialises libcrypto with
        // default config loading, well before this function ever runs.
        // A prior in-process load under the same id would leave the
        // same kind of stale registration behind. See
        // `clear_ambient_registration`'s doc comment for why this must
        // be cleared rather than adopted, and for how it avoids
        // `ENGINE_by_id`'s dynamic-load fallback while doing so.
        clear_ambient_registration(&id_c);

        // Run the SO_PATH/ID/LOAD ctrl sequence, stopping at the first
        // non-1 return.  We close over `raw` and `_guard` by reference;
        // any failure must drop the engine before returning.  Each
        // ENGINE_ctrl_cmd_string call gets its own `unsafe` block.
        let cmd_results = {
            // SAFETY: `so_path_cmd`/`path_c` are valid NUL-terminated
            // strings from `CString`s outliving the call; `raw` is a valid
            // ENGINE handle we hold a reference to.
            let r1 = unsafe {
                ENGINE_ctrl_cmd_string(raw.as_ptr(), so_path_cmd.as_ptr(), path_c.as_ptr(), 0)
            };
            let r2 = if r1 == 1 {
                // SAFETY: `id_cmd`/`id_c` are valid NUL-terminated strings
                // from `CString`s outliving the call; `raw` is a valid
                // ENGINE handle we hold a reference to.
                unsafe { ENGINE_ctrl_cmd_string(raw.as_ptr(), id_cmd.as_ptr(), id_c.as_ptr(), 0) }
            } else {
                0
            };
            let r3 = if r2 == 1 {
                // SAFETY: `load_cmd` is a valid NUL-terminated string from a
                // `CString` outliving the call; the value argument is NULL
                // as the LOAD command expects; `raw` is a valid ENGINE
                // handle we hold a reference to.
                unsafe {
                    ENGINE_ctrl_cmd_string(raw.as_ptr(), load_cmd.as_ptr(), std::ptr::null(), 0)
                }
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

        // The matching pair of (`ENGINE_finish`, `ENGINE_free`) releases the
        // functional and structural references taken in the constructors;
        // each call gets its own `unsafe` block.
        //
        // SAFETY: `self.raw` is a valid ENGINE handle that we initialised;
        // `ENGINE_finish` releases the functional reference.
        unsafe {
            let _ = ENGINE_finish(self.raw.as_ptr());
        }
        // SAFETY: `self.raw` is a valid ENGINE handle; `ENGINE_free`
        // releases the structural reference taken in the constructor.
        unsafe {
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

    /// Finds a real, dynamically-loadable OpenSSL engine module on this
    /// host, paired with its own true engine id.
    ///
    /// Deliberately avoids `"gost"`/gost-engine paths: the `ID` ctrl
    /// command doesn't let a caller rename an engine module to an
    /// arbitrary id (it only selects *which* id inside the module to
    /// bind, and a mismatch makes `LOAD` fail), so the regression test
    /// below must use each module's own real id — and the crate's own
    /// `gost::engine` keeps a process-wide `OnceLock` keyed on `"gost"`
    /// that other unit tests in this same test binary rely on staying
    /// unavailable/consistent. Registering a real `"gost"` engine as a
    /// side effect of this test would leak into and race with those
    /// other tests. Non-GOST stock OpenSSL engine modules (e.g.
    /// `loader_attic`, shipped by Homebrew's `openssl@3` and by distro
    /// OpenSSL 3.x packages) are just as valid for exercising the
    /// generic id-collision-then-clear mechanism, which has nothing
    /// GOST-specific about it, without that risk.
    fn find_real_engine_module() -> Option<(std::path::PathBuf, &'static str)> {
        const CANDIDATES: &[(&str, &str)] = &[
            // Debian/Astra Linux OpenSSL 3.x stock engine modules.
            (
                "/usr/lib/x86_64-linux-gnu/engines-3/loader_attic.so",
                "loader_attic",
            ),
            ("/usr/lib/engines-3/loader_attic.so", "loader_attic"),
            ("/usr/lib/x86_64-linux-gnu/engines-3/afalg.so", "afalg"),
            // Homebrew on macOS dev hosts (Apple Silicon / Intel prefixes).
            (
                "/opt/homebrew/lib/engines-3/loader_attic.dylib",
                "loader_attic",
            ),
            (
                "/usr/local/lib/engines-3/loader_attic.dylib",
                "loader_attic",
            ),
        ];
        CANDIDATES
            .iter()
            .map(|(p, id)| (std::path::Path::new(p), *id))
            .find(|(p, _)| p.exists())
            .map(|(p, id)| (p.to_path_buf(), id))
    }

    /// Registers a *genuine*, persistent ambient engine registration
    /// under `id`, independent of `EngineHandle::load_dynamic` — this is
    /// what makes the regression test below actually exercise the
    /// id-collision path instead of a no-op.
    ///
    /// This replicates what a real ambient `openssl.cnf` `engine_id` /
    /// `init = 1` auto-load does: it drives the `dynamic` engine's raw
    /// ctrl sequence itself, but — unlike `EngineHandle::load_dynamic`,
    /// which only ever sends `SO_PATH`/`ID`/`LOAD` — it also sends
    /// `LIST_ADD=1` before `LOAD`. `LIST_ADD` is what makes the dynamic
    /// loader call `ENGINE_add()` internally as part of `LOAD`, which is
    /// the only thing that leaves a lasting entry in libcrypto's global
    /// registered-engine list under `id`. Without it (as production
    /// `load_dynamic` calls are), nothing persists globally and a second
    /// `load_dynamic` call never collides with anything — which is
    /// exactly why the original version of this test asserted nothing.
    ///
    /// Returns the structural reference this call itself holds on the
    /// loaded `dynamic` engine instance so the caller can release it;
    /// the separate reference `ENGINE_add` took for the global list is
    /// left in place, which is the genuine collision the test needs.
    fn register_ambient_engine(path: &Path, id: &str) {
        let dynamic_c = CString::new("dynamic").expect("no NUL byte");
        // SAFETY: `dynamic_c` is a valid NUL-terminated string; the
        // returned pointer is either a valid ENGINE handle (with a
        // structural reference for us) or NULL.
        let raw = unsafe { ENGINE_by_id(dynamic_c.as_ptr()) };
        let raw = NonNull::new(raw).expect("libcrypto must have the `dynamic` engine");

        let path_str = path.to_str().expect("test fixture paths are UTF-8");
        let path_c = CString::new(path_str).expect("no NUL byte");
        let id_c = CString::new(id).expect("no NUL byte");
        let so_path_cmd = CString::new("SO_PATH").expect("no NUL byte");
        let id_cmd = CString::new("ID").expect("no NUL byte");
        let list_add_cmd = CString::new("LIST_ADD").expect("no NUL byte");
        let list_add_val = CString::new("1").expect("no NUL byte");
        let load_cmd = CString::new("LOAD").expect("no NUL byte");

        // Each ctrl command configures the `dynamic` engine instance in
        // turn; `LOAD` performs the actual load and, because
        // `LIST_ADD=1` was set first, calls `ENGINE_add()` internally to
        // register the result globally under `id`.
        //
        // SAFETY: `so_path_cmd`/`path_c` are valid NUL-terminated
        // strings from `CString`s outliving the call; `raw` is a valid
        // ENGINE handle we hold a reference to.
        let r1 = unsafe {
            ENGINE_ctrl_cmd_string(raw.as_ptr(), so_path_cmd.as_ptr(), path_c.as_ptr(), 0)
        };
        // SAFETY: `id_cmd`/`id_c` are valid NUL-terminated strings from
        // `CString`s outliving the call; `raw` is a valid ENGINE handle
        // we hold a reference to.
        let r2 =
            unsafe { ENGINE_ctrl_cmd_string(raw.as_ptr(), id_cmd.as_ptr(), id_c.as_ptr(), 0) };
        // SAFETY: `list_add_cmd`/`list_add_val` are valid NUL-terminated
        // strings from `CString`s outliving the call; `raw` is a valid
        // ENGINE handle we hold a reference to.
        let r3 = unsafe {
            ENGINE_ctrl_cmd_string(raw.as_ptr(), list_add_cmd.as_ptr(), list_add_val.as_ptr(), 0)
        };
        // SAFETY: `load_cmd` is a valid NUL-terminated string from a
        // `CString` outliving the call; the value argument is NULL as
        // the LOAD command expects; `raw` is a valid ENGINE handle we
        // hold a reference to.
        let r4 =
            unsafe { ENGINE_ctrl_cmd_string(raw.as_ptr(), load_cmd.as_ptr(), std::ptr::null(), 0) };
        assert_eq!(
            (r1, r2, r3, r4),
            (1, 1, 1, 1),
            "ambient-registration setup (SO_PATH/ID/LIST_ADD/LOAD) must itself succeed \
             for the regression test to be meaningful",
        );

        // Release only our own structural reference from `ENGINE_by_id`
        // above; the separate reference `ENGINE_add` took for the global
        // list (triggered by `LIST_ADD=1`) is left in place — that is
        // the genuine ambient collision this test needs.
        // SAFETY: `raw` is a valid ENGINE pointer we hold a reference to.
        unsafe {
            let _ = ENGINE_free(raw.as_ptr());
        }
    }

    #[test]
    fn load_dynamic_clears_a_preexisting_registration_under_the_same_id() {
        // Regression test for the Astra Linux ambient-registration bug:
        // the system `/usr/lib/ssl/openssl.cnf` auto-registers a "gost"
        // engine at libcrypto init time, before tessera's own explicit
        // `load_dynamic` call ever runs — so tessera's own attempt to
        // register under the same id used to fail with `LoadFailed`
        // citing `LOAD=0`, even though the exact same path loads
        // cleanly on a host with no prior registration. (This test uses
        // a non-GOST stock engine module to reproduce the same
        // mechanism — see the doc comment on `find_real_engine_module`
        // for why.)
        //
        // We can't drive a *real* ambient-config auto-load from a unit
        // test, but `register_ambient_engine` reproduces the exact
        // mechanism directly: it runs the same raw ctrl sequence as
        // `openssl.cnf`'s `engine_id`/`init = 1` auto-load would (see
        // its doc comment for why plain `EngineHandle::load_dynamic`
        // calls do *not* leave a real collision behind, unlike this
        // helper).
        //
        // No env-var-gated fixture mechanism exists for pulling in a
        // real engine `.so` at the `src/`-unit-test level (that pattern
        // — `tests/fixtures/gen_gost.sh` + `gost-tests` feature + skip
        // when absent — only exists for the `tests/gost_*_real.rs`
        // integration tests), so this test follows the same
        // skip-with-a-message convention used by
        // `tests/common::skip_unless_gost_ready` rather than inventing
        // a new one.
        let Some((path, id)) = find_real_engine_module() else {
            eprintln!(
                "skipped: no real OpenSSL dynamic engine module found on \
                 this host (checked conventional distro/Homebrew \
                 locations); run on a host that has one to exercise this \
                 regression test.",
            );
            return;
        };

        register_ambient_engine(&path, id);

        let result = EngineHandle::load_dynamic(&path, id);
        assert!(
            result.is_ok(),
            "load_dynamic must succeed despite a genuine preexisting ambient \
             registration under the same id (pre-fix this failed with \
             LoadFailed citing LOAD=0): {result:?}",
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

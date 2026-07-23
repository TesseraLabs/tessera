//! C-compatible plugin envelope and enforcement-backend vtable.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_void};

/// ABI version understood by this host.
pub const TESSERA_PLUGIN_ABI_VERSION: u32 = 1;
/// Plugin kind for an enforcement backend.
pub const TESSERA_ENFORCEMENT_BACKEND_KIND: u32 = 1;

/// Common header returned by the `tessera_plugin_entry` export.
#[repr(C)]
#[derive(Debug)]
pub struct TesseraPluginHeader {
    /// Must equal [`TESSERA_PLUGIN_ABI_VERSION`].
    pub abi_version: u32,
    /// Plugin kind. Version 1 accepts only
    /// [`TESSERA_ENFORCEMENT_BACKEND_KIND`].
    pub kind: u32,
    /// NUL-terminated stable plugin name, for example `parsec`.
    pub name: *const c_char,
    /// NUL-terminated plugin version.
    pub plugin_version: *const c_char,
    /// Kind-specific vtable.
    pub vtable: *const c_void,
}

// SAFETY: a valid header is immutable process-lifetime data. Its raw pointers
// address immutable NUL strings and an immutable vtable with the same lifetime.
unsafe impl Sync for TesseraPluginHeader {}

/// Integrity label representation crossing the plugin ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginIntegrityLabel {
    /// Linear integrity level.
    pub level: i8,
    /// Reserved bytes; must be zero.
    pub reserved: [u8; 7],
    /// Integrity categories bitmap.
    pub categories: u64,
}

/// Return code: operation succeeded.
pub const PLUGIN_OK: i32 = 0;
/// Return code: requested user is absent from the backend database.
pub const PLUGIN_USER_UNKNOWN: i32 = 2;
/// Return code: runtime is unavailable.
pub const PLUGIN_UNAVAILABLE: i32 = 3;
/// Return code: required capability is absent.
pub const PLUGIN_CAP_MISSING: i32 = 4;
/// Return code: invalid input or label text.
pub const PLUGIN_INVALID_INPUT: i32 = 5;
/// Return code: plugin panicked behind its ABI guard.
pub const PLUGIN_PANIC: i32 = 6;

/// C ABI mirror of `MacBackend`.
///
/// Plugins own the opaque `context` returned by `init`. Every callback must
/// contain its own panic boundary and translate panic to [`PLUGIN_PANIC`]
/// before returning across this C ABI. Rust unwind payloads cannot safely
/// cross independently linked dynamic-library runtimes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EnforcementBackendVTable {
    /// Initialise the plugin from the selected backend's configuration blob.
    pub init: Option<
        unsafe extern "C" fn(
            config: *const u8,
            config_len: usize,
            context: *mut *mut c_void,
        ) -> i32,
    >,
    /// Release plugin-owned context. The shared library itself is not unloaded.
    pub teardown: Option<unsafe extern "C" fn(context: *mut c_void)>,
    /// Return the numeric `MacRuntime` discriminator.
    pub probe: Option<unsafe extern "C" fn(context: *mut c_void) -> i32>,
    /// Return the numeric `MrdState` discriminator.
    pub probe_mrd: Option<unsafe extern "C" fn(context: *mut c_void) -> i32>,
    /// Check the process capability required for MAC label writes.
    pub check_write_capability: Option<unsafe extern "C" fn(context: *mut c_void) -> i32>,
    /// Resolve a user's maximum integrity label.
    pub get_user_mnkc: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            user: *const u8,
            user_len: usize,
            label: *mut PluginIntegrityLabel,
        ) -> i32,
    >,
    /// Apply a label to the current session.
    pub apply_session:
        Option<unsafe extern "C" fn(context: *mut c_void, label: PluginIntegrityLabel) -> i32>,
    /// Read a file label.
    pub get_file_label: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            path: *const u8,
            path_len: usize,
            label: *mut PluginIntegrityLabel,
        ) -> i32,
    >,
    /// Write a file label.
    pub set_file_label: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            path: *const u8,
            path_len: usize,
            label: PluginIntegrityLabel,
            irelax: bool,
        ) -> i32,
    >,
    /// Write a label through an already-open file descriptor.
    pub set_fd_label: Option<
        unsafe extern "C" fn(
            context: *mut c_void,
            fd: i32,
            label: PluginIntegrityLabel,
            irelax: bool,
        ) -> i32,
    >,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_constants_are_stable() {
        assert_eq!(TESSERA_PLUGIN_ABI_VERSION, 1);
        assert_eq!(TESSERA_ENFORCEMENT_BACKEND_KIND, 1);
    }

    #[test]
    fn label_has_stable_layout() {
        assert_eq!(std::mem::size_of::<PluginIntegrityLabel>(), 16);
        assert_eq!(std::mem::align_of::<PluginIntegrityLabel>(), 8);
    }
}

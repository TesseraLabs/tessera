//! Fixture runtime enforcement plugin for loader contract tests.

#![allow(unsafe_code)]

use std::ffi::c_void;

use tessera_core::plugin::{
    header_codes, EnforcementBackendVTable, PluginIntegrityLabel, TesseraPluginHeader,
    TESSERA_ENFORCEMENT_BACKEND_KIND, TESSERA_PLUGIN_ABI_VERSION,
};

const NAME: &[u8] = b"fixture\0";
const VERSION: &[u8] = b"1.0.0-test\0";

fn mode() -> Option<String> {
    std::env::var("TESSERA_TEST_PLUGIN_MODE").ok()
}

fn guard(call: impl FnOnce() -> i32) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)).unwrap_or(header_codes::PANIC)
}

unsafe extern "C" fn init(
    _config: *const u8,
    _config_len: usize,
    context: *mut *mut c_void,
) -> i32 {
    guard(|| {
        if mode().as_deref() == Some("panic-init") {
            panic!("fixture init panic");
        }
        if mode().as_deref() == Some("init-error") {
            return header_codes::UNAVAILABLE;
        }
        if context.is_null() {
            return header_codes::INVALID_INPUT;
        }
        // SAFETY: the host supplied a writable out-pointer. The fixture
        // context is a non-null sentinel and is never dereferenced.
        unsafe { context.write(std::ptr::dangling_mut::<c_void>()) };
        header_codes::OK
    })
}

unsafe extern "C" fn teardown(_context: *mut c_void) {}

unsafe extern "C" fn probe(_context: *mut c_void) -> i32 {
    1
}

unsafe extern "C" fn probe_mrd(_context: *mut c_void) -> i32 {
    0
}

unsafe extern "C" fn check_write_capability(_context: *mut c_void) -> i32 {
    header_codes::OK
}

unsafe extern "C" fn get_user_mnkc(
    _context: *mut c_void,
    user: *const u8,
    user_len: usize,
    output: *mut PluginIntegrityLabel,
) -> i32 {
    if user.is_null() || output.is_null() {
        return header_codes::INVALID_INPUT;
    }
    // SAFETY: host supplies a readable `user_len` buffer.
    let user = unsafe { std::slice::from_raw_parts(user, user_len) };
    if user != b"alice" {
        return header_codes::USER_UNKNOWN;
    }
    // SAFETY: host supplied a writable label pointer.
    unsafe {
        output.write(PluginIntegrityLabel {
            level: 7,
            reserved: [0; 7],
            categories: 0xff,
        })
    };
    header_codes::OK
}

unsafe extern "C" fn apply_session(_context: *mut c_void, _label: PluginIntegrityLabel) -> i32 {
    guard(|| {
        if mode().as_deref() == Some("panic-apply") {
            panic!("fixture apply panic");
        }
        header_codes::OK
    })
}

unsafe extern "C" fn get_file_label(
    _context: *mut c_void,
    _path: *const u8,
    _path_len: usize,
    output: *mut PluginIntegrityLabel,
) -> i32 {
    if output.is_null() {
        return header_codes::INVALID_INPUT;
    }
    // SAFETY: host supplied a writable label pointer.
    unsafe {
        output.write(PluginIntegrityLabel {
            level: 0,
            reserved: [0; 7],
            categories: 0,
        })
    };
    header_codes::OK
}

unsafe extern "C" fn set_file_label(
    _context: *mut c_void,
    _path: *const u8,
    _path_len: usize,
    _label: PluginIntegrityLabel,
    _irelax: bool,
) -> i32 {
    header_codes::OK
}

unsafe extern "C" fn set_fd_label(
    _context: *mut c_void,
    _fd: i32,
    _label: PluginIntegrityLabel,
    _irelax: bool,
) -> i32 {
    header_codes::OK
}

static VTABLE: EnforcementBackendVTable = EnforcementBackendVTable {
    init: Some(init),
    teardown: Some(teardown),
    probe: Some(probe),
    probe_mrd: Some(probe_mrd),
    check_write_capability: Some(check_write_capability),
    get_user_mnkc: Some(get_user_mnkc),
    apply_session: Some(apply_session),
    get_file_label: Some(get_file_label),
    set_file_label: Some(set_file_label),
    set_fd_label: Some(set_fd_label),
};

static HEADER: TesseraPluginHeader = TesseraPluginHeader {
    abi_version: TESSERA_PLUGIN_ABI_VERSION,
    kind: TESSERA_ENFORCEMENT_BACKEND_KIND,
    name: NAME.as_ptr().cast(),
    plugin_version: VERSION.as_ptr().cast(),
    vtable: (&VTABLE as *const EnforcementBackendVTable).cast(),
};

static ABI_MISMATCH_HEADER: TesseraPluginHeader = TesseraPluginHeader {
    abi_version: TESSERA_PLUGIN_ABI_VERSION + 1,
    kind: TESSERA_ENFORCEMENT_BACKEND_KIND,
    name: NAME.as_ptr().cast(),
    plugin_version: VERSION.as_ptr().cast(),
    vtable: (&VTABLE as *const EnforcementBackendVTable).cast(),
};

static KIND_MISMATCH_HEADER: TesseraPluginHeader = TesseraPluginHeader {
    abi_version: TESSERA_PLUGIN_ABI_VERSION,
    kind: TESSERA_ENFORCEMENT_BACKEND_KIND + 1,
    name: NAME.as_ptr().cast(),
    plugin_version: VERSION.as_ptr().cast(),
    vtable: (&VTABLE as *const EnforcementBackendVTable).cast(),
};

static MALFORMED_HEADER: TesseraPluginHeader = TesseraPluginHeader {
    abi_version: TESSERA_PLUGIN_ABI_VERSION,
    kind: TESSERA_ENFORCEMENT_BACKEND_KIND,
    name: NAME.as_ptr().cast(),
    plugin_version: VERSION.as_ptr().cast(),
    vtable: std::ptr::null(),
};

/// Return the fixture plugin header.
#[no_mangle]
pub extern "C" fn tessera_plugin_entry() -> *const TesseraPluginHeader {
    match mode().as_deref() {
        Some("null-header") => std::ptr::null(),
        Some("abi-mismatch") => &ABI_MISMATCH_HEADER,
        Some("kind-mismatch") => &KIND_MISMATCH_HEADER,
        Some("malformed-header") => &MALFORMED_HEADER,
        _ => &HEADER,
    }
}

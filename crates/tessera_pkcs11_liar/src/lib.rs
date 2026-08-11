//! A PKCS#11 module that lies on request.
//!
//! Reading key attributes back after generation only proves something if a
//! provider can accept a template and then report otherwise. Neither `SoftHSM`
//! nor a live token does that on demand, so this fixture does: it applies the
//! template, generates a real P-256 pair, signs honestly — and answers
//! `C_GetAttributeValue` according to [`state::Mode`], read once from
//! `TESSERA_PKCS11_LIAR_MODE` at `C_Initialize`.
//!
//! The module is a test fixture and is never shipped. It presents one slot with
//! one token, implements the functions the generation and signing path calls,
//! and leaves the rest of `CK_FUNCTION_LIST` null so a caller that strays out
//! of that path gets a clean `CKR_...`/`NullFunctionPointer` rather than a
//! plausible answer.
//!
//! # Modes
//!
//! | `TESSERA_PKCS11_LIAR_MODE` | behaviour |
//! |---|---|
//! | unset, or anything unrecognised | [`Mode::Honest`] |
//! | `ignores-template` | [`Mode::IgnoresTemplate`] |
//! | `leaks` | [`Mode::Leaks`] |
//! | `attributes-absent` | [`Mode::AttributesAbsent`] |
//! | `no-mechanisms` | [`Mode::NoMechanisms`] |
//! | `was-extractable` | [`Mode::WasExtractable`] |

pub mod state;

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use cryptoki_sys::{
    CKF_EC_F_P, CKF_GENERATE_KEY_PAIR, CKF_HW, CKF_HW_SLOT, CKF_LOGIN_REQUIRED, CKF_RNG,
    CKF_SERIAL_SESSION, CKF_SIGN, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT,
    CKF_USER_PIN_INITIALIZED, CKF_VERIFY, CKO_DATA, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_MECHANISM_INVALID,
    CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SLOT_ID_INVALID, CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE,
    CK_BBOOL, CK_BYTE, CK_FLAGS, CK_FUNCTION_LIST, CK_INFO, CK_MECHANISM, CK_MECHANISM_INFO,
    CK_MECHANISM_TYPE, CK_NOTIFY, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID,
    CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_UNAVAILABLE_INFORMATION, CK_VERSION,
};

pub use crate::state::Mode;
use crate::state::{Answer, Material, State, StoredObject};

/// The only slot the fixture presents.
const SLOT_ID: CK_SLOT_ID = 0;

/// Everything the module knows, behind one lock.
///
/// A PKCS#11 module is called from several threads; the fixture serialises
/// every entry point rather than reproducing a provider's locking bugs, which
/// are a different test's subject.
static STATE: Mutex<State> = Mutex::new(State::new());

fn state() -> MutexGuard<'static, State> {
    // A panic inside one call must not turn every later call into a panic: the
    // fixture's job is to answer, and a poisoned store is still a valid store.
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs an entry point, turning a panic into `CKR_FUNCTION_FAILED`.
///
/// Unwinding out of an `extern "C"` frame aborts the process, which in a test
/// run hides which call went wrong.
fn guard(call: impl FnOnce() -> CK_RV) -> CK_RV {
    catch_unwind(AssertUnwindSafe(call)).unwrap_or(CKR_FUNCTION_FAILED)
}

/// Copies `text` into a blank-padded PKCS#11 fixed-width field.
fn blank_padded<const N: usize>(text: &str) -> [u8; N] {
    let mut field = [b' '; N];
    for (slot, byte) in field.iter_mut().zip(text.bytes()) {
        *slot = byte;
    }
    field
}

// ---- The function list -----------------------------------------------------

/// The PKCS#11 2.40 dispatch table, handed out by `C_GetFunctionList`.
///
/// Only the functions the generation, read-back, probe and signing paths use
/// are filled in. `cryptoki` reports a null entry as an error, so an untaken
/// path fails loudly instead of returning a fabricated success.
static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: None,
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: None,
    C_GetSessionInfo: None,
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: None,
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: None,
    C_Encrypt: None,
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: None,
    C_Decrypt: None,
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: None,
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: None,
    C_SignFinal: None,
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None,
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: None,
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: None,
    C_GenerateRandom: None,
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

/// The PKCS#11 entry point: hands out the dispatch table.
///
/// # Safety
///
/// `list` must be a writable pointer to a `CK_FUNCTION_LIST` pointer, as the
/// caller of a PKCS#11 module is required to supply.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_GetFunctionList(list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    if list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // SAFETY: the caller supplied a writable out-pointer, checked non-null
    // above. The table is `static` and never mutated, so the pointer handed out
    // outlives every call the caller can make through it.
    unsafe { list.write(ptr::addr_of!(FUNCTION_LIST).cast_mut()) };
    CKR_OK
}

// ---- General purpose -------------------------------------------------------

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_Initialize(_args: *mut c_void) -> CK_RV {
    guard(|| {
        let mut state = state();
        if state.is_initialized() {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }
        state.initialize();
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_Finalize(_reserved: *mut c_void) -> CK_RV {
    guard(|| {
        let mut state = state();
        if !state.is_initialized() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        state.finalize();
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_GetInfo(info: *mut CK_INFO) -> CK_RV {
    guard(|| {
        if info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let value = CK_INFO {
            cryptokiVersion: CK_VERSION {
                major: 2,
                minor: 40,
            },
            manufacturerID: blank_padded("Tessera test fixtures"),
            flags: 0,
            libraryDescription: blank_padded("dishonest PKCS#11 module"),
            libraryVersion: CK_VERSION { major: 0, minor: 1 },
        };
        // SAFETY: `info` is non-null and, per the PKCS#11 contract, points at a
        // caller-owned `CK_INFO`.
        unsafe { info.write(value) };
        CKR_OK
    })
}

// ---- Slots and tokens ------------------------------------------------------

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    slots: *mut CK_SLOT_ID,
    count: *mut CK_ULONG,
) -> CK_RV {
    guard(|| {
        if count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if slots.is_null() {
            // SAFETY: `count` is non-null and writable.
            unsafe { count.write(1) };
            return CKR_OK;
        }
        // SAFETY: `count` is non-null and, on this branch, carries the length
        // of the caller's `slots` buffer.
        let capacity = unsafe { count.read() };
        if capacity < 1 {
            // SAFETY: as above.
            unsafe { count.write(1) };
            return CKR_BUFFER_TOO_SMALL;
        }
        // SAFETY: the caller promised `slots` holds at least `capacity` entries
        // and `capacity` is at least one.
        unsafe { slots.write(SLOT_ID) };
        // SAFETY: `count` is non-null and writable.
        unsafe { count.write(1) };
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_GetSlotInfo(slot: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> CK_RV {
    guard(|| {
        if slot != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let value = CK_SLOT_INFO {
            slotDescription: blank_padded("Tessera liar slot"),
            manufacturerID: blank_padded("Tessera test fixtures"),
            flags: CKF_TOKEN_PRESENT | CKF_HW_SLOT,
            hardwareVersion: CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: CK_VERSION { major: 0, minor: 1 },
        };
        // SAFETY: `info` is non-null and caller-owned.
        unsafe { info.write(value) };
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_GetTokenInfo(slot: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> CK_RV {
    guard(|| {
        if slot != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut value = CK_TOKEN_INFO {
            label: blank_padded("tessera-liar"),
            manufacturerID: blank_padded("Tessera test fixtures"),
            model: blank_padded("liar"),
            serialNumber: blank_padded("0000000000000001"),
            // No `CKF_CLOCK_ON_TOKEN`: the fixture has no clock, and claiming
            // one would oblige it to fill `utcTime`.
            flags: CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED,
            ..CK_TOKEN_INFO::default()
        };
        value.ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
        value.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
        value.ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;
        value.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
        value.ulMaxPinLen = 32;
        value.ulMinPinLen = 4;
        value.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
        value.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
        value.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        value.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
        value.hardwareVersion = CK_VERSION { major: 0, minor: 1 };
        value.firmwareVersion = CK_VERSION { major: 0, minor: 1 };
        // SAFETY: `info` is non-null and caller-owned.
        unsafe { info.write(value) };
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_GetMechanismList(
    slot: CK_SLOT_ID,
    mechanisms: *mut CK_MECHANISM_TYPE,
    count: *mut CK_ULONG,
) -> CK_RV {
    guard(|| {
        if slot != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let announced = state().mode().mechanisms();
        let len = announced.len() as CK_ULONG;
        if mechanisms.is_null() {
            // SAFETY: `count` is non-null and writable.
            unsafe { count.write(len) };
            return CKR_OK;
        }
        // SAFETY: on this branch `count` carries the caller's buffer length.
        let capacity = unsafe { count.read() };
        if capacity < len {
            // SAFETY: as above.
            unsafe { count.write(len) };
            return CKR_BUFFER_TOO_SMALL;
        }
        // SAFETY: the caller promised `mechanisms` holds `capacity` entries and
        // `capacity` is at least `len`; the source is a `'static` slice of the
        // same element type.
        unsafe { ptr::copy_nonoverlapping(announced.as_ptr(), mechanisms, announced.len()) };
        // SAFETY: `count` is non-null and writable.
        unsafe { count.write(len) };
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_GetMechanismInfo(
    slot: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    info: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    guard(|| {
        if slot != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if !state().mode().mechanisms().contains(&mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        let value = CK_MECHANISM_INFO {
            ulMinKeySize: 256,
            ulMaxKeySize: 256,
            flags: CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P,
        };
        // SAFETY: `info` is non-null and caller-owned.
        unsafe { info.write(value) };
        CKR_OK
    })
}

// ---- Sessions --------------------------------------------------------------

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_OpenSession(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: *mut c_void,
    _notify: CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    guard(|| {
        if slot != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if session.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        let mut state = state();
        if !state.is_initialized() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        let handle = state.open_session();
        // SAFETY: `session` is a non-null, caller-owned out-pointer.
        unsafe { session.write(handle) };
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| {
        if state().close_session(session) {
            CKR_OK
        } else {
            CKR_SESSION_HANDLE_INVALID
        }
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_Login(
    session: CK_SESSION_HANDLE,
    _user: CK_ULONG,
    _pin: *mut CK_BYTE,
    _pin_len: CK_ULONG,
) -> CK_RV {
    // Any PIN is accepted: the fixture's subject is what the token reports
    // about a key, not how it authenticates.
    guard(|| {
        if state().login(session) {
            CKR_OK
        } else {
            CKR_SESSION_HANDLE_INVALID
        }
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_Logout(session: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| {
        if state().logout(session) {
            CKR_OK
        } else {
            CKR_SESSION_HANDLE_INVALID
        }
    })
}

// ---- Objects ---------------------------------------------------------------

/// Reads a caller's attribute template into owned pairs.
///
/// # Safety
///
/// `template` must point at `count` initialised `CK_ATTRIBUTE`s, each with
/// either a null `pValue` or a readable buffer of `ulValueLen` bytes.
unsafe fn read_template(
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> {
    let Ok(len) = usize::try_from(count) else {
        return Vec::new();
    };
    if template.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: the caller promised `count` initialised attributes at `template`.
    let attributes = unsafe { std::slice::from_raw_parts(template, len) };
    attributes
        .iter()
        .map(|attribute| {
            let value_len = usize::try_from(attribute.ulValueLen).unwrap_or(0);
            let value = if attribute.pValue.is_null() || value_len == 0 {
                Vec::new()
            } else {
                // SAFETY: the caller promised `pValue` points at `ulValueLen`
                // readable bytes for the duration of the call.
                unsafe {
                    std::slice::from_raw_parts(attribute.pValue.cast::<u8>(), value_len).to_vec()
                }
            };
            (attribute.type_, value)
        })
        .collect()
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_CreateObject(
    session: CK_SESSION_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
    object: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| {
        if object.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // SAFETY: the caller supplied a PKCS#11 template of `count` entries.
        let attributes = unsafe { read_template(template, count) };
        let mut state = state();
        if !state.has_session(session) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let take = |wanted: CK_ATTRIBUTE_TYPE| -> Option<Vec<u8>> {
            attributes
                .iter()
                .find(|(type_, _)| *type_ == wanted)
                .map(|(_, value)| value.clone())
        };
        let stored = StoredObject {
            class: CKO_DATA,
            key_type: None,
            label: take(cryptoki_sys::CKA_LABEL).unwrap_or_default(),
            id: take(cryptoki_sys::CKA_ID).unwrap_or_default(),
            token: true,
            private: false,
            requested_extractable: true,
            requested_sensitive: false,
            material: Material::Data {
                value: take(cryptoki_sys::CKA_VALUE).unwrap_or_default(),
            },
        };
        let handle = state.add_object(stored);
        // SAFETY: `object` is a non-null, caller-owned out-pointer.
        unsafe { object.write(handle) };
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_DestroyObject(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| {
        let mut state = state();
        if !state.has_session(session) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if state.destroy_object(object) {
            CKR_OK
        } else {
            CKR_OBJECT_HANDLE_INVALID
        }
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_GetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    guard(|| {
        let state = state();
        if !state.has_session(session) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let Some(stored) = state.object(object) else {
            return CKR_OBJECT_HANDLE_INVALID;
        };
        let Ok(len) = usize::try_from(count) else {
            return CKR_ARGUMENTS_BAD;
        };
        if template.is_null() || len == 0 {
            return CKR_OK;
        }
        let mode = state.mode();
        // SAFETY: the caller supplied `count` writable `CK_ATTRIBUTE`s; each
        // one's `pValue`, when non-null, points at `ulValueLen` writable bytes.
        let attributes = unsafe { std::slice::from_raw_parts_mut(template, len) };
        let mut outcome = CKR_OK;
        for attribute in attributes {
            let rv = match stored.attribute(mode, attribute.type_) {
                // SAFETY: `attribute` is a caller-owned entry of the template.
                Answer::Value(bytes) => unsafe { write_attribute(attribute, &bytes) },
                Answer::Sensitive => {
                    attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_SENSITIVE
                }
                Answer::TypeInvalid => {
                    attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    CKR_ATTRIBUTE_TYPE_INVALID
                }
            };
            if rv != CKR_OK && outcome == CKR_OK {
                outcome = rv;
            }
        }
        outcome
    })
}

/// Fills one template entry, following the PKCS#11 two-pass convention: a null
/// `pValue` asks for the length, a short buffer is refused.
///
/// # Safety
///
/// `attribute.pValue`, when non-null, must point at `ulValueLen` writable bytes.
unsafe fn write_attribute(attribute: &mut CK_ATTRIBUTE, bytes: &[u8]) -> CK_RV {
    let len = bytes.len() as CK_ULONG;
    if attribute.pValue.is_null() {
        attribute.ulValueLen = len;
        return CKR_OK;
    }
    if attribute.ulValueLen < len {
        attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    // SAFETY: `pValue` is non-null and holds at least `ulValueLen` >= `len`
    // writable bytes; the source is a distinct owned buffer.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), attribute.pValue.cast::<u8>(), bytes.len()) };
    attribute.ulValueLen = len;
    CKR_OK
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_FindObjectsInit(
    session: CK_SESSION_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    guard(|| {
        // SAFETY: the caller supplied a PKCS#11 template of `count` entries.
        let filter = unsafe { read_template(template, count) };
        match state().find_objects_init(session, &filter) {
            Ok(()) => CKR_OK,
            Err(rv) => rv,
        }
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_FindObjects(
    session: CK_SESSION_HANDLE,
    objects: *mut CK_OBJECT_HANDLE,
    max: CK_ULONG,
    count: *mut CK_ULONG,
) -> CK_RV {
    guard(|| {
        if count.is_null() || objects.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let Ok(max) = usize::try_from(max) else {
            return CKR_ARGUMENTS_BAD;
        };
        let handles = match state().find_objects(session, max) {
            Ok(handles) => handles,
            Err(rv) => return rv,
        };
        // SAFETY: the caller promised `objects` holds `max` handles, and the
        // store never returns more than `max`.
        unsafe { ptr::copy_nonoverlapping(handles.as_ptr(), objects, handles.len()) };
        // SAFETY: `count` is a non-null, caller-owned out-pointer.
        unsafe { count.write(handles.len() as CK_ULONG) };
        CKR_OK
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| match state().find_objects_final(session) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    })
}

// ---- Generation and signing ------------------------------------------------

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_GenerateKeyPair(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    public_template: *mut CK_ATTRIBUTE,
    public_count: CK_ULONG,
    private_template: *mut CK_ATTRIBUTE,
    private_count: CK_ULONG,
    public_key: *mut CK_OBJECT_HANDLE,
    private_key: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| {
        if mechanism.is_null() || public_key.is_null() || private_key.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // SAFETY: `mechanism` is non-null and, per the PKCS#11 contract, points
        // at an initialised `CK_MECHANISM`.
        let mechanism_type = unsafe { (*mechanism).mechanism };
        // SAFETY: both templates carry the counts the caller declared.
        let public = unsafe { read_template(public_template, public_count) };
        // SAFETY: as above.
        let private = unsafe { read_template(private_template, private_count) };

        let mut state = state();
        if !state.has_session(session) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        match state.generate_key_pair(mechanism_type, &public, &private) {
            Ok((public_handle, private_handle)) => {
                // SAFETY: both out-pointers are non-null and caller-owned.
                unsafe { public_key.write(public_handle) };
                // SAFETY: as above.
                unsafe { private_key.write(private_handle) };
                CKR_OK
            }
            Err(rv) => rv,
        }
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_SignInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| {
        if mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // SAFETY: `mechanism` is non-null and points at an initialised
        // `CK_MECHANISM`.
        let mechanism_type = unsafe { (*mechanism).mechanism };
        match state().sign_init(session, mechanism_type, key) {
            Ok(()) => CKR_OK,
            Err(rv) => rv,
        }
    })
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn C_Sign(
    session: CK_SESSION_HANDLE,
    data: *mut CK_BYTE,
    data_len: CK_ULONG,
    signature: *mut CK_BYTE,
    signature_len: *mut CK_ULONG,
) -> CK_RV {
    guard(|| {
        if data.is_null() || signature_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let Ok(len) = usize::try_from(data_len) else {
            return CKR_ARGUMENTS_BAD;
        };
        // SAFETY: the caller promised `data` holds `data_len` readable bytes
        // for the duration of the call.
        let message = unsafe { std::slice::from_raw_parts(data, len) };

        let mut state = state();
        let produced = match state.sign_peek(session, message) {
            Ok(bytes) => bytes,
            Err(rv) => return rv,
        };
        let produced_len = produced.len() as CK_ULONG;
        if signature.is_null() {
            // A length query leaves the operation open for the second call.
            // SAFETY: `signature_len` is a non-null, caller-owned out-pointer.
            unsafe { signature_len.write(produced_len) };
            return CKR_OK;
        }
        // SAFETY: as above; on this branch it carries the buffer's capacity.
        let capacity = unsafe { signature_len.read() };
        if capacity < produced_len {
            // SAFETY: as above.
            unsafe { signature_len.write(produced_len) };
            return CKR_BUFFER_TOO_SMALL;
        }
        // SAFETY: the caller promised `signature` holds `capacity` >=
        // `produced_len` writable bytes; the source is a distinct owned buffer.
        unsafe { ptr::copy_nonoverlapping(produced.as_ptr(), signature, produced.len()) };
        // SAFETY: `signature_len` is a non-null, caller-owned out-pointer.
        unsafe { signature_len.write(produced_len) };
        state.sign_finish(session);
        CKR_OK
    })
}

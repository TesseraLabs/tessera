//! The COM in-process server: exports, class factory, CLSID.
//!
//! `LogonUI` loads this DLL, asks it for a class object by CLSID and builds a
//! provider out of it. Everything below is that handshake and nothing more —
//! the provider's behaviour lives in [`provider`], the tile's in [`credential`],
//! and the decisions behind both in the platform-neutral half of the crate.
//!
//! # Unsafe
//!
//! The whole file is FFI: raw out-parameters from a caller this code does not
//! control, and exported symbols with a C ABI. Every `unsafe` block wraps one
//! operation and states what makes it sound.
#![allow(unsafe_code)]
// `#[implement]` generates a companion `..._Impl` struct and its vtable glue at
// the span of the attribute: undocumented, `#[inline(always)]`, and casting
// references to raw pointers. None of that can be annotated at its own site, so
// the three lints are relaxed for the file; they stay on for every hand-written
// item in it, and the macro-generated code is not ours to style.
#![allow(missing_docs, clippy::inline_always, clippy::ref_as_ptr)]

pub mod credential;
pub mod lsa;
pub mod provider;
pub mod wide;

use std::ffi::c_void;

use windows::core::{
    implement, Error, IUnknown, Interface, Ref, Result as WinResult, BOOL, GUID, HRESULT,
};
use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_INVALIDARG, E_POINTER, E_UNEXPECTED,
    S_FALSE, S_OK,
};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};

use crate::com::provider::TesseraProvider;
use crate::panic_guard::{guard, PanicFlag};

/// Class identifier of this provider, in binary form.
///
/// Must equal [`crate::PROVIDER_CLSID`]; the test below holds them together.
#[must_use]
pub const fn provider_clsid() -> GUID {
    GUID::from_u128(crate::PROVIDER_CLSID_U128)
}

/// Panic containment for the exported entry points, which have no object to
/// hang a flag on.
static EXPORT_PANICS: PanicFlag = PanicFlag::new();

/// Class object `LogonUI` asks for before it can build a provider.
#[implement(IClassFactory)]
struct ProviderFactory;

impl IClassFactory_Impl for ProviderFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut c_void,
    ) -> WinResult<()> {
        if ppvobject.is_null() || riid.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }
        // SAFETY: checked non-null immediately above; the slot belongs to the
        // caller, which expects it cleared before any failure return.
        unsafe { ppvobject.write(std::ptr::null_mut()) };

        if !punkouter.is_null() {
            // Aggregation is not supported, and saying so is not optional: a
            // half-aggregated object is a crash inside LogonUI later.
            return Err(Error::from_hresult(CLASS_E_NOAGGREGATION));
        }

        guard(
            "DllGetClassObject::CreateInstance",
            &EXPORT_PANICS,
            Err(Error::from_hresult(E_UNEXPECTED)),
            || {
                let provider: IUnknown = TesseraProvider::new().into();
                // SAFETY: `riid` and `ppvobject` were checked non-null above and
                // are the standard `QueryInterface` out-parameters; the object
                // was just constructed and holds its own reference.
                unsafe { provider.query(riid, ppvobject) }.ok()
            },
        )
    }

    fn LockServer(&self, _flock: BOOL) -> WinResult<()> {
        // The DLL never reports itself as unloadable (see `DllCanUnloadNow`),
        // so there is no lock count to keep.
        Ok(())
    }
}

/// Hands `LogonUI` the class object for our CLSID.
///
/// # Safety
///
/// The COM contract of `DllGetClassObject`: `rclsid` and `riid` point at
/// readable `GUID`s and `ppv` at a writable pointer-sized slot.
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    // The first call into the DLL is the first chance to have a log at all.
    crate::logging::init();
    tracing::debug!(target: "tessera.cp", "DllGetClassObject");

    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: checked non-null above; the caller guarantees the slot is
    // writable and pointer-sized.
    unsafe { ppv.write(std::ptr::null_mut()) };

    guard("DllGetClassObject", &EXPORT_PANICS, E_UNEXPECTED, || {
        // SAFETY: checked non-null above; the caller guarantees a readable GUID.
        let requested = unsafe { *rclsid };
        if requested != provider_clsid() {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        let factory: IClassFactory = ProviderFactory.into();
        // SAFETY: `riid`/`ppv` were checked non-null above and carry the
        // standard `QueryInterface` contract; `factory` holds its own
        // reference until this call takes one.
        unsafe { factory.query(riid, ppv) }
    })
}

/// Tells COM whether the DLL may be unloaded.
///
/// It answers `S_FALSE` unconditionally. Unloading a credential provider out
/// from under `LogonUI` buys nothing — the process is short-lived by design — and
/// getting the lock count wrong there costs the logon screen.
#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}

/// Registration is performed by script rather than by the DLL.
///
/// `DllRegisterServer` exists so that a stray `regsvr32` reports an honest
/// success/failure instead of "entry point not found", but it does nothing: the
/// registry writes belong to the installer, which knows the path the DLL was
/// installed to.
#[no_mangle]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    S_OK
}

/// Counterpart of [`DllRegisterServer`], and equally inert.
#[no_mangle]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
    S_OK
}

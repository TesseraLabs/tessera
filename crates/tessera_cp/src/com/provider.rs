//! `ICredentialProvider` — the object `LogonUI` asks for tiles.
//!
//! The provider declares the field table, hands out exactly one credential, and
//! refuses every usage scenario it has no business in. It holds no secrets and
//! makes no decisions; both live one layer down.
#![allow(unsafe_code)]
// `#[implement]` generates a companion `..._Impl` struct and its vtable glue at
// the span of the attribute: undocumented, `#[inline(always)]`, and casting
// references to raw pointers. None of that can be annotated at its own site, so
// the three lints are relaxed for the file; they stay on for every hand-written
// item in it, and the macro-generated code is not ours to style.
#![allow(missing_docs, clippy::inline_always, clippy::ref_as_ptr)]

use std::cell::RefCell;

use windows::core::{implement, Error, Ref, Result as WinResult, BOOL, GUID, PWSTR};
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_OUTOFMEMORY, E_POINTER, E_UNEXPECTED};
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::Win32::UI::Shell::{
    ICredentialProvider, ICredentialProviderCredential, ICredentialProviderCredential2,
    ICredentialProviderEvents, ICredentialProvider_Impl, CPFT_COMBOBOX, CPFT_LARGE_TEXT,
    CPFT_PASSWORD_TEXT, CPFT_SMALL_TEXT, CPFT_SUBMIT_BUTTON, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    CREDENTIAL_PROVIDER_FIELD_TYPE, CREDENTIAL_PROVIDER_NO_DEFAULT,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};

use crate::com::{credential::new_credential, wide};
use crate::fields::{Field, FieldKind};
use crate::kerb::LogonKind;
use crate::panic_guard::{guard, PanicFlag};

/// Mutable half of the provider.
struct Inner {
    credential: Option<ICredentialProviderCredential2>,
    events: Option<ICredentialProviderEvents>,
    advise_context: usize,
}

/// The Tessera credential provider.
#[implement(ICredentialProvider)]
pub struct TesseraProvider {
    panic_flag: PanicFlag,
    inner: RefCell<Inner>,
}

impl TesseraProvider {
    /// Builds a provider with no tile yet: `LogonUI` names the scenario first.
    #[must_use]
    pub fn new() -> Self {
        Self {
            panic_flag: PanicFlag::new(),
            inner: RefCell::new(Inner {
                credential: None,
                events: None,
                advise_context: 0,
            }),
        }
    }
}

impl Default for TesseraProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TesseraProvider_Impl {
    /// Runs an entry-point body against the provider state, panics contained.
    fn with_inner<T>(
        &self,
        entry: &'static str,
        fallback: T,
        body: impl FnOnce(&mut Inner) -> T,
    ) -> T
    where
        T: Clone,
    {
        guard(entry, &self.panic_flag, fallback.clone(), || {
            match self.inner.try_borrow_mut() {
                Ok(mut inner) => body(&mut inner),
                Err(_borrowed) => {
                    tracing::error!(
                        target: "tessera.cp",
                        entry_point = entry,
                        "re-entrant call refused"
                    );
                    fallback.clone()
                }
            }
        })
    }
}

// The raw pointers in these signatures are the COM out-parameters of the
// interface; the trait dictates the shape, and every one of them is checked
// against null before it is written through. Marking the methods `unsafe` is
// not an option — the vtable calls them.
#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "signatures are fixed by the COM vtable; every pointer is null-checked before use"
)]
impl ICredentialProvider_Impl for TesseraProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> WinResult<()> {
        // Logging on and unlocking are the two scenarios this provider belongs
        // in. Credential-UI prompts, password changes and the pre-logon access
        // provider are answered with E_NOTIMPL, which is how a provider says
        // "not mine" without affecting anyone else's tile.
        let kind = if cpus == CPUS_LOGON {
            LogonKind::Interactive
        } else if cpus == CPUS_UNLOCK_WORKSTATION {
            LogonKind::WorkstationUnlock
        } else {
            return Err(Error::from_hresult(E_NOTIMPL));
        };

        self.with_inner(
            "Provider::SetUsageScenario",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                inner.credential = Some(new_credential(kind));
                Ok(())
            },
        )
    }

    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> WinResult<()> {
        // Credentials handed *in* — from a remote session or another provider —
        // are not something this tile can act on: the engine's verdict is about
        // a credential on a medium at this console.
        Err(Error::from_hresult(E_NOTIMPL))
    }

    fn Advise(
        &self,
        pcpe: Ref<'_, ICredentialProviderEvents>,
        upadvisecontext: usize,
    ) -> WinResult<()> {
        self.with_inner(
            "Provider::Advise",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                inner.events = pcpe.cloned();
                inner.advise_context = upadvisecontext;
                Ok(())
            },
        )
    }

    fn UnAdvise(&self) -> WinResult<()> {
        self.with_inner(
            "Provider::UnAdvise",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                inner.events = None;
                inner.advise_context = 0;
                Ok(())
            },
        )
    }

    fn GetFieldDescriptorCount(&self) -> WinResult<u32> {
        u32::try_from(Field::ALL.len()).map_err(|_| Error::from_hresult(E_UNEXPECTED))
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> WinResult<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        let Some(field) = Field::from_id(dwindex) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };

        let label = wide::alloc_pwstr(field.label())?;
        let descriptor = CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: field.id(),
            cpft: field_type(field.kind()),
            pszLabel: label,
            guidFieldType: GUID::zeroed(),
        };

        // SAFETY: `CoTaskMemAlloc` is safe to call with any size; the result is
        // checked for null before it is written through.
        let raw = unsafe { CoTaskMemAlloc(size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>()) }
            .cast::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>();
        if raw.is_null() {
            free_pwstr(label);
            return Err(Error::from_hresult(E_OUTOFMEMORY));
        }

        // SAFETY: `raw` points at a fresh, correctly sized and aligned
        // allocation that nothing else refers to yet; ownership of it and of
        // `label` passes to LogonUI.
        unsafe { raw.write(descriptor) };
        Ok(raw)
    }

    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut BOOL,
    ) -> WinResult<()> {
        if pdwcount.is_null() || pdwdefault.is_null() || pbautologonwithdefault.is_null() {
            return Err(Error::from_hresult(E_POINTER));
        }

        // SAFETY: checked non-null above; all three are caller-owned slots.
        unsafe { pdwcount.write(1) };
        // SAFETY: as above. No default tile: the engineer chooses Tessera
        // deliberately, exactly as they choose a role.
        unsafe { pdwdefault.write(CREDENTIAL_PROVIDER_NO_DEFAULT) };
        // SAFETY: as above. Nothing is ever submitted without a PIN.
        unsafe { pbautologonwithdefault.write(BOOL::from(false)) };
        Ok(())
    }

    fn GetCredentialAt(&self, dwindex: u32) -> WinResult<ICredentialProviderCredential> {
        if dwindex != 0 {
            return Err(Error::from_hresult(E_INVALIDARG));
        }

        self.with_inner(
            "Provider::GetCredentialAt",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                inner
                    .credential
                    .as_ref()
                    .map(|credential| ICredentialProviderCredential::from(credential.clone()))
                    .ok_or_else(|| Error::from_hresult(E_UNEXPECTED))
            },
        )
    }
}

/// Translates the neutral field kind into the Windows enumeration.
fn field_type(kind: FieldKind) -> CREDENTIAL_PROVIDER_FIELD_TYPE {
    match kind {
        FieldKind::LargeText => CPFT_LARGE_TEXT,
        FieldKind::SmallText => CPFT_SMALL_TEXT,
        FieldKind::ComboBox => CPFT_COMBOBOX,
        FieldKind::PasswordText => CPFT_PASSWORD_TEXT,
        FieldKind::SubmitButton => CPFT_SUBMIT_BUTTON,
    }
}

/// Releases a COM string this module allocated but never handed over.
fn free_pwstr(value: PWSTR) {
    if value.is_null() {
        return;
    }
    // SAFETY: `value` came from `CoTaskMemAlloc` in `wide::alloc_pwstr` and has
    // not been given to anyone else, so this is its only owner.
    unsafe { windows::Win32::System::Com::CoTaskMemFree(Some(value.as_ptr().cast())) };
}

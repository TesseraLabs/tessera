//! `ICredentialProviderCredential2` — the tile itself.
//!
//! Every method here is the same shape: contain panics, take the tile state,
//! translate. The decisions live in [`crate::state`]; what this file adds is
//! the Windows vocabulary — field identifiers, `CPFS_*`/`CPFIS_*` values,
//! COM-allocated strings, and the two-out-parameter shape of
//! `GetSerialization`.
#![allow(unsafe_code)]
// `#[implement]` generates a companion `..._Impl` struct and its vtable glue at
// the span of the attribute: undocumented, `#[inline(always)]`, and casting
// references to raw pointers. None of that can be annotated at its own site, so
// the three lints are relaxed for the file; they stay on for every hand-written
// item in it, and the macro-generated code is not ours to style.
#![allow(missing_docs, clippy::inline_always, clippy::ref_as_ptr)]

use std::cell::RefCell;

use windows::core::{
    implement, Error, IUnknownImpl, Ref, Result as WinResult, BOOL, PCWSTR, PWSTR,
};
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_UNEXPECTED, NTSTATUS};
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::UI::Shell::{
    ICredentialProviderCredential2, ICredentialProviderCredential2_Impl,
    ICredentialProviderCredentialEvents, ICredentialProviderCredential_Impl, CPFIS_DISABLED,
    CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE,
    CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    CREDENTIAL_PROVIDER_STATUS_ICON,
};

use crate::com::{lsa, provider_clsid, wide};
use crate::fields::{interactivity, Field, Interactivity, Visibility};
use crate::kerb::LogonKind;
use crate::method::LoginMethod;
use crate::panic_guard::{guard, PanicFlag};
use crate::service::{PipeConnector, ServiceEngine};
use crate::state::{Submission, TileState, TileStatus};

/// The engine this tile talks to: the real service, over its named pipe.
type TileEngine = ServiceEngine<PipeConnector>;

/// Mutable half of the tile, reached only through the guarded entry points.
struct Inner {
    tile: TileState<TileEngine>,
    events: Option<ICredentialProviderCredentialEvents>,
}

/// The Tessera logon tile.
#[implement(ICredentialProviderCredential2)]
pub struct TesseraCredential {
    panic_flag: PanicFlag,
    inner: RefCell<Inner>,
}

impl TesseraCredential {
    /// Builds a tile for one usage scenario and asks the service for its roles.
    ///
    /// The role list is fetched *here*, before `LogonUI` has seen the tile,
    /// because `LogonUI` reads a combo box's contents when it builds the tile
    /// and does not come back to re-read them. A list filled any later than this
    /// exists only in memory: the screen keeps the empty, disabled box it was
    /// given. Filling it late is possible — [`Self::adopt_late_roles`] does it
    /// through the events interface — but it is the recovery path, not the
    /// normal one.
    ///
    /// The cost is that the logon screen's construction waits for one exchange
    /// with the service. That is why the role list has its own, much shorter
    /// deadline than an authentication: nobody has asked for anything yet, and
    /// a stuck service must not hold up a screen the engineer may want for a
    /// different provider entirely.
    #[must_use]
    pub fn new(kind: LogonKind) -> Self {
        let mut tile = TileState::new(ServiceEngine::new(PipeConnector::default()), kind);
        let filled = tile.ensure_roles();
        tracing::debug!(
            target: "tessera.cp",
            filled,
            roles = tile.roles().len(),
            "tile built"
        );

        Self {
            panic_flag: PanicFlag::new(),
            inner: RefCell::new(Inner { tile, events: None }),
        }
    }
}

impl TesseraCredential_Impl {
    /// Runs `body` against the tile state with panics contained.
    ///
    /// A contained panic does two things: it returns `fallback` to `LogonUI`, and
    /// it drives the tile into its faulted state so that no later call can
    /// serialise anything from state that was interrupted mid-update.
    fn with_tile<T>(
        &self,
        entry: &'static str,
        fallback: T,
        body: impl FnOnce(&mut Inner) -> T,
    ) -> T
    where
        T: Clone,
    {
        let outcome = guard(entry, &self.panic_flag, fallback.clone(), || {
            match self.inner.try_borrow_mut() {
                Ok(mut inner) => body(&mut inner),
                Err(_borrowed) => {
                    // Re-entrancy: LogonUI called back into the tile while a
                    // call was in flight. Refusing is the only safe answer; the
                    // alternative is a borrow panic.
                    tracing::error!(
                        target: "tessera.cp",
                        entry_point = entry,
                        "re-entrant call refused"
                    );
                    fallback.clone()
                }
            }
        });

        if self.panic_flag.is_raised() {
            if let Ok(mut inner) = self.inner.try_borrow_mut() {
                inner.tile.fault();
            }
        }
        outcome
    }

    /// Puts a role list that arrived late onto the screen.
    ///
    /// The tile it is called on has already been drawn with one combo-box item,
    /// the placeholder, so the roles are *appended* after it — which is exactly
    /// the order [`TileState::role_items`] describes. The field is then enabled
    /// and the placeholder re-selected, because the box `LogonUI` drew was
    /// disabled and had nothing else to select.
    ///
    /// Called only when [`TileState::ensure_roles`] reports that this call is
    /// what filled the list. Calling it twice would append the roles twice.
    fn adopt_late_roles(&self, inner: &Inner) {
        let Some(events) = inner.events.as_ref() else {
            // Not advised: nothing to tell. The state is right, and the next
            // enumeration will read it.
            tracing::debug!(
                target: "tessera.cp",
                "roles arrived while LogonUI was not listening; the screen is not updated"
            );
            return;
        };

        let this: ICredentialProviderCredential2 = self.to_interface();
        let field = Field::Role.id();

        for item in inner.tile.role_items().iter().skip(1) {
            let wide: Vec<u16> = item.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: `events` is the interface `LogonUI` handed over in
            // `Advise` and holds a reference to; `this` is this very object;
            // `wide` outlives the call, which copies what it needs.
            let appended =
                unsafe { events.AppendFieldComboBoxItem(&*this, field, PCWSTR(wide.as_ptr())) };
            if let Err(error) = appended {
                tracing::warn!(
                    target: "tessera.cp",
                    error = %error,
                    "a role could not be added to the combo box"
                );
                return;
            }
        }

        // SAFETY: as above; the selection index is one this tile just published.
        let selected = unsafe {
            events.SetFieldComboBoxSelectedItem(
                &*this,
                field,
                u32::try_from(inner.tile.selected_role_item()).unwrap_or(0),
            )
        };
        // SAFETY: as above.
        let enabled = unsafe { events.SetFieldInteractiveState(&*this, field, CPFIS_NONE) };

        if let Err(error) = selected.and(enabled) {
            tracing::warn!(
                target: "tessera.cp",
                error = %error,
                "the role combo box was filled but could not be enabled"
            );
        } else {
            tracing::info!(
                target: "tessera.cp",
                roles = inner.tile.roles().len(),
                "a late role list was put on screen"
            );
        }
    }

    /// Pushes the current status line at `LogonUI`, if it is listening.
    ///
    /// Failures are swallowed on purpose: the status line is a courtesy, and a
    /// tile that cannot draw it is still a tile that refused to serialise.
    fn push_status(&self, inner: &Inner) {
        let Some(events) = inner.events.as_ref() else {
            return;
        };
        let text: Vec<u16> = inner
            .tile
            .status()
            .message()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let this: ICredentialProviderCredential2 = self.to_interface();

        // SAFETY: `events` is a live interface pointer `LogonUI` handed over in
        // `Advise` and holds a reference to; `this` is this very object; `text`
        // outlives the call, which copies what it needs.
        let drawn =
            unsafe { events.SetFieldString(&*this, Field::Status.id(), PCWSTR(text.as_ptr())) };
        if let Err(error) = drawn {
            tracing::debug!(target: "tessera.cp", error = %error, "status line not drawn");
        }
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
impl ICredentialProviderCredential_Impl for TesseraCredential_Impl {
    fn Advise(&self, pcpce: Ref<'_, ICredentialProviderCredentialEvents>) -> WinResult<()> {
        self.with_tile(
            "Credential::Advise",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                inner.events = pcpce.cloned();
                Ok(())
            },
        )
    }

    fn UnAdvise(&self) -> WinResult<()> {
        self.with_tile(
            "Credential::UnAdvise",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                inner.events = None;
                Ok(())
            },
        )
    }

    fn SetSelected(&self) -> WinResult<BOOL> {
        let filled = self.with_tile("Credential::SetSelected", None, |inner| {
            // The list is normally already there, taken when the tile was
            // built. This second attempt is for the one case the first cannot
            // cover: a service that was not answering then and is now.
            Some(inner.tile.ensure_roles())
        });

        match filled {
            Some(true) => {
                // The screen was drawn without these; it has to be told.
                self.with_tile("Credential::SetSelected/roles", (), |inner| {
                    self.adopt_late_roles(inner);
                });
            }
            Some(false) => {
                self.with_tile("Credential::SetSelected/status", (), |inner| {
                    self.push_status(inner);
                });
            }
            None => return Err(Error::from_hresult(E_UNEXPECTED)),
        }

        // Never auto-logon: the engineer picks a role and enters a PIN.
        Ok(BOOL::from(false))
    }

    fn SetDeselected(&self) -> WinResult<()> {
        self.with_tile(
            "Credential::SetDeselected",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                // Leaving the tile wipes the PIN: it has no reason to survive
                // the engineer walking away from it.
                inner.tile.clear_pin();
                Ok(())
            },
        )
    }

    #[expect(
        clippy::similar_names,
        reason = "parameter names are the ones the interface documents"
    )]
    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> WinResult<()> {
        let Some(field) = Field::from_id(dwfieldid) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };
        if pcpfs.is_null() || pcpfis.is_null() {
            return Err(Error::from_hresult(E_INVALIDARG));
        }

        self.with_tile(
            "Credential::GetFieldState",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                let state = match field.visibility() {
                    Visibility::Both => CPFS_DISPLAY_IN_BOTH,
                    Visibility::SelectedOnly => CPFS_DISPLAY_IN_SELECTED_TILE,
                };
                let interactive = match interactivity(field, !inner.tile.roles().is_empty()) {
                    Interactivity::Normal => CPFIS_NONE,
                    Interactivity::Disabled => CPFIS_DISABLED,
                    Interactivity::Focused => CPFIS_FOCUSED,
                };

                // SAFETY: both pointers were checked non-null above and are
                // out-parameters LogonUI sized for exactly these types.
                unsafe { pcpfs.write(state) };
                // SAFETY: as above, for the second out-parameter.
                unsafe { pcpfis.write(interactive) };
                Ok(())
            },
        )
    }

    fn GetStringValue(&self, dwfieldid: u32) -> WinResult<PWSTR> {
        let Some(field) = Field::from_id(dwfieldid) else {
            return Err(Error::from_hresult(E_INVALIDARG));
        };

        self.with_tile(
            "Credential::GetStringValue",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| match field {
                Field::Label => wide::alloc_pwstr(Field::Label.label()),
                Field::Status => wide::alloc_pwstr(inner.tile.status().message()),
                // The PIN is never handed back out, and the two combo boxes
                // report their contents through the combo-box methods.
                Field::Pin | Field::Method | Field::Role | Field::Submit => wide::alloc_pwstr(""),
            },
        )
    }

    fn GetBitmapValue(&self, _dwfieldid: u32) -> WinResult<HBITMAP> {
        // No tile image is declared, so no field can answer with one.
        Err(Error::from_hresult(E_INVALIDARG))
    }

    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> WinResult<()> {
        // No checkbox is declared.
        Err(Error::from_hresult(E_INVALIDARG))
    }

    fn GetSubmitButtonValue(&self, dwfieldid: u32) -> WinResult<u32> {
        if Field::from_id(dwfieldid) == Some(Field::Submit) {
            // The button belongs next to the PIN box, which is what makes
            // Enter in that box submit the tile.
            Ok(Field::Pin.id())
        } else {
            Err(Error::from_hresult(E_INVALIDARG))
        }
    }

    fn GetComboBoxValueCount(
        &self,
        dwfieldid: u32,
        pcitems: *mut u32,
        pdwselecteditem: *mut u32,
    ) -> WinResult<()> {
        let field = Field::from_id(dwfieldid);
        if pcitems.is_null() || pdwselecteditem.is_null() {
            return Err(Error::from_hresult(E_INVALIDARG));
        }

        self.with_tile(
            "Credential::GetComboBoxValueCount",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                let (count, selected) = match field {
                    Some(Field::Method) => (LoginMethod::ALL.len(), inner.tile.method().index()),
                    Some(Field::Role) => (
                        inner.tile.role_items().len(),
                        inner.tile.selected_role_item(),
                    ),
                    _ => return Err(Error::from_hresult(E_INVALIDARG)),
                };

                // SAFETY: checked non-null above; LogonUI owns both slots.
                unsafe { pcitems.write(u32::try_from(count).unwrap_or(0)) };
                // SAFETY: as above, for the second out-parameter.
                unsafe { pdwselecteditem.write(u32::try_from(selected).unwrap_or(0)) };
                Ok(())
            },
        )
    }

    fn GetComboBoxValueAt(&self, dwfieldid: u32, dwitem: u32) -> WinResult<PWSTR> {
        let field = Field::from_id(dwfieldid);
        let item = usize::try_from(dwitem).unwrap_or(usize::MAX);

        self.with_tile(
            "Credential::GetComboBoxValueAt",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| match field {
                Some(Field::Method) => LoginMethod::from_index(item)
                    .ok_or_else(|| Error::from_hresult(E_INVALIDARG))
                    .and_then(|method| wide::alloc_pwstr(method.label())),
                Some(Field::Role) => inner
                    .tile
                    .role_items()
                    .get(item)
                    .ok_or_else(|| Error::from_hresult(E_INVALIDARG))
                    .and_then(|label| wide::alloc_pwstr(label)),
                _ => Err(Error::from_hresult(E_INVALIDARG)),
            },
        )
    }

    fn SetStringValue(&self, dwfieldid: u32, psz: &PCWSTR) -> WinResult<()> {
        if Field::from_id(dwfieldid) != Some(Field::Pin) {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        // SAFETY: `psz` is an in-parameter of the COM call: LogonUI guarantees
        // a NUL-terminated string valid for the duration of the call.
        let pin = unsafe { wide::read_pcwstr(*psz) };

        self.with_tile(
            "Credential::SetStringValue",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                inner.tile.set_pin(&pin);
                Ok(())
            },
        )
    }

    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> WinResult<()> {
        Err(Error::from_hresult(E_INVALIDARG))
    }

    fn SetComboBoxSelectedValue(&self, dwfieldid: u32, dwselecteditem: u32) -> WinResult<()> {
        let field = Field::from_id(dwfieldid);
        let item = usize::try_from(dwselecteditem).unwrap_or(usize::MAX);

        self.with_tile(
            "Credential::SetComboBoxSelectedValue",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                let accepted = match field {
                    Some(Field::Method) => inner.tile.select_method(item),
                    Some(Field::Role) => inner.tile.select_role_item(item),
                    _ => return Err(Error::from_hresult(E_INVALIDARG)),
                };
                if !accepted {
                    // A refused selection is not a COM failure — the tile keeps
                    // the previous choice and says why in its status line.
                    self.push_status(inner);
                }
                Ok(())
            },
        )
    }

    fn CommandLinkClicked(&self, _dwfieldid: u32) -> WinResult<()> {
        // No command link is declared.
        Err(Error::from_hresult(E_INVALIDARG))
    }

    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> WinResult<()> {
        if pcpgsr.is_null() || pcpcs.is_null() {
            return Err(Error::from_hresult(E_INVALIDARG));
        }

        self.with_tile(
            "Credential::GetSerialization",
            Err(Error::from_hresult(E_UNEXPECTED)),
            |inner| {
                let outcome = inner.tile.submit();
                match outcome {
                    Submission::NotFinished => {
                        // Fail-closed: nothing is serialized, the engineer is
                        // told why, and every other provider on the screen is
                        // untouched.
                        // SAFETY: checked non-null above.
                        unsafe { pcpgsr.write(CPGSR_NO_CREDENTIAL_NOT_FINISHED) };
                        write_status_text(
                            ppszoptionalstatustext,
                            pcpsioptionalstatusicon,
                            inner.tile.status(),
                        );
                        self.push_status(inner);
                        Ok(())
                    }
                    Submission::Serialize(blob) => {
                        // A grant that cannot be turned into a block is still a
                        // logon that does not happen, and it is reported the
                        // same way as any other refusal rather than as a COM
                        // failure with no explanation on screen.
                        let prepared = lsa::negotiate_package()
                            .and_then(|package| Ok((package, wide::alloc_bytes(&blob)?)));
                        let (package, bytes) = match prepared {
                            Ok(pair) => pair,
                            Err(error) => {
                                tracing::error!(
                                    target: "tessera.cp",
                                    error = %error,
                                    "granted credentials could not be handed to LogonUI"
                                );
                                inner.tile.fail_serialization();
                                // SAFETY: checked non-null above.
                                unsafe { pcpgsr.write(CPGSR_NO_CREDENTIAL_NOT_FINISHED) };
                                write_status_text(
                                    ppszoptionalstatustext,
                                    pcpsioptionalstatusicon,
                                    inner.tile.status(),
                                );
                                self.push_status(inner);
                                return Ok(());
                            }
                        };
                        let length = u32::try_from(blob.len()).unwrap_or(0);
                        // `blob` is dropped — and wiped — as this scope ends;
                        // the only remaining copy is the one LogonUI frees.

                        let serialization = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
                            ulAuthenticationPackage: package,
                            clsidCredentialProvider: provider_clsid(),
                            cbSerialization: length,
                            rgbSerialization: bytes,
                        };

                        // SAFETY: checked non-null above; LogonUI owns the slot
                        // and takes ownership of `bytes` with it.
                        unsafe { pcpcs.write(serialization) };
                        // SAFETY: checked non-null above.
                        unsafe { pcpgsr.write(CPGSR_RETURN_CREDENTIAL_FINISHED) };
                        Ok(())
                    }
                }
            },
        )
    }

    fn ReportResult(
        &self,
        _ntsstatus: NTSTATUS,
        _ntssubstatus: NTSTATUS,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> WinResult<()> {
        // Winlogon's own verdict on the technical account's logon is not
        // something this tile translates: the decision that mattered was the
        // engine's, and it was made before serialization.
        Err(Error::from_hresult(E_NOTIMPL))
    }
}

impl ICredentialProviderCredential2_Impl for TesseraCredential_Impl {
    fn GetUserSid(&self) -> WinResult<PWSTR> {
        // The tile is not associated with an existing user tile: the account it
        // ends up serializing is the technical one, which the engineer neither
        // picks nor sees. A null SID is how that is expressed.
        Ok(PWSTR::null())
    }
}

/// Fills the optional status out-parameters of `GetSerialization`.
///
/// `LogonUI` frees the string; the icon marks it as a failure rather than
/// informational text.
fn write_status_text(
    text_out: *mut PWSTR,
    icon_out: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    status: TileStatus,
) {
    if text_out.is_null() {
        return;
    }
    let Ok(text) = wide::alloc_pwstr(status.message()) else {
        return;
    };

    // SAFETY: checked non-null above; the slot belongs to LogonUI, which frees
    // what is written into it.
    unsafe { text_out.write(text) };

    if !icon_out.is_null() {
        // SAFETY: checked non-null immediately above.
        unsafe { icon_out.write(CPSI_ERROR) };
    }
}

/// Builds the tile as a COM interface for the provider to hand out.
#[must_use]
pub fn new_credential(kind: LogonKind) -> ICredentialProviderCredential2 {
    TesseraCredential::new(kind).into()
}

//! Lookup of the authentication package the serialized credentials belong to.
//!
//! `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION` carries a package identifier,
//! and that identifier is per-boot: it has to be asked for rather than
//! hard-coded. Asking is all that happens here — `LsaConnectUntrusted` opens an
//! *untrusted* connection, which can enumerate packages and nothing else. No
//! logon is performed by this crate; `Winlogon` does that with the block the tile
//! returns.
#![allow(unsafe_code)]

use windows::core::{Error, Result as WinResult, PSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::Authentication::Identity::{
    LsaConnectUntrusted, LsaLookupAuthenticationPackage, LSA_STRING,
};

/// Name of the package that negotiates between Kerberos and NTLM. It is what
/// interactive logon uses, and it is what a local account resolves through.
///
/// NUL-terminated because `LSA_STRING::MaximumLength` counts the terminator.
const NEGOTIATE: &[u8] = b"Negotiate\0";

/// `LSA_STRING::Length` — the name without its terminator.
const NEGOTIATE_LENGTH: u16 = 9;

/// Asks LSA for the identifier of the `Negotiate` authentication package.
///
/// # Errors
///
/// The `NTSTATUS` of whichever LSA call failed, converted to an `HRESULT`.
pub fn negotiate_package() -> WinResult<u32> {
    let mut lsa = HANDLE::default();

    // SAFETY: `lsa` is a live, properly aligned `HANDLE` this call fills in.
    let status = unsafe { LsaConnectUntrusted(&raw mut lsa) };
    if status.is_err() {
        return Err(Error::from_hresult(status.to_hresult()));
    }

    let name = LSA_STRING {
        Length: NEGOTIATE_LENGTH,
        MaximumLength: NEGOTIATE_LENGTH + 1,
        Buffer: PSTR(NEGOTIATE.as_ptr().cast_mut()),
    };
    let mut package = 0u32;

    // SAFETY: `lsa` is the handle just opened; `name` borrows a `'static`
    // byte string that outlives the call; `package` is a live `u32`.
    let status = unsafe { LsaLookupAuthenticationPackage(lsa, &raw const name, &raw mut package) };

    // SAFETY: `lsa` was opened by `LsaConnectUntrusted` above and is not used
    // after this point. `LsaDeregisterLogonProcess` is for *trusted*
    // connections; an untrusted one is closed with `CloseHandle`.
    if let Err(error) = unsafe { CloseHandle(lsa) } {
        tracing::debug!(target: "tessera.cp", error = %error, "closing the LSA handle failed");
    }

    if status.is_err() {
        return Err(Error::from_hresult(status.to_hresult()));
    }
    Ok(package)
}

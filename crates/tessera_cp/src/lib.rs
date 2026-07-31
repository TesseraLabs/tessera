//! Credential Provider for the Windows logon screen.
//!
//! The provider is the UI half of the Windows adapter. It declares a logon tile
//! and its fields, collects what the engineer types, asks the engine service
//! for a verdict, and — only after a grant — serialises the credentials of the
//! technical account that `Winlogon` then uses through the ordinary path.
//!
//! # Boundary
//!
//! The contract of this crate is defined as much by what it must *not* do:
//!
//! * no enforcement and no token surgery — nothing here calls `LsaLogonUser`,
//!   `SetTokenInformation`, `CreateRestrictedToken` or `AdjustTokenPrivileges`;
//! * no reading of local Tessera state — the role list, the configuration and
//!   the journal are the service's business, and the only inputs this crate has
//!   are the engineer's typing and the service's replies;
//! * no cryptography of trust — chain validation, challenge-response and
//!   revocation happen behind [`EngineClient`], never here.
//!
//! Everything that fails — an unavailable service, a dropped pipe, a protocol
//! version that does not match, a refusal — ends in the same place: a status
//! line on the tile and no serialization. The standard Windows providers are
//! untouched in every one of those cases; this provider cannot block another
//! tile's logon.
//!
//! # Layout
//!
//! The COM surface is a thin shell over platform-neutral modules, which is what
//! makes the interesting half testable on a developer machine that has no COM
//! at all:
//!
//! * [`fields`] — the tile's field table (identifiers, kinds, visibility);
//! * [`method`] and [`role`] — the two combo boxes' contents;
//! * [`engine`] — the trait the service sits behind;
//! * [`service`] — that trait over the named pipe, under a deadline;
//! * [`logging`] — the file the provider's diagnostics go to, since nothing
//!   inside `LogonUI` collects them;
//! * [`state`] — the tile state machine, including what happens on a verdict;
//! * [`kerb`] — packing of `KERB_INTERACTIVE_UNLOCK_LOGON`;
//! * [`panic_guard`] — containment of panics at every COM entry point;
//! * `com` (Windows only) — `ICredentialProvider` and
//!   `ICredentialProviderCredential2`, plus the in-process server exports.
//!
//! [`EngineClient`]: engine::EngineClient

pub mod engine;
pub mod fields;
pub mod kerb;
pub mod logging;
pub mod method;
pub mod panic_guard;
pub mod role;
pub mod service;
pub mod state;

#[cfg(windows)]
pub mod com;

/// Class identifier of the credential provider's COM server.
///
/// Registration writes it twice — once as the COM server under
/// `HKCR\CLSID\{CLSID}\InprocServer32`, once as an enrolled provider under
/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`;
/// see `scripts/register-cp.ps1`. The value is fixed for the product: changing
/// it orphans every existing registration.
pub const PROVIDER_CLSID: &str = "{D88A8B6F-ECE6-4A9D-B6A6-1C30562C0448}";

/// The same identifier in binary form, for building a `GUID`.
///
/// Kept beside the textual form rather than derived from it so that the COM
/// layer needs no parsing, and held to it by a test that runs everywhere.
pub const PROVIDER_CLSID_U128: u128 = 0xd88a_8b6f_ece6_4a9d_b6a6_1c30_562c_0448;

/// Display name of the provider as registered in the system.
pub const PROVIDER_NAME: &str = "Tessera Credential Provider";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_two_forms_of_the_clsid_agree() {
        let digits: String = PROVIDER_CLSID
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect();
        assert_eq!(digits.len(), 32, "a CLSID is 32 hex digits");
        assert_eq!(
            u128::from_str_radix(&digits, 16).unwrap(),
            PROVIDER_CLSID_U128
        );
    }
}

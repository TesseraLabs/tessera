//! The boundary between Windows' own principals and accounts that may act as
//! roles.
//!
//! The Unix side of this question is a uid range: an account below `UID_MIN`
//! or inside the block reserved at the top of the uid space belongs to the
//! system, and a login into it would hand the role's rights to an identity
//! daemons already share. Windows draws the same line, but not with numbers a
//! range can bracket — it names its own principals with **well-known SIDs**
//! (`LocalSystem` is `S-1-5-18` everywhere, `BUILTIN\Administrators` is
//! `S-1-5-32-544`) and gives the accounts it creates for itself a RID below
//! 1000 inside the machine's own account domain.
//!
//! So the rule stated here is:
//!
//! * a name Windows resolves to one of its own well-known SIDs is refused —
//!   whatever it is called on a localized system, and whether it is a user, a
//!   service principal or a built-in group;
//! * a name the machine's local account database holds is admitted only when
//!   its SID is an account SID of *this machine* whose RID is at or above
//!   [`FIRST_REGULAR_RID`];
//! * everything else — a name qualified with a domain or another authority, a
//!   SID that is not machine-local, a lookup that fails — is refused. The class
//!   of the account is then unknown, and an unknown class is not a regular one.
//!
//! # Why the resolution never leaves the machine
//!
//! `LookupAccountNameW` falls back to a domain controller for a name the local
//! system cannot resolve. On a domain-joined device that turns a question asked
//! before any credential is presented into a network round trip — and, worse,
//! lets the answer come from a directory that is not the authority over the
//! sessions this device opens. The lookup here is therefore built from two
//! sources that only read local state: the well-known SIDs the system defines
//! for itself, and the local account database (`NetUserGetInfo` against the
//! local SAM). A name neither of them knows is refused, not chased.
//!
//! # What is testable where
//!
//! The rules above are stated over a resolved SID in string form, so they hold
//! still on any platform and are exercised with a stand-in source. Only the
//! source that asks Windows itself is Windows-only, and only its behaviour is
//! left to the bench.

use std::fmt;

/// Lowest RID an account created on this machine can carry.
///
/// Windows allocates RIDs for locally created accounts from 1000 upwards and
/// keeps everything below for the accounts it creates itself: `Administrator`
/// is 500, `Guest` 501, `krbtgt` 502, `DefaultAccount` 503 and
/// `WDAGUtilityAccount` 504, with the rest of the block reserved. The boundary
/// is the Windows counterpart of the uid boundary the Unix path applies, and it
/// is a compiled-in constant for the same reason: a login-time dependency on a
/// value the machine can edit would be a way to widen the gate.
pub const FIRST_REGULAR_RID: u32 = 1000;

/// The NT identifier authority — the `5` in `S-1-5-…`.
///
/// Every account SID Windows issues for a machine or a domain sits under it;
/// the other authorities describe things that are not accounts at all (`S-1-1-0`
/// is `Everyone`, `S-1-16-…` an integrity label).
const NT_AUTHORITY: u64 = 5;

/// `SECURITY_NT_NON_UNIQUE`: the first sub-authority of a machine or domain
/// account SID, the one that introduces the three-part domain identifier.
///
/// Requiring it is what separates an account of this machine from the service
/// and built-in principals that live directly under the NT authority
/// (`S-1-5-18`, `S-1-5-32-544`, `S-1-5-80-…`).
const NON_UNIQUE_AUTHORITY: u32 = 21;

/// How many sub-authorities an account SID carries: the `21` marker, the three
/// parts of the domain identifier, and the RID.
const ACCOUNT_SUBAUTHORITIES: usize = 5;

/// Why a login name cannot be used as a role on this device.
///
/// The reasons stay apart rather than collapsing into one refusal: an operator
/// reading the log has to be able to tell "this is the machine's own principal"
/// from "this machine has no such account" from "the account database could not
/// be asked", and only the last of the three is a fault to chase.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WindowsAccountError {
    /// The name is qualified with a domain, a machine or a UPN suffix.
    ///
    /// Refused without asking anyone: resolving it is exactly the round trip to
    /// a domain controller this module does not make, and a domain principal is
    /// not an account of this device in the first place.
    #[error(
        "account `{account}` names a domain or another machine; \
         only accounts of this device can be roles"
    )]
    Qualified {
        /// The login name as it was given.
        account: String,
    },

    /// The name resolves to a principal Windows defines for itself.
    #[error(
        "account `{account}` is a principal Windows defines for itself \
         (well-known SID {sid}) and cannot be a role"
    )]
    WellKnownPrincipal {
        /// The login name.
        account: String,
        /// The well-known SID it resolved to, in string form.
        sid: String,
    },

    /// The account exists on this device but Windows created it for itself.
    #[error(
        "account `{account}` is built into this device \
         (SID {sid}, RID below {first_regular_rid}) and cannot be a role"
    )]
    BuiltInAccount {
        /// The login name.
        account: String,
        /// The account's SID, in string form.
        sid: String,
        /// The boundary applied ([`FIRST_REGULAR_RID`]).
        first_regular_rid: u32,
    },

    /// The account database answered with a SID that is not an account SID of
    /// this machine — another authority, or a principal that is not an account.
    #[error("account `{account}` does not carry an account SID of this device (SID {sid})")]
    NotLocalAccount {
        /// The login name.
        account: String,
        /// The SID as the account database gave it.
        sid: String,
    },

    /// This device has no such account.
    ///
    /// Distinct from every other refusal: nothing failed, the machine simply
    /// does not know the name, and no directory was asked on its behalf.
    #[error("account `{account}` is not an account of this device")]
    NoLocalAccount {
        /// The login name.
        account: String,
    },

    /// The account database could not be consulted, so the class stays unknown.
    #[error("cannot establish whether `{account}` is one of this device's own accounts: {source}")]
    LookupFailed {
        /// The login name.
        account: String,
        /// What the operating system said.
        source: AccountSourceError,
    },
}

/// A failure of the operating system to answer the account question.
///
/// Carries the call that failed and the code it returned, because those are the
/// two facts that make such a failure actionable and neither survives being
/// flattened into a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSourceError {
    /// The Win32 or network-management call that failed.
    pub api: &'static str,
    /// The status the call returned.
    pub code: u32,
}

impl fmt::Display for AccountSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed with status {}", self.api, self.code)
    }
}

impl std::error::Error for AccountSourceError {}

/// Where the answers about a login name come from.
///
/// A trait so the rules can be exercised without Windows: the production
/// implementation reads local system state and cannot run anywhere else, while
/// the rules themselves have nothing platform-specific left in them once the
/// SID is a string.
pub trait AccountSource {
    /// The well-known SID `account` names, if it names one of the principals
    /// Windows defines for itself.
    ///
    /// Answering here is the one thing that can only *add* a refusal: a name
    /// this source does not recognise still has to clear the local account
    /// database below, so a source that recognises nothing at all refuses
    /// everything the machine does not hold as an account.
    fn well_known_principal(&self, account: &str) -> Option<String>;

    /// The SID of the local account named `account`, in string form.
    ///
    /// `Ok(None)` means the local account database has no such account —
    /// nothing failed. The local database is the *only* thing consulted; no
    /// domain controller is asked on this call.
    ///
    /// # Errors
    ///
    /// [`AccountSourceError`] when the database could not be read at all, which
    /// leaves the account's class unknown.
    fn local_account_sid(&self, account: &str) -> Result<Option<String>, AccountSourceError>;
}

/// Decide whether `account` may act as a role on this device.
///
/// # Errors
///
/// One of the [`WindowsAccountError`] variants; every one of them is a refusal,
/// and there is no path through this function that admits an account whose
/// class could not be established.
pub fn classify<S: AccountSource + ?Sized>(
    source: &S,
    account: &str,
) -> Result<(), WindowsAccountError> {
    if account.is_empty() || account.contains(['\\', '/', '@']) {
        return Err(WindowsAccountError::Qualified {
            account: account.to_owned(),
        });
    }

    if let Some(sid) = source.well_known_principal(account) {
        return Err(WindowsAccountError::WellKnownPrincipal {
            account: account.to_owned(),
            sid,
        });
    }

    let sid = match source.local_account_sid(account) {
        Ok(Some(sid)) => sid,
        Ok(None) => {
            return Err(WindowsAccountError::NoLocalAccount {
                account: account.to_owned(),
            })
        }
        Err(source) => {
            return Err(WindowsAccountError::LookupFailed {
                account: account.to_owned(),
                source,
            })
        }
    };

    let Some(rid) = machine_account_rid(&sid) else {
        return Err(WindowsAccountError::NotLocalAccount {
            account: account.to_owned(),
            sid,
        });
    };
    if rid < FIRST_REGULAR_RID {
        return Err(WindowsAccountError::BuiltInAccount {
            account: account.to_owned(),
            sid,
            first_regular_rid: FIRST_REGULAR_RID,
        });
    }
    Ok(())
}

/// The RID of `sid` when it is an account SID of a machine or domain, `None`
/// otherwise.
///
/// The shape being insisted on is `S-1-5-21-<a>-<b>-<c>-<rid>`. Anything
/// shorter or under another authority is a principal rather than an account —
/// `S-1-5-18` (`LocalSystem`), `S-1-5-32-544` (`BUILTIN\Administrators`),
/// `S-1-5-80-…` (a service) — and a check that read a RID out of those would
/// be reading the last number of something that has no RID.
fn machine_account_rid(sid: &str) -> Option<u32> {
    let parsed = parse_sid(sid)?;
    if parsed.authority != NT_AUTHORITY
        || parsed.sub_authorities.len() != ACCOUNT_SUBAUTHORITIES
        || parsed.sub_authorities.first() != Some(&NON_UNIQUE_AUTHORITY)
    {
        return None;
    }
    parsed.sub_authorities.last().copied()
}

/// A SID taken apart far enough to answer the questions above.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSid {
    /// The identifier authority — the `5` in `S-1-5-…`.
    authority: u64,
    /// The sub-authorities, in the order they are written.
    sub_authorities: Vec<u32>,
}

/// Parse the string form of a SID, `S-<revision>-<authority>-<sub>…`.
///
/// The string form is what `ConvertSidToStringSidW` produces, and parsing it
/// here rather than walking the binary SID keeps every rule above on the safe
/// side of the FFI boundary.
///
/// Only revision 1 is accepted: it is the only revision defined, and a SID
/// claiming another one is not something to guess at on a login path. The
/// identifier authority is written in decimal when it fits in 32 bits and as
/// `0x…` (12 hex digits) when it does not — both forms are read, because the
/// hexadecimal one is what the SIDs above `S-1-4294967295` are printed as and
/// silently failing to parse them would turn "not an account SID" into "not a
/// SID at all".
fn parse_sid(text: &str) -> Option<ParsedSid> {
    let mut parts = text.split('-');
    if !parts.next()?.eq_ignore_ascii_case("S") {
        return None;
    }
    if parts.next()?.parse::<u8>().ok()? != 1 {
        return None;
    }
    let authority_text = parts.next()?;
    let authority = match authority_text
        .strip_prefix("0x")
        .or_else(|| authority_text.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => authority_text.parse::<u64>().ok()?,
    };
    // A 48-bit field: anything wider was never written by Windows.
    if authority > 0x0000_FFFF_FFFF_FFFF {
        return None;
    }

    let mut sub_authorities = Vec::new();
    for part in parts {
        sub_authorities.push(part.parse::<u32>().ok()?);
    }
    // A SID always carries at least one sub-authority; SIDs with none are
    // written by nothing this code will ever be handed.
    if sub_authorities.is_empty() || sub_authorities.len() > 15 {
        return None;
    }
    Some(ParsedSid {
        authority,
        sub_authorities,
    })
}

#[cfg(windows)]
pub use os::OsAccounts;

#[cfg(windows)]
mod os {
    //! The source that asks this machine, and nothing beyond it.
    //!
    //! # FFI
    //!
    //! All raw Win32 calls live here so the rest of the crate stays under
    //! `unsafe_code = "deny"`. Every `unsafe` block wraps exactly one call and
    //! carries the reasoning that makes it sound.
    #![allow(unsafe_code)]

    use std::ffi::c_void;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::ptr;
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{LocalFree, ERROR_NONE_MAPPED, HLOCAL};
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NERR_UserNotFound, NetApiBufferFree, NetUserGetInfo, USER_INFO_4,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountSidW, SID_NAME_USE, WELL_KNOWN_SID_TYPE,
    };

    use super::{AccountSource, AccountSourceError};

    /// Highest `WELL_KNOWN_SID_TYPE` this build knows about.
    ///
    /// The enumeration is walked rather than curated: every value Windows
    /// defines is asked about, so the refusal covers the principals this code
    /// has never heard of as well as the obvious ones. A value the running
    /// system does not know simply fails to produce a SID and is skipped, which
    /// is why the bound may sit above what any one Windows version defines.
    const MAX_WELL_KNOWN_SID_TYPE: WELL_KNOWN_SID_TYPE = 130;

    /// Bytes reserved for a SID: `SECURITY_MAX_SID_SIZE` is 68, and the buffer
    /// is fixed so no allocation is made inside the FFI wrapper.
    const MAX_SID_BYTES: usize = 68;

    /// Characters reserved for an account or domain name. Windows caps account
    /// names at 20 and domain names at 255; the buffer holds both with room to
    /// spare, and an answer that would not fit is skipped rather than retried.
    const NAME_CHARS: u32 = 512;

    /// `NetUserGetInfo` level 4 — the level whose record carries the account's
    /// SID.
    const USER_INFO_LEVEL_SID: u32 = 4;

    /// The names of the principals Windows defines for itself, lowercased,
    /// paired with the well-known SID each one resolves to.
    ///
    /// Built once: the table is the same for the life of the machine, and the
    /// walk behind it costs one lookup per defined well-known SID. A login must
    /// not pay that more than once in a resident process.
    static WELL_KNOWN_NAMES: OnceLock<Vec<(String, String)>> = OnceLock::new();

    /// This machine's own account view: well-known SIDs plus the local account
    /// database.
    ///
    /// A unit struct rather than a handle: both sources are consulted by name
    /// at the moment the question is asked, and there is nothing to keep open
    /// between two logins.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct OsAccounts;

    impl AccountSource for OsAccounts {
        fn well_known_principal(&self, account: &str) -> Option<String> {
            let table = WELL_KNOWN_NAMES.get_or_init(build_well_known_table);
            let wanted = account.to_lowercase();
            table
                .iter()
                .find(|(name, _)| *name == wanted)
                .map(|(_, sid)| sid.clone())
        }

        fn local_account_sid(&self, account: &str) -> Result<Option<String>, AccountSourceError> {
            let name = wide(account);
            let mut buffer: *mut u8 = ptr::null_mut();
            // SAFETY: `name` is a NUL-terminated UTF-16 buffer owned by this
            // frame; a NULL server name reads this machine's own account
            // database. `buffer` receives an allocation the callee owns, freed
            // through `NetApiBufferFree` below on every path.
            let status = unsafe {
                NetUserGetInfo(
                    ptr::null(),
                    name.as_ptr(),
                    USER_INFO_LEVEL_SID,
                    ptr::addr_of_mut!(buffer),
                )
            };
            if status == NERR_UserNotFound || status == ERROR_NONE_MAPPED {
                return Ok(None);
            }
            if status != 0 {
                return Err(AccountSourceError {
                    api: "NetUserGetInfo",
                    code: status,
                });
            }
            if buffer.is_null() {
                // A success that produced no record: nothing to read, and
                // guessing at the account's class is the one thing this module
                // never does.
                return Err(AccountSourceError {
                    api: "NetUserGetInfo",
                    code: 0,
                });
            }

            // SAFETY: the call above succeeded at level 4, so the buffer holds
            // one `USER_INFO_4` record; it is read once and not retained.
            let info = unsafe { buffer.cast::<USER_INFO_4>().read_unaligned() };
            let sid = sid_to_string(info.usri4_user_sid.cast::<c_void>());
            // SAFETY: `buffer` is the allocation `NetUserGetInfo` made and it
            // has not been freed on this path; every pointer read out of the
            // record has already been copied into owned memory above.
            unsafe { NetApiBufferFree(buffer.cast::<c_void>()) };

            match sid {
                Some(sid) => Ok(Some(sid)),
                None => Err(AccountSourceError {
                    api: "ConvertSidToStringSid",
                    code: 0,
                }),
            }
        }
    }

    /// Resolve every well-known SID this system defines to the name it is known
    /// by here.
    ///
    /// Localized systems name these principals in their own language, so the
    /// names are asked of the system rather than compiled in — a table of
    /// English names would recognise nothing on a Russian Windows, which is the
    /// installation this product is built for.
    ///
    /// Domain-relative well-known SIDs (`Domain Admins` and its siblings) need
    /// a domain SID to be built at all and are skipped here: a name in a domain
    /// is refused before this table is ever consulted.
    fn build_well_known_table() -> Vec<(String, String)> {
        let mut table = Vec::new();
        for kind in 1..=MAX_WELL_KNOWN_SID_TYPE {
            let Some(sid) = well_known_sid(kind) else {
                continue;
            };
            let Some(name) = account_name_for_sid(sid.as_ptr().cast::<c_void>()) else {
                continue;
            };
            let Some(text) = sid_to_string(sid.as_ptr().cast::<c_void>()) else {
                continue;
            };
            table.push((name.to_lowercase(), text));
        }
        table
    }

    /// The binary form of one well-known SID, or `None` when this system does
    /// not define it without a domain.
    fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Option<[u8; MAX_SID_BYTES]> {
        let mut sid = [0u8; MAX_SID_BYTES];
        let mut len = u32::try_from(MAX_SID_BYTES).ok()?;
        // SAFETY: `sid` is a live buffer of exactly `len` bytes and the callee
        // writes no further; a NULL domain SID asks for the domain-independent
        // form, which fails cleanly for the types that need a domain.
        let ok = unsafe {
            CreateWellKnownSid(
                kind,
                ptr::null_mut(),
                sid.as_mut_ptr().cast::<c_void>(),
                ptr::addr_of_mut!(len),
            )
        };
        (ok != 0).then_some(sid)
    }

    /// The name this system knows `sid` by, without its domain part.
    fn account_name_for_sid(sid: *const c_void) -> Option<String> {
        let mut name = [0u16; NAME_CHARS as usize];
        let mut name_len = NAME_CHARS;
        let mut domain = [0u16; NAME_CHARS as usize];
        let mut domain_len = NAME_CHARS;
        let mut use_kind: SID_NAME_USE = 0;
        // SAFETY: `sid` points at a SID built above and still in scope; both
        // buffers are live and exactly as long as the counts passed with them.
        // A NULL system name resolves on this machine, which is where every SID
        // handed to this function is defined.
        let ok = unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid.cast_mut(),
                name.as_mut_ptr(),
                ptr::addr_of_mut!(name_len),
                domain.as_mut_ptr(),
                ptr::addr_of_mut!(domain_len),
                ptr::addr_of_mut!(use_kind),
            )
        };
        if ok == 0 {
            return None;
        }
        // The callee sets `name_len` to the characters it wrote, excluding the
        // terminator; a count that does not fit the buffer would mean the call
        // both succeeded and overran, so the answer is dropped rather than
        // trusted.
        from_wide(name.get(..name_len as usize)?)
    }

    /// The string form of a SID, or `None` when it could not be converted.
    fn sid_to_string(sid: *const c_void) -> Option<String> {
        if sid.is_null() {
            return None;
        }
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `sid` is a valid SID for the duration of the call; the callee
        // allocates the string and hands over ownership, released below.
        let ok = unsafe { ConvertSidToStringSidW(sid.cast_mut(), ptr::addr_of_mut!(text)) };
        if ok == 0 || text.is_null() {
            return None;
        }
        // SAFETY: `text` is the NUL-terminated buffer the call just allocated.
        let owned = unsafe { string_from_ptr(text) };
        // SAFETY: `text` came from `ConvertSidToStringSidW`, which documents
        // `LocalFree` as its release, and nothing else holds it.
        unsafe { LocalFree(text.cast::<c_void>() as HLOCAL) };
        owned
    }

    /// Copy a NUL-terminated UTF-16 string out of a pointer the system owns.
    ///
    /// # Safety
    ///
    /// `text` must point at a NUL-terminated UTF-16 buffer that stays valid for
    /// the duration of the call.
    unsafe fn string_from_ptr(text: *const u16) -> Option<String> {
        let mut len = 0usize;
        loop {
            // SAFETY: the caller guarantees a NUL-terminated buffer, so every
            // offset up to and including the terminator is inside it.
            let cell = unsafe { text.add(len) };
            // SAFETY: `cell` is that offset, and it is read once.
            if unsafe { *cell } == 0 {
                break;
            }
            len += 1;
        }
        // SAFETY: `len` is the length just measured, so the slice stays inside
        // the buffer the caller vouched for.
        let slice = unsafe { std::slice::from_raw_parts(text, len) };
        from_wide(slice)
    }

    /// A UTF-16 slice as a `String`, or `None` when it is not valid UTF-16.
    fn from_wide(chars: &[u16]) -> Option<String> {
        std::ffi::OsString::from_wide(chars).into_string().ok()
    }

    /// A NUL-terminated UTF-16 copy of `text`, for the Win32 calls above.
    fn wide(text: &str) -> Vec<u16> {
        std::ffi::OsStr::new(text)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::missing_docs_in_private_items
    )]

    use super::*;

    /// A source whose answers the test states outright, so the rules are what
    /// is being exercised and not the machine the tests run on.
    struct FakeSource {
        /// Names the system claims as its own, with the SID each resolves to.
        well_known: Vec<(String, String)>,
        /// The local account database: name to SID.
        local: Vec<(String, String)>,
        /// When set, the local database refuses to answer at all.
        failure: Option<AccountSourceError>,
    }

    impl FakeSource {
        fn new() -> Self {
            Self {
                well_known: Vec::new(),
                local: Vec::new(),
                failure: None,
            }
        }

        fn with_well_known(mut self, name: &str, sid: &str) -> Self {
            self.well_known.push((name.to_owned(), sid.to_owned()));
            self
        }

        fn with_local(mut self, name: &str, sid: &str) -> Self {
            self.local.push((name.to_owned(), sid.to_owned()));
            self
        }

        fn failing(mut self, error: AccountSourceError) -> Self {
            self.failure = Some(error);
            self
        }
    }

    impl AccountSource for FakeSource {
        fn well_known_principal(&self, account: &str) -> Option<String> {
            let wanted = account.to_lowercase();
            self.well_known
                .iter()
                .find(|(name, _)| name.to_lowercase() == wanted)
                .map(|(_, sid)| sid.clone())
        }

        fn local_account_sid(&self, account: &str) -> Result<Option<String>, AccountSourceError> {
            if let Some(error) = self.failure.clone() {
                return Err(error);
            }
            Ok(self
                .local
                .iter()
                .find(|(name, _)| name == account)
                .map(|(_, sid)| sid.clone()))
        }
    }

    /// A SID of this machine's own account domain, with the RID appended.
    fn machine_sid(rid: u32) -> String {
        format!("S-1-5-21-1004336348-1177238915-682003330-{rid}")
    }

    #[test]
    fn ordinary_local_account_is_admitted() {
        let source = FakeSource::new().with_local("engineer", &machine_sid(1001));
        classify(&source, "engineer").expect("a local account above the RID boundary is regular");
    }

    #[test]
    fn built_in_account_is_refused_by_its_rid() {
        let source = FakeSource::new().with_local("Администратор", &machine_sid(500));
        let err = classify(&source, "Администратор").expect_err("RID 500 is built in");
        assert!(
            matches!(err, WindowsAccountError::BuiltInAccount { .. }),
            "expected BuiltInAccount, got {err:?}"
        );
    }

    #[test]
    fn account_at_the_boundary_is_admitted() {
        let source = FakeSource::new().with_local("first", &machine_sid(FIRST_REGULAR_RID));
        classify(&source, "first").expect("the boundary itself is a regular account");
    }

    #[test]
    fn account_just_below_the_boundary_is_refused() {
        let source = FakeSource::new().with_local("reserved", &machine_sid(FIRST_REGULAR_RID - 1));
        let err = classify(&source, "reserved").expect_err("999 is below the boundary");
        assert!(
            matches!(err, WindowsAccountError::BuiltInAccount { .. }),
            "expected BuiltInAccount, got {err:?}"
        );
    }

    /// The service principals are refused by name, whatever the system calls
    /// them: the source resolves the localized name to the well-known SID.
    #[test]
    fn service_principal_is_refused_by_its_well_known_sid() {
        let source = FakeSource::new()
            .with_well_known("система", "S-1-5-18")
            .with_well_known("LOCAL SERVICE", "S-1-5-19")
            .with_well_known("NETWORK SERVICE", "S-1-5-20");
        for account in ["система", "Система", "LOCAL SERVICE", "network service"] {
            let err = classify(&source, account).expect_err("a service principal is never a role");
            assert!(
                matches!(err, WindowsAccountError::WellKnownPrincipal { .. }),
                "expected WellKnownPrincipal for {account}, got {err:?}"
            );
        }
    }

    /// A built-in group carries a well-known SID too, and the same rule catches
    /// it — the group would otherwise pass every later check, having no local
    /// account record at all.
    #[test]
    fn built_in_group_is_refused() {
        let source = FakeSource::new().with_well_known("Администраторы", "S-1-5-32-544");
        let err = classify(&source, "Администраторы").expect_err("a built-in group is not a role");
        assert!(
            matches!(&err, WindowsAccountError::WellKnownPrincipal { sid, .. } if sid == "S-1-5-32-544"),
            "expected the group's well-known SID, got {err:?}"
        );
    }

    /// The well-known table is consulted first, so a machine that also holds a
    /// local account under that name cannot admit it.
    #[test]
    fn well_known_name_wins_over_a_local_account_record() {
        let source = FakeSource::new()
            .with_well_known("guest", "S-1-5-32-546")
            .with_local("guest", &machine_sid(1500));
        let err = classify(&source, "guest").expect_err("a well-known name is refused first");
        assert!(
            matches!(err, WindowsAccountError::WellKnownPrincipal { .. }),
            "expected WellKnownPrincipal, got {err:?}"
        );
    }

    #[test]
    fn unknown_name_is_refused_as_not_an_account_of_this_device() {
        let source = FakeSource::new();
        let err = classify(&source, "nobody-here").expect_err("an unknown name is not admitted");
        assert!(
            matches!(err, WindowsAccountError::NoLocalAccount { .. }),
            "expected NoLocalAccount, got {err:?}"
        );
    }

    /// Every qualified form is refused before any source is asked — that is
    /// what keeps the lookup on this machine.
    #[test]
    fn qualified_names_are_refused_without_asking_anyone() {
        let source = FakeSource::new()
            .with_local("CORP\\engineer", &machine_sid(1001))
            .with_local("engineer@corp.example", &machine_sid(1001));
        for account in [
            "CORP\\engineer",
            "engineer@corp.example",
            "corp/engineer",
            "",
        ] {
            let err = classify(&source, account).expect_err("a qualified name is never a role");
            assert!(
                matches!(err, WindowsAccountError::Qualified { .. }),
                "expected Qualified for {account:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn lookup_failure_is_a_refusal_and_names_the_call() {
        let source = FakeSource::new().failing(AccountSourceError {
            api: "NetUserGetInfo",
            code: 53,
        });
        let err = classify(&source, "engineer").expect_err("an unanswered question is a refusal");
        match err {
            WindowsAccountError::LookupFailed { source, .. } => {
                assert_eq!(source.api, "NetUserGetInfo");
                assert_eq!(source.code, 53);
            }
            other => panic!("expected LookupFailed, got {other:?}"),
        }
    }

    /// A SID that is not an account SID of this machine is refused even when
    /// the account database is the one that produced it.
    #[test]
    fn non_account_sids_are_refused() {
        for sid in [
            // A service principal: no domain identifier, so no RID either.
            "S-1-5-18",
            // A built-in alias: the trailing number is an alias, not a RID.
            "S-1-5-32-544",
            // Everyone, under another identifier authority.
            "S-1-1-0",
            // A virtual service account.
            "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420",
            // An account SID with a part missing.
            "S-1-5-21-1004336348-1177238915-1001",
            // Not a SID at all.
            "engineer",
            "S-2-5-21-1-2-3-1001",
        ] {
            let source = FakeSource::new().with_local("engineer", sid);
            let err = classify(&source, "engineer")
                .expect_err("a SID that is not this machine's account SID is never admitted");
            assert!(
                matches!(err, WindowsAccountError::NotLocalAccount { .. }),
                "expected NotLocalAccount for {sid}, got {err:?}"
            );
        }
    }

    #[test]
    fn parse_sid_reads_both_authority_forms() {
        assert_eq!(
            parse_sid("S-1-5-21-1-2-3-1001"),
            Some(ParsedSid {
                authority: 5,
                sub_authorities: vec![21, 1, 2, 3, 1001],
            })
        );
        assert_eq!(
            parse_sid("S-1-0x000000000005-21-1-2-3-1001")
                .expect("the hexadecimal authority form is valid")
                .authority,
            5
        );
        assert_eq!(parse_sid("S-1-5"), None, "a SID needs a sub-authority");
        assert_eq!(parse_sid("S-2-5-21"), None, "only revision 1 is defined");
        assert_eq!(parse_sid("X-1-5-21"), None);
        assert_eq!(parse_sid("S-1-5-21-4294967296"), None, "a RID is 32 bits");
    }

    #[test]
    fn machine_account_rid_reads_only_account_sids() {
        assert_eq!(machine_account_rid("S-1-5-21-1-2-3-1001"), Some(1001));
        assert_eq!(machine_account_rid("S-1-5-18"), None);
        assert_eq!(machine_account_rid("S-1-5-32-544"), None);
        assert_eq!(machine_account_rid("S-1-1-0"), None);
    }
}

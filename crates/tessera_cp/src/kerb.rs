//! Packing of `KERB_INTERACTIVE_UNLOCK_LOGON` for `GetSerialization`.
//!
//! LSA expects one flat block of memory: the fixed-size structure first, then
//! the three strings it points at, with every `UNICODE_STRING::Buffer` holding
//! a *byte offset from the start of the block* rather than an address. LSA adds
//! its own base to those offsets after copying the block across, which is why
//! an ordinary structure with real pointers would be rejected.
//!
//! The layout is expressed here in arithmetic instead of through the Win32
//! types on purpose: it makes the packing testable on a developer machine, and
//! the arithmetic is derived from the pointer width of the target, so a 32-bit
//! build produces a 32-bit layout without a second code path. The Windows half
//! asserts at compile time that the computed size matches the real structure.
//!
//! What is packed is the *technical account* whose logon `Winlogon` then performs
//! by the standard path — the provider never performs it itself.

use zeroize::Zeroizing;

/// Pointer width of the target, which is also the alignment of every
/// pointer-bearing Windows structure below.
const PTR: usize = size_of::<usize>();

/// `sizeof(UNICODE_STRING)`: two `u16` lengths, padding up to the pointer
/// alignment, then the buffer pointer.
const UNICODE_STRING_SIZE: usize = align_up(2 * size_of::<u16>(), PTR) + PTR;

/// Offset of `KERB_INTERACTIVE_LOGON::LogonDomainName` — the `KERB_LOGON_SUBMIT_TYPE`
/// discriminant padded up to the structure's alignment.
const DOMAIN_OFFSET: usize = align_up(size_of::<u32>(), PTR);
/// Offset of `KERB_INTERACTIVE_LOGON::UserName`.
const USER_OFFSET: usize = DOMAIN_OFFSET + UNICODE_STRING_SIZE;
/// Offset of `KERB_INTERACTIVE_LOGON::Password`.
const PASSWORD_OFFSET: usize = USER_OFFSET + UNICODE_STRING_SIZE;
/// Offset of `KERB_INTERACTIVE_UNLOCK_LOGON::LogonId`, a `LUID` left zeroed.
const LOGON_ID_OFFSET: usize = PASSWORD_OFFSET + UNICODE_STRING_SIZE;

/// `sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)`.
pub const STRUCT_SIZE: usize = align_up(LOGON_ID_OFFSET + 2 * size_of::<u32>(), PTR);

/// Rounds `value` up to the next multiple of `alignment`.
const fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

/// Which `KERB_LOGON_SUBMIT_TYPE` the packed block declares.
///
/// LSA distinguishes a fresh logon from unlocking an already-open session, and
/// the usage scenario `LogonUI` hands the provider decides which one applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogonKind {
    /// `KerbInteractiveLogon` — logging on.
    Interactive,
    /// `KerbWorkstationUnlockLogon` — unlocking a locked session.
    WorkstationUnlock,
}

impl LogonKind {
    /// Numeric `KERB_LOGON_SUBMIT_TYPE` value.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::Interactive => 2,
            Self::WorkstationUnlock => 7,
        }
    }
}

/// The account whose credentials are being serialised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogonTarget {
    /// Domain, or `"."` for an account in this machine's own database.
    pub domain: String,
    /// Account name.
    pub user: String,
}

impl LogonTarget {
    /// Names an account in this machine's own account database.
    #[must_use]
    pub fn local(user: impl Into<String>) -> Self {
        Self {
            domain: ".".to_owned(),
            user: user.into(),
        }
    }
}

/// A string that does not fit the `u16` length of a `UNICODE_STRING`.
#[derive(Debug, thiserror::Error)]
#[error("logon field '{field}' is {bytes} bytes and does not fit a UNICODE_STRING")]
pub struct PackError {
    /// Which of the three strings was too long.
    pub field: &'static str,
    /// Its size in bytes, terminator included.
    pub bytes: usize,
}

/// Packs the block LSA expects for an interactive logon or unlock.
///
/// The result is [`Zeroizing`] because it carries the technical account's
/// password in clear UTF-16: it must not outlive the call that hands it to
/// `LogonUI`, and it must not be left behind in a freed allocation.
///
/// # Errors
///
/// Returns [`PackError`] when a field exceeds what a `UNICODE_STRING` can
/// describe. This cannot happen with account names Windows itself accepts, and
/// is reported rather than truncated because a truncated password would turn
/// into a puzzling logon failure.
pub fn pack(
    kind: LogonKind,
    target: &LogonTarget,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, PackError> {
    let domain = encode_utf16_nul("domain", &target.domain)?;
    let user = encode_utf16_nul("user", &target.user)?;
    let secret = encode_utf16_nul("password", password)?;

    // The block is sized before anything is written into it. Growing a buffer
    // that already holds part of the password would leave the old allocation —
    // with that part still in it — in the heap of a process nobody wipes, so
    // the one allocation that carries the secret is also the only one.
    let total = STRUCT_SIZE + byte_len(&domain) + byte_len(&user) + byte_len(&secret);
    let mut blob = Zeroizing::new(vec![0u8; total]);
    write_u32(&mut blob, 0, kind.code());

    let after_domain = write_string(&mut blob, DOMAIN_OFFSET, STRUCT_SIZE, &domain);
    let after_user = write_string(&mut blob, USER_OFFSET, after_domain, &user);
    let _end = write_string(&mut blob, PASSWORD_OFFSET, after_user, &secret);

    Ok(blob)
}

/// Size in bytes of the encoded units, terminator included.
fn byte_len(units: &[u16]) -> usize {
    size_of_val(units)
}

/// Encodes a string as NUL-terminated UTF-16, rejecting what will not fit.
fn encode_utf16_nul(field: &'static str, value: &str) -> Result<Zeroizing<Vec<u16>>, PackError> {
    // Counted first, then allocated exactly: collecting straight from the
    // iterator grows the buffer as it goes, and every growth abandons an
    // allocation holding a prefix of what is being encoded — which for one of
    // the three fields is the password.
    let count = value.encode_utf16().count() + 1;
    let mut units = Zeroizing::new(Vec::with_capacity(count));
    units.extend(value.encode_utf16());
    units.push(0);

    let bytes = units.len() * size_of::<u16>();
    if u16::try_from(bytes).is_err() {
        return Err(PackError { field, bytes });
    }
    Ok(units)
}

/// Writes the characters at `data_offset` and fills in the `UNICODE_STRING`
/// that describes them. Returns the offset just past the characters.
///
/// `Length` excludes the terminator and `MaximumLength` includes it — the
/// convention LSA and every Win32 caller of `UNICODE_STRING` follow.
fn write_string(blob: &mut [u8], field_offset: usize, data_offset: usize, units: &[u16]) -> usize {
    let mut at = data_offset;
    for unit in units {
        write_u16(blob, at, *unit);
        at += size_of::<u16>();
    }

    let with_terminator = size_of_val(units);
    let length = with_terminator.saturating_sub(size_of::<u16>());
    write_u16(blob, field_offset, truncate_u16(length));
    write_u16(
        blob,
        field_offset + size_of::<u16>(),
        truncate_u16(with_terminator),
    );
    write_usize(
        blob,
        field_offset + align_up(2 * size_of::<u16>(), PTR),
        data_offset,
    );
    at
}

/// Narrows a length already validated by [`encode_utf16_nul`].
fn truncate_u16(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn write_u16(blob: &mut [u8], offset: usize, value: u16) {
    write_bytes(blob, offset, &value.to_le_bytes());
}

fn write_u32(blob: &mut [u8], offset: usize, value: u32) {
    write_bytes(blob, offset, &value.to_le_bytes());
}

fn write_usize(blob: &mut [u8], offset: usize, value: usize) {
    write_bytes(blob, offset, &value.to_le_bytes());
}

/// Copies `value` into `blob` at `offset`, silently doing nothing if the slice
/// is too short.
///
/// Every call site writes inside a buffer this module sized itself, so the
/// short case is unreachable; it is handled rather than asserted because a
/// panic here would fire inside `LogonUI`.
fn write_bytes(blob: &mut [u8], offset: usize, value: &[u8]) {
    if let Some(slot) = blob.get_mut(offset..offset + value.len()) {
        slot.copy_from_slice(value);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    /// Reads back a `UNICODE_STRING` the way LSA would after relocation.
    fn read_string(blob: &[u8], field_offset: usize) -> (u16, u16, String) {
        let length = u16::from_le_bytes(
            blob[field_offset..field_offset + 2]
                .try_into()
                .expect("two bytes"),
        );
        let maximum = u16::from_le_bytes(
            blob[field_offset + 2..field_offset + 4]
                .try_into()
                .expect("two bytes"),
        );
        let pointer_at = field_offset + align_up(4, PTR);
        let data_offset = usize::from_le_bytes(
            blob[pointer_at..pointer_at + PTR]
                .try_into()
                .expect("pointer-sized"),
        );

        let chars: Vec<u16> = blob[data_offset..data_offset + usize::from(length)]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes(pair.try_into().expect("two bytes")))
            .collect();
        (length, maximum, String::from_utf16_lossy(&chars))
    }

    #[test]
    fn the_layout_matches_the_documented_x64_structure() {
        // Guards the arithmetic on the platform the stand actually runs on.
        if PTR == 8 {
            assert_eq!(UNICODE_STRING_SIZE, 16);
            assert_eq!(DOMAIN_OFFSET, 8);
            assert_eq!(USER_OFFSET, 24);
            assert_eq!(PASSWORD_OFFSET, 40);
            assert_eq!(LOGON_ID_OFFSET, 56);
            assert_eq!(STRUCT_SIZE, 64);
        }
    }

    #[test]
    fn packs_the_three_strings_after_the_structure() {
        let target = LogonTarget::local("tessera-logon");
        let blob = pack(LogonKind::Interactive, &target, "s3cret").unwrap();

        assert!(blob.len() > STRUCT_SIZE);
        assert_eq!(
            u32::from_le_bytes(blob[0..4].try_into().unwrap()),
            LogonKind::Interactive.code()
        );

        let (_, _, domain) = read_string(&blob, DOMAIN_OFFSET);
        let (_, _, user) = read_string(&blob, USER_OFFSET);
        let (_, _, password) = read_string(&blob, PASSWORD_OFFSET);
        assert_eq!(domain, ".");
        assert_eq!(user, "tessera-logon");
        assert_eq!(password, "s3cret");
    }

    #[test]
    fn lengths_exclude_and_maximum_lengths_include_the_terminator() {
        let blob = pack(LogonKind::Interactive, &LogonTarget::local("abc"), "defg").unwrap();

        let (user_len, user_max, _) = read_string(&blob, USER_OFFSET);
        assert_eq!(user_len, 6, "three characters, two bytes each");
        assert_eq!(user_max, 8, "plus the NUL");

        let (pass_len, pass_max, _) = read_string(&blob, PASSWORD_OFFSET);
        assert_eq!(pass_len, 8);
        assert_eq!(pass_max, 10);
    }

    #[test]
    fn string_offsets_do_not_overlap() {
        let blob = pack(
            LogonKind::Interactive,
            &LogonTarget {
                domain: "WORKGROUP".to_owned(),
                user: "tessera-logon".to_owned(),
            },
            "password",
        )
        .unwrap();

        let ends: Vec<usize> = [DOMAIN_OFFSET, USER_OFFSET, PASSWORD_OFFSET]
            .iter()
            .map(|field| {
                let pointer_at = field + align_up(4, PTR);
                let start =
                    usize::from_le_bytes(blob[pointer_at..pointer_at + PTR].try_into().unwrap());
                let maximum = u16::from_le_bytes(blob[field + 2..field + 4].try_into().unwrap());
                start + usize::from(maximum)
            })
            .collect();

        for end in &ends {
            assert!(*end <= blob.len(), "a string runs past the packed block");
        }
        assert_eq!(ends.last().copied(), Some(blob.len()));
    }

    #[test]
    fn the_unlock_kind_declares_a_different_submit_type() {
        let blob = pack(
            LogonKind::WorkstationUnlock,
            &LogonTarget::local("tessera-logon"),
            "x",
        )
        .unwrap();

        assert_eq!(u32::from_le_bytes(blob[0..4].try_into().unwrap()), 7);
    }

    #[test]
    fn non_ascii_survives_as_utf16() {
        let blob = pack(
            LogonKind::Interactive,
            &LogonTarget::local("инженер"),
            "пароль",
        )
        .unwrap();

        let (_, _, user) = read_string(&blob, USER_OFFSET);
        let (_, _, password) = read_string(&blob, PASSWORD_OFFSET);
        assert_eq!(user, "инженер");
        assert_eq!(password, "пароль");
    }

    #[test]
    fn an_oversized_field_is_refused_rather_than_truncated() {
        let long = "a".repeat(40_000);
        let error = pack(LogonKind::Interactive, &LogonTarget::local("u"), &long)
            .expect_err("40000 characters exceed a UNICODE_STRING");

        assert_eq!(error.field, "password");
    }

    /// The packed block is allocated once, at its final size. A buffer that
    /// grew while the password was being written into it would have left a
    /// prefix of that password in an abandoned allocation, and the only visible
    /// trace of that is spare capacity here.
    #[test]
    fn the_block_is_allocated_once_at_its_final_size() {
        let blob = pack(
            LogonKind::Interactive,
            &LogonTarget {
                domain: "WORKGROUP".to_owned(),
                user: "tessera-logon".to_owned(),
            },
            "a rather long technical account password",
        )
        .unwrap();

        assert_eq!(
            blob.capacity(),
            blob.len(),
            "the block was grown after it was allocated"
        );
    }

    /// The same property for the intermediate UTF-16 encoding, which holds the
    /// password on its own before the block does.
    #[test]
    fn the_encoded_units_are_allocated_once() {
        let units = encode_utf16_nul("password", "a rather long technical account password")
            .expect("the password fits a UNICODE_STRING");

        assert_eq!(units.capacity(), units.len());
    }

    #[test]
    fn the_logon_id_is_left_zeroed() {
        let blob = pack(LogonKind::Interactive, &LogonTarget::local("u"), "p").unwrap();
        assert_eq!(&blob[LOGON_ID_OFFSET..LOGON_ID_OFFSET + 8], &[0u8; 8]);
    }
}

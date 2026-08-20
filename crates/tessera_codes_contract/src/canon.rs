//! Canonical serialisation of the MAC input.
//!
//! The encoding is written by hand and never derived: a format produced by a
//! derive macro changes its bytes when a dependency is updated, and on the phone
//! channel that shows up as "the code does not fit" at a site in another city.
//!
//! # Encoding
//!
//! The result is the concatenation of the fields in the order given by
//! [`canon_field_order`]. Every field is encoded as its length in bytes as a
//! big-endian `u32`, followed by the bytes themselves:
//!
//! - text fields are normalised to Unicode NFC and encoded as UTF-8;
//! - integer fields are encoded in a fixed width of four bytes, big-endian, so
//!   their length prefix is always `00 00 00 04`.
//!
//! The order comes from the table [`canon_field_order`] reports, not from the
//! declaration order of [`CodeInput`]: reordering the fields of the struct
//! cannot move a field in the output.

use unicode_normalization::UnicodeNormalization;

use crate::device_number::CheckedDeviceNumber;

/// Number of fields in the canonical MAC input.
pub const CANON_FIELD_COUNT: usize = 4;

/// Access level of the role the code is issued for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Level(u32);

impl Level {
    /// Wraps a raw level value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw level value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Input of the code MAC.
///
/// The struct carries borrowed values only: it is built at the call site right
/// before the code is computed and never stored.
///
/// The device number is a [`CheckedDeviceNumber`] rather than a string, and
/// that is the whole point of the type: the encoding takes the significant
/// characters of the number, so the spelling a caller happens to have — with
/// dashes, with spaces, in lowercase — cannot reach the bytes. A field of type
/// `&str` would hand that choice to every call site, and the first site that
/// chose differently would be a device and a cabinet computing two codes for
/// one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeInput<'a> {
    /// Device number, with its check character.
    pub device_number: &'a CheckedDeviceNumber,
    // Declared out of canonical order on purpose: the encoding follows the
    // field table, and this makes that visible instead of merely stated.
    /// Identifier of the role the code grants.
    pub role_id: &'a str,
    /// Rendered hybrid nonce; see [`crate::nonce::Nonce::as_str`].
    pub nonce: &'a str,
    /// Access level of that role.
    pub level: Level,
}

/// Failure of the canonical encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    /// A field does not fit the `u32` length prefix of the encoding.
    #[error("canonical field `{field}` is longer than the encoding allows")]
    FieldTooLong {
        /// Name of the offending field, as listed by [`canon_field_order`].
        field: &'static str,
    },
}

/// One value pulled out of [`CodeInput`] by the field table.
#[derive(Debug, Clone, Copy)]
enum CanonValue<'a> {
    /// UTF-8 text, normalised to NFC before encoding.
    Text(&'a str),
    /// Integer encoded in four big-endian bytes.
    U32(u32),
}

/// One row of the field table: the name that identifies the field in the
/// contract, and the accessor that reads it.
struct CanonField {
    name: &'static str,
    read: for<'a> fn(&'a CodeInput<'a>) -> CanonValue<'a>,
}

fn read_device_number<'a>(input: &CodeInput<'a>) -> CanonValue<'a> {
    CanonValue::Text(input.device_number.significant())
}

fn read_nonce<'a>(input: &CodeInput<'a>) -> CanonValue<'a> {
    CanonValue::Text(input.nonce)
}

fn read_role_id<'a>(input: &CodeInput<'a>) -> CanonValue<'a> {
    CanonValue::Text(input.role_id)
}

fn read_level(input: &CodeInput<'_>) -> CanonValue<'static> {
    CanonValue::U32(input.level.get())
}

/// The field table — the single place the canonical order is written down.
const CANON_FIELDS: [CanonField; CANON_FIELD_COUNT] = [
    CanonField {
        name: "device_number",
        read: read_device_number,
    },
    CanonField {
        name: "nonce",
        read: read_nonce,
    },
    CanonField {
        name: "role_id",
        read: read_role_id,
    },
    CanonField {
        name: "level",
        read: read_level,
    },
];

/// Returns the canonical field order as named by the contract.
///
/// The order is part of the frozen format: a test compares this list against
/// the order written in the specification, so a field cannot move unnoticed.
#[must_use]
pub fn canon_field_order() -> [&'static str; CANON_FIELD_COUNT] {
    let mut names = [""; CANON_FIELD_COUNT];
    for (slot, field) in names.iter_mut().zip(CANON_FIELDS.iter()) {
        *slot = field.name;
    }
    names
}

/// Encodes the MAC input canonically.
///
/// # Errors
///
/// Returns [`CanonError::FieldTooLong`] when a text field exceeds the range of
/// the `u32` length prefix.
pub fn canon(input: &CodeInput<'_>) -> Result<Vec<u8>, CanonError> {
    let mut encoder = Encoder::default();
    for field in &CANON_FIELDS {
        match (field.read)(input) {
            CanonValue::Text(text) => encoder.push_text(field.name, text)?,
            CanonValue::U32(value) => encoder.push_u32(field.name, value)?,
        }
    }
    Ok(encoder.finish())
}

/// Writer of the length-prefixed encoding, shared by every canonical structure
/// of the contract.
#[derive(Debug, Default)]
pub(crate) struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Appends a raw byte field.
    pub(crate) fn push_bytes(
        &mut self,
        field: &'static str,
        value: &[u8],
    ) -> Result<(), CanonError> {
        let len = u32::try_from(value.len()).map_err(|_| CanonError::FieldTooLong { field })?;
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(value);
        Ok(())
    }

    /// Appends a text field, normalised to NFC.
    pub(crate) fn push_text(&mut self, field: &'static str, value: &str) -> Result<(), CanonError> {
        let normalised: String = value.nfc().collect();
        self.push_bytes(field, normalised.as_bytes())
    }

    /// Appends an integer field in the fixed four-byte big-endian form.
    pub(crate) fn push_u32(&mut self, field: &'static str, value: u32) -> Result<(), CanonError> {
        self.push_bytes(field, &value.to_be_bytes())
    }

    /// Appends an integer field in the fixed eight-byte big-endian form.
    ///
    /// Widths do not mix inside one field: a value declared eight bytes wide is
    /// always written in eight, however small it is, so that no document can be
    /// re-encoded into shorter bytes that hash to something else.
    pub(crate) fn push_u64(&mut self, field: &'static str, value: u64) -> Result<(), CanonError> {
        self.push_bytes(field, &value.to_be_bytes())
    }

    /// Returns the encoded bytes.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{canon, canon_field_order, CodeInput, Level};
    use crate::device_number::CheckedDeviceNumber;

    fn number(body: &str) -> CheckedDeviceNumber {
        CheckedDeviceNumber::from_body(body).unwrap()
    }

    #[test]
    fn field_order_is_the_contract_order() {
        assert_eq!(
            canon_field_order(),
            ["device_number", "nonce", "role_id", "level"]
        );
    }

    #[test]
    fn framing_matches_the_hand_written_bytes() {
        // "A" carries the check character "H", so the significant form is "AH".
        let device_number = number("A");
        assert_eq!(device_number.significant(), "AH");
        let input = CodeInput {
            device_number: &device_number,
            nonce: "1",
            role_id: "r",
            level: Level::new(3),
        };
        let encoded = canon(&input).unwrap_or_default();
        assert_eq!(
            hex::encode(encoded),
            concat!(
                "00000002", "4148", // device number "AH"
                "00000001", "31", // nonce "1"
                "00000001", "72", // role id "r"
                "00000004", "00000003", // level 3
            )
        );
    }

    #[test]
    fn text_is_normalised_to_nfc() {
        let device_number = number("A");
        let decomposed = CodeInput {
            device_number: &device_number,
            nonce: "1",
            role_id: "ro\u{0302}le",
            level: Level::new(0),
        };
        let composed = CodeInput {
            role_id: "r\u{00f4}le",
            ..decomposed
        };
        assert_eq!(canon(&decomposed), canon(&composed));
    }

    #[test]
    fn two_spellings_of_one_number_give_one_encoding() {
        let printed = number("77-000123");
        let retyped =
            CheckedDeviceNumber::parse(&printed.as_str().replace('-', " ").to_lowercase()).unwrap();
        assert_ne!(printed.as_str(), retyped.as_str());

        let left = CodeInput {
            device_number: &printed,
            nonce: "0004200713",
            role_id: "ops.dc.senior",
            level: Level::new(2),
        };
        let right = CodeInput {
            device_number: &retyped,
            ..left
        };
        assert_eq!(canon(&left), canon(&right));
    }

    #[test]
    fn distinct_fields_do_not_collide() {
        let long = number("AB");
        let short = number("A");
        let left = CodeInput {
            device_number: &long,
            nonce: "C",
            role_id: "r",
            level: Level::new(0),
        };
        let right = CodeInput {
            device_number: &short,
            nonce: "BC",
            role_id: "r",
            level: Level::new(0),
        };
        assert_ne!(canon(&left), canon(&right));
    }
}

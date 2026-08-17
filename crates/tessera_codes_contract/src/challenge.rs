//! The challenge of the phone channel.
//!
//! A challenge is what the engineer at the device reads out to the operator:
//! which device, which key epoch, which nonce, which role at which level, and
//! who is asking. The operator's cabinet turns the same six values into the
//! code that is read back.
//!
//! Two forms of the same value therefore have to exist and never drift apart:
//!
//! - the wire form ([`Challenge::parse`] and [`core::fmt::Display`]) — one line
//!   of `key=value` pairs, carried by a QR code, a paste buffer or a log;
//! - the spoken form ([`Challenge::spoken_form`]) — the same values split into
//!   short groups, because a twenty-two character nonce read as one run is
//!   mistyped.
//!
//! Neither is the input of the MAC. That is the canonical encoding
//! ([`Challenge::encode`]), written with the same [`Encoder`] as every other
//! structure of the contract, over the *significant* characters of the device
//! number — two labels printing one number with different separators must not
//! produce two different challenges.
//!
//! The wire form is written and read through [`crate::wire`], the same module
//! the other documents of the contract go through: a missing field, an unknown
//! field, a field out of order, an empty value or a value the type cannot hold
//! is an error, never a field quietly dropped. One reader for every document of
//! the channel is what keeps the cabinet and the device from disagreeing about
//! which line is well formed.

use crate::canon::{CanonError, CodeInput, Encoder, Level};
use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
use crate::key::Epoch;
use crate::nonce::{Nonce, NonceError};
use crate::params::FleetParams;
use crate::wire::{self, WireError};

/// Number of fields a challenge carries.
pub const CHALLENGE_FIELD_COUNT: usize = 6;

/// Marker that opens the wire form and pins the version of the format.
pub const CHALLENGE_PREFIX: &str = "tessera-codes/v1/challenge";

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; CHALLENGE_FIELD_COUNT] =
    ["device", "epoch", "nonce", "role", "level", "operator"];

/// Field names of the canonical encoding, in the order they are encoded.
///
/// The order is the contract's, not the declaration order of [`Challenge`]; a
/// test compares this list against the order written in the specification.
const CANON_FIELDS: [&str; CHALLENGE_FIELD_COUNT] = [
    "device_number",
    "epoch",
    "nonce",
    "role_id",
    "level",
    "operator_id",
];

/// Number of characters in one group of the spoken form.
const SPOKEN_GROUP: usize = 3;

/// A phone-channel challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    device_number: CheckedDeviceNumber,
    epoch: Epoch,
    nonce: Nonce,
    role_id: String,
    level: Level,
    operator_id: String,
}

impl Challenge {
    /// Assembles a challenge.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::EmptyValue`] for an empty role or operator
    /// identifier, and [`WireError::UnusableValue`] when either carries a
    /// character the wire form cannot hold — a separator of the format or a
    /// control character.
    pub fn new(
        device_number: CheckedDeviceNumber,
        epoch: Epoch,
        nonce: Nonce,
        role_id: &str,
        level: Level,
        operator_id: &str,
    ) -> Result<Self, ChallengeError> {
        wire::check_free_text("role_id", role_id)?;
        wire::check_free_text("operator_id", operator_id)?;
        Ok(Self {
            device_number,
            epoch,
            nonce,
            role_id: role_id.to_owned(),
            level,
            operator_id: operator_id.to_owned(),
        })
    }

    /// Parses the wire form against the fleet parameters, which fix the shape
    /// of the nonce.
    ///
    /// # Errors
    ///
    /// Returns the [`ChallengeError`] describing the first violation: a missing
    /// or misspelled prefix, a wrong number of fields, a field out of order or
    /// unknown, an empty value, a number that does not parse, a device number
    /// whose check character does not match, or a nonce that does not fit the
    /// parameters.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, ChallengeError> {
        let values = wire::parse(text, CHALLENGE_PREFIX, &WIRE_KEYS)?;
        let device_number = CheckedDeviceNumber::parse(wire::value(&values, 0))?;
        let epoch = Epoch::new(wire::parse_u32("epoch", wire::value(&values, 1))?);
        let nonce = Nonce::parse(wire::value(&values, 2), params)?;
        let level = Level::new(wire::parse_u32("level", wire::value(&values, 4))?);

        Self::new(
            device_number,
            epoch,
            nonce,
            wire::value(&values, 3),
            level,
            wire::value(&values, 5),
        )
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let [device, epoch, nonce, role, level, operator] = WIRE_KEYS;
        let fields = [
            (device, self.device_number.as_str().to_owned()),
            (epoch, self.epoch.get().to_string()),
            (nonce, self.nonce.as_str().to_owned()),
            (role, self.role_id.clone()),
            (level, self.level.get().to_string()),
            (operator, self.operator_id.clone()),
        ];
        wire::render(CHALLENGE_PREFIX, &fields)
    }

    /// Encodes the challenge canonically, with the framing every structure of
    /// the contract shares.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the `u32` length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let [device, epoch, nonce, role, level, operator] = CANON_FIELDS;
        let mut encoder = Encoder::default();
        encoder.push_text(device, self.device_number.significant())?;
        encoder.push_u32(epoch, self.epoch.get())?;
        encoder.push_text(nonce, self.nonce.as_str())?;
        encoder.push_text(role, &self.role_id)?;
        encoder.push_u32(level, self.level.get())?;
        encoder.push_text(operator, &self.operator_id)?;
        Ok(encoder.finish())
    }

    /// Returns the MAC input of the code this challenge asks for.
    ///
    /// The number travels as the checked value, and the canonical encoding
    /// takes its significant characters — so a challenge spelled with one set
    /// of separators and the same challenge spelled with another produce one
    /// code, not two.
    #[must_use]
    pub fn code_input(&self) -> CodeInput<'_> {
        CodeInput {
            device_number: &self.device_number,
            nonce: self.nonce.as_str(),
            role_id: &self.role_id,
            level: self.level,
        }
    }

    /// Renders the challenge for dictation: the device number and the nonce in
    /// groups of three characters, the numbers as they are, the identifiers
    /// verbatim.
    ///
    /// The rendering carries no labels on purpose — a library has no business
    /// choosing the language they are spoken in; the caller pairs the fields,
    /// in the order of [`challenge_field_order`], with its own wording.
    #[must_use]
    pub fn spoken_form(&self) -> String {
        [
            group(self.device_number.significant()),
            self.epoch.get().to_string(),
            group(self.nonce.as_str()),
            self.role_id.clone(),
            self.level.get().to_string(),
            self.operator_id.clone(),
        ]
        .join(" / ")
    }

    /// Returns the device number, check character included.
    #[must_use]
    pub const fn device_number(&self) -> &CheckedDeviceNumber {
        &self.device_number
    }

    /// Returns the key epoch of the device.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the nonce.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns the identifier of the role the code is asked for.
    #[must_use]
    pub fn role_id(&self) -> &str {
        &self.role_id
    }

    /// Returns the access level of that role.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.level
    }

    /// Returns the identifier of the operator handling the call.
    #[must_use]
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }
}

impl core::fmt::Display for Challenge {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Returns the canonical field order of a challenge, as named by the contract.
#[must_use]
pub const fn challenge_field_order() -> [&'static str; CHALLENGE_FIELD_COUNT] {
    CANON_FIELDS
}

/// Rejection of a challenge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
    /// The wire form of the challenge is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The device number failed its check character.
    #[error(transparent)]
    DeviceNumber(#[from] DeviceNumberError),
    /// The nonce does not fit the fleet parameters.
    #[error(transparent)]
    Nonce(#[from] NonceError),
}

/// Splits a run of characters into groups for reading aloud.
fn group(value: &str) -> String {
    value
        .chars()
        .collect::<Vec<_>>()
        .chunks(SPOKEN_GROUP)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{
        challenge_field_order, Challenge, ChallengeError, CANON_FIELDS, CHALLENGE_FIELD_COUNT,
        CHALLENGE_PREFIX,
    };
    use crate::canon::Level;
    use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
    use crate::key::Epoch;
    use crate::nonce::Nonce;
    use crate::params::FleetParams;
    use crate::wire::WireError;

    fn params() -> FleetParams {
        FleetParams::defaults()
    }

    fn challenge() -> Challenge {
        Challenge::new(
            CheckedDeviceNumber::from_body("77-000123").unwrap(),
            Epoch::new(7),
            Nonce::new(420, "0713", &params()).unwrap(),
            "ops.dc.senior",
            Level::new(2),
            "op-42",
        )
        .unwrap()
    }

    #[test]
    fn the_canonical_field_order_is_the_contract_order() {
        assert_eq!(
            challenge_field_order(),
            [
                "device_number",
                "epoch",
                "nonce",
                "role_id",
                "level",
                "operator_id"
            ]
        );
        assert_eq!(CANON_FIELDS.len(), CHALLENGE_FIELD_COUNT);
    }

    #[test]
    fn the_wire_form_round_trips() {
        let original = challenge();
        let text = original.to_string();
        assert_eq!(Challenge::parse(&text, &params()), Ok(original));
    }

    #[test]
    fn the_canonical_bytes_are_the_hand_written_framing() {
        let encoded = challenge().encode().unwrap();
        assert_eq!(
            hex::encode(encoded),
            concat!(
                // Device number, significant characters only: "77000123" and
                // its check character `S`, which the algorithm computes as 28.
                "00000009",
                "373730303031323353",
                "00000004",
                "00000007", // epoch 7
                "0000000a",
                "30303034323030373133", // nonce
                "0000000d",
                "6f70732e64632e73656e696f72", // role id
                "00000004",
                "00000002", // level 2
                "00000005",
                "6f702d3432", // operator id
            )
        );
    }

    #[test]
    fn separators_do_not_change_the_canonical_bytes() {
        let spaced = Challenge::new(
            CheckedDeviceNumber::parse(&challenge().device_number().as_str().replace('-', " "))
                .unwrap(),
            Epoch::new(7),
            Nonce::new(420, "0713", &params()).unwrap(),
            "ops.dc.senior",
            Level::new(2),
            "op-42",
        )
        .unwrap();
        assert_eq!(spaced.encode(), challenge().encode());
        assert_ne!(spaced.to_string(), challenge().to_string());
    }

    #[test]
    fn the_code_input_carries_the_significant_device_number() {
        let challenge = challenge();
        let input = challenge.code_input();
        assert_eq!(input.device_number, challenge.device_number());
        assert_eq!(input.nonce, challenge.nonce().as_str());
        assert_eq!(input.role_id, "ops.dc.senior");
        assert_eq!(input.level, Level::new(2));
    }

    #[test]
    fn the_spoken_form_groups_what_is_read_aloud() {
        let challenge = challenge();
        let spoken = challenge.spoken_form();
        let grouped_number = group_of(challenge.device_number().significant());
        let mut fields = spoken.split(" / ");
        assert_eq!(fields.next(), Some(grouped_number.as_str()));
        assert!(grouped_number.contains(' '), "{grouped_number}");
        assert_eq!(fields.next(), Some("7"));
        assert_eq!(fields.next(), Some("000 420 071 3"));
        assert_eq!(fields.next(), Some("ops.dc.senior"));
        assert_eq!(fields.next(), Some("2"));
        assert_eq!(fields.next(), Some("op-42"));
        assert_eq!(fields.next(), None);
    }

    fn group_of(value: &str) -> String {
        super::group(value)
    }

    #[test]
    fn a_missing_prefix_does_not_parse() {
        let text = challenge().to_string().replace("tessera-codes/v1/", "");
        assert_eq!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::WrongPrefix {
                expected: CHALLENGE_PREFIX
            }))
        );
    }

    #[test]
    fn a_dropped_field_does_not_parse() {
        let text = challenge().to_string().replace(";level=2", "");
        assert!(matches!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::UnexpectedField {
                expected: "level",
                ..
            }))
        ));
    }

    #[test]
    fn an_unknown_field_does_not_parse() {
        let text = format!("{};extra=1", challenge());
        assert!(matches!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn a_field_that_is_not_a_pair_does_not_parse() {
        let text = challenge().to_string().replace(";level=2", ";level");
        assert_eq!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::MalformedField {
                expected: "level"
            }))
        );
    }

    #[test]
    fn fields_out_of_order_do_not_parse() {
        let text = format!(
            "tessera-codes/v1/challenge;epoch=7;device={};nonce=0004200713;role=ops;level=2;operator=op-42",
            challenge().device_number().as_str()
        );
        assert!(matches!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::UnexpectedField {
                expected: "device",
                ..
            }))
        ));
    }

    #[test]
    fn an_empty_value_does_not_parse() {
        let text = challenge()
            .to_string()
            .replace("operator=op-42", "operator=");
        assert_eq!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::EmptyValue {
                field: "operator"
            }))
        );
    }

    #[test]
    fn a_broken_check_character_does_not_parse() {
        let number = challenge().device_number().as_str().to_owned();
        let damaged = number.replacen("77", "78", 1);
        let text = challenge()
            .to_string()
            .replace(&format!("device={number}"), &format!("device={damaged}"));
        assert!(matches!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::DeviceNumber(
                DeviceNumberError::CheckCharacterMismatch { .. }
            ))
        ));
    }

    #[test]
    fn a_nonce_of_the_wrong_shape_does_not_parse() {
        let text = challenge()
            .to_string()
            .replace("nonce=0004200713", "nonce=00042007");
        assert!(matches!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Nonce(_))
        ));
    }

    #[test]
    fn a_level_that_is_not_a_number_does_not_parse() {
        let text = challenge().to_string().replace("level=2", "level=two");
        assert_eq!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::NotANumber {
                field: "level"
            }))
        );
    }

    #[test]
    fn an_identifier_carrying_a_separator_is_refused_at_assembly() {
        let refused = Challenge::new(
            CheckedDeviceNumber::from_body("77-000123").unwrap(),
            Epoch::new(7),
            Nonce::new(420, "0713", &params()).unwrap(),
            "ops;dc",
            Level::new(2),
            "op-42",
        );
        assert_eq!(
            refused,
            Err(ChallengeError::Wire(WireError::UnusableValue {
                field: "role_id"
            }))
        );
    }

    #[test]
    fn a_separator_inside_an_identifier_does_not_parse() {
        let with_key_separator = challenge()
            .to_string()
            .replace("role=ops.dc.senior", "role=ops=dc");
        assert_eq!(
            Challenge::parse(&with_key_separator, &params()),
            Err(ChallengeError::Wire(WireError::UnusableValue {
                field: "role_id"
            }))
        );

        let with_field_separator = challenge()
            .to_string()
            .replace("role=ops.dc.senior", "role=ops;dc");
        assert_eq!(
            Challenge::parse(&with_field_separator, &params()),
            Err(ChallengeError::Wire(WireError::MalformedField {
                expected: "level"
            }))
        );
    }
}

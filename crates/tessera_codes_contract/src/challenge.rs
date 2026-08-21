//! The challenge of the phone channel.
//!
//! A challenge is what the device states about one attempt: which device, which
//! key epoch, which nonce, which role at which level, which issuing side it is
//! addressed to, who is asking — and the ephemeral public point of that attempt.
//! The issuing side turns the same values into the code that is presented back.
//!
//! The ephemeral point is here and not somewhere alongside because it is the
//! only thing that ties `K` to this attempt and to no other: the issuing side
//! computes `Z` against it, and a point that arrived out of band would be a
//! second document nobody checks against the first. It is carried, not read
//! aloud — see [`Challenge::spoken_form`].
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
use crate::key::{EphemeralPublicPoint, Epoch, KeyError};
use crate::nonce::{Nonce, NonceError};
use crate::params::FleetParams;
use crate::registry::DeviceRecord;
use crate::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::wire::{self, WireError};

/// Number of fields a challenge carries.
pub const CHALLENGE_FIELD_COUNT: usize = 8;

/// Marker that opens the wire form and pins the version of the format.
pub const CHALLENGE_PREFIX: &str = "tessera-codes/v1/challenge";

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; CHALLENGE_FIELD_COUNT] = [
    "device",
    "epoch",
    "nonce",
    "role",
    "level",
    "server",
    "engineer",
    "ephemeral",
];

/// Number of fields the signed form carries: the challenge, and the signature
/// the device put on it.
pub const SIGNED_CHALLENGE_FIELD_COUNT: usize = CHALLENGE_FIELD_COUNT + 1;

/// Marker that opens the wire form of a signed challenge.
///
/// A prefix of its own rather than a ninth field under the prefix above: the
/// parser of this contract accepts one field list per prefix, so an unsigned
/// challenge offered where a signed one is expected is refused by the reader
/// instead of being read and found to be missing a signature later.
pub const SIGNED_CHALLENGE_PREFIX: &str = "tessera-codes/v1/signed-challenge";

/// Label the signature of a challenge is made under.
///
/// Every signature of the contract is made over a labelled message, so bytes
/// signed as one document can never be replayed as another.
pub const CHALLENGE_SIGNATURE_LABEL: &str = "tessera-codes/v1/challenge-signature";

/// Field keys of the signed wire form, in the only order the parser accepts.
const SIGNED_WIRE_KEYS: [&str; SIGNED_CHALLENGE_FIELD_COUNT] = [
    "device",
    "epoch",
    "nonce",
    "role",
    "level",
    "server",
    "engineer",
    "ephemeral",
    "signature",
];

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
    "server_id",
    "engineer_id",
    "ephemeral_point",
];

/// Number of characters in one group of the spoken form.
const SPOKEN_GROUP: usize = 3;

/// The values a challenge is assembled from.
///
/// Named fields rather than a row of positional arguments: the device number,
/// the role and the operator are all things a caller holds at once, and two of
/// them are strings that would swap places unnoticed.
#[derive(Debug)]
pub struct ChallengeFields<'a> {
    /// Device the attempt is running on, check character included.
    pub device_number: CheckedDeviceNumber,
    /// Key epoch of that device.
    pub epoch: Epoch,
    /// Nonce of the attempt.
    pub nonce: Nonce,
    /// Role being asked for.
    pub role_id: &'a str,
    /// Level of that role.
    pub level: Level,
    /// The issuing side this attempt is addressed to.
    pub server_id: &'a str,
    /// Personal number of the engineer standing at the device.
    ///
    /// Not the same party as the issuing side, and not interchangeable with it:
    /// the issuing side answers the request, the engineer is who the code is
    /// issued to and who the device names in its own journal.
    pub engineer_id: &'a str,
    /// Public half of the pair this attempt agreed on.
    pub ephemeral_point: EphemeralPublicPoint,
}

/// A phone-channel challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    device_number: CheckedDeviceNumber,
    epoch: Epoch,
    nonce: Nonce,
    role_id: String,
    level: Level,
    server_id: String,
    engineer_id: String,
    ephemeral_point: EphemeralPublicPoint,
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
    pub fn new(fields: ChallengeFields<'_>) -> Result<Self, ChallengeError> {
        wire::check_free_text("role_id", fields.role_id)?;
        wire::check_free_text("server_id", fields.server_id)?;
        wire::check_free_text("engineer_id", fields.engineer_id)?;
        Ok(Self {
            device_number: fields.device_number,
            epoch: fields.epoch,
            nonce: fields.nonce,
            role_id: fields.role_id.to_owned(),
            level: fields.level,
            server_id: fields.server_id.to_owned(),
            engineer_id: fields.engineer_id.to_owned(),
            ephemeral_point: fields.ephemeral_point,
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
        Self::from_values(&values, params)
    }

    /// Builds a challenge from the first eight values of a parsed wire form.
    ///
    /// Shared by the plain and the signed form so that the two cannot come to
    /// read the same eight fields differently.
    fn from_values(values: &[&str], params: &FleetParams) -> Result<Self, ChallengeError> {
        let device_number = CheckedDeviceNumber::parse(wire::value(values, 0))?;
        let epoch = Epoch::new(wire::parse_u32("epoch", wire::value(values, 1))?);
        let nonce = Nonce::parse(wire::value(values, 2), params)?;
        let level = Level::new(wire::parse_u32("level", wire::value(values, 4))?);
        let ephemeral_point =
            EphemeralPublicPoint::new(wire::parse_hex("ephemeral", wire::value(values, 7))?)?;

        Self::new(ChallengeFields {
            device_number,
            epoch,
            nonce,
            role_id: wire::value(values, 3),
            level,
            server_id: wire::value(values, 5),
            engineer_id: wire::value(values, 6),
            ephemeral_point,
        })
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        wire::render(CHALLENGE_PREFIX, &self.wire_fields())
    }

    /// Returns the eight fields of the wire form, keyed and in order.
    ///
    /// Shared with the signed form, which renders these fields and its own
    /// signature under its own prefix. Two places spelling out the same eight
    /// values would be two spellings to keep in step.
    fn wire_fields(&self) -> [(&'static str, String); CHALLENGE_FIELD_COUNT] {
        let [device, epoch, nonce, role, level, server, engineer, ephemeral] = WIRE_KEYS;
        [
            (device, self.device_number.as_str().to_owned()),
            (epoch, self.epoch.get().to_string()),
            (nonce, self.nonce.as_str().to_owned()),
            (role, self.role_id.clone()),
            (level, self.level.get().to_string()),
            (server, self.server_id.clone()),
            (engineer, self.engineer_id.clone()),
            (ephemeral, hex::encode(self.ephemeral_point.as_bytes())),
        ]
    }

    /// Encodes the challenge canonically, with the framing every structure of
    /// the contract shares.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the `u32` length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let [device, epoch, nonce, role, level, server, engineer, ephemeral] = CANON_FIELDS;
        let mut encoder = Encoder::default();
        encoder.push_text(device, self.device_number.significant())?;
        encoder.push_u32(epoch, self.epoch.get())?;
        encoder.push_text(nonce, self.nonce.as_str())?;
        encoder.push_text(role, &self.role_id)?;
        encoder.push_u32(level, self.level.get())?;
        encoder.push_text(server, &self.server_id)?;
        encoder.push_text(engineer, &self.engineer_id)?;
        encoder.push_bytes(ephemeral, self.ephemeral_point.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Encodes the message the device signs to state this challenge.
    ///
    /// The label makes the message a challenge signature and nothing else: the
    /// same bytes offered as a registry record's proof of possession, or as any
    /// other signature of the contract, verify against nothing.
    ///
    /// # Errors
    ///
    /// The errors of [`Challenge::encode`].
    pub fn signing_message(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("label", CHALLENGE_SIGNATURE_LABEL)?;
        encoder.push_bytes("challenge", &self.encode()?)?;
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
            epoch: self.epoch,
            engineer_id: &self.engineer_id,
        }
    }

    /// Renders the challenge field by field: the device number and the nonce in
    /// groups of three characters, the numbers as they are, the identifiers
    /// verbatim, the ephemeral point in one run of hexadecimal.
    ///
    /// The point is not grouped, and it is not something a person reads out:
    /// it is sixty-five bytes, and the channel it travels — a screen, a QR
    /// code, a paste buffer — carries it whole. Grouping it would only invite
    /// somebody to try. Every field is present because the issuing side needs
    /// every field, and a form that dropped one would make the caller fetch it
    /// from somewhere else.
    ///
    /// The rendering carries no labels on purpose — a library has no business
    /// choosing the language they are shown in; the caller pairs the fields,
    /// in the order of [`challenge_field_order`], with its own wording.
    #[must_use]
    pub fn spoken_form(&self) -> String {
        [
            group(self.device_number.significant()),
            self.epoch.get().to_string(),
            group(self.nonce.as_str()),
            self.role_id.clone(),
            self.level.get().to_string(),
            self.server_id.clone(),
            self.engineer_id.clone(),
            hex::encode(self.ephemeral_point.as_bytes()),
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

    /// Returns the identifier of the issuing side this attempt is addressed to.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Returns the personal number of the engineer at the device.
    #[must_use]
    pub fn engineer_id(&self) -> &str {
        &self.engineer_id
    }

    /// Returns the ephemeral public point of this attempt.
    ///
    /// This is what the issuing side computes `Z` against — the device key it
    /// holds a record of is not part of that computation.
    #[must_use]
    pub const fn ephemeral_point(&self) -> &EphemeralPublicPoint {
        &self.ephemeral_point
    }
}

/// A challenge and the signature the device made over it.
///
/// # What the signature settles, and what it does not
///
/// It does not stand between anyone and a code. A stranger who rewrites the
/// ephemeral point of a challenge in flight receives a code computed for the
/// pair he substituted, and the device — which holds the other half of its own
/// pair and no other — refuses it. That was true before this signature existed
/// and is true without it.
///
/// What it settles is origin. Without it the issuing side cannot tell a
/// challenge a device stated from one somebody composed: the nonce, the role,
/// the level and the engineer number are all values a caller can type. With it,
/// a challenge either carries the mark of a key registered to that device or it
/// does not, and only the first is answered.
///
/// What it still does not settle: freshness, and who is standing at the device.
/// A signed challenge captured once stays signed, and replaying it to the
/// issuing side yields a code — which is of no use to whoever replayed it,
/// because the ephemeral half that turns the code into a login never left the
/// process that drew it. The engineer number is a claim of the caller here as
/// it is everywhere else in this channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedChallenge {
    challenge: Challenge,
    signature: Signature,
}

impl SignedChallenge {
    /// Puts a signature and a challenge together.
    ///
    /// Nothing is checked here: the crate performs no public-key arithmetic,
    /// and the value this returns is a claim until
    /// [`SignedChallenge::verify`] is called against the record of the device.
    #[must_use]
    pub const fn new(challenge: Challenge, signature: Signature) -> Self {
        Self {
            challenge,
            signature,
        }
    }

    /// Parses the signed wire form against the fleet parameters.
    ///
    /// # Errors
    ///
    /// The errors of [`Challenge::parse`], and [`WireError`] for a signature
    /// field that is empty or is not hexadecimal.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, ChallengeError> {
        let values = wire::parse(text, SIGNED_CHALLENGE_PREFIX, &SIGNED_WIRE_KEYS)?;
        let challenge = Challenge::from_values(&values, params)?;
        let signature = Signature::new(wire::parse_hex("signature", wire::value(&values, 8))?)
            .map_err(ChallengeError::Signature)?;
        Ok(Self {
            challenge,
            signature,
        })
    }

    /// Renders the signed wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let challenge = self.challenge.wire_fields();
        let mut fields = Vec::with_capacity(SIGNED_CHALLENGE_FIELD_COUNT);
        fields.extend(challenge);
        fields.push((
            SIGNED_WIRE_KEYS[CHALLENGE_FIELD_COUNT],
            hex::encode(self.signature.as_bytes()),
        ));
        wire::render(SIGNED_CHALLENGE_PREFIX, &fields)
    }

    /// Renders the fields for reading, the signature last.
    ///
    /// Like the ephemeral point beside it, the signature is carried rather than
    /// dictated — see [`Challenge::spoken_form`].
    #[must_use]
    pub fn spoken_form(&self) -> String {
        format!(
            "{} / {}",
            self.challenge.spoken_form(),
            hex::encode(self.signature.as_bytes())
        )
    }

    /// Checks the signature against the key the registry holds for this device.
    ///
    /// The key comes from `record` and from nowhere else. A challenge carries
    /// no key of its own precisely so that this call cannot be written the
    /// other way round: a signature checked against a key that travelled beside
    /// it is checked against nothing, because whoever wrote the signature chose
    /// the key.
    ///
    /// The record is matched to the challenge before the key is used — the same
    /// device, the same key epoch. A caller that fetched the wrong record is a
    /// bug, but it is a bug that would otherwise turn into a device signing for
    /// another device.
    ///
    /// The record itself is not verified here: whether the organisation and the
    /// owner stand behind it is [`DeviceRecord::verify`], and the caller
    /// **must** have run it — a record nobody signed says nothing about which
    /// key belongs to which device.
    ///
    /// # Errors
    ///
    /// [`ChallengeError::RecordMismatch`] when the record describes another
    /// device or another epoch, [`ChallengeError::Canon`] when the challenge
    /// cannot be encoded, and [`ChallengeError::Signature`] when the signature
    /// does not hold or the key cannot be read.
    pub fn verify(
        &self,
        record: &DeviceRecord,
        verifier: &impl SignatureVerifier,
    ) -> Result<(), ChallengeError> {
        if record.device_number().significant() != self.challenge.device_number.significant() {
            return Err(ChallengeError::RecordMismatch {
                field: "device number",
            });
        }
        if record.epoch() != self.challenge.epoch {
            return Err(ChallengeError::RecordMismatch { field: "epoch" });
        }

        verifier
            .verify(
                SignerRef::Key(record.public_key()),
                &self.challenge.signing_message()?,
                &self.signature,
            )
            .map_err(ChallengeError::Signature)
    }

    /// Returns the challenge, signature aside.
    #[must_use]
    pub const fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// Returns the signature the device made.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl core::fmt::Display for SignedChallenge {
    /// Writes the signed wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
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
    /// The ephemeral public point is not a value the contract accepts.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// The challenge could not be encoded for signing.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// The registry record offered for the check describes another device, or
    /// the same device under another key epoch.
    #[error("the registry record and the challenge disagree about the {field}")]
    RecordMismatch {
        /// The field the two documents disagree about.
        field: &'static str,
    },
    /// The signature of the device does not hold over the challenge.
    #[error("the device did not sign this challenge: {0}")]
    Signature(#[source] SignatureError),
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
        challenge_field_order, Challenge, ChallengeError, ChallengeFields, SignedChallenge,
        CANON_FIELDS, CHALLENGE_FIELD_COUNT, CHALLENGE_PREFIX, CHALLENGE_SIGNATURE_LABEL,
        SIGNED_CHALLENGE_PREFIX,
    };
    use crate::canon::Level;
    use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
    use crate::key::{EphemeralPublicPoint, Epoch};
    use crate::nonce::Nonce;
    use crate::params::FleetParams;
    use crate::registry::{
        AnchorKind, DeviceRecord, KeyProtection, MonotonicAnchor, PayloadFields, RecordFields,
        RecordPayload, SerialNumber,
    };
    use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
    use crate::wire::WireError;

    fn params() -> FleetParams {
        FleetParams::defaults()
    }

    /// A nonce of the default width, in the default alphabet.
    ///
    /// Written out rather than drawn: the tests compare byte for byte, and a
    /// value that changed between runs would only prove the comparison ran.
    fn fixture_nonce(params: FleetParams) -> String {
        "4".repeat(usize::from(params.nonce_width()))
    }

    /// Stand-in for the point of an attempt; the contract never parses it, so
    /// three bytes say everything a longer run would.
    fn point() -> EphemeralPublicPoint {
        EphemeralPublicPoint::new(vec![0x04, 0xaa, 0xbb]).unwrap()
    }

    fn fields() -> ChallengeFields<'static> {
        ChallengeFields {
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            epoch: Epoch::new(7),
            nonce: Nonce::parse(&fixture_nonce(params()), &params()).unwrap(),
            role_id: "ops.dc.senior",
            level: Level::new(2),
            server_id: "op-42",
            engineer_id: "eng-7",
            ephemeral_point: point(),
        }
    }

    fn challenge() -> Challenge {
        Challenge::new(fields()).unwrap()
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
                "server_id",
                "engineer_id",
                "ephemeral_point"
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
                "0000001a",
                "3434343434343434343434343434343434343434343434343434", // nonce: 26 characters of the default width
                "0000000d",
                "6f70732e64632e73656e696f72", // role id
                "00000004",
                "00000002", // level 2
                "00000005",
                "6f702d3432", // server id
                "00000005",
                "656e672d37", // engineer id
                "00000003",
                "04aabb", // ephemeral public point
            )
        );
    }

    #[test]
    fn separators_do_not_change_the_canonical_bytes() {
        let spaced = Challenge::new(ChallengeFields {
            device_number: CheckedDeviceNumber::parse(
                &challenge().device_number().as_str().replace('-', " "),
            )
            .unwrap(),
            ..fields()
        })
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
        // The two fields the MAC gained: a challenge that carried them and a
        // code input that dropped them would leave both sides computing over
        // less than the challenge says.
        assert_eq!(input.epoch, challenge.epoch());
        assert_eq!(input.engineer_id, "eng-7");
    }

    #[test]
    fn an_empty_engineer_number_is_refused_at_assembly() {
        assert_eq!(
            Challenge::new(ChallengeFields {
                engineer_id: "",
                ..fields()
            }),
            Err(ChallengeError::Wire(WireError::EmptyValue {
                field: "engineer_id"
            }))
        );
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
        let grouped_nonce = group_of(challenge.nonce().as_str());
        assert_eq!(fields.next(), Some(grouped_nonce.as_str()));
        assert!(grouped_nonce.contains(' '), "{grouped_nonce}");
        assert_eq!(fields.next(), Some("ops.dc.senior"));
        assert_eq!(fields.next(), Some("2"));
        assert_eq!(fields.next(), Some("op-42"));
        assert_eq!(fields.next(), Some("eng-7"));
        assert_eq!(fields.next(), Some("04aabb"));
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
            "tessera-codes/v1/challenge;epoch=7;device={};nonce=444444444444444444444444444444444444444;role=ops;level=2;\
             server=op-42;engineer=eng-7;ephemeral=04aabb",
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
        let text = challenge().to_string().replace("server=op-42", "server=");
        assert_eq!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::EmptyValue {
                field: "server"
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
        let full = fixture_nonce(params());
        let short = &full[1..];
        let text = challenge()
            .to_string()
            .replace(&format!("nonce={full}"), &format!("nonce={short}"));
        assert!(matches!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Nonce(_))
        ));
    }

    #[test]
    fn an_ephemeral_point_that_is_not_hexadecimal_does_not_parse() {
        let text = challenge()
            .to_string()
            .replace("ephemeral=04aabb", "ephemeral=04aabbz");
        assert_eq!(
            Challenge::parse(&text, &params()),
            Err(ChallengeError::Wire(WireError::NotHex {
                field: "ephemeral"
            }))
        );
    }

    #[test]
    fn a_substituted_ephemeral_point_changes_the_canonical_bytes() {
        // The point is what `Z` is computed against, so a challenge carrying
        // another point is another attempt — the bytes have to say so, or a
        // signature over them would cover a point that was swapped afterwards.
        let swapped = Challenge::new(ChallengeFields {
            ephemeral_point: EphemeralPublicPoint::new(vec![0x04, 0xaa, 0xbc]).unwrap(),
            ..fields()
        })
        .unwrap();
        assert_ne!(swapped.encode(), challenge().encode());
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
        let refused = Challenge::new(ChallengeFields {
            role_id: "ops;dc",
            ..fields()
        });
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

    /// Key of the device in the fixture registry record.
    const DEVICE_KEY: [u8; 3] = [0x04, 0xd1, 0xd1];

    /// Key of somebody else who also owns a device.
    const STRANGER_KEY: [u8; 3] = [0x04, 0xaa, 0xaa];

    /// A verifier where a signature holds under one key and no other.
    ///
    /// The fixture signature of a key is the key's own last byte, so a
    /// signature made by the stranger is a value this verifier can tell from a
    /// signature made by the device — which is the whole of what the test needs
    /// from public-key arithmetic the contract crate does not do.
    struct KeyBoundVerifier {
        /// Bytes the message must be, verbatim.
        message: Vec<u8>,
    }

    impl SignatureVerifier for KeyBoundVerifier {
        fn verify(
            &self,
            signer: SignerRef<'_>,
            message: &[u8],
            signature: &Signature,
        ) -> Result<(), SignatureError> {
            let SignerRef::Key(key) = signer else {
                return Err(SignatureError::UnknownSigner);
            };
            if message != self.message.as_slice() {
                return Err(SignatureError::Rejected);
            }
            let expected = [*key.as_bytes().last().unwrap()];
            if signature.as_bytes() != expected {
                return Err(SignatureError::Rejected);
            }
            Ok(())
        }
    }

    /// A verifier bound to the message the device signs for `challenge`.
    fn verifier_for(challenge: &Challenge) -> KeyBoundVerifier {
        KeyBoundVerifier {
            message: challenge.signing_message().unwrap(),
        }
    }

    /// Builds a registry record for one device number, epoch and key.
    fn record_of(device_body: &str, epoch: u32, key: [u8; 3]) -> DeviceRecord {
        let payload = RecordPayload::new(PayloadFields {
            device_number: CheckedDeviceNumber::from_body(device_body).unwrap(),
            public_key: PublicKey::new(key.to_vec()).unwrap(),
            epoch: Epoch::new(epoch),
            serials: vec![SerialNumber::new("chassis", "SN-1").unwrap()],
            key_protection: KeyProtection::Pkcs11ReportedNonExtractable,
            anchor: MonotonicAnchor::Present(AnchorKind::Tpm),
            batch: "batch-9",
            baseline: [0x55; 32],
        })
        .unwrap();
        DeviceRecord::new(RecordFields {
            payload,
            organisation_id: "acme",
            owner_id: "owner-1",
            possession_signature: Signature::new(vec![0x01]).unwrap(),
            organisation_signature: Signature::new(vec![0x02]).unwrap(),
            owner_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap()
    }

    /// The record of the device the fixture challenge is stated by.
    fn device_record() -> DeviceRecord {
        record_of("77-000123", 7, DEVICE_KEY)
    }

    /// Signs the fixture challenge as `key` would.
    fn signed_by(challenge: Challenge, key: [u8; 3]) -> SignedChallenge {
        let signature = Signature::new(vec![*key.last().unwrap()]).unwrap();
        SignedChallenge::new(challenge, signature)
    }

    #[test]
    fn a_challenge_signed_by_a_stranger_is_refused_against_the_registry_key() {
        let challenge = challenge();
        let signed = signed_by(challenge.clone(), STRANGER_KEY);
        assert_eq!(
            signed.verify(&device_record(), &verifier_for(&challenge)),
            Err(ChallengeError::Signature(SignatureError::Rejected))
        );
    }

    #[test]
    fn the_key_comes_from_the_record_and_the_record_must_be_the_right_one() {
        // The stranger holds a registry record of his own device, and his
        // signature holds under his key. Passing his record for this device's
        // challenge is the shape a lookup by the wrong number would take, and
        // it is refused before the key is used at all: otherwise one device
        // would be signing for another.
        let challenge = challenge();
        let signed = signed_by(challenge.clone(), STRANGER_KEY);
        let strangers_record = record_of("77-000999", 7, STRANGER_KEY);
        assert_eq!(
            signed.verify(&strangers_record, &verifier_for(&challenge)),
            Err(ChallengeError::RecordMismatch {
                field: "device number"
            })
        );

        // Same device, the key epoch before this one. The record is about a key
        // this challenge is not stated under.
        let older = record_of("77-000123", 6, DEVICE_KEY);
        assert_eq!(
            signed_by(challenge.clone(), DEVICE_KEY).verify(&older, &verifier_for(&challenge)),
            Err(ChallengeError::RecordMismatch { field: "epoch" })
        );
    }

    #[test]
    fn a_signature_does_not_carry_from_one_challenge_to_another() {
        // The device signed this challenge; the same signature offered for a
        // challenge asking for a higher level is a different message.
        let stated = challenge();
        let retold = Challenge::new(ChallengeFields {
            level: Level::new(3),
            ..fields()
        })
        .unwrap();
        let signed = signed_by(retold, DEVICE_KEY);
        assert_eq!(
            signed.verify(&device_record(), &verifier_for(&stated)),
            Err(ChallengeError::Signature(SignatureError::Rejected))
        );
    }

    #[test]
    fn the_signed_bytes_are_labelled_and_not_the_bare_encoding() {
        // A verifier expecting the challenge encoding itself rejects, which is
        // what keeps these bytes from being replayed as another document of the
        // contract signed over the same fields.
        let challenge = challenge();
        let unlabelled = KeyBoundVerifier {
            message: challenge.encode().unwrap(),
        };
        assert_eq!(
            signed_by(challenge.clone(), DEVICE_KEY).verify(&device_record(), &unlabelled),
            Err(ChallengeError::Signature(SignatureError::Rejected))
        );

        let message = challenge.signing_message().unwrap();
        assert!(message
            .windows(CHALLENGE_SIGNATURE_LABEL.len())
            .any(|window| window == CHALLENGE_SIGNATURE_LABEL.as_bytes()));
    }

    #[test]
    fn the_signed_bytes_are_frozen() {
        // A compatibility surface as hard as the golden vectors beside it: a
        // shift of one length prefix here does not fail anything obvious, it
        // quietly stops every signature any device ever made from verifying.
        // The vector files cannot hold this one — they carry the fields of the
        // code input, not of a challenge — so the bytes are frozen here.
        assert_eq!(
            hex::encode(challenge().signing_message().unwrap()),
            "00000024746573736572612d636f6465732f76312f6368616c6c656e67652d7369676e61\
             74757265000000650000000937373030303132335300000004000000070000001a343434\
             34343434343434343434343434343434343434343434340000000d6f70732e64632e7365\
             6e696f720000000400000002000000056f702d343200000005656e672d370000000304aa\
             bb"
        );
    }

    #[test]
    fn the_device_signature_is_accepted_against_its_own_record() {
        let challenge = challenge();
        assert_eq!(
            signed_by(challenge.clone(), DEVICE_KEY)
                .verify(&device_record(), &verifier_for(&challenge)),
            Ok(())
        );
    }

    #[test]
    fn the_signed_form_round_trips_and_refuses_the_unsigned_one() {
        let signed = signed_by(challenge(), DEVICE_KEY);
        let wire = signed.to_string();
        assert!(wire.starts_with(SIGNED_CHALLENGE_PREFIX));
        assert_eq!(SignedChallenge::parse(&wire, &params()), Ok(signed.clone()));

        // The two documents are not interchangeable in either direction: a
        // challenge with no signature offered where a signed one is expected is
        // refused by the reader, and the reverse too.
        assert!(SignedChallenge::parse(&challenge().to_string(), &params()).is_err());
        assert!(Challenge::parse(&wire, &params()).is_err());
    }

    #[test]
    fn the_spoken_form_ends_with_the_signature() {
        let signed = signed_by(challenge(), DEVICE_KEY);
        let spoken = signed.spoken_form();
        assert!(spoken.starts_with(&signed.challenge().spoken_form()));
        assert!(spoken.ends_with("d1"));
    }
}

//! The signed request of an engineer.
//!
//! One canonical object, signed once, carried everywhere afterwards. It says:
//! this engineer, at this device, asked for this role at this level, on these
//! grounds, at this moment, under this four-eyes policy. The issuing side signs
//! it into a grant ([`crate::grant`]); the reconciliation of a fleet pairs it
//! with what the devices recorded.
//!
//! # Why the authorisation fields are not here
//!
//! Because they are already in the challenge, and the challenge is inside the
//! request. Device, epoch, nonce, role, level, the personal number of the
//! engineer and the ephemeral point exist in **one** copy — the one the device
//! produced and the engineer signed over. A request that carried "role" beside
//! the challenge would have two roles in one document, and every consumer would
//! have to decide which of them is the request. The specification states the
//! rule; this module makes it structural: there is nowhere to put a second copy.
//!
//! What that costs is a little convenience for a reader of the wire form, and
//! that cost is paid back in [`crate::grant`], where a summary may be repeated
//! outside the signature — and is checked byte for byte against it.
//!
//! # Grounds
//!
//! Mandatory free text, plus an optional structured reference of "kind and
//! identifier" — a work order number, a ticket URL. The text is what makes the
//! format work in a fleet with no ticket system at all; the reference is what
//! lets a fleet that has one reconcile logins against orders automatically. A
//! request with no grounds is not a document of this contract and does not
//! assemble.

use crate::canon::{CanonError, Encoder};
use crate::challenge::{Challenge, ChallengeError};
use crate::mac::{sha256, DIGEST_LEN};
use crate::params::FleetParams;
use crate::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::time::ClaimedTime;
use crate::wire::{self, WireError};

/// Marker that opens the wire form of a request and pins the version.
pub const REQUEST_PREFIX: &str = "tessera-codes/v1/engineer-request";

/// Marker that opens the wire form of a signed request.
pub const SIGNED_REQUEST_PREFIX: &str = "tessera-codes/v1/signed-engineer-request";

/// Number of fields a request carries in its wire form.
pub const REQUEST_FIELD_COUNT: usize = 6;

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; REQUEST_FIELD_COUNT] = [
    "challenge",
    "grounds",
    "grounds_ref_kind",
    "grounds_ref_id",
    "requested_at",
    "four_eyes",
];

/// Field keys of the signed form.
const SIGNED_WIRE_KEYS: [&str; 2] = ["request", "engineer_signature"];

/// Value of the structured reference fields when there is no reference.
///
/// Written out rather than left empty because the wire form refuses empty
/// values everywhere else, and one field that may be empty is one field a
/// parser has to special-case in two places.
pub const NO_REFERENCE: &str = "none";

/// Label separating what an engineer signs from what anybody else signs.
///
/// Without it a signature made over these bytes for one purpose would be a
/// valid signature for another — the confirmation of [`crate::grant`] is over
/// the same object, and a confirmation that could stand in for the request
/// itself would let one signature do the work of two.
const ENGINEER_LABEL: &str = "tessera-codes-contract/v1/engineer-request";

/// A structured reference to whatever a fleet answers to.
///
/// Deliberately not tied to a system: a kind ("work-order", "ticket") and an
/// identifier the fleet reads. The contract checks that both are usable text
/// and that they travel together — a kind with no identifier says nothing, and
/// an identifier with no kind cannot be looked up.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroundsReference {
    kind: String,
    id: String,
}

impl GroundsReference {
    /// Wraps a reference.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::EmptyValue`] when either half is empty and
    /// [`WireError::UnusableValue`] when either carries a character the format
    /// cannot hold, or is spelled exactly like [`NO_REFERENCE`] — that spelling
    /// is how the absence of a reference is written, and a reference that
    /// looked like its own absence would be dropped by a reader.
    pub fn new(kind: &str, id: &str) -> Result<Self, RequestError> {
        wire::check_free_text("grounds_ref_kind", kind)?;
        wire::check_free_text("grounds_ref_id", id)?;
        if kind == NO_REFERENCE {
            return Err(RequestError::Wire(WireError::UnusableValue {
                field: "grounds_ref_kind",
            }));
        }
        Ok(Self {
            kind: kind.to_owned(),
            id: id.to_owned(),
        })
    }

    /// Returns the kind of the reference.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the identifier the fleet reads.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Digest of the four-eyes policy in force when the request was made.
///
/// The policy itself is a fleet configuration and does not belong in the
/// document; what belongs is which policy the engineer was working under, so
/// that a grant issued under a lax policy cannot later be read as one issued
/// under a strict one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourEyesDigest([u8; DIGEST_LEN]);

impl FourEyesDigest {
    /// Hashes the canonical text of a policy.
    #[must_use]
    pub fn of_policy(bytes: &[u8]) -> Self {
        Self(sha256(bytes))
    }

    /// Wraps a digest that was read from a document.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::DigestWidth`] when the value is not exactly the
    /// width of the digest: a short value silently zero-padded would compare
    /// equal to something it is not.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RequestError> {
        let value: [u8; DIGEST_LEN] = bytes
            .try_into()
            .map_err(|_| RequestError::DigestWidth { got: bytes.len() })?;
        Ok(Self(value))
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }
}

/// The values a request is assembled from.
#[derive(Debug)]
pub struct RequestFields<'a> {
    /// The challenge of the attempt, whole.
    pub challenge: Challenge,
    /// Grounds for the request, in free text. May not be empty.
    pub grounds: &'a str,
    /// Structured reference beside the text, when the fleet has one.
    pub grounds_reference: Option<GroundsReference>,
    /// The moment the engineer's side claims.
    pub requested_at: ClaimedTime,
    /// Which four-eyes policy was in force.
    pub four_eyes: FourEyesDigest,
}

/// What an engineer asks for, as one canonical object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineerRequest {
    challenge: Challenge,
    grounds: String,
    grounds_reference: Option<GroundsReference>,
    requested_at: ClaimedTime,
    four_eyes: FourEyesDigest,
}

impl EngineerRequest {
    /// Assembles a request.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::MissingGrounds`] when the grounds are empty or
    /// whitespace alone — a request nobody can answer for later is not a
    /// document of this contract — and the wire errors when the grounds carry a
    /// character the format cannot hold.
    pub fn new(fields: RequestFields<'_>) -> Result<Self, RequestError> {
        if fields.grounds.trim().is_empty() {
            return Err(RequestError::MissingGrounds);
        }
        wire::check_free_text("grounds", fields.grounds)?;
        Ok(Self {
            challenge: fields.challenge,
            grounds: fields.grounds.to_owned(),
            grounds_reference: fields.grounds_reference,
            requested_at: fields.requested_at,
            four_eyes: fields.four_eyes,
        })
    }

    /// Returns the challenge of the attempt.
    #[must_use]
    pub const fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// Returns the personal number of the engineer.
    ///
    /// Read out of the challenge rather than stored beside it: one copy, and
    /// this accessor is what makes the single copy convenient to use.
    #[must_use]
    pub fn engineer_id(&self) -> &str {
        self.challenge.engineer_id()
    }

    /// Returns the grounds, in free text.
    #[must_use]
    pub fn grounds(&self) -> &str {
        &self.grounds
    }

    /// Returns the structured reference, when the request carries one.
    #[must_use]
    pub const fn grounds_reference(&self) -> Option<&GroundsReference> {
        self.grounds_reference.as_ref()
    }

    /// Returns the moment the engineer's side claimed.
    #[must_use]
    pub const fn requested_at(&self) -> ClaimedTime {
        self.requested_at
    }

    /// Returns the digest of the four-eyes policy in force.
    #[must_use]
    pub const fn four_eyes(&self) -> FourEyesDigest {
        self.four_eyes
    }

    /// Encodes the object canonically — the bytes an engineer signs.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let (kind, id) = match &self.grounds_reference {
            Some(reference) => (reference.kind(), reference.id()),
            None => (NO_REFERENCE, NO_REFERENCE),
        };
        let mut encoder = Encoder::default();
        encoder.push_text("engineer_label", ENGINEER_LABEL)?;
        encoder.push_bytes("challenge", &self.challenge.encode()?)?;
        encoder.push_text("grounds", &self.grounds)?;
        encoder.push_text("grounds_ref_kind", kind)?;
        encoder.push_text("grounds_ref_id", id)?;
        encoder.push_u64("requested_at", self.requested_at.get())?;
        encoder.push_bytes("four_eyes", self.four_eyes.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Returns the digest of the canonical object.
    ///
    /// What a status-token binds to, and what a reconciliation names a request
    /// by: the whole object in thirty-two bytes.
    ///
    /// # Errors
    ///
    /// The errors of [`EngineerRequest::encode`].
    pub fn digest(&self) -> Result<[u8; DIGEST_LEN], CanonError> {
        Ok(sha256(&self.encode()?))
    }

    /// Renders the wire form.
    ///
    /// The challenge travels as the hexadecimal of its own wire form: one
    /// parser for a challenge, wherever it is read, and no second spelling of a
    /// document that is already frozen.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let (kind, id) = match &self.grounds_reference {
            Some(reference) => (reference.kind().to_owned(), reference.id().to_owned()),
            None => (NO_REFERENCE.to_owned(), NO_REFERENCE.to_owned()),
        };
        let [challenge, grounds, ref_kind, ref_id, requested_at, four_eyes] = WIRE_KEYS;
        let fields = [
            (challenge, hex::encode(self.challenge.to_wire())),
            (grounds, self.grounds.clone()),
            (ref_kind, kind),
            (ref_id, id),
            (requested_at, self.requested_at.get().to_string()),
            (four_eyes, hex::encode(self.four_eyes.as_bytes())),
        ];
        wire::render(REQUEST_PREFIX, &fields)
    }

    /// Parses the wire form against the fleet parameters, which fix the shape
    /// of the nonce inside the challenge.
    ///
    /// # Errors
    ///
    /// The [`RequestError`] describing the first violation: a missing or
    /// misspelled prefix, a wrong number of fields, a field out of order or
    /// unknown, an empty value, a challenge that does not parse, a reference
    /// with only one half, or grounds that are whitespace alone.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, RequestError> {
        let values = wire::parse(text, REQUEST_PREFIX, &WIRE_KEYS)?;
        let challenge_bytes = wire::parse_hex("challenge", wire::value(&values, 0))?;
        let challenge_text = String::from_utf8(challenge_bytes)
            .map_err(|_| RequestError::Wire(WireError::UnusableValue { field: "challenge" }))?;
        let challenge = Challenge::parse(&challenge_text, params)?;

        let kind = wire::value(&values, 1 + 1);
        let id = wire::value(&values, 1 + 2);
        let grounds_reference = match (kind, id) {
            (NO_REFERENCE, NO_REFERENCE) => None,
            (NO_REFERENCE, _) | (_, NO_REFERENCE) => {
                // Half a reference is not a reference: a kind with no
                // identifier cannot be looked up, and an identifier with no
                // kind does not say where to look.
                return Err(RequestError::HalfReference);
            }
            (kind, id) => Some(GroundsReference::new(kind, id)?),
        };

        let four_eyes =
            FourEyesDigest::from_bytes(&wire::parse_hex("four_eyes", wire::value(&values, 5))?)?;

        Self::new(RequestFields {
            challenge,
            grounds: wire::value(&values, 1),
            grounds_reference,
            requested_at: ClaimedTime::new(wire::parse_u64(
                "requested_at",
                wire::value(&values, 4),
            )?),
            four_eyes,
        })
    }
}

impl core::fmt::Display for EngineerRequest {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// A request with the signature of the engineer who made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    request: EngineerRequest,
    engineer_signature: Signature,
}

impl SignedRequest {
    /// Binds a signature to a request.
    #[must_use]
    pub const fn new(request: EngineerRequest, engineer_signature: Signature) -> Self {
        Self {
            request,
            engineer_signature,
        }
    }

    /// Returns the request.
    #[must_use]
    pub const fn request(&self) -> &EngineerRequest {
        &self.request
    }

    /// Returns the signature of the engineer.
    #[must_use]
    pub const fn engineer_signature(&self) -> &Signature {
        &self.engineer_signature
    }

    /// Verifies the signature of the engineer against the anchors of the
    /// consumer.
    ///
    /// The engineer is a named signer: which key belongs to which personal
    /// number is a registry question, and this crate holds no registry. What it
    /// does state is *which bytes* were signed — the canonical object, label
    /// included.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::Canon`] when the request cannot be encoded and
    /// [`RequestError::EngineerSignature`] when the signature does not hold or
    /// the engineer is not anchored.
    pub fn verify(&self, verifier: &impl SignatureVerifier) -> Result<(), RequestError> {
        let message = self.request.encode()?;
        verifier
            .verify(
                SignerRef::Named(self.request.engineer_id()),
                &message,
                &self.engineer_signature,
            )
            .map_err(RequestError::EngineerSignature)
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let [request, signature] = SIGNED_WIRE_KEYS;
        let fields = [
            (request, hex::encode(self.request.to_wire())),
            (signature, hex::encode(self.engineer_signature.as_bytes())),
        ];
        wire::render(SIGNED_REQUEST_PREFIX, &fields)
    }

    /// Parses the wire form.
    ///
    /// # Errors
    ///
    /// The [`RequestError`] describing the first violation, including every
    /// way the request inside can fail to parse.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, RequestError> {
        let values = wire::parse(text, SIGNED_REQUEST_PREFIX, &SIGNED_WIRE_KEYS)?;
        let inner = wire::parse_hex("request", wire::value(&values, 0))?;
        let inner = String::from_utf8(inner)
            .map_err(|_| RequestError::Wire(WireError::UnusableValue { field: "request" }))?;
        let request = EngineerRequest::parse(&inner, params)?;
        let signature = Signature::new(wire::parse_hex(
            "engineer_signature",
            wire::value(&values, 1),
        )?)?;
        Ok(Self::new(request, signature))
    }
}

impl core::fmt::Display for SignedRequest {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Rejection of a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The request carries no grounds.
    #[error(
        "the request records no grounds; a request nobody can answer for later is not a request"
    )]
    MissingGrounds,
    /// The structured reference carries only one of its two halves.
    #[error("the structured reference carries a kind without an identifier, or the reverse")]
    HalfReference,
    /// A digest field is not the width of a digest.
    #[error("a digest field is {got} bytes where the format has {}", DIGEST_LEN)]
    DigestWidth {
        /// Width that was offered.
        got: usize,
    },
    /// The wire form is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The challenge inside the request is not well formed.
    #[error(transparent)]
    Challenge(#[from] ChallengeError),
    /// The request could not be encoded.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// The signature of the engineer did not hold.
    #[error("the signature of the engineer was rejected: {0}")]
    EngineerSignature(#[source] SignatureError),
    /// A key or signature carries no material.
    #[error(transparent)]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
pub(crate) mod tests {
    use super::{
        EngineerRequest, FourEyesDigest, GroundsReference, RequestError, RequestFields,
        SignedRequest, NO_REFERENCE, REQUEST_PREFIX,
    };
    use crate::canon::Level;
    use crate::challenge::{Challenge, ChallengeFields};
    use crate::device_number::CheckedDeviceNumber;
    use crate::key::{EphemeralPublicPoint, Epoch};
    use crate::nonce::Nonce;
    use crate::params::FleetParams;
    use crate::signature::Signature;
    use crate::time::ClaimedTime;
    use crate::wire::WireError;

    pub(crate) fn params() -> FleetParams {
        FleetParams::defaults()
    }

    pub(crate) fn challenge() -> Challenge {
        let params = params();
        Challenge::new(ChallengeFields {
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            epoch: Epoch::new(7),
            nonce: Nonce::parse(&"4".repeat(usize::from(params.nonce_width())), &params).unwrap(),
            role_id: "ops.dc.senior",
            level: Level::new(2),
            server_id: "srv-1",
            engineer_id: "eng-7",
            ephemeral_point: EphemeralPublicPoint::new(vec![0x04, 0xaa, 0xbb]).unwrap(),
        })
        .unwrap()
    }

    pub(crate) fn request() -> EngineerRequest {
        EngineerRequest::new(RequestFields {
            challenge: challenge(),
            grounds: "work order 42",
            grounds_reference: Some(GroundsReference::new("work-order", "42").unwrap()),
            requested_at: ClaimedTime::new(1_800_000_000),
            four_eyes: FourEyesDigest::of_policy(b"level>=3 needs a second pair of eyes"),
        })
        .unwrap()
    }

    pub(crate) fn signed_request() -> SignedRequest {
        SignedRequest::new(request(), Signature::new(vec![0xab, 0xcd]).unwrap())
    }

    #[test]
    fn a_request_round_trips_through_the_wire_form() {
        let original = request();
        assert_eq!(
            EngineerRequest::parse(&original.to_wire(), &params()),
            Ok(original)
        );
    }

    #[test]
    fn a_request_without_a_reference_round_trips_too() {
        let plain = EngineerRequest::new(RequestFields {
            challenge: challenge(),
            grounds: "work order 42",
            grounds_reference: None,
            requested_at: ClaimedTime::new(1_800_000_000),
            four_eyes: FourEyesDigest::of_policy(b"off"),
        })
        .unwrap();
        assert!(plain.to_wire().contains(NO_REFERENCE));
        assert_eq!(
            EngineerRequest::parse(&plain.to_wire(), &params()),
            Ok(plain)
        );
    }

    #[test]
    fn the_authorisation_fields_exist_in_one_copy() {
        // The rule of the format, made structural: what the request says about
        // the device, the role, the level and the engineer is read out of the
        // challenge, so there is nowhere for a second answer to live.
        let request = request();
        assert_eq!(request.engineer_id(), request.challenge().engineer_id());
        assert_eq!(request.challenge().role_id(), "ops.dc.senior");

        // And the wire form carries no second copy of any of them beside the
        // challenge: every field of it is accounted for by the format.
        let wire = request.to_wire();
        let keys: Vec<&str> = wire
            .split(';')
            .skip(1)
            .filter_map(|field| field.split_once('='))
            .map(|(key, _)| key)
            .collect();
        assert_eq!(
            keys,
            vec![
                "challenge",
                "grounds",
                "grounds_ref_kind",
                "grounds_ref_id",
                "requested_at",
                "four_eyes"
            ]
        );
    }

    #[test]
    fn a_request_without_grounds_does_not_assemble() {
        let refused = EngineerRequest::new(RequestFields {
            challenge: challenge(),
            grounds: "   ",
            grounds_reference: None,
            requested_at: ClaimedTime::new(1_800_000_000),
            four_eyes: FourEyesDigest::of_policy(b"off"),
        });
        assert_eq!(refused, Err(RequestError::MissingGrounds));
    }

    #[test]
    fn half_a_reference_does_not_parse() {
        let text = request().to_wire().replace(
            "grounds_ref_id=42",
            &format!("grounds_ref_id={NO_REFERENCE}"),
        );
        assert_eq!(
            EngineerRequest::parse(&text, &params()),
            Err(RequestError::HalfReference)
        );
    }

    #[test]
    fn a_reference_spelled_like_its_own_absence_is_refused() {
        assert!(matches!(
            GroundsReference::new(NO_REFERENCE, "42"),
            Err(RequestError::Wire(WireError::UnusableValue {
                field: "grounds_ref_kind"
            }))
        ));
    }

    #[test]
    fn an_unknown_field_does_not_parse() {
        let text = format!("{};extra=1", request().to_wire());
        assert!(matches!(
            EngineerRequest::parse(&text, &params()),
            Err(RequestError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn a_field_out_of_order_does_not_parse() {
        let text = format!("{REQUEST_PREFIX};grounds=x;challenge=00");
        assert!(matches!(
            EngineerRequest::parse(&text, &params()),
            Err(RequestError::Wire(WireError::UnexpectedField {
                expected: "challenge",
                ..
            }))
        ));
    }

    #[test]
    fn a_broken_challenge_inside_does_not_parse() {
        let request = request();
        let damaged = hex::encode(
            request
                .challenge()
                .to_wire()
                .replace("level=2", "level=two"),
        );
        let text = request
            .to_wire()
            .replace(&hex::encode(request.challenge().to_wire()), &damaged);
        assert!(matches!(
            EngineerRequest::parse(&text, &params()),
            Err(RequestError::Challenge(_))
        ));
    }

    #[test]
    fn a_four_eyes_digest_of_the_wrong_width_does_not_parse() {
        let request = request();
        let text = request
            .to_wire()
            .replace(&hex::encode(request.four_eyes().as_bytes()), "0a0b");
        assert!(matches!(
            EngineerRequest::parse(&text, &params()),
            Err(RequestError::DigestWidth { got: 2 })
        ));
    }

    #[test]
    fn the_signed_form_round_trips() {
        let original = signed_request();
        assert_eq!(
            SignedRequest::parse(&original.to_wire(), &params()),
            Ok(original)
        );
    }

    #[test]
    fn editing_any_field_changes_the_bytes_the_engineer_signed() {
        let signed = request().encode().unwrap();
        for edited in [
            EngineerRequest::new(RequestFields {
                challenge: challenge(),
                grounds: "work order 43",
                grounds_reference: Some(GroundsReference::new("work-order", "42").unwrap()),
                requested_at: ClaimedTime::new(1_800_000_000),
                four_eyes: FourEyesDigest::of_policy(b"level>=3 needs a second pair of eyes"),
            })
            .unwrap(),
            EngineerRequest::new(RequestFields {
                challenge: challenge(),
                grounds: "work order 42",
                grounds_reference: Some(GroundsReference::new("work-order", "43").unwrap()),
                requested_at: ClaimedTime::new(1_800_000_000),
                four_eyes: FourEyesDigest::of_policy(b"level>=3 needs a second pair of eyes"),
            })
            .unwrap(),
            EngineerRequest::new(RequestFields {
                challenge: challenge(),
                grounds: "work order 42",
                grounds_reference: Some(GroundsReference::new("work-order", "42").unwrap()),
                requested_at: ClaimedTime::new(1_800_000_001),
                four_eyes: FourEyesDigest::of_policy(b"level>=3 needs a second pair of eyes"),
            })
            .unwrap(),
            EngineerRequest::new(RequestFields {
                challenge: challenge(),
                grounds: "work order 42",
                grounds_reference: Some(GroundsReference::new("work-order", "42").unwrap()),
                requested_at: ClaimedTime::new(1_800_000_000),
                four_eyes: FourEyesDigest::of_policy(b"off"),
            })
            .unwrap(),
        ] {
            assert_ne!(edited.encode().unwrap(), signed);
        }
    }
}

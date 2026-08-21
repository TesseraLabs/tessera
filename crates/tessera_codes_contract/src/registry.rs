//! The device registry record.
//!
//! A record says that a device exists, which key epoch it is in, what its key
//! is kept in, and who vouches for all of that. It is read at an exchange point
//! nobody controls — a medium carried between sites, a directory somebody else
//! writes — so nothing here is a conversion: every field is checked, and a
//! document that is not exactly the document this format describes is refused
//! rather than partially believed.
//!
//! # The payload and the three signatures
//!
//! The record is a **payload** and three signatures over it, in one order that
//! cannot be rearranged:
//!
//! 1. the **proof of possession**, made with the device key over the payload —
//!    it says the device holds the private half. Without it an organisation can
//!    enrol a key it does not control, its own or somebody else's;
//! 2. the **organisation signature**, over the payload *together with the proof
//!    of possession* — it says the fleet owner accepted this device with this
//!    key and this proof;
//! 3. the **owner countersignature**, over the digest of everything above — the
//!    signature of whoever answers for the registry as a whole.
//!
//! The order is a property of the format and not a convention, and that matters
//! more than it looks: "we always put them in this order" is the kind of
//! agreement that turns into a defect a year later. Two things enforce it. The
//! wire form has the signatures in fixed positions, so a rearranged document
//! does not parse; and each message carries what came before it, so a
//! rearranged *set* verifies against nothing — an organisation signature with
//! no proof of possession beneath it is a signature over other bytes.
//!
//! Every signature is domain separated by a label. Were they over the same
//! bytes, an organisation signature made by a device key would be a valid proof
//! of possession, and the reverse would hold too.
//!
//! # What the record says about the key, and what it does not
//!
//! The key protection rung ([`KeyProtection`]) is named after what was
//! **observed**, not after what anybody promised. A provider that reports
//! `CKA_EXTRACTABLE = false` and a provider that reports nothing at all are
//! different rungs, because silence proves nothing; folding them together is
//! exactly how "unknown" quietly becomes "safe". Nor does the top rung claim
//! the private half never reached host memory — a software provider can report
//! a non-extractable key. The rung is what the stack *claimed*; it becomes
//! confirmed only through an independent attestation, which is a separate
//! measure and not this document.
//!
//! The monotonic anchor field says an anchor is **present** and of which kind.
//! It does not say the anchor is trusted, and its absence is not an error: a
//! device without one is a device whose environment has to guarantee that its
//! memory cannot be snapshotted and restored. That is a premise about the
//! environment, and it is written down here so that it is visible in the
//! registry rather than assumed by whoever reads it.

use crate::canon::{CanonError, Encoder};
use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
use crate::key::Epoch;
use crate::mac::{sha256, DIGEST_LEN};
use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::wire::{self, WireError};

/// Marker that opens the wire form of a registry record and pins the version.
pub const RECORD_PREFIX: &str = "tessera-codes/v1/device-record";

/// Number of fields a record carries in its wire form.
pub const RECORD_FIELD_COUNT: usize = 13;

/// Field keys of the wire form, in the only order the parser accepts.
///
/// The three signatures sit at the end in the order they are made. A document
/// carrying them in another order does not parse at all — see the module
/// documentation for the second half of that guarantee.
const WIRE_KEYS: [&str; RECORD_FIELD_COUNT] = [
    "device",
    "key",
    "epoch",
    "serials",
    "key_protection",
    "anchor",
    "batch",
    "baseline",
    "organisation",
    "owner",
    "possession_signature",
    "organisation_signature",
    "owner_signature",
];

/// Label of the proof of possession.
const POSSESSION_LABEL: &str = "tessera-codes-contract/v1/proof-of-possession";

/// Label of the organisation signature.
const ORGANISATION_LABEL: &str = "tessera-codes-contract/v1/registry-organisation";

/// Label of the owner countersignature.
const OWNER_LABEL: &str = "tessera-codes-contract/v1/registry-owner";

/// Separator between the kind of a serial number and its value.
const SERIAL_SEPARATOR: char = ':';

/// Where the private half of the device key is kept, by what was observed.
///
/// The rungs are named after observable facts rather than after where an
/// operation is believed to have run — PKCS#11 does not report that, and a name
/// implying it would be a promise the stack cannot keep. See the module
/// documentation for what the top rung does *not* claim.
///
/// The declaration order is the strength order, weakest first, and
/// [`KeyProtection::is_at_least`] is what a fleet floor is enforced with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyProtection {
    /// A container — a file, or an object on a token — whose key is copyable.
    Pkcs12Envelope,
    /// The provider reports the key as extractable.
    Pkcs11ReportedExtractable,
    /// The provider reports nothing about extractability.
    ///
    /// A rung of its own and not a variety of either neighbour: silence does
    /// not prove non-extractability, and reading it as one of them is how a
    /// fleet learns about a weak key from an incident report rather than from
    /// its own configuration.
    Pkcs11ExtractabilityUnknown,
    /// The provider reports the key as non-extractable.
    Pkcs11ReportedNonExtractable,
}

impl KeyProtection {
    /// The token this rung is written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pkcs12Envelope => "pkcs12_envelope",
            Self::Pkcs11ReportedExtractable => "pkcs11_reported_extractable",
            Self::Pkcs11ExtractabilityUnknown => "pkcs11_extractability_unknown",
            Self::Pkcs11ReportedNonExtractable => "pkcs11_reported_nonextractable",
        }
    }

    /// Reads a rung, or nothing.
    ///
    /// A token this format does not describe is not mapped to a neighbouring
    /// rung: a record written by something else is refused, not guessed at.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "pkcs12_envelope" => Some(Self::Pkcs12Envelope),
            "pkcs11_reported_extractable" => Some(Self::Pkcs11ReportedExtractable),
            "pkcs11_extractability_unknown" => Some(Self::Pkcs11ExtractabilityUnknown),
            "pkcs11_reported_nonextractable" => Some(Self::Pkcs11ReportedNonExtractable),
            _ => None,
        }
    }

    /// Reports whether this rung is at least as strong as `floor`.
    #[must_use]
    pub fn is_at_least(self, floor: Self) -> bool {
        self >= floor
    }
}

/// The kind of monotonic anchor a device carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorKind {
    /// A monotonic counter of a TPM.
    Tpm,
    /// A counter in the chip of the carrier.
    Carrier,
}

impl AnchorKind {
    /// The token this kind is written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::Carrier => "carrier",
        }
    }
}

/// Whether the device carries a monotonic anchor, and of which kind.
///
/// Absence is a value, not a failure: a device without an anchor is a device
/// whose environment has to guarantee its memory cannot be snapshotted and
/// restored. A field that could not express "none" would leave every reader
/// guessing which devices those are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MonotonicAnchor {
    /// No anchor. See the module documentation for what that premises.
    None,
    /// An anchor of this kind is present. Present, not trusted.
    Present(AnchorKind),
}

impl MonotonicAnchor {
    /// The token this value is written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Present(kind) => kind.as_str(),
        }
    }

    /// Reads an anchor field, or nothing.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "none" => Some(Self::None),
            "tpm" => Some(Self::Present(AnchorKind::Tpm)),
            "carrier" => Some(Self::Present(AnchorKind::Carrier)),
            _ => None,
        }
    }

    /// Reports whether an anchor is present.
    #[must_use]
    pub const fn is_present(self) -> bool {
        matches!(self, Self::Present(_))
    }
}

/// One serial number of a device: what it identifies, and the number itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SerialNumber {
    kind: String,
    value: String,
}

impl SerialNumber {
    /// Wraps a serial number.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when either half is empty or carries a character
    /// the format cannot hold, and [`RecordError::SerialShape`] when either half
    /// carries the separator — a serial that split into three pieces would be
    /// read as a different serial by anything that split it differently.
    pub fn new(kind: &str, value: &str) -> Result<Self, RecordError> {
        wire::check_list_item("serials", kind)?;
        wire::check_list_item("serials", value)?;
        if kind.contains(SERIAL_SEPARATOR) || value.contains(SERIAL_SEPARATOR) {
            return Err(RecordError::SerialShape);
        }
        Ok(Self {
            kind: kind.to_owned(),
            value: value.to_owned(),
        })
    }

    /// Returns what this serial identifies — a chassis, a board, a carrier.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the number itself.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Renders the serial as it travels.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{}{SERIAL_SEPARATOR}{}", self.kind, self.value)
    }

    /// Parses one item of the serial list.
    ///
    /// # Errors
    ///
    /// [`RecordError::SerialShape`] when the item is not exactly one kind and
    /// one value, and the wire errors for an unusable half.
    pub fn parse(text: &str) -> Result<Self, RecordError> {
        let (kind, value) = text
            .split_once(SERIAL_SEPARATOR)
            .ok_or(RecordError::SerialShape)?;
        Self::new(kind, value)
    }
}

/// The values a payload is assembled from.
#[derive(Debug)]
pub struct PayloadFields<'a> {
    /// Number of the device, check character included.
    pub device_number: CheckedDeviceNumber,
    /// Public key of the key epoch the device is in.
    pub public_key: PublicKey,
    /// The key epoch.
    pub epoch: Epoch,
    /// Serial numbers of the device. At least one.
    pub serials: Vec<SerialNumber>,
    /// What the key is kept in, by observation.
    pub key_protection: KeyProtection,
    /// Whether a monotonic anchor is present, and of which kind.
    pub anchor: MonotonicAnchor,
    /// Manufacturing batch of the device.
    pub batch: &'a str,
    /// Fingerprint of the baseline the device was accepted with.
    pub baseline: [u8; DIGEST_LEN],
}

/// What the registry says about a device, before anybody signs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPayload {
    device_number: CheckedDeviceNumber,
    public_key: PublicKey,
    epoch: Epoch,
    serials: Vec<SerialNumber>,
    key_protection: KeyProtection,
    anchor: MonotonicAnchor,
    batch: String,
    baseline: [u8; DIGEST_LEN],
}

impl RecordPayload {
    /// Assembles a payload.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::NoSerials`] when the list of serial numbers is
    /// empty — a device the registry cannot identify by anything but its own
    /// number is not a device an audit can find on a shelf — and the wire
    /// errors when the batch carries a character the format cannot hold.
    pub fn new(fields: PayloadFields<'_>) -> Result<Self, RecordError> {
        if fields.serials.is_empty() {
            return Err(RecordError::NoSerials);
        }
        wire::check_free_text("batch", fields.batch)?;
        Ok(Self {
            device_number: fields.device_number,
            public_key: fields.public_key,
            epoch: fields.epoch,
            serials: fields.serials,
            key_protection: fields.key_protection,
            anchor: fields.anchor,
            batch: fields.batch.to_owned(),
            baseline: fields.baseline,
        })
    }

    /// Returns the device number, check character included.
    #[must_use]
    pub const fn device_number(&self) -> &CheckedDeviceNumber {
        &self.device_number
    }

    /// Returns the public key of this key epoch of the device.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the key epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the serial numbers of the device.
    #[must_use]
    pub fn serials(&self) -> &[SerialNumber] {
        &self.serials
    }

    /// Returns the rung the key protection was observed at.
    #[must_use]
    pub const fn key_protection(&self) -> KeyProtection {
        self.key_protection
    }

    /// Returns whether a monotonic anchor is present, and of which kind.
    #[must_use]
    pub const fn anchor(&self) -> MonotonicAnchor {
        self.anchor
    }

    /// Returns the manufacturing batch.
    #[must_use]
    pub fn batch(&self) -> &str {
        &self.batch
    }

    /// Returns the fingerprint of the baseline.
    #[must_use]
    pub const fn baseline(&self) -> &[u8; DIGEST_LEN] {
        &self.baseline
    }

    /// Encodes the payload canonically.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("device_number", self.device_number.significant())?;
        encoder.push_bytes("public_key", self.public_key.as_bytes())?;
        encoder.push_u32("epoch", self.epoch.get())?;
        // The count goes in front of the items so the encoding says how many
        // there are rather than leaving it to be inferred from where the next
        // field starts. Every item is length-prefixed too, so this is not what
        // keeps two lists apart — it is what keeps the byte string readable
        // without the field table beside it.
        let count = u32::try_from(self.serials.len()).map_err(|_| CanonError::FieldTooLong {
            field: "serial_count",
        })?;
        encoder.push_u32("serial_count", count)?;
        for serial in &self.serials {
            encoder.push_text("serial_kind", serial.kind())?;
            encoder.push_text("serial_value", serial.value())?;
        }
        encoder.push_text("key_protection", self.key_protection.as_str())?;
        encoder.push_text("anchor", self.anchor.as_str())?;
        encoder.push_text("batch", &self.batch)?;
        encoder.push_bytes("baseline", &self.baseline)?;
        Ok(encoder.finish())
    }
}

/// The values a record is assembled from.
#[derive(Debug)]
pub struct RecordFields<'a> {
    /// What the registry says about the device.
    pub payload: RecordPayload,
    /// Organisation that registered the device.
    pub organisation_id: &'a str,
    /// Owner who answers for the registry and countersigns the record.
    pub owner_id: &'a str,
    /// Proof of possession, made with the device key over the payload.
    pub possession_signature: Signature,
    /// Organisation signature, over the payload and the proof of possession.
    pub organisation_signature: Signature,
    /// Owner countersignature, over the digest of everything above.
    pub owner_signature: Signature,
}

/// A device as its registry holds it: the payload and three signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    payload: RecordPayload,
    organisation_id: String,
    owner_id: String,
    possession_signature: Signature,
    organisation_signature: Signature,
    owner_signature: Signature,
}

impl DeviceRecord {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when an identifier is empty or carries a
    /// character the format cannot hold.
    pub fn new(fields: RecordFields<'_>) -> Result<Self, RecordError> {
        wire::check_free_text("organisation", fields.organisation_id)?;
        wire::check_free_text("owner", fields.owner_id)?;
        Ok(Self {
            payload: fields.payload,
            organisation_id: fields.organisation_id.to_owned(),
            owner_id: fields.owner_id.to_owned(),
            possession_signature: fields.possession_signature,
            organisation_signature: fields.organisation_signature,
            owner_signature: fields.owner_signature,
        })
    }

    /// Returns the payload.
    #[must_use]
    pub const fn payload(&self) -> &RecordPayload {
        &self.payload
    }

    /// Returns the device number, check character included.
    #[must_use]
    pub const fn device_number(&self) -> &CheckedDeviceNumber {
        self.payload.device_number()
    }

    /// Returns the public key of this key epoch of the device.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        self.payload.public_key()
    }

    /// Returns the key epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.payload.epoch()
    }

    /// Returns the identifier of the organisation that registered the device.
    #[must_use]
    pub fn organisation_id(&self) -> &str {
        &self.organisation_id
    }

    /// Returns the identifier of the owner who countersigned the record.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// Returns the proof of possession made with the device key.
    #[must_use]
    pub const fn possession_signature(&self) -> &Signature {
        &self.possession_signature
    }

    /// Returns the signature of the organisation.
    #[must_use]
    pub const fn organisation_signature(&self) -> &Signature {
        &self.organisation_signature
    }

    /// Returns the countersignature of the owner.
    #[must_use]
    pub const fn owner_signature(&self) -> &Signature {
        &self.owner_signature
    }

    /// Encodes the message the device signs to prove possession of the key.
    ///
    /// # Errors
    ///
    /// The errors of the payload encoding.
    pub fn possession_message(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("label", POSSESSION_LABEL)?;
        encoder.push_bytes("payload", &self.payload.encode()?)?;
        Ok(encoder.finish())
    }

    /// Encodes the message the organisation signs: the payload *and* the proof
    /// of possession beneath it.
    ///
    /// # Errors
    ///
    /// The errors of the payload encoding.
    pub fn organisation_message(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("label", ORGANISATION_LABEL)?;
        encoder.push_text("organisation_id", &self.organisation_id)?;
        encoder.push_bytes("payload", &self.payload.encode()?)?;
        encoder.push_bytes("possession", self.possession_signature.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Encodes the message the owner countersigns: the digest of everything
    /// above it.
    ///
    /// # Errors
    ///
    /// The errors of the payload encoding.
    pub fn owner_message(&self) -> Result<Vec<u8>, CanonError> {
        let mut previous = Encoder::default();
        previous.push_bytes("payload", &self.payload.encode()?)?;
        previous.push_bytes("possession", self.possession_signature.as_bytes())?;
        previous.push_bytes("organisation", self.organisation_signature.as_bytes())?;
        let digest = sha256(&previous.finish());

        let mut encoder = Encoder::default();
        encoder.push_text("label", OWNER_LABEL)?;
        encoder.push_text("owner_id", &self.owner_id)?;
        encoder.push_bytes("previous", &digest)?;
        Ok(encoder.finish())
    }

    /// Verifies the three signatures, in the order they were made.
    ///
    /// The order is enforced by construction rather than by comparing anything:
    /// each message carries what came before it, so a set of signatures made in
    /// another order verifies against nothing. The organisation and the owner
    /// are signers the verifier resolves against its own anchors; the proof of
    /// possession is checked against the key the record carries, which proves
    /// possession of that key and says nothing about whether the key is
    /// trusted. All three are required: none of the three statements implies
    /// another.
    ///
    /// # Errors
    ///
    /// [`RecordError::Canon`] when the record cannot be encoded, and
    /// [`RecordError::PossessionSignature`],
    /// [`RecordError::OrganisationSignature`] or [`RecordError::OwnerSignature`]
    /// when the respective signature does not hold or its signer is not
    /// anchored.
    pub fn verify(&self, verifier: &impl SignatureVerifier) -> Result<(), RecordError> {
        verifier
            .verify(
                SignerRef::Key(self.public_key()),
                &self.possession_message()?,
                &self.possession_signature,
            )
            .map_err(RecordError::PossessionSignature)?;

        verifier
            .verify(
                SignerRef::Named(&self.organisation_id),
                &self.organisation_message()?,
                &self.organisation_signature,
            )
            .map_err(RecordError::OrganisationSignature)?;

        verifier
            .verify(
                SignerRef::Named(&self.owner_id),
                &self.owner_message()?,
                &self.owner_signature,
            )
            .map_err(RecordError::OwnerSignature)?;
        Ok(())
    }

    /// Renders the wire form of the record.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let serials = self
            .payload
            .serials()
            .iter()
            .map(SerialNumber::to_wire)
            .collect::<Vec<_>>()
            .join(",");
        let fields = [
            ("device", self.device_number().as_str().to_owned()),
            ("key", hex::encode(self.public_key().as_bytes())),
            ("epoch", self.epoch().get().to_string()),
            ("serials", serials),
            (
                "key_protection",
                self.payload.key_protection().as_str().to_owned(),
            ),
            ("anchor", self.payload.anchor().as_str().to_owned()),
            ("batch", self.payload.batch().to_owned()),
            ("baseline", hex::encode(self.payload.baseline())),
            ("organisation", self.organisation_id.clone()),
            ("owner", self.owner_id.clone()),
            (
                "possession_signature",
                hex::encode(self.possession_signature.as_bytes()),
            ),
            (
                "organisation_signature",
                hex::encode(self.organisation_signature.as_bytes()),
            ),
            (
                "owner_signature",
                hex::encode(self.owner_signature.as_bytes()),
            ),
        ];
        wire::render(RECORD_PREFIX, &fields)
    }

    /// Parses the wire form of a record.
    ///
    /// # Errors
    ///
    /// Returns the [`RecordError`] describing the first violation: a wrong or
    /// missing prefix, a field that is unknown, missing or out of order, an
    /// empty value, a device number whose check character does not match, a
    /// rung or an anchor no variant is written under, a serial that is not one
    /// kind and one value, a baseline of the wrong width, or a value the target
    /// type cannot hold.
    pub fn parse(text: &str) -> Result<Self, RecordError> {
        let values = wire::parse(text, RECORD_PREFIX, &WIRE_KEYS)?;
        let device_number = CheckedDeviceNumber::parse(wire::value(&values, 0))?;
        let public_key = PublicKey::new(wire::parse_hex("key", wire::value(&values, 1))?)?;
        let epoch = Epoch::new(wire::parse_u32("epoch", wire::value(&values, 2))?);

        let serials = wire::value(&values, 3)
            .split(',')
            .map(SerialNumber::parse)
            .collect::<Result<Vec<_>, _>>()?;

        let key_protection =
            KeyProtection::parse(wire::value(&values, 4)).ok_or(RecordError::UnknownToken {
                field: "key_protection",
            })?;
        let anchor = MonotonicAnchor::parse(wire::value(&values, 5))
            .ok_or(RecordError::UnknownToken { field: "anchor" })?;

        let baseline_bytes = wire::parse_hex("baseline", wire::value(&values, 7))?;
        let baseline: [u8; DIGEST_LEN] =
            baseline_bytes
                .as_slice()
                .try_into()
                .map_err(|_| RecordError::DigestWidth {
                    field: "baseline",
                    got: baseline_bytes.len(),
                })?;

        let payload = RecordPayload::new(PayloadFields {
            device_number,
            public_key,
            epoch,
            serials,
            key_protection,
            anchor,
            batch: wire::value(&values, 6),
            baseline,
        })?;

        Self::new(RecordFields {
            payload,
            organisation_id: wire::value(&values, 8),
            owner_id: wire::value(&values, 9),
            possession_signature: Signature::new(wire::parse_hex(
                "possession_signature",
                wire::value(&values, 10),
            )?)?,
            organisation_signature: Signature::new(wire::parse_hex(
                "organisation_signature",
                wire::value(&values, 11),
            )?)?,
            owner_signature: Signature::new(wire::parse_hex(
                "owner_signature",
                wire::value(&values, 12),
            )?)?,
        })
    }
}

impl core::fmt::Display for DeviceRecord {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Rejection of a registry record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The record carries no serial number of the device.
    #[error("the record carries no serial number")]
    NoSerials,
    /// A serial number is not exactly one kind and one value.
    #[error("a serial number is not one kind and one value")]
    SerialShape,
    /// A token field carries a value no variant is written under.
    #[error("the record field `{field}` carries a value no variant is written under")]
    UnknownToken {
        /// Name of the offending field.
        field: &'static str,
    },
    /// A digest field is not the width of a digest.
    #[error(
        "the record field `{field}` is {got} bytes where the format has {}",
        DIGEST_LEN
    )]
    DigestWidth {
        /// Name of the offending field.
        field: &'static str,
        /// Width that was offered.
        got: usize,
    },
    /// The wire form of the record is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The device number failed its check character.
    #[error(transparent)]
    DeviceNumber(#[from] DeviceNumberError),
    /// The record cannot be encoded canonically.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// A key or signature carries no material.
    #[error(transparent)]
    Material(#[from] SignatureError),
    /// The proof of possession was rejected.
    #[error("the proof of possession was rejected: {0}")]
    PossessionSignature(SignatureError),
    /// The organisation signature was rejected.
    #[error("the organisation signature was rejected: {0}")]
    OrganisationSignature(SignatureError),
    /// The owner countersignature was rejected.
    #[error("the owner countersignature was rejected: {0}")]
    OwnerSignature(SignatureError),
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
pub(crate) mod tests {
    use super::{
        AnchorKind, DeviceRecord, KeyProtection, MonotonicAnchor, PayloadFields, RecordError,
        RecordFields, RecordPayload, SerialNumber, RECORD_PREFIX,
    };
    use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
    use crate::key::Epoch;
    use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
    use crate::wire::WireError;

    /// A verifier that accepts a signature only over the message the record
    /// says belongs to that signer, so a test can tell the three messages
    /// apart — and so a rearranged set of signatures fails the way it would in
    /// a real fleet.
    struct MessageBoundVerifier {
        possession: Vec<u8>,
        organisation: Vec<u8>,
        owner: Vec<u8>,
    }

    impl MessageBoundVerifier {
        fn of(record: &DeviceRecord) -> Self {
            Self {
                possession: record.possession_message().unwrap(),
                organisation: record.organisation_message().unwrap(),
                owner: record.owner_message().unwrap(),
            }
        }
    }

    impl SignatureVerifier for MessageBoundVerifier {
        fn verify(
            &self,
            signer: SignerRef<'_>,
            message: &[u8],
            signature: &Signature,
        ) -> Result<(), SignatureError> {
            // The signer decides which message is expected, and the signature
            // bytes decide which signature is expected: the fixture uses one
            // byte per role, so a swapped pair is visible here exactly as a
            // wrong signature would be to a real verifier.
            let (expected_message, expected_signature) = match signer {
                SignerRef::Key(_) => (&self.possession, 0x01_u8),
                SignerRef::Named("acme") => (&self.organisation, 0x02),
                SignerRef::Named(_) => (&self.owner, 0x03),
                SignerRef::TicketAuthority => return Err(SignatureError::UnknownSigner),
            };
            if message != expected_message.as_slice() {
                return Err(SignatureError::Rejected);
            }
            if signature.as_bytes() != [expected_signature] {
                return Err(SignatureError::Rejected);
            }
            Ok(())
        }
    }

    pub(crate) fn payload() -> RecordPayload {
        RecordPayload::new(PayloadFields {
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            public_key: PublicKey::new(vec![0x04, 0x11, 0x22]).unwrap(),
            epoch: Epoch::new(7),
            serials: vec![
                SerialNumber::new("chassis", "SN-1").unwrap(),
                SerialNumber::new("board", "SN-2").unwrap(),
            ],
            key_protection: KeyProtection::Pkcs11ReportedNonExtractable,
            anchor: MonotonicAnchor::Present(AnchorKind::Tpm),
            batch: "batch-9",
            baseline: [0x55; 32],
        })
        .unwrap()
    }

    pub(crate) fn record() -> DeviceRecord {
        DeviceRecord::new(RecordFields {
            payload: payload(),
            organisation_id: "acme",
            owner_id: "owner-1",
            possession_signature: Signature::new(vec![0x01]).unwrap(),
            organisation_signature: Signature::new(vec![0x02]).unwrap(),
            owner_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn a_record_round_trips_through_the_wire_form() {
        let original = record();
        assert_eq!(DeviceRecord::parse(&original.to_wire()), Ok(original));
    }

    #[test]
    fn all_three_signatures_are_checked() {
        let record = record();
        assert_eq!(record.verify(&MessageBoundVerifier::of(&record)), Ok(()));
    }

    #[test]
    fn the_three_messages_are_different_bytes() {
        // Domain separation: an organisation signature made by a device key
        // must not be a valid proof of possession, and the reverse must not
        // hold either.
        let record = record();
        let possession = record.possession_message().unwrap();
        let organisation = record.organisation_message().unwrap();
        let owner = record.owner_message().unwrap();
        assert_ne!(possession, organisation);
        assert_ne!(organisation, owner);
        assert_ne!(possession, owner);
    }

    #[test]
    fn each_signature_covers_the_ones_before_it() {
        // What makes the order a property of the format rather than a habit:
        // change the proof of possession and the organisation message moves;
        // change either and the owner message moves.
        let record = record();
        let other_possession = DeviceRecord::new(RecordFields {
            payload: payload(),
            organisation_id: "acme",
            owner_id: "owner-1",
            possession_signature: Signature::new(vec![0x09]).unwrap(),
            organisation_signature: Signature::new(vec![0x02]).unwrap(),
            owner_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap();
        assert_ne!(
            record.organisation_message().unwrap(),
            other_possession.organisation_message().unwrap()
        );
        assert_ne!(
            record.owner_message().unwrap(),
            other_possession.owner_message().unwrap()
        );

        let other_organisation = DeviceRecord::new(RecordFields {
            payload: payload(),
            organisation_id: "acme",
            owner_id: "owner-1",
            possession_signature: Signature::new(vec![0x01]).unwrap(),
            organisation_signature: Signature::new(vec![0x09]).unwrap(),
            owner_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap();
        assert_ne!(
            record.owner_message().unwrap(),
            other_organisation.owner_message().unwrap()
        );
    }

    #[test]
    fn signatures_in_the_wrong_order_do_not_verify() {
        // The set is the same three signatures, put in different places. A
        // format where the order were a convention would accept this.
        let swapped = DeviceRecord::new(RecordFields {
            payload: payload(),
            organisation_id: "acme",
            owner_id: "owner-1",
            possession_signature: Signature::new(vec![0x01]).unwrap(),
            organisation_signature: Signature::new(vec![0x03]).unwrap(),
            owner_signature: Signature::new(vec![0x02]).unwrap(),
        })
        .unwrap();
        let verifier = MessageBoundVerifier::of(&swapped);
        assert!(matches!(
            swapped.verify(&verifier),
            Err(RecordError::OrganisationSignature(_))
        ));
    }

    #[test]
    fn a_signature_over_other_bytes_does_not_verify() {
        // The organisation signed a record with another payload; the signature
        // is well formed and belongs to an anchored signer, and it still must
        // not carry this record.
        let record = record();
        let elsewhere = DeviceRecord::new(RecordFields {
            payload: RecordPayload::new(PayloadFields {
                device_number: CheckedDeviceNumber::from_body("77-000999").unwrap(),
                public_key: PublicKey::new(vec![0x04, 0x11, 0x22]).unwrap(),
                epoch: Epoch::new(7),
                serials: vec![SerialNumber::new("chassis", "SN-1").unwrap()],
                key_protection: KeyProtection::Pkcs11ReportedNonExtractable,
                anchor: MonotonicAnchor::Present(AnchorKind::Tpm),
                batch: "batch-9",
                baseline: [0x55; 32],
            })
            .unwrap(),
            organisation_id: "acme",
            owner_id: "owner-1",
            possession_signature: Signature::new(vec![0x01]).unwrap(),
            organisation_signature: Signature::new(vec![0x02]).unwrap(),
            owner_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap();
        // The verifier is bound to the messages of the *other* record.
        assert!(matches!(
            record.verify(&MessageBoundVerifier::of(&elsewhere)),
            Err(RecordError::PossessionSignature(_))
        ));
    }

    #[test]
    fn a_missing_signature_does_not_parse() {
        let text = record().to_wire().replace(";owner_signature=03", "");
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn an_extra_signature_does_not_parse() {
        let text = format!("{};extra_signature=04", record().to_wire());
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn signatures_out_of_order_do_not_parse() {
        let text = record().to_wire().replace(
            "possession_signature=01;organisation_signature=02",
            "organisation_signature=02;possession_signature=01",
        );
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::Wire(WireError::UnexpectedField {
                expected: "possession_signature",
                ..
            }))
        ));
    }

    #[test]
    fn an_unknown_field_does_not_parse() {
        let text = format!("{};extra=1", record().to_wire());
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn a_broken_structure_does_not_parse() {
        assert!(matches!(
            DeviceRecord::parse("tessera-codes/v0/device-record;device=77-000123S"),
            Err(RecordError::Wire(WireError::WrongPrefix { .. }))
        ));
        let text = record().to_wire().replace(";epoch=7", ";epoch");
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::Wire(WireError::MalformedField { .. }))
        ));
    }

    #[test]
    fn an_empty_value_does_not_parse() {
        let text = record().to_wire().replace("batch=batch-9", "batch=");
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::Wire(WireError::EmptyValue { field: "batch" }))
        ));
    }

    #[test]
    fn a_broken_check_character_does_not_parse() {
        let text = record().to_wire().replacen("device=77", "device=78", 1);
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::DeviceNumber(
                DeviceNumberError::CheckCharacterMismatch { .. }
            ))
        ));
    }

    #[test]
    fn a_key_protection_rung_no_variant_is_written_under_does_not_parse() {
        // In particular: a record that says "the token is fine, trust us" is
        // not a record. The rungs are observations, and an unknown observation
        // is not mapped onto a neighbouring one.
        let text = record().to_wire().replace(
            "key_protection=pkcs11_reported_nonextractable",
            "key_protection=hardware_backed",
        );
        assert_eq!(
            DeviceRecord::parse(&text),
            Err(RecordError::UnknownToken {
                field: "key_protection"
            })
        );
    }

    #[test]
    fn the_rungs_are_ordered_and_silence_is_not_the_top() {
        // The distinction the ladder exists for: "reported non-extractable" is
        // stronger than "said nothing", which is stronger than "reported
        // extractable". Folding the middle rung into either neighbour is the
        // defect this test exists to catch.
        assert!(KeyProtection::Pkcs11ReportedNonExtractable
            .is_at_least(KeyProtection::Pkcs11ExtractabilityUnknown));
        assert!(!KeyProtection::Pkcs11ExtractabilityUnknown
            .is_at_least(KeyProtection::Pkcs11ReportedNonExtractable));
        assert!(KeyProtection::Pkcs11ExtractabilityUnknown
            .is_at_least(KeyProtection::Pkcs11ReportedExtractable));
        assert!(
            !KeyProtection::Pkcs12Envelope.is_at_least(KeyProtection::Pkcs11ReportedExtractable)
        );
    }

    #[test]
    fn an_anchor_no_variant_is_written_under_does_not_parse() {
        let text = record().to_wire().replace("anchor=tpm", "anchor=yes");
        assert_eq!(
            DeviceRecord::parse(&text),
            Err(RecordError::UnknownToken { field: "anchor" })
        );
    }

    #[test]
    fn a_device_without_an_anchor_is_a_record_and_not_an_error() {
        // The absence is a premise about the environment, and the registry has
        // to be able to say it plainly.
        let without = DeviceRecord::new(RecordFields {
            payload: RecordPayload::new(PayloadFields {
                anchor: MonotonicAnchor::None,
                ..PayloadFields {
                    device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
                    public_key: PublicKey::new(vec![0x04, 0x11, 0x22]).unwrap(),
                    epoch: Epoch::new(7),
                    serials: vec![SerialNumber::new("chassis", "SN-1").unwrap()],
                    key_protection: KeyProtection::Pkcs12Envelope,
                    anchor: MonotonicAnchor::None,
                    batch: "batch-9",
                    baseline: [0x55; 32],
                }
            })
            .unwrap(),
            organisation_id: "acme",
            owner_id: "owner-1",
            possession_signature: Signature::new(vec![0x01]).unwrap(),
            organisation_signature: Signature::new(vec![0x02]).unwrap(),
            owner_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap();
        assert!(!without.payload().anchor().is_present());
        assert_eq!(DeviceRecord::parse(&without.to_wire()), Ok(without));
    }

    #[test]
    fn a_record_without_serials_does_not_assemble_or_parse() {
        let refused = RecordPayload::new(PayloadFields {
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            public_key: PublicKey::new(vec![0x04, 0x11, 0x22]).unwrap(),
            epoch: Epoch::new(7),
            serials: Vec::new(),
            key_protection: KeyProtection::Pkcs12Envelope,
            anchor: MonotonicAnchor::None,
            batch: "batch-9",
            baseline: [0x55; 32],
        });
        assert_eq!(refused, Err(RecordError::NoSerials));

        let text = record()
            .to_wire()
            .replace("serials=chassis:SN-1,board:SN-2", "serials=");
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::Wire(WireError::EmptyValue {
                field: "serials"
            }))
        ));
    }

    #[test]
    fn a_serial_that_is_not_one_kind_and_one_value_does_not_parse() {
        let text = record()
            .to_wire()
            .replace("serials=chassis:SN-1", "serials=chassis");
        assert_eq!(DeviceRecord::parse(&text), Err(RecordError::SerialShape));

        let text = record()
            .to_wire()
            .replace("serials=chassis:SN-1", "serials=chassis:SN:1");
        assert_eq!(DeviceRecord::parse(&text), Err(RecordError::SerialShape));
    }

    #[test]
    fn a_serial_added_or_removed_changes_what_is_signed() {
        // The list is part of the payload, so a device the registry describes
        // by two serials and the same device described by one are different
        // claims and different bytes.
        let one = RecordPayload::new(PayloadFields {
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            public_key: PublicKey::new(vec![0x04, 0x11, 0x22]).unwrap(),
            epoch: Epoch::new(7),
            serials: vec![SerialNumber::new("chassis", "SN-1").unwrap()],
            key_protection: KeyProtection::Pkcs12Envelope,
            anchor: MonotonicAnchor::None,
            batch: "batch-9",
            baseline: [0x55; 32],
        })
        .unwrap();
        let two = RecordPayload::new(PayloadFields {
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            public_key: PublicKey::new(vec![0x04, 0x11, 0x22]).unwrap(),
            epoch: Epoch::new(7),
            serials: vec![
                SerialNumber::new("chassis", "SN-1").unwrap(),
                SerialNumber::new("board", "SN-2").unwrap(),
            ],
            key_protection: KeyProtection::Pkcs12Envelope,
            anchor: MonotonicAnchor::None,
            batch: "batch-9",
            baseline: [0x55; 32],
        })
        .unwrap();
        assert_ne!(one.encode().unwrap(), two.encode().unwrap());
    }

    #[test]
    fn every_rung_parses_back_to_the_rung_it_names() {
        // The mapping itself, not only the ordering: a parser that read
        // "extractability unknown" as "reported non-extractable" would turn
        // silence into proof, and a test over the enum values alone would not
        // see it. Each token is checked against the rung it belongs to, and the
        // round trip through a whole record is checked with it.
        for rung in [
            KeyProtection::Pkcs12Envelope,
            KeyProtection::Pkcs11ReportedExtractable,
            KeyProtection::Pkcs11ExtractabilityUnknown,
            KeyProtection::Pkcs11ReportedNonExtractable,
        ] {
            assert_eq!(KeyProtection::parse(rung.as_str()), Some(rung));

            let text = record().to_wire().replace(
                "key_protection=pkcs11_reported_nonextractable",
                &format!("key_protection={}", rung.as_str()),
            );
            assert_eq!(
                DeviceRecord::parse(&text).map(|parsed| parsed.payload().key_protection()),
                Ok(rung)
            );
        }
    }

    #[test]
    fn every_anchor_value_parses_back_to_what_it_names() {
        for anchor in [
            MonotonicAnchor::None,
            MonotonicAnchor::Present(AnchorKind::Tpm),
            MonotonicAnchor::Present(AnchorKind::Carrier),
        ] {
            assert_eq!(MonotonicAnchor::parse(anchor.as_str()), Some(anchor));

            let text = record()
                .to_wire()
                .replace("anchor=tpm", &format!("anchor={}", anchor.as_str()));
            assert_eq!(
                DeviceRecord::parse(&text).map(|parsed| parsed.payload().anchor()),
                Ok(anchor)
            );
        }
    }

    #[test]
    fn a_baseline_of_the_wrong_width_does_not_parse() {
        let text = record().to_wire().replace(&hex::encode([0x55; 32]), "0a0b");
        assert_eq!(
            DeviceRecord::parse(&text),
            Err(RecordError::DigestWidth {
                field: "baseline",
                got: 2
            })
        );
    }

    #[test]
    fn a_field_out_of_order_does_not_parse() {
        let text = format!("{RECORD_PREFIX};key=0411;device=77-000123S");
        assert!(matches!(
            DeviceRecord::parse(&text),
            Err(RecordError::Wire(WireError::UnexpectedField {
                expected: "device",
                ..
            }))
        ));
    }
}

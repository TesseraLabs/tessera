//! The device registry record.
//!
//! A record says that an organisation put a device into its registry: the
//! number of the device, the public key of the key epoch it is in, and who
//! vouches for it. It carries two signatures, and both are needed for different
//! reasons:
//!
//! - the organisation signature says the fleet owner accepted this device with
//!   this key;
//! - the proof of possession, made with the device key itself, says the device
//!   actually holds the private half — without it an organisation can enrol a
//!   key it does not control, its own or somebody else's, and the phone channel
//!   would agree keys with whoever holds that half.
//!
//! The two signatures are taken over different messages. The proof of
//! possession is domain separated by a label, so a signature made for one
//! purpose cannot be replayed as the other: were both over the same bytes, an
//! organisation signature by a device key would be a valid proof of possession
//! and the reverse would hold too.

use crate::canon::{CanonError, Encoder};
use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
use crate::key::Epoch;
use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::wire::{self, WireError};

/// Marker that opens the wire form of a registry record and pins the version.
pub const RECORD_PREFIX: &str = "tessera-codes/v1/device-record";

/// Number of fields a record carries in its wire form.
pub const RECORD_FIELD_COUNT: usize = 6;

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; RECORD_FIELD_COUNT] = [
    "device",
    "key",
    "epoch",
    "organisation",
    "organisation_signature",
    "possession_signature",
];

/// Label that separates the proof of possession from the organisation
/// signature.
const POSSESSION_LABEL: &str = "tessera-codes-contract/v1/proof-of-possession";

/// A device as an organisation registered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    device_number: CheckedDeviceNumber,
    public_key: PublicKey,
    epoch: Epoch,
    organisation_id: String,
    organisation_signature: Signature,
    possession_signature: Signature,
}

impl DeviceRecord {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when the organisation identifier is empty or
    /// carries a character the format cannot hold.
    pub fn new(
        device_number: CheckedDeviceNumber,
        public_key: PublicKey,
        epoch: Epoch,
        organisation_id: &str,
        organisation_signature: Signature,
        possession_signature: Signature,
    ) -> Result<Self, RecordError> {
        wire::check_free_text("organisation", organisation_id)?;
        Ok(Self {
            device_number,
            public_key,
            epoch,
            organisation_id: organisation_id.to_owned(),
            organisation_signature,
            possession_signature,
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

    /// Returns the identifier of the organisation that registered the device.
    #[must_use]
    pub fn organisation_id(&self) -> &str {
        &self.organisation_id
    }

    /// Returns the signature of the organisation.
    #[must_use]
    pub const fn organisation_signature(&self) -> &Signature {
        &self.organisation_signature
    }

    /// Returns the proof of possession made with the device key.
    #[must_use]
    pub const fn possession_signature(&self) -> &Signature {
        &self.possession_signature
    }

    /// Encodes the fields the organisation signs.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        self.encode_body(&mut encoder)?;
        Ok(encoder.finish())
    }

    /// Encodes the message the device signs to prove possession of the key.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn possession_message(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("possession_label", POSSESSION_LABEL)?;
        self.encode_body(&mut encoder)?;
        Ok(encoder.finish())
    }

    /// Writes the body fields, in the canonical order.
    fn encode_body(&self, encoder: &mut Encoder) -> Result<(), CanonError> {
        encoder.push_text("device_number", self.device_number.significant())?;
        encoder.push_bytes("public_key", self.public_key.as_bytes())?;
        encoder.push_u32("epoch", self.epoch.get())?;
        encoder.push_text("organisation_id", &self.organisation_id)?;
        Ok(())
    }

    /// Verifies both signatures.
    ///
    /// The organisation is a signer the verifier resolves against its own
    /// anchors; the proof of possession is checked against the key the record
    /// carries, which proves possession of that key and nothing about whether
    /// the key is trusted. Both are required: neither statement implies the
    /// other.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Canon`] when the record cannot be encoded,
    /// [`RecordError::OrganisationSignature`] when the organisation signature
    /// does not hold or the organisation is not anchored, and
    /// [`RecordError::PossessionSignature`] when the proof of possession does
    /// not hold.
    pub fn verify(&self, verifier: &impl SignatureVerifier) -> Result<(), RecordError> {
        let body = self.encode()?;
        verifier
            .verify(
                SignerRef::Named(&self.organisation_id),
                &body,
                &self.organisation_signature,
            )
            .map_err(RecordError::OrganisationSignature)?;

        let possession = self.possession_message()?;
        verifier
            .verify(
                SignerRef::Key(&self.public_key),
                &possession,
                &self.possession_signature,
            )
            .map_err(RecordError::PossessionSignature)?;
        Ok(())
    }

    /// Renders the wire form of the record.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let fields = [
            ("device", self.device_number.as_str().to_owned()),
            ("key", hex::encode(self.public_key.as_bytes())),
            ("epoch", self.epoch.get().to_string()),
            ("organisation", self.organisation_id.clone()),
            (
                "organisation_signature",
                hex::encode(self.organisation_signature.as_bytes()),
            ),
            (
                "possession_signature",
                hex::encode(self.possession_signature.as_bytes()),
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
    /// empty value, a device number whose check character does not match, or a
    /// value the target type cannot hold.
    pub fn parse(text: &str) -> Result<Self, RecordError> {
        let values = wire::parse(text, RECORD_PREFIX, &WIRE_KEYS)?;
        let device_number = CheckedDeviceNumber::parse(wire::value(&values, 0))?;
        let public_key = PublicKey::new(wire::parse_hex("key", wire::value(&values, 1))?)?;
        let epoch = Epoch::new(wire::parse_u32("epoch", wire::value(&values, 2))?);
        let organisation_signature = Signature::new(wire::parse_hex(
            "organisation_signature",
            wire::value(&values, 4),
        )?)?;
        let possession_signature = Signature::new(wire::parse_hex(
            "possession_signature",
            wire::value(&values, 5),
        )?)?;
        Self::new(
            device_number,
            public_key,
            epoch,
            wire::value(&values, 3),
            organisation_signature,
            possession_signature,
        )
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
    /// The organisation signature was rejected.
    #[error("the organisation signature was rejected: {0}")]
    OrganisationSignature(SignatureError),
    /// The proof of possession was rejected.
    #[error("the proof of possession was rejected: {0}")]
    PossessionSignature(SignatureError),
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{DeviceRecord, RecordError, RECORD_PREFIX};
    use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
    use crate::key::Epoch;
    use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
    use crate::wire::WireError;

    /// Verifier that accepts a signature only over the message the record says
    /// belongs to that signer, so a test can tell the two messages apart.
    struct MessageBoundVerifier {
        organisation: Vec<u8>,
        possession: Vec<u8>,
    }

    impl SignatureVerifier for MessageBoundVerifier {
        fn verify(
            &self,
            signer: SignerRef<'_>,
            message: &[u8],
            _signature: &Signature,
        ) -> Result<(), SignatureError> {
            let expected = match signer {
                SignerRef::Named(_) => &self.organisation,
                SignerRef::Key(_) => &self.possession,
                SignerRef::TicketAuthority => return Err(SignatureError::UnknownSigner),
            };
            if message == expected.as_slice() {
                Ok(())
            } else {
                Err(SignatureError::Rejected)
            }
        }
    }

    fn record() -> DeviceRecord {
        DeviceRecord::new(
            CheckedDeviceNumber::from_body("77-000123").unwrap(),
            PublicKey::new(vec![0x04, 0xaa, 0xbb]).unwrap(),
            Epoch::new(7),
            "org-1",
            Signature::new(vec![0x01, 0x02]).unwrap(),
            Signature::new(vec![0x03, 0x04]).unwrap(),
        )
        .unwrap()
    }

    fn honest_verifier(record: &DeviceRecord) -> MessageBoundVerifier {
        MessageBoundVerifier {
            organisation: record.encode().unwrap(),
            possession: record.possession_message().unwrap(),
        }
    }

    #[test]
    fn the_wire_form_round_trips() {
        let record = record();
        assert_eq!(DeviceRecord::parse(&record.to_wire()), Ok(record));
    }

    #[test]
    fn the_canonical_bytes_are_the_hand_written_framing() {
        assert_eq!(
            hex::encode(record().encode().unwrap()),
            concat!(
                "00000009",
                "373730303031323353", // device number "77000123S", significant only
                "00000003",
                "04aabb", // public key
                "00000004",
                "00000007", // epoch 7
                "00000005",
                "6f72672d31", // organisation "org-1"
            )
        );
    }

    #[test]
    fn both_signatures_are_checked() {
        let record = record();
        assert_eq!(record.verify(&honest_verifier(&record)), Ok(()));
    }

    #[test]
    fn a_record_with_only_the_organisation_signature_is_refused() {
        let record = record();
        let verifier = MessageBoundVerifier {
            organisation: record.encode().unwrap(),
            possession: Vec::new(),
        };
        assert_eq!(
            record.verify(&verifier),
            Err(RecordError::PossessionSignature(SignatureError::Rejected))
        );
    }

    #[test]
    fn a_record_with_only_the_proof_of_possession_is_refused() {
        let record = record();
        let verifier = MessageBoundVerifier {
            organisation: Vec::new(),
            possession: record.possession_message().unwrap(),
        };
        assert_eq!(
            record.verify(&verifier),
            Err(RecordError::OrganisationSignature(SignatureError::Rejected))
        );
    }

    #[test]
    fn the_two_messages_are_domain_separated() {
        let record = record();
        assert_ne!(
            record.encode().unwrap(),
            record.possession_message().unwrap()
        );
        // Neither message is a prefix of the other in a way that would let one
        // be re-read as the other: the label is a length-prefixed field of its
        // own at the head of the proof of possession.
        assert!(!record
            .possession_message()
            .unwrap()
            .starts_with(&record.encode().unwrap()));
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
        let record = record();
        assert!(matches!(
            DeviceRecord::parse(&record.to_wire().replace("epoch=", "epoch")),
            Err(RecordError::Wire(WireError::MalformedField { .. }))
        ));
        assert!(matches!(
            DeviceRecord::parse(&record.to_wire().replace(";epoch=7", "")),
            Err(RecordError::Wire(WireError::UnexpectedField { .. }))
        ));
        assert!(matches!(
            DeviceRecord::parse(&record.to_wire().replace(RECORD_PREFIX, "other/v1/record")),
            Err(RecordError::Wire(WireError::WrongPrefix { .. }))
        ));
    }

    #[test]
    fn an_unusable_value_does_not_parse() {
        let record = record();
        let number = record.device_number().as_str().to_owned();
        assert!(matches!(
            DeviceRecord::parse(
                &record
                    .to_wire()
                    .replace(&format!("device={number}"), "device=77-000124-S")
            ),
            Err(RecordError::DeviceNumber(
                DeviceNumberError::CheckCharacterMismatch { .. }
            ))
        ));
        assert!(matches!(
            DeviceRecord::parse(&record.to_wire().replace("epoch=7", "epoch=seven")),
            Err(RecordError::Wire(WireError::NotANumber { field: "epoch" }))
        ));
        assert!(matches!(
            DeviceRecord::parse(&record.to_wire().replace("key=04aabb", "key=04aab")),
            Err(RecordError::Wire(WireError::NotHex { field: "key" }))
        ));
    }
}

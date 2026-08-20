//! The issuance receipt.
//!
//! A receipt is what remains after a code has been given out over the
//! telephone: which device, which key epoch, which nonce, which role at which
//! level, when the issuing side says it happened, and on what grounds.
//!
//! The grounds are mandatory. A receipt without them records that a level of
//! access was granted and refuses to say why, which is exactly the receipt
//! nobody can answer for six months later; the type therefore has no way to
//! hold an empty reason, and assembling one fails.
//!
//! Receipts are written as files, one per issuance, and the name of that file
//! is composed rather than free ([`IssuanceReceipt::file_name`]): the device,
//! the epoch, the nonce counter, the ticket, the operator and a digest of the
//! receipt itself. Two receipts of one channel therefore sort next to each
//! other and never overwrite one another.

use crate::canon::{CanonError, Encoder, Level};
use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
use crate::key::Epoch;
use crate::mac::sha256;
use crate::nonce::{Nonce, NonceError};
use crate::params::FleetParams;
use crate::ticket::OperatorTicket;
use crate::time::ClaimedTime;
use crate::wire::{self, WireError};

/// Marker that opens the wire form of a receipt and pins the version.
pub const RECEIPT_PREFIX: &str = "tessera-codes/v1/receipt";

/// Number of fields a receipt carries in its wire form.
pub const RECEIPT_FIELD_COUNT: usize = 7;

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; RECEIPT_FIELD_COUNT] = [
    "device",
    "epoch",
    "nonce",
    "role",
    "level",
    "issued_at",
    "reason",
];

/// Number of digest bytes the file name carries.
///
/// Eight bytes distinguish the receipts of one device, epoch and counter — the
/// case where the rest of the name repeats — and the name still fits a line.
/// The digest is not a secret and is not a signature: it separates names, it
/// does not authenticate them.
const FILE_NAME_DIGEST_BYTES: usize = 8;

/// Longest run of an identifier the file name carries.
const FILE_NAME_PART_LIMIT: usize = 32;

/// Character that replaces anything a file name should not carry.
const FILE_NAME_FILLER: char = '_';

/// Separator between the parts of the file name.
const FILE_NAME_SEPARATOR: char = '-';

/// A record of one issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceReceipt {
    device_number: CheckedDeviceNumber,
    epoch: Epoch,
    nonce: Nonce,
    role_id: String,
    level: Level,
    issued_at: ClaimedTime,
    reason: String,
}

/// What a receipt is assembled from.
///
/// The fields arrive together rather than as a run of positional arguments,
/// and every one of them is required: a receipt is a record of an issuance
/// that already happened, so there is no partially built state for a builder
/// to hold, and no field a caller may leave out and fill in later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptFields<'a> {
    /// Device the code was issued for.
    pub device_number: CheckedDeviceNumber,
    /// Key epoch the code was issued under.
    pub epoch: Epoch,
    /// Nonce of the issuance.
    pub nonce: Nonce,
    /// Role the code granted.
    pub role_id: &'a str,
    /// Level of that role.
    pub level: Level,
    /// Moment the issuing side claims the code was given out.
    pub issued_at: ClaimedTime,
    /// Grounds for the issuance; may not be empty.
    pub reason: &'a str,
}

impl IssuanceReceipt {
    /// Assembles a receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptError::MissingReason`] when the grounds are empty or
    /// only whitespace, and the wire errors when the role identifier or the
    /// grounds carry a character the format cannot hold.
    pub fn new(fields: ReceiptFields<'_>) -> Result<Self, ReceiptError> {
        wire::check_free_text("role", fields.role_id)?;
        if fields.reason.trim().is_empty() {
            return Err(ReceiptError::MissingReason);
        }
        wire::check_free_text("reason", fields.reason)?;
        Ok(Self {
            device_number: fields.device_number,
            epoch: fields.epoch,
            nonce: fields.nonce,
            role_id: fields.role_id.to_owned(),
            level: fields.level,
            issued_at: fields.issued_at,
            reason: fields.reason.to_owned(),
        })
    }

    /// Returns the device the code was issued for.
    #[must_use]
    pub const fn device_number(&self) -> &CheckedDeviceNumber {
        &self.device_number
    }

    /// Returns the key epoch the code was issued under.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the nonce of the issuance.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns the role the code granted.
    #[must_use]
    pub fn role_id(&self) -> &str {
        &self.role_id
    }

    /// Returns the level of that role.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.level
    }

    /// Returns the moment the issuing side claims the code was given out.
    #[must_use]
    pub const fn issued_at(&self) -> ClaimedTime {
        self.issued_at
    }

    /// Returns the grounds recorded for the issuance.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Encodes the receipt canonically.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("device_number", self.device_number.significant())?;
        encoder.push_u32("epoch", self.epoch.get())?;
        encoder.push_text("nonce", self.nonce.as_str())?;
        encoder.push_text("role_id", &self.role_id)?;
        encoder.push_u32("level", self.level.get())?;
        encoder.push_u64("issued_at", self.issued_at.get())?;
        encoder.push_text("reason", &self.reason)?;
        Ok(encoder.finish())
    }

    /// Returns the composed file name of the receipt: device, epoch, nonce
    /// counter, ticket number, operator and a digest of the receipt.
    ///
    /// The ticket is a parameter rather than a field of the receipt because the
    /// ticket number and the operator identifier have to come from one and the
    /// same ticket — passing them separately would let a caller pair a number
    /// with another operator.
    ///
    /// The name is safe to hand to a filesystem: every part is reduced to ASCII
    /// letters, digits, `-`, `_` and `.`, and each is bounded in length, so no
    /// identifier can smuggle a path separator, a leading dot or a name of
    /// unbounded size. It is a name, not a format — nothing parses it back, and
    /// a consumer that needs the fields reads the receipt.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when the receipt cannot be encoded,
    /// since the digest is taken over its canonical bytes.
    pub fn file_name(&self, ticket: &OperatorTicket) -> Result<String, CanonError> {
        let digest = sha256(&self.encode()?);
        let digest_hex = hex::encode(digest.get(..FILE_NAME_DIGEST_BYTES).unwrap_or(&digest));
        let parts = [
            safe_part(self.device_number.significant()),
            self.epoch.get().to_string(),
            self.nonce.counter().to_string(),
            safe_part(ticket.number().as_str()),
            safe_part(ticket.operator_id()),
            digest_hex,
        ];
        Ok(parts.join(&FILE_NAME_SEPARATOR.to_string()))
    }

    /// Renders the wire form of the receipt.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let fields = [
            ("device", self.device_number.as_str().to_owned()),
            ("epoch", self.epoch.get().to_string()),
            ("nonce", self.nonce.as_str().to_owned()),
            ("role", self.role_id.clone()),
            ("level", self.level.get().to_string()),
            ("issued_at", self.issued_at.get().to_string()),
            ("reason", self.reason.clone()),
        ];
        wire::render(RECEIPT_PREFIX, &fields)
    }

    /// Parses the wire form of a receipt against the fleet parameters, which
    /// fix the shape of the nonce.
    ///
    /// # Errors
    ///
    /// Returns the [`ReceiptError`] describing the first violation: a wrong or
    /// missing prefix, a field that is unknown, missing or out of order, an
    /// empty value, a device number whose check character does not match, a
    /// nonce that does not fit the parameters, a value the target type cannot
    /// hold, or grounds that are only whitespace.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, ReceiptError> {
        let values = wire::parse(text, RECEIPT_PREFIX, &WIRE_KEYS)?;
        let device_number = CheckedDeviceNumber::parse(wire::value(&values, 0))?;
        let epoch = Epoch::new(wire::parse_u32("epoch", wire::value(&values, 1))?);
        let nonce = Nonce::parse(wire::value(&values, 2), params)?;
        let level = Level::new(wire::parse_u32("level", wire::value(&values, 4))?);
        let issued_at = ClaimedTime::new(wire::parse_u64("issued_at", wire::value(&values, 5))?);
        Self::new(ReceiptFields {
            device_number,
            epoch,
            nonce,
            role_id: wire::value(&values, 3),
            level,
            issued_at,
            reason: wire::value(&values, 6),
        })
    }
}

impl core::fmt::Display for IssuanceReceipt {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Reduces one part of the file name to characters a filesystem takes without
/// interpreting them.
fn safe_part(value: &str) -> String {
    let reduced: String = value
        .chars()
        .take(FILE_NAME_PART_LIMIT)
        .map(|symbol| {
            if symbol.is_ascii_alphanumeric() || matches!(symbol, '-' | '_' | '.') {
                symbol
            } else {
                FILE_NAME_FILLER
            }
        })
        .collect();
    // A part that starts with a dot would hide the file on a Unix filesystem,
    // and a part of dots alone would name a directory.
    if reduced.starts_with('.') || reduced.chars().all(|symbol| symbol == '.') {
        return format!("{FILE_NAME_FILLER}{reduced}");
    }
    reduced
}

/// Rejection of a receipt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    /// The wire form of the receipt is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The device number failed its check character.
    #[error(transparent)]
    DeviceNumber(#[from] DeviceNumberError),
    /// The nonce does not fit the fleet parameters.
    #[error(transparent)]
    Nonce(#[from] NonceError),
    /// The receipt carries no grounds for the issuance.
    #[error("the receipt records no grounds for the issuance")]
    MissingReason,
    /// The receipt cannot be encoded canonically.
    #[error(transparent)]
    Canon(#[from] CanonError),
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{safe_part, IssuanceReceipt, ReceiptError, ReceiptFields, RECEIPT_PREFIX};
    use crate::canon::Level;
    use crate::device_number::{CheckedDeviceNumber, DeviceNumberError};
    use crate::key::Epoch;
    use crate::nonce::Nonce;
    use crate::params::FleetParams;
    use crate::ticket::tests::signed_ticket;
    use crate::time::ClaimedTime;
    use crate::wire::WireError;

    fn params() -> FleetParams {
        FleetParams::defaults()
    }

    fn fields(role_id: &'static str, reason: &'static str) -> ReceiptFields<'static> {
        ReceiptFields {
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            epoch: Epoch::new(7),
            nonce: Nonce::new(420, "0713", &params()).unwrap(),
            role_id,
            level: Level::new(2),
            issued_at: ClaimedTime::new(1_755_000_000),
            reason,
        }
    }

    fn receipt() -> IssuanceReceipt {
        IssuanceReceipt::new(fields(
            "ops.dc.senior",
            "incident INC-8891, on-site power supply replacement",
        ))
        .unwrap()
    }

    #[test]
    fn the_wire_form_round_trips() {
        let receipt = receipt();
        assert_eq!(
            IssuanceReceipt::parse(&receipt.to_wire(), &params()),
            Ok(receipt)
        );
    }

    #[test]
    fn the_canonical_bytes_are_the_hand_written_framing() {
        let short = IssuanceReceipt::new(fields("ops", "call")).unwrap();
        assert_eq!(
            hex::encode(short.encode().unwrap()),
            concat!(
                "00000009",
                "373730303031323353", // device number "77000123S", significant only
                "00000004",
                "00000007", // epoch 7
                "0000000a",
                "30303034323030373133", // nonce
                "00000003",
                "6f7073", // role "ops"
                "00000004",
                "00000002", // level 2
                "00000008",
                "00000000689b2cc0", // issued_at 1755000000
                "00000004",
                "63616c6c", // reason "call"
            )
        );
    }

    #[test]
    fn a_receipt_without_grounds_is_refused() {
        let refused = IssuanceReceipt::new(fields("ops.dc.senior", "   "));
        assert_eq!(refused, Err(ReceiptError::MissingReason));
    }

    #[test]
    fn the_file_name_composes_the_parts_of_the_issuance() {
        let receipt = receipt();
        let ticket = signed_ticket();
        let name = receipt.file_name(ticket.ticket()).unwrap();
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.first().copied(), Some("77000123S"));
        assert_eq!(parts.get(1).copied(), Some("7"));
        assert_eq!(parts.get(2).copied(), Some("420"));
        // The ticket number "tk-17" carries the separator itself, so it spans
        // two parts; the name is a name, not a format to be split back.
        assert!(name.contains("-tk-17-op-42-"), "{name}");
        assert!(
            name.chars()
                .all(|symbol| symbol.is_ascii_alphanumeric() || matches!(symbol, '-' | '_' | '.')),
            "{name}"
        );
    }

    #[test]
    fn the_file_name_separates_two_receipts_of_one_counter() {
        let ticket = signed_ticket();
        let first = receipt();
        let second = IssuanceReceipt::new(ReceiptFields {
            device_number: first.device_number().clone(),
            epoch: first.epoch(),
            nonce: first.nonce().clone(),
            role_id: first.role_id(),
            level: first.level(),
            issued_at: first.issued_at(),
            reason: "another reason",
        })
        .unwrap();
        assert_ne!(
            first.file_name(ticket.ticket()).unwrap(),
            second.file_name(ticket.ticket()).unwrap()
        );
    }

    #[test]
    fn a_file_name_part_carries_nothing_a_filesystem_reads() {
        assert_eq!(safe_part("../../etc/passwd"), "_.._.._etc_passwd");
        assert_eq!(safe_part(".hidden"), "_.hidden");
        assert_eq!(safe_part(".."), "_..");
        assert_eq!(safe_part("op 42\u{0000}"), "op_42_");
        assert_eq!(safe_part(&"x".repeat(64)).len(), 32);
    }

    #[test]
    fn an_unknown_field_does_not_parse() {
        let text = format!("{};extra=1", receipt().to_wire());
        assert!(matches!(
            IssuanceReceipt::parse(&text, &params()),
            Err(ReceiptError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn a_broken_structure_does_not_parse() {
        let receipt = receipt();
        assert!(matches!(
            IssuanceReceipt::parse(&receipt.to_wire().replace("level=", "level"), &params()),
            Err(ReceiptError::Wire(WireError::MalformedField { .. }))
        ));
        assert!(matches!(
            IssuanceReceipt::parse(&receipt.to_wire().replace(";level=2", ""), &params()),
            Err(ReceiptError::Wire(WireError::UnexpectedField { .. }))
        ));
        assert!(matches!(
            IssuanceReceipt::parse(
                &receipt
                    .to_wire()
                    .replace(RECEIPT_PREFIX, "other/v1/receipt"),
                &params()
            ),
            Err(ReceiptError::Wire(WireError::WrongPrefix { .. }))
        ));
    }

    #[test]
    fn an_unusable_value_does_not_parse() {
        let receipt = receipt();
        assert!(matches!(
            IssuanceReceipt::parse(
                &receipt
                    .to_wire()
                    .replace("issued_at=1755000000", "issued_at=now"),
                &params()
            ),
            Err(ReceiptError::Wire(WireError::NotANumber {
                field: "issued_at"
            }))
        ));
        assert!(matches!(
            IssuanceReceipt::parse(
                &receipt
                    .to_wire()
                    .replace("nonce=0004200713", "nonce=00042007"),
                &params()
            ),
            Err(ReceiptError::Nonce(_))
        ));
        let number = receipt.device_number().as_str().to_owned();
        assert!(matches!(
            IssuanceReceipt::parse(
                &receipt
                    .to_wire()
                    .replace(&format!("device={number}"), "device=77-000124-S"),
                &params()
            ),
            Err(ReceiptError::DeviceNumber(
                DeviceNumberError::CheckCharacterMismatch { .. }
            ))
        ));
    }

    #[test]
    fn grounds_of_whitespace_do_not_parse() {
        let receipt = receipt();
        // The grounds are the last field of the wire form, so a value of
        // nothing but whitespace is gone with the trailing whitespace of the
        // line and is reported as an empty field. Either way the document does
        // not parse: what matters is that no receipt without grounds is ever
        // constructed — grounds that reach the assembly are refused there, see
        // `a_receipt_without_grounds_is_refused`.
        assert_eq!(
            IssuanceReceipt::parse(&receipt.to_wire().replace(receipt.reason(), " "), &params()),
            Err(ReceiptError::Wire(WireError::EmptyValue {
                field: "reason"
            }))
        );
    }
}

//! What a receipt of the phone channel records beyond the contract's own
//! fields.
//!
//! The receipt of [`tessera_codes_contract::receipt`] is frozen: device, epoch,
//! nonce, role, level, moment, grounds. Four things an auditor needs are not
//! among them, and none of them can be recovered afterwards from anything else:
//!
//! - the **ticket** the operator worked under, and the operator themselves —
//!   the receipt's file name carries both, but a file name is a name, not a
//!   document, and it is the first thing to be lost when receipts are copied;
//! - **how the operator key was held** — a code produced with a key on a token
//!   and a code produced with a key file on a disk are different assurances,
//!   and after the fact nothing distinguishes them;
//! - **what the counter said**, including whether the refusal was overridden
//!   and by whom — an override that leaves no trace is not an override, it is a
//!   bypass;
//! - whether the **site axis** of the ticket was checked at all — see
//!   [`crate::codes::scope`];
//! - **how deep the counter history was** when the code was issued. That number
//!   is the one thing about the ledger that survives the ledger: a receipt
//!   claiming no history, filed behind a run of receipts that claimed one, is
//!   what a deleted history looks like afterwards
//!   ([`crate::codes::ledger`]).
//!
//! The annex is therefore a second line beside the receipt, in the same shape of
//! document: a version-pinning prefix, then `key=value` fields in one fixed
//! order, separated by `;`. Parsing is strict in the same three ways — an
//! unknown field, a field out of order and an empty value are errors, never a
//! field quietly dropped — because an annex is a claim about how an issuance was
//! made, and a parser that repairs one is deciding on the operator's behalf.

use tessera_codes_contract::ticket::{OperatorTicket, TicketNumber};

use crate::codes::counter::{CounterNote, CounterOverride};

/// Marker that opens the annex and pins the version of the format.
pub const ANNEX_PREFIX: &str = "tessera-issuer/v1/codes-receipt-annex";

/// Number of fields the annex carries.
pub const ANNEX_FIELD_COUNT: usize = 8;

/// Field keys, in the only order the parser accepts.
const KEYS: [&str; ANNEX_FIELD_COUNT] = [
    "ticket",
    "operator",
    "organisation",
    "key_storage",
    "counter",
    "approver",
    "site_scope",
    "history",
];

/// Separator between the fields.
const FIELD_SEPARATOR: char = ';';

/// Separator between a key and its value.
const KEY_SEPARATOR: char = '=';

/// Value of `approver` when the issuance was not overridden.
///
/// An operator identifier spelled exactly like this is refused when the annex is
/// assembled, so the marker has one meaning.
pub const NO_APPROVER: &str = "none";

/// How the operator's private key was held during the issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStorage {
    /// A PKCS#11 token or HSM.
    Token,
    /// A key file on the operator's own machine, in the explicitly enabled
    /// software mode.
    Software,
}

impl KeyStorage {
    /// The token this storage is written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Software => "software",
        }
    }

    /// Parses a storage written by [`KeyStorage::as_str`].
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        [Self::Token, Self::Software]
            .into_iter()
            .find(|storage| storage.as_str() == token)
    }
}

/// Whether the site axis of the ticket was checked against the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteScope {
    /// The operator declared where the device stands, and the ticket covered it.
    Checked,
    /// Nobody declared where the device stands; the device checks that axis
    /// itself before it accepts the code.
    Undeclared,
}

impl SiteScope {
    /// The token this state is written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Checked => "checked",
            Self::Undeclared => "undeclared",
        }
    }

    /// Parses a state written by [`SiteScope::as_str`].
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        [Self::Checked, Self::Undeclared]
            .into_iter()
            .find(|scope| scope.as_str() == token)
    }
}

/// What an annex is assembled from.
#[derive(Debug, Clone, Copy)]
pub struct AnnexFields<'a> {
    /// Ticket the operator worked under.
    pub ticket: &'a OperatorTicket,
    /// Organisation that signed the device record.
    pub organisation_id: &'a str,
    /// How the operator's key was held.
    pub key_storage: KeyStorage,
    /// What the counter said about the call.
    pub counter_note: CounterNote,
    /// The second operator who approved an override, when there was one.
    pub approval: Option<&'a CounterOverride>,
    /// Whether the site axis was checked.
    pub site_scope: SiteScope,
    /// How many issuances the history held for this device before this one.
    pub history_depth: u64,
}

/// The annex of one receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAnnex {
    ticket_number: TicketNumber,
    operator_id: String,
    organisation_id: String,
    key_storage: KeyStorage,
    counter_note: CounterNote,
    approver: Option<String>,
    site_scope: SiteScope,
    history_depth: u64,
}

impl ReceiptAnnex {
    /// Assembles an annex.
    ///
    /// # Errors
    ///
    /// Returns [`AnnexError::UnusableValue`] when an identifier carries a
    /// character the format cannot hold or is spelled exactly like
    /// [`NO_APPROVER`], and [`AnnexError::OverrideMismatch`] when an override is
    /// recorded without an approver or an approver without an override — the two
    /// are one statement, and an annex that carries half of it would let a
    /// bypass read as an ordinary issuance.
    pub fn new(fields: AnnexFields<'_>) -> Result<Self, AnnexError> {
        check_value("operator", fields.ticket.operator_id())?;
        check_value("organisation", fields.organisation_id)?;
        let approver = fields
            .approval
            .map(|decision| decision.approver().to_owned());
        if let Some(approver) = approver.as_deref() {
            check_value("approver", approver)?;
            if approver == NO_APPROVER {
                return Err(AnnexError::UnusableValue { field: "approver" });
            }
        }
        check_override_pairing(fields.counter_note, approver.is_some())?;

        Ok(Self {
            ticket_number: fields.ticket.number().clone(),
            operator_id: fields.ticket.operator_id().to_owned(),
            organisation_id: fields.organisation_id.to_owned(),
            key_storage: fields.key_storage,
            counter_note: fields.counter_note,
            approver,
            site_scope: fields.site_scope,
            history_depth: fields.history_depth,
        })
    }

    /// Returns the ticket number the issuance was made under.
    #[must_use]
    pub const fn ticket_number(&self) -> &TicketNumber {
        &self.ticket_number
    }

    /// Returns the operator who handled the call.
    #[must_use]
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    /// Returns the organisation that signed the device record.
    #[must_use]
    pub fn organisation_id(&self) -> &str {
        &self.organisation_id
    }

    /// Returns how the operator's key was held.
    #[must_use]
    pub const fn key_storage(&self) -> KeyStorage {
        self.key_storage
    }

    /// Returns what the counter said about the call.
    #[must_use]
    pub const fn counter_note(&self) -> CounterNote {
        self.counter_note
    }

    /// Returns the second operator who approved an override, if there was one.
    #[must_use]
    pub fn approver(&self) -> Option<&str> {
        self.approver.as_deref()
    }

    /// Returns whether the site axis was checked.
    #[must_use]
    pub const fn site_scope(&self) -> SiteScope {
        self.site_scope
    }

    /// Returns how deep the counter history was when this code was issued.
    #[must_use]
    pub const fn history_depth(&self) -> u64 {
        self.history_depth
    }

    /// Renders the annex.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let values = [
            self.ticket_number.as_str().to_owned(),
            self.operator_id.clone(),
            self.organisation_id.clone(),
            self.key_storage.as_str().to_owned(),
            self.counter_note.as_str().to_owned(),
            self.approver
                .clone()
                .unwrap_or_else(|| NO_APPROVER.to_owned()),
            self.site_scope.as_str().to_owned(),
            self.history_depth.to_string(),
        ];
        let mut text = String::from(ANNEX_PREFIX);
        for (key, value) in KEYS.iter().zip(values.iter()) {
            text.push(FIELD_SEPARATOR);
            text.push_str(key);
            text.push(KEY_SEPARATOR);
            text.push_str(value);
        }
        text
    }

    /// Parses an annex.
    ///
    /// # Errors
    ///
    /// The [`AnnexError`] describing the first violation: a missing or
    /// misspelled prefix, a wrong number of fields, a field out of order or
    /// unknown, an empty value, a token no variant is written under, a ticket
    /// number the format does not allow, or an override without its approver.
    pub fn parse(text: &str) -> Result<Self, AnnexError> {
        let values = split(text)?;
        let field = |index: usize| values.get(index).copied().unwrap_or_default();

        let ticket_number = TicketNumber::parse(field(0))
            .map_err(|_| AnnexError::UnusableValue { field: "ticket" })?;
        check_value("operator", field(1))?;
        check_value("organisation", field(2))?;
        let key_storage = KeyStorage::parse(field(3)).ok_or(AnnexError::UnknownToken {
            field: "key_storage",
        })?;
        let counter_note =
            CounterNote::parse(field(4)).ok_or(AnnexError::UnknownToken { field: "counter" })?;
        let approver = match field(5) {
            NO_APPROVER => None,
            named => {
                check_value("approver", named)?;
                Some(named.to_owned())
            }
        };
        let site_scope = SiteScope::parse(field(6)).ok_or(AnnexError::UnknownToken {
            field: "site_scope",
        })?;
        let history_depth = field(7)
            .parse::<u64>()
            .map_err(|_| AnnexError::UnknownToken { field: "history" })?;
        check_override_pairing(counter_note, approver.is_some())?;

        Ok(Self {
            ticket_number,
            operator_id: field(1).to_owned(),
            organisation_id: field(2).to_owned(),
            key_storage,
            counter_note,
            approver,
            site_scope,
            history_depth,
        })
    }
}

impl core::fmt::Display for ReceiptAnnex {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Rejection of an annex.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnnexError {
    /// The text does not open with the format marker.
    #[error("the annex does not open with `{ANNEX_PREFIX}`")]
    WrongPrefix,
    /// The text carries the wrong number of fields.
    #[error("the annex carries {got} fields where the format has {ANNEX_FIELD_COUNT}")]
    FieldCount {
        /// Number of fields the text carried.
        got: usize,
    },
    /// A field is not a `key=value` pair, or is unknown or out of order.
    #[error("expected the annex field `{expected}`")]
    UnexpectedField {
        /// Key the format expects in this position.
        expected: &'static str,
    },
    /// A field carries a value the format cannot hold.
    #[error("the annex field `{field}` carries a value the format cannot hold")]
    UnusableValue {
        /// Name of the offending field.
        field: &'static str,
    },
    /// A field carries a token no variant is written under.
    #[error("the annex field `{field}` carries a value the format does not define")]
    UnknownToken {
        /// Name of the offending field.
        field: &'static str,
    },
    /// An override and its approver do not travel together.
    #[error("an overridden issuance names the second operator who approved it, and only an overridden one does")]
    OverrideMismatch,
}

/// Splits the text into the values of [`KEYS`], in that exact order.
fn split(text: &str) -> Result<Vec<&str>, AnnexError> {
    let mut parts = text.trim().split(FIELD_SEPARATOR);
    if parts.next().unwrap_or_default() != ANNEX_PREFIX {
        return Err(AnnexError::WrongPrefix);
    }

    let mut values: Vec<&str> = Vec::with_capacity(ANNEX_FIELD_COUNT);
    for (index, part) in parts.enumerate() {
        let expected = KEYS
            .get(index)
            .copied()
            .ok_or(AnnexError::FieldCount { got: index + 1 })?;
        let (key, value) = part
            .split_once(KEY_SEPARATOR)
            .ok_or(AnnexError::UnexpectedField { expected })?;
        if key != expected {
            return Err(AnnexError::UnexpectedField { expected });
        }
        if value.is_empty() {
            return Err(AnnexError::UnusableValue { field: expected });
        }
        values.push(value);
    }
    if values.len() != ANNEX_FIELD_COUNT {
        return Err(AnnexError::FieldCount { got: values.len() });
    }
    Ok(values)
}

/// Checks a free-text value against what the format can carry.
fn check_value(field: &'static str, value: &str) -> Result<(), AnnexError> {
    if value.is_empty()
        || value.chars().any(|symbol| {
            symbol == FIELD_SEPARATOR || symbol == KEY_SEPARATOR || symbol.is_control()
        })
    {
        return Err(AnnexError::UnusableValue { field });
    }
    Ok(())
}

/// Checks that an override and an approver travel together.
fn check_override_pairing(note: CounterNote, has_approver: bool) -> Result<(), AnnexError> {
    if (note == CounterNote::Overridden) == has_approver {
        Ok(())
    } else {
        Err(AnnexError::OverrideMismatch)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{
        AnnexError, AnnexFields, KeyStorage, ReceiptAnnex, SiteScope, ANNEX_PREFIX, NO_APPROVER,
    };
    use crate::codes::counter::{CounterNote, CounterOverride};
    use crate::codes::tests::fixtures;

    fn annex(note: CounterNote, approval: Option<&CounterOverride>) -> ReceiptAnnex {
        let world = fixtures::world();
        ReceiptAnnex::new(AnnexFields {
            ticket: world.ticket.ticket(),
            organisation_id: "acme",
            key_storage: KeyStorage::Token,
            counter_note: note,
            approval,
            site_scope: SiteScope::Checked,
            history_depth: 3,
        })
        .unwrap()
    }

    #[test]
    fn an_annex_survives_a_round_trip() {
        let original = annex(CounterNote::Advanced, None);
        assert_eq!(ReceiptAnnex::parse(&original.to_wire()), Ok(original));
    }

    #[test]
    fn an_override_survives_a_round_trip_with_its_approver() {
        let decision = CounterOverride::by("op-7", "op-42").unwrap();
        let original = annex(CounterNote::Overridden, Some(&decision));
        assert_eq!(original.approver(), Some("op-7"));
        assert_eq!(ReceiptAnnex::parse(&original.to_wire()), Ok(original));
    }

    #[test]
    fn the_storage_of_the_key_is_recorded_and_read_back() {
        let world = fixtures::world();
        let software = ReceiptAnnex::new(AnnexFields {
            ticket: world.ticket.ticket(),
            organisation_id: "acme",
            key_storage: KeyStorage::Software,
            counter_note: CounterNote::Advanced,
            approval: None,
            site_scope: SiteScope::Undeclared,
            history_depth: 0,
        })
        .unwrap();
        let read_back = ReceiptAnnex::parse(&software.to_wire()).unwrap();
        assert_eq!(read_back.key_storage(), KeyStorage::Software);
        assert_eq!(read_back.site_scope(), SiteScope::Undeclared);
    }

    #[test]
    fn an_override_without_an_approver_cannot_be_assembled() {
        let world = fixtures::world();
        assert_eq!(
            ReceiptAnnex::new(AnnexFields {
                ticket: world.ticket.ticket(),
                organisation_id: "acme",
                key_storage: KeyStorage::Token,
                counter_note: CounterNote::Overridden,
                approval: None,
                site_scope: SiteScope::Checked,
                history_depth: 0,
            }),
            Err(AnnexError::OverrideMismatch)
        );
    }

    #[test]
    fn an_approver_without_an_override_cannot_be_assembled() {
        let world = fixtures::world();
        let decision = CounterOverride::by("op-7", "op-42").unwrap();
        assert_eq!(
            ReceiptAnnex::new(AnnexFields {
                ticket: world.ticket.ticket(),
                organisation_id: "acme",
                key_storage: KeyStorage::Token,
                counter_note: CounterNote::Advanced,
                approval: Some(&decision),
                site_scope: SiteScope::Checked,
                history_depth: 0,
            }),
            Err(AnnexError::OverrideMismatch)
        );
    }

    #[test]
    fn an_override_edited_out_of_a_written_annex_no_longer_parses() {
        let decision = CounterOverride::by("op-7", "op-42").unwrap();
        let text = annex(CounterNote::Overridden, Some(&decision)).to_wire();
        let edited = text.replace("approver=op-7", &format!("approver={NO_APPROVER}"));
        assert_eq!(
            ReceiptAnnex::parse(&edited),
            Err(AnnexError::OverrideMismatch)
        );
    }

    #[test]
    fn a_field_out_of_order_is_refused() {
        let text = format!("{ANNEX_PREFIX};operator=op-42;ticket=tk-17");
        assert_eq!(
            ReceiptAnnex::parse(&text),
            Err(AnnexError::UnexpectedField { expected: "ticket" })
        );
    }

    #[test]
    fn a_wrong_prefix_is_refused() {
        assert_eq!(
            ReceiptAnnex::parse("tessera-issuer/v0/codes-receipt-annex;ticket=tk-17"),
            Err(AnnexError::WrongPrefix)
        );
    }

    #[test]
    fn an_empty_value_is_refused() {
        let text = annex(CounterNote::Advanced, None)
            .to_wire()
            .replace("organisation=acme", "organisation=");
        assert_eq!(
            ReceiptAnnex::parse(&text),
            Err(AnnexError::UnusableValue {
                field: "organisation"
            })
        );
    }

    #[test]
    fn a_token_no_variant_is_written_under_is_refused() {
        let text = annex(CounterNote::Advanced, None)
            .to_wire()
            .replace("key_storage=token", "key_storage=smartcard");
        assert_eq!(
            ReceiptAnnex::parse(&text),
            Err(AnnexError::UnknownToken {
                field: "key_storage"
            })
        );
    }

    #[test]
    fn a_trailing_field_is_refused() {
        let text = format!("{};extra=1", annex(CounterNote::Advanced, None).to_wire());
        assert_eq!(
            ReceiptAnnex::parse(&text),
            Err(AnnexError::FieldCount { got: 9 })
        );
    }
}

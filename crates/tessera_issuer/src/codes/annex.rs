//! What a receipt of the phone channel records beyond the contract's own
//! fields.
//!
//! The receipt of [`tessera_codes_contract::receipt`] is frozen: device, epoch,
//! nonce, role, level, moment, grounds. Three things an auditor needs are not
//! among them, and none of them can be recovered afterwards from anything else:
//!
//! - the **ticket** the operator worked under, and the operator themselves —
//!   the receipt's file name carries both, but a file name is a name, not a
//!   document, and it is the first thing to be lost when receipts are copied;
//! - **how the operator key was held** — a code produced with a key on a token
//!   and a code produced with a key file on a disk are different assurances,
//!   and after the fact nothing distinguishes them;
//! - whether the **site axis** of the ticket was checked at all — see
//!   [`crate::codes::scope`].
//!
//! The annex is therefore a second line beside the receipt, in the same shape of
//! document: a version-pinning prefix, then `key=value` fields in one fixed
//! order, separated by `;`. Parsing is strict in the same three ways — an
//! unknown field, a field out of order and an empty value are errors, never a
//! field quietly dropped — because an annex is a claim about how an issuance was
//! made, and a parser that repairs one is deciding on the operator's behalf.

use tessera_codes_contract::ticket::{ServerTicket, TicketNumber};

/// Marker that opens the annex and pins the version of the format.
pub const ANNEX_PREFIX: &str = "tessera-issuer/v1/codes-receipt-annex";

/// Number of fields the annex carries.
pub const ANNEX_FIELD_COUNT: usize = 5;

/// Field keys, in the only order the parser accepts.
const KEYS: [&str; ANNEX_FIELD_COUNT] = [
    "ticket",
    "operator",
    "organisation",
    "key_storage",
    "site_scope",
];

/// Separator between the fields.
const FIELD_SEPARATOR: char = ';';

/// Separator between a key and its value.
const KEY_SEPARATOR: char = '=';

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
    pub ticket: &'a ServerTicket,
    /// Organisation that signed the device record.
    pub organisation_id: &'a str,
    /// How the operator's key was held.
    pub key_storage: KeyStorage,
    /// Whether the site axis was checked.
    pub site_scope: SiteScope,
}

/// The annex of one receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAnnex {
    ticket_number: TicketNumber,
    server_id: String,
    organisation_id: String,
    key_storage: KeyStorage,
    site_scope: SiteScope,
}

impl ReceiptAnnex {
    /// Assembles an annex.
    ///
    /// # Errors
    ///
    /// Returns [`AnnexError::UnusableValue`] when an identifier carries a
    /// character the format cannot hold.
    pub fn new(fields: AnnexFields<'_>) -> Result<Self, AnnexError> {
        check_value("operator", fields.ticket.server_id())?;
        check_value("organisation", fields.organisation_id)?;

        Ok(Self {
            ticket_number: fields.ticket.number().clone(),
            server_id: fields.ticket.server_id().to_owned(),
            organisation_id: fields.organisation_id.to_owned(),
            key_storage: fields.key_storage,
            site_scope: fields.site_scope,
        })
    }

    /// Returns the ticket number the issuance was made under.
    #[must_use]
    pub const fn ticket_number(&self) -> &TicketNumber {
        &self.ticket_number
    }

    /// Returns the operator who handled the call.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
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

    /// Returns whether the site axis was checked.
    #[must_use]
    pub const fn site_scope(&self) -> SiteScope {
        self.site_scope
    }

    /// Renders the annex.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let values = [
            self.ticket_number.as_str().to_owned(),
            self.server_id.clone(),
            self.organisation_id.clone(),
            self.key_storage.as_str().to_owned(),
            self.site_scope.as_str().to_owned(),
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
    /// unknown, an empty value, a token no variant is written under, or a
    /// ticket number the format does not allow.
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
        let site_scope = SiteScope::parse(field(4)).ok_or(AnnexError::UnknownToken {
            field: "site_scope",
        })?;

        Ok(Self {
            ticket_number,
            server_id: field(1).to_owned(),
            organisation_id: field(2).to_owned(),
            key_storage,
            site_scope,
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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{AnnexError, AnnexFields, KeyStorage, ReceiptAnnex, SiteScope, ANNEX_PREFIX};
    use crate::codes::tests::fixtures;

    fn annex() -> ReceiptAnnex {
        let world = fixtures::world();
        ReceiptAnnex::new(AnnexFields {
            ticket: world.ticket.ticket(),
            organisation_id: "acme",
            key_storage: KeyStorage::Token,
            site_scope: SiteScope::Checked,
        })
        .unwrap()
    }

    #[test]
    fn an_annex_survives_a_round_trip() {
        let original = annex();
        assert_eq!(ReceiptAnnex::parse(&original.to_wire()), Ok(original));
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
        let text = annex()
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
        let text = annex()
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
        let text = format!("{};extra=1", annex().to_wire());
        assert_eq!(
            ReceiptAnnex::parse(&text),
            Err(AnnexError::FieldCount { got: 6 })
        );
    }

    #[test]
    fn the_site_scope_travels_as_written() {
        let world = fixtures::world();
        let undeclared = ReceiptAnnex::new(AnnexFields {
            ticket: world.ticket.ticket(),
            organisation_id: "acme",
            key_storage: KeyStorage::Software,
            site_scope: SiteScope::Undeclared,
        })
        .unwrap();
        assert_eq!(
            ReceiptAnnex::parse(&undeclared.to_wire()).map(|parsed| parsed.site_scope()),
            Ok(SiteScope::Undeclared)
        );
    }
}

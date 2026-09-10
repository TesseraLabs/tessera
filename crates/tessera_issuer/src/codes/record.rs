//! The journal record of one issuance.
//!
//! What the issuing side writes into its hash-chain the moment it decides to
//! hand out a code, before the code leaves the process. Four facts, and each is
//! here because its absence would make an audit read the wrong thing:
//!
//! - the **organisation** whose record the device was registered under, which
//!   the grant does not carry either: a reconciliation that has to say "this
//!   code was issued after that organisation was cut off" needs to know whose
//!   code it was;
//! - the **number of the ticket** the issuing side worked under, which the grant
//!   does not carry and which the device writes into its own journal: without it
//!   a reconciliation cannot tell a login decided under one ticket from a grant
//!   issued under another;
//! - the **grant**, which carries the request the engineer signed and therefore
//!   the challenge, the nonce, the role, the level and the personal number —
//!   the whole of what was asked and answered, in one signed object;
//! - the **custody tier of the agreement key**, because a code computed with a
//!   key that never left a token and a code computed with a key file are
//!   different assurances and nothing after the fact tells them apart;
//! - whether the **site axis** was checked, because "the ticket covered the
//!   site" and "nobody said where the device stands" are two statements;
//! - whether the **identity of the engineer was left unverified**, because an
//!   issuance where a stub took a person's word for who they are is not an
//!   issuance where a factor was presented, and the two must not read alike.
//!
//! # Why the request is not a field of its own
//!
//! Because the grant already carries it, signed. A record holding both would
//! hold two copies of one object, and every reader would have to decide which
//! of them is the request. The contract refuses that shape elsewhere for the
//! same reason — [`tessera_codes_contract::grant::Grant`] checks the summary it
//! repeats byte for byte against what was signed — and the rule does not become
//! safer here. [`IssuanceRecord::request`] reads it out of the grant.
//!
//! The wire form goes through [`tessera_codes_contract::wire`], the same reader
//! and writer every document of the channel goes through: one spelling, or the
//! two sides eventually disagree about which line is well formed.

use tessera_codes_contract::grant::{Grant, GrantError};
use tessera_codes_contract::params::FleetParams;
use tessera_codes_contract::request::SignedRequest;
use tessera_codes_contract::ticket::{TicketError, TicketNumber};
use tessera_codes_contract::wire::{self, WireError};

use crate::codes::agreement::KeyStorage;
use crate::codes::scope::SiteScope;

/// Marker that opens the wire form of a record and pins the version.
pub const RECORD_PREFIX: &str = "tessera-codes/v1/issuance-record";

/// Number of fields a record carries in its wire form.
const RECORD_FIELD_COUNT: usize = 6;

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; RECORD_FIELD_COUNT] = [
    "grant",
    "ticket",
    "organisation",
    "key_storage",
    "site_scope",
    "identity_unverified",
];

/// How a boolean field is written. The format holds no empty values, so the
/// absence of a flag is a word, not a missing field.
const YES: &str = "yes";
/// The other half of [`YES`].
const NO: &str = "no";

/// The values a record is assembled from.
#[derive(Debug)]
pub struct IssuanceRecordFields {
    /// The grant the issuing side signed.
    pub grant: Grant,
    /// Number of the ticket the issuing side worked under.
    pub ticket_number: TicketNumber,
    /// Organisation the device record was signed by.
    pub organisation_id: String,
    /// Custody tier of the agreement key of this issuance.
    pub key_storage: KeyStorage,
    /// Whether the site axis of the ticket was checked against the device.
    pub site_scope: SiteScope,
    /// Whether the identity of the engineer was taken on trust.
    pub identity_unverified: bool,
}

/// One issuance, as the journal of the issuing side records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceRecord {
    grant: Grant,
    ticket_number: TicketNumber,
    organisation_id: String,
    key_storage: KeyStorage,
    site_scope: SiteScope,
    identity_unverified: bool,
}

impl IssuanceRecord {
    /// Assembles a record.
    ///
    /// Every field is required by the type: there is no constructor that leaves
    /// the custody tier or the identity mark to a default, because a default is
    /// what a writer forgets and a reader then cannot tell from a fact.
    ///
    /// # Errors
    ///
    /// The wire errors when the organisation identifier is empty or carries a
    /// character the format cannot hold, and
    /// [`IssuanceRecordError::IdentityMarkDisagrees`] when the mark and the
    /// request disagree about whether anybody vouched for the engineer.
    pub fn new(fields: IssuanceRecordFields) -> Result<Self, IssuanceRecordError> {
        wire::check_free_text("organisation", &fields.organisation_id)?;
        // The mark and the document have to say the same thing. A request
        // nobody signed, filed with the mark clear, is a record that reads a
        // year later as an issuance to a person somebody checked — and nothing
        // in it would ever show otherwise. The reverse is refused too: a mark
        // set over a signed request would make a fleet look worse than it is,
        // and a field that can lie in either direction stops being read at all.
        let unsigned = !fields.grant.request().engineer_signature().is_signed();
        if unsigned != fields.identity_unverified {
            return Err(IssuanceRecordError::IdentityMarkDisagrees {
                marked: fields.identity_unverified,
                signed: !unsigned,
            });
        }
        Ok(Self {
            grant: fields.grant,
            ticket_number: fields.ticket_number,
            organisation_id: fields.organisation_id,
            key_storage: fields.key_storage,
            site_scope: fields.site_scope,
            identity_unverified: fields.identity_unverified,
        })
    }

    /// Returns the grant this record is about.
    #[must_use]
    pub const fn grant(&self) -> &Grant {
        &self.grant
    }

    /// Returns the number of the ticket the issuing side worked under.
    #[must_use]
    pub const fn ticket_number(&self) -> &TicketNumber {
        &self.ticket_number
    }

    /// Returns the organisation the device record was signed by.
    #[must_use]
    pub fn organisation_id(&self) -> &str {
        &self.organisation_id
    }

    /// Returns the request the engineer signed, out of the grant.
    #[must_use]
    pub const fn request(&self) -> &SignedRequest {
        self.grant.request()
    }

    /// Returns the custody tier of the agreement key.
    #[must_use]
    pub const fn key_storage(&self) -> KeyStorage {
        self.key_storage
    }

    /// Returns the state of the site axis.
    #[must_use]
    pub const fn site_scope(&self) -> SiteScope {
        self.site_scope
    }

    /// Reports whether the identity of the engineer was taken on trust.
    #[must_use]
    pub const fn identity_unverified(&self) -> bool {
        self.identity_unverified
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let [grant, ticket, organisation, key_storage, site_scope, identity_unverified] = WIRE_KEYS;
        wire::render(
            RECORD_PREFIX,
            &[
                (grant, hex::encode(self.grant.to_wire())),
                (ticket, self.ticket_number.as_str().to_owned()),
                (organisation, self.organisation_id.clone()),
                (key_storage, self.key_storage.as_str().to_owned()),
                (site_scope, self.site_scope.as_str().to_owned()),
                (
                    identity_unverified,
                    if self.identity_unverified { YES } else { NO }.to_owned(),
                ),
            ],
        )
    }

    /// Parses the wire form against the fleet parameters, which fix the shape of
    /// the nonce inside the challenge inside the grant.
    ///
    /// # Errors
    ///
    /// The [`IssuanceRecordError`] describing the first violation: a missing or
    /// misspelled prefix, a wrong number of fields, a field out of order, an
    /// empty value, a grant that does not parse, or a token no field of this
    /// document is written under.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, IssuanceRecordError> {
        let values = wire::parse(text, RECORD_PREFIX, &WIRE_KEYS)?;

        let grant_bytes = wire::parse_hex("grant", wire::value(&values, 0))?;
        let grant_text = String::from_utf8(grant_bytes)
            .map_err(|_| IssuanceRecordError::Wire(WireError::UnusableValue { field: "grant" }))?;
        let grant = Grant::parse(&grant_text, params)?;

        let ticket_number = TicketNumber::parse(wire::value(&values, 1))?;

        let organisation_id = wire::value(&values, 2).to_owned();
        wire::check_free_text("organisation", &organisation_id)?;

        let key_storage = KeyStorage::parse(wire::value(&values, 3)).ok_or(
            IssuanceRecordError::UnknownToken {
                field: "key_storage",
            },
        )?;
        let site_scope =
            SiteScope::parse(wire::value(&values, 4)).ok_or(IssuanceRecordError::UnknownToken {
                field: "site_scope",
            })?;
        let identity_unverified = match wire::value(&values, 5) {
            YES => true,
            NO => false,
            _ => {
                return Err(IssuanceRecordError::UnknownToken {
                    field: "identity_unverified",
                })
            }
        };

        // Through the constructor, and not by assembling the fields here. The
        // agreement between the mark and the request is a property of the
        // DOCUMENT, not of the act of writing one: a record that came from
        // another build, from a writer that skipped the constructor, or from
        // somebody editing the file, is exactly the record whose mark must not
        // be believed. Building `Self` here left one of the two doors unlocked
        // — and the unlocked one was the door every reader comes through.
        Self::new(IssuanceRecordFields {
            grant,
            ticket_number,
            organisation_id,
            key_storage,
            site_scope,
            identity_unverified,
        })
    }
}

impl core::fmt::Display for IssuanceRecord {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Rejection of a record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssuanceRecordError {
    /// The wire form is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The grant inside the record was rejected.
    #[error("the grant of the record was rejected: {0}")]
    Grant(#[from] GrantError),
    /// The identity mark and the request disagree.
    #[error(
        "the record marks identity_unverified={marked} while the request it carries is \
         signed={signed}: the mark and the document have to say the same thing about whether \
         anybody vouched for the engineer"
    )]
    IdentityMarkDisagrees {
        /// What the mark says.
        marked: bool,
        /// Whether an authenticator signed the request.
        signed: bool,
    },
    /// The ticket number is not a ticket number.
    #[error("the record names a ticket that is not one: {0}")]
    Ticket(#[from] TicketError),
    /// A field carries a token this document is not written with.
    #[error("the record field `{field}` carries a token this document is not written with")]
    UnknownToken {
        /// Name of the offending field.
        field: &'static str,
    },
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{IssuanceRecord, IssuanceRecordError, IssuanceRecordFields, RECORD_PREFIX};
    use crate::codes::agreement::KeyStorage;
    use crate::codes::scope::SiteScope;
    use crate::codes::tests::fixtures;
    use tessera_codes_contract::grant::UnsignedGrant;
    use tessera_codes_contract::params::FleetParams;
    use tessera_codes_contract::signature::Signature;
    use tessera_codes_contract::ticket::TicketNumber;

    /// A record of the fixture world, with the marks a caller chooses.
    ///
    /// The request follows the mark rather than the other way round: the two
    /// have to agree, and a fixture that could set them apart would be a
    /// fixture for a document the type refuses to build.
    fn record(key_storage: KeyStorage, identity_unverified: bool) -> IssuanceRecord {
        let world = fixtures::world();
        let request = if identity_unverified {
            fixtures::unverified_request(&world)
        } else {
            fixtures::signed_request(&world)
        };
        let grant = UnsignedGrant::new(request, "op-42")
            .unwrap()
            .sign(Signature::new(vec![0x11, 0x22]).unwrap(), None)
            .unwrap();
        IssuanceRecord::new(IssuanceRecordFields {
            grant,
            ticket_number: TicketNumber::parse("tk-17").unwrap(),
            organisation_id: "acme".to_owned(),
            key_storage,
            site_scope: SiteScope::Checked,
            identity_unverified,
        })
        .unwrap()
    }

    #[test]
    fn a_record_round_trips_through_the_wire_form() {
        let original = record(KeyStorage::Software, true);
        assert_eq!(
            IssuanceRecord::parse(&original.to_wire(), &FleetParams::defaults()),
            Ok(original)
        );
    }

    #[test]
    fn the_mark_of_an_unverified_identity_survives_the_parser() {
        // The mark is the only thing separating an issuance a stub waved
        // through from one where somebody presented a factor. A parser that
        // dropped it, or defaulted it, would make the two read alike — and the
        // reading that matters happens months later, off the document alone.
        for unverified in [true, false] {
            let parsed = IssuanceRecord::parse(
                &record(KeyStorage::Software, unverified).to_wire(),
                &FleetParams::defaults(),
            )
            .unwrap();
            assert_eq!(parsed.identity_unverified(), unverified);
        }
    }

    #[test]
    fn the_custody_tier_survives_the_parser() {
        for tier in [KeyStorage::Software, KeyStorage::Token] {
            let parsed =
                IssuanceRecord::parse(&record(tier, false).to_wire(), &FleetParams::defaults())
                    .unwrap();
            assert_eq!(parsed.key_storage(), tier);
        }
    }

    #[test]
    fn a_record_without_a_custody_tier_does_not_parse() {
        // Not "parses with a default": the field is what says how the code of
        // this issuance was computed, and a record that lost it is a record
        // that cannot answer the question it exists to answer.
        let text = record(KeyStorage::Software, true)
            .to_wire()
            .replace(";key_storage=software", "");
        assert!(matches!(
            IssuanceRecord::parse(&text, &FleetParams::defaults()),
            Err(IssuanceRecordError::Wire(_))
        ));
    }

    #[test]
    fn a_custody_tier_nobody_writes_is_refused() {
        let text = record(KeyStorage::Software, true)
            .to_wire()
            .replace(";key_storage=software", ";key_storage=maybe");
        assert_eq!(
            IssuanceRecord::parse(&text, &FleetParams::defaults()),
            Err(IssuanceRecordError::UnknownToken {
                field: "key_storage"
            })
        );
    }

    #[test]
    fn a_mark_nobody_writes_is_refused() {
        let text = record(KeyStorage::Software, true)
            .to_wire()
            .replace(";identity_unverified=yes", ";identity_unverified=true");
        assert_eq!(
            IssuanceRecord::parse(&text, &FleetParams::defaults()),
            Err(IssuanceRecordError::UnknownToken {
                field: "identity_unverified"
            })
        );
    }

    #[test]
    fn a_mark_that_disagrees_with_the_request_does_not_assemble() {
        // Both directions, because a field that can lie either way stops being
        // read at all. Unsigned and unmarked is the one that matters: a year
        // later it reads as an issuance to somebody who was checked, and
        // nothing in the document would ever say otherwise.
        let world = fixtures::world();
        let unsigned = UnsignedGrant::new(fixtures::unverified_request(&world), "op-42")
            .unwrap()
            .sign(Signature::new(vec![0x11, 0x22]).unwrap(), None)
            .unwrap();
        assert_eq!(
            IssuanceRecord::new(IssuanceRecordFields {
                grant: unsigned,
                ticket_number: TicketNumber::parse("tk-17").unwrap(),
                organisation_id: "acme".to_owned(),
                key_storage: KeyStorage::Software,
                site_scope: SiteScope::Checked,
                identity_unverified: false,
            })
            .map(|_| ()),
            Err(IssuanceRecordError::IdentityMarkDisagrees {
                marked: false,
                signed: false
            })
        );

        let signed = UnsignedGrant::new(fixtures::signed_request(&world), "op-42")
            .unwrap()
            .sign(Signature::new(vec![0x11, 0x22]).unwrap(), None)
            .unwrap();
        assert_eq!(
            IssuanceRecord::new(IssuanceRecordFields {
                grant: signed,
                ticket_number: TicketNumber::parse("tk-17").unwrap(),
                organisation_id: "acme".to_owned(),
                key_storage: KeyStorage::Software,
                site_scope: SiteScope::Checked,
                identity_unverified: true,
            })
            .map(|_| ()),
            Err(IssuanceRecordError::IdentityMarkDisagrees {
                marked: true,
                signed: true
            })
        );
    }

    #[test]
    fn a_mark_that_disagrees_with_the_request_does_not_parse_either() {
        // Assembling and READING are two doors into the same document, and only
        // one of them was locked. A record filed elsewhere — by another build,
        // by a writer that skipped the constructor, by anyone editing the file —
        // came back through `parse` with the mark clear over a request nobody
        // signed, and the reconciliation copied that mark into its report. The
        // whole point of the mark is that it cannot be quietly clear.
        //
        // The wire form is built from a record that DOES agree and then edited,
        // which is exactly how such a line comes to exist: nothing produces it
        // on purpose.
        let honest = record(KeyStorage::Software, true);
        let text = honest.to_wire();
        assert!(text.contains(";identity_unverified=yes"));
        let forged = text.replace(";identity_unverified=yes", ";identity_unverified=no");

        assert_eq!(
            IssuanceRecord::parse(&forged, &FleetParams::defaults()).map(|_| ()),
            Err(IssuanceRecordError::IdentityMarkDisagrees {
                marked: false,
                signed: false
            })
        );

        // And the honest one still reads, so the check refuses a disagreement
        // rather than the field.
        assert!(IssuanceRecord::parse(&text, &FleetParams::defaults()).is_ok());
    }

    #[test]
    fn the_request_is_read_out_of_the_grant_and_not_beside_it() {
        let record = record(KeyStorage::Token, false);
        assert_eq!(record.request(), record.grant().request());
    }

    #[test]
    fn a_document_of_another_kind_does_not_parse_as_a_record() {
        let text = record(KeyStorage::Software, true)
            .to_wire()
            .replace(RECORD_PREFIX, "tessera-codes/v1/grant");
        assert!(matches!(
            IssuanceRecord::parse(&text, &FleetParams::defaults()),
            Err(IssuanceRecordError::Wire(_))
        ));
    }
}

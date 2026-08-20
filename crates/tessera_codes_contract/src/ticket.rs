//! The operator ticket.
//!
//! A ticket is what an operator holds while working a call: who they are, the
//! public key their side of the key agreement uses, the scope they may act in,
//! how long the ticket lasts and which number identifies it. It is signed by
//! the authority of the fleet, and its canonical bytes are hashed into the
//! derivation context of the shared key — so an edit of a scope does not merely
//! fail a signature check, it moves the key and the two sides stop meeting on a
//! code at all.
//!
//! That second effect is why [`SignedTicket::context_hash`] is the only way to
//! obtain a [`TicketHash`]: the hash has to be taken over the canonical bytes of
//! the ticket *with* its signature, and a consumer that hashed a slice of its
//! own choosing would be free to hash something an editor can leave untouched.
//!
//! # Scope
//!
//! A scope carries at least one tag and at least one role. The wire form has no
//! spelling for an absent field, and a ticket that is scoped by nothing at all
//! should say so in a value an auditor can read rather than by an emptiness
//! nobody notices.
//!
//! The role list is a bound of its own, checked apart from the highest level:
//! a role identifier and an integrity level are orthogonal axes, so a ceiling
//! on the level says nothing about which rights a role carries at it. Without
//! the list, an operator scoped to "region south, level at most 1" could hand
//! out a code for any role of that level, including one whose sudo grants are
//! wide.
//!
//! "Every role of the fleet" is written as [`ALL_ROLES`] and not as an empty
//! list: the marker travels in the wire form, reaches the audit journal of the
//! device and is legible in the printed ticket, where an absent bound would be
//! visible to nobody.

use unicode_normalization::UnicodeNormalization as _;

use crate::canon::{CanonError, Encoder, Level};
use crate::key::TicketHash;
use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::time::ClaimedTime;
use crate::wire::{self, WireError, LIST_SEPARATOR};

/// Marker that opens the wire form of a ticket and pins the version.
pub const TICKET_PREFIX: &str = "tessera-codes/v1/ticket";

/// Number of fields a signed ticket carries in its wire form.
pub const TICKET_FIELD_COUNT: usize = 9;

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; TICKET_FIELD_COUNT] = [
    "operator",
    "key",
    "tags",
    "roles",
    "region",
    "max_level",
    "not_after",
    "number",
    "signature",
];

/// The role list entry that stands for every role of the fleet.
///
/// An asterisk cannot collide with a role identifier: a role of Tessera is a
/// role account of the operating system, and no account name carries one. The
/// parser refuses it beside a named role as well, so the marker has exactly one
/// meaning and one spelling — a list is either this marker alone or a list of
/// names.
pub const ALL_ROLES: &str = "*";

/// Characters a ticket number may carry.
///
/// The set is the intersection of what is readable over a telephone and what is
/// safe in a file name: the ticket number is one component of the receipt file
/// name, and a component that could carry a path separator would let a document
/// choose where it is written.
fn is_number_character(symbol: char) -> bool {
    symbol.is_ascii_alphanumeric() || matches!(symbol, '-' | '_' | '.')
}

/// The number identifying a ticket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TicketNumber(String);

impl TicketNumber {
    /// Parses a ticket number.
    ///
    /// # Errors
    ///
    /// Returns [`TicketError::EmptyValue`] for an empty number and
    /// [`TicketError::UnusableTicketNumber`] when it carries a character
    /// outside the restricted set — see [`is_number_character`].
    pub fn parse(text: &str) -> Result<Self, TicketError> {
        if text.is_empty() {
            return Err(TicketError::Wire(WireError::EmptyValue { field: "number" }));
        }
        if !text.chars().all(is_number_character) {
            return Err(TicketError::UnusableTicketNumber);
        }
        Ok(Self(text.to_owned()))
    }

    /// Returns the number as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for TicketNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The bounds of a scope, as they arrive from a caller.
///
/// The scope is built from a named struct rather than from positional
/// arguments: the tags and the roles are both lists of strings, and two call
/// sites that swapped them would compile into a ticket bounded by the wrong
/// axis on both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketScopeInput {
    /// Tags of the sites the ticket reaches.
    pub tags: Vec<String>,
    /// Roles the ticket may hand out, or [`ALL_ROLES`] alone.
    pub roles: Vec<String>,
    /// Region the ticket is confined to.
    pub region: String,
    /// Highest level the holder may ask for.
    pub max_level: Level,
}

/// The bounds a ticket puts on its holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketScope {
    tags: Vec<String>,
    roles: Vec<String>,
    region: String,
    max_level: Level,
}

impl TicketScope {
    /// Builds a scope.
    ///
    /// # Errors
    ///
    /// Returns [`TicketError::EmptyScope`] when no tag is given,
    /// [`TicketError::EmptyRoles`] when no role is given,
    /// [`TicketError::RoleMarkerNotAlone`] when [`ALL_ROLES`] stands beside a
    /// named role, and the wire errors when a tag, a role or the region carries
    /// a character the format cannot hold — a separator of the format or of a
    /// list, or a control character.
    pub fn new(input: TicketScopeInput) -> Result<Self, TicketError> {
        let TicketScopeInput {
            tags,
            roles,
            region,
            max_level,
        } = input;

        if tags.is_empty() {
            return Err(TicketError::EmptyScope);
        }
        for tag in &tags {
            wire::check_list_item("tags", tag)?;
        }

        if roles.is_empty() {
            return Err(TicketError::EmptyRoles);
        }
        for role in &roles {
            wire::check_list_item("roles", role)?;
        }
        if roles.iter().any(|role| role == ALL_ROLES) && roles.len() > 1 {
            return Err(TicketError::RoleMarkerNotAlone);
        }

        wire::check_free_text("region", &region)?;
        Ok(Self {
            tags,
            roles,
            region,
            max_level,
        })
    }

    /// Returns the tags of the scope.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Returns the role list of the scope, which is either [`ALL_ROLES`] alone
    /// or one or more role identifiers.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns the region of the scope.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Returns the highest level the holder may ask for.
    #[must_use]
    pub const fn max_level(&self) -> Level {
        self.max_level
    }

    /// Reports whether the scope was written for every role of the fleet.
    #[must_use]
    pub fn admits_all_roles(&self) -> bool {
        self.roles.iter().any(|role| role == ALL_ROLES)
    }

    /// Reports whether a role is within the scope.
    ///
    /// The comparison is made in Unicode NFC, the same normalisation the
    /// canonical encoding applies to the role identifier of a code: the bound
    /// that admits a role and the bytes that bind it into the MAC must not read
    /// two spellings of one name differently.
    #[must_use]
    pub fn admits_role(&self, role_id: &str) -> bool {
        self.admits_all_roles() || self.roles.iter().any(|role| role.nfc().eq(role_id.nfc()))
    }

    /// Reports whether a level is within the scope.
    ///
    /// A level within the ceiling is not by itself a permission: which roles
    /// the holder may hand out is [`TicketScope::admits_role`], and the two
    /// bounds are checked apart.
    #[must_use]
    pub fn admits_level(&self, level: Level) -> bool {
        level <= self.max_level
    }
}

/// An operator ticket, without its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorTicket {
    operator_id: String,
    public_key: PublicKey,
    scope: TicketScope,
    not_after: ClaimedTime,
    number: TicketNumber,
}

impl OperatorTicket {
    /// Assembles a ticket.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when the operator identifier is empty or carries
    /// a character the format cannot hold.
    pub fn new(
        operator_id: &str,
        public_key: PublicKey,
        scope: TicketScope,
        not_after: ClaimedTime,
        number: TicketNumber,
    ) -> Result<Self, TicketError> {
        wire::check_free_text("operator", operator_id)?;
        Ok(Self {
            operator_id: operator_id.to_owned(),
            public_key,
            scope,
            not_after,
            number,
        })
    }

    /// Returns the identifier of the operator the ticket belongs to.
    #[must_use]
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    /// Returns the public key of the operator side of the key agreement.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the scope of the ticket.
    #[must_use]
    pub const fn scope(&self) -> &TicketScope {
        &self.scope
    }

    /// Returns the moment the ticket stops being valid, as claimed by the
    /// issuing side.
    #[must_use]
    pub const fn not_after(&self) -> ClaimedTime {
        self.not_after
    }

    /// Returns the number of the ticket.
    #[must_use]
    pub const fn number(&self) -> &TicketNumber {
        &self.number
    }

    /// Reports whether the ticket is still within its term at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`TicketError::Expired`] when the term has passed. Both moments
    /// are claims, and the comparison is only as good as the clock the caller
    /// supplied — see [`ClaimedTime`].
    pub fn check_term(&self, now: ClaimedTime) -> Result<(), TicketError> {
        if now > self.not_after {
            return Err(TicketError::Expired {
                not_after: self.not_after,
                now,
            });
        }
        Ok(())
    }

    /// Writes the body fields into an encoder, in the canonical order.
    fn encode_into(&self, encoder: &mut Encoder) -> Result<(), CanonError> {
        encoder.push_text("operator_id", &self.operator_id)?;
        encoder.push_bytes("public_key", self.public_key.as_bytes())?;
        let tag_count = u32::try_from(self.scope.tags.len())
            .map_err(|_| CanonError::FieldTooLong { field: "tag_count" })?;
        encoder.push_u32("tag_count", tag_count)?;
        for tag in &self.scope.tags {
            encoder.push_text("tag", tag)?;
        }
        let role_count =
            u32::try_from(self.scope.roles.len()).map_err(|_| CanonError::FieldTooLong {
                field: "role_count",
            })?;
        encoder.push_u32("role_count", role_count)?;
        for role in &self.scope.roles {
            encoder.push_text("role", role)?;
        }
        encoder.push_text("region", &self.scope.region)?;
        encoder.push_u32("max_level", self.scope.max_level.get())?;
        encoder.push_u64("not_after", self.not_after.get())?;
        encoder.push_text("ticket_number", self.number.as_str())?;
        Ok(())
    }

    /// Encodes the unsigned ticket canonically — the bytes the authority signs.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        self.encode_into(&mut encoder)?;
        Ok(encoder.finish())
    }
}

/// An operator ticket with the signature of the issuing authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTicket {
    ticket: OperatorTicket,
    signature: Signature,
}

impl SignedTicket {
    /// Pairs a ticket with the signature over its canonical bytes.
    #[must_use]
    pub const fn new(ticket: OperatorTicket, signature: Signature) -> Self {
        Self { ticket, signature }
    }

    /// Returns the ticket.
    ///
    /// The value is returned whether or not the signature has been verified:
    /// checking it is [`SignedTicket::verify`], and a consumer that reads the
    /// fields without calling it is reading an unauthenticated document.
    #[must_use]
    pub const fn ticket(&self) -> &OperatorTicket {
        &self.ticket
    }

    /// Returns the signature of the issuing authority.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Encodes the signed ticket canonically: the body fields, then the
    /// signature as one more length-prefixed field.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        self.ticket.encode_into(&mut encoder)?;
        encoder.push_bytes("signature", self.signature.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Returns the hash that binds this ticket into the key derivation context.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when the ticket cannot be encoded.
    pub fn context_hash(&self) -> Result<TicketHash, CanonError> {
        Ok(TicketHash::of_canonical_signed_ticket(&self.encode()?))
    }

    /// Verifies the signature of the authority and the term of the ticket.
    ///
    /// The signature is checked first: the term of a document nobody signed is
    /// not information, and reporting "expired" for a forged ticket would tell
    /// a caller it had a real ticket that merely aged.
    ///
    /// # Errors
    ///
    /// Returns [`TicketError::Canon`] when the ticket cannot be encoded,
    /// [`TicketError::Signature`] when the authority signature does not hold or
    /// the authority is not anchored, and [`TicketError::Expired`] when the
    /// term has passed.
    pub fn verify(
        &self,
        verifier: &impl SignatureVerifier,
        now: ClaimedTime,
    ) -> Result<(), TicketError> {
        let message = self.ticket.encode()?;
        verifier.verify(SignerRef::TicketAuthority, &message, &self.signature)?;
        self.ticket.check_term(now)
    }

    /// Renders the wire form of the signed ticket.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let fields = [
            ("operator", self.ticket.operator_id.clone()),
            ("key", hex::encode(self.ticket.public_key.as_bytes())),
            (
                "tags",
                self.ticket.scope.tags.join(&LIST_SEPARATOR.to_string()),
            ),
            (
                "roles",
                self.ticket.scope.roles.join(&LIST_SEPARATOR.to_string()),
            ),
            ("region", self.ticket.scope.region.clone()),
            ("max_level", self.ticket.scope.max_level.get().to_string()),
            ("not_after", self.ticket.not_after.get().to_string()),
            ("number", self.ticket.number.0.clone()),
            ("signature", hex::encode(self.signature.as_bytes())),
        ];
        wire::render(TICKET_PREFIX, &fields)
    }

    /// Parses the wire form of a signed ticket.
    ///
    /// # Errors
    ///
    /// Returns the [`TicketError`] describing the first violation: a wrong or
    /// missing prefix, a field that is unknown, missing or out of order, an
    /// empty value, a value the target type cannot hold, or a scope with no
    /// tag or no role. Nothing is repaired and nothing is dropped: a ticket
    /// whose role list is missing is refused rather than read as a ticket for
    /// every role.
    pub fn parse(text: &str) -> Result<Self, TicketError> {
        let values = wire::parse(text, TICKET_PREFIX, &WIRE_KEYS)?;
        let public_key = PublicKey::new(wire::parse_hex("key", wire::value(&values, 1))?)?;
        let tags = parse_list("tags", wire::value(&values, 2))?;
        let roles = parse_list("roles", wire::value(&values, 3))?;
        let scope = TicketScope::new(TicketScopeInput {
            tags,
            roles,
            region: wire::value(&values, 4).to_owned(),
            max_level: Level::new(wire::parse_u32("max_level", wire::value(&values, 5))?),
        })?;
        let not_after = ClaimedTime::new(wire::parse_u64("not_after", wire::value(&values, 6))?);
        let number = TicketNumber::parse(wire::value(&values, 7))?;
        let ticket = OperatorTicket::new(
            wire::value(&values, 0),
            public_key,
            scope,
            not_after,
            number,
        )?;
        let signature = Signature::new(wire::parse_hex("signature", wire::value(&values, 8))?)?;
        Ok(Self::new(ticket, signature))
    }
}

/// Splits a list-valued field of the wire form.
///
/// # Errors
///
/// Returns [`WireError::EmptyValue`] when an item of the list is empty — a
/// trailing separator is a malformed document, not a list with a blank at the
/// end.
fn parse_list(field: &'static str, value: &str) -> Result<Vec<String>, TicketError> {
    let items: Vec<String> = value.split(LIST_SEPARATOR).map(str::to_owned).collect();
    if items.iter().any(String::is_empty) {
        return Err(TicketError::Wire(WireError::EmptyValue { field }));
    }
    Ok(items)
}

impl core::fmt::Display for SignedTicket {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Rejection of a ticket.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    /// The wire form of the ticket is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The ticket carries a scope with no tag.
    #[error("the ticket scope carries no tag")]
    EmptyScope,
    /// The ticket carries a scope with no role.
    #[error("the ticket scope carries no role")]
    EmptyRoles,
    /// The all-roles marker stands beside a named role.
    #[error("the ticket scope carries `{ALL_ROLES}` beside a named role")]
    RoleMarkerNotAlone,
    /// The ticket number carries a character outside the restricted set.
    #[error("the ticket number carries a character the format does not allow")]
    UnusableTicketNumber,
    /// The ticket cannot be encoded canonically.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// The signature of the authority was rejected.
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// The term of the ticket has passed.
    #[error("the ticket expired at {not_after}, the caller reports {now}")]
    Expired {
        /// Moment the ticket stopped being valid.
        not_after: ClaimedTime,
        /// Moment the caller reported.
        now: ClaimedTime,
    },
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
pub(crate) mod tests {
    use super::{
        OperatorTicket, SignedTicket, TicketError, TicketNumber, TicketScope, TicketScopeInput,
        ALL_ROLES, TICKET_PREFIX,
    };
    use crate::canon::Level;
    use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
    use crate::time::ClaimedTime;
    use crate::wire::WireError;

    /// Verifier that accepts one message from the ticket authority and nothing
    /// else — enough to tell "the signature was checked" from "it was not".
    pub(crate) struct AcceptingAuthority {
        pub(crate) accepted: Vec<u8>,
    }

    impl SignatureVerifier for AcceptingAuthority {
        fn verify(
            &self,
            signer: SignerRef<'_>,
            message: &[u8],
            _signature: &Signature,
        ) -> Result<(), SignatureError> {
            match signer {
                SignerRef::TicketAuthority if message == self.accepted => Ok(()),
                SignerRef::TicketAuthority => Err(SignatureError::Rejected),
                SignerRef::Key(_) | SignerRef::Named(_) => Err(SignatureError::UnknownSigner),
            }
        }
    }

    pub(crate) fn signed_ticket() -> SignedTicket {
        let scope = TicketScope::new(TicketScopeInput {
            tags: vec!["dc-1".to_owned(), "hq".to_owned()],
            roles: vec!["ops.dc.senior".to_owned()],
            region: "ru-central".to_owned(),
            max_level: Level::new(3),
        })
        .unwrap();
        let ticket = OperatorTicket::new(
            "op-42",
            PublicKey::new(vec![0x04, 0x11, 0x22]).unwrap(),
            scope,
            ClaimedTime::new(1_800_000_000),
            TicketNumber::parse("tk-17").unwrap(),
        )
        .unwrap();
        SignedTicket::new(ticket, Signature::new(vec![0xab, 0xcd]).unwrap())
    }

    #[test]
    fn the_wire_form_round_trips() {
        let ticket = signed_ticket();
        assert_eq!(SignedTicket::parse(&ticket.to_wire()), Ok(ticket));
    }

    #[test]
    fn the_canonical_bytes_are_the_hand_written_framing() {
        let encoded = signed_ticket().encode().unwrap();
        assert_eq!(
            hex::encode(encoded),
            concat!(
                "00000005",
                "6f702d3432", // operator id "op-42"
                "00000003",
                "041122", // public key
                "00000004",
                "00000002", // two tags
                "00000004",
                "64632d31", // tag "dc-1"
                "00000002",
                "6871", // tag "hq"
                "00000004",
                "00000001", // one role
                "0000000d",
                "6f70732e64632e73656e696f72", // role "ops.dc.senior"
                "0000000a",
                "72752d63656e7472616c", // region "ru-central"
                "00000004",
                "00000003", // max level 3
                "00000008",
                "000000006b49d200", // not_after 1800000000
                "00000005",
                "746b2d3137", // ticket number "tk-17"
                "00000002",
                "abcd", // signature
            )
        );
    }

    #[test]
    fn the_context_hash_covers_the_signature() {
        let ticket = signed_ticket();
        let resigned = SignedTicket::new(
            ticket.ticket().clone(),
            Signature::new(vec![0xab, 0xce]).unwrap(),
        );
        assert_ne!(
            ticket.context_hash().unwrap(),
            resigned.context_hash().unwrap()
        );
    }

    #[test]
    fn an_edited_field_moves_the_context_hash() {
        let ticket = signed_ticket();
        let widened = SignedTicket::new(
            OperatorTicket::new(
                ticket.ticket().operator_id(),
                ticket.ticket().public_key().clone(),
                TicketScope::new(TicketScopeInput {
                    tags: ticket.ticket().scope().tags().to_vec(),
                    roles: ticket.ticket().scope().roles().to_vec(),
                    region: ticket.ticket().scope().region().to_owned(),
                    max_level: Level::new(9),
                })
                .unwrap(),
                ticket.ticket().not_after(),
                ticket.ticket().number().clone(),
            )
            .unwrap(),
            ticket.signature().clone(),
        );
        assert_ne!(
            ticket.context_hash().unwrap(),
            widened.context_hash().unwrap()
        );
    }

    #[test]
    fn verification_checks_the_signature_before_the_term() {
        let ticket = signed_ticket();
        let verifier = AcceptingAuthority {
            accepted: ticket.ticket().encode().unwrap(),
        };
        assert_eq!(
            ticket.verify(&verifier, ClaimedTime::new(1_700_000_000)),
            Ok(())
        );
        // Past the term, with a signature that holds.
        assert!(matches!(
            ticket.verify(&verifier, ClaimedTime::new(1_900_000_000)),
            Err(TicketError::Expired { .. })
        ));
        // A ticket the authority did not sign is reported as a signature
        // failure even when it is also expired.
        let stranger = AcceptingAuthority {
            accepted: Vec::new(),
        };
        assert_eq!(
            ticket.verify(&stranger, ClaimedTime::new(1_900_000_000)),
            Err(TicketError::Signature(SignatureError::Rejected))
        );
    }

    #[test]
    fn the_term_ends_after_the_last_admitted_moment() {
        let ticket = signed_ticket();
        assert_eq!(
            ticket.ticket().check_term(ClaimedTime::new(1_800_000_000)),
            Ok(())
        );
        assert!(ticket
            .ticket()
            .check_term(ClaimedTime::new(1_800_000_001))
            .is_err());
    }

    /// A scope carrying `roles`, and one tag so that the tag bound is satisfied.
    fn scope_with_roles(roles: &[&str]) -> Result<TicketScope, TicketError> {
        TicketScope::new(TicketScopeInput {
            tags: vec!["dc-1".to_owned()],
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            region: "ru".to_owned(),
            max_level: Level::new(1),
        })
    }

    #[test]
    fn a_scope_without_tags_is_refused() {
        assert_eq!(
            TicketScope::new(TicketScopeInput {
                tags: Vec::new(),
                roles: vec!["ops".to_owned()],
                region: "ru".to_owned(),
                max_level: Level::new(1),
            }),
            Err(TicketError::EmptyScope)
        );
    }

    #[test]
    fn a_scope_without_roles_is_refused() {
        assert_eq!(scope_with_roles(&[]), Err(TicketError::EmptyRoles));
    }

    #[test]
    fn the_all_roles_marker_stands_alone_or_not_at_all() {
        assert_eq!(
            scope_with_roles(&[ALL_ROLES, "ops"]),
            Err(TicketError::RoleMarkerNotAlone)
        );
        assert_eq!(
            scope_with_roles(&["ops", ALL_ROLES]),
            Err(TicketError::RoleMarkerNotAlone)
        );
    }

    #[test]
    fn the_scope_bounds_the_role() {
        let scope = scope_with_roles(&["ops.dc.senior", "serv"]).unwrap();
        assert!(scope.admits_role("ops.dc.senior"));
        assert!(scope.admits_role("serv"));
        // The role the ticket does not name is refused even though the level it
        // would be asked for is within the ceiling.
        assert!(!scope.admits_role("ops.dc.root"));
        assert!(!scope.admits_all_roles());
    }

    #[test]
    fn the_all_roles_marker_admits_any_role() {
        let scope = scope_with_roles(&[ALL_ROLES]).unwrap();
        assert!(scope.admits_all_roles());
        assert!(scope.admits_role("ops.dc.senior"));
        assert!(scope.admits_role("anything-at-all"));
        assert_eq!(scope.roles(), [ALL_ROLES.to_owned()]);
    }

    #[test]
    fn a_role_is_matched_in_the_normalisation_the_code_is_computed_in() {
        let scope = scope_with_roles(&["r\u{00f4}le"]).unwrap();
        assert!(scope.admits_role("ro\u{0302}le"));
    }

    #[test]
    fn an_unknown_field_does_not_parse() {
        let text = format!("{};extra=1", signed_ticket().to_wire());
        assert!(matches!(
            SignedTicket::parse(&text),
            Err(TicketError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn a_broken_structure_does_not_parse() {
        let ticket = signed_ticket();
        assert!(matches!(
            SignedTicket::parse(&ticket.to_wire().replace("region=", "region")),
            Err(TicketError::Wire(WireError::MalformedField { .. }))
        ));
        assert!(matches!(
            SignedTicket::parse(&ticket.to_wire().replace(";number=tk-17", "")),
            Err(TicketError::Wire(WireError::UnexpectedField { .. }))
        ));
        assert!(matches!(
            SignedTicket::parse(&ticket.to_wire().replace(TICKET_PREFIX, "other/v1/ticket")),
            Err(TicketError::Wire(WireError::WrongPrefix { .. }))
        ));
    }

    #[test]
    fn an_unusable_value_does_not_parse() {
        let ticket = signed_ticket();
        assert!(matches!(
            SignedTicket::parse(&ticket.to_wire().replace("max_level=3", "max_level=three")),
            Err(TicketError::Wire(WireError::NotANumber {
                field: "max_level"
            }))
        ));
        assert!(matches!(
            SignedTicket::parse(&ticket.to_wire().replace("key=041122", "key=04112")),
            Err(TicketError::Wire(WireError::NotHex { field: "key" }))
        ));
        assert!(matches!(
            SignedTicket::parse(&ticket.to_wire().replace("number=tk-17", "number=tk/17")),
            Err(TicketError::UnusableTicketNumber)
        ));
        assert!(matches!(
            SignedTicket::parse(&ticket.to_wire().replace("tags=dc-1,hq", "tags=dc-1,")),
            Err(TicketError::Wire(WireError::EmptyValue { field: "tags" }))
        ));
        assert!(matches!(
            SignedTicket::parse(
                &ticket
                    .to_wire()
                    .replace("roles=ops.dc.senior", "roles=ops.dc.senior,")
            ),
            Err(TicketError::Wire(WireError::EmptyValue { field: "roles" }))
        ));
        assert!(matches!(
            SignedTicket::parse(
                &ticket
                    .to_wire()
                    .replace("not_after=1800000000", "not_after=-1")
            ),
            Err(TicketError::Wire(WireError::NotANumber {
                field: "not_after"
            }))
        ));
    }

    #[test]
    fn the_wire_form_carries_the_roles_and_refuses_a_ticket_without_them() {
        let ticket = signed_ticket();
        let wire = ticket.to_wire();
        assert!(wire.contains(";roles=ops.dc.senior;"));
        assert_eq!(
            SignedTicket::parse(&wire).unwrap().ticket().scope().roles(),
            ["ops.dc.senior".to_owned()]
        );

        // A ticket of the older shape, whose scope named no role, does not
        // become a ticket for every role: it does not parse at all.
        assert!(matches!(
            SignedTicket::parse(&wire.replace(";roles=ops.dc.senior", "")),
            Err(TicketError::Wire(WireError::UnexpectedField {
                expected: "roles",
                ..
            }))
        ));

        let all_roles = SignedTicket::parse(&wire.replace("roles=ops.dc.senior", "roles=*"));
        assert!(all_roles.unwrap().ticket().scope().admits_all_roles());
    }

    #[test]
    fn the_scope_bounds_the_level() {
        let ticket = signed_ticket();
        assert!(ticket.ticket().scope().admits_level(Level::new(3)));
        assert!(!ticket.ticket().scope().admits_level(Level::new(4)));
    }
}

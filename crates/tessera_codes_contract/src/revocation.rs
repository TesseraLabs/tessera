//! The list of withdrawn rights: engineers and organisations.
//!
//! A right is granted by a document ([`crate::engineer`]) and taken away by
//! this one. The two are asymmetric on purpose: a grant is checked where it is
//! used, and a withdrawal has to reach every place the grant already travelled
//! to, so it is published as a whole list rather than as a message about one
//! subject.
//!
//! # Why the list is signed, and by which key
//!
//! Because the consumer of a revocation list is the side that would otherwise
//! keep letting people in. A list that arrives unsigned is a list anybody on
//! the path can replace with an empty one, and an empty revocation list is
//! indistinguishable from "nobody has been cut off" — the failure is silent and
//! it fails **open**, which is the worst shape a security control can take.
//!
//! The signer is the fleet's authorisation key
//! ([`crate::signature::SignerRef::AuthorisationKey`]), the same key that grants
//! authorisations, and deliberately not the organisation: an organisation must
//! not be able to un-revoke its own people, and a fleet that let it would have
//! given the ceiling away to the party the ceiling is about.
//!
//! # Why the serial is monotonic
//!
//! A signature stops substitution but not replay: yesterday's list is signed
//! just as validly as today's, and yesterday's is the one that still admits the
//! engineer who was cut off this morning. The serial is what makes an older
//! list refusable, and the rule belongs to the consumer, which knows which
//! serial it has already applied — see [`RevocationList::is_newer_than`].
//!
//! # Why an unknown reason is not a refusal
//!
//! The reason is a token for a person reading a report; the *withdrawal* is the
//! fact. A reader that refused the whole list over a reason word it does not
//! know would fail open on every entry in it, including the ones it understands
//! perfectly. Unknown reasons are carried verbatim, exactly as unknown outcome
//! words are elsewhere in this channel.

use crate::canon::{CanonError, Encoder};
use crate::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::time::ClaimedTime;
use crate::wire::{self, WireError, LIST_SEPARATOR};

/// Marker that opens the wire form of a list and pins the version.
pub const REVOCATION_LIST_PREFIX: &str = "tessera-codes/v1/revocation-list";

/// Marker that opens the wire form of a signed list.
///
/// A prefix of its own rather than a field: the parser accepts one field list
/// per prefix, so an unsigned list offered where a signed one is expected is
/// refused by the reader instead of being read and found unsigned later — which
/// is the whole failure this document exists to prevent.
pub const SIGNED_REVOCATION_LIST_PREFIX: &str = "tessera-codes/v1/signed-revocation-list";

/// Number of fields a list carries in its wire form.
pub const REVOCATION_LIST_FIELD_COUNT: usize = 3;

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; REVOCATION_LIST_FIELD_COUNT] = ["serial", "issued_at", "entries"];

/// Field keys of the signed form.
const SIGNED_WIRE_KEYS: [&str; 2] = ["list", "authorisation_signature"];

/// Label the signature of a list is made under.
///
/// Every signature of the contract is made over a labelled message, so bytes
/// signed as one document can never be replayed as another.
const LIST_LABEL: &str = "tessera-codes-contract/v1/revocation-list";

/// Separator between the fields of one entry.
///
/// The list separator already divides entries, so an entry needs a second one.
/// A colon cannot appear in any part of an entry: the parts are checked for it,
/// because an identifier carrying the separator would let one entry read as two
/// — and the second of the two would name a subject nobody withdrew.
const ENTRY_SEPARATOR: char = ':';

/// Value of the entry field when the list withdraws nothing.
///
/// Written out rather than left empty because the wire form refuses empty
/// values everywhere else. An empty list is a legitimate document — a fleet
/// that has cut nobody off publishes one, and it says so signed, which is
/// exactly the statement an unsigned absence cannot make.
pub const NO_ENTRIES: &str = "none";

/// Whose right was withdrawn.
///
/// Two kinds and not one string: an engineer and an organisation can carry the
/// same identifier in a fleet that numbers them separately, and a reader that
/// matched on the identifier alone would cut off the wrong party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectKind {
    /// A person, by their personal number.
    Engineer,
    /// An organisation, by its identifier.
    Organisation,
}

impl SubjectKind {
    /// The token this kind is written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Engineer => "engineer",
            Self::Organisation => "organisation",
        }
    }

    /// Parses a kind written by [`SubjectKind::as_str`].
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        [Self::Engineer, Self::Organisation]
            .into_iter()
            .find(|kind| kind.as_str() == token)
    }
}

/// Reports whether two identifiers name the same subject of that kind.
///
/// One rule, in one place, because every party to the channel has to agree
/// about it: the device that took the number from a prompt, the issuing side
/// that wrote it into a grant, and the reconciliation that pairs the two. A
/// second spelling of this comparison somewhere else is a party that can be
/// made to disagree, and disagreement here reads as "no withdrawal applies".
///
/// A personal number is a number of this channel's format, where separators and
/// case carry nothing and are retyped freely; it is compared by the characters
/// the format counts. An organisation identifier is a name a fleet assigns, not
/// a number, and is compared by its bytes.
#[must_use]
pub fn same_subject(kind: SubjectKind, left: &str, right: &str) -> bool {
    match kind {
        SubjectKind::Engineer => {
            crate::number::significant_characters(left)
                == crate::number::significant_characters(right)
        }
        SubjectKind::Organisation => left == right,
    }
}

/// One withdrawn right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationEntry {
    kind: SubjectKind,
    subject_id: String,
    revoked_at: ClaimedTime,
    reason: String,
}

impl RevocationEntry {
    /// Records one withdrawal.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when the identifier or the reason is empty or
    /// carries a character the format cannot hold, and
    /// [`RevocationError::SeparatorInEntry`] when either carries the separator
    /// that divides the parts of an entry.
    pub fn new(
        kind: SubjectKind,
        subject_id: &str,
        revoked_at: ClaimedTime,
        reason: &str,
    ) -> Result<Self, RevocationError> {
        check_entry_part("subject_id", subject_id)?;
        check_entry_part("reason", reason)?;
        Ok(Self {
            kind,
            subject_id: subject_id.to_owned(),
            revoked_at,
            reason: reason.to_owned(),
        })
    }

    /// Returns whose right this is about.
    #[must_use]
    pub const fn kind(&self) -> SubjectKind {
        self.kind
    }

    /// Returns the identifier of the subject.
    #[must_use]
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    /// Returns the moment the right was withdrawn.
    #[must_use]
    pub const fn revoked_at(&self) -> ClaimedTime {
        self.revoked_at
    }

    /// Returns the reason token, verbatim.
    ///
    /// Verbatim because the vocabulary is open: a fleet adds reasons, and a
    /// reader of an older build has to carry a word it does not know rather
    /// than drop the entry that carries it.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Renders the entry as one item of the list field.
    fn to_item(&self) -> String {
        format!(
            "{}{ENTRY_SEPARATOR}{}{ENTRY_SEPARATOR}{}{ENTRY_SEPARATOR}{}",
            self.kind.as_str(),
            self.subject_id,
            self.revoked_at.get(),
            self.reason
        )
    }

    /// Reads one item of the list field.
    fn parse_item(item: &str) -> Result<Self, RevocationError> {
        let parts: Vec<&str> = item.split(ENTRY_SEPARATOR).collect();
        let [kind, subject_id, revoked_at, reason] = <[&str; 4]>::try_from(parts.as_slice())
            .map_err(|_| RevocationError::MalformedEntry {
                item: item.to_owned(),
            })?;
        let kind = SubjectKind::parse(kind).ok_or_else(|| RevocationError::UnknownSubjectKind {
            token: kind.to_owned(),
        })?;
        let revoked_at = ClaimedTime::new(wire::parse_u64("revoked_at", revoked_at)?);
        Self::new(kind, subject_id, revoked_at, reason)
    }
}

/// The values a list is assembled from.
#[derive(Debug)]
pub struct RevocationListFields {
    /// Serial of the list, monotonic under the key that signs it.
    pub serial: u64,
    /// The moment the fleet published it.
    pub issued_at: ClaimedTime,
    /// The withdrawals, possibly none.
    pub entries: Vec<RevocationEntry>,
}

/// Every right a fleet has withdrawn, as of one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationList {
    serial: u64,
    issued_at: ClaimedTime,
    entries: Vec<RevocationEntry>,
}

impl RevocationList {
    /// Assembles a list.
    ///
    /// # Errors
    ///
    /// [`RevocationError::RepeatedSubject`] when one subject appears twice: two
    /// entries about one party are two answers about when their right ended,
    /// and a reader that took either of them would be choosing.
    pub fn new(fields: RevocationListFields) -> Result<Self, RevocationError> {
        for (index, entry) in fields.entries.iter().enumerate() {
            if fields.entries.iter().take(index).any(|earlier| {
                earlier.kind == entry.kind
                    && same_subject(entry.kind, &earlier.subject_id, &entry.subject_id)
            }) {
                return Err(RevocationError::RepeatedSubject {
                    subject: entry.subject_id.clone(),
                });
            }
        }
        Ok(Self {
            serial: fields.serial,
            issued_at: fields.issued_at,
            entries: fields.entries,
        })
    }

    /// Returns the serial of the list.
    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }

    /// Returns the moment the fleet published it.
    #[must_use]
    pub const fn issued_at(&self) -> ClaimedTime {
        self.issued_at
    }

    /// Returns the withdrawals.
    #[must_use]
    pub fn entries(&self) -> &[RevocationEntry] {
        &self.entries
    }

    /// Reports whether this list supersedes the serial already applied.
    ///
    /// The rule the consumer enforces, stated once here so two consumers cannot
    /// state it differently. A list whose serial is not greater is a replay: it
    /// is signed just as validly as the current one and it is the one that
    /// still admits whoever was cut off since.
    #[must_use]
    pub const fn is_newer_than(&self, applied_serial: u64) -> bool {
        self.serial > applied_serial
    }

    /// Returns the withdrawal of one subject, when this list carries one.
    ///
    /// A personal number is matched by the characters the format counts, not by
    /// the bytes: separators and case are not part of a number, and the person
    /// who types it chooses them. Matching bytes would hand the choice of
    /// whether a withdrawal applies to the person it was written against — type
    /// `org1 000001 4` instead of `ORG1-0000014` and the list stops naming you.
    ///
    /// An organisation identifier is matched by its bytes, because it is not a
    /// number of this format: it is a name a fleet assigns, and folding it
    /// would make two names one.
    #[must_use]
    pub fn withdrawal_of(&self, kind: SubjectKind, subject_id: &str) -> Option<&RevocationEntry> {
        self.entries
            .iter()
            .find(|entry| entry.kind == kind && same_subject(kind, &entry.subject_id, subject_id))
    }

    /// Encodes the message the authorisation key signs.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("label", LIST_LABEL)?;
        encoder.push_u64("serial", self.serial)?;
        encoder.push_u64("issued_at", self.issued_at.get())?;
        // The count travels inside the signed bytes so that a list cannot be
        // shortened by an editor who leaves the remaining entries intact: the
        // canonical encoding of a shorter list differs before the entries are
        // even reached.
        encoder.push_u32(
            "entry_count",
            u32::try_from(self.entries.len()).unwrap_or(u32::MAX),
        )?;
        for entry in &self.entries {
            encoder.push_text("kind", entry.kind.as_str())?;
            encoder.push_text("subject_id", &entry.subject_id)?;
            encoder.push_u64("revoked_at", entry.revoked_at.get())?;
            encoder.push_text("reason", &entry.reason)?;
        }
        Ok(encoder.finish())
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let [serial, issued_at, entries] = WIRE_KEYS;
        let items = if self.entries.is_empty() {
            NO_ENTRIES.to_owned()
        } else {
            self.entries
                .iter()
                .map(RevocationEntry::to_item)
                .collect::<Vec<_>>()
                .join(&LIST_SEPARATOR.to_string())
        };
        wire::render(
            REVOCATION_LIST_PREFIX,
            &[
                (serial, self.serial.to_string()),
                (issued_at, self.issued_at.get().to_string()),
                (entries, items),
            ],
        )
    }

    /// Parses the wire form.
    ///
    /// # Errors
    ///
    /// The [`RevocationError`] describing the first violation: a missing or
    /// misspelled prefix, a field unknown, missing or out of order, an empty
    /// value, an entry that is not four parts, a subject kind nobody writes, or
    /// one subject twice.
    pub fn parse(text: &str) -> Result<Self, RevocationError> {
        let values = wire::parse(text, REVOCATION_LIST_PREFIX, &WIRE_KEYS)?;
        let serial = wire::parse_u64("serial", wire::value(&values, 0))?;
        let issued_at = ClaimedTime::new(wire::parse_u64("issued_at", wire::value(&values, 1))?);
        let items = wire::value(&values, 2);
        let entries = if items == NO_ENTRIES {
            Vec::new()
        } else {
            items
                .split(LIST_SEPARATOR)
                .map(RevocationEntry::parse_item)
                .collect::<Result<Vec<_>, _>>()?
        };
        Self::new(RevocationListFields {
            serial,
            issued_at,
            entries,
        })
    }
}

impl core::fmt::Display for RevocationList {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// A list with the signature of the fleet's authorisation key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRevocationList {
    list: RevocationList,
    authorisation_signature: Signature,
}

impl SignedRevocationList {
    /// Binds a list to its signature.
    #[must_use]
    pub const fn new(list: RevocationList, authorisation_signature: Signature) -> Self {
        Self {
            list,
            authorisation_signature,
        }
    }

    /// Returns the list.
    ///
    /// Available before verification on purpose — a caller may want to report
    /// what a rejected document claimed — and useless for deciding anything:
    /// the decision is [`SignedRevocationList::verify`].
    #[must_use]
    pub const fn list(&self) -> &RevocationList {
        &self.list
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.authorisation_signature
    }

    /// Verifies the signature of the fleet's authorisation key.
    ///
    /// The key is the fleet's, not the organisation's: an organisation that
    /// could sign this document could publish a list without its own people in
    /// it, which is the one thing a revocation list must not permit.
    ///
    /// # Errors
    ///
    /// [`RevocationError::Canon`] when the list cannot be encoded and
    /// [`RevocationError::Signature`] when the signature does not hold or the
    /// authorisation key is not anchored.
    pub fn verify(&self, verifier: &impl SignatureVerifier) -> Result<(), RevocationError> {
        let message = self.list.encode()?;
        verifier
            .verify(
                SignerRef::AuthorisationKey,
                &message,
                &self.authorisation_signature,
            )
            .map_err(RevocationError::Signature)
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let [list, signature] = SIGNED_WIRE_KEYS;
        wire::render(
            SIGNED_REVOCATION_LIST_PREFIX,
            &[
                (list, hex::encode(self.list.to_wire())),
                (
                    signature,
                    hex::encode(self.authorisation_signature.as_bytes()),
                ),
            ],
        )
    }

    /// Parses the wire form.
    ///
    /// # Errors
    ///
    /// The [`RevocationError`] describing the first violation, including every
    /// way the list inside can fail to parse.
    pub fn parse(text: &str) -> Result<Self, RevocationError> {
        let values = wire::parse(text, SIGNED_REVOCATION_LIST_PREFIX, &SIGNED_WIRE_KEYS)?;
        let inner = wire::parse_hex("list", wire::value(&values, 0))?;
        let inner = String::from_utf8(inner)
            .map_err(|_| RevocationError::Wire(WireError::UnusableValue { field: "list" }))?;
        let list = RevocationList::parse(&inner)?;
        let signature = Signature::new(wire::parse_hex(
            "authorisation_signature",
            wire::value(&values, 1),
        )?)?;
        Ok(Self::new(list, signature))
    }
}

impl core::fmt::Display for SignedRevocationList {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Checks one part of an entry.
///
/// Stricter than a list item by one character: the part separator. A subject
/// identifier carrying it would split one entry into two, and the second would
/// name a withdrawal nobody published.
fn check_entry_part(field: &'static str, value: &str) -> Result<(), RevocationError> {
    wire::check_list_item(field, value)?;
    if value.contains(ENTRY_SEPARATOR) {
        return Err(RevocationError::SeparatorInEntry { field });
    }
    Ok(())
}

/// Rejection of a revocation list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RevocationError {
    /// The wire form is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// An entry is not four parts.
    #[error("the entry `{item}` is not a subject kind, an identifier, a moment and a reason")]
    MalformedEntry {
        /// The offending item, verbatim.
        item: String,
    },
    /// The subject kind is a word this document is not written with.
    #[error("`{token}` is not a subject a right can be withdrawn from")]
    UnknownSubjectKind {
        /// The offending token, verbatim.
        token: String,
    },
    /// A part of an entry carries the separator that divides them.
    #[error("the entry field `{field}` carries the separator between the parts of an entry")]
    SeparatorInEntry {
        /// Name of the offending field.
        field: &'static str,
    },
    /// One subject appears twice.
    #[error("the list withdraws the right of `{subject}` twice, and the two say different things")]
    RepeatedSubject {
        /// Identifier of the repeated subject.
        subject: String,
    },
    /// The list could not be encoded.
    #[error("the revocation list could not be encoded: {0}")]
    Canon(#[from] CanonError),
    /// The signature did not hold.
    #[error("the revocation list was not signed by the authorisation key of the fleet: {0}")]
    Signature(#[source] SignatureError),
}

impl From<SignatureError> for RevocationError {
    /// Wraps the material errors of a key or signature.
    fn from(error: SignatureError) -> Self {
        Self::Signature(error)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{
        RevocationEntry, RevocationError, RevocationList, RevocationListFields,
        SignedRevocationList, SubjectKind, NO_ENTRIES,
    };
    use crate::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
    use crate::time::ClaimedTime;
    use crate::wire::WireError;

    /// A verifier that accepts one message, and only from the authorisation key.
    ///
    /// The point of the fixture is the *signer*, not the arithmetic: what has to
    /// be impossible is a list an organisation signed being taken for one the
    /// fleet published.
    struct AuthorisationBound {
        accepted: Vec<u8>,
    }

    impl SignatureVerifier for AuthorisationBound {
        fn verify(
            &self,
            signer: SignerRef<'_>,
            message: &[u8],
            _signature: &Signature,
        ) -> Result<(), SignatureError> {
            match signer {
                SignerRef::AuthorisationKey if message == self.accepted => Ok(()),
                SignerRef::AuthorisationKey => Err(SignatureError::Rejected),
                _ => Err(SignatureError::UnknownSigner),
            }
        }
    }

    /// A consumer that anchors everything except the authorisation key.
    ///
    /// It stands for the fleet where the list arrived from an organisation, or
    /// from the web tier: whoever signed it, it was not the office that may.
    struct NoAuthorisationKey;

    impl SignatureVerifier for NoAuthorisationKey {
        fn verify(
            &self,
            _signer: SignerRef<'_>,
            _message: &[u8],
            _signature: &Signature,
        ) -> Result<(), SignatureError> {
            Err(SignatureError::UnknownSigner)
        }
    }

    fn entry(kind: SubjectKind, id: &str) -> RevocationEntry {
        RevocationEntry::new(kind, id, ClaimedTime::new(1_800_000_000), "left-the-fleet").unwrap()
    }

    fn list() -> RevocationList {
        RevocationList::new(RevocationListFields {
            serial: 7,
            issued_at: ClaimedTime::new(1_800_000_100),
            entries: vec![
                entry(SubjectKind::Engineer, "eng-1"),
                entry(SubjectKind::Organisation, "acme"),
            ],
        })
        .unwrap()
    }

    fn signed() -> SignedRevocationList {
        SignedRevocationList::new(list(), Signature::new(vec![0xab, 0xcd]).unwrap())
    }

    #[test]
    fn a_list_round_trips_through_the_wire_form() {
        let original = list();
        assert_eq!(RevocationList::parse(&original.to_wire()), Ok(original));

        let original = signed();
        assert_eq!(
            SignedRevocationList::parse(&original.to_wire()),
            Ok(original)
        );
    }

    #[test]
    fn a_list_that_withdraws_nothing_is_a_document_too() {
        // The statement a fleet with nobody cut off has to be able to make, and
        // make signed: an absent list and an empty one are the same thing to a
        // reader, and only one of them is signed.
        let empty = RevocationList::new(RevocationListFields {
            serial: 1,
            issued_at: ClaimedTime::new(1_800_000_000),
            entries: Vec::new(),
        })
        .unwrap();
        assert!(empty.to_wire().ends_with(&format!("entries={NO_ENTRIES}")));
        assert_eq!(RevocationList::parse(&empty.to_wire()), Ok(empty));
    }

    #[test]
    fn a_list_signed_by_anybody_but_the_authorisation_key_is_refused() {
        // The defect this document exists to close: an organisation, or the
        // web tier, publishing a list without its own people in it.
        let verifier = AuthorisationBound {
            accepted: list().encode().unwrap(),
        };
        assert_eq!(signed().verify(&verifier), Ok(()));
        assert!(matches!(
            signed().verify(&NoAuthorisationKey),
            Err(RevocationError::Signature(SignatureError::UnknownSigner))
        ));
    }

    #[test]
    fn a_list_edited_after_it_was_signed_does_not_verify() {
        // The signature covers the canonical bytes, so removing an entry moves
        // them. Byte-level proof rather than a claim: the verifier accepts one
        // message and this is a different one.
        let verifier = AuthorisationBound {
            accepted: list().encode().unwrap(),
        };
        let shortened = RevocationList::new(RevocationListFields {
            serial: 7,
            issued_at: ClaimedTime::new(1_800_000_100),
            entries: vec![entry(SubjectKind::Engineer, "eng-1")],
        })
        .unwrap();
        let forged =
            SignedRevocationList::new(shortened, Signature::new(vec![0xab, 0xcd]).unwrap());
        assert!(matches!(
            forged.verify(&verifier),
            Err(RevocationError::Signature(SignatureError::Rejected))
        ));
    }

    #[test]
    fn an_older_list_does_not_supersede_the_applied_one() {
        // A signature stops substitution, not replay: yesterday's list is
        // signed just as validly, and it is the one that still admits whoever
        // was cut off this morning.
        let list = list();
        assert!(list.is_newer_than(6));
        assert!(!list.is_newer_than(7));
        assert!(!list.is_newer_than(8));
    }

    #[test]
    fn one_subject_of_two_kinds_is_two_subjects() {
        // A fleet may number an organisation and a person alike; a reader that
        // matched on the identifier alone would cut off the wrong party.
        let list = RevocationList::new(RevocationListFields {
            serial: 1,
            issued_at: ClaimedTime::new(1_800_000_000),
            entries: vec![
                entry(SubjectKind::Engineer, "same"),
                entry(SubjectKind::Organisation, "same"),
            ],
        })
        .unwrap();
        assert!(list
            .withdrawal_of(SubjectKind::Engineer, "same")
            .is_some_and(|found| found.kind() == SubjectKind::Engineer));
        assert!(list
            .withdrawal_of(SubjectKind::Organisation, "same")
            .is_some_and(|found| found.kind() == SubjectKind::Organisation));
    }

    #[test]
    fn a_personal_number_is_withdrawn_however_it_is_spelled() {
        // The evasion this closes is chosen by the person being watched: type
        // the number with different separators, and a byte-wise lookup answers
        // "no withdrawal applies to you". Separators and case are not part of a
        // number, so both spellings are the same subject.
        let list = RevocationList::new(RevocationListFields {
            serial: 1,
            issued_at: ClaimedTime::new(1_800_000_000),
            entries: vec![entry(SubjectKind::Engineer, "ORG1-0000014")],
        })
        .unwrap();

        for spelling in [
            "ORG1-0000014",
            "org1 000001 4",
            "org1.0000014",
            "ORG10000014",
        ] {
            assert!(
                list.withdrawal_of(SubjectKind::Engineer, spelling)
                    .is_some(),
                "the withdrawal did not name {spelling}"
            );
        }
        // And a different number is still a different number.
        assert!(list
            .withdrawal_of(SubjectKind::Engineer, "ORG1-0000022")
            .is_none());
    }

    #[test]
    fn an_organisation_identifier_is_matched_by_its_bytes() {
        // It is a name a fleet assigns, not a number of this format. Folding it
        // the way a number is folded would make `acme-1` and `ACME 1` one
        // organisation, and a withdrawal would reach a party it never named.
        let list = RevocationList::new(RevocationListFields {
            serial: 1,
            issued_at: ClaimedTime::new(1_800_000_000),
            entries: vec![entry(SubjectKind::Organisation, "acme-1")],
        })
        .unwrap();
        assert!(list
            .withdrawal_of(SubjectKind::Organisation, "acme-1")
            .is_some());
        assert!(list
            .withdrawal_of(SubjectKind::Organisation, "ACME 1")
            .is_none());
    }

    #[test]
    fn one_subject_twice_is_refused() {
        let refused = RevocationList::new(RevocationListFields {
            serial: 1,
            issued_at: ClaimedTime::new(1_800_000_000),
            entries: vec![
                entry(SubjectKind::Engineer, "eng-1"),
                RevocationEntry::new(
                    SubjectKind::Engineer,
                    "eng-1",
                    ClaimedTime::new(1_800_000_500),
                    "another-reason",
                )
                .unwrap(),
            ],
        });
        assert_eq!(
            refused.map(|_| ()),
            Err(RevocationError::RepeatedSubject {
                subject: "eng-1".to_owned()
            })
        );
    }

    #[test]
    fn one_engineer_twice_under_different_spellings_is_refused() {
        let refused = RevocationList::new(RevocationListFields {
            serial: 1,
            issued_at: ClaimedTime::new(1_800_000_000),
            entries: vec![
                entry(SubjectKind::Engineer, "ORG1-0000014"),
                entry(SubjectKind::Engineer, "org1 000001 4"),
            ],
        });

        assert_eq!(
            refused.map(|_| ()),
            Err(RevocationError::RepeatedSubject {
                subject: "org1 000001 4".to_owned()
            })
        );
    }

    #[test]
    fn an_identifier_carrying_the_entry_separator_is_refused() {
        // Otherwise one entry reads as two, and the second names a withdrawal
        // nobody published.
        assert_eq!(
            RevocationEntry::new(
                SubjectKind::Engineer,
                "eng:1",
                ClaimedTime::new(1_800_000_000),
                "left-the-fleet",
            )
            .map(|_| ()),
            Err(RevocationError::SeparatorInEntry {
                field: "subject_id"
            })
        );
    }

    #[test]
    fn an_unknown_reason_is_carried_rather_than_refused() {
        // Refusing the list over a word this build does not know would fail
        // open on every entry in it, including the ones it reads perfectly.
        let list = RevocationList::new(RevocationListFields {
            serial: 1,
            issued_at: ClaimedTime::new(1_800_000_000),
            entries: vec![RevocationEntry::new(
                SubjectKind::Engineer,
                "eng-1",
                ClaimedTime::new(1_800_000_000),
                "a-reason-from-a-later-build",
            )
            .unwrap()],
        })
        .unwrap();
        let parsed = RevocationList::parse(&list.to_wire()).unwrap();
        assert_eq!(
            parsed.entries().first().unwrap().reason(),
            "a-reason-from-a-later-build"
        );
    }

    #[test]
    fn a_subject_kind_nobody_writes_is_refused() {
        let text = list().to_wire().replace("engineer:eng-1", "device:eng-1");
        assert_eq!(
            RevocationList::parse(&text).map(|_| ()),
            Err(RevocationError::UnknownSubjectKind {
                token: "device".to_owned()
            })
        );
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let text = format!("{};extra=1", list().to_wire());
        assert!(matches!(
            RevocationList::parse(&text),
            Err(RevocationError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn an_unsigned_list_offered_where_a_signed_one_is_expected_is_refused() {
        assert!(SignedRevocationList::parse(&list().to_wire()).is_err());
        assert!(RevocationList::parse(&signed().to_wire()).is_err());
    }
}

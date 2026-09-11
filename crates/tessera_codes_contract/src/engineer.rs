//! The engineer: who they are, and what they are allowed to ask for.
//!
//! Two documents, deliberately apart:
//!
//! - the **registry record** says a person exists and holds a key. It changes
//!   when a person joins or their key is replaced — rarely, and by the
//!   organisation;
//! - the **authorisation** says what that person may ask for, within which
//!   bounds and until when. It changes often, and it is the thing a fleet
//!   narrows in a hurry.
//!
//! Keeping them in one document would tie the two together: narrowing what
//! somebody may do would mean re-issuing the statement that they exist, and the
//! natural shortcut — editing the bounds in place — would be indistinguishable
//! from an attacker doing the same. Two documents, two signatures, two
//! lifetimes.
//!
//! # Neither of them says the authorisation is still standing
//!
//! An authorisation carries a term, and a term is not freshness: a person
//! suspended this morning holds an authorisation that is still inside its term.
//! What answers that question is the status-token ([`crate::status`]), signed by
//! a service whose only job is to answer it, and the consumer is required to
//! check the token **before** it uses the authorisation for anything. This
//! module cannot enforce that ordering — it holds no clock and no service — so
//! it states it here and in the documentation of [`EngineerAuthorisation`].

use crate::canon::{CanonError, Encoder, Level};
use crate::mac::{sha256, DIGEST_LEN};
use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::time::ClaimedTime;
use crate::wire::{self, WireError};

/// Marker that opens the wire form of an engineer record.
pub const ENGINEER_RECORD_PREFIX: &str = "tessera-codes/v1/engineer-record";

/// Marker that opens the wire form of an engineer authorisation.
pub const AUTHORISATION_PREFIX: &str = "tessera-codes/v1/engineer-authorisation";

/// Number of fields an engineer record carries.
pub const ENGINEER_RECORD_FIELD_COUNT: usize = 5;

/// Number of fields an authorisation carries.
pub const AUTHORISATION_FIELD_COUNT: usize = 8;

/// Field keys of the record, in the only order the parser accepts.
const RECORD_KEYS: [&str; ENGINEER_RECORD_FIELD_COUNT] = [
    "engineer",
    "key",
    "organisation",
    "organisation_signature",
    "possession_signature",
];

/// Field keys of the authorisation, in the only order the parser accepts.
const AUTHORISATION_KEYS: [&str; AUTHORISATION_FIELD_COUNT] = [
    "engineer",
    "organisation",
    "key_fingerprint",
    "tags",
    "roles",
    "max_level",
    "not_after",
    "authorisation_signature",
];

/// Label of the proof of possession of an engineer key.
const POSSESSION_LABEL: &str = "tessera-codes-contract/v1/engineer-possession";

/// Label of the organisation signature over an engineer record.
const RECORD_LABEL: &str = "tessera-codes-contract/v1/engineer-record";

/// Label of the organisation signature over an authorisation.
const AUTHORISATION_LABEL: &str = "tessera-codes-contract/v1/engineer-authorisation";

/// Marker standing for "every role of the fleet" in the list of roles.
///
/// The same marker the server ticket uses, and for the same reason: a role
/// account of an operating system cannot be named `*`, so the marker cannot
/// collide with a real role, and "may ask for anything" stays visible in the
/// document instead of being expressed by an empty list.
pub const ALL_ROLES: &str = "*";

/// Separator between the marker of an absent authenticator and its reason.
const ABSENT_SEPARATOR: char = ':';

/// Marker of a record that carries an authenticator.
const AUTHENTICATOR_PRESENT: &str = "present";

/// Marker of a record that states there is no authenticator.
const AUTHENTICATOR_ABSENT: &str = "unverified";

/// The authenticator of an engineer — or the statement that there is none.
///
/// # Why this is one type and not two fields
///
/// A key without a proof of possession is the hole this document exists to
/// close: an organisation could register somebody else's public key as an
/// engineer's, and every request signed with the matching private half would be
/// attributed to that engineer. Held as two fields, that state is expressible,
/// and what is expressible eventually gets expressed. Held like this, it is not.
///
/// # Why the absence is a variant and not an empty key
///
/// Because a fleet in the middle of its rollout has engineers whose identity
/// nothing vouches for, and the two cases must not read alike. An empty key, a
/// key of zeros, or a placeholder from a stub provider all parse as "a key" to
/// the next reader, and the report an auditor sees then says an identity was
/// checked where nothing checked it. The absence carries its reason for the
/// same reason: a year later, "there was never a provider" and "the provider
/// was there and failed" send an auditor to different places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatorKey {
    /// The engineer holds a key, and proved it.
    Present {
        /// The public half the engineer signs with.
        key: PublicKey,
        /// The signature that proves the private half is theirs.
        possession: Signature,
    },
    /// Nothing vouches for this engineer's identity, and this says why.
    Absent {
        /// Why there is no authenticator — a stub provider in an MVP, a
        /// rollout that has not reached this person, a factor withdrawn.
        reason: String,
    },
}

impl AuthenticatorKey {
    /// States that an engineer has no authenticator, and why.
    ///
    /// # Errors
    ///
    /// The wire errors when the reason is empty or carries a character the
    /// format cannot hold, and [`EngineerError::ReasonSeparator`] when it
    /// carries the separator that divides the marker from the reason.
    pub fn absent(reason: &str) -> Result<Self, EngineerError> {
        wire::check_free_text("authenticator_reason", reason)?;
        if reason.contains(ABSENT_SEPARATOR) {
            return Err(EngineerError::ReasonSeparator);
        }
        Ok(Self::Absent {
            reason: reason.to_owned(),
        })
    }

    /// Reads the pair of wire fields the two cases share.
    ///
    /// # Errors
    ///
    /// [`EngineerError::HalfAnAuthenticator`] when one field states a key and
    /// the other states none — a document that says both things about one
    /// person — and the material errors of a key or a signature.
    fn parse(key: &str, possession: &str) -> Result<Self, EngineerError> {
        let absent_key = key
            .strip_prefix(AUTHENTICATOR_ABSENT)
            .and_then(|rest| rest.strip_prefix(ABSENT_SEPARATOR));
        match (absent_key, possession == AUTHENTICATOR_ABSENT) {
            (Some(reason), true) => Self::absent(reason),
            (None, false) => Ok(Self::Present {
                key: PublicKey::new(wire::parse_hex("key", key)?)?,
                possession: Signature::new(wire::parse_hex("possession_signature", possession)?)?,
            }),
            _ => Err(EngineerError::HalfAnAuthenticator),
        }
    }
}

/// A person as the organisation registered them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineerRecord {
    engineer_id: String,
    authenticator_key: AuthenticatorKey,
    organisation_id: String,
    organisation_signature: Signature,
}

impl EngineerRecord {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when an identifier is empty or carries a
    /// character the format cannot hold.
    pub fn new(
        engineer_id: &str,
        authenticator_key: AuthenticatorKey,
        organisation_id: &str,
        organisation_signature: Signature,
    ) -> Result<Self, EngineerError> {
        wire::check_free_text("engineer", engineer_id)?;
        wire::check_free_text("organisation", organisation_id)?;
        Ok(Self {
            engineer_id: engineer_id.to_owned(),
            authenticator_key,
            organisation_id: organisation_id.to_owned(),
            organisation_signature,
        })
    }

    /// Returns the personal number of the engineer.
    #[must_use]
    pub fn engineer_id(&self) -> &str {
        &self.engineer_id
    }

    /// Returns the authenticator of the engineer, present or explicitly not.
    #[must_use]
    pub const fn authenticator_key(&self) -> &AuthenticatorKey {
        &self.authenticator_key
    }

    /// Reports whether this record vouches for a key the engineer holds.
    ///
    /// The question every consumer of a record actually asks, answered in one
    /// place so that nobody answers it by looking at a field and guessing.
    #[must_use]
    pub const fn identity_is_verified(&self) -> bool {
        matches!(self.authenticator_key, AuthenticatorKey::Present { .. })
    }

    /// Returns the organisation that registered the engineer.
    #[must_use]
    pub fn organisation_id(&self) -> &str {
        &self.organisation_id
    }

    /// Returns the signature of the organisation.
    #[must_use]
    pub const fn organisation_signature(&self) -> &Signature {
        &self.organisation_signature
    }

    /// Returns the proof of possession, when the record carries a key at all.
    #[must_use]
    pub const fn possession_signature(&self) -> Option<&Signature> {
        match &self.authenticator_key {
            AuthenticatorKey::Present { possession, .. } => Some(possession),
            AuthenticatorKey::Absent { .. } => None,
        }
    }

    /// Returns the fingerprint of the authenticator key, when there is one.
    ///
    /// What an authorisation and a status-token name the key by: a fingerprint
    /// travels where a key would be unwieldy, and the two documents must agree
    /// on how it is taken. Here is where that is decided, once.
    ///
    /// `None` for a record that states no key. A zero fingerprint, or one taken
    /// of a placeholder, would let an authorisation bind to a key nobody holds
    /// and read afterwards exactly like one that binds to a key somebody does.
    #[must_use]
    pub fn key_fingerprint(&self) -> Option<[u8; DIGEST_LEN]> {
        match &self.authenticator_key {
            AuthenticatorKey::Present { key, .. } => Some(sha256(key.as_bytes())),
            AuthenticatorKey::Absent { .. } => None,
        }
    }

    /// Encodes the body both signatures are taken over.
    ///
    /// The absent case is encoded as itself — the marker and the reason — and
    /// not as an empty key. An organisation signing a record with no key signs
    /// the statement "this person has no authenticator, because …", and that
    /// statement is what a reader gets to check afterwards.
    fn body(&self, encoder: &mut Encoder) -> Result<(), CanonError> {
        encoder.push_text("engineer_id", &self.engineer_id)?;
        match &self.authenticator_key {
            AuthenticatorKey::Present { key, .. } => {
                encoder.push_text("authenticator", AUTHENTICATOR_PRESENT)?;
                encoder.push_bytes("authenticator_key", key.as_bytes())?;
            }
            AuthenticatorKey::Absent { reason } => {
                encoder.push_text("authenticator", AUTHENTICATOR_ABSENT)?;
                encoder.push_text("authenticator_reason", reason)?;
            }
        }
        encoder.push_text("organisation_id", &self.organisation_id)?;
        Ok(())
    }

    /// Encodes the message the organisation signs.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn organisation_message(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("label", RECORD_LABEL)?;
        self.body(&mut encoder)?;
        Ok(encoder.finish())
    }

    /// Encodes the message the engineer signs to prove possession of the key.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn possession_message(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("label", POSSESSION_LABEL)?;
        self.body(&mut encoder)?;
        Ok(encoder.finish())
    }

    /// Verifies both signatures.
    ///
    /// Both are required and neither implies the other: the organisation
    /// signature says the fleet accepted this person with this key, and the
    /// proof of possession says the key is one they actually hold. Without the
    /// second, an organisation can register somebody else's public key as an
    /// engineer's — and every request signed with the matching private half
    /// would then be attributed to that engineer.
    ///
    /// # Errors
    ///
    /// [`EngineerError::Canon`] when the record cannot be encoded,
    /// [`EngineerError::OrganisationSignature`] and
    /// [`EngineerError::PossessionSignature`] when the respective signature
    /// does not hold or its signer is not anchored.
    pub fn verify(&self, verifier: &impl SignatureVerifier) -> Result<(), EngineerError> {
        verifier
            .verify(
                SignerRef::Named(&self.organisation_id),
                &self.organisation_message()?,
                &self.organisation_signature,
            )
            .map_err(EngineerError::OrganisationSignature)?;
        // A proof of possession exists only where a key does. A record that
        // states no authenticator is verified when the organisation signed that
        // statement — and it is still a record of somebody whose identity
        // nothing here vouches for, which is what
        // [`EngineerRecord::identity_is_verified`] is for and what the journal
        // of an issuance carries as its own field.
        if let AuthenticatorKey::Present { key, possession } = &self.authenticator_key {
            verifier
                .verify(SignerRef::Key(key), &self.possession_message()?, possession)
                .map_err(EngineerError::PossessionSignature)?;
        }
        Ok(())
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let (key, possession) = match &self.authenticator_key {
            AuthenticatorKey::Present { key, possession } => (
                hex::encode(key.as_bytes()),
                hex::encode(possession.as_bytes()),
            ),
            // The marker carries the reason with it, so a reader that sees no
            // key also sees why there is none. Hexadecimal never contains the
            // separator, so the two cases are told apart by the parser rather
            // than by a length or a guess.
            AuthenticatorKey::Absent { reason } => (
                format!("{AUTHENTICATOR_ABSENT}{ABSENT_SEPARATOR}{reason}"),
                AUTHENTICATOR_ABSENT.to_owned(),
            ),
        };
        let fields = [
            ("engineer", self.engineer_id.clone()),
            ("key", key),
            ("organisation", self.organisation_id.clone()),
            (
                "organisation_signature",
                hex::encode(self.organisation_signature.as_bytes()),
            ),
            ("possession_signature", possession),
        ];
        wire::render(ENGINEER_RECORD_PREFIX, &fields)
    }

    /// Parses the wire form.
    ///
    /// # Errors
    ///
    /// The [`EngineerError`] describing the first violation: a wrong prefix, a
    /// field unknown, missing or out of order, an empty value, or material the
    /// target type cannot hold.
    pub fn parse(text: &str) -> Result<Self, EngineerError> {
        let values = wire::parse(text, ENGINEER_RECORD_PREFIX, &RECORD_KEYS)?;
        let authenticator_key =
            AuthenticatorKey::parse(wire::value(&values, 1), wire::value(&values, 4))?;
        Self::new(
            wire::value(&values, 0),
            authenticator_key,
            wire::value(&values, 2),
            Signature::new(wire::parse_hex(
                "organisation_signature",
                wire::value(&values, 3),
            )?)?,
        )
    }
}

impl core::fmt::Display for EngineerRecord {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// The values an authorisation is assembled from.
#[derive(Debug)]
pub struct AuthorisationFields<'a> {
    /// Personal number of the engineer.
    pub engineer_id: &'a str,
    /// Organisation that granted the authorisation.
    pub organisation_id: &'a str,
    /// Fingerprint of the authenticator key it is granted to.
    pub key_fingerprint: [u8; DIGEST_LEN],
    /// Site tags the engineer may work at. At least one.
    pub tags: Vec<String>,
    /// Roles the engineer may ask for, or the marker [`ALL_ROLES`].
    pub roles: Vec<String>,
    /// Highest level the engineer may ask for.
    pub max_level: Level,
    /// When the authorisation stops.
    pub not_after: ClaimedTime,
    /// Signature of the fleet's authorisation key over the authorisation.
    pub authorisation_signature: Signature,
}

/// What an engineer may ask for, and until when.
///
/// # This document is not freshness
///
/// The term says when the authorisation stops being valid at the latest. It
/// says nothing about whether it was withdrawn this morning. A consumer must
/// check the status-token ([`crate::status`]) **before** using an authorisation
/// for anything — the specification puts it plainly, and the ordering is the
/// consumer's to enforce because the token comes from a service this crate
/// knows nothing about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineerAuthorisation {
    engineer_id: String,
    organisation_id: String,
    key_fingerprint: [u8; DIGEST_LEN],
    tags: Vec<String>,
    roles: Vec<String>,
    max_level: Level,
    not_after: ClaimedTime,
    authorisation_signature: Signature,
}

impl EngineerAuthorisation {
    /// Assembles an authorisation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineerError::NoTags`] and [`EngineerError::NoRoles`] when a
    /// bound is empty — an authorisation that names no site or no role is not a
    /// narrower authorisation, it is one nobody can read — and
    /// [`EngineerError::MarkerBesideNames`] when the marker for "every role"
    /// travels beside a named role, which is two different statements in one
    /// list. The wire errors follow for an item the format cannot hold.
    pub fn new(fields: AuthorisationFields<'_>) -> Result<Self, EngineerError> {
        wire::check_free_text("engineer", fields.engineer_id)?;
        wire::check_free_text("organisation", fields.organisation_id)?;
        if fields.tags.is_empty() {
            return Err(EngineerError::NoTags);
        }
        if fields.roles.is_empty() {
            return Err(EngineerError::NoRoles);
        }
        for tag in &fields.tags {
            wire::check_list_item("tags", tag)?;
        }
        for role in &fields.roles {
            wire::check_list_item("roles", role)?;
        }
        if fields.roles.iter().any(|role| role == ALL_ROLES) && fields.roles.len() > 1 {
            return Err(EngineerError::MarkerBesideNames);
        }
        Ok(Self {
            engineer_id: fields.engineer_id.to_owned(),
            organisation_id: fields.organisation_id.to_owned(),
            key_fingerprint: fields.key_fingerprint,
            tags: fields.tags,
            roles: fields.roles,
            max_level: fields.max_level,
            not_after: fields.not_after,
            authorisation_signature: fields.authorisation_signature,
        })
    }

    /// Returns the personal number of the engineer.
    #[must_use]
    pub fn engineer_id(&self) -> &str {
        &self.engineer_id
    }

    /// Returns the organisation that granted the authorisation.
    #[must_use]
    pub fn organisation_id(&self) -> &str {
        &self.organisation_id
    }

    /// Returns the fingerprint of the key this authorisation is granted to.
    #[must_use]
    pub const fn key_fingerprint(&self) -> &[u8; DIGEST_LEN] {
        &self.key_fingerprint
    }

    /// Returns the site tags.
    #[must_use]
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Returns the roles, or the single marker for all of them.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns the highest level the engineer may ask for.
    #[must_use]
    pub const fn max_level(&self) -> Level {
        self.max_level
    }

    /// Returns the moment the authorisation stops.
    #[must_use]
    pub const fn not_after(&self) -> ClaimedTime {
        self.not_after
    }

    /// Returns the signature of the fleet's authorisation key.
    #[must_use]
    pub const fn authorisation_signature(&self) -> &Signature {
        &self.authorisation_signature
    }

    /// Reports whether the authorisation covers `role`.
    #[must_use]
    pub fn covers_role(&self, role: &str) -> bool {
        self.roles
            .iter()
            .any(|named| named == ALL_ROLES || named == role)
    }

    /// Reports whether the authorisation covers `tag`.
    #[must_use]
    pub fn covers_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|named| named == tag)
    }

    /// Reports whether the term still holds at `now`.
    ///
    /// Not freshness — see the type documentation.
    #[must_use]
    pub const fn within_term(&self, now: ClaimedTime) -> bool {
        now.get() <= self.not_after.get()
    }

    /// Returns the digest of the authorisation.
    ///
    /// What a status-token is bound to: an answer about "this authorisation"
    /// has to name which one, and a digest names it without carrying it.
    ///
    /// # Errors
    ///
    /// The errors of the canonical encoding.
    pub fn digest(&self) -> Result<[u8; DIGEST_LEN], CanonError> {
        Ok(sha256(&self.encode()?))
    }

    /// Encodes the message the authorisation key signs.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("label", AUTHORISATION_LABEL)?;
        encoder.push_text("engineer_id", &self.engineer_id)?;
        encoder.push_text("organisation_id", &self.organisation_id)?;
        encoder.push_bytes("key_fingerprint", &self.key_fingerprint)?;
        push_list(&mut encoder, "tags", &self.tags)?;
        push_list(&mut encoder, "roles", &self.roles)?;
        encoder.push_u32("max_level", self.max_level.get())?;
        encoder.push_u64("not_after", self.not_after.get())?;
        Ok(encoder.finish())
    }

    /// Verifies the signature of the fleet's authorisation key.
    ///
    /// **Not the organisation's.** The organisation is named in the document
    /// and its ceiling comes from its certificate, not from its signature: an
    /// organisation that could sign this would be granting its own people
    /// whatever it liked, and the ceiling the fleet set for it would be a
    /// suggestion. The office that signs authorisations is a separate key under
    /// the fleet root, held apart from the organisations and from the key that
    /// signs grants.
    ///
    /// # Errors
    ///
    /// [`EngineerError::Canon`] when the authorisation cannot be encoded and
    /// [`EngineerError::AuthorisationSignature`] when the signature does not
    /// hold or the authorisation key is not anchored.
    pub fn verify(&self, verifier: &impl SignatureVerifier) -> Result<(), EngineerError> {
        verifier
            .verify(
                SignerRef::AuthorisationKey,
                &self.encode()?,
                &self.authorisation_signature,
            )
            .map_err(EngineerError::AuthorisationSignature)
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let fields = [
            ("engineer", self.engineer_id.clone()),
            ("organisation", self.organisation_id.clone()),
            ("key_fingerprint", hex::encode(self.key_fingerprint)),
            ("tags", self.tags.join(",")),
            ("roles", self.roles.join(",")),
            ("max_level", self.max_level.get().to_string()),
            ("not_after", self.not_after.get().to_string()),
            (
                "authorisation_signature",
                hex::encode(self.authorisation_signature.as_bytes()),
            ),
        ];
        wire::render(AUTHORISATION_PREFIX, &fields)
    }

    /// Parses the wire form.
    ///
    /// # Errors
    ///
    /// The [`EngineerError`] describing the first violation: a wrong prefix, a
    /// field unknown, missing or out of order, an empty value, a fingerprint of
    /// the wrong width, an empty bound, or the marker beside a named role.
    pub fn parse(text: &str) -> Result<Self, EngineerError> {
        let values = wire::parse(text, AUTHORISATION_PREFIX, &AUTHORISATION_KEYS)?;
        let fingerprint_bytes = wire::parse_hex("key_fingerprint", wire::value(&values, 2))?;
        let key_fingerprint: [u8; DIGEST_LEN] =
            fingerprint_bytes
                .as_slice()
                .try_into()
                .map_err(|_| EngineerError::DigestWidth {
                    field: "key_fingerprint",
                    got: fingerprint_bytes.len(),
                })?;

        Self::new(AuthorisationFields {
            engineer_id: wire::value(&values, 0),
            organisation_id: wire::value(&values, 1),
            key_fingerprint,
            tags: split_list(wire::value(&values, 3)),
            roles: split_list(wire::value(&values, 4)),
            max_level: Level::new(wire::parse_u32("max_level", wire::value(&values, 5))?),
            not_after: ClaimedTime::new(wire::parse_u64("not_after", wire::value(&values, 6))?),
            authorisation_signature: Signature::new(wire::parse_hex(
                "authorisation_signature",
                wire::value(&values, 7),
            )?)?,
        })
    }
}

impl core::fmt::Display for EngineerAuthorisation {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Splits a comma-separated list of the wire form.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Encodes a list with its length in front of it.
///
/// Every item is length-prefixed as well, so the count is not what keeps two
/// lists apart — that is already impossible. What it buys is a byte string that
/// says how many items there are instead of leaving it to be inferred from
/// where the next field begins.
fn push_list(
    encoder: &mut Encoder,
    field: &'static str,
    items: &[String],
) -> Result<(), CanonError> {
    let count = u32::try_from(items.len()).map_err(|_| CanonError::FieldTooLong { field })?;
    encoder.push_u32(field, count)?;
    for item in items {
        encoder.push_text(field, item)?;
    }
    Ok(())
}

/// Rejection of an engineer document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineerError {
    /// The authorisation names no site tag.
    #[error("the authorisation names no site tag")]
    NoTags,
    /// The authorisation names no role.
    #[error("the authorisation names no role")]
    NoRoles,
    /// The marker for every role travels beside a named role.
    #[error("the marker for every role cannot travel beside a named role")]
    MarkerBesideNames,
    /// A digest field is not the width of a digest.
    #[error(
        "the field `{field}` is {got} bytes where the format has {}",
        DIGEST_LEN
    )]
    DigestWidth {
        /// Name of the offending field.
        field: &'static str,
        /// Width that was offered.
        got: usize,
    },
    /// The wire form is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The document cannot be encoded canonically.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// A key or signature carries no material.
    #[error(transparent)]
    Material(#[from] SignatureError),
    /// The organisation signature was rejected.
    ///
    /// The registry record of an engineer: that one an organisation does sign,
    /// because it is a statement about its own people. An authorisation is not
    /// — see [`EngineerError::AuthorisationSignature`].
    #[error("the organisation signature was rejected: {0}")]
    OrganisationSignature(SignatureError),
    /// The signature of the fleet's authorisation key was rejected.
    #[error("the authorisation was not signed by the authorisation key of the fleet: {0}")]
    AuthorisationSignature(SignatureError),
    /// The reason of an absent authenticator carries the separator that divides
    /// it from the marker.
    #[error("the reason for an absent authenticator carries the separator `:`")]
    ReasonSeparator,
    /// One field states a key and the other states there is none.
    #[error(
        "the record states a key and states there is none: a document that says both things \
         about one person is not a record of either"
    )]
    HalfAnAuthenticator,
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
    use super::{
        AuthenticatorKey, AuthorisationFields, EngineerAuthorisation, EngineerError,
        EngineerRecord, ALL_ROLES, AUTHORISATION_PREFIX, ENGINEER_RECORD_PREFIX,
    };
    use crate::canon::Level;
    use crate::signature::{PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef};
    use crate::time::ClaimedTime;
    use crate::wire::WireError;

    /// A verifier bound to the two messages of a record, so a test can tell
    /// them apart the way a real one would.
    struct MessageBound {
        organisation: Vec<u8>,
        possession: Vec<u8>,
    }

    impl SignatureVerifier for MessageBound {
        fn verify(
            &self,
            signer: SignerRef<'_>,
            message: &[u8],
            _signature: &Signature,
        ) -> Result<(), SignatureError> {
            let expected = match signer {
                SignerRef::Named(_) => &self.organisation,
                SignerRef::Key(_) => &self.possession,
                SignerRef::TicketAuthority | SignerRef::AuthorisationKey => {
                    return Err(SignatureError::UnknownSigner)
                }
            };
            if message == expected.as_slice() {
                Ok(())
            } else {
                Err(SignatureError::Rejected)
            }
        }
    }

    fn record() -> EngineerRecord {
        EngineerRecord::new(
            "eng-7",
            AuthenticatorKey::Present {
                key: PublicKey::new(vec![0x04, 0xaa, 0xbb]).unwrap(),
                possession: Signature::new(vec![0x02]).unwrap(),
            },
            "acme",
            Signature::new(vec![0x01]).unwrap(),
        )
        .unwrap()
    }

    fn authorisation() -> EngineerAuthorisation {
        EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: "eng-7",
            organisation_id: "acme",
            key_fingerprint: record().key_fingerprint().unwrap(),
            tags: vec!["dc-1".to_owned(), "hq".to_owned()],
            roles: vec!["ops.dc.senior".to_owned()],
            max_level: Level::new(2),
            not_after: ClaimedTime::new(1_800_000_000),
            authorisation_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn a_record_round_trips_through_the_wire_form() {
        let original = record();
        assert_eq!(EngineerRecord::parse(&original.to_wire()), Ok(original));
    }

    #[test]
    fn both_signatures_of_a_record_are_checked_over_different_bytes() {
        let record = record();
        let verifier = MessageBound {
            organisation: record.organisation_message().unwrap(),
            possession: record.possession_message().unwrap(),
        };
        assert_ne!(verifier.organisation, verifier.possession);
        assert_eq!(record.verify(&verifier), Ok(()));

        // The proof of possession alone is not the organisation's acceptance.
        let swapped = MessageBound {
            organisation: record.possession_message().unwrap(),
            possession: record.organisation_message().unwrap(),
        };
        assert!(matches!(
            record.verify(&swapped),
            Err(EngineerError::OrganisationSignature(_))
        ));
    }

    #[test]
    fn the_fingerprint_is_taken_of_the_key_and_agrees_with_the_authorisation() {
        // One decision about how a key is named, in one place: an authorisation
        // that computed it differently would name a key nobody holds.
        assert_eq!(
            record().key_fingerprint().as_ref(),
            Some(authorisation().key_fingerprint())
        );
    }

    /// A verifier that holds the fleet's authorisation key and the
    /// organisations, and never confuses the two.
    ///
    /// The fixture exists for one question, and it is the question this
    /// document changed: WHICH key vouches for what an engineer may ask for.
    struct OfficeBound {
        /// The bytes the authorisation key is willing to have signed.
        authorisation: Vec<u8>,
    }

    impl SignatureVerifier for OfficeBound {
        fn verify(
            &self,
            signer: SignerRef<'_>,
            message: &[u8],
            _signature: &Signature,
        ) -> Result<(), SignatureError> {
            match signer {
                SignerRef::AuthorisationKey if message == self.authorisation.as_slice() => Ok(()),
                SignerRef::AuthorisationKey => Err(SignatureError::Rejected),
                // An organisation is anchored — the fixture stands for a fleet
                // that trusts it for what it may sign — and it is still not the
                // office that grants authorisations.
                SignerRef::Named(_) | SignerRef::Key(_) | SignerRef::TicketAuthority => {
                    Err(SignatureError::UnknownSigner)
                }
            }
        }
    }

    #[test]
    fn an_authorisation_is_vouched_for_by_the_fleet_and_not_by_the_organisation() {
        // The defect this rename closes: while the authorisation was verified
        // against the organisation that granted it, an organisation could write
        // its own people any ceiling it liked, and the ceiling the fleet set for
        // it in its certificate was a suggestion.
        let authorisation = authorisation();
        let office = OfficeBound {
            authorisation: authorisation.encode().unwrap(),
        };
        assert_eq!(authorisation.verify(&office), Ok(()));

        // The same document offered to a fleet that anchors organisations and
        // no authorisation key: nobody who may sign this has signed it.
        let organisations_only = MessageBound {
            organisation: authorisation.encode().unwrap(),
            possession: Vec::new(),
        };
        assert!(matches!(
            authorisation.verify(&organisations_only),
            Err(EngineerError::AuthorisationSignature(
                SignatureError::UnknownSigner
            ))
        ));
    }

    #[test]
    fn an_authorisation_edited_after_it_was_signed_does_not_verify() {
        // The signature covers the canonical bytes, so raising the ceiling
        // moves them. Without this the rename would be a rename and nothing
        // more.
        let signed = authorisation();
        let office = OfficeBound {
            authorisation: signed.encode().unwrap(),
        };
        let raised = EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: "eng-7",
            organisation_id: "acme",
            key_fingerprint: record().key_fingerprint().unwrap(),
            tags: vec!["dc-1".to_owned(), "hq".to_owned()],
            roles: vec!["ops.dc.senior".to_owned()],
            max_level: Level::new(3),
            not_after: ClaimedTime::new(1_800_000_000),
            authorisation_signature: signed.authorisation_signature().clone(),
        })
        .unwrap();
        assert!(matches!(
            raised.verify(&office),
            Err(EngineerError::AuthorisationSignature(
                SignatureError::Rejected
            ))
        ));
    }

    #[test]
    fn the_registry_record_is_still_the_organisations_to_sign() {
        // The other half of the rule, and the reason this is a rename of one
        // document and not of two: who a person is inside an organisation is
        // the organisation's statement; what they may ask for is not.
        let record = record();
        let verifier = MessageBound {
            organisation: record.organisation_message().unwrap(),
            possession: record.possession_message().unwrap(),
        };
        assert_eq!(record.verify(&verifier), Ok(()));
    }

    #[test]
    fn an_authorisation_round_trips_through_the_wire_form() {
        let original = authorisation();
        assert_eq!(
            EngineerAuthorisation::parse(&original.to_wire()),
            Ok(original)
        );
    }

    #[test]
    fn an_authorisation_covers_what_it_names_and_nothing_else() {
        let authorisation = authorisation();
        assert!(authorisation.covers_role("ops.dc.senior"));
        assert!(!authorisation.covers_role("ops.dc.root"));
        assert!(authorisation.covers_tag("dc-1"));
        assert!(!authorisation.covers_tag("dc-2"));
        assert!(authorisation.within_term(ClaimedTime::new(1_800_000_000)));
        assert!(!authorisation.within_term(ClaimedTime::new(1_800_000_001)));
    }

    #[test]
    fn the_marker_covers_every_role_and_cannot_stand_beside_a_name() {
        let all = EngineerAuthorisation::new(AuthorisationFields {
            roles: vec![ALL_ROLES.to_owned()],
            ..AuthorisationFields {
                engineer_id: "eng-7",
                organisation_id: "acme",
                key_fingerprint: [0x11; 32],
                tags: vec!["dc-1".to_owned()],
                roles: vec![ALL_ROLES.to_owned()],
                max_level: Level::new(2),
                not_after: ClaimedTime::new(1_800_000_000),
                authorisation_signature: Signature::new(vec![0x03]).unwrap(),
            }
        })
        .unwrap();
        assert!(all.covers_role("anything.at.all"));

        let mixed = EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: "eng-7",
            organisation_id: "acme",
            key_fingerprint: [0x11; 32],
            tags: vec!["dc-1".to_owned()],
            roles: vec![ALL_ROLES.to_owned(), "ops.dc.senior".to_owned()],
            max_level: Level::new(2),
            not_after: ClaimedTime::new(1_800_000_000),
            authorisation_signature: Signature::new(vec![0x03]).unwrap(),
        });
        assert_eq!(mixed, Err(EngineerError::MarkerBesideNames));
    }

    #[test]
    fn an_authorisation_with_an_empty_bound_does_not_assemble_or_parse() {
        let no_roles = EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: "eng-7",
            organisation_id: "acme",
            key_fingerprint: [0x11; 32],
            tags: vec!["dc-1".to_owned()],
            roles: Vec::new(),
            max_level: Level::new(2),
            not_after: ClaimedTime::new(1_800_000_000),
            authorisation_signature: Signature::new(vec![0x03]).unwrap(),
        });
        assert_eq!(no_roles, Err(EngineerError::NoRoles));

        let text = authorisation()
            .to_wire()
            .replace("roles=ops.dc.senior", "roles=");
        assert!(matches!(
            EngineerAuthorisation::parse(&text),
            Err(EngineerError::Wire(WireError::EmptyValue {
                field: "roles"
            }))
        ));
    }

    #[test]
    fn every_bound_is_part_of_what_the_organisation_signs() {
        // Narrowing an authorisation means signing a new one; editing the
        // bounds of an old one must move the bytes.
        let base = authorisation().encode().unwrap();
        let wider = EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: "eng-7",
            organisation_id: "acme",
            key_fingerprint: record().key_fingerprint().unwrap(),
            tags: vec!["dc-1".to_owned(), "hq".to_owned()],
            roles: vec!["ops.dc.senior".to_owned()],
            max_level: Level::new(3),
            not_after: ClaimedTime::new(1_800_000_000),
            authorisation_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap();
        assert_ne!(wider.encode().unwrap(), base);

        let longer = EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: "eng-7",
            organisation_id: "acme",
            key_fingerprint: record().key_fingerprint().unwrap(),
            tags: vec!["dc-1".to_owned(), "hq".to_owned()],
            roles: vec!["ops.dc.senior".to_owned()],
            max_level: Level::new(2),
            not_after: ClaimedTime::new(1_900_000_000),
            authorisation_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap();
        assert_ne!(longer.encode().unwrap(), base);
    }

    #[test]
    fn two_lists_that_read_alike_do_not_encode_alike() {
        // Passes because of the length prefix on every item, not because of the
        // count in front of the list — checked by mutation, and the comment on
        // `push_list` says so.
        let left = EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: "eng-7",
            organisation_id: "acme",
            key_fingerprint: [0x11; 32],
            tags: vec!["ab".to_owned(), "c".to_owned()],
            roles: vec!["r".to_owned()],
            max_level: Level::new(2),
            not_after: ClaimedTime::new(1_800_000_000),
            authorisation_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap();
        let right = EngineerAuthorisation::new(AuthorisationFields {
            engineer_id: "eng-7",
            organisation_id: "acme",
            key_fingerprint: [0x11; 32],
            tags: vec!["a".to_owned(), "bc".to_owned()],
            roles: vec!["r".to_owned()],
            max_level: Level::new(2),
            not_after: ClaimedTime::new(1_800_000_000),
            authorisation_signature: Signature::new(vec![0x03]).unwrap(),
        })
        .unwrap();
        assert_ne!(left.encode().unwrap(), right.encode().unwrap());
    }

    #[test]
    fn a_fingerprint_of_the_wrong_width_does_not_parse() {
        let text = authorisation()
            .to_wire()
            .replace(&hex::encode(record().key_fingerprint().unwrap()), "0a0b");
        assert_eq!(
            EngineerAuthorisation::parse(&text),
            Err(EngineerError::DigestWidth {
                field: "key_fingerprint",
                got: 2
            })
        );
    }

    #[test]
    fn an_unknown_field_does_not_parse() {
        assert!(matches!(
            EngineerRecord::parse(&format!("{};extra=1", record().to_wire())),
            Err(EngineerError::Wire(WireError::FieldCount { .. }))
        ));
        assert!(matches!(
            EngineerAuthorisation::parse(&format!("{};extra=1", authorisation().to_wire())),
            Err(EngineerError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn a_field_out_of_order_does_not_parse() {
        assert!(matches!(
            EngineerRecord::parse(&format!("{ENGINEER_RECORD_PREFIX};key=04;engineer=eng-7")),
            Err(EngineerError::Wire(WireError::UnexpectedField {
                expected: "engineer",
                ..
            }))
        ));
        assert!(matches!(
            EngineerAuthorisation::parse(&format!(
                "{AUTHORISATION_PREFIX};organisation=acme;engineer=eng-7"
            )),
            Err(EngineerError::Wire(WireError::UnexpectedField {
                expected: "engineer",
                ..
            }))
        ));
    }

    #[test]
    fn a_broken_structure_does_not_parse() {
        assert!(matches!(
            EngineerRecord::parse("tessera-codes/v0/engineer-record;engineer=eng-7"),
            Err(EngineerError::Wire(WireError::WrongPrefix { .. }))
        ));
        let text = authorisation()
            .to_wire()
            .replace(";max_level=2", ";max_level");
        assert!(matches!(
            EngineerAuthorisation::parse(&text),
            Err(EngineerError::Wire(WireError::MalformedField { .. }))
        ));
    }

    #[test]
    fn a_level_that_is_not_a_number_does_not_parse() {
        let text = authorisation()
            .to_wire()
            .replace("max_level=2", "max_level=two");
        assert!(matches!(
            EngineerAuthorisation::parse(&text),
            Err(EngineerError::Wire(WireError::NotANumber {
                field: "max_level"
            }))
        ));
    }
}

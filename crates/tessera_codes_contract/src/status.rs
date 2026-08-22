//! The status-token: what the status service says about an engineer, now.
//!
//! A grant says an engineer was authorised when the request was signed. It does
//! not say the authorisation is still standing: a person is suspended, a key is
//! withdrawn, an authorisation is cancelled, and the grant in somebody's hand
//! goes on saying what it said. The status-token is the freshness of that
//! claim, stated separately and signed by a service whose only job is to say
//! it.
//!
//! # What it is bound to
//!
//! To the attempt and to the authorisation, both:
//!
//! - the **nonce of the attempt**, so a token cannot be lifted from one login
//!   and shown at another. Without it the freshest possible token is a token
//!   about nobody in particular;
//! - the **digest of the authorisation** that was presented, so a token issued
//!   about one authorisation cannot vouch for a different one — which is what a
//!   token bound to a person alone would do the moment their authorisation is
//!   replaced by a wider one;
//! - the **fingerprint of the engineer key**, so the person the token is about
//!   is the person who signed the request;
//! - the **head of the revocation list**, so a consumer can tell how fresh the
//!   list behind the answer was, rather than trusting that the service looked.
//!
//! # The window
//!
//! Two moments, not one: when the service answered and how long the answer
//! stands. A token that carried only its expiry could be issued with an expiry
//! as far away as the caller liked, and "the authorisation is live" would
//! quietly become "it was live at some point today". Keeping both is what lets
//! a fleet bound the window — the bound itself is a fleet parameter and does not
//! belong here, but a format that cannot express the window could not be
//! bounded later without being changed again.

use crate::canon::{CanonError, Encoder};
use crate::mac::DIGEST_LEN;
use crate::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::time::ClaimedTime;
use crate::wire::{self, WireError};

/// Marker that opens the wire form of a status-token and pins the version.
pub const STATUS_TOKEN_PREFIX: &str = "tessera-codes/v1/status-token";

/// Number of fields a status-token carries in its wire form.
pub const STATUS_TOKEN_FIELD_COUNT: usize = 8;

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; STATUS_TOKEN_FIELD_COUNT] = [
    "service_key",
    "nonce",
    "engineer_key",
    "authorisation",
    "revocations_head",
    "status",
    "issued_at",
    "not_after",
];

/// Label separating a status-token from every other document of the channel.
const STATUS_LABEL: &str = "tessera-codes-contract/v1/status-token";

/// What the service says about the authorisation.
///
/// Two answers and no third: a service that cannot say "standing" says
/// "withheld". There is deliberately no "unknown" — a consumer that has to
/// decide what to do about an answer that means nothing would decide it
/// differently in every place it appears, and one of those places would decide
/// to let the login through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorisationStatus {
    /// The authorisation is standing.
    Standing,
    /// The authorisation is not standing — withdrawn, suspended, unknown to the
    /// service, or the service declines to answer.
    Withheld,
}

impl AuthorisationStatus {
    /// The token this status is written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standing => "standing",
            Self::Withheld => "withheld",
        }
    }

    /// Reads a status, or nothing.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "standing" => Some(Self::Standing),
            "withheld" => Some(Self::Withheld),
            _ => None,
        }
    }
}

/// The values a status-token is assembled from.
#[derive(Debug)]
pub struct StatusTokenFields<'a> {
    /// Identifier of the key the status service signed with.
    pub service_key_id: &'a str,
    /// Nonce of the attempt this answer is about.
    pub nonce: &'a str,
    /// Fingerprint of the engineer key.
    pub engineer_key_fingerprint: [u8; DIGEST_LEN],
    /// Digest of the authorisation that was presented.
    pub authorisation_digest: [u8; DIGEST_LEN],
    /// Head of the revocation list the answer was given against.
    pub revocations_head: [u8; DIGEST_LEN],
    /// What the service says.
    pub status: AuthorisationStatus,
    /// When the service answered.
    pub issued_at: ClaimedTime,
    /// How long the answer stands.
    pub not_after: ClaimedTime,
}

/// What the status service said, and the signature that says it said it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusToken {
    service_key_id: String,
    nonce: String,
    engineer_key_fingerprint: [u8; DIGEST_LEN],
    authorisation_digest: [u8; DIGEST_LEN],
    revocations_head: [u8; DIGEST_LEN],
    status: AuthorisationStatus,
    issued_at: ClaimedTime,
    not_after: ClaimedTime,
}

impl StatusToken {
    /// Assembles a token.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when an identifier is empty or carries a
    /// character the format cannot hold, and [`StatusError::EmptyWindow`] when
    /// the answer expires no later than it was given — a window of zero length
    /// is an answer that was never valid, and a consumer comparing against it
    /// would refuse everything or, worse, treat the comparison as vacuous.
    pub fn new(fields: &StatusTokenFields<'_>) -> Result<Self, StatusError> {
        wire::check_free_text("service_key", fields.service_key_id)?;
        wire::check_free_text("nonce", fields.nonce)?;
        if fields.not_after.get() <= fields.issued_at.get() {
            return Err(StatusError::EmptyWindow);
        }
        Ok(Self {
            service_key_id: fields.service_key_id.to_owned(),
            nonce: fields.nonce.to_owned(),
            engineer_key_fingerprint: fields.engineer_key_fingerprint,
            authorisation_digest: fields.authorisation_digest,
            revocations_head: fields.revocations_head,
            status: fields.status,
            issued_at: fields.issued_at,
            not_after: fields.not_after,
        })
    }

    /// Returns the identifier of the key the service signed with.
    #[must_use]
    pub fn service_key_id(&self) -> &str {
        &self.service_key_id
    }

    /// Returns the nonce of the attempt this answer is about.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns the fingerprint of the engineer key.
    #[must_use]
    pub const fn engineer_key_fingerprint(&self) -> &[u8; DIGEST_LEN] {
        &self.engineer_key_fingerprint
    }

    /// Returns the digest of the authorisation the answer is about.
    #[must_use]
    pub const fn authorisation_digest(&self) -> &[u8; DIGEST_LEN] {
        &self.authorisation_digest
    }

    /// Returns the head of the revocation list behind the answer.
    #[must_use]
    pub const fn revocations_head(&self) -> &[u8; DIGEST_LEN] {
        &self.revocations_head
    }

    /// Returns what the service said.
    #[must_use]
    pub const fn status(&self) -> AuthorisationStatus {
        self.status
    }

    /// Returns the moment the service answered.
    #[must_use]
    pub const fn issued_at(&self) -> ClaimedTime {
        self.issued_at
    }

    /// Returns the moment the answer stops standing.
    #[must_use]
    pub const fn not_after(&self) -> ClaimedTime {
        self.not_after
    }

    /// Returns how long the answer stands, in seconds.
    ///
    /// Exposed so a fleet can bound it. The bound is a parameter and lives
    /// elsewhere; what lives here is the ability to ask the question.
    #[must_use]
    pub const fn window_secs(&self) -> u64 {
        self.not_after.get().saturating_sub(self.issued_at.get())
    }

    /// Reports whether the answer stands at `now`.
    ///
    /// Both ends are checked. A token presented before it was issued is refused
    /// rather than treated as fresh: on a device whose clock is not trusted,
    /// "not yet valid" and "valid" are the same mistake in opposite directions.
    #[must_use]
    pub const fn stands_at(&self, now: ClaimedTime) -> bool {
        matches!(self.status, AuthorisationStatus::Standing)
            && now.get() >= self.issued_at.get()
            && now.get() <= self.not_after.get()
    }

    /// Encodes the message the status service signs.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when a field exceeds the range of
    /// the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("status_label", STATUS_LABEL)?;
        encoder.push_text("service_key_id", &self.service_key_id)?;
        encoder.push_text("nonce", &self.nonce)?;
        encoder.push_bytes("engineer_key", &self.engineer_key_fingerprint)?;
        encoder.push_bytes("authorisation", &self.authorisation_digest)?;
        encoder.push_bytes("revocations_head", &self.revocations_head)?;
        encoder.push_text("status", self.status.as_str())?;
        encoder.push_u64("issued_at", self.issued_at.get())?;
        encoder.push_u64("not_after", self.not_after.get())?;
        Ok(encoder.finish())
    }

    /// Verifies the signature of the status service.
    ///
    /// The service is a named signer: which key belongs to the status service
    /// of a fleet is an anchor question, and this crate holds no anchors.
    ///
    /// # Errors
    ///
    /// Returns [`StatusError::Canon`] when the token cannot be encoded and
    /// [`StatusError::ServiceSignature`] when the signature does not hold or
    /// the service key is not anchored.
    pub fn verify(
        &self,
        verifier: &impl SignatureVerifier,
        signature: &Signature,
    ) -> Result<(), StatusError> {
        let message = self.encode()?;
        verifier
            .verify(SignerRef::Named(&self.service_key_id), &message, signature)
            .map_err(StatusError::ServiceSignature)
    }

    /// Renders the wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let [service_key, nonce, engineer_key, authorisation, head, status, issued_at, not_after] =
            WIRE_KEYS;
        let fields = [
            (service_key, self.service_key_id.clone()),
            (nonce, self.nonce.clone()),
            (engineer_key, hex::encode(self.engineer_key_fingerprint)),
            (authorisation, hex::encode(self.authorisation_digest)),
            (head, hex::encode(self.revocations_head)),
            (status, self.status.as_str().to_owned()),
            (issued_at, self.issued_at.get().to_string()),
            (not_after, self.not_after.get().to_string()),
        ];
        wire::render(STATUS_TOKEN_PREFIX, &fields)
    }

    /// Parses the wire form.
    ///
    /// # Errors
    ///
    /// The [`StatusError`] describing the first violation: a missing or
    /// misspelled prefix, a wrong number of fields, a field out of order or
    /// unknown, an empty value, a digest of the wrong width, a status token no
    /// variant is written under, or a window that ends before it starts.
    pub fn parse(text: &str) -> Result<Self, StatusError> {
        let values = wire::parse(text, STATUS_TOKEN_PREFIX, &WIRE_KEYS)?;
        let digest = |index: usize, field: &'static str| -> Result<[u8; DIGEST_LEN], StatusError> {
            let bytes = wire::parse_hex(field, wire::value(&values, index))?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| StatusError::DigestWidth {
                    field,
                    got: bytes.len(),
                })
        };

        let status = AuthorisationStatus::parse(wire::value(&values, 5))
            .ok_or(StatusError::UnknownStatus)?;

        Self::new(&StatusTokenFields {
            service_key_id: wire::value(&values, 0),
            nonce: wire::value(&values, 1),
            engineer_key_fingerprint: digest(2, "engineer_key")?,
            authorisation_digest: digest(3, "authorisation")?,
            revocations_head: digest(4, "revocations_head")?,
            status,
            issued_at: ClaimedTime::new(wire::parse_u64("issued_at", wire::value(&values, 6))?),
            not_after: ClaimedTime::new(wire::parse_u64("not_after", wire::value(&values, 7))?),
        })
    }
}

impl core::fmt::Display for StatusToken {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Rejection of a status-token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusError {
    /// The answer expires no later than it was given.
    #[error("the status-token stands for no time at all")]
    EmptyWindow,
    /// The status is not a token any variant is written under.
    #[error("the status-token carries a status no variant is written under")]
    UnknownStatus,
    /// A digest field is not the width of a digest.
    #[error(
        "the status-token field `{field}` is {got} bytes where the format has {}",
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
    /// The token could not be encoded.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// The signature of the status service did not hold.
    #[error("the signature of the status service was rejected: {0}")]
    ServiceSignature(#[source] SignatureError),
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{
        AuthorisationStatus, StatusError, StatusToken, StatusTokenFields, STATUS_TOKEN_PREFIX,
    };
    use crate::time::ClaimedTime;
    use crate::wire::WireError;

    fn token() -> StatusToken {
        StatusToken::new(&StatusTokenFields {
            service_key_id: "status-1",
            nonce: "4444444444",
            engineer_key_fingerprint: [0x11; 32],
            authorisation_digest: [0x22; 32],
            revocations_head: [0x33; 32],
            status: AuthorisationStatus::Standing,
            issued_at: ClaimedTime::new(1_800_000_000),
            not_after: ClaimedTime::new(1_800_000_060),
        })
        .unwrap()
    }

    #[test]
    fn a_token_round_trips_through_the_wire_form() {
        let original = token();
        assert_eq!(StatusToken::parse(&original.to_wire()), Ok(original));
    }

    #[test]
    fn the_window_is_the_two_moments_and_is_askable() {
        assert_eq!(token().window_secs(), 60);
    }

    #[test]
    fn a_window_that_ends_before_it_starts_does_not_assemble() {
        let refused = StatusToken::new(&StatusTokenFields {
            service_key_id: "status-1",
            nonce: "4444444444",
            engineer_key_fingerprint: [0x11; 32],
            authorisation_digest: [0x22; 32],
            revocations_head: [0x33; 32],
            status: AuthorisationStatus::Standing,
            issued_at: ClaimedTime::new(1_800_000_060),
            not_after: ClaimedTime::new(1_800_000_060),
        });
        assert_eq!(refused, Err(StatusError::EmptyWindow));
    }

    #[test]
    fn a_token_stands_only_inside_its_window_and_only_when_standing() {
        let token = token();
        assert!(token.stands_at(ClaimedTime::new(1_800_000_000)));
        assert!(token.stands_at(ClaimedTime::new(1_800_000_060)));
        assert!(!token.stands_at(ClaimedTime::new(1_800_000_061)));
        // Before it was issued: on a device whose clock is not trusted this is
        // the same mistake as an expired token, in the other direction.
        assert!(!token.stands_at(ClaimedTime::new(1_799_999_999)));

        let withheld = StatusToken::new(&StatusTokenFields {
            service_key_id: "status-1",
            nonce: "4444444444",
            engineer_key_fingerprint: [0x11; 32],
            authorisation_digest: [0x22; 32],
            revocations_head: [0x33; 32],
            status: AuthorisationStatus::Withheld,
            issued_at: ClaimedTime::new(1_800_000_000),
            not_after: ClaimedTime::new(1_800_000_060),
        })
        .unwrap();
        assert!(!withheld.stands_at(ClaimedTime::new(1_800_000_001)));
    }

    #[test]
    fn every_binding_changes_the_bytes_the_service_signs() {
        // A token lifted from another attempt, another authorisation, another
        // engineer or another revocation list must not verify against this one.
        let signed = token().encode().unwrap();
        let variants = [
            StatusTokenFields {
                service_key_id: "status-1",
                nonce: "4444444445",
                engineer_key_fingerprint: [0x11; 32],
                authorisation_digest: [0x22; 32],
                revocations_head: [0x33; 32],
                status: AuthorisationStatus::Standing,
                issued_at: ClaimedTime::new(1_800_000_000),
                not_after: ClaimedTime::new(1_800_000_060),
            },
            StatusTokenFields {
                service_key_id: "status-1",
                nonce: "4444444444",
                engineer_key_fingerprint: [0x12; 32],
                authorisation_digest: [0x22; 32],
                revocations_head: [0x33; 32],
                status: AuthorisationStatus::Standing,
                issued_at: ClaimedTime::new(1_800_000_000),
                not_after: ClaimedTime::new(1_800_000_060),
            },
            StatusTokenFields {
                service_key_id: "status-1",
                nonce: "4444444444",
                engineer_key_fingerprint: [0x11; 32],
                authorisation_digest: [0x23; 32],
                revocations_head: [0x33; 32],
                status: AuthorisationStatus::Standing,
                issued_at: ClaimedTime::new(1_800_000_000),
                not_after: ClaimedTime::new(1_800_000_060),
            },
            StatusTokenFields {
                service_key_id: "status-1",
                nonce: "4444444444",
                engineer_key_fingerprint: [0x11; 32],
                authorisation_digest: [0x22; 32],
                revocations_head: [0x34; 32],
                status: AuthorisationStatus::Standing,
                issued_at: ClaimedTime::new(1_800_000_000),
                not_after: ClaimedTime::new(1_800_000_060),
            },
            StatusTokenFields {
                service_key_id: "status-1",
                nonce: "4444444444",
                engineer_key_fingerprint: [0x11; 32],
                authorisation_digest: [0x22; 32],
                revocations_head: [0x33; 32],
                status: AuthorisationStatus::Withheld,
                issued_at: ClaimedTime::new(1_800_000_000),
                not_after: ClaimedTime::new(1_800_000_060),
            },
        ];
        for fields in variants {
            let other = StatusToken::new(&fields).unwrap();
            assert_ne!(other.encode().unwrap(), signed);
        }
    }

    #[test]
    fn a_status_no_variant_is_written_under_does_not_parse() {
        let text = token().to_wire().replace("status=standing", "status=maybe");
        assert_eq!(StatusToken::parse(&text), Err(StatusError::UnknownStatus));
    }

    #[test]
    fn a_digest_of_the_wrong_width_does_not_parse() {
        let text = token().to_wire().replace(&hex::encode([0x22; 32]), "0a0b");
        assert_eq!(
            StatusToken::parse(&text),
            Err(StatusError::DigestWidth {
                field: "authorisation",
                got: 2
            })
        );
    }

    #[test]
    fn an_unknown_field_does_not_parse() {
        let text = format!("{};extra=1", token().to_wire());
        assert!(matches!(
            StatusToken::parse(&text),
            Err(StatusError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn a_field_out_of_order_does_not_parse() {
        let text = format!("{STATUS_TOKEN_PREFIX};nonce=1;service_key=status-1");
        assert!(matches!(
            StatusToken::parse(&text),
            Err(StatusError::Wire(WireError::UnexpectedField {
                expected: "service_key",
                ..
            }))
        ));
    }

    #[test]
    fn an_empty_value_does_not_parse() {
        let text = token()
            .to_wire()
            .replace("service_key=status-1", "service_key=");
        assert!(matches!(
            StatusToken::parse(&text),
            Err(StatusError::Wire(WireError::EmptyValue {
                field: "service_key"
            }))
        ));
    }
}

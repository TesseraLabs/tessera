//! The grant: what the issuing side answers a request with.
//!
//! A grant is the signed request of the engineer ([`crate::request`]), the
//! signature of the issuing side over that same object, and — where the fleet
//! asks for four eyes — the signature of a second person over that same object
//! again. Nothing else is authoritative in it.
//!
//! # Why the confirmation is a signature over the request
//!
//! Because anything weaker moves. A confirmation recorded as a name, a flag or
//! a note beside the grant says "somebody approved something", and nothing in
//! the document ties it to *this* request: the same approval reads as valid
//! against another issuance, which is exactly the defect a second pair of eyes
//! exists to prevent. A signature over the canonical request cannot travel: the
//! request carries the challenge, and the challenge carries the nonce and the
//! ephemeral point of one attempt on one device. Moving it to another issuance
//! means producing a signature over other bytes, which is the thing the
//! confirmer's key is for.
//!
//! The two signatures are separated by a label, so neither can stand in for the
//! other. An engineer's signature is not a confirmation of their own request,
//! and a confirmation is not a request.
//!
//! # The summary outside the signature
//!
//! A grant is read by people and by tooling that does not want to open the
//! challenge to learn which device a grant is for. So the wire form repeats a
//! short summary — device, role, level, engineer — beside the signed object,
//! and **every field of it is checked byte for byte against what was signed**
//! before the grant parses at all. A summary that disagrees is not a grant with
//! a cosmetic error: it is a document that says two different things about who
//! may do what, and the reader that trusts the cheaper of the two is the one an
//! attacker is writing for.

use crate::canon::{CanonError, Encoder, Level};
use crate::params::FleetParams;
use crate::request::{RequestError, SignedRequest};
use crate::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
use crate::wire::{self, WireError};

/// Marker that opens the wire form of a grant and pins the version.
pub const GRANT_PREFIX: &str = "tessera-codes/v1/grant";

/// Number of fields a grant carries in its wire form.
pub const GRANT_FIELD_COUNT: usize = 7;

/// Field keys of the wire form, in the only order the parser accepts.
const WIRE_KEYS: [&str; GRANT_FIELD_COUNT] = [
    "request",
    "server",
    "server_signature",
    "confirmer",
    "confirmer_signature",
    "summary_device",
    "summary_role",
];

/// Value of the confirmer fields when the grant carries no confirmation.
pub const NO_CONFIRMER: &str = "none";

/// Label separating the signature of the issuing side from every other
/// signature over the same object.
const SERVER_LABEL: &str = "tessera-codes-contract/v1/grant-server";

/// Label separating the confirmation from every other signature over the same
/// object.
const CONFIRMER_LABEL: &str = "tessera-codes-contract/v1/grant-confirmer";

/// The summary a grant repeats outside the signature.
///
/// Every field of it is a copy of something inside the signed request, and the
/// only reason it exists is that a reader should not have to open the challenge
/// to see which device and which role a grant is about. It is not a source of
/// truth and cannot become one: [`Grant::parse`] refuses a grant whose summary
/// differs from the signed object in any byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSummary {
    device_number: String,
    role_id: String,
    level: Level,
    engineer_id: String,
}

impl GrantSummary {
    /// Returns the significant form of the device number.
    #[must_use]
    pub fn device_number(&self) -> &str {
        &self.device_number
    }

    /// Returns the role identifier.
    #[must_use]
    pub fn role_id(&self) -> &str {
        &self.role_id
    }

    /// Returns the level.
    #[must_use]
    pub const fn level(&self) -> Level {
        self.level
    }

    /// Returns the personal number of the engineer.
    #[must_use]
    pub fn engineer_id(&self) -> &str {
        &self.engineer_id
    }
}

/// The values a grant is assembled from.
#[derive(Debug)]
pub struct GrantFields<'a> {
    /// The request, as the engineer signed it.
    pub request: SignedRequest,
    /// Identifier of the issuing side.
    pub server_id: &'a str,
    /// Signature of the issuing side over the request object.
    pub server_signature: Signature,
    /// The second pair of eyes, when the fleet asked for them.
    pub confirmation: Option<Confirmation>,
}

/// A second person's signature over the same request object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    confirmer_id: String,
    signature: Signature,
}

impl Confirmation {
    /// Binds a confirmer to their signature.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when the identifier is empty or carries a
    /// character the format cannot hold, and [`GrantError::ConfirmerSpelling`]
    /// when it is spelled exactly like [`NO_CONFIRMER`] — that spelling is how
    /// the absence of a confirmation is written.
    pub fn by(confirmer_id: &str, signature: Signature) -> Result<Self, GrantError> {
        wire::check_free_text("confirmer", confirmer_id)?;
        if confirmer_id == NO_CONFIRMER {
            return Err(GrantError::ConfirmerSpelling);
        }
        Ok(Self {
            confirmer_id: confirmer_id.to_owned(),
            signature,
        })
    }

    /// Returns the identifier of the confirmer.
    #[must_use]
    pub fn confirmer_id(&self) -> &str {
        &self.confirmer_id
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// A grant with everything the issuing side knows and nothing it signs.
///
/// The computation of a code and the signature over the grant are performed by
/// different holders: the code needs the agreement key, the grant needs the
/// signing key, and in the deployment those two live behind different custody.
/// The issuing core therefore assembles what it knows — the request it served
/// and the identifier it served it under — and hands it to whoever holds the
/// signing key. Making that intermediate state a type of its own is what keeps
/// a half-built [`Grant`] from existing: there is no value here that could be
/// mistaken for a grant somebody signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedGrant {
    request: SignedRequest,
    server_id: String,
}

impl UnsignedGrant {
    /// Assembles what the issuing side will sign.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when the identifier of the issuing side is empty
    /// or carries a character the format cannot hold — the same check
    /// [`Grant::new`] performs, made here so a value that cannot become a grant
    /// never comes into being.
    pub fn new(request: SignedRequest, server_id: &str) -> Result<Self, GrantError> {
        wire::check_free_text("server", server_id)?;
        Ok(Self {
            request,
            server_id: server_id.to_owned(),
        })
    }

    /// Returns the signed request this grant answers.
    #[must_use]
    pub const fn request(&self) -> &SignedRequest {
        &self.request
    }

    /// Returns the identifier of the issuing side.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Encodes the message the holder of the signing key signs.
    ///
    /// The same bytes [`Grant::server_message`] returns, available before the
    /// signature exists: the holder of the key signs these and nothing else, so
    /// it never has to be handed a document to fill in.
    ///
    /// # Errors
    ///
    /// The errors of the request encoding.
    pub fn signing_message(&self) -> Result<Vec<u8>, CanonError> {
        Grant::labelled(SERVER_LABEL, &self.request)
    }

    /// Turns this into a grant, with the signature of the issuing side.
    ///
    /// # Errors
    ///
    /// [`GrantError::SelfConfirmation`] when the confirmer is the engineer who
    /// asked, and the wire errors of [`Grant::new`].
    pub fn sign(
        self,
        server_signature: Signature,
        confirmation: Option<Confirmation>,
    ) -> Result<Grant, GrantError> {
        Grant::new(GrantFields {
            request: self.request,
            server_id: &self.server_id,
            server_signature,
            confirmation,
        })
    }
}

/// What the issuing side answered a request with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    request: SignedRequest,
    server_id: String,
    server_signature: Signature,
    confirmation: Option<Confirmation>,
}

impl Grant {
    /// Assembles a grant.
    ///
    /// # Errors
    ///
    /// Returns the wire errors when the identifier of the issuing side is empty
    /// or carries a character the format cannot hold.
    pub fn new(fields: GrantFields<'_>) -> Result<Self, GrantError> {
        wire::check_free_text("server", fields.server_id)?;

        // A confirmation by the engineer who asked is not a confirmation. The
        // rule belongs here and not on the issuing side, because here is where
        // the request and the confirmation are in one value: the server that
        // would otherwise enforce it does not exist yet, and an invariant
        // nobody can express is an invariant nobody keeps.
        //
        // Compared in the FOLDED form, not byte for byte. A personal number
        // ignores its separators and its case by the rule of its own format, so
        // `ORG1-0000014` and `org1 000001 4` are one number; comparing what was
        // typed let an engineer confirm their own request under the second
        // spelling and produced a document that reads as two people. The device
        // number in this crate has been compared folded all along — the
        // confirmer was the one place that was not.
        //
        // What this is still NOT: a resolution of identity. Two names for one
        // person — a login and a personal number, the same human in two
        // registers — pass it, and the four-eyes rule this serves lives where
        // identities are resolved into keys. This closes the case where the
        // document says outright that one party did both.
        if let Some(confirmation) = &fields.confirmation {
            let confirmer = crate::number::significant_characters(confirmation.confirmer_id());
            let engineer =
                crate::number::significant_characters(fields.request.request().engineer_id());
            if confirmer == engineer {
                return Err(GrantError::SelfConfirmation);
            }
        }

        Ok(Self {
            request: fields.request,
            server_id: fields.server_id.to_owned(),
            server_signature: fields.server_signature,
            confirmation: fields.confirmation,
        })
    }

    /// Returns the signed request.
    #[must_use]
    pub const fn request(&self) -> &SignedRequest {
        &self.request
    }

    /// Returns the identifier of the issuing side.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Returns the signature of the issuing side.
    #[must_use]
    pub const fn server_signature(&self) -> &Signature {
        &self.server_signature
    }

    /// Returns the confirmation, when the grant carries one.
    #[must_use]
    pub const fn confirmation(&self) -> Option<&Confirmation> {
        self.confirmation.as_ref()
    }

    /// Returns the summary this grant states outside the signature.
    ///
    /// Built from the signed object rather than stored, so a summary that is
    /// asked for is a summary that agrees with what was signed by construction.
    /// What [`Grant::parse`] does is check that the summary a *document*
    /// carried is this one.
    #[must_use]
    pub fn summary(&self) -> GrantSummary {
        let challenge = self.request.request().challenge();
        GrantSummary {
            device_number: challenge.device_number().significant().to_owned(),
            role_id: challenge.role_id().to_owned(),
            level: challenge.level(),
            engineer_id: challenge.engineer_id().to_owned(),
        }
    }

    /// Encodes the message the issuing side signs.
    ///
    /// # Errors
    ///
    /// The errors of the request encoding.
    pub fn server_message(&self) -> Result<Vec<u8>, CanonError> {
        Self::labelled(SERVER_LABEL, &self.request)
    }

    /// Encodes the message a confirmer signs.
    ///
    /// The same request object as the engineer and the issuing side signed,
    /// under a label of its own — see the module documentation for why a
    /// confirmation that is not a signature over these bytes is a confirmation
    /// that can be moved to another issuance.
    ///
    /// # Errors
    ///
    /// The errors of the request encoding.
    pub fn confirmer_message(&self) -> Result<Vec<u8>, CanonError> {
        Self::labelled(CONFIRMER_LABEL, &self.request)
    }

    /// Encodes the request object under a label.
    pub(crate) fn labelled(label: &str, request: &SignedRequest) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("label", label)?;
        encoder.push_bytes("request", &request.request().encode()?)?;
        Ok(encoder.finish())
    }

    /// Verifies the grant: the engineer, then the issuing side, then the
    /// confirmer when there is one.
    ///
    /// The order is the order of the claims. The request is what the engineer
    /// asked for; the grant is what the issuing side answered; the confirmation
    /// is what a second person agreed to. A consumer that checked the issuing
    /// side alone would accept a grant whose request was written by whoever
    /// holds the issuing key.
    ///
    /// This does **not** decide whether a confirmation was *required* — that is
    /// the level threshold of a fleet, which lives in its parameters and not in
    /// this crate. What is decided here is that a confirmation which is present
    /// holds over this request and no other.
    ///
    /// # Errors
    ///
    /// [`GrantError::Request`] when the engineer's signature does not hold,
    /// [`GrantError::ServerSignature`] when the issuing side's does not, and
    /// [`GrantError::ConfirmerSignature`] when the confirmation does not.
    pub fn verify(&self, verifier: &impl SignatureVerifier) -> Result<(), GrantError> {
        self.request.verify(verifier)?;

        verifier
            .verify(
                SignerRef::Named(&self.server_id),
                &self.server_message()?,
                &self.server_signature,
            )
            .map_err(GrantError::ServerSignature)?;

        if let Some(confirmation) = &self.confirmation {
            verifier
                .verify(
                    SignerRef::Named(confirmation.confirmer_id()),
                    &self.confirmer_message()?,
                    confirmation.signature(),
                )
                .map_err(GrantError::ConfirmerSignature)?;
        }
        Ok(())
    }

    /// Verifies ONLY the signature of the issuing side.
    ///
    /// [`Grant::verify`] is the whole document: the engineer's signature, the
    /// issuing side's, and the confirmer's if there is one. This is the part a
    /// reader can check when the engineer's identity was never vouched for —
    /// which, in a release whose identity provider is a stub, is every grant
    /// there is. Refusing all of them would not be a stricter check; it would
    /// be a check whose answer says nothing about the document.
    ///
    /// What it does NOT say, and a caller must not read into it: that the
    /// engineer is who the grant names. Only the mark in the issuance record
    /// speaks to that, and it says nobody vouched.
    ///
    /// # Errors
    ///
    /// [`GrantError::ServerSignature`] when the signature does not hold, and
    /// the canonical errors when the message cannot be encoded.
    pub fn verify_issuing_side(&self, verifier: &impl SignatureVerifier) -> Result<(), GrantError> {
        verifier
            .verify(
                SignerRef::Named(&self.server_id),
                &self.server_message()?,
                &self.server_signature,
            )
            .map_err(GrantError::ServerSignature)
    }

    /// Renders the wire form, summary included.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let summary = self.summary();
        let (confirmer, confirmer_signature) = match &self.confirmation {
            Some(confirmation) => (
                confirmation.confirmer_id().to_owned(),
                hex::encode(confirmation.signature().as_bytes()),
            ),
            None => (NO_CONFIRMER.to_owned(), NO_CONFIRMER.to_owned()),
        };
        let [request, server, server_signature, confirmer_key, confirmer_signature_key, device, role] =
            WIRE_KEYS;
        let fields = [
            (request, hex::encode(self.request.to_wire())),
            (server, self.server_id.clone()),
            (
                server_signature,
                hex::encode(self.server_signature.as_bytes()),
            ),
            (confirmer_key, confirmer),
            (confirmer_signature_key, confirmer_signature),
            (device, summary.device_number().to_owned()),
            (
                role,
                format!(
                    "{}/{}/{}",
                    summary.role_id(),
                    summary.level().get(),
                    summary.engineer_id()
                ),
            ),
        ];
        wire::render(GRANT_PREFIX, &fields)
    }

    /// Parses the wire form and checks the summary against the signed object.
    ///
    /// # Errors
    ///
    /// The [`GrantError`] describing the first violation, and
    /// [`GrantError::SummaryMismatch`] naming the field of the summary that
    /// disagrees with what was signed.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, GrantError> {
        let values = wire::parse(text, GRANT_PREFIX, &WIRE_KEYS)?;
        let inner = wire::parse_hex("request", wire::value(&values, 0))?;
        let inner = String::from_utf8(inner)
            .map_err(|_| GrantError::Wire(WireError::UnusableValue { field: "request" }))?;
        let request = SignedRequest::parse(&inner, params)?;

        let confirmation = match (wire::value(&values, 3), wire::value(&values, 4)) {
            (NO_CONFIRMER, NO_CONFIRMER) => None,
            (NO_CONFIRMER, _) | (_, NO_CONFIRMER) => return Err(GrantError::HalfConfirmation),
            (confirmer, signature) => Some(Confirmation::by(
                confirmer,
                Signature::new(wire::parse_hex("confirmer_signature", signature)?)?,
            )?),
        };

        let grant = Self::new(GrantFields {
            request,
            server_id: wire::value(&values, 1),
            server_signature: Signature::new(wire::parse_hex(
                "server_signature",
                wire::value(&values, 2),
            )?)?,
            confirmation,
        })?;

        // The summary the document carried, against the summary the signed
        // object states. Byte for byte, field by field, before the grant is
        // handed to anybody.
        let signed = grant.summary();
        if wire::value(&values, 5) != signed.device_number() {
            return Err(GrantError::SummaryMismatch { field: "device" });
        }
        let stated_role = format!(
            "{}/{}/{}",
            signed.role_id(),
            signed.level().get(),
            signed.engineer_id()
        );
        if wire::value(&values, 6) != stated_role {
            return Err(GrantError::SummaryMismatch { field: "role" });
        }

        Ok(grant)
    }
}

impl core::fmt::Display for Grant {
    /// Writes the wire form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

/// Rejection of a grant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// A field repeated outside the signature disagrees with the signed object.
    #[error("the grant summary field `{field}` does not match the signed request")]
    SummaryMismatch {
        /// Name of the field that disagreed.
        field: &'static str,
    },
    /// A confirmer without a signature, or a signature without a confirmer.
    #[error("the grant names a confirmer without a signature, or the reverse")]
    HalfConfirmation,
    /// The confirmer is spelled exactly like the absence of one.
    #[error("the confirmer is spelled like the absence of a confirmation")]
    ConfirmerSpelling,
    /// The confirmer of the grant is the engineer who asked for it.
    #[error("the confirmation names the engineer who made the request; a second signature by the same party is not a second pair of eyes")]
    SelfConfirmation,
    /// The wire form is not well formed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The request inside the grant was rejected.
    #[error(transparent)]
    Request(#[from] RequestError),
    /// The grant could not be encoded.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// The signature of the issuing side did not hold.
    #[error("the signature of the issuing side was rejected: {0}")]
    ServerSignature(#[source] SignatureError),
    /// The signature of the confirmer did not hold.
    #[error("the signature of the confirmer was rejected: {0}")]
    ConfirmerSignature(#[source] SignatureError),
    /// A key or signature carries no material.
    #[error(transparent)]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{Confirmation, Grant, GrantError, GrantFields, UnsignedGrant, NO_CONFIRMER};
    use crate::request::tests::{params, signed_request};
    use crate::request::EngineerSignature;
    use crate::request::SignedRequest;
    use crate::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
    use crate::wire::WireError;

    fn grant() -> Grant {
        Grant::new(GrantFields {
            request: signed_request(),
            server_id: "srv-1",
            server_signature: Signature::new(vec![0x11, 0x22]).unwrap(),
            confirmation: None,
        })
        .unwrap()
    }

    fn confirmed() -> Grant {
        Grant::new(GrantFields {
            request: signed_request(),
            server_id: "srv-1",
            server_signature: Signature::new(vec![0x11, 0x22]).unwrap(),
            confirmation: Some(
                Confirmation::by("duty-officer", Signature::new(vec![0x33, 0x44]).unwrap())
                    .unwrap(),
            ),
        })
        .unwrap()
    }

    #[test]
    fn what_the_issuing_side_signs_is_known_before_it_signs() {
        // The holder of the signing key never sees a half-built document: it is
        // handed bytes, and the bytes are the ones the finished grant states as
        // its own signing message. Were the two to part ways, a grant would
        // carry a signature over something other than itself and would still
        // parse.
        let unsigned = UnsignedGrant::new(signed_request(), "srv-1").unwrap();
        let message = unsigned.signing_message().unwrap();
        let signed = unsigned
            .sign(Signature::new(vec![0x11, 0x22]).unwrap(), None)
            .unwrap();
        assert_eq!(signed.server_message().unwrap(), message);
        assert_eq!(signed, grant());
    }

    #[test]
    fn an_issuing_side_the_format_cannot_hold_is_refused_before_anything_is_signed() {
        assert_eq!(
            UnsignedGrant::new(signed_request(), "").map(|_| ()),
            Err(GrantError::Wire(WireError::EmptyValue { field: "server" }))
        );
    }

    #[test]
    fn a_confirmation_by_the_engineer_who_asked_is_refused_at_signing() {
        let unsigned = UnsignedGrant::new(signed_request(), "srv-1").unwrap();
        let engineer = unsigned.request().request().engineer_id().to_owned();
        assert_eq!(
            unsigned
                .sign(
                    Signature::new(vec![0x11, 0x22]).unwrap(),
                    Some(Confirmation::by(&engineer, Signature::new(vec![0x33]).unwrap()).unwrap()),
                )
                .map(|_| ()),
            Err(GrantError::SelfConfirmation)
        );
    }

    /// A verifier that says yes to everything.
    ///
    /// The most permissive one that can exist, on purpose: what these tests
    /// establish is which refusals happen BEFORE anybody is asked, and a strict
    /// fixture would refuse for its own reasons and prove nothing.
    struct AcceptsAnything;

    impl SignatureVerifier for AcceptsAnything {
        fn verify(
            &self,
            _signer: SignerRef<'_>,
            _message: &[u8],
            _signature: &Signature,
        ) -> Result<(), SignatureError> {
            Ok(())
        }
    }

    /// A verifier that refuses one named signer and admits the rest.
    struct RefusesOne(&'static str);

    impl SignatureVerifier for RefusesOne {
        fn verify(
            &self,
            signer: SignerRef<'_>,
            _message: &[u8],
            _signature: &Signature,
        ) -> Result<(), SignatureError> {
            match signer {
                SignerRef::Named(name) if name == self.0 => Err(SignatureError::Rejected),
                _ => Ok(()),
            }
        }
    }

    #[test]
    fn a_grant_whose_request_nobody_signed_does_not_verify() {
        // The order of the claims, and the first of them: the request is what
        // the engineer asked for. A consumer that checked the issuing side
        // alone would accept a grant whose request was written by whoever holds
        // the issuing key — and after the explicit "nobody signed it" variant,
        // by whoever holds nothing at all.
        let unsigned = Grant::new(GrantFields {
            request: SignedRequest::new(
                signed_request().request().clone(),
                EngineerSignature::unverified("stub-provider").unwrap(),
            ),
            server_id: "srv-1",
            server_signature: Signature::new(vec![0x11, 0x22]).unwrap(),
            confirmation: None,
        })
        .unwrap();

        assert!(matches!(
            unsigned.verify(&AcceptsAnything),
            Err(GrantError::Request(_))
        ));
    }

    #[test]
    fn each_signature_of_a_grant_is_actually_checked() {
        // Three claims, three refusals, one at a time. Without this every
        // signature of this document could have gone unchecked and every test
        // in the file would still have passed: nothing called `verify` at all.
        assert_eq!(grant().verify(&AcceptsAnything), Ok(()));
        assert_eq!(confirmed().verify(&AcceptsAnything), Ok(()));

        // The engineer.
        let engineer = signed_request().request().engineer_id().to_owned();
        assert!(matches!(
            grant().verify(&RefusesOne(Box::leak(engineer.into_boxed_str()))),
            Err(GrantError::Request(_))
        ));
        // The issuing side.
        assert!(matches!(
            grant().verify(&RefusesOne("srv-1")),
            Err(GrantError::ServerSignature(_))
        ));
        // The second pair of eyes, when there is one.
        assert!(matches!(
            confirmed().verify(&RefusesOne("duty-officer")),
            Err(GrantError::ConfirmerSignature(_))
        ));
    }

    #[test]
    fn a_grant_round_trips_through_the_wire_form() {
        let original = grant();
        assert_eq!(Grant::parse(&original.to_wire(), &params()), Ok(original));
        let original = confirmed();
        assert_eq!(Grant::parse(&original.to_wire(), &params()), Ok(original));
    }

    #[test]
    fn a_summary_device_that_disagrees_does_not_parse() {
        let grant = grant();
        let summary = grant.summary();
        let text = grant.to_wire().replace(
            &format!("summary_device={}", summary.device_number()),
            "summary_device=77000999X",
        );
        assert_eq!(
            Grant::parse(&text, &params()),
            Err(GrantError::SummaryMismatch { field: "device" })
        );
    }

    #[test]
    fn a_summary_role_that_disagrees_does_not_parse() {
        let text = grant().to_wire().replace(
            "summary_role=ops.dc.senior/2/",
            "summary_role=ops.dc.root/2/",
        );
        assert_eq!(
            Grant::parse(&text, &params()),
            Err(GrantError::SummaryMismatch { field: "role" })
        );
    }

    #[test]
    fn a_summary_level_that_disagrees_does_not_parse() {
        // The level travels inside the same summary field as the role, so a
        // level raised by one digit is the same class of edit: a document that
        // says two different things about what was authorised.
        let text = grant().to_wire().replace(
            "summary_role=ops.dc.senior/2/",
            "summary_role=ops.dc.senior/9/",
        );
        assert_eq!(
            Grant::parse(&text, &params()),
            Err(GrantError::SummaryMismatch { field: "role" })
        );
    }

    #[test]
    fn a_summary_engineer_that_disagrees_does_not_parse() {
        let text = grant().to_wire().replace("/2/eng-7", "/2/eng-8");
        assert_eq!(
            Grant::parse(&text, &params()),
            Err(GrantError::SummaryMismatch { field: "role" })
        );
    }

    #[test]
    fn the_two_signatures_are_over_different_bytes() {
        // A confirmation is not a request and a request is not a confirmation:
        // were both over the same bytes, an engineer signing their own request
        // would have produced its confirmation as well.
        let grant = confirmed();
        assert_ne!(
            grant.server_message().unwrap(),
            grant.confirmer_message().unwrap()
        );
        assert_ne!(
            grant.confirmer_message().unwrap(),
            grant.request().request().encode().unwrap()
        );
    }

    #[test]
    fn a_confirmation_is_bound_to_the_request_it_was_made_for() {
        // The whole point of the format: the bytes a confirmer signs carry the
        // challenge — and with it the nonce and the ephemeral point of one
        // attempt — so a confirmation cannot be carried to another issuance.
        let first = confirmed();
        let other_attempt = {
            use crate::challenge::{Challenge, ChallengeFields};
            use crate::key::EphemeralPublicPoint;
            use crate::request::tests::{challenge, request};
            use crate::request::SignedRequest;
            use crate::request::{EngineerRequest, RequestFields};
            let base = challenge();
            let moved = Challenge::new(ChallengeFields {
                device_number: base.device_number().clone(),
                epoch: base.epoch(),
                nonce: base.nonce().clone(),
                role_id: base.role_id(),
                level: base.level(),
                server_id: base.server_id(),
                engineer_id: base.engineer_id(),
                ephemeral_point: EphemeralPublicPoint::new(vec![0x04, 0xaa, 0xbc]).unwrap(),
            })
            .unwrap();
            let request = EngineerRequest::new(RequestFields {
                challenge: moved,
                grounds: request().grounds(),
                grounds_reference: request().grounds_reference().cloned(),
                requested_at: request().requested_at(),
                four_eyes: request().four_eyes(),
            })
            .unwrap();
            Grant::new(GrantFields {
                request: SignedRequest::new(
                    request,
                    EngineerSignature::Signed(Signature::new(vec![0xab, 0xcd]).unwrap()),
                ),
                server_id: "srv-1",
                server_signature: Signature::new(vec![0x11, 0x22]).unwrap(),
                confirmation: first.confirmation().cloned(),
            })
            .unwrap()
        };

        assert_ne!(
            first.confirmer_message().unwrap(),
            other_attempt.confirmer_message().unwrap(),
            "a confirmation carried to another attempt must not cover it"
        );
    }

    #[test]
    fn an_engineer_cannot_confirm_their_own_request() {
        // The four-eyes rule the confirmation exists for, at the one point of
        // this contract where both parties are in the same value.
        let engineer = signed_request().request().engineer_id().to_owned();
        assert_eq!(
            Grant::new(GrantFields {
                request: signed_request(),
                server_id: "srv-1",
                server_signature: Signature::new(vec![0x11, 0x22]).unwrap(),
                confirmation: Some(
                    Confirmation::by(&engineer, Signature::new(vec![0x33, 0x44]).unwrap()).unwrap(),
                ),
            })
            .map(|_| ()),
            Err(GrantError::SelfConfirmation)
        );

        // The wire form is refused for the same reason: a document assembled
        // elsewhere goes through the same constructor.
        let text = confirmed()
            .to_wire()
            .replace("confirmer=duty-officer", &format!("confirmer={engineer}"));
        assert_eq!(
            Grant::parse(&text, &params()),
            Err(GrantError::SelfConfirmation)
        );
    }

    #[test]
    fn a_confirmation_under_another_spelling_of_the_same_number_is_still_self_confirmation() {
        // Byte equality is not identity here. The personal number ignores its
        // separators and its case by the rule of its own format, so
        // `ORG1-0000014` and `org1 000001 4` are ONE number — and an engineer
        // who confirms their own request under the second spelling would have
        // produced a document that reads as two people.
        //
        // The device number in this same crate has been compared in its folded
        // form all along; the confirmer was the one place that compared what
        // was typed.
        let engineer = signed_request().request().engineer_id().to_owned();
        let respelled = respell(&engineer);
        assert_ne!(
            respelled, engineer,
            "the two spellings must differ as bytes"
        );

        assert_eq!(
            Grant::new(GrantFields {
                request: signed_request(),
                server_id: "srv-1",
                server_signature: Signature::new(vec![0x11, 0x22]).unwrap(),
                confirmation: Some(
                    Confirmation::by(&respelled, Signature::new(vec![0x33, 0x44]).unwrap())
                        .unwrap(),
                ),
            })
            .map(|_| ()),
            Err(GrantError::SelfConfirmation)
        );

        // And through the wire, because that is how such a document arrives.
        let text = confirmed()
            .to_wire()
            .replace("confirmer=duty-officer", &format!("confirmer={respelled}"));
        assert_eq!(
            Grant::parse(&text, &params()),
            Err(GrantError::SelfConfirmation)
        );
    }

    /// The same number written differently: lowercase, with the separators of
    /// the number moved about.
    fn respell(number: &str) -> String {
        let significant: String = crate::number::significant_characters(number).to_lowercase();
        let mut respelled = String::new();
        for (index, symbol) in significant.chars().enumerate() {
            if index == 2 || index == 6 {
                respelled.push(' ');
            }
            respelled.push(symbol);
        }
        respelled
    }

    #[test]
    fn a_confirmation_by_anybody_else_is_accepted() {
        // The other direction: the rule may not grow into a taste for
        // identifiers. Anyone whose name is not the engineer's passes.
        assert!(Grant::new(GrantFields {
            request: signed_request(),
            server_id: "srv-1",
            server_signature: Signature::new(vec![0x11, 0x22]).unwrap(),
            confirmation: Some(
                Confirmation::by("eng-70", Signature::new(vec![0x33, 0x44]).unwrap()).unwrap(),
            ),
        })
        .is_ok());
    }

    #[test]
    fn half_a_confirmation_does_not_parse() {
        let text = confirmed().to_wire().replace(
            "confirmer=duty-officer",
            &format!("confirmer={NO_CONFIRMER}"),
        );
        assert_eq!(
            Grant::parse(&text, &params()),
            Err(GrantError::HalfConfirmation)
        );
    }

    #[test]
    fn a_confirmer_spelled_like_its_own_absence_is_refused() {
        assert_eq!(
            Confirmation::by(NO_CONFIRMER, Signature::new(vec![0x01]).unwrap()),
            Err(GrantError::ConfirmerSpelling)
        );
    }

    #[test]
    fn an_unknown_field_does_not_parse() {
        let text = format!("{};extra=1", grant().to_wire());
        assert!(matches!(
            Grant::parse(&text, &params()),
            Err(GrantError::Wire(WireError::FieldCount { .. }))
        ));
    }

    #[test]
    fn a_field_out_of_order_does_not_parse() {
        let text = format!("{};server=srv-1;request=00", super::GRANT_PREFIX);
        assert!(matches!(
            Grant::parse(&text, &params()),
            Err(GrantError::Wire(WireError::UnexpectedField {
                expected: "request",
                ..
            }))
        ));
    }

    #[test]
    fn a_broken_request_inside_does_not_parse() {
        let grant = grant();
        let text = grant
            .to_wire()
            .replace(&hex::encode(grant.request().to_wire()), "00");
        assert!(matches!(
            Grant::parse(&text, &params()),
            Err(GrantError::Request(_))
        ));
    }
}

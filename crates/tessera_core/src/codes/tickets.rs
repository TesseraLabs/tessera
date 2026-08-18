//! The operator tickets a device holds, and the order they are checked in.
//!
//! A ticket is the only thing that says an operator on the telephone is allowed
//! to hand this device a code at all. It is checked before any key is derived,
//! in a fixed order:
//!
//! 1. the signature of the ticket authority, against the anchor the device was
//!    enrolled with;
//! 2. the term of the ticket;
//! 3. absence from the revocation list;
//! 4. the scope: this device, then the role being asked for, then the level.
//!
//! The order is the one a caller cannot observe. Every failure leaves the same
//! [`CodeLoginError::Denied`](crate::codes::CodeLoginError::Denied) behind, and
//! which step failed is written to the audit journal instead — an operator of
//! the fleet needs it, and a caller feeding operator identifiers at the device
//! must not learn from the answer which of them exist.
//!
//! Revocation is applied before authentication, the same way a certificate
//! revocation list is: a ticket that has been withdrawn stops working when the
//! list arrives, not when the ticket would have expired anyway.
//!
//! # Why the role is a step of its own
//!
//! A role identifier and an integrity level are orthogonal: a role at level 1
//! may carry sudo grants that another role at the same level does not. The
//! ceiling of the ticket therefore bounds neither the rights nor the role, and
//! the two are checked apart — an operator scoped to "region south, level at
//! most 1" reaches only the roles the ticket names, whatever their level.
//!
//! # The ticket is the ceiling of the level
//!
//! `max_level` here is the only bound on the linear level in this path, and it
//! is the counterpart of the `MAX_INTEGRITY` extension of a certificate. A role
//! slice carries no such bound: its `mac_mask` is a mask of МКЦ categories, not
//! a set of levels. The device adds one further check of its own, and it is
//! about the role alone — see [`super::roles::LocalRoles`].

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Public};
use openssl::sign::Verifier;

use tessera_codes_contract::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
use tessera_codes_contract::ticket::{SignedTicket, TicketError, TicketNumber};

use super::{audit, AttemptRequest};

/// Largest number of tickets a device carries.
const MAX_TICKETS: usize = 64;

/// Largest number of revoked ticket numbers a device carries.
const MAX_REVOCATIONS: usize = 4096;

/// Largest artefact file accepted, in bytes.
///
/// Public because an import has to refuse an artefact the device would later
/// refuse to read: a cap enforced only at login would let enrolment install a
/// file that quietly turns the method off.
pub const MAX_ARTEFACT_BYTES: usize = 256 * 1024;

/// The scope of the device itself, as the fleet describes it.
///
/// The values are compared against the scope of a ticket: the region has to be
/// the same one, and the device has to carry at least one of the tags the
/// ticket names. "At least one" rather than "all" is what a ticket scoped to a
/// group of sites means — a ticket for `dc-1, hq` covers a device in either,
/// not a device that is somehow in both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceScope {
    /// Tags the device carries.
    pub tags: Vec<String>,
    /// Region the device stands in.
    pub region: String,
}

/// Why a ticket was not accepted.
///
/// The value never reaches the caller of the method; it names the field of the
/// audit event, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketRejection {
    /// No ticket of that operator is on the device.
    Unknown,
    /// The signature of the authority did not hold.
    Signature,
    /// The term of the ticket has passed.
    Expired,
    /// The ticket is on the revocation list.
    Revoked,
    /// The scope does not reach this device.
    ScopeDevice,
    /// The scope does not name the role being asked for.
    ScopeRole,
    /// The scope does not reach the level being asked for.
    ScopeLevel,
}

impl TicketRejection {
    /// Returns the audit reason this rejection is recorded under.
    #[must_use]
    pub const fn audit_reason(self) -> &'static str {
        match self {
            Self::Unknown => audit::REASON_NO_TICKET,
            Self::Signature => audit::REASON_TICKET_SIGNATURE,
            Self::Expired => audit::REASON_TICKET_EXPIRED,
            Self::Revoked => audit::REASON_TICKET_REVOKED,
            Self::ScopeDevice => audit::REASON_TICKET_SCOPE_DEVICE,
            Self::ScopeRole => audit::REASON_TICKET_SCOPE_ROLE,
            Self::ScopeLevel => audit::REASON_TICKET_SCOPE_LEVEL,
        }
    }
}

/// Failure of reading the ticket artefacts.
#[derive(Debug, thiserror::Error)]
pub enum TicketStoreError {
    /// An artefact could not be read.
    #[error("a ticket artefact could not be read: {0}")]
    Io(#[from] io::Error),
    /// An artefact does not hold what the format describes.
    #[error("a ticket artefact is malformed: {reason}")]
    Malformed {
        /// What was wrong with the artefact.
        reason: String,
    },
}

impl From<TicketError> for TicketStoreError {
    fn from(error: TicketError) -> Self {
        Self::Malformed {
            reason: error.to_string(),
        }
    }
}

/// The trust anchor of the ticket authority.
///
/// The device verifies every ticket against this one key, which arrives with
/// the enrolment package. There is no chain and no second anchor: a ticket is
/// signed by the authority of the fleet or it is not a ticket.
pub struct TicketAnchor {
    key: PKey<Public>,
}

impl TicketAnchor {
    /// Reads the anchor from a `SubjectPublicKeyInfo` file, PEM or DER.
    ///
    /// # Errors
    ///
    /// [`TicketStoreError::Io`] when the file cannot be read and
    /// [`TicketStoreError::Malformed`] when it holds no public key.
    pub fn load(path: &Path) -> Result<Self, TicketStoreError> {
        Self::parse(&read_capped(path)?)
    }

    /// Reads the anchor from bytes that are not on the device yet.
    ///
    /// The counterpart of [`TicketAnchor::load`] for a delivery: an import has
    /// to refuse an anchor the device would later refuse to read, and it has to
    /// refuse it with this parser rather than a second one.
    ///
    /// # Errors
    ///
    /// [`TicketStoreError::Malformed`] when the bytes hold no public key.
    pub fn parse(bytes: &[u8]) -> Result<Self, TicketStoreError> {
        let key = PKey::public_key_from_pem(bytes)
            .or_else(|_| PKey::public_key_from_der(bytes))
            .map_err(|error| TicketStoreError::Malformed {
                reason: format!("the ticket authority anchor is not a public key: {error}"),
            })?;
        Ok(Self { key })
    }

    /// Builds the anchor from a key already in hand.
    #[must_use]
    pub const fn from_key(key: PKey<Public>) -> Self {
        Self { key }
    }
}

impl std::fmt::Debug for TicketAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketAnchor")
            .field("algorithm", &self.key.id().as_raw())
            .finish()
    }
}

impl SignatureVerifier for TicketAnchor {
    /// Verifies a signature the document attributes to the ticket authority.
    ///
    /// A signer the document carries itself is refused outright: this anchor
    /// answers one question — did the authority of the fleet sign these bytes —
    /// and a key that travels inside the document it vouches for is not an
    /// answer to it.
    fn verify(
        &self,
        signer: SignerRef<'_>,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        match signer {
            SignerRef::TicketAuthority => {}
            SignerRef::Key(_) | SignerRef::Named(_) => {
                return Err(SignatureError::UnknownSigner);
            }
        }

        // Ed25519 is pure EdDSA and takes no message digest; every other family
        // the fleet may anchor on is verified over SHA-256.
        let verified = if self.key.id() == Id::ED25519 {
            Verifier::new_without_digest(&self.key)
                .and_then(|mut verifier| verifier.verify_oneshot(signature.as_bytes(), message))
        } else {
            Verifier::new(MessageDigest::sha256(), &self.key).and_then(|mut verifier| {
                verifier.update(message)?;
                verifier.verify(signature.as_bytes())
            })
        };

        match verified {
            Ok(true) => Ok(()),
            // An OpenSSL failure and a signature that simply does not hold are
            // the same answer here: the bytes were not vouched for.
            Ok(false) | Err(_) => Err(SignatureError::Rejected),
        }
    }
}

/// The tickets a device holds and the numbers withdrawn from them.
#[derive(Debug, Clone, Default)]
pub struct TicketStore {
    tickets: Vec<SignedTicket>,
    revoked: BTreeSet<String>,
}

impl TicketStore {
    /// Reads the ticket set and its revocation list.
    ///
    /// Both files hold one document per line; a blank line is skipped and
    /// anything else has to parse. A revocation list that is absent is an empty
    /// one — a fleet that has withdrawn nothing ships no list — while an absent
    /// ticket file leaves the method with nothing to work from and is reported
    /// as such by [`TicketStore::is_empty`].
    ///
    /// # Errors
    ///
    /// [`TicketStoreError::Io`] for a read that failed and
    /// [`TicketStoreError::Malformed`] for a line that does not parse.
    pub fn load(tickets_path: &Path, revocations_path: &Path) -> Result<Self, TicketStoreError> {
        Ok(Self {
            tickets: parse_tickets(read_optional(tickets_path)?.as_deref())?,
            revoked: parse_revocations(read_optional(revocations_path)?.as_deref())?,
        })
    }

    /// Parses a ticket set and a revocation list that are already in memory.
    ///
    /// The counterpart of [`TicketStore::load`] for artefacts that have not
    /// been written to the device yet: an import checks what it was handed
    /// before it replaces what the device holds, and it has to check it with
    /// the same parser and the same bounds, not with a second one.
    ///
    /// `None` for either side means the delivery carries none of it.
    ///
    /// # Errors
    ///
    /// [`TicketStoreError::Malformed`] for a line that does not parse or for a
    /// set larger than the bounds a device accepts.
    pub fn parse(
        tickets: Option<&str>,
        revocations: Option<&str>,
    ) -> Result<Self, TicketStoreError> {
        Ok(Self {
            tickets: parse_tickets(tickets)?,
            revoked: parse_revocations(revocations)?,
        })
    }

    /// The ticket numbers this store treats as withdrawn.
    #[must_use]
    pub const fn revoked(&self) -> &BTreeSet<String> {
        &self.revoked
    }

    /// Builds a store from values already in hand.
    #[must_use]
    pub fn from_parts(tickets: Vec<SignedTicket>, revoked: BTreeSet<String>) -> Self {
        Self { tickets, revoked }
    }

    /// Reports whether the device holds no ticket at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tickets.is_empty()
    }

    /// Returns the number of the ticket the operator holds, checked or not.
    ///
    /// For the audit journal alone, and it says nothing about whether the
    /// ticket is any good: a refusal has to carry the ticket number, because a
    /// login and an operator receipt are reconciled by that number and a nonce,
    /// and a refusal that names neither cannot be paired with the receipt of
    /// the call it belongs to.
    #[must_use]
    pub fn ticket_number_of(&self, operator_id: &str) -> Option<&str> {
        self.tickets
            .iter()
            .find(|signed| signed.ticket().operator_id() == operator_id)
            .map(|signed| signed.ticket().number().as_str())
    }

    /// Finds the ticket of the operator the request names and checks it, in the
    /// fixed order.
    ///
    /// The request carries the moment the caller vouches for; the term of a
    /// ticket is a claim compared against another claim, and this one is the
    /// device's.
    ///
    /// The whole request is taken rather than its fields one by one: the
    /// operator identifier and the role identifier are both strings, and a call
    /// site that passed them the wrong way round would check a role against the
    /// operator list and an operator against the role list.
    ///
    /// # Errors
    ///
    /// The [`TicketRejection`] naming the first step that failed. The value is
    /// for the audit journal — the caller reports one refusal whatever it says.
    pub fn admit(
        &self,
        request: &AttemptRequest<'_>,
        device: &DeviceScope,
        anchor: &TicketAnchor,
    ) -> Result<&SignedTicket, TicketRejection> {
        let signed = self
            .tickets
            .iter()
            .find(|signed| signed.ticket().operator_id() == request.operator_id)
            .ok_or(TicketRejection::Unknown)?;

        // Signature first: the term, the revocation state and the scope of a
        // document nobody signed are not information about anything.
        signed
            .verify(anchor, request.now)
            .map_err(|error| match error {
                TicketError::Expired { .. } => TicketRejection::Expired,
                _ => TicketRejection::Signature,
            })?;

        if self.revoked.contains(signed.ticket().number().as_str()) {
            return Err(TicketRejection::Revoked);
        }

        let scope = signed.ticket().scope();
        if scope.region() != device.region
            || !scope.tags().iter().any(|tag| device.tags.contains(tag))
        {
            return Err(TicketRejection::ScopeDevice);
        }
        // The role before the level, and independently of it: the ceiling of
        // the ticket is not a permission to hand out whatever role happens to
        // sit under it.
        if !scope.admits_role(request.role_id) {
            return Err(TicketRejection::ScopeRole);
        }
        if !scope.admits_level(request.level) {
            return Err(TicketRejection::ScopeLevel);
        }

        Ok(signed)
    }
}

/// Parses the ticket set, refusing one larger than a device carries.
fn parse_tickets(text: Option<&str>) -> Result<Vec<SignedTicket>, TicketStoreError> {
    let mut tickets = Vec::new();
    let Some(text) = text else {
        return Ok(tickets);
    };
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if tickets.len() == MAX_TICKETS {
            return Err(TicketStoreError::Malformed {
                reason: format!("the device carries more than {MAX_TICKETS} tickets"),
            });
        }
        tickets.push(SignedTicket::parse(line)?);
    }
    Ok(tickets)
}

/// Parses the revocation list, refusing one larger than a device carries.
fn parse_revocations(text: Option<&str>) -> Result<BTreeSet<String>, TicketStoreError> {
    let mut revoked = BTreeSet::new();
    let Some(text) = text else {
        return Ok(revoked);
    };
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if revoked.len() == MAX_REVOCATIONS {
            return Err(TicketStoreError::Malformed {
                reason: format!("the revocation list holds more than {MAX_REVOCATIONS} numbers"),
            });
        }
        revoked.insert(TicketNumber::parse(line)?.as_str().to_owned());
    }
    Ok(revoked)
}

/// Reads a file that has to be there, refusing one larger than the format
/// describes.
///
/// The cap bounds the read rather than the buffer it fills: sizing a buffer
/// from the metadata first would let a file nobody meant to ship take the
/// process down before the cap could refuse it.
fn read_capped(path: &Path) -> Result<Vec<u8>, TicketStoreError> {
    match crate::fs_mode::read_capped_regular(path, MAX_ARTEFACT_BYTES)? {
        crate::fs_mode::CappedRead::Whole(bytes) => Ok(bytes),
        crate::fs_mode::CappedRead::TooLarge => Err(oversize(path)),
    }
}

/// Reads a file that may be absent.
fn read_optional(path: &Path) -> Result<Option<String>, TicketStoreError> {
    let bytes = match crate::fs_mode::read_capped_regular(path, MAX_ARTEFACT_BYTES) {
        Ok(crate::fs_mode::CappedRead::Whole(bytes)) => bytes,
        Ok(crate::fs_mode::CappedRead::TooLarge) => return Err(oversize(path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(TicketStoreError::Io(error)),
    };
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| TicketStoreError::Malformed {
            reason: format!("{} is not valid UTF-8", path.display()),
        })
}

/// The refusal of an artefact past the cap of the format.
fn oversize(path: &Path) -> TicketStoreError {
    TicketStoreError::Malformed {
        reason: format!(
            "{} is larger than the {MAX_ARTEFACT_BYTES}-byte cap",
            path.display()
        ),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
pub(crate) mod tests {
    use std::collections::BTreeSet;

    use openssl::pkey::PKey;

    use tessera_codes_contract::canon::Level;
    use tessera_codes_contract::signature::{PublicKey, Signature};
    use tessera_codes_contract::ticket::{
        OperatorTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput, ALL_ROLES,
    };
    use tessera_codes_contract::time::ClaimedTime;

    use super::{
        AttemptRequest, DeviceScope, TicketAnchor, TicketRejection, TicketStore, TicketStoreError,
    };

    /// Role the fixture ticket names.
    const ROLE: &str = "oper";

    /// The authority of the fixture fleet, and the tickets it signs.
    pub(crate) struct Authority {
        key: PKey<openssl::pkey::Private>,
    }

    impl Authority {
        pub(crate) fn new() -> Self {
            Self {
                key: PKey::generate_ed25519().unwrap(),
            }
        }

        /// The anchor file a device would be enrolled with.
        ///
        /// Used only by the tests that stand up a real store, which do not
        /// compile where the store cannot be carried.
        #[cfg(unix)]
        pub(crate) fn public_key_pem(&self) -> Vec<u8> {
            self.key.public_key_to_pem().unwrap()
        }

        pub(crate) fn anchor(&self) -> TicketAnchor {
            let der = self.key.public_key_to_der().unwrap();
            TicketAnchor::from_key(PKey::public_key_from_der(&der).unwrap())
        }

        pub(crate) fn sign(&self, ticket: OperatorTicket) -> SignedTicket {
            let message = ticket.encode().unwrap();
            let mut signer = openssl::sign::Signer::new_without_digest(&self.key).unwrap();
            let raw = signer.sign_oneshot_to_vec(&message).unwrap();
            SignedTicket::new(ticket, Signature::new(raw).unwrap())
        }
    }

    pub(crate) fn operator_key() -> PublicKey {
        PublicKey::new(vec![0x04, 0x11, 0x22]).unwrap()
    }

    pub(crate) fn ticket(operator: &str, max_level: u32, number: &str) -> OperatorTicket {
        ticket_for_roles(operator, &[ROLE], max_level, number)
    }

    /// A ticket whose scope names exactly `roles`.
    pub(crate) fn ticket_for_roles(
        operator: &str,
        roles: &[&str],
        max_level: u32,
        number: &str,
    ) -> OperatorTicket {
        OperatorTicket::new(
            operator,
            operator_key(),
            TicketScope::new(TicketScopeInput {
                tags: vec!["dc-1".to_owned(), "hq".to_owned()],
                roles: roles.iter().map(|role| (*role).to_owned()).collect(),
                region: "ru-south".to_owned(),
                max_level: Level::new(max_level),
            })
            .unwrap(),
            ClaimedTime::new(1_800_000_000),
            TicketNumber::parse(number).unwrap(),
        )
        .unwrap()
    }

    pub(crate) fn device_scope() -> DeviceScope {
        DeviceScope {
            tags: vec!["dc-1".to_owned()],
            region: "ru-south".to_owned(),
        }
    }

    fn now() -> ClaimedTime {
        ClaimedTime::new(1_700_000_000)
    }

    /// What an engineer at the fixture device is asking for.
    fn request<'a>(operator: &'a str, role: &'a str, level: u32) -> AttemptRequest<'a> {
        AttemptRequest {
            role_id: role,
            level: Level::new(level),
            operator_id: operator,
            now: now(),
        }
    }

    fn store(authority: &Authority) -> TicketStore {
        TicketStore::from_parts(
            vec![authority.sign(ticket("op-42", 1, "tk-17"))],
            BTreeSet::new(),
        )
    }

    #[test]
    fn a_ticket_within_its_scope_is_admitted() {
        let authority = Authority::new();
        let store = store(&authority);
        let admitted = store
            .admit(
                &request("op-42", ROLE, 1),
                &device_scope(),
                &authority.anchor(),
            )
            .unwrap();
        assert_eq!(admitted.ticket().number().as_str(), "tk-17");
    }

    #[test]
    fn an_unknown_operator_is_refused() {
        let authority = Authority::new();
        assert_eq!(
            store(&authority)
                .admit(
                    &request("op-7", ROLE, 1),
                    &device_scope(),
                    &authority.anchor()
                )
                .unwrap_err(),
            TicketRejection::Unknown
        );
    }

    #[test]
    fn a_ticket_the_anchor_did_not_sign_is_refused() {
        let authority = Authority::new();
        let stranger = Authority::new();
        assert_eq!(
            store(&authority)
                .admit(
                    &request("op-42", ROLE, 1),
                    &device_scope(),
                    &stranger.anchor()
                )
                .unwrap_err(),
            TicketRejection::Signature
        );
    }

    #[test]
    fn an_edited_ticket_is_refused_before_its_scope_is_read() {
        let authority = Authority::new();
        let signed = authority.sign(ticket("op-42", 1, "tk-17"));
        // The level of the scope is widened while the signature stays as it
        // was: the wider scope must never be the answer.
        let widened = SignedTicket::new(ticket("op-42", 9, "tk-17"), signed.signature().clone());
        let store = TicketStore::from_parts(vec![widened], BTreeSet::new());
        assert_eq!(
            store
                .admit(
                    &request("op-42", ROLE, 9),
                    &device_scope(),
                    &authority.anchor()
                )
                .unwrap_err(),
            TicketRejection::Signature
        );

        // The same for the role list: a role added to a signed ticket does not
        // become a role the ticket names.
        let signed = authority.sign(ticket_for_roles("op-42", &[ROLE], 1, "tk-17"));
        let widened = SignedTicket::new(
            ticket_for_roles("op-42", &[ROLE, "root-ish"], 1, "tk-17"),
            signed.signature().clone(),
        );
        let store = TicketStore::from_parts(vec![widened], BTreeSet::new());
        assert_eq!(
            store
                .admit(
                    &request("op-42", "root-ish", 1),
                    &device_scope(),
                    &authority.anchor()
                )
                .unwrap_err(),
            TicketRejection::Signature
        );
    }

    #[test]
    fn an_expired_ticket_is_refused() {
        let authority = Authority::new();
        let late = AttemptRequest {
            now: ClaimedTime::new(1_900_000_000),
            ..request("op-42", ROLE, 1)
        };
        assert_eq!(
            store(&authority)
                .admit(&late, &device_scope(), &authority.anchor())
                .unwrap_err(),
            TicketRejection::Expired
        );
    }

    #[test]
    fn a_revoked_ticket_is_refused_while_still_within_its_term() {
        let authority = Authority::new();
        let store = TicketStore::from_parts(
            vec![authority.sign(ticket("op-42", 1, "tk-17"))],
            BTreeSet::from(["tk-17".to_owned()]),
        );
        assert_eq!(
            store
                .admit(
                    &request("op-42", ROLE, 1),
                    &device_scope(),
                    &authority.anchor()
                )
                .unwrap_err(),
            TicketRejection::Revoked
        );
    }

    #[test]
    fn a_device_outside_the_scope_is_refused() {
        let authority = Authority::new();
        let store = store(&authority);
        let anchor = authority.anchor();

        let other_region = DeviceScope {
            region: "ru-central".to_owned(),
            ..device_scope()
        };
        assert_eq!(
            store
                .admit(&request("op-42", ROLE, 1), &other_region, &anchor)
                .unwrap_err(),
            TicketRejection::ScopeDevice
        );

        let other_site = DeviceScope {
            tags: vec!["dc-9".to_owned()],
            ..device_scope()
        };
        assert_eq!(
            store
                .admit(&request("op-42", ROLE, 1), &other_site, &anchor)
                .unwrap_err(),
            TicketRejection::ScopeDevice
        );
    }

    #[test]
    fn a_role_outside_the_scope_is_refused_at_a_level_the_ticket_allows() {
        let authority = Authority::new();
        assert_eq!(
            store(&authority)
                .admit(
                    &request("op-42", "wide-sudo", 1),
                    &device_scope(),
                    &authority.anchor()
                )
                .unwrap_err(),
            TicketRejection::ScopeRole
        );
    }

    #[test]
    fn a_role_the_scope_names_is_admitted() {
        let authority = Authority::new();
        let store = TicketStore::from_parts(
            vec![authority.sign(ticket_for_roles("op-42", &[ROLE, "wide-sudo"], 1, "tk-17"))],
            BTreeSet::new(),
        );
        for role in [ROLE, "wide-sudo"] {
            assert!(store
                .admit(
                    &request("op-42", role, 1),
                    &device_scope(),
                    &authority.anchor()
                )
                .is_ok());
        }
    }

    #[test]
    fn the_all_roles_marker_admits_a_role_the_ticket_never_named() {
        let authority = Authority::new();
        let store = TicketStore::from_parts(
            vec![authority.sign(ticket_for_roles("op-42", &[ALL_ROLES], 1, "tk-17"))],
            BTreeSet::new(),
        );
        assert!(store
            .admit(
                &request("op-42", "a-role-nobody-listed", 1),
                &device_scope(),
                &authority.anchor()
            )
            .is_ok());
    }

    #[test]
    fn the_role_is_checked_before_the_level_and_apart_from_it() {
        let authority = Authority::new();
        let store = store(&authority);
        let anchor = authority.anchor();

        // A role the ticket does not name, at a level it does allow.
        assert_eq!(
            store
                .admit(&request("op-42", "wide-sudo", 1), &device_scope(), &anchor)
                .unwrap_err(),
            TicketRejection::ScopeRole
        );
        // A role the ticket does name, above the level it allows.
        assert_eq!(
            store
                .admit(&request("op-42", ROLE, 2), &device_scope(), &anchor)
                .unwrap_err(),
            TicketRejection::ScopeLevel
        );
    }

    #[test]
    fn a_level_above_the_scope_is_refused() {
        let authority = Authority::new();
        assert_eq!(
            store(&authority)
                .admit(
                    &request("op-42", ROLE, 2),
                    &device_scope(),
                    &authority.anchor()
                )
                .unwrap_err(),
            TicketRejection::ScopeLevel
        );
    }

    #[test]
    fn the_artefacts_round_trip_through_their_files() {
        let authority = Authority::new();
        let dir = tempfile::tempdir().unwrap();
        let tickets = dir.path().join("tickets");
        let revocations = dir.path().join("revoked");
        std::fs::write(
            &tickets,
            format!(
                "{}\n\n",
                authority.sign(ticket("op-42", 1, "tk-17")).to_wire()
            ),
        )
        .unwrap();
        std::fs::write(&revocations, "tk-99\n").unwrap();

        let store = TicketStore::load(&tickets, &revocations).unwrap();
        assert!(!store.is_empty());
        assert!(store
            .admit(
                &request("op-42", ROLE, 1),
                &device_scope(),
                &authority.anchor()
            )
            .is_ok());
    }

    #[test]
    fn an_absent_revocation_list_is_an_empty_one_and_an_absent_ticket_file_is_no_tickets() {
        let dir = tempfile::tempdir().unwrap();
        let store = TicketStore::load(
            &dir.path().join("missing-tickets"),
            &dir.path().join("missing-revocations"),
        )
        .unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn a_malformed_artefact_does_not_load() {
        let dir = tempfile::tempdir().unwrap();
        let tickets = dir.path().join("tickets");
        std::fs::write(&tickets, "tessera-codes/v1/ticket;operator=op-42\n").unwrap();
        assert!(TicketStore::load(&tickets, &dir.path().join("none")).is_err());

        let revocations = dir.path().join("revoked");
        std::fs::write(&revocations, "tk/17\n").unwrap();
        assert!(TicketStore::load(&dir.path().join("none"), &revocations).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn an_artefact_that_is_not_a_regular_file_is_refused_rather_than_read() {
        // A store whose ticket set is a FIFO is a store an attacker turned into
        // a hang: an ordinary read blocks on the open until a writer that never
        // comes appears, and the login it blocks is the one an engineer is
        // standing at.
        let dir = tempfile::tempdir().unwrap();
        let tickets = dir.path().join("tickets");
        nix::unistd::mkfifo(
            &tickets,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();

        let error = TicketStore::load(&tickets, &dir.path().join("none")).unwrap_err();
        assert!(matches!(error, TicketStoreError::Io(_)), "{error:?}");
    }

    #[test]
    fn an_artefact_larger_than_the_cap_is_refused_without_being_read_whole() {
        // The file is sparse, so it costs nothing to create and everything to
        // read: what must not happen is a buffer sized from its metadata.
        let dir = tempfile::tempdir().unwrap();
        let tickets = dir.path().join("tickets");
        let file = std::fs::File::create(&tickets).unwrap();
        file.set_len(4 * 1024 * 1024 * 1024).unwrap();
        drop(file);

        let error = TicketStore::load(&tickets, &dir.path().join("none")).unwrap_err();
        assert!(
            matches!(error, TicketStoreError::Malformed { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn the_anchor_reads_both_encodings_and_refuses_anything_else() {
        let dir = tempfile::tempdir().unwrap();
        let key = PKey::generate_ed25519().unwrap();

        let pem = dir.path().join("anchor.pem");
        std::fs::write(&pem, key.public_key_to_pem().unwrap()).unwrap();
        assert!(TicketAnchor::load(&pem).is_ok());

        let der = dir.path().join("anchor.der");
        std::fs::write(&der, key.public_key_to_der().unwrap()).unwrap();
        assert!(TicketAnchor::load(&der).is_ok());

        let junk = dir.path().join("anchor.junk");
        std::fs::write(&junk, b"not a key").unwrap();
        assert!(TicketAnchor::load(&junk).is_err());
    }
}

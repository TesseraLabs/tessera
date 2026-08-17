//! One issuance of a code, from the challenge read out to the receipt written.
//!
//! The whole refusal ladder is one function, [`issue`], and both wrappers of the
//! channel — the command line and the browser cabinet — call it. A wrapper that
//! assembled the steps in its own order would be a second policy: the same
//! request would be refused by one and served by the other, and which of the two
//! was right would be settled at a site, over the telephone.
//!
//! The order of the ladder is deliberate:
//!
//! 1. **The grounds.** Nothing is computed for an issuance nobody can answer
//!    for later. It is first because it is the only thing here that does not
//!    depend on any document.
//! 2. **The device record**, then **the ticket**. The scope, the term and the
//!    counter of documents nobody signed are not information about anything.
//! 3. **The coverage** of the request by the ticket — see
//!    [`crate::codes::scope`].
//! 4. **The counter** — see [`crate::codes::counter`].
//! 5. **The key**, and only then the code. Key agreement is the one step that
//!    reaches a token, so it happens after everything that can refuse the call
//!    without touching one.
//!
//! The check character of the device number is checked before all of this,
//! where the challenge is parsed: a number typed wrong never reaches a
//! computation, and the operator hears about the typo rather than about a code
//! that does not fit.

use tessera_codes_contract::challenge::Challenge;
use tessera_codes_contract::code::{compute_code, Code};
use tessera_codes_contract::key::{derive_key, KeyContext};
use tessera_codes_contract::params::FleetParams;
use tessera_codes_contract::receipt::{IssuanceReceipt, ReceiptFields};
use tessera_codes_contract::registry::DeviceRecord;
use tessera_codes_contract::signature::SignatureVerifier;
use tessera_codes_contract::ticket::SignedTicket;
use tessera_codes_contract::time::ClaimedTime;

use crate::codes::agreement::OperatorKey;
use crate::codes::annex::{AnnexFields, ReceiptAnnex, SiteScope};
use crate::codes::counter::{self, CounterOverride, KnownCounter};
use crate::codes::scope::{self, Coverage, DeviceScope};
use crate::codes::Refusal;

/// Number of characters in one group of a code read aloud.
///
/// Three, as in the spoken form of a challenge: an eight-digit run read as one
/// number is mistyped, and the two sides of one call should not group their
/// numbers differently.
const SPOKEN_GROUP: usize = 3;

/// One request an operator is answering.
#[derive(Debug, Clone, Copy)]
pub struct IssuanceRequest<'a> {
    /// The challenge read out over the telephone.
    pub challenge: &'a Challenge,
    /// The signed record of the device.
    pub record: &'a DeviceRecord,
    /// The ticket the operator is working under.
    pub ticket: &'a SignedTicket,
    /// Parameters of the fleet.
    pub params: &'a FleetParams,
    /// Where the fleet says the device stands, when the operator supplied it.
    pub device_scope: Option<&'a DeviceScope>,
    /// Grounds for the issuance: a work order, a request, a ticket number of
    /// the fleet's own tracker.
    pub reason: &'a str,
    /// The moment the operator's side claims.
    pub now: ClaimedTime,
    /// Where the history of this device says it was left — the later of what
    /// the ledger and the receipts say (see [`crate::codes::ledger`]).
    pub known_counter: Option<&'a KnownCounter>,
    /// How many issuances that history holds for this device.
    ///
    /// It travels into the receipt, where it outlives the history itself.
    pub history_depth: u64,
    /// The decision of a second operator to answer a challenge the counter
    /// refused.
    pub override_decision: Option<&'a CounterOverride>,
}

/// What one issuance leaves behind.
#[derive(Debug, Clone)]
pub struct Issuance {
    /// The code to read out.
    pub code: Code,
    /// The receipt of the issuance, in the format of the contract.
    pub receipt: IssuanceReceipt,
    /// What the receipt records beyond the contract's own fields.
    pub annex: ReceiptAnnex,
}

impl Issuance {
    /// Returns the code in groups, as it is read out.
    #[must_use]
    pub fn spoken_code(&self) -> String {
        spoken(self.code.as_str())
    }
}

/// Answers one challenge, or refuses it.
///
/// # Errors
///
/// The [`Refusal`] naming the first step of the ladder that did not pass. No
/// code is computed and no receipt is assembled for a refused request — in
/// particular an issuance without grounds produces neither.
pub fn issue(
    request: &IssuanceRequest<'_>,
    verifier: &impl SignatureVerifier,
    // `?Sized` so a caller that only knows at run time where the operator key is
    // — a token or, in the software mode, a file — can pass the key it built
    // behind a reference without a second copy of this function per backend.
    key: &(impl OperatorKey + ?Sized),
) -> Result<Issuance, Refusal> {
    if request.reason.trim().is_empty() {
        return Err(Refusal::MissingReason);
    }

    request.record.verify(verifier)?;
    request.ticket.verify(verifier, request.now)?;

    let coverage = Coverage {
        challenge: request.challenge,
        record: request.record,
        ticket: request.ticket.ticket(),
        device_scope: request.device_scope,
    };
    scope::check(&coverage)?;

    let note = match counter::assess(
        request.challenge.epoch(),
        request.challenge.nonce().counter(),
        request.challenge.nonce().as_str(),
        request.known_counter,
    ) {
        Ok(_) if request.override_decision.is_some() => {
            return Err(Refusal::OverrideNotNeeded);
        }
        Ok(note) => note,
        Err(refusal) => counter::override_refusal(refusal, request.override_decision)?,
    };

    if !same_point(
        key.public_point().as_slice(),
        request.ticket.ticket().public_key().as_bytes(),
    ) {
        return Err(Refusal::OperatorKeyMismatch);
    }

    let secret = key.agree(request.record.public_key().as_bytes())?;
    let context = KeyContext::new(
        request.challenge.device_number(),
        request.challenge.epoch(),
        request.ticket.context_hash()?,
    );
    let derived = derive_key(&secret, &context)?;
    let code = compute_code(&derived, &request.challenge.code_input(), request.params)?;

    let receipt = IssuanceReceipt::new(ReceiptFields {
        device_number: request.challenge.device_number().clone(),
        epoch: request.challenge.epoch(),
        nonce: request.challenge.nonce().clone(),
        role_id: request.challenge.role_id(),
        level: request.challenge.level(),
        issued_at: request.now,
        reason: request.reason,
    })?;
    let annex = ReceiptAnnex::new(AnnexFields {
        ticket: request.ticket.ticket(),
        organisation_id: request.record.organisation_id(),
        key_storage: key.storage(),
        counter_note: note,
        approval: request.override_decision,
        site_scope: if coverage.site_axis_checked() {
            SiteScope::Checked
        } else {
            SiteScope::Undeclared
        },
        history_depth: request.history_depth,
    })?;

    Ok(Issuance {
        code,
        receipt,
        annex,
    })
}

/// Reports whether two SEC1 encodings name one point.
///
/// The comparison goes through the curve rather than the bytes: the same key
/// travels compressed in one document and uncompressed in another, and a byte
/// comparison would call that a different operator.
fn same_point(left: &[u8], right: &[u8]) -> bool {
    match (
        p256::PublicKey::from_sec1_bytes(left),
        p256::PublicKey::from_sec1_bytes(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Splits a run of characters into groups for reading aloud.
fn spoken(value: &str) -> String {
    value
        .chars()
        .collect::<Vec<_>>()
        .chunks(SPOKEN_GROUP)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{issue, spoken, IssuanceRequest};
    use crate::codes::annex::{KeyStorage, SiteScope};
    use crate::codes::counter::{CounterNote, CounterOverride, CounterRefusal, KnownCounter};
    use crate::codes::tests::fixtures;
    use crate::codes::Refusal;
    use tessera_codes_contract::key::Epoch;
    use tessera_codes_contract::time::ClaimedTime;

    /// The request every test starts from: covered, grounded, at the first
    /// counter of the epoch with no receipts behind it.
    fn request(world: &fixtures::World) -> IssuanceRequest<'_> {
        IssuanceRequest {
            challenge: &world.challenge,
            record: &world.record,
            ticket: &world.ticket,
            params: &world.params,
            device_scope: Some(&world.device_scope),
            reason: "work order 42",
            now: fixtures::NOW,
            known_counter: None,
            history_depth: 0,
            override_decision: None,
        }
    }

    #[test]
    fn a_covered_request_produces_a_code_and_a_receipt() {
        let world = fixtures::world();
        let issuance = issue(&request(&world), &world.anchors, &world.operator_key).unwrap();

        assert_eq!(issuance.code.as_str().len(), 8);
        assert_eq!(issuance.receipt.reason(), "work order 42");
        assert_eq!(issuance.receipt.role_id(), "ops.dc.senior");
        assert_eq!(issuance.annex.key_storage(), KeyStorage::Software);
        assert_eq!(issuance.annex.counter_note(), CounterNote::FirstOfEpoch);
        assert_eq!(issuance.annex.site_scope(), SiteScope::Checked);
        assert_eq!(issuance.annex.approver(), None);
    }

    #[test]
    fn the_device_arrives_at_the_same_code() {
        let world = fixtures::world();
        let issuance = issue(&request(&world), &world.anchors, &world.operator_key).unwrap();
        // The device derives with its own key against the operator's public
        // half; the code it verifies is the one the operator read out.
        assert_eq!(
            fixtures::device_side_code(&world),
            issuance.code.as_str().to_owned()
        );
    }

    #[test]
    fn an_issuance_without_grounds_computes_nothing() {
        let world = fixtures::world();
        for blank in ["", "   ", "\t"] {
            let mut request = request(&world);
            request.reason = blank;
            assert_eq!(
                issue(&request, &world.anchors, &world.operator_key)
                    .map(|_| ())
                    .unwrap_err(),
                Refusal::MissingReason
            );
        }
    }

    #[test]
    fn a_record_whose_organisation_signature_was_edited_is_refused() {
        let mut world = fixtures::world();
        world.record = fixtures::record_with_broken_organisation_signature(&world);
        assert!(matches!(
            issue(&request(&world), &world.anchors, &world.operator_key),
            Err(Refusal::Record(_))
        ));
    }

    #[test]
    fn a_record_without_a_proof_of_possession_is_refused() {
        let mut world = fixtures::world();
        world.record = fixtures::record_with_foreign_possession_signature(&world);
        assert!(matches!(
            issue(&request(&world), &world.anchors, &world.operator_key),
            Err(Refusal::Record(_))
        ));
    }

    #[test]
    fn an_expired_ticket_is_refused() {
        let world = fixtures::world();
        let mut request = request(&world);
        request.now = ClaimedTime::new(fixtures::TICKET_NOT_AFTER + 1);
        assert!(matches!(
            issue(&request, &world.anchors, &world.operator_key),
            Err(Refusal::Ticket(_))
        ));
    }

    #[test]
    fn a_request_outside_the_ticket_is_refused_before_any_key_is_touched() {
        let world = fixtures::world();
        let challenge = fixtures::challenge_with(|input| input.level = 9);
        let mut request = request(&world);
        request.challenge = &challenge;
        assert!(matches!(
            issue(&request, &world.anchors, &world.operator_key),
            Err(Refusal::ScopeLevel { .. })
        ));
    }

    #[test]
    fn a_counter_running_ahead_is_refused() {
        let world = fixtures::world();
        let challenge = fixtures::challenge_with(|input| input.counter = 5);
        let mut request = request(&world);
        request.challenge = &challenge;
        let known = KnownCounter {
            epoch: Epoch::new(fixtures::EPOCH),
            counter: 1,
            nonce: "0000014711".to_owned(),
        };
        request.known_counter = Some(&known);
        request.history_depth = 1;
        assert!(matches!(
            issue(&request, &world.anchors, &world.operator_key),
            Err(Refusal::Counter(CounterRefusal::Ahead { .. }))
        ));
    }

    #[test]
    fn an_override_of_a_challenge_the_counter_admitted_is_refused() {
        let world = fixtures::world();
        let decision = CounterOverride::by("op-7", "op-42").unwrap();
        let mut request = request(&world);
        request.override_decision = Some(&decision);
        assert_eq!(
            issue(&request, &world.anchors, &world.operator_key)
                .map(|_| ())
                .unwrap_err(),
            Refusal::OverrideNotNeeded
        );
    }

    #[test]
    fn an_override_is_recorded_in_the_receipt_it_produced() {
        let world = fixtures::world();
        let decision = CounterOverride::by("op-7", "op-42").unwrap();
        let challenge = fixtures::challenge_with(|input| input.counter = 5);
        let mut request = request(&world);
        request.challenge = &challenge;
        let known = KnownCounter {
            epoch: Epoch::new(fixtures::EPOCH),
            counter: 1,
            nonce: "0000014711".to_owned(),
        };
        request.known_counter = Some(&known);
        request.history_depth = 1;
        request.override_decision = Some(&decision);

        let issuance = issue(&request, &world.anchors, &world.operator_key).unwrap();
        assert_eq!(issuance.annex.counter_note(), CounterNote::Overridden);
        assert_eq!(issuance.annex.approver(), Some("op-7"));
        assert!(issuance.annex.to_wire().contains("approver=op-7"));
    }

    #[test]
    fn a_key_the_ticket_does_not_name_is_refused() {
        let world = fixtures::world();
        let foreign = fixtures::software_key(fixtures::DEVICE_SEED);
        assert_eq!(
            issue(&request(&world), &world.anchors, &foreign)
                .map(|_| ())
                .unwrap_err(),
            Refusal::OperatorKeyMismatch
        );
    }

    #[test]
    fn an_undeclared_site_is_marked_in_the_receipt() {
        let world = fixtures::world();
        let mut request = request(&world);
        request.device_scope = None;
        let issuance = issue(&request, &world.anchors, &world.operator_key).unwrap();
        assert_eq!(issuance.annex.site_scope(), SiteScope::Undeclared);
    }

    #[test]
    fn a_code_is_read_out_in_groups() {
        assert_eq!(spoken("12345678"), "123 456 78");
    }
}

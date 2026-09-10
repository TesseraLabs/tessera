//! One issuance of a code, from the challenge the device showed to the grant
//! the issuing side is left holding.
//!
//! The whole refusal ladder is one function, [`issue`], and every wrapper of the
//! channel — the command line and the issuing service — calls it. A wrapper that
//! assembled the steps in its own order would be a second policy: the same
//! request would be refused by one and served by the other, and which of the two
//! was right would be settled at a site.
//!
//! The order of the ladder is deliberate:
//!
//! 1. **The two challenges are one.** The request carries a challenge and the
//!    caller supplies the signed one; a pair that disagrees would let the
//!    grounds of one attempt answer for the code of another.
//! 2. **The device record**, then **the ticket**. The scope and the term of
//!    documents nobody signed are not information about anything.
//! 3. **The coverage** of the request by the ticket — see
//!    [`crate::codes::scope`].
//! 4. **The key**, and only then the code. Key agreement is the one step that
//!    reaches a token, so it happens after everything that can refuse the call
//!    without touching one. It is performed against the ephemeral point the
//!    challenge carries — the device key in the record identifies the device,
//!    it does not derive the code.
//!
//! The grounds are not a rung here, and their absence from the list is not an
//! omission. Nothing is computed for an issuance nobody can answer for later —
//! but that is enforced where the document is assembled: an
//! [`tessera_codes_contract::request::EngineerRequest`] without grounds does not
//! come into being, so a request that reached this function has them. A rung
//! that no input can reach is a rung no test can prove, and this crate does not
//! keep those; the caller that reads a request off a wire maps the refusal of
//! the parser onto the same class token an operator sees.
//!
//! The check character of the device number is checked before all of this,
//! where the challenge is parsed: a number typed wrong never reaches a
//! computation, and the engineer hears about the typo rather than about a code
//! that does not fit.
//!
//! # What comes out, and what does not
//!
//! An issuance yields the code, the grant **without the signature of the issuing
//! side**, and the custody tier of the agreement key. The signature is missing
//! because the key that makes it is not the key that agreed the secret: this
//! function holds the second and never the first, and a value that pretended
//! otherwise would be a signed document nobody signed. The custody tier is here
//! because after the fact nothing distinguishes a code computed with a key that
//! never left a token from one computed with a key file — except what was
//! written down at the moment it happened.

use tessera_codes_contract::challenge::SignedChallenge;
use tessera_codes_contract::code::{compute_code, Code};
use tessera_codes_contract::grant::UnsignedGrant;
use tessera_codes_contract::key::{derive_key, KeyContext};
use tessera_codes_contract::params::FleetParams;
use tessera_codes_contract::registry::DeviceRecord;
use tessera_codes_contract::request::SignedRequest;
use tessera_codes_contract::signature::SignatureVerifier;
use tessera_codes_contract::ticket::SignedTicket;
use tessera_codes_contract::time::ClaimedTime;

use crate::codes::agreement::{KeyStorage, OperatorKey};
use crate::codes::scope::{self, Coverage, DeviceScope, SiteScope};
use crate::codes::Refusal;

/// One request the issuing side is answering.
#[derive(Debug, Clone, Copy)]
pub struct IssuanceRequest<'a> {
    /// The challenge the device showed, with its signature.
    pub challenge: &'a SignedChallenge,
    /// The request the engineer signed, grounds included.
    pub request: &'a SignedRequest,
    /// The signed record of the device.
    pub record: &'a DeviceRecord,
    /// The ticket the issuing side is working under.
    pub ticket: &'a SignedTicket,
    /// Parameters of the fleet.
    pub params: &'a FleetParams,
    /// Where the fleet says the device stands, when the caller supplied it.
    pub device_scope: Option<&'a DeviceScope>,
    /// The moment the issuing side claims.
    pub now: ClaimedTime,
}

/// What one issuance leaves behind.
#[derive(Debug, Clone)]
pub struct Issuance {
    /// The code to hand to the engineer.
    pub code: Code,
    /// The grant, short of the signature of the issuing side: the signature is
    /// put on by whoever holds the signing key, which this function does not.
    pub grant: UnsignedGrant,
    /// Custody tier of the agreement key of this issuance.
    pub key_storage: KeyStorage,
    /// Whether the site axis of the ticket was checked against the device.
    ///
    /// Decided here, where the coverage was decided, and carried out with the
    /// issuance rather than recomputed by whoever writes the journal. Three
    /// places computing it from "was a device scope supplied" is three places
    /// that can come to disagree, and the one that disagrees quietly is the one
    /// that writes the record an auditor reads.
    pub site_scope: SiteScope,
}

/// Answers one challenge, or refuses it.
///
/// # Errors
///
/// The [`Refusal`] naming the first step of the ladder that did not pass. No
/// code is computed and no grant is assembled for a refused request.
pub fn issue(
    request: &IssuanceRequest<'_>,
    verifier: &impl SignatureVerifier,
    // `?Sized` so a caller that only knows at run time where the agreement key
    // is — a token or, in the software mode, a file — can pass the key it built
    // behind a reference without a second copy of this function per backend.
    key: &(impl OperatorKey + ?Sized),
) -> Result<Issuance, Refusal> {
    let challenge = request.challenge.challenge();

    // Two documents carry a challenge here — the one the device signed and the
    // one the engineer signed their request over — and they are compared before
    // anything is checked about either. A pair that disagrees is not a stale
    // copy to be tolerated: it is grounds recorded for one attempt answering for
    // the code of another, and the journal would then pair a login with a
    // request nobody made for it.
    if request.request.request().challenge() != challenge {
        return Err(Refusal::RequestChallengeMismatch);
    }

    request.record.verify(verifier)?;
    request.ticket.verify(verifier, request.now)?;

    let coverage = Coverage {
        challenge,
        record: request.record,
        ticket: request.ticket.ticket(),
        device_scope: request.device_scope,
    };
    scope::check(&coverage)?;

    // After the coverage and not before it, for one reason: a challenge and a
    // record about two different devices are refused by the step above in the
    // fleet's own words — which number the device showed, which number the
    // record carries — and a signature check running first would answer the same
    // situation with `the device did not sign this`. Both are refusals; only
    // one of them tells the caller what to do about it. Before the key
    // agreement, which is the step that reaches a token.
    request.challenge.verify(request.record, verifier)?;

    if !same_point(
        key.public_point().as_slice(),
        request.ticket.ticket().public_key().as_bytes(),
    ) {
        return Err(Refusal::OperatorKeyMismatch);
    }

    // Against the ephemeral point of this attempt, not against the key the
    // device record carries: the record says which device holds which
    // long-lived key, and a code derived from that key would be computable by
    // anyone who ever held it. The record is still checked — it is what says
    // the device is the one it claims — it just does not enter the code.
    let secret = key.agree(challenge.ephemeral_point().as_bytes())?;
    let context = KeyContext::new(challenge.device_number(), request.ticket.context_hash()?);
    let derived = derive_key(&secret, &context)?;
    let code = compute_code(&derived, &challenge.code_input(), request.params)?;

    let grant = UnsignedGrant::new(request.request.clone(), challenge.server_id())?;

    Ok(Issuance {
        code,
        grant,
        key_storage: key.storage(),
        site_scope: coverage.site_scope(),
    })
}

/// Reports whether two SEC1 encodings name one point.
///
/// The comparison goes through the curve rather than the bytes: the same key
/// travels compressed in one document and uncompressed in another, and a byte
/// comparison would call that a different issuing side.
fn same_point(left: &[u8], right: &[u8]) -> bool {
    match (
        p256::PublicKey::from_sec1_bytes(left),
        p256::PublicKey::from_sec1_bytes(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{issue, IssuanceRequest};
    use crate::codes::agreement::KeyStorage;
    use crate::codes::tests::fixtures;
    use crate::codes::Refusal;
    use tessera_codes_contract::time::ClaimedTime;

    /// The request every test starts from: covered and grounded.
    fn request<'a>(
        world: &'a fixtures::World,
        signed_request: &'a tessera_codes_contract::request::SignedRequest,
    ) -> IssuanceRequest<'a> {
        IssuanceRequest {
            challenge: &world.challenge,
            request: signed_request,
            record: &world.record,
            ticket: &world.ticket,
            params: &world.params,
            device_scope: Some(&world.device_scope),
            now: fixtures::NOW,
        }
    }

    #[test]
    fn a_covered_request_produces_a_code_and_a_grant_to_be_signed() {
        let world = fixtures::world();
        let signed = fixtures::signed_request(&world);
        let issuance = issue(
            &request(&world, &signed),
            &world.anchors,
            &world.operator_key,
        )
        .unwrap();

        assert_eq!(
            issuance.code.as_str().len(),
            usize::from(world.params.code_len())
        );
        // The grant answers the request that was brought, and nothing was
        // rebuilt from it: a grant assembled out of fields copied one by one
        // would answer a request nobody signed.
        assert_eq!(issuance.grant.request(), &signed);
        assert_eq!(issuance.grant.server_id(), "op-42");
        assert_eq!(
            issuance.grant.request().request().grounds(),
            fixtures::GROUNDS
        );
    }

    #[test]
    fn the_custody_tier_of_the_key_that_agreed_the_secret_comes_out_with_the_code() {
        // The tier is not decoration on the way to the journal: it is the only
        // thing that will ever distinguish this code from one computed with a
        // key that never left a token, and the distinction has to be made at
        // the moment it happens, by the thing that knows.
        let world = fixtures::world();
        let signed = fixtures::signed_request(&world);
        let issuance = issue(
            &request(&world, &signed),
            &world.anchors,
            &world.operator_key,
        )
        .unwrap();
        assert_eq!(issuance.key_storage, KeyStorage::Software);
    }

    #[test]
    fn a_request_signed_over_another_challenge_is_refused() {
        // The grounds of one attempt answering for the code of another: the
        // pair is refused before any document is checked, because after the
        // code is computed nothing in the journal would show that the two
        // halves came from different attempts.
        let world = fixtures::world();
        let other = fixtures::signed_challenge_with(|input| input.level = 1);
        let signed = fixtures::signed_request_for(other.challenge(), fixtures::GROUNDS);
        assert_eq!(
            issue(
                &request(&world, &signed),
                &world.anchors,
                &world.operator_key
            )
            .map(|_| ())
            .unwrap_err(),
            Refusal::RequestChallengeMismatch
        );
    }

    #[test]
    fn the_device_arrives_at_the_same_code() {
        let world = fixtures::world();
        let signed = fixtures::signed_request(&world);
        let issuance = issue(
            &request(&world, &signed),
            &world.anchors,
            &world.operator_key,
        )
        .unwrap();
        // The device derives with its own ephemeral key against the public half
        // of the agreement key; the code it verifies is the one that was issued.
        assert_eq!(
            fixtures::device_side_code(&world),
            issuance.code.as_str().to_owned()
        );
    }

    #[test]
    fn a_request_without_grounds_does_not_come_into_being() {
        // The guarantee "no code is computed for an issuance nobody can answer
        // for" is kept where the document is assembled, not by a rung of this
        // ladder: a request without grounds does not exist, so there is nothing
        // to hand to `issue`. This test states that, so that a future edit
        // loosening the contract is a red test here and not a silent hole.
        let world = fixtures::world();
        for blank in ["", "   ", "\t"] {
            assert_eq!(
                tessera_codes_contract::request::EngineerRequest::new(
                    tessera_codes_contract::request::RequestFields {
                        challenge: world.challenge.challenge().clone(),
                        grounds: blank,
                        grounds_reference: None,
                        requested_at: fixtures::NOW,
                        four_eyes: tessera_codes_contract::request::FourEyesDigest::of_policy(
                            b"off"
                        ),
                    }
                )
                .map(|_| ())
                .unwrap_err(),
                tessera_codes_contract::request::RequestError::MissingGrounds
            );
        }
    }

    #[test]
    fn a_record_whose_organisation_signature_was_edited_is_refused() {
        let mut world = fixtures::world();
        world.record = fixtures::record_with_broken_organisation_signature(&world);
        let signed = fixtures::signed_request(&world);
        assert!(matches!(
            issue(
                &request(&world, &signed),
                &world.anchors,
                &world.operator_key
            ),
            Err(Refusal::Record(_))
        ));
    }

    #[test]
    fn a_record_without_a_proof_of_possession_is_refused() {
        let mut world = fixtures::world();
        world.record = fixtures::record_with_foreign_possession_signature(&world);
        let signed = fixtures::signed_request(&world);
        assert!(matches!(
            issue(
                &request(&world, &signed),
                &world.anchors,
                &world.operator_key
            ),
            Err(Refusal::Record(_))
        ));
    }

    #[test]
    fn a_challenge_the_device_did_not_sign_is_refused() {
        // The values are all the device's own — number, epoch, nonce, role,
        // level — and only the signature is somebody else's. Without the
        // signature check nothing here would tell this apart from a challenge
        // the device stated, because there is nothing else to tell it by.
        let world = fixtures::world();
        let composed =
            fixtures::signed_by(fixtures::challenge_with(|_| {}), fixtures::OPERATOR_SEED);
        // The request is signed over the very challenge that is offered, so the
        // refusal below can only come from the signature of the device.
        let signed = fixtures::signed_request_for(composed.challenge(), fixtures::GROUNDS);
        let mut request = request(&world, &signed);
        request.challenge = &composed;

        let refusal = issue(&request, &world.anchors, &world.operator_key).unwrap_err();
        assert!(matches!(refusal, Refusal::ChallengeSignature(_)));
        assert_eq!(refusal.class(), "challenge_signature_rejected");
        assert_eq!(refusal.group(), crate::codes::RefusalGroup::Trust);
    }

    #[test]
    fn a_challenge_edited_after_it_was_signed_is_refused() {
        // The signature of the device travels verbatim, the level asked for is
        // raised. This is the shape a rewritten challenge takes on the way to
        // the issuing side, and it is the whole reason the signature covers the
        // canonical bytes rather than the device number alone.
        let world = fixtures::world();
        let signed = fixtures::signed_challenge_with(|_| {});
        let raised = tessera_codes_contract::challenge::SignedChallenge::new(
            fixtures::challenge_with(|input| input.level = 1),
            signed.signature().clone(),
        );
        let signed_request = fixtures::signed_request_for(raised.challenge(), fixtures::GROUNDS);
        let mut request = request(&world, &signed_request);
        request.challenge = &raised;
        assert!(matches!(
            issue(&request, &world.anchors, &world.operator_key),
            Err(Refusal::ChallengeSignature(_))
        ));
    }

    #[test]
    fn the_disk_holders_challenge_passes_issuance_and_is_left_to_the_device() {
        // Условие кейса CODE-014, проверенное здесь, а не рассуждением: у
        // снявшего диск ключ устройства есть, поэтому подменённый challenge он
        // подписывает законно, и выдача обязана его ПРОПУСТИТЬ. Отказ на этой
        // стороне означал бы, что кейс стережёт проверку подписи вместо
        // проверки, ради которой он написан, — что код из статического ключа
        // устройства не сходится при сверке НА УСТРОЙСТВЕ.
        //
        // Эфемерная точка здесь — открытая половина статического ключа
        // устройства (тот же seed), то есть ровно то, что подставляет хелпер
        // стенда.
        let world = fixtures::world();
        let doctored = fixtures::signed_by(
            fixtures::challenge_with(|input| input.ephemeral_seed = fixtures::DEVICE_SEED),
            fixtures::DEVICE_SEED,
        );
        let signed = fixtures::signed_request_for(doctored.challenge(), fixtures::GROUNDS);
        let mut request = request(&world, &signed);
        request.challenge = &doctored;

        let issued = issue(&request, &world.anchors, &world.operator_key)
            .map(|issuance| issuance.code.as_str().len());
        assert_eq!(
            issued,
            Ok(usize::from(world.params.code_len())),
            "выдача обязана посчитать код: подпись устройства законна"
        );
    }

    #[test]
    fn an_expired_ticket_is_refused() {
        let world = fixtures::world();
        let signed = fixtures::signed_request(&world);
        let mut request = request(&world, &signed);
        request.now = ClaimedTime::new(fixtures::TICKET_NOT_AFTER + 1);
        assert!(matches!(
            issue(&request, &world.anchors, &world.operator_key),
            Err(Refusal::Ticket(_))
        ));
    }

    #[test]
    fn a_request_outside_the_ticket_is_refused_before_any_key_is_touched() {
        let world = fixtures::world();
        let challenge = fixtures::signed_challenge_with(|input| input.level = 9);
        let signed = fixtures::signed_request_for(challenge.challenge(), fixtures::GROUNDS);
        let mut request = request(&world, &signed);
        request.challenge = &challenge;
        assert!(matches!(
            issue(&request, &world.anchors, &world.operator_key),
            Err(Refusal::ScopeLevel { .. })
        ));
    }

    #[test]
    fn a_key_the_ticket_does_not_name_is_refused() {
        let world = fixtures::world();
        let foreign = fixtures::software_key(fixtures::DEVICE_SEED);
        let signed = fixtures::signed_request(&world);
        assert_eq!(
            issue(&request(&world, &signed), &world.anchors, &foreign)
                .map(|_| ())
                .unwrap_err(),
            Refusal::OperatorKeyMismatch
        );
    }

    #[test]
    fn the_site_axis_comes_out_with_the_issuance() {
        // Decided once, where the coverage was decided. Three consumers used to
        // recompute it from "was a device scope supplied", and the one that
        // came to disagree quietly would have been the one writing the record
        // an auditor reads.
        let world = fixtures::world();
        let signed = fixtures::signed_request(&world);

        let declared = issue(
            &request(&world, &signed),
            &world.anchors,
            &world.operator_key,
        )
        .unwrap();
        assert_eq!(declared.site_scope, crate::codes::scope::SiteScope::Checked);

        let mut undeclared = request(&world, &signed);
        undeclared.device_scope = None;
        let issuance = issue(&undeclared, &world.anchors, &world.operator_key).unwrap();
        assert_eq!(
            issuance.site_scope,
            crate::codes::scope::SiteScope::Undeclared
        );
    }

    #[test]
    fn an_undeclared_site_still_produces_a_code() {
        // The device checks the site axis itself before it accepts a code, so
        // an undeclared site is not a refusal here. What it is, is a fact the
        // caller has to carry into the journal record — see
        // `crate::codes::scope::Coverage::site_scope`.
        let world = fixtures::world();
        let signed = fixtures::signed_request(&world);
        let mut request = request(&world, &signed);
        request.device_scope = None;
        assert!(issue(&request, &world.anchors, &world.operator_key).is_ok());
    }
}

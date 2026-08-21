//! End-to-end tests of the code method against real artefacts.
//!
//! The fixture stands in for the whole channel: a fleet authority that signs a
//! ticket, an operator whose key the ticket carries, a device whose key lives
//! in a PKCS#12 container, and a cabinet that computes the code with the same
//! contract crate the device verifies it with. Nothing here reimplements the
//! formula — the "cabinet" side calls [`compute_code`] exactly as the browser
//! build does.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed setup step in a test should fail the test on the spot"
)]

use std::time::Duration;

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509Builder, X509NameBuilder};
use tempfile::TempDir;

use tessera_codes_contract::canon::Level;
use tessera_codes_contract::challenge::{Challenge, ChallengeFields};
use tessera_codes_contract::code::compute_code;
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::key::{derive_key, Epoch, KeyAgreement as _, KeyContext};
use tessera_codes_contract::params::FleetParams;
use tessera_codes_contract::profile::AlgorithmProfile;
use tessera_codes_contract::signature::PublicKey;
use tessera_codes_contract::ticket::{
    ServerTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput,
};
use tessera_codes_contract::time::ClaimedTime;

use super::agreement::tests::p256_pair;
use super::agreement::StaticKeyAgreement;
use super::boot::BootMarkers;
use super::throttle;
use super::tickets::tests::Authority;
use super::tickets::DeviceScope;
use super::{
    artefacts, epoch, AttemptRequest, CodeLoginError, CodeMethod, CodesConfig, CodesPaths,
    LocalRoles, StartedAttempt, DEFAULT_CODE_TTL,
};

/// The fixture container carries no password, the way a stored one does: the
/// PIN is a form of delivery, and by the time a container sits in the store the
/// import has already opened it once and re-written the key without one.
const STORED_CONTAINER_PASSWORD: &str = "";

/// Role the fixture logs into.
const ROLE: &str = "oper";

/// Issuing side the fixture ticket belongs to.
const SERVER: &str = "op-42";

/// Personal number the engineer of the fixture gives at the device.
const ENGINEER: &str = "eng-1";

/// The whole channel, on disk.
struct Fixture {
    _dir: TempDir,
    config: CodesConfig,
    roles: LocalRoles,
    operator_key: PKey<Private>,
    /// The long-lived key of the device, as the container on disk holds it.
    ///
    /// Kept so a test can play the one who lifted that container: it is what
    /// the code used to be derived from, and what must not derive one now.
    device_key: PKey<Private>,
    /// The public half of that key, as the registry record of the device
    /// carries it — the value the issuing side checks the challenge against.
    device_point: Vec<u8>,
    ticket: SignedTicket,
}

impl Fixture {
    /// Builds a fixture whose ticket admits levels up to `max_level` and whose
    /// device defines the roles in `local_roles`.
    fn build(params: FleetParams, max_level: u32, local_roles: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = CodesPaths::under(dir.path());
        std::fs::create_dir_all(&paths.state_dir).unwrap();

        let (device_key, device_point) = p256_pair();
        std::fs::write(&paths.device_key_container, container(&device_key)).unwrap();

        let (operator_key, operator_point) = p256_pair();
        let authority = Authority::new();
        let ticket = authority.sign(
            ServerTicket::new(
                SERVER,
                PublicKey::new(operator_point).unwrap(),
                TicketScope::new(TicketScopeInput {
                    tags: vec!["dc-1".to_owned(), "hq".to_owned()],
                    roles: vec![ROLE.to_owned()],
                    region: "ru-south".to_owned(),
                    max_level: Level::new(max_level),
                })
                .unwrap(),
                ClaimedTime::new(1_800_000_000),
                TicketNumber::parse("tk-17").unwrap(),
            )
            .unwrap(),
        );
        std::fs::write(&paths.tickets, format!("{}\n", ticket.to_wire())).unwrap();
        std::fs::write(
            &paths.ticket_authority,
            authority.public_key_pem().as_slice(),
        )
        .unwrap();

        let config = CodesConfig {
            paths,
            params,
            device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
            epoch: Epoch::new(7),
            device_scope: DeviceScope {
                tags: vec!["dc-1".to_owned()],
                region: "ru-south".to_owned(),
            },
            code_ttl: DEFAULT_CODE_TTL,
            gost_engine_path: None,
        };

        Self {
            _dir: dir,
            config,
            roles: LocalRoles::from_ids(local_roles.iter().copied()),
            operator_key,
            device_key,
            device_point,
            ticket,
        }
    }

    /// The default fixture: a ticket up to level 1, and a device that defines
    /// the role the ticket names.
    fn new() -> Self {
        Self::build(FleetParams::defaults(), 1, &[ROLE])
    }

    fn method(&self) -> Result<CodeMethod, CodeLoginError> {
        CodeMethod::open(self.config.clone(), self.roles.clone())
    }

    fn request(level: u32) -> AttemptRequest<'static> {
        AttemptRequest {
            role_id: ROLE,
            level: Level::new(level),
            server_id: SERVER,
            engineer_id: ENGINEER,
            now: ClaimedTime::new(1_700_000_000),
        }
    }

    /// What the issuing side computes for a challenge it was given.
    ///
    /// Its key against the ephemeral point of that challenge — the pair of this
    /// attempt and no other. Nothing about the device key of the fixture enters
    /// it, which is the whole change: what the issuing side answers is bound to
    /// an attempt that the device has to be running for the point to exist.
    fn cabinet_code(&self, challenge: &Challenge) -> String {
        self.code_agreed_with(challenge, challenge.ephemeral_point().as_bytes())
    }

    /// The code that comes out of agreeing the issuing key against `point`.
    ///
    /// Split out so a test can put a point there that no honest issuance would
    /// have used.
    fn code_agreed_with(&self, challenge: &Challenge, point: &[u8]) -> String {
        let secret = StaticKeyAgreement::new(&self.operator_key, AlgorithmProfile::P256)
            .unwrap()
            .agree(point)
            .unwrap();
        let context = KeyContext::new(
            &self.config.device_number,
            self.ticket.context_hash().unwrap(),
        );
        let key = derive_key(&secret, &context).unwrap();
        compute_code(&key, &challenge.code_input(), &self.config.params)
            .unwrap()
            .as_str()
            .to_owned()
    }

    fn revoke_the_ticket(&self) {
        std::fs::write(&self.config.paths.ticket_revocations, "tk-17\n").unwrap();
    }
}

/// Markers `step` issuance windows after boot.
///
/// Used where a test needs several challenges and is not about the rate at
/// which they may be asked for: putting each one in a window of its own keeps
/// the issuance limit out of the way without turning it off.
fn after_a_window(step: u64) -> BootMarkers {
    markers(
        "boot-a",
        100 + step * (throttle::CHALLENGE_WINDOW.as_secs() + 1),
    )
}

fn markers(boot: &str, since_boot: u64) -> BootMarkers {
    BootMarkers::new(boot, Duration::from_secs(since_boot))
}

/// A PKCS#12 container holding `key` and a self-signed certificate for it.
fn container(key: &PKey<Private>) -> Vec<u8> {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "device 77-000123")
        .unwrap();
    let name = name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder
        .sign(key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let cert = builder.build();

    openssl::pkcs12::Pkcs12::builder()
        .name("device")
        .pkey(key)
        .cert(&cert)
        .build2(STORED_CONTAINER_PASSWORD)
        .unwrap()
        .to_der()
        .unwrap()
}

/// Starts an attempt on a fresh method and returns both.
fn start(fixture: &Fixture, level: u32, at: &BootMarkers) -> (CodeMethod, StartedAttempt) {
    let method = fixture.method().unwrap();
    let attempt = method
        .begin_with_markers(&Fixture::request(level), at)
        .unwrap();
    (method, attempt)
}

#[test]
fn a_dictated_code_admits_the_engineer() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);

    // What the engineer reads out, and what the operator reads back.
    assert!(attempt.spoken_form().contains(' '));
    assert_eq!(attempt.ticket_number(), "tk-17");
    let code = fixture.cabinet_code(attempt.challenge());

    let accepted = method
        .verify_with_markers(&mut attempt, &code, &markers("boot-a", 140))
        .unwrap();
    assert_eq!(accepted.role_id, ROLE);
    assert_eq!(accepted.level, Level::new(1));
    assert_eq!(accepted.ticket_number, "tk-17");
    // The ceiling travels with the verdict: it is what the session label is
    // bounded by, and the device states no linear bound of its own.
    assert_eq!(accepted.level_ceiling, Level::new(1));
}

/// Retells the challenge of an attempt with one field changed.
///
/// What somebody standing in front of the device can do without the device's
/// help: take what it printed and hand the issuing side a version that says
/// something else. Everything the two sides agree on is in these bytes, so a
/// field that does not reach the MAC input can be changed here without the
/// code changing — which is exactly what these tests are for.
fn retold(challenge: &Challenge, edit: impl FnOnce(&mut ChallengeFields<'_>)) -> Challenge {
    let mut fields = ChallengeFields {
        device_number: challenge.device_number().clone(),
        epoch: challenge.epoch(),
        nonce: challenge.nonce().clone(),
        role_id: challenge.role_id(),
        level: challenge.level(),
        server_id: challenge.server_id(),
        engineer_id: challenge.engineer_id(),
        ephemeral_point: challenge.ephemeral_point().clone(),
    };
    edit(&mut fields);
    Challenge::new(fields).unwrap()
}

#[test]
fn a_code_cut_for_one_engineer_does_not_admit_another() {
    // One attempt, one nonce, one ephemeral pair — and two names. The engineer
    // who started the attempt gave their number; somebody retells the same
    // challenge to the issuing side under another number and brings the code
    // back. Nothing about the nonce or the timing refuses that; the personal
    // number in the MAC input is the only thing that does.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    assert_eq!(attempt.challenge().engineer_id(), ENGINEER);

    let under_another_name = retold(attempt.challenge(), |fields| {
        fields.engineer_id = "eng-2";
    });
    let code_for_them = fixture.cabinet_code(&under_another_name);

    assert!(
        matches!(
            method.verify_with_markers(&mut attempt, &code_for_them, &boot),
            Err(CodeLoginError::Denied)
        ),
        "a code cut under another engineer's number must not admit this attempt"
    );

    // The attempt is otherwise sound: the code cut under the number the
    // engineer actually gave is accepted. Without this half the test would go
    // green on any refusal at all.
    let code_for_me = fixture.cabinet_code(attempt.challenge());
    assert!(
        method
            .verify_with_markers(&mut attempt, &code_for_me, &boot)
            .is_ok(),
        "the code cut under the engineer's own number must be accepted"
    );
}

#[test]
fn a_code_cut_under_one_epoch_does_not_survive_a_key_rotation() {
    // The epoch used to reach the code through the key it named; it does not
    // any more — the long-lived key left the derivation — so unless the epoch
    // is in the MAC input, a code cut under one epoch would meet under the
    // next. Same attempt, same everything, one number of epoch apart.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);

    let under_the_next_epoch = retold(attempt.challenge(), |fields| {
        fields.epoch = Epoch::new(fields.epoch.get() + 1);
    });
    let code_of_another_epoch = fixture.cabinet_code(&under_the_next_epoch);

    assert!(
        matches!(
            method.verify_with_markers(&mut attempt, &code_of_another_epoch, &boot),
            Err(CodeLoginError::Denied)
        ),
        "a code cut under another epoch must not admit this attempt"
    );

    let code_of_this_epoch = fixture.cabinet_code(attempt.challenge());
    assert!(
        method
            .verify_with_markers(&mut attempt, &code_of_this_epoch, &boot)
            .is_ok(),
        "the code cut under the epoch of the challenge must be accepted"
    );
}

#[test]
fn the_challenge_carries_a_signature_the_device_record_verifies() {
    // What the issuing side does with a challenge it receives, done here with
    // the other library: the device signs through OpenSSL, this checks through
    // the `p256` crate. Two implementations agreeing is worth more than one
    // implementation agreeing with itself — and this is the only place in the
    // workspace where the signature the device actually makes meets the key the
    // registry actually holds.
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use sha2::{Digest as _, Sha256};

    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (_method, attempt) = start(&fixture, 1, &boot);
    let signed = attempt.signed_challenge();

    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&fixture.device_point).unwrap();
    let signature = p256::ecdsa::Signature::from_der(signed.signature().as_bytes()).unwrap();
    let digest = Sha256::digest(signed.challenge().signing_message().unwrap());

    assert!(
        verifying.verify_prehash(&digest, &signature).is_ok(),
        "the signature of the device must hold over the message of its own challenge"
    );

    // And it holds over that message only: the same signature against the
    // canonical bytes without the label verifies against nothing.
    let bare = Sha256::digest(signed.challenge().encode().unwrap());
    assert!(verifying.verify_prehash(&bare, &signature).is_err());
}

#[test]
fn the_long_lived_device_key_does_not_compute_a_code() {
    // The disk was lifted: a preparer kept a copy, a backup was restored
    // somewhere else, the machine was stolen. Everything the device stores is
    // in the attacker's hands, the key container included, and the ticket they
    // need travels in the open. What they cannot have is the private half of
    // the pair this attempt agreed on — it was made when the attempt started
    // and it never left the memory of the process.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);

    // The exchange the code used to come out of: the long-lived device key
    // against the key the ticket carries. Nothing here needs the device to be
    // running.
    let secret = StaticKeyAgreement::new(&fixture.device_key, AlgorithmProfile::P256)
        .unwrap()
        .agree(fixture.ticket.ticket().public_key().as_bytes())
        .unwrap();
    let context = KeyContext::new(
        &fixture.config.device_number,
        fixture.ticket.context_hash().unwrap(),
    );
    let key = derive_key(&secret, &context).unwrap();
    let forged = compute_code(
        &key,
        &attempt.challenge().code_input(),
        &fixture.config.params,
    )
    .unwrap();

    assert!(
        matches!(
            method.verify_with_markers(&mut attempt, forged.as_str(), &boot),
            Err(CodeLoginError::Denied)
        ),
        "a code derived from the stored device key must not open the attempt"
    );

    // The attempt was otherwise sound: the code the issuing side computes for
    // the same challenge is still accepted here. Without this half the test
    // would go green on any refusal at all — a broken fixture, a spent budget,
    // an attempt nobody was holding — and would stop guarding anything.
    let honest = fixture.cabinet_code(attempt.challenge());
    assert!(
        method
            .verify_with_markers(&mut attempt, &honest, &boot)
            .is_ok(),
        "the code of the issuing side must still be accepted"
    );
}

#[test]
fn the_ceiling_of_the_verdict_is_the_ceiling_of_the_ticket() {
    // A ticket that reaches level 3, used for a login at level 1: the level of
    // the login and the ceiling it was authorised under are different numbers
    // and are reported as such.
    let fixture = Fixture::build(FleetParams::defaults(), 3, &[ROLE]);
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    let accepted = method
        .verify_with_markers(&mut attempt, &code, &boot)
        .unwrap();
    assert_eq!(accepted.level, Level::new(1));
    assert_eq!(accepted.level_ceiling, Level::new(3));
}

#[test]
fn a_level_equal_to_the_ceiling_of_the_ticket_is_admitted() {
    let fixture = Fixture::build(FleetParams::defaults(), 2, &[ROLE]);
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 2, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    let accepted = method
        .verify_with_markers(&mut attempt, &code, &boot)
        .unwrap();
    assert_eq!(accepted.level, Level::new(2));
    assert_eq!(accepted.level_ceiling, Level::new(2));
}

#[test]
fn the_method_needs_no_server_configuration_of_any_kind() {
    // The fixture never names a URL, and nothing in the path above reads one:
    // the dictation mode is complete without a site to point at.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method
        .verify_with_markers(&mut attempt, &code, &boot)
        .is_ok());
}

#[test]
fn a_wrong_code_does_not_admit_anybody() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);

    assert!(matches!(
        method.verify_with_markers(&mut attempt, "00000000", &boot),
        Err(CodeLoginError::Denied)
    ));
    // The attempt survives one wrong code: the budget is larger than one.
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method
        .verify_with_markers(&mut attempt, &code, &boot)
        .is_ok());
}

#[test]
fn the_attempt_budget_of_a_nonce_runs_out() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let budget = fixture.config.params.attempts_per_nonce();

    for guess in 1..budget {
        assert!(
            matches!(
                method.verify_with_markers(&mut attempt, "00000000", &boot),
                Err(CodeLoginError::Denied)
            ),
            "guess {guess} should still be inside the budget"
        );
    }
    assert!(matches!(
        method.verify_with_markers(&mut attempt, "00000000", &boot),
        Err(CodeLoginError::AttemptsExhausted)
    ));

    // The attempt is over with the budget: the right code no longer helps, and
    // what comes back keeps saying the budget is what ended it.
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(matches!(
        method.verify_with_markers(&mut attempt, &code, &boot),
        Err(CodeLoginError::AttemptsExhausted)
    ));
}

#[test]
fn the_budget_is_not_refilled_by_a_new_process() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let budget = fixture.config.params.attempts_per_nonce();

    for _ in 1..budget {
        assert!(method
            .verify_with_markers(&mut attempt, "00000000", &boot)
            .is_err());
    }
    // A second process opens the method afresh and meets the same budget.
    let reopened = fixture.method().unwrap();
    assert!(matches!(
        reopened.verify_with_markers(&mut attempt, "00000000", &boot),
        Err(CodeLoginError::AttemptsExhausted)
    ));
}

#[test]
fn a_spent_nonce_is_refused_when_it_comes_back() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method
        .verify_with_markers(&mut attempt, &code, &boot)
        .is_ok());

    // The same code, in the same process and then in a new one after a reboot.
    assert!(matches!(
        method.verify_with_markers(&mut attempt, &code, &boot),
        Err(CodeLoginError::Denied)
    ));
    let after_reboot = fixture.method().unwrap();
    assert!(matches!(
        after_reboot.verify_with_markers(&mut attempt, &code, &markers("boot-b", 5)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_reboot_puts_out_a_pending_attempt() {
    let fixture = Fixture::new();
    let (method, mut attempt) = start(&fixture, 1, &markers("boot-a", 100));
    let code = fixture.cabinet_code(attempt.challenge());

    // The code was never used, and it still does not work: the attempt it
    // belongs to did not survive the restart.
    assert!(matches!(
        method.verify_with_markers(&mut attempt, &code, &markers("boot-b", 5)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_monotonic_clock_dragged_backwards_puts_out_a_pending_attempt() {
    let fixture = Fixture::new();
    let (method, mut attempt) = start(&fixture, 1, &markers("boot-a", 500));
    let code = fixture.cabinet_code(attempt.challenge());

    assert!(matches!(
        method.verify_with_markers(&mut attempt, &code, &markers("boot-a", 499)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_code_past_its_local_lifetime_is_refused() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    let too_late = markers("boot-a", 100 + DEFAULT_CODE_TTL.as_secs() + 1);
    assert!(matches!(
        method.verify_with_markers(&mut attempt, &code, &too_late),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_level_above_the_ceiling_of_the_ticket_is_refused_even_though_the_code_would_meet() {
    let fixture = Fixture::build(FleetParams::defaults(), 1, &[ROLE]);
    let method = fixture.method().unwrap();
    assert!(matches!(
        method.begin_with_markers(&Fixture::request(2), &markers("boot-a", 100)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_role_outside_the_ticket_is_refused_at_a_level_the_ticket_allows() {
    // The device defines a second role as well, so the local bound is not what
    // refuses here: the ticket names one role, and the level ceiling is not a
    // permission for the other.
    let fixture = Fixture::build(FleetParams::defaults(), 1, &[ROLE, "wide-sudo"]);
    let method = fixture.method().unwrap();
    let request = AttemptRequest {
        role_id: "wide-sudo",
        ..Fixture::request(1)
    };
    assert!(matches!(
        method.begin_with_markers(&request, &markers("boot-a", 100)),
        Err(CodeLoginError::Denied)
    ));
    // The role the ticket does name still works, at the same level.
    assert!(method
        .begin_with_markers(&Fixture::request(1), &markers("boot-a", 100))
        .is_ok());
}

#[test]
fn a_role_this_device_does_not_define_is_refused() {
    // The ticket names the role and reaches the level; the device does not
    // define the role at all, which is the residual local bound.
    let fixture = Fixture::build(FleetParams::defaults(), 1, &[]);
    let method = fixture.method().unwrap();
    assert!(matches!(
        method.begin_with_markers(&Fixture::request(1), &markers("boot-a", 100)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn the_device_puts_no_ceiling_of_its_own_on_the_level() {
    // The device defines the role and nothing more; every level the ticket
    // reaches is admitted, because a role slice states no linear bound. The
    // module read the role's category mask as a set of levels once, and this is
    // what that cost: a login at any level above the lowest bit was refused.
    let fixture = Fixture::build(FleetParams::defaults(), 3, &[ROLE]);
    let method = fixture.method().unwrap();
    for level in 0..=3 {
        assert!(
            method
                .begin_with_markers(&Fixture::request(level), &markers("boot-a", 100))
                .is_ok(),
            "level {level} is within the ticket and must be admitted",
        );
    }
}

#[test]
fn a_revoked_ticket_closes_the_method_for_that_operator() {
    let fixture = Fixture::new();
    fixture.revoke_the_ticket();
    let method = fixture.method().unwrap();
    assert!(matches!(
        method.begin_with_markers(&Fixture::request(1), &markers("boot-a", 100)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_revocation_that_arrives_between_two_logins_takes_effect() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method
        .verify_with_markers(&mut attempt, &code, &boot)
        .is_ok());

    fixture.revoke_the_ticket();
    let next = fixture.method().unwrap();
    assert!(matches!(
        next.begin_with_markers(&Fixture::request(1), &markers("boot-a", 200)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn an_unknown_operator_is_refused() {
    let fixture = Fixture::new();
    let method = fixture.method().unwrap();
    let request = AttemptRequest {
        server_id: "op-99",
        ..Fixture::request(1)
    };
    assert!(matches!(
        method.begin_with_markers(&request, &markers("boot-a", 100)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_device_without_artefacts_does_not_offer_the_method() {
    let dir = tempfile::tempdir().unwrap();
    let paths = CodesPaths::under(dir.path());
    let config = CodesConfig {
        paths,
        params: FleetParams::defaults(),
        device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
        epoch: Epoch::new(7),
        device_scope: DeviceScope {
            tags: vec!["dc-1".to_owned()],
            region: "ru-south".to_owned(),
        },
        code_ttl: DEFAULT_CODE_TTL,
        gost_engine_path: None,
    };
    assert!(matches!(
        CodeMethod::open(config, LocalRoles::default()),
        Err(CodeLoginError::Unavailable)
    ));
}

#[test]
fn a_container_that_will_not_open_stops_the_attempt_before_it_starts() {
    // A container the device cannot open is the device's own failure — an
    // enrolment that went wrong, a store damaged after it — and never the
    // engineer's mistake. It is answered before a challenge exists: no counter
    // value is spent, nothing is read out, and the refusal says the device is
    // in a bad state rather than that the engineer got something wrong.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let method = fixture.method().unwrap();

    let container = &fixture.config.paths.device_key_container;
    let intact = std::fs::read(container).unwrap();
    std::fs::write(container, b"not a container at all").unwrap();
    assert!(matches!(
        method.begin_with_markers(&Fixture::request(1), &boot),
        Err(CodeLoginError::State { .. })
    ));

    // Nothing was taken from the device while the container was broken: with it
    // back, an attempt starts and its code is accepted.
    std::fs::write(container, &intact).unwrap();
    let mut attempt = method
        .begin_with_markers(&Fixture::request(1), &boot)
        .unwrap();
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method
        .verify_with_markers(&mut attempt, &code, &boot)
        .is_ok());
}

#[test]
fn every_attempt_takes_a_nonce_of_its_own() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let method = fixture.method().unwrap();

    // One attempt at a time, so the first is finished before the second begins.
    let first = method
        .begin_with_markers(&Fixture::request(1), &boot)
        .unwrap();
    let first_nonce = first.challenge().nonce().as_str().to_owned();
    let code = fixture.cabinet_code(first.challenge());
    drop(first);

    let mut second = method
        .begin_with_markers(&Fixture::request(0), &after_a_window(1))
        .unwrap();
    assert_ne!(second.challenge().nonce().as_str(), first_nonce);

    // A code cut for one attempt does not open the other.
    assert!(matches!(
        method.verify_with_markers(&mut second, &code, &after_a_window(1)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_device_holds_one_attempt_at_a_time() {
    // The lock of the state directory lives as long as the attempt, so a second
    // login arriving while the first is being answered is refused rather than
    // given an attempt of its own. Eight attempts alive at once used to be the
    // grace window; there is no window now, because there is nothing on disk
    // for a second attempt to live in.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let method = fixture.method().unwrap();

    let held = method
        .begin_with_markers(&Fixture::request(1), &boot)
        .unwrap();
    assert!(
        matches!(
            method.begin_with_markers(&Fixture::request(1), &after_a_window(1)),
            Err(CodeLoginError::State { .. })
        ),
        "a second attempt must not start while one is open"
    );

    // And the device is not stuck: the attempt ends, the next one starts.
    drop(held);
    assert!(method
        .begin_with_markers(&Fixture::request(1), &after_a_window(2))
        .is_ok());
}

#[test]
fn the_authority_of_another_fleet_does_not_open_this_device() {
    let fixture = Fixture::new();
    let stranger = Authority::new();
    std::fs::write(
        &fixture.config.paths.ticket_authority,
        stranger.public_key_pem().as_slice(),
    )
    .unwrap();
    let method = fixture.method().unwrap();
    assert!(matches!(
        method.begin_with_markers(&Fixture::request(1), &markers("boot-a", 100)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn opening_the_method_creates_the_state_directory() {
    // The directory used to be created by the first write, which happens after
    // the challenge has been printed and the operator named. A device that
    // announced the method and then failed on a missing directory wasted a
    // telephone call.
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let mut config = fixture.config.clone();
    config.paths.state_dir = dir.path().join("deeper").join("state");
    assert!(!config.paths.state_dir.exists());

    let method = CodeMethod::open(config.clone(), fixture.roles.clone()).unwrap();

    assert!(config.paths.state_dir.is_dir());
    // And it is usable straight away, not merely present.
    assert!(method
        .begin_with_markers(&Fixture::request(1), &markers("boot-a", 100))
        .is_ok());
}

#[cfg(unix)]
#[test]
fn a_world_writable_artefact_stops_the_method_offering_itself() {
    // The artefacts are the whole of what the method trusts: whoever can
    // rewrite the key container can mint codes, and whoever can rewrite the
    // anchor can name their own ticket authority. Presence was never the
    // question — permissions are.
    use std::os::unix::fs::PermissionsExt as _;

    for weakened in [
        |fixture: &Fixture| fixture.config.paths.device_key_container.clone(),
        |fixture: &Fixture| fixture.config.paths.ticket_authority.clone(),
        |fixture: &Fixture| fixture.config.paths.tickets.clone(),
    ] {
        let fixture = Fixture::new();
        let path = weakened(&fixture);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let opened = CodeMethod::open_privileged(fixture.config.clone(), fixture.roles.clone());

        assert!(
            matches!(opened, Err(CodeLoginError::State { .. })),
            "a world-writable {} was accepted",
            path.display()
        );
        // The unprivileged entry is the one tests use, and it still opens —
        // otherwise this test would be proving that the fixture is broken.
        assert!(CodeMethod::open(fixture.config.clone(), fixture.roles.clone()).is_ok());
    }
}

#[cfg(unix)]
#[test]
fn a_world_writable_state_directory_stops_the_method_offering_itself() {
    // The spent-nonce record lives here. Somebody who can rewrite it can make
    // a spent nonce look fresh, which is the offline replay defence undone.
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    std::fs::set_permissions(
        &fixture.config.paths.state_dir,
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();

    assert!(matches!(
        CodeMethod::open_privileged(fixture.config.clone(), fixture.roles.clone()),
        Err(CodeLoginError::State { .. })
    ));
}

#[test]
fn a_code_that_meets_emits_no_success_event_of_its_own() {
    // The login is not over when the code meets: the caller still re-reads the
    // integrity level, fixes the role payload and registers the session, and
    // any of those can refuse. An event written here would record a successful
    // login for an attempt that ends in a PAM refusal, and the reconciliation
    // this event exists for — logins against operator receipts — would then
    // pair a receipt with a login that never happened.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    // Read from the journal, not from a `tracing` subscriber. An assertion that
    // something was NOT emitted is exactly the assertion a subscriber cannot
    // carry: `tracing` caches callsite interest per process, so a subscriber
    // that was never offered an event reports the same emptiness as a method
    // that never emitted one, and the test passes without checking anything.
    let records = crate::audit::testing::capture_records(|| {
        method
            .verify_with_markers(&mut attempt, &code, &boot)
            .unwrap();
    });

    assert!(
        crate::audit::testing::with_outcome(&records, crate::codes::audit::OUTCOME_SUCCESS)
            .is_empty(),
        "the method emitted an outcome of its own: {records:?}",
    );
}

#[test]
fn a_key_delivered_under_a_new_epoch_is_the_one_the_login_computes_with() {
    // The epoch a device derives codes under is a fact of its store, not of its
    // configuration. An import that rotates the key writes the new number
    // beside it and never touches `config.toml`, so a device that read the
    // configured number instead would announce the old epoch, derive under the
    // old key pair, and refuse every code the operator computed — on the one
    // channel that reaches a device nobody can visit.
    //
    // The epoch no longer picks the key the code is derived from — that is the
    // ephemeral pair of the attempt — so what a wrong epoch costs is the
    // record: every event of this login, and every register the issuing side
    // reconciles them against, names a key the device does not hold.
    let fixture = Fixture::new();
    let configured = fixture.config.epoch;
    epoch::write(&fixture.config.paths.state_dir, configured).unwrap();

    // The fleet rotates the key: a new pair, delivered under the next epoch.
    let rotated = Epoch::new(configured.get() + 1);
    let (rotated_key, _rotated_point) = p256_pair();
    artefacts::apply(
        &fixture.config.paths,
        &artefacts::CodesDelivery {
            key: Some(artefacts::DeliveredKey {
                epoch: rotated,
                container: container(&rotated_key),
                pin: secrecy::SecretString::from(String::new()),
            }),
            ..artefacts::CodesDelivery::default()
        },
        None,
        artefacts::StoreCheck::Skipped,
    )
    .unwrap();

    // The configuration still names the epoch it was written with.
    assert_eq!(fixture.config.epoch, configured);

    let method = fixture.method().unwrap();
    let boot = markers("boot-a", 100);
    let mut attempt = method
        .begin_with_markers(&Fixture::request(1), &boot)
        .unwrap();
    assert_eq!(
        attempt.challenge().epoch(),
        rotated,
        "the challenge must announce the epoch of the key the device actually holds"
    );

    let code = fixture.cabinet_code(attempt.challenge());
    assert!(
        method
            .verify_with_markers(&mut attempt, &code, &boot)
            .is_ok(),
        "a code computed for the challenge the device printed must be accepted"
    );
}

// ---------------------------------------------------------------------------
// What a caller may ask for, as opposed to what they may answer
// ---------------------------------------------------------------------------

#[test]
fn a_storm_of_challenge_requests_runs_into_the_issuance_budget() {
    // A challenge is printed before any code is presented, so anyone who
    // reaches the PAM stack with the name of a role account makes this device
    // draw an ephemeral pair and take its only attempt slot. Nothing about that
    // is permanent any more — there is no counter left to spend — but a caller
    // who can keep the slot busy keeps an engineer out, so the budget bounds
    // how often it can be asked for.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let method = fixture.method().unwrap();

    for issued in 0..throttle::MAX_CHALLENGES_PER_WINDOW {
        assert!(
            method
                .begin_with_markers(&Fixture::request(1), &boot)
                .is_ok(),
            "challenge {issued} is inside the budget"
        );
    }

    // Everything past the budget is refused, and the refusal is temporary: it
    // says "wait", not "this device is finished".
    for _ in 0..100 {
        assert!(matches!(
            method.begin_with_markers(&Fixture::request(1), &boot),
            Err(CodeLoginError::TemporarilyLocked { .. })
        ));
    }
}

#[test]
fn the_refusal_to_issue_ends_by_itself() {
    // The other half of the same guarantee, and without it the first half is a
    // different outage with the same effect: a limit that hangs the login until
    // somebody drives to the site is no better on a cash machine than the flood
    // it prevents. Nobody clears this; it clears itself.
    let fixture = Fixture::new();
    let method = fixture.method().unwrap();
    for _ in 0..throttle::MAX_CHALLENGES_PER_WINDOW {
        method
            .begin_with_markers(&Fixture::request(1), &markers("boot-a", 100))
            .unwrap();
    }
    assert!(matches!(
        method.begin_with_markers(&Fixture::request(1), &markers("boot-a", 100)),
        Err(CodeLoginError::TemporarilyLocked { .. })
    ));

    let after = 100 + throttle::CHALLENGE_WINDOW.as_secs();
    let mut attempt = method
        .begin_with_markers(&Fixture::request(1), &markers("boot-a", after))
        .unwrap();
    // And the challenge that comes out of the far side is a working one.
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method
        .verify_with_markers(&mut attempt, &code, &markers("boot-a", after))
        .is_ok());
}

#[test]
fn the_wait_a_storm_earns_is_reported_rather_than_left_to_guesswork() {
    let fixture = Fixture::new();
    let method = fixture.method().unwrap();
    for _ in 0..throttle::MAX_CHALLENGES_PER_WINDOW {
        method
            .begin_with_markers(&Fixture::request(1), &markers("boot-a", 100))
            .unwrap();
    }
    let Err(CodeLoginError::TemporarilyLocked { retry_after }) =
        method.begin_with_markers(&Fixture::request(1), &markers("boot-a", 100))
    else {
        panic!("the budget should be spent");
    };
    // The branch that prompts has to be able to say how long, and a caller
    // cannot compute it: the window is the method's own.
    assert!(retry_after <= throttle::CHALLENGE_WINDOW);
    assert!(retry_after > Duration::ZERO);
}

#[test]
fn a_run_of_spent_budgets_locks_the_role_and_the_lock_ends() {
    // Guessing is not bounded by the per-nonce budget: a new conversation
    // brings a new nonce with a full budget of its own. What bounds it is this.
    let fixture = Fixture::new();
    let method = fixture.method().unwrap();

    for round in 0..throttle::LOCKOUT_AFTER_FAILURES {
        let at = after_a_window(u64::from(round));
        let mut attempt = method
            .begin_with_markers(&Fixture::request(1), &at)
            .unwrap();
        for _ in 0..fixture.config.params.attempts_per_nonce() {
            let _refused = method.verify_with_markers(&mut attempt, "00000000", &at);
        }
    }

    // Checked at the moment the run of failures ended: the lock is short by
    // design, and a check taken a window later would be testing that it had
    // already expired.
    let locked_at = after_a_window(u64::from(throttle::LOCKOUT_AFTER_FAILURES - 1));
    assert!(matches!(
        method.begin_with_markers(&Fixture::request(1), &locked_at),
        Err(CodeLoginError::TemporarilyLocked { .. })
    ));

    // The lock is served, not cleared by hand.
    let freed = markers(
        "boot-a",
        locked_at.since_boot_secs() + throttle::LOCKOUT_BASE.as_secs(),
    );
    let mut attempt = method
        .begin_with_markers(&Fixture::request(1), &freed)
        .unwrap();
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method
        .verify_with_markers(&mut attempt, &code, &freed)
        .is_ok());
}

#[test]
fn the_lock_leaves_the_tries_the_budget_grants_alone() {
    // The two limits must not eat each other: the fleet parameters grant a
    // nonce several tries, and a lock armed by the third wrong code would take
    // the rest of them away from the engineer they were granted to.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);

    for guess in 1..fixture.config.params.attempts_per_nonce() {
        assert!(
            matches!(
                method.verify_with_markers(&mut attempt, "00000000", &boot),
                Err(CodeLoginError::Denied)
            ),
            "try {guess} is one the budget grants"
        );
    }
    assert!(matches!(
        method.verify_with_markers(&mut attempt, "00000000", &boot),
        Err(CodeLoginError::AttemptsExhausted)
    ));
}

#[test]
fn a_login_clears_the_run_of_failures_behind_it() {
    let fixture = Fixture::new();
    let method = fixture.method().unwrap();

    // Two spent budgets — one short of the lock.
    for round in 0..(throttle::LOCKOUT_AFTER_FAILURES - 1) {
        let at = after_a_window(u64::from(round));
        let mut attempt = method
            .begin_with_markers(&Fixture::request(1), &at)
            .unwrap();
        for _ in 0..fixture.config.params.attempts_per_nonce() {
            let _refused = method.verify_with_markers(&mut attempt, "00000000", &at);
        }
    }

    let at = after_a_window(u64::from(throttle::LOCKOUT_AFTER_FAILURES));
    {
        let mut attempt = method
            .begin_with_markers(&Fixture::request(1), &at)
            .unwrap();
        let code = fixture.cabinet_code(attempt.challenge());
        assert!(method.verify_with_markers(&mut attempt, &code, &at).is_ok());
    }

    // The engineer who got in does not carry the earlier fumbling forward: one
    // more spent budget is the first of a new run, not the third of the old
    // one. Checked at the moment it ends — had the run continued, the role
    // would be locked right here.
    let later = after_a_window(u64::from(throttle::LOCKOUT_AFTER_FAILURES) + 1);
    {
        let mut attempt = method
            .begin_with_markers(&Fixture::request(1), &later)
            .unwrap();
        for _ in 0..fixture.config.params.attempts_per_nonce() {
            let _refused = method.verify_with_markers(&mut attempt, "00000000", &later);
        }
    }
    assert!(method
        .begin_with_markers(&Fixture::request(1), &later)
        .is_ok());
}

// ---------------------------------------------------------------------------
// What a refusal says to the journal
// ---------------------------------------------------------------------------

#[test]
fn a_refused_code_names_the_ticket_it_was_refused_under() {
    // A login and an operator receipt are reconciled by the ticket number and
    // the nonce. A refusal that names neither cannot be paired with the receipt
    // of the call it belongs to, and the pairing is the whole point of writing
    // refusals down: a login without a receipt and a receipt without a login
    // are both alarms.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);

    let records = crate::audit::testing::capture_records(|| {
        let _refused = method.verify_with_markers(&mut attempt, "00000000", &boot);
    });
    // Narrowed by this attempt's own nonce: the journal sink is process-wide,
    // so a parallel test can have written its own refusal into the same file.
    let nonce = attempt.challenge().nonce().to_string();
    let refusals = crate::audit::testing::matching(
        &records,
        &[
            ("outcome", crate::codes::audit::OUTCOME_DENIED),
            ("nonce_ref", &nonce),
        ],
    );
    let refusal = refusals
        .first()
        .unwrap_or_else(|| panic!("a refusal is written down; saw {records:#?}"));
    assert_eq!(refusal["ticket_no"], "tk-17", "{refusal}");
}

#[test]
fn every_decided_attempt_names_the_engineer_who_claimed_it() {
    // The reconciliation this field exists for pairs the logins a fleet saw
    // with the grants its server issued, and the number is what names the
    // person on the device side. A journal without it can say a role account
    // was let in and nothing about who was standing there.
    //
    // Both outcomes, because both are reconciled: a refusal that named nobody
    // would leave exactly the attempts an audit cares about anonymous.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);
    let nonce = attempt.challenge().nonce().to_string();

    let refused = crate::audit::testing::capture_records(|| {
        let _refused = method.verify_with_markers(&mut attempt, "00000000", &boot);
    });
    let refusals = crate::audit::testing::matching(
        &refused,
        &[
            ("outcome", crate::codes::audit::OUTCOME_DENIED),
            ("nonce_ref", &nonce),
        ],
    );
    let refusal = refusals
        .first()
        .unwrap_or_else(|| panic!("a refusal is written down; saw {refused:#?}"));
    assert_eq!(refusal["claimed_engineer_no"], ENGINEER, "{refusal}");

    let code = fixture.cabinet_code(attempt.challenge());
    let accepted = method
        .verify_with_markers(&mut attempt, &code, &boot)
        .unwrap();
    // The verdict carries the number out to the caller, which is what emits the
    // success event once nothing is left that can refuse.
    assert_eq!(accepted.claimed_engineer_no, ENGINEER);
}

#[test]
fn a_spent_budget_names_the_ticket_it_was_spent_under() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, mut attempt) = start(&fixture, 1, &boot);

    let records = crate::audit::testing::capture_records(|| {
        for _ in 0..=fixture.config.params.attempts_per_nonce() {
            let _refused = method.verify_with_markers(&mut attempt, "00000000", &boot);
        }
    });
    let nonce = attempt.challenge().nonce().to_string();
    let spent = crate::audit::testing::matching(
        &records,
        &[
            ("outcome", crate::codes::audit::OUTCOME_ATTEMPTS_EXHAUSTED),
            ("nonce_ref", &nonce),
        ],
    );
    let exhausted = spent
        .first()
        .unwrap_or_else(|| panic!("a spent budget is written down; saw {records:#?}"));
    assert_eq!(exhausted["ticket_no"], "tk-17", "{exhausted}");
}

#[test]
fn a_ticket_refused_by_its_scope_is_named_in_the_journal() {
    // The refusal happens before any nonce exists, so the ticket number is the
    // only thing that pairs it with the operator's side of the call.
    let fixture = Fixture::build(FleetParams::defaults(), 1, &[ROLE]);
    let method = fixture.method().unwrap();
    let records = crate::audit::testing::capture_records(|| {
        let _refused = method.begin_with_markers(&Fixture::request(2), &markers("boot-a", 100));
    });
    // This refusal happens before any nonce exists, so it is narrowed by its
    // reason instead — the scope check is the only thing that produces it.
    let refusals = crate::audit::testing::matching(
        &records,
        &[
            ("outcome", crate::codes::audit::OUTCOME_DENIED),
            ("reason", crate::codes::audit::REASON_TICKET_SCOPE_LEVEL),
        ],
    );
    let refusal = refusals
        .first()
        .unwrap_or_else(|| panic!("a refusal is written down; saw {records:#?}"));
    assert_eq!(refusal["ticket_no"], "tk-17", "{refusal}");
}

#[test]
fn the_method_reports_the_epoch_it_is_running_under_not_the_configured_one() {
    // An import rotated the key and moved the persisted epoch forward without
    // touching `config.toml`. Every code is derived under the persisted one, so
    // that is the epoch the caller has to name in the events it emits itself —
    // otherwise the journal of a single login carries two epochs.
    let fixture = Fixture::new();
    let configured = fixture.config.epoch;
    let ahead = Epoch::new(configured.get() + 5);
    super::epoch::write(&fixture.config.paths.state_dir, ahead).unwrap();

    let method = fixture.method().unwrap();

    assert_eq!(method.epoch(), ahead);
    assert_ne!(
        method.epoch(),
        configured,
        "the getter handed back the configured epoch, which is the value that \
         made the journal of one login disagree with itself",
    );
}

/// Off Unix the method refuses as unsupported, not as broken.
///
/// The distinction is what a PAM stack acts on: a stack can be configured to
/// step over "there is no method here" and go on to the certificate path, and
/// it cannot step over "this device is faulty". A device on Windows is not
/// faulty — the method it cannot offer rests on file permissions the platform
/// does not express, which is a fact about the platform and known before a
/// single artefact is read.
///
/// Runs where the answer is, which is the platform this product does not serve
/// with this method; on Unix there is nothing here to check.
#[cfg(not(unix))]
#[test]
fn a_platform_without_posix_permissions_offers_no_code_method() {
    let dir = tempfile::tempdir().unwrap();
    let config = CodesConfig {
        paths: CodesPaths::under(dir.path()),
        params: FleetParams::defaults(),
        device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
        epoch: Epoch::new(7),
        device_scope: DeviceScope {
            tags: vec!["dc-1".to_owned()],
            region: "ru-south".to_owned(),
        },
        code_ttl: DEFAULT_CODE_TTL,
        gost_engine_path: None,
    };

    assert!(matches!(
        CodeMethod::open(config, LocalRoles::default()),
        Err(CodeLoginError::UnsupportedPlatform)
    ));
}

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
use tessera_codes_contract::challenge::Challenge;
use tessera_codes_contract::code::compute_code;
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::key::{derive_key, Epoch, KeyAgreement as _, KeyContext};
use tessera_codes_contract::params::{FleetParams, FleetParamsInput};
use tessera_codes_contract::profile::AlgorithmProfile;
use tessera_codes_contract::signature::PublicKey;
use tessera_codes_contract::ticket::{
    OperatorTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput,
};
use tessera_codes_contract::time::ClaimedTime;

use super::agreement::tests::p256_pair;
use super::agreement::DeviceKeyAgreement;
use super::boot::BootMarkers;
use super::throttle;
use super::tickets::tests::Authority;
use super::tickets::DeviceScope;
use super::{
    artefacts, counter, epoch, AttemptRequest, CodeLoginError, CodeMethod, CodesConfig, CodesPaths,
    LocalRoles, StartedAttempt, DEFAULT_CODE_TTL,
};

/// The fixture container carries no password, the way a stored one does: the
/// PIN is a form of delivery, and by the time a container sits in the store the
/// import has already opened it once and re-written the key without one.
const STORED_CONTAINER_PASSWORD: &str = "";

/// Role the fixture logs into.
const ROLE: &str = "oper";

/// Operator the fixture ticket belongs to.
const OPERATOR: &str = "op-42";

/// The whole channel, on disk.
struct Fixture {
    _dir: TempDir,
    config: CodesConfig,
    roles: LocalRoles,
    operator_key: PKey<Private>,
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
            OperatorTicket::new(
                OPERATOR,
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
            operator_id: OPERATOR,
            now: ClaimedTime::new(1_700_000_000),
        }
    }

    /// What the operator's cabinet computes for a challenge it was read, using
    /// the device key registered for the epoch that challenge announces.
    ///
    /// The epoch is taken from the challenge rather than from the fixture's
    /// configuration because that is what an operator has: the number was read
    /// to them over the telephone, and it is what they look the device key up
    /// by.
    fn cabinet_code_for(&self, challenge: &Challenge, device_point: &[u8]) -> String {
        let secret = DeviceKeyAgreement::new(&self.operator_key, AlgorithmProfile::P256)
            .unwrap()
            .agree(device_point)
            .unwrap();
        let context = KeyContext::new(
            &self.config.device_number,
            challenge.epoch(),
            self.ticket.context_hash().unwrap(),
        );
        let key = derive_key(&secret, &context).unwrap();
        compute_code(&key, &challenge.code_input(), &self.config.params)
            .unwrap()
            .as_str()
            .to_owned()
    }

    /// What the operator's cabinet computes for a challenge it was read.
    fn cabinet_code(&self, challenge: &Challenge) -> String {
        let secret = DeviceKeyAgreement::new(&self.operator_key, AlgorithmProfile::P256)
            .unwrap()
            .agree(&self.device_point)
            .unwrap();
        let context = KeyContext::new(
            &self.config.device_number,
            self.config.epoch,
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
    let (method, attempt) = start(&fixture, 1, &boot);

    // What the engineer reads out, and what the operator reads back.
    assert!(attempt.spoken_form().contains(' '));
    assert_eq!(attempt.ticket_number(), "tk-17");
    let code = fixture.cabinet_code(attempt.challenge());

    let accepted = method
        .verify_with_markers(&attempt, &code, &markers("boot-a", 140))
        .unwrap();
    assert_eq!(accepted.role_id, ROLE);
    assert_eq!(accepted.level, Level::new(1));
    assert_eq!(accepted.ticket_number, "tk-17");
    // The ceiling travels with the verdict: it is what the session label is
    // bounded by, and the device states no linear bound of its own.
    assert_eq!(accepted.level_ceiling, Level::new(1));
}

#[test]
fn the_ceiling_of_the_verdict_is_the_ceiling_of_the_ticket() {
    // A ticket that reaches level 3, used for a login at level 1: the level of
    // the login and the ceiling it was authorised under are different numbers
    // and are reported as such.
    let fixture = Fixture::build(FleetParams::defaults(), 3, &[ROLE]);
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    let accepted = method.verify_with_markers(&attempt, &code, &boot).unwrap();
    assert_eq!(accepted.level, Level::new(1));
    assert_eq!(accepted.level_ceiling, Level::new(3));
}

#[test]
fn a_level_equal_to_the_ceiling_of_the_ticket_is_admitted() {
    let fixture = Fixture::build(FleetParams::defaults(), 2, &[ROLE]);
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 2, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    let accepted = method.verify_with_markers(&attempt, &code, &boot).unwrap();
    assert_eq!(accepted.level, Level::new(2));
    assert_eq!(accepted.level_ceiling, Level::new(2));
}

#[test]
fn the_method_needs_no_server_configuration_of_any_kind() {
    // The fixture never names a URL, and nothing in the path above reads one:
    // the dictation mode is complete without a site to point at.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method.verify_with_markers(&attempt, &code, &boot).is_ok());
}

#[test]
fn a_wrong_code_does_not_admit_anybody() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);

    assert!(matches!(
        method.verify_with_markers(&attempt, "00000000", &boot),
        Err(CodeLoginError::Denied)
    ));
    // The attempt survives one wrong code: the budget is larger than one.
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method.verify_with_markers(&attempt, &code, &boot).is_ok());
}

#[test]
fn the_attempt_budget_of_a_nonce_runs_out() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);
    let budget = fixture.config.params.attempts_per_nonce();

    for guess in 1..budget {
        assert!(
            matches!(
                method.verify_with_markers(&attempt, "00000000", &boot),
                Err(CodeLoginError::Denied)
            ),
            "guess {guess} should still be inside the budget"
        );
    }
    assert!(matches!(
        method.verify_with_markers(&attempt, "00000000", &boot),
        Err(CodeLoginError::AttemptsExhausted)
    ));

    // The nonce is spent with the budget: the right code no longer helps.
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(matches!(
        method.verify_with_markers(&attempt, &code, &boot),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn the_budget_is_not_refilled_by_a_new_process() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);
    let budget = fixture.config.params.attempts_per_nonce();

    for _ in 1..budget {
        assert!(method
            .verify_with_markers(&attempt, "00000000", &boot)
            .is_err());
    }
    // A second process opens the method afresh and meets the same budget.
    let reopened = fixture.method().unwrap();
    assert!(matches!(
        reopened.verify_with_markers(&attempt, "00000000", &boot),
        Err(CodeLoginError::AttemptsExhausted)
    ));
}

#[test]
fn a_spent_nonce_is_refused_when_it_comes_back() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method.verify_with_markers(&attempt, &code, &boot).is_ok());

    // The same code, in the same process and then in a new one after a reboot.
    assert!(matches!(
        method.verify_with_markers(&attempt, &code, &boot),
        Err(CodeLoginError::Denied)
    ));
    let after_reboot = fixture.method().unwrap();
    assert!(matches!(
        after_reboot.verify_with_markers(&attempt, &code, &markers("boot-b", 5)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_reboot_puts_out_a_pending_attempt() {
    let fixture = Fixture::new();
    let (method, attempt) = start(&fixture, 1, &markers("boot-a", 100));
    let code = fixture.cabinet_code(attempt.challenge());

    // The code was never used, and it still does not work: the attempt it
    // belongs to did not survive the restart.
    assert!(matches!(
        method.verify_with_markers(&attempt, &code, &markers("boot-b", 5)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_monotonic_clock_dragged_backwards_puts_out_a_pending_attempt() {
    let fixture = Fixture::new();
    let (method, attempt) = start(&fixture, 1, &markers("boot-a", 500));
    let code = fixture.cabinet_code(attempt.challenge());

    assert!(matches!(
        method.verify_with_markers(&attempt, &code, &markers("boot-a", 499)),
        Err(CodeLoginError::Denied)
    ));
}

#[test]
fn a_code_past_its_local_lifetime_is_refused() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    let too_late = markers("boot-a", 100 + DEFAULT_CODE_TTL.as_secs() + 1);
    assert!(matches!(
        method.verify_with_markers(&attempt, &code, &too_late),
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
    let (method, attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method.verify_with_markers(&attempt, &code, &boot).is_ok());

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
        operator_id: "op-99",
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
fn a_container_that_will_not_open_does_not_spend_an_attempt() {
    // A container the device cannot open is the device's own failure — an
    // enrolment that went wrong, a store damaged after it — and never the
    // engineer's mistake. Either way it must not be charged to the budget they
    // are working against.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    let container = &fixture.config.paths.device_key_container;
    let intact = std::fs::read(container).unwrap();
    std::fs::write(container, b"not a container at all").unwrap();
    for _ in 0..(u32::from(fixture.config.params.attempts_per_nonce()) + 3) {
        assert!(matches!(
            method.verify_with_markers(&attempt, &code, &boot),
            Err(CodeLoginError::Denied)
        ));
    }

    // The device's own failure cost the engineer nothing: with the container
    // back, the same code on the same nonce is still accepted.
    std::fs::write(container, &intact).unwrap();
    assert!(method.verify_with_markers(&attempt, &code, &boot).is_ok());
}

#[test]
fn the_nonce_counter_is_exhausted_rather_than_wrapped() {
    let params = FleetParams::parse(FleetParamsInput {
        counter_width: 1,
        ..FleetParamsInput::defaults()
    })
    .unwrap();
    let fixture = Fixture::build(params, 1, &[ROLE]);
    let method = fixture.method().unwrap();

    // The width holds the counters 0..=9, and the first challenge takes 1.
    // Each challenge is asked for in a window of its own: the issuance limit is
    // what an attacker meets, and this test is about what an operator meets at
    // the end of the counter — see `a_storm_of_challenge_requests_...` for the
    // other half.
    let mut issued = Vec::new();
    for step in 1..=9u64 {
        let attempt = method
            .begin_with_markers(&Fixture::request(1), &after_a_window(step))
            .unwrap();
        issued.push(attempt.challenge().nonce().counter());
    }
    assert_eq!(issued, (1..=9).collect::<Vec<_>>());

    assert!(matches!(
        method.begin_with_markers(&Fixture::request(1), &after_a_window(10)),
        Err(CodeLoginError::CounterExhausted)
    ));
    // And it stays exhausted: nothing wrapped round to a counter already spoken.
    assert!(matches!(
        fixture
            .method()
            .unwrap()
            .begin_with_markers(&Fixture::request(1), &after_a_window(11)),
        Err(CodeLoginError::CounterExhausted)
    ));
}

#[test]
fn a_rolled_back_counter_refuses_until_the_epoch_is_rotated() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let method = fixture.method().unwrap();
    for _ in 0..3 {
        method
            .begin_with_markers(&Fixture::request(1), &boot)
            .unwrap();
    }

    // The device came back from a snapshot with an older counter.
    counter::write_issued(&fixture.config.paths.state_dir, 1).unwrap();
    assert!(matches!(
        fixture
            .method()
            .unwrap()
            .begin_with_markers(&Fixture::request(1), &boot),
        Err(CodeLoginError::StateRollback)
    ));
}

#[test]
fn every_attempt_takes_a_nonce_of_its_own() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let method = fixture.method().unwrap();

    let first = method
        .begin_with_markers(&Fixture::request(1), &boot)
        .unwrap();
    let second = method
        .begin_with_markers(&Fixture::request(0), &boot)
        .unwrap();
    assert_ne!(
        first.challenge().nonce().as_str(),
        second.challenge().nonce().as_str()
    );
    assert_ne!(
        first.challenge().nonce().counter(),
        second.challenge().nonce().counter()
    );

    // A code cut for one attempt does not open the other.
    let code = fixture.cabinet_code(first.challenge());
    assert!(matches!(
        method.verify_with_markers(&second, &code, &boot),
        Err(CodeLoginError::Denied)
    ));
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

/// Environment variable naming the state directory the child process locks.
const CHILD_LOCK_DIR: &str = "TESSERA_CODES_TEST_LOCK_DIR";

/// The child half of [`the_state_is_locked_against_a_second_process`].
///
/// Runs as an ordinary test — and does nothing — unless the parent set
/// [`CHILD_LOCK_DIR`], which it only does when it re-executes this binary. The
/// child takes the lock of that directory and reports, on stdout, how long it
/// had to wait: the parent holds the lock while the child starts, so a wait it
/// did not perform is a lock that does not cross a process boundary.
#[test]
fn child_process_reports_how_long_the_lock_made_it_wait() {
    let Ok(dir) = std::env::var(CHILD_LOCK_DIR) else {
        return;
    };
    let started = std::time::Instant::now();
    let guard = super::lock::StateLock::acquire(std::path::Path::new(&dir));
    let waited = started.elapsed();
    drop(guard.unwrap());
    println!("WAITED_MS={}", waited.as_millis());
}

/// The state of a device is locked against another **process**, not merely
/// against another thread.
///
/// Threads would prove nothing here: the hold belongs to an open handle, so
/// two threads of one process share it and never contend. The defect this
/// guards lives between processes, which is what a PAM module is — `sshd`
/// forks per connection, a console login is its own process, and a device
/// reachable both ways runs them at the same time. Without a lock spanning the
/// whole load-mutate-save, the second process writes back a snapshot taken
/// before the first one spent the attempt budget, and the budget resets to zero
/// as often as an attacker likes.
///
/// So the second party is a real process: this binary, re-executed against the
/// child test above.
///
/// Runs on every platform that has a hold to take. It was Unix-only while the
/// other arm refused outright; now that Windows takes a real hold through
/// `LockFileEx`, the platform where the mechanism is newest is exactly the one
/// that must not be taken on trust.
#[test]
fn the_state_is_locked_against_a_second_process() {
    use std::process::Command;

    /// How long the parent keeps the lock while the child tries for it.
    const HELD: Duration = Duration::from_millis(400);
    /// The wait the child must report at least. Below `HELD` by a margin, so
    /// the assertion turns on the lock and not on scheduler jitter.
    const MIN_REPORTED_WAIT_MS: u128 = 200;

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().to_path_buf();

    let exe = std::env::current_exe().unwrap();
    let guard = super::lock::StateLock::acquire(&state_dir).unwrap();

    let child = Command::new(exe)
        .args([
            "--exact",
            "codes::tests::child_process_reports_how_long_the_lock_made_it_wait",
            "--nocapture",
        ])
        .env(CHILD_LOCK_DIR, &state_dir)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Held while the child starts up and blocks on the lock.
    std::thread::sleep(HELD);
    drop(guard);

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "the child test failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let waited: u128 = stdout
        .lines()
        .find_map(|line| line.strip_prefix("WAITED_MS="))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("the child reported no wait; it printed: {stdout}"));

    assert!(
        waited >= MIN_REPORTED_WAIT_MS,
        "a second process took the lock after {waited}ms without waiting for this one to \
         release it: the state of the device is not locked across processes",
    );
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
    let (method, attempt) = start(&fixture, 1, &boot);
    let code = fixture.cabinet_code(attempt.challenge());

    // Read from the journal, not from a `tracing` subscriber. An assertion that
    // something was NOT emitted is exactly the assertion a subscriber cannot
    // carry: `tracing` caches callsite interest per process, so a subscriber
    // that was never offered an event reports the same emptiness as a method
    // that never emitted one, and the test passes without checking anything.
    let records = crate::audit::testing::capture_records(|| {
        method.verify_with_markers(&attempt, &code, &boot).unwrap();
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
    // The operator here does what an operator does: takes the epoch from the
    // challenge that was read to them, looks up the device key registered for
    // that epoch, and computes with it. That is what makes the wrong epoch
    // fatal rather than cosmetic — the two sides end up on different key pairs.
    let fixture = Fixture::new();
    let configured = fixture.config.epoch;
    epoch::write(&fixture.config.paths.state_dir, configured).unwrap();

    // The fleet rotates the key: a new pair, delivered under the next epoch.
    let rotated = Epoch::new(configured.get() + 1);
    let (rotated_key, rotated_point) = p256_pair();
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
    let attempt = method
        .begin_with_markers(&Fixture::request(1), &boot)
        .unwrap();
    assert_eq!(
        attempt.challenge().epoch(),
        rotated,
        "the challenge must announce the epoch of the key the device actually holds"
    );

    let code = fixture.cabinet_code_for(attempt.challenge(), &rotated_point);
    assert!(
        method.verify_with_markers(&attempt, &code, &boot).is_ok(),
        "a code computed against the delivered key must be accepted"
    );
}

// ---------------------------------------------------------------------------
// What a caller may ask for, as opposed to what they may answer
// ---------------------------------------------------------------------------

#[test]
fn a_storm_of_challenge_requests_cannot_spend_the_counter_to_exhaustion() {
    // The worst outcome this method has: a challenge is printed before any code
    // is presented, so anyone who reaches the PAM stack with the name of a role
    // account spends one value of a counter that never wraps — and a device
    // whose counter is spent stops offering the method until somebody carries a
    // new key epoch to it. On a machine nobody can reach any other way, that is
    // a permanent outage bought with a shell loop.
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

    // Everything past the budget is refused, and refusing costs nothing: a
    // hundred further attempts leave the counter exactly where the budget left
    // it. Without the limit this loop would burn a hundred values, and a longer
    // one would burn the counter dead.
    for _ in 0..100 {
        assert!(matches!(
            method.begin_with_markers(&Fixture::request(1), &boot),
            Err(CodeLoginError::TemporarilyLocked { .. })
        ));
    }
    assert_eq!(
        counter::read_issued(&fixture.config.paths.state_dir)
            .unwrap()
            .unwrap()
            .get(),
        u64::from(throttle::MAX_CHALLENGES_PER_WINDOW)
    );
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
    let attempt = method
        .begin_with_markers(&Fixture::request(1), &markers("boot-a", after))
        .unwrap();
    // And the challenge that comes out of the far side is a working one.
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method
        .verify_with_markers(&attempt, &code, &markers("boot-a", after))
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
        let attempt = method
            .begin_with_markers(&Fixture::request(1), &at)
            .unwrap();
        for _ in 0..fixture.config.params.attempts_per_nonce() {
            let _refused = method.verify_with_markers(&attempt, "00000000", &at);
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
    let attempt = method
        .begin_with_markers(&Fixture::request(1), &freed)
        .unwrap();
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method.verify_with_markers(&attempt, &code, &freed).is_ok());
}

#[test]
fn the_lock_leaves_the_tries_the_budget_grants_alone() {
    // The two limits must not eat each other: the fleet parameters grant a
    // nonce several tries, and a lock armed by the third wrong code would take
    // the rest of them away from the engineer they were granted to.
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);

    for guess in 1..fixture.config.params.attempts_per_nonce() {
        assert!(
            matches!(
                method.verify_with_markers(&attempt, "00000000", &boot),
                Err(CodeLoginError::Denied)
            ),
            "try {guess} is one the budget grants"
        );
    }
    assert!(matches!(
        method.verify_with_markers(&attempt, "00000000", &boot),
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
        let attempt = method
            .begin_with_markers(&Fixture::request(1), &at)
            .unwrap();
        for _ in 0..fixture.config.params.attempts_per_nonce() {
            let _refused = method.verify_with_markers(&attempt, "00000000", &at);
        }
    }

    let at = after_a_window(u64::from(throttle::LOCKOUT_AFTER_FAILURES));
    let attempt = method
        .begin_with_markers(&Fixture::request(1), &at)
        .unwrap();
    let code = fixture.cabinet_code(attempt.challenge());
    assert!(method.verify_with_markers(&attempt, &code, &at).is_ok());

    // The engineer who got in does not carry the earlier fumbling forward: one
    // more spent budget is the first of a new run, not the third of the old
    // one. Checked at the moment it ends — had the run continued, the role
    // would be locked right here.
    let later = after_a_window(u64::from(throttle::LOCKOUT_AFTER_FAILURES) + 1);
    let attempt = method
        .begin_with_markers(&Fixture::request(1), &later)
        .unwrap();
    for _ in 0..fixture.config.params.attempts_per_nonce() {
        let _refused = method.verify_with_markers(&attempt, "00000000", &later);
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
    let (method, attempt) = start(&fixture, 1, &boot);

    let records = crate::audit::testing::capture_records(|| {
        let _refused = method.verify_with_markers(&attempt, "00000000", &boot);
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
fn a_spent_budget_names_the_ticket_it_was_spent_under() {
    let fixture = Fixture::new();
    let boot = markers("boot-a", 100);
    let (method, attempt) = start(&fixture, 1, &boot);

    let records = crate::audit::testing::capture_records(|| {
        for _ in 0..=fixture.config.params.attempts_per_nonce() {
            let _refused = method.verify_with_markers(&attempt, "00000000", &boot);
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

//! The branch driven against scripted answers, levels and verdicts.
//!
//! What is exercised here is everything the PAM half owns: the order of the
//! prompts, the bounds on what a person may type, the retry budget, the second
//! read of the level, and the number every refusal turns into. The
//! cryptography is not: it belongs to [`tessera_core::codes`], which has its
//! own end-to-end tests against real artefacts, and repeating them here would
//! only pin a second copy of the same fixture.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::duration_suboptimal_units,
    reason = "a failed setup step in a test should fail the test on the spot, and a fixture \
              duration reads better in the unit it was written in"
)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::SecretString;
use tempfile::TempDir;

use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::key::Epoch;
use tessera_codes_contract::params::FleetParams;
use tessera_core::codes::{CodesPaths, DeviceScope};
use tessera_core::config::validated::{CertIntegrityMode, MacPolicy};
use tessera_core::error::IpcError;
use tessera_core::ipc::{MonitorClient, MonitorFailMode};
use tessera_core::mac::backend::{MacRuntime, MockMacBackend};
use tessera_core::mac::orchestrator::{apply_session_policy, SessionContext};
use tessera_core::mac::IntegrityLabel;
use tessera_core::role::{AccountCheck, RoleOs, RoleStore, SystemAccounts, TrustMode};
use tessera_core::x509::CertIdent;

use super::{
    authenticate_by_code, open_method, Accepted, AttemptRequest, BootMarkers, CodeConversation,
    CodeDeps, CodeFlowError, CodeLogin, CodeLoginError, CodeMethodApi, CodesConfig, DeviceProbe,
    HostIdSourceKind, Level, LevelError, PamConvError, SystemTime,
};

/// The login account, which is also the role.
const ROLE: &str = "oper";

/// What the operator's cabinet computed, as far as these tests care.
const RIGHT_CODE: &str = "13572468";

/// The epoch the method reports it is running under.
///
/// Different from the one the fixture configuration names, because that is the
/// whole point: a persisted epoch ahead of the configured one is the situation
/// the effective-epoch selection exists for, and the audit journal of one login
/// has to name a single epoch across both halves of it.
const EFFECTIVE_EPOCH: u32 = 9;

/// Personal number the engineer gives at the device.
const ENGINEER: &str = "eng-1";

/// A conversation whose every answer is written down in advance.
struct ScriptedConversation {
    /// Answers handed to the visible prompts, in order.
    answers: VecDeque<String>,
    /// Prompts that were actually asked, in order.
    asked: Vec<String>,
    /// Messages that were shown, in order.
    shown: Vec<String>,
    /// Whether the secret prompt was driven, and how often.
    secrets_asked: usize,
}

impl ScriptedConversation {
    fn new<I: IntoIterator<Item = &'static str>>(answers: I) -> Self {
        Self {
            answers: answers.into_iter().map(str::to_owned).collect(),
            asked: Vec::new(),
            shown: Vec::new(),
            secrets_asked: 0,
        }
    }
}

impl CodeConversation for ScriptedConversation {
    fn show_info(&mut self, message: &str) {
        self.shown.push(message.to_owned());
    }

    fn prompt_visible(&mut self, prompt: &str) -> Result<String, PamConvError> {
        self.asked.push(prompt.to_owned());
        self.answers.pop_front().ok_or(PamConvError::ConvFailed)
    }

    fn prompt_secret(&mut self, prompt: &str) -> Result<SecretString, PamConvError> {
        self.asked.push(prompt.to_owned());
        self.secrets_asked += 1;
        Ok(SecretString::from("1234".to_owned()))
    }
}

/// A device whose level and boot markers are whatever the test says.
struct ScriptedProbe {
    /// One answer per read; the last one repeats, so a test that only cares
    /// about one reading does not have to spell out both.
    levels: RefCell<VecDeque<Result<Level, LevelError>>>,
    /// Whether the boot markers can be read at all.
    markers_readable: bool,
}

impl ScriptedProbe {
    fn at_level(level: u32) -> Self {
        Self {
            levels: RefCell::new(VecDeque::from([Ok(Level::new(level))])),
            markers_readable: true,
        }
    }

    fn levels<I: IntoIterator<Item = Result<Level, LevelError>>>(readings: I) -> Self {
        Self {
            levels: RefCell::new(readings.into_iter().collect()),
            markers_readable: true,
        }
    }
}

impl DeviceProbe for ScriptedProbe {
    fn integrity_level(&self) -> Result<Level, LevelError> {
        let mut levels = self.levels.borrow_mut();
        if levels.len() > 1 {
            return levels.pop_front().unwrap_or(Err(LevelError::Empty));
        }
        match levels.front() {
            Some(Ok(level)) => Ok(*level),
            _ => Err(LevelError::Empty),
        }
    }

    fn boot_markers(&self) -> Result<BootMarkers, std::io::Error> {
        if self.markers_readable {
            Ok(BootMarkers::new("boot-1", Duration::from_secs(120)))
        } else {
            Err(std::io::Error::other("no /proc on this fixture"))
        }
    }
}

/// A method whose verdicts are written down in advance.
///
/// The attempt it hands out is the spoken form of the challenge, which is all
/// the branch ever does with it.
struct ScriptedMethod {
    /// What `begin` answers.
    start: RefCell<Option<Result<String, CodeLoginError>>>,
    /// One verdict per verification, in order.
    verdicts: RefCell<VecDeque<Result<Accepted, CodeLoginError>>>,
    /// The codes that were presented, in order.
    presented: RefCell<Vec<String>>,
    /// How often the branch asked which epoch the method runs under.
    epoch_reads: RefCell<usize>,
}

impl ScriptedMethod {
    fn with_verdicts<I: IntoIterator<Item = Result<Accepted, CodeLoginError>>>(
        verdicts: I,
    ) -> Self {
        Self {
            start: RefCell::new(Some(Ok("77-000123M 004217-8391".to_owned()))),
            verdicts: RefCell::new(verdicts.into_iter().collect()),
            presented: RefCell::new(Vec::new()),
            epoch_reads: RefCell::new(0),
        }
    }

    fn refusing_to_start(error: CodeLoginError) -> Self {
        Self {
            start: RefCell::new(Some(Err(error))),
            verdicts: RefCell::new(VecDeque::new()),
            presented: RefCell::new(Vec::new()),
            epoch_reads: RefCell::new(0),
        }
    }
}

/// What an accepted code grants in these tests: a login at `level`, under a
/// ticket that reaches exactly that far.
fn accepted(level: u32) -> Accepted {
    accepted_under_ceiling(level, level)
}

/// An accepted code whose ticket reaches higher than the login it granted.
fn accepted_under_ceiling(level: u32, ceiling: u32) -> Accepted {
    Accepted {
        claimed_engineer_no: ENGINEER.to_owned(),
        role_id: ROLE.to_owned(),
        level: Level::new(level),
        level_ceiling: Level::new(ceiling),
        ticket_number: "tk-17".to_owned(),
        nonce_ref: "000042-8391".to_owned(),
    }
}

impl CodeMethodApi for ScriptedMethod {
    type Attempt = String;

    fn epoch(&self) -> u32 {
        // Deliberately not the epoch of the fixture configuration: the branch
        // must read this one, and a test where the two agreed would not notice
        // if it went back to reading the other.
        *self.epoch_reads.borrow_mut() += 1;
        EFFECTIVE_EPOCH
    }

    fn begin(
        &self,
        _request: &AttemptRequest<'_>,
        _markers: &BootMarkers,
    ) -> Result<Self::Attempt, CodeLoginError> {
        self.start
            .borrow_mut()
            .take()
            .unwrap_or(Err(CodeLoginError::Denied))
    }

    fn spoken_form(&self, attempt: &Self::Attempt) -> String {
        attempt.clone()
    }

    fn verify(
        &self,
        _attempt: &mut Self::Attempt,
        presented: &str,
        _markers: &BootMarkers,
    ) -> Result<Accepted, CodeLoginError> {
        self.presented.borrow_mut().push(presented.to_owned());
        self.verdicts
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(CodeLoginError::Denied))
    }
}

/// A role store holding exactly the role these tests log into.
///
/// The slice names no `mac_mask`, which is what a role on a device without a
/// mandatory mechanism looks like.
fn role_store(dir: &Path) -> RoleStore {
    std::fs::write(
        dir.join("oper.toml"),
        b"role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"oper\"\nlevel = 1\n".as_slice(),
    )
    .unwrap();
    RoleStore::load(
        dir,
        RoleOs::Linux,
        TrustMode::Standalone,
        SystemAccounts::empty(),
    )
    .unwrap()
}

/// The same role as an Astra device would define it: asking for two МКЦ
/// categories, and stating no level of its own, because a slice cannot.
fn astra_role_store(dir: &Path) -> RoleStore {
    std::fs::write(
        dir.join("oper.toml"),
        b"role = \"oper\"\nversion = 1\nos = \"astra\"\nname = \"oper\"\nlevel = 1\n\
          [payload]\nmac_mask = \"0x3\"\n"
            .as_slice(),
    )
    .unwrap();
    RoleStore::load(
        dir,
        RoleOs::Astra,
        TrustMode::Standalone,
        SystemAccounts::empty(),
    )
    .unwrap()
}

/// A configured method. Its paths point at a directory nothing reads: the
/// scripted method never opens an artefact, and what the branch takes from the
/// configuration is the epoch and the attempt budget.
fn config(dir: &Path) -> CodesConfig {
    CodesConfig {
        paths: CodesPaths::under(dir),
        params: FleetParams::defaults(),
        device_number: CheckedDeviceNumber::from_body("77-000123").unwrap(),
        epoch: Epoch::new(7),
        device_scope: DeviceScope {
            tags: vec!["dc-1".to_owned()],
            region: "ru-south".to_owned(),
        },
        code_ttl: Duration::from_secs(300),
        gost_engine_path: None,
    }
}

/// Everything a run needs, kept alive together.
/// A daemon that writes down what it was told to record.
///
/// Registration is what makes the term of a session enforceable, so the tests
/// have to see the payload rather than only the verdict: the deadline is the
/// whole point of the call.
#[derive(Default)]
struct RecordingMonitor {
    /// What each `open_session` carried, in order.
    opened: Mutex<Vec<RecordedSession>>,
    /// Session ids withdrawn through `close_session`, with their reason.
    closed: Mutex<Vec<(String, String)>>,
    /// What `open_session` answers, when it is not to succeed.
    refusal: Option<IpcError>,
}

/// The fields of an `OpenSessionInfo` these tests judge.
#[derive(Debug, Clone)]
struct RecordedSession {
    session_id: String,
    pam_user: String,
    role: Option<String>,
    session_expiry: Option<SystemTime>,
    usb_serial: Option<String>,
    target: tessera_proto::SessionTarget,
}

impl RecordingMonitor {
    /// A daemon that refuses every registration with `error`.
    fn refusing(error: IpcError) -> Self {
        Self {
            opened: Mutex::new(Vec::new()),
            closed: Mutex::new(Vec::new()),
            refusal: Some(error),
        }
    }

    /// The single session that was registered.
    fn only_session(&self) -> RecordedSession {
        let opened = self.opened.lock().unwrap();
        assert_eq!(opened.len(), 1, "expected exactly one registration");
        opened.first().unwrap().clone()
    }
}

impl MonitorClient for RecordingMonitor {
    fn open_session(&self, info: &tessera_core::ipc::OpenSessionInfo<'_>) -> Result<(), IpcError> {
        self.opened.lock().unwrap().push(RecordedSession {
            session_id: info.session_id.to_owned(),
            pam_user: info.pam_user.to_owned(),
            role: info.role.map(str::to_owned),
            session_expiry: info.session_expiry,
            usb_serial: info.usb_serial.map(str::to_owned),
            target: info.target.clone(),
        });
        match &self.refusal {
            Some(error) => Err(clone_ipc_error(error)),
            None => Ok(()),
        }
    }

    fn close_session(&self, session_id: &str, reason: &str) -> Result<(), IpcError> {
        self.closed
            .lock()
            .unwrap()
            .push((session_id.to_owned(), reason.to_owned()));
        Ok(())
    }

    fn hello(&self) -> Result<(), IpcError> {
        Ok(())
    }

    fn ping(&self) -> Result<(), IpcError> {
        Ok(())
    }
}

/// `IpcError` is not `Clone`; the tests only ever need these two back.
fn clone_ipc_error(error: &IpcError) -> IpcError {
    match error {
        IpcError::Unauthorized => IpcError::Unauthorized,
        _ => IpcError::Timeout,
    }
}

struct Harness {
    _dir: TempDir,
    store: RoleStore,
    config: CodesConfig,
    monitor: RecordingMonitor,
    fail_mode: MonitorFailMode,
}

impl Harness {
    fn new() -> Self {
        Self::with_store(role_store)
    }

    /// A device whose role asks for МКЦ categories.
    fn astra() -> Self {
        Self::with_store(astra_role_store)
    }

    fn with_store(load: fn(&Path) -> RoleStore) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = load(dir.path());
        let config = config(dir.path());
        Self {
            _dir: dir,
            store,
            config,
            monitor: RecordingMonitor::default(),
            fail_mode: MonitorFailMode::Strict,
        }
    }

    /// The same device whose daemon refuses every registration.
    fn with_refusing_daemon(error: IpcError, fail_mode: MonitorFailMode) -> Self {
        Self {
            monitor: RecordingMonitor::refusing(error),
            fail_mode,
            ..Self::new()
        }
    }

    fn deps(&self) -> CodeDeps<'_> {
        CodeDeps {
            config: &self.config,
            store: &self.store,
            accounts: AccountCheck::from_store(&self.store),
            default_session_ttl: Duration::from_secs(43_200),
            host_id_hash: "0123456789abcdef",
            host_id_source: HostIdSourceKind::Override,
            monitor: &self.monitor,
            monitor_fail_mode: self.fail_mode,
            pam_target: tessera_proto::SessionTarget::tty("/dev/tty3"),
        }
    }

    fn run(
        &self,
        method: &ScriptedMethod,
        conv: &mut ScriptedConversation,
        probe: &ScriptedProbe,
        pam_user: &str,
    ) -> Result<tessera_core::pam_data::AuthContext, CodeFlowError> {
        let login = CodeLogin {
            pam_user,
            pam_service: "codeauth",
            session_id: "sess-code".to_owned(),
            // A moment inside the term of the fixture ticket the core tests
            // use, so the two fixtures agree on when "now" is.
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        };
        // Held for the whole attempt: the audit sink is process-wide, and the
        // fail-closed tests next door install a journal into it.
        let _sink = super::test_sink::hold();
        authenticate_by_code(&self.deps(), login, method, conv, probe)
            .map(|outcome| outcome.auth_ctx)
    }
}

#[test]
fn a_dictated_code_admits_the_engineer() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let ctx = harness.run(&method, &mut conv, &probe, ROLE).unwrap();

    assert_eq!(ctx.session_id, "sess-code");
    assert_eq!(ctx.pam_service, "codeauth");
    assert_eq!(ctx.role.as_ref().unwrap().role.as_str(), ROLE);
    // There is no certificate in this login, and nothing may claim there was.
    assert!(ctx.cert_cn.is_none());
    assert!(ctx.cert_serial.is_none());
    assert!(ctx.cert_ident.is_none());
    assert!(ctx.cert_not_after.is_none());
    assert!(ctx.usb_serial.is_none());
    // The session is bounded: a role that names no TTL takes the global one.
    assert!(ctx.role.as_ref().unwrap().ttl > Duration::ZERO);
}

#[test]
fn the_session_is_registered_with_a_deadline_the_daemon_can_enforce() {
    // The invariant this closes: the branch used to snapshot a bounded TTL into
    // the context and tell nobody, so the session ran until its owner logged
    // out. The daemon is what ends a session at its term, and it only ends the
    // ones it was told about.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let ctx = harness.run(&method, &mut conv, &probe, ROLE).unwrap();
    let recorded = harness.monitor.only_session();

    assert_eq!(recorded.session_id, ctx.session_id);
    assert_eq!(recorded.pam_user, ROLE);
    assert_eq!(recorded.role.as_deref(), Some(ROLE));
    assert!(
        recorded.session_expiry.is_some(),
        "a session registered without a deadline is an unbounded session",
    );
    // The daemon needs somewhere to act when the term runs out; a session it
    // cannot locate is one it cannot end.
    assert_eq!(
        recorded.target,
        tessera_proto::SessionTarget::tty("/dev/tty3")
    );
    // No carrier travelled with this login, and none may be claimed: the
    // daemon skips every presence check for a session without a serial, which
    // is exactly right here — there is nothing to watch for.
    assert!(recorded.usb_serial.is_none());
}

#[test]
fn the_deadline_is_the_term_of_the_role_measured_from_the_login() {
    // Anchored at the moment of authentication, and bounded by the role alone:
    // there is no certificate in this path, so there is no `notAfter` to clamp
    // against — which is why the value is exactly the role term and not the
    // earlier of two things.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let ctx = harness.run(&method, &mut conv, &probe, ROLE).unwrap();
    let recorded = harness.monitor.only_session();

    let ttl = ctx.role.as_ref().unwrap().ttl;
    assert_eq!(
        recorded.session_expiry,
        Some(ctx.authenticated_at + ttl),
        "the deadline is the moment of authentication plus the term of the role",
    );
}

#[test]
fn a_daemon_that_cannot_record_the_session_refuses_the_login_in_strict_mode() {
    // A session nobody will end is not opened. The refusal carries the code the
    // certificate path returns for the same failure, so one fault reads the
    // same way whichever method met it.
    let harness = Harness::with_refusing_daemon(IpcError::Timeout, MonitorFailMode::Strict);
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::MonitorRegistration(_)));
    assert_eq!(error.pam_code(), 6);
}

#[test]
fn a_permissive_mode_admits_the_login_and_says_the_term_will_not_apply() {
    // The engineer gets in — availability is the point of the permissive mode —
    // but the session has no enforced end, and that is what the journal has to
    // record. A generic "the daemon did not answer" would leave an auditor to
    // work out the consequence for themselves.
    let harness = Harness::with_refusing_daemon(IpcError::Timeout, MonitorFailMode::Permissive);
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let ctx = harness.run(&method, &mut conv, &probe, ROLE).unwrap();

    assert_eq!(ctx.role.as_ref().unwrap().role.as_str(), ROLE);
    // The attempt to register was made, and made with a deadline: the mode
    // decides what a failure costs, not whether the daemon is told.
    assert!(harness.monitor.only_session().session_expiry.is_some());
}

#[test]
fn a_daemon_that_rejects_the_registration_refuses_the_login_in_either_mode() {
    // `Unauthorized` is not a daemon that failed to answer, it is a daemon that
    // answered no. The permissive mode exists for a socket that is not there,
    // not for a refusal.
    for mode in [MonitorFailMode::Strict, MonitorFailMode::Permissive] {
        let harness = Harness::with_refusing_daemon(IpcError::Unauthorized, mode);
        let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
        let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
        let probe = ScriptedProbe::at_level(1);

        let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

        assert!(
            matches!(error, CodeFlowError::MonitorRegistration(_)),
            "mode {mode:?}: unexpected {error:?}",
        );
        assert_eq!(error.pam_code(), 6, "mode {mode:?}");
    }
}

#[test]
fn the_session_ceiling_is_the_ticket_and_not_the_level_of_the_login() {
    // A ticket that reaches level 3, used for a login at level 1. The ceiling
    // the session label is computed against is the ticket's — the same part the
    // `MAX_INTEGRITY` extension plays for a certificate — and it is stated,
    // rather than left empty for the session phase to guess at.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted_under_ceiling(1, 3))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let ctx = harness.run(&method, &mut conv, &probe, ROLE).unwrap();

    let ceiling = ctx
        .cert_max_integrity
        .expect("a code login states the ceiling it was authorised under");
    assert_eq!(ceiling.level, 3);
    assert_eq!(
        ceiling.categories,
        u64::MAX,
        "a ticket bounds the level and narrows no category",
    );
    // A role without a mac_mask — every role on a device with no mandatory
    // mechanism — still logs in, and asks for no category.
    assert_eq!(ctx.role.as_ref().unwrap().mac_mask, None);
}

#[test]
fn a_ticket_above_what_a_label_can_hold_is_capped_rather_than_wrapped() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted_under_ceiling(1, 4096))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let ctx = harness.run(&method, &mut conv, &probe, ROLE).unwrap();

    assert_eq!(
        ctx.cert_max_integrity.unwrap().level,
        IntegrityLabel::MAX_LEVEL,
    );
}

#[test]
fn the_session_opens_when_the_cert_integrity_policy_is_required() {
    // The defect this covers: with no ceiling in the context, `required` had
    // the orchestrator refuse every code login for want of a certificate
    // extension no code login can carry, and the label of the session was never
    // computed at the level the operator had authorised.
    let harness = Harness::astra();
    let method = ScriptedMethod::with_verdicts([Ok(accepted_under_ceiling(1, 2))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let ctx = harness.run(&method, &mut conv, &probe, ROLE).unwrap();
    // The categories the role asks for are snapshotted into the session; the
    // level is not among them, and never was.
    assert_eq!(ctx.role.as_ref().unwrap().mac_mask, Some(0b11));

    let applied: Arc<Mutex<Option<IntegrityLabel>>> = Arc::new(Mutex::new(None));
    let mut backend = MockMacBackend::new();
    backend.expect_probe().returning(|| MacRuntime::Active);
    backend.expect_get_user_mnkc().returning(|_| {
        Ok(IntegrityLabel {
            level: 5,
            categories: 0b111,
        })
    });
    let seen = Arc::clone(&applied);
    backend.expect_apply_session().returning(move |label| {
        *seen.lock().unwrap() = Some(label);
        Ok(())
    });

    // The two values the session phase takes from the context, taken here the
    // same way `session::run_open_session_pipeline_with_backend` takes them.
    let role_mac_mask = ctx
        .role
        .as_ref()
        .and_then(|role| role.mac_mask)
        .map(IntegrityLabel::from_mac_mask);
    let policy = MacPolicy {
        cert_integrity: CertIntegrityMode::Required,
        ..MacPolicy::default()
    };
    let sctx = SessionContext {
        pam_user: ROLE.to_owned(),
        pam_service: "codeauth".to_owned(),
        // Empty, as the session phase builds it for a login with no
        // certificate: the audit fields of one are not invented here.
        cert_ident: CertIdent {
            serial: String::new(),
            issuer: String::new(),
            cn: String::new(),
            fingerprint: String::new(),
        },
        home_dir: None,
    };

    let outcome = apply_session_policy(
        &backend,
        &policy,
        ctx.cert_max_integrity,
        role_mac_mask,
        &sctx,
    );
    assert!(
        outcome.is_ok(),
        "a code login must open a session under cert_integrity=required: {outcome:?}",
    );
    let applied = applied.lock().unwrap().expect("the label was applied");
    assert_eq!(
        applied.categories, 0b11,
        "the session carries the categories the role asked for",
    );
}

#[test]
fn the_challenge_is_printed_before_the_code_is_asked_for() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    harness.run(&method, &mut conv, &probe, ROLE).unwrap();

    assert_eq!(
        conv.asked,
        vec![
            super::SERVER_PROMPT.to_owned(),
            super::ENGINEER_PROMPT.to_owned(),
            super::CODE_PROMPT.to_owned()
        ],
        "the operator is named, then the engineer names themselves, then the \
         code is asked for — and nothing else is, least of all anything about \
         the key of the device",
    );
    let shown = conv.shown.first().expect("the challenge is printed");
    assert!(
        shown.contains("77-000123M"),
        "the printed challenge carries the device number: {shown}"
    );
    // Nothing is ever asked in secret. The key of the device is opened by the
    // device out of a root-only file, so an engineer has no secret to give and
    // — the point of the method — a device left alone after a power cut has
    // nobody to give it.
    assert_eq!(conv.secrets_asked, 0);
}

#[test]
fn a_wrong_code_is_asked_for_again() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Err(CodeLoginError::Denied), Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, "00000000", RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    harness.run(&method, &mut conv, &probe, ROLE).unwrap();

    assert_eq!(
        *method.presented.borrow(),
        vec!["00000000".to_owned(), RIGHT_CODE.to_owned()]
    );
    assert!(conv.shown.iter().any(|m| m == super::RETRY_MESSAGE));
    assert_eq!(conv.secrets_asked, 0);
}

#[test]
fn a_spent_attempt_budget_is_passed_through_as_max_tries() {
    // The mapping only: this scripts the verdict, so it says nothing about
    // whether a real method ever produces it. That the branch actually reaches
    // 11 — that N wrong codes in one conversation come back as PAM_MAXTRIES —
    // is pinned against the real `CodeMethod` in `live_tests`, and has to be:
    // a scripted method answers whatever the test author assumed, which is the
    // one thing worth doubting here.
    //
    // 11 is the code that tells the application to stop asking rather than to
    // go looking elsewhere for the credential.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Err(CodeLoginError::AttemptsExhausted)]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, "00000000"]);
    let probe = ScriptedProbe::at_level(1);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::AttemptsExhausted));
    assert_eq!(error.pam_code(), 11);
}

#[test]
fn the_retry_loop_does_not_outlive_the_attempt_budget() {
    // A refusal that costs no attempt — a ticket that stopped admitting the
    // request, say — must not let the branch keep asking for ever.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts(
        std::iter::repeat_with(|| Err(CodeLoginError::Denied)).take(16),
    );
    let mut conv = ScriptedConversation::new(std::iter::once("op-42").chain(["00000000"; 16]));
    let probe = ScriptedProbe::at_level(1);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::Denied));
    assert_eq!(error.pam_code(), 7);
    assert_eq!(
        method.presented.borrow().len(),
        usize::from(FleetParams::defaults().attempts_per_nonce()),
        "one prompt per attempt the nonce is allowed, and not one more",
    );
}

#[test]
fn a_level_that_cannot_be_read_stops_the_attempt_before_any_prompt() {
    // The label of a process on a kernel that labels nothing. Reading it as
    // the base level would hand the device a level nobody authorised.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(0))]);
    let mut conv = ScriptedConversation::new([]);
    let probe = ScriptedProbe::levels([Err(LevelError::Empty)]);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::Level(_)));
    assert_eq!(error.pam_code(), 6);
    assert!(
        conv.asked.is_empty(),
        "nothing is asked for on a device whose level is unknown"
    );
}

#[test]
fn a_level_that_changed_during_the_attempt_refuses_the_login() {
    // The window the second read exists to close: the code was computed for
    // level 1 and the session is now running at level 3.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::levels([Ok(Level::new(1)), Ok(Level::new(3))]);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(
        error,
        CodeFlowError::LevelChanged {
            granted: 1,
            observed: 3
        }
    ));
    assert_eq!(error.pam_code(), 6);
}

#[test]
fn a_level_that_became_unreadable_after_the_code_refuses_the_login() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::levels([Ok(Level::new(1)), Err(LevelError::Empty)]);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::Level(_)));
    assert_eq!(error.pam_code(), 6);
}

#[test]
fn an_answer_past_the_bound_is_refused_without_a_verification() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let long_code: &'static str = Box::leak("9".repeat(super::MAX_CODE_LEN + 1).into_boxed_str());
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, long_code]);
    let probe = ScriptedProbe::at_level(1);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::Input { .. }));
    assert_eq!(error.pam_code(), 7);
    assert!(
        method.presented.borrow().is_empty(),
        "an answer over the bound never reaches the verification"
    );
}

#[test]
fn an_empty_answer_is_refused() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["   "]);
    let probe = ScriptedProbe::at_level(1);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::Input { .. }));
}

#[test]
fn an_empty_personal_number_is_refused() {
    // The engineer's number is part of the code, so a blank one would compute a
    // code nobody could reproduce — and would put an empty name in the record
    // of who came in. It is bounded exactly like the operator's.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", "   "]);
    let probe = ScriptedProbe::at_level(1);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::Input { .. }));
    assert_eq!(
        conv.asked,
        vec![
            super::SERVER_PROMPT.to_owned(),
            super::ENGINEER_PROMPT.to_owned()
        ],
        "the refusal comes at the personal number, before any challenge exists",
    );
}

#[test]
fn a_login_account_that_is_not_a_role_never_reaches_a_prompt() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new([]);
    let probe = ScriptedProbe::at_level(1);

    let error = harness
        .run(&method, &mut conv, &probe, "not a role id")
        .unwrap_err();

    assert!(matches!(error, CodeFlowError::RoleDenied(_)));
    assert_eq!(error.pam_code(), 6);
    assert!(conv.asked.is_empty());
}

#[test]
fn a_role_the_device_does_not_hold_is_refused_after_the_code() {
    // The method admitted the request against its own view of the roles; the
    // store is asked again for the payload the session will live under, and a
    // role it does not hold cannot produce one.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(Accepted {
        role_id: "stranger".to_owned(),
        ..accepted(1)
    })]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(
        error,
        CodeFlowError::RoleDenied(tessera_core::role::RoleDenyReason::NotFound)
    ));
}

#[test]
fn a_device_that_cannot_run_the_method_is_not_a_failed_attempt() {
    // A state directory that cannot be read or locked — another login already
    // holding the one attempt this device has, a file the device cannot write —
    // is not a verdict about the code, and it may not read as "try the next
    // method in the stack".
    let harness = Harness::new();
    let method = ScriptedMethod::refusing_to_start(CodeLoginError::State {
        reason: "the code state of this device could not be locked".to_owned(),
    });
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER]);
    let probe = ScriptedProbe::at_level(1);

    let flow_error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(flow_error, CodeFlowError::DeviceState(_)));
    assert_eq!(flow_error.pam_code(), 4);
}

#[test]
fn a_platform_without_the_method_falls_through_instead_of_failing_the_stack() {
    // The companion of the test above, and the line between them is the whole
    // point: a fault gets `PAM_SYSTEM_ERR`, and a method that cannot exist on
    // this platform gets the one code a stack may be configured to step over.
    // A Windows service offering both the certificate path and the code path
    // must reach the certificate path, not stop at a system error.
    let harness = Harness::new();
    let method = ScriptedMethod::refusing_to_start(CodeLoginError::UnsupportedPlatform);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER]);
    let probe = ScriptedProbe::at_level(1);

    let flow_error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(flow_error, CodeFlowError::UnsupportedPlatform));
    assert_eq!(flow_error.pam_code(), 9);
    // And it is the same code an unprovisioned device gets, because a stack has
    // one thing to do about either.
    assert_eq!(CodeFlowError::Unavailable.pam_code(), 9);
}

#[test]
fn a_device_without_the_method_falls_through_to_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = role_store(dir.path());

    let Err(error) = open_method(None, &store) else {
        panic!("a device with no configured method must not open one")
    };

    assert!(matches!(error, CodeFlowError::Unavailable));
    assert_eq!(
        error.pam_code(),
        9,
        "PAM_AUTHINFO_UNAVAIL is the only refusal a stack may be configured to step over",
    );
}

// Unix-only: this asserts a state of a device that runs the method — it was
// given no artefacts — and off Unix the method does not run at all, so the
// answer there is `UnsupportedPlatform` and comes first, before anything on
// disk is looked at. Accepting either verdict here would blur the line
// between "this device is not set up" and "this platform cannot carry the
// method", which is the distinction the return codes were just split on.
#[cfg(unix)]
#[test]
fn a_device_carrying_no_artefacts_does_not_offer_the_method() {
    let dir = tempfile::tempdir().unwrap();
    let store = role_store(dir.path());
    let config = config(dir.path());

    let Err(error) = open_method(Some(&config), &store) else {
        panic!("a device carrying no artefacts must not open the method")
    };

    assert!(matches!(error, CodeFlowError::Unavailable));
}

#[test]
fn unreadable_boot_markers_refuse_the_login() {
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe {
        levels: RefCell::new(VecDeque::from([Ok(Level::new(1))])),
        markers_readable: false,
    };

    let error = harness.run(&method, &mut conv, &probe, ROLE).unwrap_err();

    assert!(matches!(error, CodeFlowError::DeviceState(_)));
    assert_eq!(error.pam_code(), 4);
}

/// The numbers this branch returns, checked against the header PAM itself is
/// built from rather than against our own documentation.
///
/// The mapping has been wrong here before: `PAM_MAXTRIES` was taken to be 8,
/// which is `PAM_CRED_INSUFFICIENT` and tells a waiting application a
/// different story entirely.
///
/// The constants are compared without a cast on purpose. `pam-sys` generates
/// them from `<security/_pam_types.h>` of the system it is built on, so a
/// header that ever changed their type would surface here as a build break
/// rather than as a silent conversion.
#[cfg(target_os = "linux")]
#[test]
fn every_return_code_matches_the_pam_header() {
    assert_eq!(super::PAM_SYSTEM_ERR, pam_sys::PAM_SYSTEM_ERR);
    assert_eq!(super::PAM_PERM_DENIED, pam_sys::PAM_PERM_DENIED);
    assert_eq!(super::PAM_AUTH_ERR, pam_sys::PAM_AUTH_ERR);
    assert_eq!(super::PAM_AUTHINFO_UNAVAIL, pam_sys::PAM_AUTHINFO_UNAVAIL);
    assert_eq!(super::PAM_MAXTRIES, pam_sys::PAM_MAXTRIES);
    assert_ne!(
        super::PAM_MAXTRIES,
        pam_sys::PAM_CRED_INSUFFICIENT,
        "the two were confused once already",
    );
}

#[test]
fn a_journal_that_refuses_the_record_takes_the_session_back_from_the_daemon() {
    // The window this closes: the session is registered, the hash-chained
    // journal refuses the record, the login is refused — and the daemon is
    // left holding a session that never existed, which it would carry to the
    // end of its term and hand to an auditor as a login that happened.
    let harness = Harness::new();
    let ctx = registered_context(&harness);

    let outcome = super::record_success_or_withdraw(
        &harness.deps(),
        &ctx,
        ROLE,
        super::Registration::Recorded,
        || Err(refusing_journal_error()),
    );

    assert!(matches!(outcome, Err(CodeFlowError::Unaccountable(_))));
    let closed = harness.monitor.closed.lock().unwrap().clone();
    assert_eq!(
        closed,
        vec![(ctx.session_id.clone(), "audit_unaccountable".to_owned())],
        "the registration was not withdrawn",
    );
}

#[test]
fn a_registration_the_daemon_never_took_is_not_withdrawn() {
    // Under the permissive fail mode nothing was recorded, so there is nothing
    // to give back — and a withdrawal for a session the daemon never saw is a
    // call that can only confuse whoever reads its log.
    let harness = Harness::new();
    let ctx = registered_context(&harness);

    let outcome = super::record_success_or_withdraw(
        &harness.deps(),
        &ctx,
        ROLE,
        super::Registration::NotRecorded,
        || Err(refusing_journal_error()),
    );

    assert!(matches!(outcome, Err(CodeFlowError::Unaccountable(_))));
    assert!(harness.monitor.closed.lock().unwrap().is_empty());
}

#[test]
fn a_journal_that_takes_the_record_leaves_the_session_alone() {
    let harness = Harness::new();
    let ctx = registered_context(&harness);

    let outcome = super::record_success_or_withdraw(
        &harness.deps(),
        &ctx,
        ROLE,
        super::Registration::Recorded,
        || Ok(()),
    );

    assert!(outcome.is_ok());
    assert!(harness.monitor.closed.lock().unwrap().is_empty());
}

/// A context standing for a session that has just been registered.
fn registered_context(harness: &Harness) -> tessera_core::pam_data::AuthContext {
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);
    harness.run(&method, &mut conv, &probe, ROLE).unwrap()
}

/// The failure a hash-chained journal reports when it will not take a record.
fn refusing_journal_error() -> tessera_core::audit::AuditError {
    // The journal at its ceiling with `when_full = refuse`: a real refusal an
    // offline device meets, not an invented one.
    tessera_core::audit::AuditError::Full {
        ceiling_bytes: 1024,
        used_bytes: 1024,
    }
}

#[test]
fn the_branch_takes_the_epoch_from_the_method_and_not_from_the_configuration() {
    // The two differ whenever a persisted epoch is ahead of the configured one
    // — the situation the effective-epoch selection exists for. The branch used
    // to read `deps.config.epoch`, so its events named one epoch while the
    // events the method emitted for the same login named another, and the
    // journal of a single login contradicted itself exactly there.
    //
    // The fixture keeps the two apart on purpose: the configuration says 7, the
    // method says 9. What is asserted is that the branch asks the method at
    // all; that it no longer reads the configured value is structural, because
    // the field it used to read is gone from the epoch path.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    assert_ne!(
        harness.config.epoch.get(),
        EFFECTIVE_EPOCH,
        "the fixture must keep the configured and effective epochs apart",
    );

    harness.run(&method, &mut conv, &probe, ROLE).unwrap();

    assert!(
        *method.epoch_reads.borrow() > 0,
        "the branch never asked the method which epoch it is running under",
    );
}

#[test]
fn a_successful_login_says_whether_the_daemon_recorded_the_session() {
    // The caller stores the context into PAM data after this returns, and that
    // can fail. It has to know whether there is a registration to give back —
    // otherwise the phantom the journal path was taught to avoid comes back
    // through the other door.
    let harness = Harness::new();
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let outcome = super::authenticate_by_code(
        &harness.deps(),
        super::CodeLogin {
            pam_user: ROLE,
            pam_service: "codeauth",
            session_id: "sess-code".to_owned(),
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        },
        &method,
        &mut conv,
        &probe,
    )
    .unwrap();

    assert_eq!(outcome.registration, super::Registration::Recorded);
}

#[test]
fn a_permissive_login_the_daemon_refused_says_there_is_nothing_to_give_back() {
    // Nothing was recorded, so a withdrawal would name a session the daemon
    // never saw — a call that can only confuse whoever reads its log.
    let harness = Harness::with_refusing_daemon(IpcError::Timeout, MonitorFailMode::Permissive);
    let method = ScriptedMethod::with_verdicts([Ok(accepted(1))]);
    let mut conv = ScriptedConversation::new(["op-42", ENGINEER, RIGHT_CODE]);
    let probe = ScriptedProbe::at_level(1);

    let outcome = super::authenticate_by_code(
        &harness.deps(),
        super::CodeLogin {
            pam_user: ROLE,
            pam_service: "codeauth",
            session_id: "sess-code".to_owned(),
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        },
        &method,
        &mut conv,
        &probe,
    )
    .unwrap();

    assert_eq!(outcome.registration, super::Registration::NotRecorded);
}

#[test]
fn a_withdrawal_names_the_session_and_the_reason_it_was_given_back() {
    // The reason travels to the daemon because the two doors are different
    // faults: a journal that would not account for the login, and a context
    // PAM would not carry. An operator reading the daemon log has to be able
    // to tell them apart.
    let harness = Harness::new();

    super::withdraw_code_session(
        &harness.monitor,
        "sess-code",
        ROLE,
        super::CLOSE_REASON_CONTEXT_LOST,
    );

    assert_eq!(
        *harness.monitor.closed.lock().unwrap(),
        vec![("sess-code".to_owned(), "context_not_stored".to_owned())],
    );
}

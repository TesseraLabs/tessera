//! The branch driven against a real [`CodeMethod`] on real artefacts.
//!
//! The scripted tests next door check what the PAM half decides. These check
//! the one thing a script cannot: what the method actually answers, and
//! therefore what the branch actually returns to a stack.
//!
//! That distinction is not academic. Whether `PAM_MAXTRIES` is reachable at all
//! turns on **when** the method reports an exhausted budget — on the last
//! attempt it allowed, or on the call after it. A scripted method answers
//! whichever way the test author assumed, so it can only restate the
//! assumption. Here the assumption is removed: the codes are wrong because they
//! are wrong, the counter is the persisted one, and the verdict is whatever the
//! method really gives.
//!
//! The operator's side is played the way the telephone plays it — the challenge
//! is taken from the text the branch **printed**, not from the attempt it holds
//! privately, and the code is computed from that text with the contract crate.
//! An e2e helper has no other way in either, so anything this fixture cannot do
//! from the printed form, the helper will not be able to do on a stand.
//!
//! # Why the store-backed tests here are Unix-only
//!
//! Every test that stands up a [`LiveFixture`] carries `#[cfg(unix)]`, and the
//! reason is a property of the product rather than of the harness.
//!
//! The device key is stored **without a password** — a deliberate decision of
//! this channel, because a device has to verify codes after a reboot, when
//! nobody is standing next to it to type anything. What protects that key is
//! therefore the permissions of the file it sits in, and nothing else. Outside
//! Unix there is no mode word to check: the equivalent is a DACL, and no DACL
//! work exists here. That leaves two possibilities, and only one of them is
//! acceptable — either the method does not run there, or the key that computes
//! the access codes of a cash machine lies under permissions nobody verified.
//!
//! So the refusal these tests would meet (`fs_mode`: "file permissions cannot
//! be pinned on this platform") is not an obstacle to work around. It is the
//! boundary it was written to be, and it is stated in the same terms wherever
//! else this product meets it: the artefact store (`codes::store`), the state
//! lock (`codes::lock`) and the journal storage of `tessera_hashchain`.
//!
//! What stays cross-platform is everything that does **not** stand up a store:
//! the two portability tests below, which exist precisely to catch defects that
//! only appear off Unix, and the configuration test that couples the method to
//! its journal. Gating those would hide the class of defect they guard.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed setup step in a test should fail the test on the spot, \
              including from the helper that drives one attempt"
)]
// The helper that drives one attempt is the only thing here that panics from a
// function returning `Result`, and it is part of the store-backed half — so off
// Unix there is nothing for this expectation to catch, and an expectation
// nothing fulfils is itself a warning.
#![cfg_attr(
    unix,
    expect(
        clippy::panic_in_result_fn,
        reason = "the helper driving one attempt fails the test where the step failed"
    )
)]

#[cfg(unix)]
use std::cell::RefCell;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use openssl::bn::{BigNum, BigNumContext};
#[cfg(unix)]
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
#[cfg(unix)]
use openssl::nid::Nid;
#[cfg(unix)]
use openssl::pkey::{PKey, Private};
#[cfg(unix)]
use openssl::x509::{X509Builder, X509NameBuilder};
#[cfg(unix)]
use secrecy::SecretString;
#[cfg(unix)]
use tempfile::TempDir;

#[cfg(unix)]
use tessera_codes_contract::canon::Level;
#[cfg(unix)]
use tessera_codes_contract::challenge::Challenge;
#[cfg(unix)]
use tessera_codes_contract::code::compute_code;
#[cfg(unix)]
use tessera_codes_contract::device_number::CheckedDeviceNumber;
#[cfg(unix)]
use tessera_codes_contract::key::{derive_key, Epoch, KeyAgreement as _, KeyContext};
#[cfg(unix)]
use tessera_codes_contract::nonce::Nonce;
#[cfg(unix)]
use tessera_codes_contract::params::{FleetParams, FleetParamsInput};
#[cfg(unix)]
use tessera_codes_contract::profile::AlgorithmProfile;
#[cfg(unix)]
use tessera_codes_contract::signature::{PublicKey, Signature};
#[cfg(unix)]
use tessera_codes_contract::ticket::{
    OperatorTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput,
};
#[cfg(unix)]
use tessera_codes_contract::time::ClaimedTime;
#[cfg(unix)]
use tessera_core::codes::agreement::DeviceKeyAgreement;
#[cfg(unix)]
use tessera_core::codes::{CodeMethod, CodesConfig, CodesPaths, DeviceScope, LocalRoles};
#[cfg(unix)]
use tessera_core::ipc::{MonitorFailMode, StubClient};
#[cfg(unix)]
use tessera_core::pam_conv::PamConvError;
#[cfg(unix)]
use tessera_core::role::{AccountCheck, RoleOs, RoleStore, SystemAccounts, TrustMode};

#[cfg(unix)]
use super::{
    authenticate_by_code, CodeConversation, CodeDeps, CodeFlowError, CodeLogin, DeviceProbe,
    HostIdSourceKind, LevelError, SystemTime,
};

/// The fixture container carries no password, the way a stored one does: the
/// PIN protects a container while it travels, and the import re-writes the key
/// without one before it ever reaches the store.
#[cfg(unix)]
const STORED_CONTAINER_PASSWORD: &str = "";

/// The login account, which is also the role.
#[cfg(unix)]
const ROLE: &str = "oper";

/// The operator on the telephone.
#[cfg(unix)]
const OPERATOR: &str = "op-42";

/// The level the fixture logs in at.
#[cfg(unix)]
const LEVEL: u32 = 1;

/// A code that meets no key: eight digits the fixture never computes.
#[cfg(unix)]
const WRONG_CODE: &str = "00000000";

/// A P-256 key pair, as a private key and its uncompressed public point.
#[cfg(unix)]
fn p256_pair() -> (PKey<Private>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let point = key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)
        .unwrap();
    (PKey::from_ec_key(key).unwrap(), point)
}

/// A PKCS#12 container holding `key` and a self-signed certificate for it.
#[cfg(unix)]
fn container(key: &PKey<Private>) -> Vec<u8> {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "device 77-000123")
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
        .set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap())
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

/// The whole channel on disk, plus the operator's half in memory.
#[cfg(unix)]
struct LiveFixture {
    _dir: TempDir,
    store: RoleStore,
    config: CodesConfig,
    operator_key: PKey<Private>,
    device_point: Vec<u8>,
    ticket: SignedTicket,
    /// A daemon that accepts every registration, so nothing in these tests
    /// fails for a reason other than the channel itself.
    monitor: StubClient,
}

#[cfg(unix)]
impl LiveFixture {
    /// Builds a fixture whose nonce allows `attempts` verifications.
    #[cfg(unix)]
    fn with_attempts(attempts: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = CodesPaths::under(dir.path());
        std::fs::create_dir_all(&paths.state_dir).unwrap();

        let (device_key, device_point) = p256_pair();
        std::fs::write(&paths.device_key_container, container(&device_key)).unwrap();

        let (operator_key, operator_point) = p256_pair();
        // Ed25519 for the fleet authority: pure EdDSA, which is the branch the
        // anchor takes without a digest.
        let authority = PKey::generate_ed25519().unwrap();
        let ticket = sign_ticket(&authority, operator_point);
        std::fs::write(&paths.tickets, format!("{}\n", ticket.to_wire())).unwrap();
        std::fs::write(
            &paths.ticket_authority,
            authority.public_key_to_pem().unwrap(),
        )
        .unwrap();

        let params = FleetParams::parse(FleetParamsInput {
            attempts_per_nonce: attempts,
            ..FleetParamsInput::defaults()
        })
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
            code_ttl: Duration::from_mins(5),
            gost_engine_path: None,
        };

        let roles_dir = dir.path().join("roles");
        std::fs::create_dir_all(&roles_dir).unwrap();
        std::fs::write(
            roles_dir.join("oper.toml"),
            b"role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"oper\"\nlevel = 1\n"
                .as_slice(),
        )
        .unwrap();
        let store = RoleStore::load(
            &roles_dir,
            RoleOs::Linux,
            TrustMode::Standalone,
            SystemAccounts::empty(),
        )
        .unwrap();

        Self {
            _dir: dir,
            store,
            config,
            operator_key,
            device_point,
            ticket,
            monitor: StubClient,
        }
    }

    /// The same device whose key container the device cannot open — an
    /// enrolment that went wrong, or a store damaged after it.
    fn with_unopenable_key_container(self) -> Self {
        std::fs::write(
            &self.config.paths.device_key_container,
            b"not a container at all".as_slice(),
        )
        .unwrap();
        self
    }

    fn method(&self) -> CodeMethod {
        CodeMethod::open(self.config.clone(), LocalRoles::from_store(&self.store)).unwrap()
    }

    fn deps(&self) -> CodeDeps<'_> {
        CodeDeps {
            config: &self.config,
            store: &self.store,
            accounts: AccountCheck::from_store(&self.store),
            default_session_ttl: Duration::from_hours(12),
            host_id_hash: "0123456789abcdef",
            host_id_source: HostIdSourceKind::Override,
            // A daemon that records everything: these tests are about the
            // channel, and a registration failure here would only add a second
            // reason for a login to fail.
            monitor: &self.monitor,
            monitor_fail_mode: MonitorFailMode::Strict,
            pam_target: tessera_proto::SessionTarget::tty("/dev/tty3"),
        }
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
}

/// Signs an operator ticket the way the fleet authority would.
#[cfg(unix)]
fn sign_ticket(authority: &PKey<Private>, operator_point: Vec<u8>) -> SignedTicket {
    let ticket = OperatorTicket::new(
        OPERATOR,
        PublicKey::new(operator_point).unwrap(),
        TicketScope::new(TicketScopeInput {
            tags: vec!["dc-1".to_owned()],
            roles: vec![ROLE.to_owned()],
            region: "ru-south".to_owned(),
            max_level: Level::new(LEVEL),
        })
        .unwrap(),
        // Well past the moment the tests claim, so no run is refused by term.
        ClaimedTime::new(1_800_000_000),
        TicketNumber::parse("tk-17").unwrap(),
    )
    .unwrap();
    let message = ticket.encode().unwrap();
    let raw = openssl::sign::Signer::new_without_digest(authority)
        .unwrap()
        .sign_oneshot_to_vec(&message)
        .unwrap();
    SignedTicket::new(ticket, Signature::new(raw).unwrap())
}

/// Rebuilds a challenge out of the text the branch printed.
///
/// The spoken form is six fields separated by ` / `, with the device number and
/// the nonce broken into groups of three for reading aloud. Everything an
/// operator needs is in there and nothing else is: this function is the whole
/// of what the cabinet — or an e2e helper scraping `PAM_TEXT_INFO` — has to do.
#[cfg(unix)]
fn challenge_from_spoken(spoken: &str, params: FleetParams) -> Challenge {
    let line = spoken.lines().next_back().unwrap_or(spoken);
    let fields: Vec<&str> = line.split(" / ").collect();
    let [device, epoch, nonce, role, level, operator] = <[&str; 6]>::try_from(fields.as_slice())
        .unwrap_or_else(|_| panic!("unexpected spoken form: {line}"));
    let ungrouped = |text: &str| text.replace(' ', "");

    Challenge::new(
        CheckedDeviceNumber::parse(&ungrouped(device)).unwrap(),
        Epoch::new(epoch.parse().unwrap()),
        Nonce::parse(&ungrouped(nonce), &params).unwrap(),
        role,
        Level::new(level.parse().unwrap()),
        operator,
    )
    .unwrap()
}

/// A device standing at [`LEVEL`] whose boot markers never move.
#[cfg(unix)]
struct SteadyDevice;

#[cfg(unix)]
impl DeviceProbe for SteadyDevice {
    fn integrity_level(&self) -> Result<Level, LevelError> {
        Ok(Level::new(LEVEL))
    }

    fn boot_markers(&self) -> Result<tessera_core::codes::boot::BootMarkers, std::io::Error> {
        Ok(tessera_core::codes::boot::BootMarkers::new(
            "boot-live",
            Duration::from_mins(2),
        ))
    }
}

/// What the engineer types when the branch asks for a code.
#[cfg(unix)]
enum Typed {
    /// A code that meets nothing.
    Wrong,
    /// The code the operator computed for the printed challenge.
    Right,
    /// The same code, written down the way it was dictated: in groups.
    RightInGroups,
}

/// The engineer at the device: names the operator, reads the printed challenge
/// down the telephone, and types back whatever the script says.
#[cfg(unix)]
struct Engineer<'a> {
    fixture: &'a LiveFixture,
    /// One entry per code prompt, in order.
    script: RefCell<std::collections::VecDeque<Typed>>,
    /// The challenge that was printed, once it has been.
    printed: RefCell<Option<Challenge>>,
    /// Whether the branch asked for anything in secret. It must not: the
    /// device opens its own key, and an engineer has no secret to give.
    asked_secret: RefCell<bool>,
}

#[cfg(unix)]
impl<'a> Engineer<'a> {
    #[cfg(unix)]
    fn new<I: IntoIterator<Item = Typed>>(fixture: &'a LiveFixture, script: I) -> Self {
        Self {
            fixture,
            script: RefCell::new(script.into_iter().collect()),
            printed: RefCell::new(None),
            asked_secret: RefCell::new(false),
        }
    }
}

#[cfg(unix)]
impl CodeConversation for Engineer<'_> {
    #[cfg(unix)]
    fn show_info(&mut self, message: &str) {
        if let Some(rest) = message.strip_prefix("Продиктуйте оператору:\n") {
            *self.printed.borrow_mut() =
                Some(challenge_from_spoken(rest, self.fixture.config.params));
        }
    }

    #[cfg(unix)]
    fn prompt_visible(&mut self, prompt: &str) -> Result<String, PamConvError> {
        if prompt == super::OPERATOR_PROMPT {
            return Ok(OPERATOR.to_owned());
        }
        let Some(next) = self.script.borrow_mut().pop_front() else {
            // The engineer gave up rather than keep typing.
            return Err(PamConvError::ConvFailed);
        };
        Ok(match next {
            Typed::Wrong => WRONG_CODE.to_owned(),
            Typed::Right | Typed::RightInGroups => {
                let printed = self.printed.borrow();
                let challenge = printed
                    .as_ref()
                    .expect("the challenge is printed before the code is asked for");
                let code = self.fixture.cabinet_code(challenge);
                if matches!(next, Typed::RightInGroups) {
                    // What an engineer actually writes on the pad in front of
                    // them, and then types.
                    let (head, tail) = code.split_at(code.len() / 2);
                    format!("{head} {tail}")
                } else {
                    code
                }
            }
        })
    }

    fn prompt_secret(&mut self, _prompt: &str) -> Result<SecretString, PamConvError> {
        // Recorded rather than answered: the assertion belongs where a failing
        // test can name what went wrong — see `drive`.
        *self.asked_secret.borrow_mut() = true;
        Err(PamConvError::ConvFailed)
    }
}

/// An engineer who types one fixed code, whatever the device printed.
#[cfg(unix)]
struct Replay(String);

#[cfg(unix)]
impl CodeConversation for Replay {
    fn show_info(&mut self, _message: &str) {}

    #[cfg(unix)]
    fn prompt_visible(&mut self, prompt: &str) -> Result<String, PamConvError> {
        if prompt == super::OPERATOR_PROMPT {
            return Ok(OPERATOR.to_owned());
        }
        Ok(self.0.clone())
    }

    fn prompt_secret(&mut self, _prompt: &str) -> Result<SecretString, PamConvError> {
        // Nothing should reach here; a branch that asks fails its own test on
        // the refusal, which is the outcome that belongs in a `Result`.
        Err(PamConvError::ConvFailed)
    }
}

/// Drives one attempt against the real method.
#[cfg(unix)]
fn run<I: IntoIterator<Item = Typed>>(
    fixture: &LiveFixture,
    script: I,
) -> Result<tessera_core::pam_data::AuthContext, CodeFlowError> {
    drive(fixture, Engineer::new(fixture, script))
}

/// Drives one attempt with any conversation, holding the sink lock.
///
/// The lock matters more than it looks: the audit sink is one handle per
/// process, so a login driven outside it meets whatever journal another test
/// installed — and a journal with a zero ceiling refuses every record, which
/// turns an unrelated test into a failure of this one.
#[cfg(unix)]
fn drive_conversation<C: super::CodeConversation>(
    fixture: &LiveFixture,
    conv: &mut C,
) -> Result<tessera_core::pam_data::AuthContext, CodeFlowError> {
    let _sink = super::test_sink::hold();
    let method = fixture.method();
    let login = CodeLogin {
        pam_user: ROLE,
        pam_service: "codeauth",
        session_id: "sess-live".to_owned(),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    };
    authenticate_by_code(&fixture.deps(), login, &method, conv, &SteadyDevice)
        .map(|outcome| outcome.auth_ctx)
}

/// Drives one attempt with an engineer already built.
#[cfg(unix)]
fn drive(
    fixture: &LiveFixture,
    engineer: Engineer<'_>,
) -> Result<tessera_core::pam_data::AuthContext, CodeFlowError> {
    drive_with_config(fixture, engineer, toml::Table::new()).0
}

/// Drives one attempt with the device's audit chain set up **from `audit_toml`
/// the way a real device sets it up** — through the configuration layer and
/// `sink::install_from_config`, never by handing the sink a journal directly.
///
/// That distinction is the whole point of this helper. A test that calls
/// `sink::install` itself proves the journal works and proves nothing about
/// whether a device ever gets one, which is exactly the gap that made the
/// fail-closed contour dead on real hardware while these tests were green.
/// Here the only way a journal reaches the sink is the way production reaches
/// it, so a regression that unwires the install shows up as a failure.
///
/// `sections` are the configuration tables this test adds — `[audit]`, and
/// `[codes]` where it matters. They arrive as TOML *values*, not as text: a
/// path spliced into TOML text is a unicode escape on Windows and a path
/// everywhere else, which is a defect that hides until a Windows runner meets
/// it.
///
/// The sink lock is taken here and nowhere else: the sink is one handle per
/// process, and a test holding it across a call into [`drive`] would deadlock
/// against this.
#[cfg(unix)]
fn drive_with_config(
    fixture: &LiveFixture,
    mut engineer: Engineer<'_>,
    sections: toml::Table,
) -> (
    Result<tessera_core::pam_data::AuthContext, CodeFlowError>,
    bool,
) {
    let _sink = super::test_sink::hold();
    let config = config_with_audit(sections);
    let installed = tessera_core::audit::sink::install_from_config(&config)
        .expect("the audit journal described by the test configuration could not be opened");

    let outcome = drive_locked(fixture, &mut engineer);
    let _ = tessera_core::audit::sink::uninstall();
    (outcome, installed)
}

/// The smallest configuration that validates, with `audit_toml` spliced in.
///
/// Built through `toml` + `ValidatedConfig::try_from` — the same two steps
/// `load_validated_config` performs — so the `[audit]` section under test is
/// parsed and validated by production code rather than by the test's idea of
/// what the section means.
fn config_with_audit(sections: toml::Table) -> tessera_core::config::ValidatedConfig {
    // The anchor directory is held until validation is over: the validator
    // checks that the anchor file is there, so a fixture that dropped its
    // temporary directory first would fail on a missing file rather than on
    // whatever the test is about.
    let (document, _anchor) = fixture_document(sections);
    let raw: tessera_core::config::RawConfig = toml::Value::Table(document)
        .try_into()
        .expect("the test configuration does not parse");
    tessera_core::config::ValidatedConfig::try_from(&raw)
        .expect("the test configuration does not validate")
}

/// The fixture as a TOML document, before it becomes a configuration.
///
/// Separate from the call above so a test can look at what the fixture pins
/// rather than only at what it produces — on Unix the platform-correct monitor
/// paths and the POSIX defaults are the same strings, so nothing about the
/// finished configuration distinguishes a fixture that sets them from one that
/// lets the defaults through. The difference is only visible on Windows, and
/// structurally here.
fn fixture_document(sections: toml::Table) -> (toml::Table, tempfile::TempDir) {
    // A trust anchor has to exist for the configuration to validate at all.
    // Nothing here uses it — the code method authenticates without one — so the
    // shortest well-formed PEM does.
    const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
        -----END CERTIFICATE-----\n";

    // The skeleton carries no interpolation at all, which is the point: every
    // value that could contain a backslash is put in as *data* below, never as
    // text. A Windows temporary directory is `C:\Users\...`, and `\U` inside a
    // TOML basic string is the start of a unicode escape — so a path spliced
    // into this text does not parse there and parses fine everywhere else,
    // which is how it survived until a Windows runner met it.
    const SKELETON: &str = r#"
crypto_backend = "openssl"
mode = "pkcs12"
pkcs12_path_pattern = "{user}.p12"
[trust]
anchors = []
[trust.revocation]
mode = "none"
[host_identity]
sources = ["machine_id"]
[logging]
level = "info"
"#;

    let anchors = tempfile::tempdir().expect("anchor directory");
    let anchor = anchors.path().join("anchor.pem");
    std::fs::write(&anchor, FAKE_PEM_CERT).expect("write the anchor");

    let mut document: toml::Table =
        toml::from_str(SKELETON).expect("the test configuration skeleton does not parse");
    document
        .get_mut("trust")
        .and_then(toml::Value::as_table_mut)
        .expect("the skeleton has a [trust] table")
        .insert(
            "anchors".to_owned(),
            toml::Value::Array(vec![path(&anchor)]),
        );

    // `[monitor]` from the shared fixture rather than from the defaults.
    //
    // The defaults are POSIX paths — `/run/tessera/monitord.sock` — and unlike
    // `[roles].dir` or `[codes].dir`, which are checked only when set
    // explicitly, the monitor paths are validated whatever their origin. On
    // Windows a path with no drive letter is not absolute, so the default
    // itself is refused and the configuration never validates.
    //
    // These values satisfy the validator; they are not a statement about what
    // the product uses on either platform — the Windows transport is a named
    // pipe. `test_support` says the same at greater length, and is the one home
    // for both platform traps this fixture kept walking into.
    let monitor: toml::Table = toml::from_str(&crate::test_support::monitor_section_toml())
        .expect("the shared [monitor] fixture parses");
    for (name, value) in monitor {
        document.insert(name, value);
    }

    for (name, value) in sections {
        document.insert(name, value);
    }
    (document, anchors)
}

/// The defect this harness had, frozen so it cannot come back.
///
/// A Windows temporary directory is `C:\Users\runneradmin\AppData\Local\Temp\…`,
/// and `\U` inside a TOML **basic** string begins a unicode escape. Splicing
/// such a path into configuration text therefore fails to parse on Windows and
/// parses perfectly everywhere else — which is exactly why eleven tests here
/// were green on two platforms and red on the third.
///
/// The test needs no Windows to catch the class: the shape of the path is what
/// matters, not the machine running it.
#[test]
fn a_windows_style_path_breaks_spliced_toml_and_survives_a_toml_value() {
    let windows_path = r"C:\Users\runneradmin\AppData\Local\Temp\.tmpAbC\audit.ndjson";

    // The old harness: the path pasted into a basic string.
    let spliced = format!("[audit]\nfile = \"{windows_path}\"\n");
    let refused = toml::from_str::<toml::Table>(&spliced).expect_err(
        "a Windows path spliced into TOML text parsed; this test no longer guards anything",
    );
    assert!(
        refused.message().contains("unicode"),
        "refused for another reason than the escape: {}",
        refused.message(),
    );

    // The harness as it is now: the path handed over as a value.
    let mut audit = toml::Table::new();
    audit.insert("file".to_owned(), path(std::path::Path::new(windows_path)));
    let rendered = toml::to_string(&audit).expect("a table of one string encodes");
    let parsed: toml::Table = toml::from_str(&rendered).expect("what the encoder wrote, it reads");
    assert_eq!(
        parsed
            .get("file")
            .and_then(toml::Value::as_str)
            .expect("a string came back"),
        windows_path,
        "the path did not survive the encoder unchanged",
    );
}

/// The fixture must pin the monitor paths, not inherit them.
///
/// `[monitor].socket_path` and `state_file_path` are the one pair config
/// validation checks for absoluteness **whatever their origin** — unlike
/// `[roles].dir` and `[codes].dir`, which are checked only when set. Their
/// defaults are POSIX, and a path with no drive letter is not absolute on
/// Windows, so a fixture that lets them through validates here and is refused
/// there.
///
/// Checked structurally rather than by value on purpose: on Unix the
/// platform-correct fixture path and the POSIX default are the same string, so
/// no assertion about the finished configuration can tell the two apart. What
/// can be told apart is whether the fixture said anything at all.
#[test]
fn the_fixture_pins_the_monitor_paths_rather_than_inheriting_posix_defaults() {
    let (document, _anchor) = fixture_document(toml::Table::new());
    let monitor = document
        .get("monitor")
        .and_then(toml::Value::as_table)
        .expect("the fixture carries a [monitor] table; without it Windows refuses the defaults");

    for field in ["socket_path", "state_file_path"] {
        let value = monitor
            .get(field)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("the fixture pins [monitor].{field}"));
        assert!(
            std::path::Path::new(value).is_absolute(),
            "[monitor].{field} is not absolute on this platform: {value}",
        );
    }
}

/// A filesystem path as a TOML value.
///
/// Going through the value type instead of `format!` means the encoder owns the
/// quoting, and the backslashes of a Windows path are data rather than escape
/// sequences.
///
/// There are two safe routes in this repository and this is the second of them.
/// [`crate::test_support::toml_path`] is the first: it renders a path as an
/// already-quoted, already-escaped TOML fragment for a harness that builds its
/// configuration as text, and `flow.rs` uses it that way. This harness builds
/// its configuration as a table instead, so it needs the value rather than the
/// fragment.
///
/// What there is no route for — and what this module used to do — is
/// `format!("file = \"{}\"", path.display())`. Either helper would have
/// prevented it; hand-rolling the quotes is what did not.
fn path(path: &std::path::Path) -> toml::Value {
    toml::Value::String(path.to_string_lossy().into_owned())
}

/// The attempt itself, with the sink already held.
#[cfg(unix)]
fn drive_locked(
    fixture: &LiveFixture,
    engineer: &mut Engineer<'_>,
) -> Result<tessera_core::pam_data::AuthContext, CodeFlowError> {
    let method = fixture.method();
    let login = CodeLogin {
        pam_user: ROLE,
        pam_service: "codeauth",
        session_id: "sess-live".to_owned(),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    };
    let outcome = authenticate_by_code(&fixture.deps(), login, &method, engineer, &SteadyDevice);
    // Checked on every run rather than in one test of its own: an engineer at
    // a device has no secret to give, and a device coming back from a power
    // cut with nobody in front of it has nobody to ask.
    assert!(
        !*engineer.asked_secret.borrow(),
        "the branch asked for something in secret; the device opens its own key",
    );
    outcome.map(|outcome| outcome.auth_ctx)
}

// Stands up a real store: Unix-only, see the module docs.
#[cfg(unix)]
#[test]
fn a_code_computed_from_the_printed_challenge_admits_the_engineer() {
    // The whole channel, end to end: the branch prints, the cabinet computes
    // from what was printed, the branch verifies. Nothing is scripted but the
    // engineer's typing.
    let fixture = LiveFixture::with_attempts(5);

    let ctx = run(&fixture, [Typed::Right]).unwrap();

    assert_eq!(ctx.role.as_ref().unwrap().role.as_str(), ROLE);
    assert_eq!(
        ctx.cert_max_integrity.unwrap().level,
        i8::try_from(LEVEL).unwrap(),
        "the ceiling of the session comes from the ticket the code was cut under",
    );
}

// Stands up a real store: Unix-only, see the module docs.
#[cfg(unix)]
#[test]
fn every_allowed_attempt_spent_on_a_wrong_code_reports_max_tries() {
    // The claim under test, and the reason this fixture exists: N wrong codes
    // in ONE conversation must reach the stack as PAM_MAXTRIES (11). The method
    // reports the exhausted budget on the last attempt it allowed — not on a
    // call after it, of which there would be none, because the next
    // `pam_sm_authenticate` raises a fresh nonce with a fresh budget.
    for attempts in [2_u8, 3, 5] {
        let fixture = LiveFixture::with_attempts(attempts);
        let script = std::iter::repeat_with(|| Typed::Wrong).take(usize::from(attempts));

        let Err(error) = run(&fixture, script) else {
            panic!("{attempts} wrong codes must not admit anyone");
        };

        assert!(
            matches!(error, CodeFlowError::AttemptsExhausted),
            "budget of {attempts}: unexpected {error:?}",
        );
        assert_eq!(error.pam_code(), 11, "budget of {attempts}");
    }
}

// Stands up a real store: Unix-only, see the module docs.
#[cfg(unix)]
#[test]
fn a_wrong_code_short_of_the_budget_is_not_an_exhausted_budget() {
    // One wrong code out of five is an ordinary refusal. The engineer is asked
    // again; here they give up instead, and what comes back must not claim the
    // budget ran out — it did not, and an engineer told to stop trying would
    // stop for nothing.
    let fixture = LiveFixture::with_attempts(5);

    let Err(error) = run(&fixture, [Typed::Wrong]) else {
        panic!("a wrong code must not admit anyone");
    };

    assert!(
        !matches!(error, CodeFlowError::AttemptsExhausted),
        "a single wrong code reported an exhausted budget: {error:?}",
    );
    assert_ne!(error.pam_code(), 11);
}

// Stands up a real store: Unix-only, see the module docs.
#[cfg(unix)]
#[test]
fn refusals_that_cost_no_attempt_never_read_as_an_exhausted_budget() {
    // A key container that will not open is the device's failure, not a wrong
    // code, and the method charges the nonce nothing for it. The branch must
    // pass that through: reporting PAM_MAXTRIES here would tell the engineer
    // to stop trying about a device fault they cannot do anything about, and
    // send an administrator looking for a spent nonce that is still untouched.
    //
    // This is the test that fails if the branch ever starts deciding
    // exhaustion by counting its own prompts instead of reporting what the
    // method said.
    let fixture = LiveFixture::with_attempts(2).with_unopenable_key_container();
    let engineer = Engineer::new(&fixture, [Typed::Wrong, Typed::Wrong]);

    let Err(error) = drive(&fixture, engineer) else {
        panic!("a container that will not open must not admit anyone");
    };

    assert!(
        matches!(error, CodeFlowError::Denied),
        "a refusal that costs no attempt was reported as {error:?}",
    );
    assert_eq!(error.pam_code(), 7);
}

// Stands up a real store: Unix-only, see the module docs.
#[cfg(unix)]
#[test]
fn the_last_allowed_attempt_still_admits_a_right_code() {
    // The other side of the budget: spending every attempt but one and then
    // getting it right is a successful login, not an exhausted nonce. A branch
    // that reported exhaustion by counting its own prompts would fail here.
    let fixture = LiveFixture::with_attempts(3);
    let script = [Typed::Wrong, Typed::Wrong, Typed::Right];

    let ctx = run(&fixture, script).unwrap();

    assert_eq!(ctx.role.as_ref().unwrap().role.as_str(), ROLE);
}

// Stands up a real store: Unix-only, see the module docs.
#[cfg(unix)]
#[test]
fn a_second_conversation_cannot_replay_the_first_code() {
    // The nonce of a successful login is spent, and the code cut for it is a
    // code for a nonce that no longer exists.
    // Both halves go through `drive`, which holds the sink lock: the audit
    // sink is one handle per process, and a login driven outside the lock
    // fails on whatever journal another test happens to have installed.
    let fixture = LiveFixture::with_attempts(5);

    let mut first = Engineer::new(&fixture, [Typed::Right]);
    drive_conversation(&fixture, &mut first).unwrap();
    let spent = first.printed.borrow().clone().unwrap();

    // A fresh conversation raises a new challenge; the engineer types the code
    // of the old one.
    let mut replay = Replay(fixture.cabinet_code(&spent));
    let outcome = drive_conversation(&fixture, &mut replay);

    assert!(
        outcome.is_err(),
        "a code cut for a spent nonce must not admit anyone"
    );
}

// Stands up a real store: Unix-only, see the module docs.
#[cfg(unix)]
#[test]
fn a_code_typed_in_the_groups_it_was_dictated_in_is_accepted() {
    // The operator reads the code out in groups and the printed challenge is
    // grouped too, so an engineer writes down "1234 5678" and types what they
    // wrote. The contract alphabet holds no space, so without normalising the
    // input this costs one attempt out of five for doing exactly what the
    // channel encouraged — and the engineer cannot see what was wrong with it.
    let fixture = LiveFixture::with_attempts(5);

    let ctx = run(&fixture, [Typed::RightInGroups]).unwrap();

    assert_eq!(ctx.role.as_ref().unwrap().role.as_str(), ROLE);
}

/// The audit chain as a load-bearing part of the decision to let somebody in.
///
/// The record of a successful login is not a report about the session — it is
/// part of granting it. The control over an operator of the telephone channel
/// is the reconciliation between the logins a fleet saw and the receipts its
/// operators wrote, so a session that reached no journal is precisely the
/// session an operator with something to hide would want.
///
/// **Every test here reaches the sink only through the configuration**, the
/// way a device does. An earlier version of this module installed the journal
/// by hand, and so stayed green while no production path installed one at all:
/// the guarantee read as present and was absent. Going through
/// `sink::install_from_config` means unwiring the install shows up here.
mod fail_closed {
    use super::{config_with_audit, path};
    #[cfg(unix)]
    use super::{drive_with_config, Engineer, LiveFixture, Typed};
    #[cfg(unix)]
    use crate::codes_flow::CodeFlowError;

    /// The `[audit]` table naming a journal in `dir`.
    ///
    /// Built as a table rather than as text: the path goes in through
    /// [`super::path`], so the encoder owns the quoting and a Windows
    /// `C:\Users\...` stays a path instead of becoming a broken escape.
    #[cfg(unix)]
    fn audit_table(dir: &std::path::Path) -> toml::Table {
        let mut audit = toml::Table::new();
        audit.insert("enabled".to_owned(), toml::Value::Boolean(true));
        audit.insert("file".to_owned(), path(&dir.join("audit.ndjson")));
        audit
    }

    /// A device told to keep a journal it can write.
    #[cfg(unix)]
    fn keeping_a_journal(dir: &std::path::Path) -> toml::Table {
        let mut sections = toml::Table::new();
        sections.insert("audit".to_owned(), toml::Value::Table(audit_table(dir)));
        sections
    }

    /// A device told to keep a journal that is already at its ceiling: the
    /// ceiling is zero, so the very first record meets it, and the configured
    /// behaviour is to refuse.
    #[cfg(unix)]
    fn keeping_a_full_journal(dir: &std::path::Path) -> toml::Table {
        let mut audit = audit_table(dir);
        audit.insert("ceiling_bytes".to_owned(), toml::Value::Integer(0));
        audit.insert(
            "when_full".to_owned(),
            toml::Value::String("refuse".to_owned()),
        );
        let mut sections = toml::Table::new();
        sections.insert("audit".to_owned(), toml::Value::Table(audit));
        sections
    }

    /// A `[codes]` table for a device that offers the method.
    fn codes_table() -> toml::Table {
        let mut codes = toml::Table::new();
        codes.insert(
            "tags".to_owned(),
            toml::Value::Array(vec![toml::Value::String("site=dc1".to_owned())]),
        );
        codes.insert("enabled".to_owned(), toml::Value::Boolean(true));
        codes.insert(
            "device_number".to_owned(),
            toml::Value::String("77000123S".to_owned()),
        );
        codes.insert("epoch".to_owned(), toml::Value::Integer(7));
        codes.insert(
            "region".to_owned(),
            toml::Value::String("ru-central".to_owned()),
        );
        codes
    }

    // Stands up a real store: Unix-only, see the module docs.
    #[cfg(unix)]
    #[test]
    fn a_login_the_chain_will_not_record_is_refused() {
        let fixture = LiveFixture::with_attempts(5);
        let dir = tempfile::tempdir().unwrap();

        let (outcome, installed) = drive_with_config(
            &fixture,
            Engineer::new(&fixture, [Typed::Right]),
            keeping_a_full_journal(dir.path()),
        );
        assert!(installed, "the configuration did not produce a journal");

        // The code was right and every other step passed. The one thing that
        // did not happen is the record, and that is enough to refuse.
        let error = outcome.expect_err(
            "a login the audit chain refused to record was granted anyway: the \
             fail-closed rule is not wired to the boundary that returns the PAM result",
        );
        assert!(
            matches!(error, CodeFlowError::Unaccountable(_)),
            "refused for the wrong reason: {error}",
        );
        // The neighbour of an unregistered session, and the same code for it.
        assert_eq!(error.pam_code(), 6);
    }

    // Stands up a real store: Unix-only, see the module docs.
    #[cfg(unix)]
    #[test]
    fn a_login_the_chain_records_is_granted_and_lands_on_the_chain() {
        let fixture = LiveFixture::with_attempts(5);
        let dir = tempfile::tempdir().unwrap();

        let (outcome, installed) = drive_with_config(
            &fixture,
            Engineer::new(&fixture, [Typed::Right]),
            keeping_a_journal(dir.path()),
        );
        assert!(installed, "the configuration did not produce a journal");
        outcome.expect("a login the chain accepted was refused");

        // …and the record is really there, or the test above would pass for
        // the trivial reason that nothing is ever written.
        let written = std::fs::read_to_string(dir.path().join("audit.ndjson"))
            .expect("the configured journal file was never created");
        assert!(
            written.contains(r#""op":"code_login""#) && written.contains(r#""outcome":"success""#),
            "the granted login is not on the chain: {written}",
        );
    }

    // Stands up a real store: Unix-only, see the module docs.
    #[cfg(unix)]
    #[test]
    fn a_device_with_no_audit_section_authenticates_exactly_as_before() {
        let fixture = LiveFixture::with_attempts(5);

        // No `[audit]` section at all, and `[codes]` absent too, so the
        // coupling resolves to "no journal". The chain is opt-in and its
        // absence has never been what authorises a login — a device that was
        // never given one must not be locked out by this change.
        let (outcome, installed) = drive_with_config(
            &fixture,
            Engineer::new(&fixture, [Typed::Right]),
            toml::Table::new(),
        );

        assert!(!installed, "a device with no [audit] section got a journal");
        outcome.expect("a device without an audit chain was refused a valid login");
    }

    /// The default is not "off": a device that offers the code method gets a
    /// journal without anybody remembering to ask for one. That coupling is
    /// the difference between a guarantee and a footnote — the method's whole
    /// control model rests on the reconciliation this journal makes possible.
    #[test]
    fn enabling_the_code_method_enables_the_journal_by_itself() {
        let dir = tempfile::tempdir().unwrap();

        // `[codes].enabled = true` and no `[audit].enabled` anywhere.
        let mut audit = toml::Table::new();
        audit.insert("file".to_owned(), path(&dir.path().join("audit.ndjson")));
        let mut sections = toml::Table::new();
        sections.insert("codes".to_owned(), toml::Value::Table(codes_table()));
        sections.insert("audit".to_owned(), toml::Value::Table(audit));
        let config = config_with_audit(sections);
        assert!(
            config.audit.policy.is_some(),
            "a device offering the code method was left without a journal",
        );

        // …and turning it off explicitly is still allowed, or an operator with
        // a reason would have no way to say so.
        let mut audit = toml::Table::new();
        audit.insert("enabled".to_owned(), toml::Value::Boolean(false));
        let mut sections = toml::Table::new();
        sections.insert("codes".to_owned(), toml::Value::Table(codes_table()));
        sections.insert("audit".to_owned(), toml::Value::Table(audit));
        let off = config_with_audit(sections);
        assert!(off.audit.policy.is_none());
    }
}

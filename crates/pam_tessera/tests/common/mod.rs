//! Shared scaffolding for `tests/auth_e2e_p12.rs` and
//! `tests/negative_auth.rs`.  Hosts the fixture-staging helpers and a
//! [`Scenario`] enum that drives both the happy and the deny paths.

#![allow(
    dead_code,
    missing_docs,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_arguments,
    clippy::duration_suboptimal_units,
    clippy::pedantic,
    clippy::all
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tessera_core::config::ValidatedConfig;
use tessera_core::host_identity::HostIdSourceKind;
use tessera_core::ipc::StubClient;
use tessera_core::trust::openssl_verifier::{OpensslVerifier, OpensslVerifierConfig};
use tessera_core::x509::Certificate;

use pam_tessera::flow::{authenticate, Deps, FlowError, FlowOutcome, InMemoryFlowIo, NoopMountOps};

use secrecy::SecretString;

/// A complete role stage for the flow: an on-disk store holding the `serv`
/// role.
///
/// Every authentication resolves a role, so there is no "no role" stage to
/// fall back on. The requested role is not part of the stage — it is the login
/// account name, so tests must authenticate as [`RoleFixture::ACCOUNT`] for
/// this store to resolve. The `leaf_*` fixtures carry
/// `pam_cert_allowed_roles = [serv, oper]`, which is what proves coverage.
pub struct RoleFixture {
    _dir: tempfile::TempDir,
    store: tessera_core::role::RoleStore,
}

impl RoleFixture {
    /// The login account name that resolves this fixture's role.
    pub const ACCOUNT: &'static str = "serv";

    pub fn serv() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("serv.toml"),
            b"role = \"serv\"\nversion = 4\nos = \"linux\"\nname = \"serv\"\nlevel = 1\n\
              [payload]\ngroups = [\"wheel\"]\n"
                .as_slice(),
        )
        .unwrap();
        let store = tessera_core::role::RoleStore::load(
            dir.path(),
            tessera_core::role::RoleOs::Linux,
            tessera_core::role::TrustMode::Standalone,
            test_accounts(),
        )
        .unwrap();
        Self { _dir: dir, store }
    }

    pub fn stage(&self) -> pam_tessera::flow::RoleStage<'_> {
        pam_tessera::flow::RoleStage {
            store: &self.store,
            default_session_ttl: Duration::from_secs(
                tessera_core::config::validated::DEFAULT_ROLE_SESSION_TTL_SECONDS,
            ),
            // The store was loaded through [`test_accounts`], and the check
            // takes both the view and its verdicts from that load.
            accounts: tessera_core::role::AccountCheck::from_store(&self.store),
        }
    }
}

/// The device's account view these tests authenticate against.
///
/// The real passwd file of the machine running the tests is never
/// consulted: `root` must be a system account and `serv` a provisioned
/// role account regardless of where the suite runs.
fn test_accounts() -> tessera_core::role::SystemAccounts {
    tessera_core::role::SystemAccounts::with_lookup(|account| match account {
        "root" => tessera_core::role::PasswdLookup::Uid(0),
        "serv" => tessera_core::role::PasswdLookup::Uid(4000),
        _ => tessera_core::role::PasswdLookup::NoEntry,
    })
}

/// Repository path to the shared X.509/p12 fixtures pile.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tessera_core/tests/fixtures")
}

pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// Stage `mountpoint/certs/{user.p12,chain.pem}` from existing fixtures.
pub fn stage_mount(p12_name: &str, with_chain: bool) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let certs_dir = tmp.path().join("certs");
    std::fs::create_dir(&certs_dir).unwrap();
    std::fs::write(certs_dir.join("user.p12"), fixture_bytes(p12_name)).unwrap();
    if with_chain {
        std::fs::write(certs_dir.join("chain.pem"), fixture_bytes("int.pem")).unwrap();
    }
    tmp
}

/// Build the canonical stage-2 verifier used by the e2e + negative suites.
pub fn build_verifier(crl_pems: Vec<Vec<u8>>) -> OpensslVerifier {
    let ca = Certificate::from_pem(&fixture_bytes("ca.pem")).unwrap();
    let int_ = Certificate::from_pem(&fixture_bytes("int.pem")).unwrap();
    // A supplied CRL store is consulted (crl mode); with no CRLs there is
    // nothing to consult, which is the "no revocation" posture (none mode).
    // crl mode with an empty store is rejected at construction as a
    // silently-disabled revocation check, so pick the mode by emptiness.
    let revocation_mode = if crl_pems.is_empty() {
        tessera_core::config::validated::RevocationMode::None
    } else {
        tessera_core::config::validated::RevocationMode::Crl
    };
    OpensslVerifier::new(OpensslVerifierConfig {
        max_supported_profile_version:
            tessera_core::trust::openssl_verifier::DEFAULT_MAX_SUPPORTED_PROFILE_VERSION,
        anchors: vec![ca],
        intermediates: vec![int_],
        crl_pems,
        crl_strict: false,
        crl_max_age: None,
        clock_skew: Duration::from_secs(60),
        signature_alg_whitelist: vec!["sha256WithRSAEncryption".into(), "ecdsa-with-SHA256".into()],
        spki_pins: vec![],
        max_depth: 4,
        gost_engine_path: None,
        revocation_mode,
        ocsp_responder_url: None,
        ocsp_timeout: Duration::from_secs(5),
        ocsp_cache_dir: std::path::PathBuf::from("/var/cache/tessera/ocsp"),
        ocsp_cache_ttl: Duration::ZERO,
    })
    .unwrap()
}

/// Build a minimal validated config for tests via TOML round-trip.
pub fn minimal_cfg() -> ValidatedConfig {
    // Config validation rejects empty `[trust].anchors`, so point at a
    // real PEM fixture.
    let anchor = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tessera_core/tests/fixtures/ca.pem");
    let raw_toml = r#"
crypto_backend = "openssl"
mode = "pkcs12"
pkcs12_path_pattern = "certs/user.p12"
pkcs12_pin_prompt = "PIN: "
usb_wait_seconds = 5
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 30
monitor_fail_mode = "permissive"

[trust]
anchors = [@ANCHOR@]
intermediates = []
allowed_signature_algorithms = []
max_chain_depth = 4
clock_skew_seconds = 60

[trust.revocation]
mode = "none"
crl_paths = []

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[host_identity]
sources = ["override"]
fallback = "deny"
override = "host-T"
custom_command_timeout_seconds = 5

[logging]
level = "info"
syslog_facility = "auth"
journald_priority = false
"#;
    let raw_toml = raw_toml.replace("@ANCHOR@", &format!("{:?}", anchor.to_string_lossy()));
    let raw: tessera_core::config::raw::RawConfig = toml::from_str(&raw_toml).unwrap();
    ValidatedConfig::try_from(&raw).unwrap()
}

/// Run the full flow, returning the raw `Result` so individual tests can
/// match on specific [`FlowError`] variants.
pub fn run_flow_with(
    p12_name: &str,
    pam_user: &str,
    pin: &str,
    crl_pems: Vec<Vec<u8>>,
    host_id_hash: &str,
) -> Result<FlowOutcome<NoopMountOps>, FlowError> {
    let tmp = stage_mount(p12_name, false);
    let verifier = build_verifier(crl_pems);
    let cfg = minimal_cfg();
    let monitor = StubClient;
    let exec = tessera_core::hooks::NoopExecutor::new();
    let roles = RoleFixture::serv();

    let deps = Deps {
        cfg: &cfg,
        trust: &verifier,
        monitor: &monitor,
        hook_executor: &exec,
        host_id_hash,
        host_id_source: HostIdSourceKind::Override,
        pam_target: tessera_proto::SessionTarget::Unknown,
        role_stage: roles.stage(),
        device_tags: pam_tessera::flow::empty_device_tags(),
    };

    let io = InMemoryFlowIo::new(tmp.path().to_path_buf());
    let pin_owned = pin.to_string();
    let result = authenticate(
        deps,
        &io,
        pam_user,
        "ssh",
        format!("sess-{}", uniq()),
        |_prompt| Ok(SecretString::from(pin_owned.clone())),
    );
    // Keep tmp alive until flow completes.
    drop(tmp);
    result
}

fn uniq() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Read fixture relative to the workspace root (used for ad-hoc CRL-PEM
/// reads in negative tests).
pub fn read_fixture<P: AsRef<Path>>(p: P) -> Vec<u8> {
    std::fs::read(fixtures_dir().join(p)).unwrap()
}

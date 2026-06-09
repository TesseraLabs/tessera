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

use pam_tessera::flow::{
    authenticate, Deps, FlowError, FlowOutcome, InMemoryFlowIo, NoopMountOps,
};

use secrecy::SecretString;

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
    OpensslVerifier::new(OpensslVerifierConfig {
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

#[derive(Debug, Clone, Copy)]
pub struct UserMappingKv {
    pub pam_user: &'static str,
    pub cn: &'static str,
}

pub fn cn_mapping(user: &str, cn: &str) -> tessera_core::config::validated::UserMapping {
    use tessera_core::config::validated::{UserMapping, UserMatchCriteria};
    UserMapping {
        pam_user: user.to_string(),
        criteria: UserMatchCriteria::SubjectCn(cn.to_string()),
    }
}

/// Legacy shim retained so existing call sites keep compiling; the cert
/// scope is verified via cert extensions, not a separate ACL list.
pub fn host_acl_for(_serial: &str, _hosts: &[&str]) -> () {}
pub fn host_acl_for_subject(_cn: &str, _serial: &str, _hosts: &[&str]) -> () {}

/// Run the full flow, returning the raw `Result` so individual tests can
/// match on specific [`FlowError`] variants.
pub fn run_flow_with(
    p12_name: &str,
    mappings: Vec<tessera_core::config::validated::UserMapping>,
    _acl: (),
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

    let deps = Deps {
        cfg: &cfg,
        trust: &verifier,
        monitor: &monitor,
        hook_executor: &exec,
        host_id_hash,
        host_id_source: HostIdSourceKind::Override,
        user_mappings: &mappings,
        pam_target: tessera_proto::SessionTarget::Unknown,
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

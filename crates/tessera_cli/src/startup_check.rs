//! Startup validation pipeline.
//!
//! Beyond TOML parse + `ValidatedConfig::try_from`, the daemon checks a
//! handful of operational invariants at boot that are easy to misconfigure
//! and painful to debug post-hoc:
//!
//! 1. PAM stack ordering against `pam_parsec_mac.so` on Astra SE.
//! 2. `[mac].runtime` vs the running kernel's parsec state.
//! 3. Existence and readability of trust anchors / intermediates.
//! 4. World-writable bits on `/etc/tessera/ca/`.
//! 5. `PARSEC_CAP_CHMAC` presence when MAC writes are expected.
//! 6. `HostIdentityResolver` per-source probe (informational).
//! 7. GOST-engine configuration: dead combinations of `gost_engine_path`
//!    and the GOST entries in `allowed_signature_algorithms`, plus an actual
//!    load attempt whenever an engine path is configured.
//! 8. `mode` × `crypto_backend` pairings under which no authentication of
//!    any kind can succeed.
//!
//! Most checks are advisory (WARN); only invariants whose violation makes
//! the daemon unsafe to start are wired as fatal — those return
//! [`StartupCheckSeverity::Error`] alongside a structured message so the
//! caller can decide to fail-fast.
//!
//! The same pipeline is exposed via the `tessera check` subcommand so
//! operators can run a preflight without restarting the running daemon.

use std::path::PathBuf;

use tessera_core::config::ValidatedConfig;
use tessera_core::mac::{MacBackend, MacError, MacRuntime};

pub mod crypto_backend;
pub mod gost;
pub mod host_identity;
pub mod mac_runtime;
pub mod mrd;
pub mod pam_stack;
pub mod parsec_caps;
pub mod trust;

#[cfg(test)]
pub(crate) mod test_config;

/// Severity attached to every startup check outcome.
///
/// `Info` and `Warn` records are emitted as `tracing` events; only `Error`
/// records influence the daemon's exit status (callers fail-fast on the
/// first error after the full sweep completes, so all problems show up in
/// one log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupCheckSeverity {
    /// Informational — the configured invariant holds.
    Info,
    /// Advisory — the configured invariant does not hold but the daemon
    /// can keep running. The admin should fix this before the next reload.
    Warn,
    /// Fatal — the daemon must not start with this state.
    Error,
}

/// A single startup-check record.
#[derive(Debug, Clone)]
pub struct StartupCheckRecord {
    /// Stable identifier of the check (used for log filtering and the
    /// CLI summary). Snake-case, prefixed with the area: `pam_stack_*`,
    /// `mac_runtime_*`, `trust_anchor_*`, etc.
    pub check: &'static str,
    /// Severity level for this record.
    pub severity: StartupCheckSeverity,
    /// Human-readable message. Russian or English depending on the audience —
    /// the daemon's logs are operator-facing.
    pub message: String,
}

impl StartupCheckRecord {
    /// Construct an `Info` record.
    #[must_use]
    pub fn info(check: &'static str, message: impl Into<String>) -> Self {
        Self {
            check,
            severity: StartupCheckSeverity::Info,
            message: message.into(),
        }
    }

    /// Construct a `Warn` record.
    #[must_use]
    pub fn warn(check: &'static str, message: impl Into<String>) -> Self {
        Self {
            check,
            severity: StartupCheckSeverity::Warn,
            message: message.into(),
        }
    }

    /// Construct an `Error` record.
    #[must_use]
    pub fn error(check: &'static str, message: impl Into<String>) -> Self {
        Self {
            check,
            severity: StartupCheckSeverity::Error,
            message: message.into(),
        }
    }
}

/// Aggregated outcome of a full startup-check sweep.
#[derive(Debug, Clone, Default)]
pub struct StartupCheckReport {
    /// Records in the order they were produced.
    pub records: Vec<StartupCheckRecord>,
}

impl StartupCheckReport {
    /// Push a record.
    pub fn push(&mut self, record: StartupCheckRecord) {
        self.records.push(record);
    }

    /// Convenience: number of records at the given severity.
    #[must_use]
    pub fn count(&self, severity: StartupCheckSeverity) -> usize {
        self.records
            .iter()
            .filter(|r| r.severity == severity)
            .count()
    }

    /// `true` when at least one record is at `Error` severity.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.count(StartupCheckSeverity::Error) > 0
    }

    /// Emit every record at its severity level via `tracing`. Targeted as
    /// `tessera.startup_check` so an operator can grep
    /// `journalctl -t tessera -g startup_check`.
    pub fn log(&self) {
        for r in &self.records {
            match r.severity {
                StartupCheckSeverity::Info => {
                    tracing::info!(
                        target: "tessera.startup_check",
                        check = r.check,
                        "{}",
                        r.message
                    );
                }
                StartupCheckSeverity::Warn => {
                    tracing::warn!(
                        target: "tessera.startup_check",
                        check = r.check,
                        "{}",
                        r.message
                    );
                }
                StartupCheckSeverity::Error => {
                    tracing::error!(
                        target: "tessera.startup_check",
                        check = r.check,
                        "{}",
                        r.message
                    );
                }
            }
        }
    }
}

/// Options for the startup-check pipeline.
///
/// Most production callers will use [`StartupCheckOptions::default`]; tests
/// override [`Self::pam_d_root`] and the kernel-MAC probe to drive
/// deterministic paths.
#[derive(Debug, Clone)]
pub struct StartupCheckOptions {
    /// Directory that holds PAM service files. Defaults to `/etc/pam.d`;
    /// tests pass a tmpdir so the PAM-ordering check is reproducible.
    pub pam_d_root: PathBuf,
    /// Filesystem root prepended to other absolute paths the checks consult
    /// (currently only `/etc/tessera/ca/`). `None` means "use the real
    /// host root".
    pub fs_root: Option<PathBuf>,
    /// Optional injected probe for kernel parsec presence. When `None`, the
    /// selected runtime plugin is probed.
    pub kernel_parsec_probe: Option<KernelParsecProbe>,
    /// Optional injected probe for the mandatory confidentiality control (МРД)
    /// axis. When `None`, the selected runtime plugin is probed.
    pub mrd_probe: Option<MrdProbe>,
    /// Optional injected gost-engine probe. When `None`, the real engine
    /// loader runs. Ignored by
    /// [`run_startup_checks_with_backend_and_gost`], whose caller has
    /// already probed.
    pub gost_probe: Option<gost::EngineProbe>,
}

impl Default for StartupCheckOptions {
    fn default() -> Self {
        Self {
            pam_d_root: PathBuf::from("/etc/pam.d"),
            fs_root: None,
            kernel_parsec_probe: None,
            mrd_probe: None,
            gost_probe: None,
        }
    }
}

/// Outcome of probing the running kernel for active МКЦ support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelParsecState {
    /// `parsec_strict_mode() == 1`: backend is required to enforce MAC.
    Active,
    /// `parsec_strict_mode() == 0`: kernel is up but МКЦ is administratively
    /// off (e.g. `parsec.mac=0` on a non-PARSEC kernel).
    Disabled,
    /// No active runtime plugin, or the plugin returned an unknown value.
    Unavailable,
}

/// Function pointer for injecting a kernel parsec probe.
pub type KernelParsecProbe = fn() -> KernelParsecState;

/// Legacy standalone probe. Runtime code probes the selected plugin directly.
#[must_use]
pub fn real_kernel_parsec_probe() -> KernelParsecState {
    KernelParsecState::Unavailable
}

/// Function pointer for injecting a mandatory-confidentiality-control (МРД)
/// probe.
pub type MrdProbe = fn() -> tessera_core::mac::MrdState;

/// Legacy standalone probe. Runtime code probes the selected plugin directly.
#[must_use]
pub fn real_mrd_probe() -> tessera_core::mac::MrdState {
    tessera_core::mac::MrdState::Unknown
}

/// Run the full startup-check pipeline.
///
/// Always runs every check (so the operator sees the complete picture in a
/// single log sweep). Callers decide whether to fail-fast based on
/// [`StartupCheckReport::has_errors`].
#[must_use]
pub fn run_startup_checks(cfg: &ValidatedConfig, opts: &StartupCheckOptions) -> StartupCheckReport {
    // Probe before the plugin is loaded, not after: loading verifies the
    // plugin's detached signature through OpenSSL, and on Astra the first
    // call into libcrypto registers gost-engine ambiently from
    // `openssl.cnf`. The engine refuses a second, explicit load after that,
    // so a preflight that probed later would report a broken engine on a
    // host where authentication works.
    let readiness = probe_gost(cfg, opts);
    run_startup_checks_with_gost(cfg, opts, readiness)
}

/// Run the full startup-check pipeline with an already obtained gost-engine
/// readiness, loading the enforcement plugin here.
///
/// For callers that do their own work against libcrypto before the checks
/// run — `tessera enroll` verifies the enrollment manifest — and therefore
/// have to probe the engine (via [`gost::probe`]) before that work, not here.
/// [`StartupCheckOptions::gost_probe`] is ignored: the probe has happened.
#[must_use]
pub fn run_startup_checks_with_gost(
    cfg: &ValidatedConfig,
    opts: &StartupCheckOptions,
    gost_readiness: gost::EngineReadiness,
) -> StartupCheckReport {
    let backend = tessera_core::plugin::load_enforcement_backend(cfg.mac.backend.as_deref(), "");
    run_startup_checks_with_backend_and_gost(cfg, opts, backend.as_ref(), gost_readiness)
}

/// Run the startup-check pipeline with an already loaded backend.
///
/// The daemon uses this form so the verified plugin instance is shared by
/// startup probes, registry persistence, and listener labelling.
///
/// Note that loading the backend already touches libcrypto: a caller that
/// loads it itself must probe the gost-engine first and use
/// [`run_startup_checks_with_backend_and_gost`].
#[must_use]
pub fn run_startup_checks_with_backend(
    cfg: &ValidatedConfig,
    opts: &StartupCheckOptions,
    backend: &dyn MacBackend,
) -> StartupCheckReport {
    let readiness = probe_gost(cfg, opts);
    run_startup_checks_with_backend_and_gost(cfg, opts, backend, readiness)
}

/// Run the startup-check pipeline with an already loaded backend and an
/// already obtained gost-engine readiness.
///
/// This is the form for callers that load the enforcement plugin
/// themselves: they have to probe the engine (via [`gost::probe`]) *before*
/// that load, because signature verification pulls in libcrypto.
#[must_use]
pub fn run_startup_checks_with_backend_and_gost(
    cfg: &ValidatedConfig,
    opts: &StartupCheckOptions,
    backend: &dyn MacBackend,
    gost_readiness: gost::EngineReadiness,
) -> StartupCheckReport {
    let mut report = StartupCheckReport::default();

    // Reads `/etc/pam.d` as text; no crypto involved, so its position
    // relative to the engine probe does not matter.
    crate::startup_check::pam_stack::check(&opts.pam_d_root, &mut report);

    let kernel = opts.kernel_parsec_probe.map_or_else(
        || match backend.probe() {
            MacRuntime::Active => KernelParsecState::Active,
            MacRuntime::Disabled => KernelParsecState::Disabled,
            MacRuntime::Unavailable => KernelParsecState::Unavailable,
        },
        |probe| probe(),
    );
    mac_runtime::check(cfg, kernel, &mut report);

    let mrd = opts
        .mrd_probe
        .map_or_else(|| backend.probe_mrd(), |probe| probe());
    mrd::check(cfg, mrd, &mut report);

    trust::check_anchors(cfg, &mut report);
    trust::check_ca_dir_permissions(opts.fs_root.as_deref(), &mut report);

    // Engine first, pairing second: `tessera_core::self_check` probes the
    // gost-engine before it touches PKCS#11, so this is the order in which
    // an operator actually meets the failures. The engine itself was probed
    // by the caller before the plugin was loaded — see
    // [`run_startup_checks_with_backend_and_gost`]; only the record lands
    // here, where it reads in the operator's order.
    gost::record(cfg, gost_readiness, &mut report);
    crypto_backend::check(cfg, &mut report);

    let write_capability = match backend.check_write_capability() {
        Ok(()) => Some(true),
        Err(MacError::CapMissing) => Some(false),
        Err(_) => None,
    };
    parsec_caps::check_with_capability(cfg, kernel, write_capability, &mut report);

    host_identity::check(cfg, opts.fs_root.as_deref(), &mut report);

    report
}

/// Probe the gost-engine, honouring an injected probe from `opts`.
pub(crate) fn probe_gost(
    cfg: &ValidatedConfig,
    opts: &StartupCheckOptions,
) -> gost::EngineReadiness {
    opts.gost_probe
        .map_or_else(|| gost::probe(cfg), |probe| gost::probe_with(cfg, probe))
}

/// Re-exported here so callers (`daemon::run_async`, `check` subcommand,
/// tests) have a single import surface.
pub use crate::startup_check::{
    mac_runtime::check as check_mac_runtime,
    mrd::check as check_mrd,
    pam_stack::check as check_pam_stack,
    parsec_caps::check as check_parsec_caps,
    trust::{check_anchors as check_trust_anchors, check_ca_dir_permissions},
};

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::cell::RefCell;

    use tessera_core::mac::{IntegrityLabel, MacRawFd, MrdState};

    use super::*;
    use crate::startup_check::test_config::{base_cfg, write_anchor};

    thread_local! {
        /// Call journal shared by the injected engine probe (a plain `fn`
        /// pointer, so it cannot capture) and the recording backend.
        static CALLS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }

    fn note(what: &'static str) {
        CALLS.with(|c| c.borrow_mut().push(what));
    }

    /// Backend that records every call the pipeline makes into it.
    struct RecordingBackend;

    impl MacBackend for RecordingBackend {
        fn probe(&self) -> MacRuntime {
            note("backend.probe");
            MacRuntime::Unavailable
        }

        fn probe_mrd(&self) -> MrdState {
            note("backend.probe_mrd");
            MrdState::Unknown
        }

        fn check_write_capability(&self) -> Result<(), MacError> {
            note("backend.check_write_capability");
            Err(MacError::Unavailable)
        }

        fn get_user_mnkc(&self, _user: &str) -> Result<IntegrityLabel, MacError> {
            unreachable!("startup checks do not resolve users")
        }

        fn apply_session(&self, _label: IntegrityLabel) -> Result<(), MacError> {
            unreachable!("startup checks do not label sessions")
        }

        fn get_file_label(&self, _path: &std::path::Path) -> Result<IntegrityLabel, MacError> {
            unreachable!("startup checks do not read labels")
        }

        fn set_file_label(
            &self,
            _path: &std::path::Path,
            _label: IntegrityLabel,
            _irelax: bool,
        ) -> Result<(), MacError> {
            unreachable!("startup checks do not write labels")
        }

        fn set_fd_label(
            &self,
            _fd: MacRawFd,
            _label: IntegrityLabel,
            _irelax: bool,
        ) -> Result<(), MacError> {
            unreachable!("startup checks do not write labels")
        }
    }

    /// The engine probe has to run before anything that could pull in
    /// libcrypto — on Astra the first libcrypto call registers gost-engine
    /// ambiently from `openssl.cnf`, after which our own explicit load is
    /// refused and preflight would fail a host that authenticates fine.
    /// Inside this function the earliest such thing is the MAC backend.
    #[test]
    fn gost_engine_is_probed_before_the_mac_backend_is_touched() {
        CALLS.with(|c| c.borrow_mut().clear());

        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let mut cfg = base_cfg(&anchor, "pkcs12");
        cfg.gost_engine_path = Some(tmp.path().join("gost.so"));
        cfg.trust
            .allowed_signature_algorithms
            .insert("1.2.643.7.1.1.3.2".to_owned());
        assert!(cfg.needs_gost());

        let opts = StartupCheckOptions {
            pam_d_root: tmp.path().join("pam.d"),
            fs_root: Some(tmp.path().to_path_buf()),
            kernel_parsec_probe: None,
            mrd_probe: None,
            gost_probe: Some(|_| {
                note("gost.probe");
                Ok(())
            }),
        };

        let report = run_startup_checks_with_backend(&cfg, &opts, &RecordingBackend);

        let calls = CALLS.with(|c| c.borrow().clone());
        assert_eq!(
            calls.first().copied(),
            Some("gost.probe"),
            "engine probe must come first: {calls:?}"
        );
        assert!(
            calls.contains(&"backend.probe"),
            "the backend must still be probed: {calls:?}"
        );

        // The record itself stays where an operator expects to read it:
        // after the MAC/trust records, ahead of the host-identity probe.
        let names: Vec<&str> = report.records.iter().map(|r| r.check).collect();
        let gost_at = names
            .iter()
            .position(|n| *n == "gost_engine_ok")
            .unwrap_or_else(|| panic!("no gost record: {names:?}"));
        let trust_at = names
            .iter()
            .position(|n| n.starts_with("trust_anchor"))
            .unwrap_or_else(|| panic!("no trust record: {names:?}"));
        let host_at = names
            .iter()
            .position(|n| n.starts_with("host_identity"))
            .unwrap_or_else(|| panic!("no host_identity record: {names:?}"));
        assert!(trust_at < gost_at && gost_at < host_at, "{names:?}");
    }

    /// A host that configures no GOST at all must not load an engine and
    /// must produce no GOST record — the probe stays untouched.
    #[test]
    fn host_without_gost_never_probes_the_engine() {
        CALLS.with(|c| c.borrow_mut().clear());

        let tmp = tempfile::tempdir().expect("tmp");
        let anchor = write_anchor(tmp.path());
        let cfg = base_cfg(&anchor, "pkcs12");
        assert!(cfg.gost_engine_path.is_none());
        assert!(!cfg.needs_gost());

        let opts = StartupCheckOptions {
            pam_d_root: tmp.path().join("pam.d"),
            fs_root: Some(tmp.path().to_path_buf()),
            kernel_parsec_probe: None,
            mrd_probe: None,
            gost_probe: Some(|_| {
                note("gost.probe");
                Ok(())
            }),
        };

        let report = run_startup_checks_with_backend(&cfg, &opts, &RecordingBackend);

        let calls = CALLS.with(|c| c.borrow().clone());
        assert!(
            !calls.contains(&"gost.probe"),
            "no engine load without GOST configured: {calls:?}"
        );
        assert!(
            !report.records.iter().any(|r| r.check.starts_with("gost")),
            "{report:#?}"
        );
    }
}

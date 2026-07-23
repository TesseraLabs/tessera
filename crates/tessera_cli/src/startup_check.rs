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

pub mod host_identity;
pub mod mac_runtime;
pub mod mrd;
pub mod pam_stack;
pub mod parsec_caps;
pub mod trust;

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
}

impl Default for StartupCheckOptions {
    fn default() -> Self {
        Self {
            pam_d_root: PathBuf::from("/etc/pam.d"),
            fs_root: None,
            kernel_parsec_probe: None,
            mrd_probe: None,
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
    let backend = tessera_core::plugin::load_enforcement_backend(cfg.mac.backend.as_deref(), "");
    run_startup_checks_with_backend(cfg, opts, backend.as_ref())
}

/// Run the startup-check pipeline with an already loaded backend.
///
/// The daemon uses this form so the verified plugin instance is shared by
/// startup probes, registry persistence, and listener labelling.
#[must_use]
pub fn run_startup_checks_with_backend(
    cfg: &ValidatedConfig,
    opts: &StartupCheckOptions,
    backend: &dyn MacBackend,
) -> StartupCheckReport {
    let mut report = StartupCheckReport::default();

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

    let write_capability = match backend.check_write_capability() {
        Ok(()) => Some(true),
        Err(MacError::CapMissing) => Some(false),
        Err(_) => None,
    };
    parsec_caps::check_with_capability(cfg, kernel, write_capability, &mut report);

    host_identity::check(cfg, opts.fs_root.as_deref(), &mut report);

    report
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

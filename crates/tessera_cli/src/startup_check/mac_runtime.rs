//! `[mac].runtime` vs running kernel cross-check.

use tessera_core::config::validated::MacRuntimeMode;
use tessera_core::config::ValidatedConfig;

use super::{KernelParsecState, StartupCheckRecord, StartupCheckReport};

/// Cross-check the configured `[mac].runtime` mode against the running
/// kernel's parsec state.
///
/// * `Required` + kernel absent → ERROR (fail-fast). Without an active
///   kernel МКЦ the daemon cannot satisfy the configured invariant, so
///   the startup pipeline rejects it explicitly rather than letting the
///   per-session `build_backend` fail closed on every auth.
/// * `Disabled` + kernel present → INFO. Operator chose to bypass MAC;
///   surface it so they know StubBackend is in play.
/// * `Auto` + kernel present/absent → INFO/WARN respectively (matches
///   the per-session `mac_runtime_fallback` audit but stated up-front).
/// * `Required` + kernel present → INFO confirming the strict mode.
pub fn check(cfg: &ValidatedConfig, kernel: KernelParsecState, report: &mut StartupCheckReport) {
    match (cfg.mac.runtime, kernel) {
        (MacRuntimeMode::Required, KernelParsecState::Active) => {
            report.push(StartupCheckRecord::info(
                "mac_runtime_required_ok",
                "mac.runtime=required and kernel parsec active: enforcing MAC integrity",
            ));
        }
        (MacRuntimeMode::Required, _) => {
            report.push(StartupCheckRecord::error(
                "mac_runtime_required_missing_kernel",
                "mac.runtime=required but kernel parsec is not active \
                 (parsec_strict_mode != 1). Refusing to start: a daemon in strict mode \
                 cannot enforce МКЦ without kernel support. Either install/enable \
                 parsec or set [mac].runtime=auto (warn + fall back to StubBackend) / \
                 [mac].runtime=disabled (explicit StubBackend).",
            ));
        }
        (MacRuntimeMode::Auto, KernelParsecState::Active) => {
            report.push(StartupCheckRecord::info(
                "mac_runtime_auto_active",
                "mac.runtime=auto: kernel parsec detected, using ParsecBackend",
            ));
        }
        (MacRuntimeMode::Auto, _) => {
            report.push(StartupCheckRecord::warn(
                "mac_runtime_auto_fallback",
                "mac.runtime=auto: kernel parsec absent (parsec.mac=0?), falling back \
                 to StubBackend. MAC integrity will NOT be enforced.",
            ));
        }
        (MacRuntimeMode::Disabled, KernelParsecState::Active) => {
            report.push(StartupCheckRecord::info(
                "mac_runtime_disabled_with_kernel",
                "mac.runtime=disabled while kernel parsec is active; ParsecBackend will NOT be \
                 used. To enable MAC enforcement, set runtime=required or auto.",
            ));
        }
        (MacRuntimeMode::Disabled, _) => {
            report.push(StartupCheckRecord::info(
                "mac_runtime_disabled",
                "mac.runtime=disabled: StubBackend in use (no kernel parsec detected anyway).",
            ));
        }
    }
}

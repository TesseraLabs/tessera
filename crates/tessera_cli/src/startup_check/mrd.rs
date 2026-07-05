//! Active-МРД detection vs the configured `[mac].runtime` mode.
//!
//! МРД is Astra's mandatory *confidentiality* control (Bell–LaPadula, active
//! on the «Смоленск» protection level) — a separate parsec axis from МКЦ
//! (mandatory *integrity* control), which is the only axis Tessera assigns.
//! Tessera never selects or writes the confidentiality coordinate, so hosts
//! with an active МРД are unsupported: integrity-only labelling cannot reason
//! about the confidentiality field. This check surfaces that up front instead
//! of leaving the behaviour undefined at runtime.

use tessera_core::config::validated::MacRuntimeMode;
use tessera_core::config::ValidatedConfig;
use tessera_core::mac::MrdState;

use super::{StartupCheckRecord, StartupCheckReport};

/// Cross-check the configured `[mac].runtime` mode against the probed МРД
/// (mandatory confidentiality control) state.
///
/// The severity mirrors the `[mac].runtime` risk posture:
///
/// * `Required` — strict-invariant mode. `Active` → ERROR (the daemon refuses
///   to start on an unsupported МРД system); `Unknown` → WARN (state could not
///   be confirmed); `Inactive` → INFO.
/// * `Auto` — `Active` → WARN (unsupported configuration, but the daemon
///   starts); `Unknown`/`Inactive` → INFO.
/// * `Disabled` — always INFO: no labels are written, so an active МРД cannot
///   be perturbed by Tessera.
///
/// A single stable record code `mac_mrd_active` carries the probed state and
/// guidance so operators can filter on one identifier regardless of severity.
pub fn check(cfg: &ValidatedConfig, mrd: MrdState, report: &mut StartupCheckReport) {
    match (cfg.mac.runtime, mrd) {
        (MacRuntimeMode::Required, MrdState::Active) => {
            report.push(StartupCheckRecord::error(
                "mac_mrd_active",
                "mac.runtime=required but active МРД (mandatory confidentiality control) \
                 detected. МРД-systems are unsupported: Tessera assigns only the МКЦ \
                 integrity axis and never touches confidentiality. Refusing to start. \
                 Only as an explicit acceptance of the unsupported configuration, set \
                 [mac].runtime=auto (warn + start) or [mac].runtime=disabled.",
            ));
        }
        (MacRuntimeMode::Required, MrdState::Unknown) => {
            report.push(StartupCheckRecord::warn(
                "mac_mrd_active",
                "mac.runtime=required and МРД (mandatory confidentiality control) state is \
                 Unknown: the confidentiality axis could not be probed. МРД-systems are \
                 unsupported; verify the host is not on the «Смоленск» protection level.",
            ));
        }
        (MacRuntimeMode::Required, MrdState::Inactive) => {
            report.push(StartupCheckRecord::info(
                "mac_mrd_active",
                "mac.runtime=required and МРД (mandatory confidentiality control) inactive: \
                 integrity-only labelling is safe.",
            ));
        }
        (MacRuntimeMode::Auto, MrdState::Active) => {
            report.push(StartupCheckRecord::warn(
                "mac_mrd_active",
                "mac.runtime=auto and active МРД (mandatory confidentiality control) detected. \
                 МРД-systems are unsupported; the daemon starts but МКЦ integrity labelling on \
                 a confidentiality-enforcing host is an unsupported configuration.",
            ));
        }
        (MacRuntimeMode::Auto, _) => {
            report.push(StartupCheckRecord::info(
                "mac_mrd_active",
                "mac.runtime=auto: no active МРД (mandatory confidentiality control) detected.",
            ));
        }
        (MacRuntimeMode::Disabled, _) => {
            report.push(StartupCheckRecord::info(
                "mac_mrd_active",
                "mac.runtime=disabled: no МКЦ labels are written, so МРД (mandatory \
                 confidentiality control) state cannot be affected by Tessera.",
            ));
        }
    }
}

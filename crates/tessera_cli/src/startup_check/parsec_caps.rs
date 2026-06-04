//! PARSEC_CAP_CHMAC presence check when MAC writes are expected.

use tessera_core::config::validated::{CertIntegrityMode, MacRuntimeMode};
use tessera_core::config::ValidatedConfig;

use super::{KernelParsecState, StartupCheckRecord, StartupCheckReport};

/// When the daemon is expected to *write* МКЦ labels (e.g. on
/// `sessions.json`), it must hold `PARSEC_CAP_CHMAC` in its effective set.
/// Without it `pdp_set_*` calls are kernel-rejected and the label silently
/// stays at default, which defeats the whole point of MAC.
///
/// We only run the FFI probe when (a) `astra-mac` is compiled in, (b) the
/// kernel reports parsec active, and (c) the config asks for MAC label
/// writes (`runtime` not `Disabled` AND `cert_integrity` is not `Ignore`).
/// In every other combination the daemon would never call `pdp_set_*`
/// anyway, so missing capability is irrelevant.
pub fn check(cfg: &ValidatedConfig, kernel: KernelParsecState, report: &mut StartupCheckReport) {
    let writes_expected = !matches!(cfg.mac.runtime, MacRuntimeMode::Disabled)
        && !matches!(cfg.mac.cert_integrity, CertIntegrityMode::Ignore);
    if !writes_expected || !matches!(kernel, KernelParsecState::Active) {
        return;
    }
    if chmac_cap_present() {
        report.push(StartupCheckRecord::info(
            "parsec_cap_chmac_ok",
            "PARSEC_CAP_CHMAC present in effective set; daemon can write МКЦ labels",
        ));
    } else {
        report.push(StartupCheckRecord::warn(
            "parsec_cap_chmac_missing",
            "PARSEC_CAP_CHMAC not granted to tessera daemon; MAC labels on \
             sessions.json will NOT be applied. Activate via systemd drop-in: see \
             /usr/share/tessera/systemd/mac-integrity.conf.example",
        ));
    }
}

#[cfg(feature = "astra-mac")]
fn chmac_cap_present() -> bool {
    tessera_mac_parsec::check_chmac_capability()
}

#[cfg(not(feature = "astra-mac"))]
fn chmac_cap_present() -> bool {
    // Without the FFI we can't introspect; play safe and skip the warn by
    // pretending it's present. Production binaries on Astra are always
    // built with `astra-mac`.
    true
}

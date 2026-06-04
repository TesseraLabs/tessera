//! Informational probe of every configured host_id source.

use std::path::{Path, PathBuf};

use tessera_core::config::ValidatedConfig;
use tessera_core::host_identity::HostIdentityResolver;

use super::{StartupCheckRecord, StartupCheckReport};

/// Probe every source via [`HostIdentityResolver::probe_all`] and emit
/// one INFO/WARN line per source.
pub fn check(cfg: &ValidatedConfig, fs_root: Option<&Path>, report: &mut StartupCheckReport) {
    let root = fs_root.map_or_else(|| PathBuf::from("/"), PathBuf::from);
    let resolver = HostIdentityResolver::from_validated(&cfg.host_identity, root);
    let probes = resolver.probe_all();
    if probes.is_empty() {
        report.push(StartupCheckRecord::info(
            "host_identity_sources",
            "no host_identity sources configured",
        ));
        return;
    }
    for p in probes {
        match p.outcome {
            Ok(r) => report.push(StartupCheckRecord::info(
                "host_identity_source_ok",
                format!(
                    "host_identity source {source:?}: ok (hash={hash})",
                    source = p.source,
                    hash = r.hash_hex
                ),
            )),
            Err(e) => report.push(StartupCheckRecord::warn(
                "host_identity_source_failed",
                format!(
                    "host_identity source {source:?}: failed ({e})",
                    source = p.source,
                ),
            )),
        }
    }
}

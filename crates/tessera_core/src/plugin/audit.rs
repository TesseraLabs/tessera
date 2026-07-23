//! Stable `plugin.audit` events.

use std::path::Path;

pub(crate) fn loaded(name: &str, version: &str, sha256: &str) {
    tracing::info!(
        target: "plugin.audit",
        event = "plugin_loaded",
        name,
        plugin_version = version,
        kind = "backend.enforcement",
        sha256,
    );
}

pub(crate) fn rejected(path: &Path, reason: &'static str) {
    tracing::error!(
        target: "plugin.audit",
        event = "plugin_rejected",
        path = %path.display(),
        reason,
    );
}

pub(crate) fn inactive(path: &Path) {
    tracing::info!(
        target: "plugin.audit",
        event = "plugin_inactive_file",
        path = %path.display(),
    );
}

pub(crate) fn panic(name: &str, entry_point: &'static str) {
    tracing::error!(
        target: "plugin.audit",
        event = "plugin_panic",
        name,
        entry_point,
    );
}

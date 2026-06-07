//! Trust anchor / intermediate file checks + `/etc/tessera/ca/`
//! permission sanity.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tessera_core::config::ValidatedConfig;

use super::{StartupCheckRecord, StartupCheckReport};

/// Every anchor must exist, be readable, and be non-empty; otherwise the
/// daemon has nothing to validate against and any auth will fail.
/// Intermediates are validated with the same rules — a missing
/// intermediate is almost always an admin packaging mistake worth surfacing
/// at startup rather than discovering on the first failed chain build.
pub fn check_anchors(cfg: &ValidatedConfig, report: &mut StartupCheckReport) {
    check_pem_list(&cfg.trust.anchors, "trust_anchor", "trust anchor", report);
    check_pem_list(
        &cfg.trust.intermediates,
        "trust_intermediate",
        "trust intermediate",
        report,
    );
}

fn check_pem_list(
    paths: &[PathBuf],
    check_prefix: &'static str,
    kind: &str,
    report: &mut StartupCheckReport,
) {
    for path in paths {
        if !path.exists() {
            report.push(StartupCheckRecord::error(
                missing_check(check_prefix),
                format!(
                    "{kind} {path} does not exist; daemon cannot validate \
                     any certificate without it",
                    path = path.display()
                ),
            ));
            continue;
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                report.push(StartupCheckRecord::error(
                    unreadable_check(check_prefix),
                    format!("{kind} {path}: read failed ({e})", path = path.display()),
                ));
                continue;
            }
        };
        if bytes.is_empty() {
            report.push(StartupCheckRecord::error(
                empty_check(check_prefix),
                format!(
                    "{kind} {path} is zero-bytes; treat as missing",
                    path = path.display()
                ),
            ));
            continue;
        }
        let count = count_pem_blocks(&bytes);
        if count == 0 {
            report.push(StartupCheckRecord::warn(
                no_pem_check(check_prefix),
                format!(
                    "{kind} {path}: file present but contains no \
                     '-----BEGIN CERTIFICATE-----' markers",
                    path = path.display()
                ),
            ));
            continue;
        }
        report.push(StartupCheckRecord::info(
            ok_check(check_prefix),
            format!(
                "{kind} {path}: ok ({count} PEM block{plural})",
                path = path.display(),
                plural = if count == 1 { "" } else { "s" },
            ),
        ));
    }
}

fn count_pem_blocks(bytes: &[u8]) -> usize {
    // BEGIN CERTIFICATE markers — sufficient for sanity, NOT a parser.
    let needle = b"-----BEGIN CERTIFICATE-----";
    let mut n = 0;
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if bytes.get(i..i + needle.len()) == Some(needle.as_slice()) {
            n += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    n
}

/// Surface world-writable `/etc/tessera/ca/`. Not fatal — production
/// setups sometimes layer additional ACLs — but a WARN is worth it because
/// world-writable trust anchors would let any local user swap in their own
/// roots.
pub fn check_ca_dir_permissions(fs_root: Option<&Path>, report: &mut StartupCheckReport) {
    let root = fs_root.map_or_else(|| PathBuf::from("/"), PathBuf::from);
    let ca_dir = root.join("etc/tessera/ca");
    let meta = match std::fs::metadata(&ca_dir) {
        Ok(m) => m,
        Err(_) => {
            // Directory absent — no admin convention violated; trust paths
            // can live anywhere. Stay quiet.
            return;
        }
    };
    if !meta.is_dir() {
        return;
    }
    let mode = meta.permissions().mode();
    if mode & 0o002 != 0 {
        report.push(StartupCheckRecord::warn(
            "trust_ca_dir_world_writable",
            format!(
                "{path} is world-writable (mode {mode:o}); any local user can swap \
                 trust anchors. Recommended: chmod 0755 {path}",
                path = ca_dir.display(),
                mode = mode & 0o7777,
            ),
        ));
    } else {
        report.push(StartupCheckRecord::info(
            "trust_ca_dir_ok",
            format!(
                "{path} permissions OK (mode {mode:o})",
                path = ca_dir.display(),
                mode = mode & 0o7777,
            ),
        ));
    }
}

fn missing_check(prefix: &'static str) -> &'static str {
    match prefix {
        "trust_anchor" => "trust_anchor_missing",
        _ => "trust_intermediate_missing",
    }
}

fn unreadable_check(prefix: &'static str) -> &'static str {
    match prefix {
        "trust_anchor" => "trust_anchor_unreadable",
        _ => "trust_intermediate_unreadable",
    }
}

fn empty_check(prefix: &'static str) -> &'static str {
    match prefix {
        "trust_anchor" => "trust_anchor_empty",
        _ => "trust_intermediate_empty",
    }
}

fn no_pem_check(prefix: &'static str) -> &'static str {
    match prefix {
        "trust_anchor" => "trust_anchor_no_pem",
        _ => "trust_intermediate_no_pem",
    }
}

fn ok_check(prefix: &'static str) -> &'static str {
    match prefix {
        "trust_anchor" => "trust_anchor_ok",
        _ => "trust_intermediate_ok",
    }
}

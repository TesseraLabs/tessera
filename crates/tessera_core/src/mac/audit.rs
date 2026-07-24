//! Audit events for the MAC subsystem.
//!
//! Every event uses the `mac.audit` tracing target and carries the
//! canonical `F_*` field set declared in the MAC integrity spec
//! (§4.1.3): `F_event`, `F_pam_user`, `F_pam_service`, `F_cert_serial`,
//! `F_cert_issuer`, `F_cert_cn`, `F_cert_fingerprint`, plus
//! per-event extra fields.
//!
//! Use the `emit_*` helpers — they freeze the event name and field
//! schema in code so tests can assert on `EVENT_*` constants without
//! mistyping a string literal.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::mac::IntegrityLabel;
use crate::x509::CertIdent;

/// `mac_skipped` — orchestrator decided not to touch the kernel
/// (policy = ignore, runtime not Active, etc.).
pub const EVENT_MAC_SKIPPED: &str = "mac_skipped";
/// `mac_runtime_required` — `cert_integrity=required` but `probe()`
/// reported a non-Active runtime.
pub const EVENT_MAC_RUNTIME_REQUIRED: &str = "mac_runtime_required";
/// `cert_lacks_max_integrity_ext` — `cert_integrity=required` but the
/// leaf is missing the `MAX_INTEGRITY` extension.
pub const EVENT_CERT_LACKS_EXT: &str = "cert_lacks_max_integrity_ext";
/// `integrity_applied` — process label resolved and applied.
pub const EVENT_INTEGRITY_APPLIED: &str = "integrity_applied";
/// `integrity_capped_below_user_mnkc` — effective label strictly below
/// user MNKC.
pub const EVENT_INTEGRITY_CAPPED: &str = "integrity_capped_below_user_mnkc";
/// `homedir_label_above_session_cap` — `$HOME` label exceeds the
/// effective process label (advisory; warn-only).
pub const EVENT_HOMEDIR_LABEL_ABOVE: &str = "homedir_label_above_session_cap";
/// `role_mask_exceeds_ceiling` — a role's requested `mac_mask` is not covered
/// by the cert integrity ceiling; the session is denied (no silent narrowing).
pub const EVENT_MASK_EXCEEDS_CEILING: &str = "role_mask_exceeds_ceiling";
/// `mac_apply_failed` — `apply_session` returned an error.
pub const EVENT_MAC_APPLY_FAILED: &str = "mac_apply_failed";
/// `mac_caps_missing` — process is missing `PARSEC_CAP_CHMAC`.
pub const EVENT_MAC_CAPS_MISSING: &str = "mac_caps_missing";
/// `mac_user_unknown` — `get_user_mnkc` reported `UserUnknown`.
pub const EVENT_MAC_USER_UNKNOWN: &str = "mac_user_unknown";
/// `mac_fallback_used` — falling back to `fallback_max_integrity`
/// because the cert carries no `MAX_INTEGRITY` extension.
pub const EVENT_MAC_FALLBACK_USED: &str = "mac_fallback_used";
/// `cert_max_integrity_categories_above_32bit` — DER decoder observed
/// integrity category bits beyond bit 31; advisory.
pub const EVENT_CERT_MAX_INT_CATS_ABOVE_32BIT: &str = "cert_max_integrity_categories_above_32bit";
/// `cert_max_integrity_parse_failed` — the `MAX_INTEGRITY` extension
/// was present but failed to decode.
pub const EVENT_CERT_EXT_PARSE_FAILED: &str = "cert_max_integrity_parse_failed";
/// `mac_socket_label_set` — daemon set the irelax label on its IPC
/// socket prior to atomic-rename publication.
pub const EVENT_MAC_SOCKET_LABEL: &str = "mac_socket_label_set";
/// `mac_sessions_file_label_warning` — fd-based irelax labeling of the
/// `sessions.json` tempfile failed; write continued best-effort.
pub const EVENT_MAC_SESSIONS_FILE_WARN: &str = "mac_sessions_file_label_warning";
/// `mac_runtime_fallback` — `[mac].runtime = "auto"` and the kernel
/// МКЦ subsystem is not available, so the daemon fell back to the
/// no-op `StubBackend`.
pub const EVENT_MAC_RUNTIME_FALLBACK: &str = "mac_runtime_fallback";
/// `mac_runtime_disabled` — `[mac].runtime = "disabled"`; the stub backend
/// is used intentionally even when a plugin is installed.
pub const EVENT_MAC_RUNTIME_DISABLED: &str = "mac_runtime_disabled";

/// Emit `mac_skipped`.
pub fn emit_mac_skipped(reason: &str) {
    tracing::info!(
        target: "mac.audit",
        F_event = EVENT_MAC_SKIPPED,
        F_reason = reason,
    );
}

/// Emit `mac_runtime_required`.
pub fn emit_mac_runtime_required(runtime: &str) {
    tracing::error!(
        target: "mac.audit",
        F_event = EVENT_MAC_RUNTIME_REQUIRED,
        F_runtime = runtime,
    );
}

/// Emit `cert_lacks_ext`.
pub fn emit_cert_lacks_ext(ident: &CertIdent, pam_user: &str, pam_service: &str) {
    tracing::error!(
        target: "mac.audit",
        F_event = EVENT_CERT_LACKS_EXT,
        F_pam_user = pam_user,
        F_pam_service = pam_service,
        F_cert_serial = ident.serial.as_str(),
        F_cert_issuer = ident.issuer.as_str(),
        F_cert_cn = ident.cn.as_str(),
        F_cert_fingerprint = ident.fingerprint.as_str(),
    );
}

/// Emit `integrity_applied`.
pub fn emit_integrity_applied(
    ident: &CertIdent,
    pam_user: &str,
    pam_service: &str,
    label: IntegrityLabel,
) {
    tracing::info!(
        target: "mac.audit",
        F_event = EVENT_INTEGRITY_APPLIED,
        F_pam_user = pam_user,
        F_pam_service = pam_service,
        F_cert_serial = ident.serial.as_str(),
        F_cert_issuer = ident.issuer.as_str(),
        F_cert_cn = ident.cn.as_str(),
        F_cert_fingerprint = ident.fingerprint.as_str(),
        F_level = i64::from(label.level),
        F_categories = format!("{:016x}", label.categories).as_str(),
    );
}

/// Emit `integrity_capped`.
pub fn emit_integrity_capped(
    ident: &CertIdent,
    pam_user: &str,
    pam_service: &str,
    effective: IntegrityLabel,
    user_mnkc: IntegrityLabel,
) {
    tracing::warn!(
        target: "mac.audit",
        F_event = EVENT_INTEGRITY_CAPPED,
        F_pam_user = pam_user,
        F_pam_service = pam_service,
        F_cert_serial = ident.serial.as_str(),
        F_cert_issuer = ident.issuer.as_str(),
        F_cert_cn = ident.cn.as_str(),
        F_cert_fingerprint = ident.fingerprint.as_str(),
        F_effective_level = i64::from(effective.level),
        F_effective_categories = format!("{:016x}", effective.categories).as_str(),
        F_user_level = i64::from(user_mnkc.level),
        F_user_categories = format!("{:016x}", user_mnkc.categories).as_str(),
    );
}

/// Emit `role_mask_exceeds_ceiling` — role `mac_mask` not covered by the cert
/// ceiling. The caller additionally emits a `role.audit` `role_deny` with
/// `reason=mask_exceeds_ceiling`; this event records the MAC-side detail.
pub fn emit_mask_exceeds_ceiling(
    ident: &CertIdent,
    pam_user: &str,
    pam_service: &str,
    requested: IntegrityLabel,
    ceiling: IntegrityLabel,
) {
    tracing::warn!(
        target: "mac.audit",
        F_event = EVENT_MASK_EXCEEDS_CEILING,
        F_pam_user = pam_user,
        F_pam_service = pam_service,
        F_cert_serial = ident.serial.as_str(),
        F_cert_issuer = ident.issuer.as_str(),
        F_cert_cn = ident.cn.as_str(),
        F_cert_fingerprint = ident.fingerprint.as_str(),
        F_requested_level = i64::from(requested.level),
        F_requested_categories = format!("{:016x}", requested.categories).as_str(),
        F_ceiling_level = i64::from(ceiling.level),
        F_ceiling_categories = format!("{:016x}", ceiling.categories).as_str(),
    );
}

/// Emit `homedir_label_above`.
pub fn emit_homedir_label_above(
    pam_user: &str,
    pam_service: &str,
    home_dir: &std::path::Path,
    home_label: IntegrityLabel,
    effective: IntegrityLabel,
) {
    tracing::warn!(
        target: "mac.audit",
        F_event = EVENT_HOMEDIR_LABEL_ABOVE,
        F_pam_user = pam_user,
        F_pam_service = pam_service,
        F_home_dir = %home_dir.display(),
        F_home_level = i64::from(home_label.level),
        F_home_categories = format!("{:016x}", home_label.categories).as_str(),
        F_effective_level = i64::from(effective.level),
        F_effective_categories = format!("{:016x}", effective.categories).as_str(),
    );
}

/// Emit `apply_failed`.
pub fn emit_apply_failed(ident: &CertIdent, pam_user: &str, pam_service: &str, detail: &str) {
    tracing::error!(
        target: "mac.audit",
        F_event = EVENT_MAC_APPLY_FAILED,
        F_pam_user = pam_user,
        F_pam_service = pam_service,
        F_cert_serial = ident.serial.as_str(),
        F_cert_issuer = ident.issuer.as_str(),
        F_cert_cn = ident.cn.as_str(),
        F_cert_fingerprint = ident.fingerprint.as_str(),
        F_detail = detail,
    );
}

/// Emit `mac_caps_missing` — process lacks `PARSEC_CAP_CHMAC`.
pub fn emit_caps_missing(detail: &str) {
    tracing::warn!(
        target: "mac.audit",
        F_event = EVENT_MAC_CAPS_MISSING,
        F_detail = detail,
    );
}

/// Emit `mac_user_unknown`.
pub fn emit_user_unknown(pam_user: &str, pam_service: &str) {
    tracing::error!(
        target: "mac.audit",
        F_event = EVENT_MAC_USER_UNKNOWN,
        F_pam_user = pam_user,
        F_pam_service = pam_service,
    );
}

/// Emit `mac_fallback_used`.
pub fn emit_fallback_used(pam_user: &str, pam_service: &str, fallback: IntegrityLabel) {
    tracing::info!(
        target: "mac.audit",
        F_event = EVENT_MAC_FALLBACK_USED,
        F_pam_user = pam_user,
        F_pam_service = pam_service,
        F_level = i64::from(fallback.level),
        F_categories = format!("{:016x}", fallback.categories).as_str(),
    );
}

/// Sliding window for `cert_max_integrity_parse_failed` deduplication.
const PARSE_FAIL_RATE_WINDOW: Duration = Duration::from_mins(1);
/// Hard cap on tracked fingerprints; oldest entry is evicted when full.
const PARSE_FAIL_CACHE_CAP: usize = 256;

fn parse_fail_cache() -> &'static Mutex<HashMap<String, Instant>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::with_capacity(PARSE_FAIL_CACHE_CAP)))
}

/// Returns `true` when an emit for `fingerprint` is permitted *right
/// now*; updates the bookkeeping side-effect. Used by
/// [`emit_cert_ext_parse_failed`] to avoid log floods if the same bad
/// cert is presented repeatedly.
#[doc(hidden)]
pub fn should_emit_parse_failed(fingerprint: &str) -> bool {
    let now = Instant::now();
    let mut cache = parse_fail_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Lazy GC of expired entries.
    cache.retain(|_, t| now.duration_since(*t) < PARSE_FAIL_RATE_WINDOW);

    if let Some(last) = cache.get(fingerprint) {
        if now.duration_since(*last) < PARSE_FAIL_RATE_WINDOW {
            return false;
        }
    }

    if cache.len() >= PARSE_FAIL_CACHE_CAP {
        if let Some(oldest_key) = cache.iter().min_by_key(|(_, t)| *t).map(|(k, _)| k.clone()) {
            cache.remove(&oldest_key);
        }
    }

    cache.insert(fingerprint.to_string(), now);
    true
}

/// Clear the parse-failed dedup cache; intended for tests.
#[doc(hidden)]
pub fn reset_parse_failed_cache() {
    if let Ok(mut cache) = parse_fail_cache().lock() {
        cache.clear();
    }
}

/// Emit `cert_max_integrity_parse_failed`.
///
/// Rate-limited: repeated calls with the same cert fingerprint inside a
/// 60-second window are suppressed (≤256 fingerprints tracked at once).
pub fn emit_cert_ext_parse_failed(pam_user: &str, ident: &CertIdent, err: &str) {
    if !should_emit_parse_failed(&ident.fingerprint) {
        return;
    }
    tracing::warn!(
        target: "mac.audit",
        F_event = EVENT_CERT_EXT_PARSE_FAILED,
        F_pam_user = pam_user,
        F_cert_serial = ident.serial.as_str(),
        F_cert_issuer = ident.issuer.as_str(),
        F_cert_cn = ident.cn.as_str(),
        F_cert_fingerprint = ident.fingerprint.as_str(),
        F_error = err,
        "MAX_INTEGRITY ext parse failed"
    );
}

/// Emit `mac_runtime_fallback` — `[mac].runtime = "auto"` resolved to
/// the stub backend because the kernel МКЦ subsystem is unavailable.
pub fn emit_runtime_fallback(reason: &str) {
    tracing::warn!(
        target: "mac.audit",
        F_event = EVENT_MAC_RUNTIME_FALLBACK,
        F_reason = reason,
    );
}

/// Emit `mac_runtime_disabled` — operator explicitly disabled the selected
/// plugin via `[mac].runtime = "disabled"`.
pub fn emit_runtime_disabled() {
    tracing::info!(
        target: "mac.audit",
        F_event = EVENT_MAC_RUNTIME_DISABLED,
    );
}

/// Emit `mac_socket_label_set` — debug-level breadcrumb that the daemon
/// successfully labeled its IPC socket tempfile before rename.
pub fn emit_socket_label(path: &str) {
    tracing::debug!(
        target: "mac.audit",
        F_event = EVENT_MAC_SOCKET_LABEL,
        F_path = path,
    );
}

/// Emit `mac_sessions_file_label_warning` — fd-based label of the
/// `sessions.json` tempfile could not be applied; the write continues
/// best-effort and DAC + parent-dir inheritance remain the guardrails.
pub fn emit_sessions_file_warn(path: &str, err: Option<&str>) {
    tracing::warn!(
        target: "mac.audit",
        F_event = EVENT_MAC_SESSIONS_FILE_WARN,
        F_path = path,
        F_error = err.unwrap_or("-"),
    );
}

/// Emit `cert_max_integrity_categories_above_32bit` — diagnostic only.
pub fn emit_categories_above_32bit(categories: u64) {
    tracing::info!(
        target: "mac.audit",
        F_event = EVENT_CERT_MAX_INT_CATS_ABOVE_32BIT,
        F_categories = format!("{categories:016x}").as_str(),
    );
}

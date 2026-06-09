//! PAM stack ordering check.
//!
//! Astra SE 1.8.x ships `pam_parsec_mac.so` in the `auth` phase of every
//! interactive service (login, fly-dm, sshd, …). Our integrate-pam.sh adds
//! `@include tessera-only` (or `tessera-optional`) whose Felix block uses
//! `success=done` to short-circuit on a successful certificate auth.
//!
//! If our include lands BEFORE `auth required pam_parsec_mac.so`, the
//! short-circuit jumps over `pam_parsec_mac` and its later `account`-phase
//! companion fails with "Can't obtain required data", denying login on an
//! otherwise correct setup.
//!
//! This check scans the well-known PAM service files and warns whenever the
//! ordering invariant is violated. It does NOT auto-repair — admins keep
//! the autonomy to override — but it surfaces the regression on every
//! daemon start so a stray edit doesn't sit unnoticed.

use std::path::Path;

use super::{StartupCheckRecord, StartupCheckReport};

/// Standard Astra services we scan. Missing files are silently skipped —
/// e.g. `fly-dm-np` only exists on некоторых конфигурациях.
const STANDARD_SERVICES: &[&str] = &["login", "fly-dm", "fly-dm-np", "sshd", "sudo", "su"];

/// Run the PAM stack ordering check.
pub fn check(pam_d_root: &Path, report: &mut StartupCheckReport) {
    for svc in STANDARD_SERVICES {
        let path = pam_d_root.join(svc);
        if !path.exists() {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                report.push(StartupCheckRecord::warn(
                    "pam_stack_read_failed",
                    format!(
                        "PAM service {path}: read failed ({e})",
                        path = path.display()
                    ),
                ));
                continue;
            }
        };
        evaluate_service(&path, &text, report);
    }
}

/// Inspect a single PAM service file. Public for unit tests that want to
/// drive arbitrary content without round-tripping through the filesystem.
pub fn evaluate_service(path: &Path, text: &str, report: &mut StartupCheckReport) {
    let mut include_line: Option<usize> = None;
    let mut parsec_line: Option<usize> = None;
    let mut session_tessera_line: Option<usize> = None;
    let mut systemd_anchor_line: Option<usize> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if is_tessera_include(line) {
            include_line.get_or_insert(idx);
        } else if is_auth_parsec_mac(line) {
            parsec_line.get_or_insert(idx);
        }
        if is_session_pam_tessera(line) {
            session_tessera_line.get_or_insert(idx);
        }
        // Anchor for the session-ordering check: either the direct module
        // line or the @include common-session aggregator (Debian/Astra
        // ships pam_systemd via common-session). We don't recursively
        // follow includes — direct line OR @include is good enough.
        if is_session_pam_systemd(line) || is_common_session_include(line) {
            systemd_anchor_line.get_or_insert(idx);
        }
    }

    // Auth/account misorder check (pre-0.3.12 invariant).
    match (include_line, parsec_line) {
        (Some(inc), Some(par)) if inc < par => {
            report.push(StartupCheckRecord::error(
                "pam_stack_misorder",
                format!(
                    "PAM stack misorder in {path}: @include tessera-* (line {inc}) appears \
                     BEFORE 'auth required pam_parsec_mac.so' (line {par}). On Astra SE the \
                     success=done jump will skip pam_parsec_mac and account-phase will fail \
                     'Can't obtain required data'. Run: \
                     sudo /usr/share/tessera/integrate-pam.sh --unintegrate {path} && \
                     sudo /usr/share/tessera/integrate-pam.sh --mode=<your-mode> {path}",
                    path = path.display(),
                    inc = inc + 1,
                    par = par + 1,
                ),
            ));
        }
        (Some(_), Some(_)) => {
            report.push(StartupCheckRecord::info(
                "pam_stack_ok",
                format!(
                    "PAM stack {path}: @include tessera-* correctly placed after \
                     pam_parsec_mac",
                    path = path.display()
                ),
            ));
        }
        // Either include missing (service not integrated) or pam_parsec_mac
        // missing (host without МКЦ). Both are common; no log noise.
        _ => {}
    }

    // Session-ordering check (0.3.12 invariant): `session required
    // pam_tessera.so` MUST come AFTER `pam_systemd.so` / @include
    // common-session, otherwise XDG_SESSION_ID is not yet in PAM env when
    // pam_sm_open_session runs → UpdateSessionTarget never sent → monitord
    // can't drive logind Logout/Lock on USB removal.
    match (session_tessera_line, systemd_anchor_line) {
        (Some(ses), Some(sys)) if ses < sys => {
            report.push(StartupCheckRecord::error(
                "pam_stack_session_misorder",
                format!(
                    "PAM session-phase misorder in {path}: 'session required pam_tessera.so' \
                     (line {ses}) appears BEFORE pam_systemd.so / @include common-session \
                     (line {sys}). XDG_SESSION_ID is not available during pam_sm_open_session \
                     and UpdateSessionTarget is not sent → USB-removal Lock/Logout actions \
                     will not work. Run: \
                     sudo /usr/share/tessera/integrate-pam.sh --unintegrate {path} && \
                     sudo /usr/share/tessera/integrate-pam.sh --mode=<your-mode> {path}",
                    path = path.display(),
                    ses = ses + 1,
                    sys = sys + 1,
                ),
            ));
        }
        (Some(_), Some(_)) => {
            report.push(StartupCheckRecord::info(
                "pam_stack_session_ok",
                format!(
                    "PAM stack {path}: 'session required pam_tessera.so' correctly placed \
                     after pam_systemd.so / @include common-session",
                    path = path.display()
                ),
            ));
        }
        // session pam_tessera present but no systemd anchor: host has no
        // systemd (sysvinit/OpenRC) or pam_systemd never wired in. The
        // USB-removal logout via logind won't work in this layout anyway —
        // surface as INFO so the operator at least sees the state.
        (Some(_), None) => {
            report.push(StartupCheckRecord::info(
                "pam_stack_session_no_systemd",
                format!(
                    "PAM stack {path}: 'session required pam_tessera.so' present but no \
                     pam_systemd.so / @include common-session detected — XDG_SESSION_ID \
                     pathway unavailable, USB-removal Logout via logind will fall back to \
                     placeholder targets",
                    path = path.display()
                ),
            ));
        }
        // No session pam_tessera line at all → service not integrated for
        // session phase. Stay silent (auth-only integrations exist).
        _ => {}
    }
}

fn is_tessera_include(line: &str) -> bool {
    // Matches `@include tessera`, `@include tessera-only`,
    // `@include tessera-optional` with arbitrary surrounding whitespace.
    // These are the snippet names shipped in dist/pam.d/ and inserted by
    // integrate-pam.sh; the pre-rename `certauth*` snippets never shipped,
    // so the legacy names are intentionally not recognized.
    let mut it = line.split_whitespace();
    let Some(first) = it.next() else { return false };
    if first != "@include" {
        return false;
    }
    let Some(name) = it.next() else { return false };
    if it.next().is_some() {
        return false;
    }
    matches!(name, "tessera" | "tessera-only" | "tessera-optional")
}

fn is_auth_parsec_mac(line: &str) -> bool {
    // Matches lines whose first token is `auth` and which mention
    // `pam_parsec_mac.so` anywhere in the rest of the line. We are
    // intentionally lenient on the control field (could be `required`,
    // `requisite`, or a substack expression on customized stacks).
    let mut it = line.split_whitespace();
    let Some(phase) = it.next() else { return false };
    if phase != "auth" {
        return false;
    }
    line.contains("pam_parsec_mac.so")
}

fn is_session_pam_tessera(line: &str) -> bool {
    // Matches `session <control> pam_tessera.so [args...]` regardless of
    // control field. Used by the 0.3.12 session-ordering check.
    let mut it = line.split_whitespace();
    let Some(phase) = it.next() else { return false };
    if phase != "session" {
        return false;
    }
    line.contains("pam_tessera.so")
}

fn is_session_pam_systemd(line: &str) -> bool {
    // Direct `session <control> pam_systemd.so` line — Debian usually
    // delivers this via @include common-session, but Astra SE custom
    // stacks sometimes inline it; both shapes need to anchor our check.
    let mut it = line.split_whitespace();
    let Some(phase) = it.next() else { return false };
    if phase != "session" {
        return false;
    }
    line.contains("pam_systemd.so")
}

fn is_common_session_include(line: &str) -> bool {
    // `@include common-session` or `@include common-session-noninteractive`.
    // We do NOT recursively follow the include — on a healthy Debian/Astra
    // host common-session contains pam_systemd, so its presence is a good
    // proxy. Operators with custom common-session content will see
    // pam_stack_session_no_systemd if they also omit the direct line.
    let mut it = line.split_whitespace();
    let Some(first) = it.next() else { return false };
    if first != "@include" {
        return false;
    }
    let Some(name) = it.next() else { return false };
    if it.next().is_some() {
        return false;
    }
    name == "common-session" || name == "common-session-noninteractive"
}

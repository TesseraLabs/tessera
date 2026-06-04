//! XDG_SESSION_ID capture: pushes a fresh `SessionTarget::LogindSession`
//! to monitord during `pam_sm_open_session` so the action handler can
//! later target the real logind id on USB removal.
//!
//! The PAM module is called twice per login (see `integrate-pam.sh`):
//!
//! 1. From the `@include certauth-only` block — runs BEFORE
//!    `pam_systemd.so`, so `XDG_SESSION_ID` is NULL. We log debug and
//!    no-op.
//! 2. From the explicit `session required pam_tessera.so` after
//!    `@include common-session` — runs AFTER `pam_systemd.so` set
//!    `XDG_SESSION_ID`. We push `UpdateSessionTarget` to monitord.
//!
//! Both calls are best-effort: an IPC failure logs a WARN but never
//! breaks the session-open path. Authentication is already complete
//! and the kernel/user verdict cannot be reversed at this point.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use tessera_core::error::IpcError;
use tessera_proto::SessionTarget;
use uuid::Uuid;

/// Outcome of a single capture attempt — exposed so tests can assert
/// the right branch fired without spying on `tracing` macros.
#[derive(Debug, PartialEq, Eq)]
pub enum CaptureOutcome {
    /// `XDG_SESSION_ID` was present and the IPC push succeeded.
    Pushed,
    /// `XDG_SESSION_ID` was present but the IPC push failed (best-effort).
    PushFailed,
    /// `XDG_SESSION_ID` was unset/empty — first call before
    /// `pam_systemd`. Expected and benign.
    Skipped,
}

/// Map the PAM-supplied session-id string to a stable [`Uuid`].
///
/// Mirrors `tessera_core::ipc::client::uuid_from_session_id`
/// (which is private to that crate): if the input parses as a UUID,
/// use it as-is; otherwise hash deterministically under `NAMESPACE_OID`.
#[must_use]
pub fn session_uuid_from_string(s: &str) -> Uuid {
    if let Ok(parsed) = Uuid::parse_str(s) {
        return parsed;
    }
    Uuid::new_v5(&Uuid::NAMESPACE_OID, s.as_bytes())
}

/// Pure capture helper: given a possibly-NULL `XDG_SESSION_ID` and a
/// callable that performs the IPC push, decide whether to call it and
/// classify the outcome.
///
/// The callable receives the constructed [`SessionTarget`] so tests
/// can verify the variant + payload without needing a live socket.
pub fn capture_xdg<F>(
    session_id: Uuid,
    xdg_session_id: Option<&str>,
    push: F,
) -> CaptureOutcome
where
    F: FnOnce(SessionTarget) -> Result<(), IpcError>,
{
    let Some(xdg) = xdg_session_id.filter(|s| !s.is_empty()) else {
        tracing::debug!(
            target: "tessera.session",
            session_id = %session_id,
            "XDG_SESSION_ID not yet in PAM env (early session call — pam_systemd not yet run, normal); USB-removal action will fall back to original target",
        );
        return CaptureOutcome::Skipped;
    };
    let target = SessionTarget::LogindSession { id: xdg.to_string() };
    match push(target) {
        Ok(()) => {
            tracing::info!(
                target: "tessera.session",
                session_id = %session_id,
                xdg_session_id = %xdg,
                "update_session_target sent: LogindSession",
            );
            CaptureOutcome::Pushed
        }
        Err(err) => {
            tracing::warn!(
                target: "tessera.session",
                session_id = %session_id,
                xdg_session_id = %xdg,
                error = %err,
                "update_session_target IPC failed (best-effort; auth verdict unchanged)",
            );
            CaptureOutcome::PushFailed
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn fixed_uuid() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()
    }

    #[test]
    fn skipped_when_xdg_missing() {
        let called = RefCell::new(false);
        let out = capture_xdg(fixed_uuid(), None, |_t| {
            *called.borrow_mut() = true;
            Ok(())
        });
        assert_eq!(out, CaptureOutcome::Skipped);
        assert!(!*called.borrow(), "IPC must not be called when XDG is None");
    }

    #[test]
    fn skipped_when_xdg_empty() {
        let called = RefCell::new(false);
        let out = capture_xdg(fixed_uuid(), Some(""), |_t| {
            *called.borrow_mut() = true;
            Ok(())
        });
        assert_eq!(out, CaptureOutcome::Skipped);
        assert!(
            !*called.borrow(),
            "IPC must not be called when XDG is empty"
        );
    }

    #[test]
    fn pushed_when_xdg_present() {
        let captured: RefCell<Option<SessionTarget>> = RefCell::new(None);
        let out = capture_xdg(fixed_uuid(), Some("c1"), |t| {
            *captured.borrow_mut() = Some(t);
            Ok(())
        });
        assert_eq!(out, CaptureOutcome::Pushed);
        match captured.into_inner() {
            Some(SessionTarget::LogindSession { id }) => assert_eq!(id, "c1"),
            other => panic!("expected LogindSession {{ id: \"c1\" }}, got {other:?}"),
        }
    }

    #[test]
    fn push_failure_is_classified_but_does_not_propagate() {
        // Mimic a daemon that returns BAD_REQUEST (older monitord).
        let out = capture_xdg(fixed_uuid(), Some("c7"), |_t| {
            Err(IpcError::Server {
                code: 0,
                message: "bad request".into(),
            })
        });
        assert_eq!(out, CaptureOutcome::PushFailed);
    }

    #[test]
    fn uuid_from_string_parses_uuid_format() {
        let s = "00000000-0000-4000-8000-000000000001";
        assert_eq!(session_uuid_from_string(s), Uuid::parse_str(s).unwrap());
    }

    #[test]
    fn uuid_from_string_hashes_non_uuid() {
        let a = session_uuid_from_string("sess-deadbeef");
        let b = session_uuid_from_string("sess-deadbeef");
        let c = session_uuid_from_string("sess-cafef00d");
        assert_eq!(a, b, "deterministic for same input");
        assert_ne!(a, c, "differs for different input");
    }
}

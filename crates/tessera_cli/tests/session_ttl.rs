#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Bounded role-session TTL enforcement, driven directly against the state
//! manager so the raw expiry [`ActionRequest`] can be observed.
//!
//! Timings are wall-clock and deliberately short: firing cases put the
//! deadline a few hundred milliseconds ahead (or already in the past) and the
//! cancellation case leaves a full second so the close is guaranteed to land
//! first. This mirrors the style of `udev_simulation.rs` and sidesteps the
//! `spawn_blocking` persist that runs inside the `SessionOpen` handler, which
//! makes tokio's paused-clock auto-advance awkward to reason about here.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tessera_cli::registry::{ActiveSession, RegistryStore, SessionRegistry};
use tessera_cli::state::{
    spawn_state_manager, ActionRequest, Event, IpcRequest, OnUsbRemoved, StateConfig,
};
use tessera_cli::udev_query::AlwaysPresent;
use tessera_proto::{ServerMessage, SessionTarget};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Build a session with an explicit open time and bounded TTL, expressed as an
/// absolute `session_expiry` of `opened_at + ttl` so these tests keep exercising
/// the same deadlines against the daemon's absolute scheduler.
fn session(id: u128, opened_at: SystemTime, bounded_ttl_secs: Option<u64>) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(id),
        pam_user: "alice".into(),
        pam_service: "sshd".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: Some("AB".into()),
        host_id_hash: "h".into(),
        opened_at,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 1000,
        session_expiry: bounded_ttl_secs.map(|s| opened_at + Duration::from_secs(s)),
    }
}

struct Harness {
    event_tx: mpsc::UnboundedSender<Event>,
    action_rx: mpsc::UnboundedReceiver<ActionRequest>,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

fn spawn(registry: SessionRegistry) -> Harness {
    let dir = tempfile::tempdir().expect("tmp");
    let store = RegistryStore::new(dir.path().join("sessions.json"));
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, action_rx) = mpsc::unbounded_channel();
    let cfg = StateConfig {
        grace_seconds: 1,
        suspend_grace_seconds: 5,
        on_usb_removed: OnUsbRemoved::Logout,
        registry_store: store,
    };
    let shutdown = CancellationToken::new();
    let _h = spawn_state_manager(
        cfg,
        registry,
        event_rx,
        action_tx,
        Arc::new(AlwaysPresent),
        shutdown.clone(),
    );
    Harness {
        event_tx,
        action_rx,
        shutdown,
        _dir: dir,
    }
}

/// Send a `SessionOpen` and wait for the daemon's `Ack`, so the caller knows
/// the session (and its TTL timer) is live before proceeding.
async fn open_session(event_tx: &mpsc::UnboundedSender<Event>, session: ActiveSession) {
    let (reply, reply_rx) = oneshot::channel();
    event_tx
        .send(Event::Ipc(IpcRequest::SessionOpen {
            session: Box::new(session),
            reply,
        }))
        .expect("send open");
    let msg = reply_rx.await.expect("open reply");
    assert!(matches!(msg, ServerMessage::Ack), "got {msg:?}");
}

async fn close_session(event_tx: &mpsc::UnboundedSender<Event>, id: Uuid) {
    let (reply, reply_rx) = oneshot::channel();
    event_tx
        .send(Event::Ipc(IpcRequest::SessionClose {
            session_id: id,
            closed_at: SystemTime::now(),
            reply,
        }))
        .expect("send close");
    let msg = reply_rx.await.expect("close reply");
    assert!(matches!(msg, ServerMessage::Ack), "got {msg:?}");
}

#[tokio::test]
async fn ttl_dispatches_exactly_one_expiry_action_after_deadline() {
    let mut h = spawn(SessionRegistry::new());
    // Deadline ~300 ms out: opened_at is 700 ms in the past with a 1 s TTL.
    let opened_at = SystemTime::now() - Duration::from_millis(700);
    open_session(&h.event_tx, session(1, opened_at, Some(1))).await;

    let req = tokio::time::timeout(Duration::from_secs(3), h.action_rx.recv())
        .await
        .expect("expiry action within deadline")
        .expect("action present");
    match req {
        ActionRequest::HandleSessionExpired { session, action } => {
            assert_eq!(session.session_id, Uuid::from_u128(1));
            assert_eq!(action, OnUsbRemoved::Logout);
        }
        other => panic!("expected HandleSessionExpired, got {other:?}"),
    }

    // Exactly one — no duplicate for the same session.
    assert!(
        h.action_rx.try_recv().is_err(),
        "a single expiry must fire exactly one action"
    );
    h.shutdown.cancel();
}

#[tokio::test]
async fn session_close_before_deadline_cancels_ttl() {
    let mut h = spawn(SessionRegistry::new());
    // A full second of head-room so the close is processed well before the
    // TTL timer could fire.
    let opened_at = SystemTime::now();
    open_session(&h.event_tx, session(2, opened_at, Some(1))).await;
    close_session(&h.event_tx, Uuid::from_u128(2)).await;

    // Wait past the original deadline: no action must fire for a cleanly
    // closed session.
    let res = tokio::time::timeout(Duration::from_millis(1500), h.action_rx.recv()).await;
    assert!(res.is_err(), "cancelled TTL must not fire, got {res:?}");
    h.shutdown.cancel();
}

#[tokio::test]
async fn startup_restore_expires_overdue_immediately_and_schedules_future() {
    // One session whose deadline already passed while the daemon was "down",
    // and one whose deadline is far in the future.
    let overdue = session(
        10,
        SystemTime::now() - Duration::from_secs(100),
        Some(10), // deadline = now - 90 s
    );
    let future = session(11, SystemTime::now(), Some(1000));
    let registry = SessionRegistry::from_snapshot(vec![overdue, future]);
    let mut h = spawn(registry);

    // The overdue session is terminated as soon as the startup sweep runs.
    let req = tokio::time::timeout(Duration::from_secs(3), h.action_rx.recv())
        .await
        .expect("overdue session expired on startup")
        .expect("action present");
    match req {
        ActionRequest::HandleSessionExpired { session, .. } => {
            assert_eq!(session.session_id, Uuid::from_u128(10));
        }
        other => panic!("expected HandleSessionExpired, got {other:?}"),
    }

    // The future-dated session is scheduled, not fired immediately.
    assert!(
        h.action_rx.try_recv().is_err(),
        "future-dated session must not expire on startup"
    );
    h.shutdown.cancel();
}

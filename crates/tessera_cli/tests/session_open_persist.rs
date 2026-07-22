#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Fault-injection coverage for durable `SessionOpen` registration.
//!
//! A session must not be acknowledged until its registry entry is durably
//! written. When the persist fails, the daemon rolls the in-memory insert
//! back and replies with an error so a strict-mode PAM client fails closed
//! instead of believing a never-persisted session is active.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tessera_cli::registry::{ActiveSession, RegistryStore, SessionRegistry};
use tessera_cli::state::{spawn_state_manager, ActionRequest, Event, IpcRequest, StateConfig};
use tessera_cli::udev_query::AlwaysPresent;
use tessera_proto::{ServerMessage, SessionTarget};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn session() -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(7),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: Some("AB".into()),
        usb_vid_pid: None,
        usb_devnode: None,
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
        session_expiry: None,
    }
}

fn spawn(
    store: RegistryStore,
) -> (
    mpsc::UnboundedSender<Event>,
    SessionRegistry,
    CancellationToken,
) {
    let registry = SessionRegistry::new();
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    // The action receiver is unused here — these tests never drive a removal,
    // so no `ActionRequest` is ever sent. Dropping it is harmless.
    let (action_tx, _action_rx) = mpsc::unbounded_channel::<ActionRequest>();
    let cfg = StateConfig::test_defaults(store);
    let shutdown = CancellationToken::new();
    let _h = spawn_state_manager(
        cfg,
        registry.clone(),
        event_rx,
        action_tx,
        Arc::new(AlwaysPresent),
        shutdown.clone(),
    );
    (event_tx, registry, shutdown)
}

async fn open(event_tx: &mpsc::UnboundedSender<Event>) -> ServerMessage {
    let (tx, rx) = oneshot::channel();
    event_tx
        .send(Event::Ipc(IpcRequest::SessionOpen {
            session: Box::new(session()),
            reply: tx,
        }))
        .expect("send");
    tokio::time::timeout(Duration::from_secs(3), rx)
        .await
        .expect("reply timeout")
        .expect("reply dropped")
}

#[tokio::test]
async fn session_open_persist_failure_rolls_back_and_errors() {
    // Point the store at a path whose parent is a regular file, so the
    // atomic write's `create_dir_all` fails deterministically.
    let dir = tempfile::tempdir().expect("tmp");
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"not a dir").expect("write blocker");
    let store = RegistryStore::new(blocker.join("sessions.json"));

    let (event_tx, registry, shutdown) = spawn(store);
    let reply = open(&event_tx).await;

    assert!(
        matches!(
            reply,
            ServerMessage::Error {
                code: tessera_proto::error_codes::INTERNAL,
                ..
            }
        ),
        "expected INTERNAL error reply, got {reply:?}"
    );
    // Rolled back: the in-memory registry must not retain the session.
    assert!(
        registry.is_empty(),
        "in-memory insert must be rolled back on persist failure"
    );
    shutdown.cancel();
}

#[tokio::test]
async fn session_open_persist_success_acks_and_persists() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("sessions.json");
    let store = RegistryStore::new(path.clone());

    let (event_tx, registry, shutdown) = spawn(store.clone());
    let reply = open(&event_tx).await;

    assert!(
        matches!(reply, ServerMessage::Ack),
        "expected Ack, got {reply:?}"
    );
    assert_eq!(registry.len(), 1);
    let loaded = store.load().expect("load");
    assert_eq!(loaded.len(), 1, "session must be durably persisted");
    shutdown.cancel();
}

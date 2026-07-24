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
use tessera_cli::state::{
    spawn_state_manager, ActionRequest, CredentialMode, Event, IpcRequest, StateConfig,
};
use tessera_cli::udev_query::{AlwaysAbsent, AlwaysPresent, FakeUdevQuery, UdevQuery};
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
    spawn_with(
        store,
        SessionRegistry::new(),
        CredentialMode::Pkcs12,
        Arc::new(AlwaysPresent),
    )
}

fn spawn_with(
    store: RegistryStore,
    registry: SessionRegistry,
    credential_mode: CredentialMode,
    udev_query: Arc<dyn UdevQuery>,
) -> (
    mpsc::UnboundedSender<Event>,
    SessionRegistry,
    CancellationToken,
) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    // The action receiver is unused here — these tests never drive a removal,
    // so no `ActionRequest` is ever sent. Dropping it is harmless.
    let (action_tx, _action_rx) = mpsc::unbounded_channel::<ActionRequest>();
    let mut cfg = StateConfig::test_defaults(store);
    cfg.credential_mode = credential_mode;
    let shutdown = CancellationToken::new();
    let _h = spawn_state_manager(
        cfg,
        registry.clone(),
        event_rx,
        action_tx,
        udev_query,
        shutdown.clone(),
    );
    (event_tx, registry, shutdown)
}

async fn open(event_tx: &mpsc::UnboundedSender<Event>, session: ActiveSession) -> ServerMessage {
    let (tx, rx) = oneshot::channel();
    event_tx
        .send(Event::Ipc(IpcRequest::SessionOpen {
            session: Box::new(session),
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
    let reply = open(&event_tx, session()).await;

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
    let reply = open(&event_tx, session()).await;

    assert!(
        matches!(reply, ServerMessage::Ack),
        "expected Ack, got {reply:?}"
    );
    assert_eq!(registry.len(), 1);
    let loaded = store.load().expect("load");
    assert_eq!(loaded.len(), 1, "session must be durably persisted");
    shutdown.cancel();
}

#[tokio::test]
async fn duplicate_open_persist_failure_preserves_previous_session() {
    let dir = tempfile::tempdir().expect("tmp");
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"not a dir").expect("write blocker");
    let store = RegistryStore::new(blocker.join("sessions.json"));

    let mut previous = session();
    previous.cert_cn = "previous".into();
    previous.session_expiry = Some(SystemTime::now() + Duration::from_secs(3600));
    let registry = SessionRegistry::from_snapshot(vec![previous.clone()]);
    let (event_tx, registry, shutdown) = spawn_with(
        store,
        registry,
        CredentialMode::Pkcs12,
        Arc::new(AlwaysPresent),
    );

    let mut replacement = session();
    replacement.cert_cn = "replacement".into();
    replacement.session_expiry = None;
    let reply = open(&event_tx, replacement).await;

    assert!(matches!(
        reply,
        ServerMessage::Error {
            code: tessera_proto::error_codes::INTERNAL,
            ..
        }
    ));
    assert_eq!(
        registry.find_by_session_id(previous.session_id),
        Some(previous),
        "failed duplicate open must preserve the previous durable session"
    );
    shutdown.cancel();
}

#[tokio::test]
async fn pkcs12_open_requires_full_captured_topology() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = RegistryStore::new(dir.path().join("sessions.json"));
    let query = FakeUdevQuery::with_device("AB", Some("9999:9999"), Some("/dev/sdc1"));
    let (event_tx, registry, shutdown) = spawn_with(
        store,
        SessionRegistry::new(),
        CredentialMode::Pkcs12,
        Arc::new(query),
    );
    let mut attempted = session();
    attempted.usb_vid_pid = Some("1234:5678".into());
    attempted.usb_devnode = Some("/dev/sdb1".into());

    let reply = open(&event_tx, attempted).await;

    assert!(matches!(
        reply,
        ServerMessage::Error {
            code: tessera_proto::error_codes::DEVICE_GONE,
            ..
        }
    ));
    assert!(registry.is_empty());
    shutdown.cancel();
}

#[tokio::test]
async fn permissive_pkcs11_open_skips_block_device_namespace() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = RegistryStore::new(dir.path().join("sessions.json"));
    let (event_tx, registry, shutdown) = spawn_with(
        store,
        SessionRegistry::new(),
        CredentialMode::Pkcs11,
        Arc::new(AlwaysAbsent),
    );

    let reply = open(&event_tx, session()).await;

    assert!(matches!(reply, ServerMessage::Ack));
    assert_eq!(registry.len(), 1);
    shutdown.cancel();
}

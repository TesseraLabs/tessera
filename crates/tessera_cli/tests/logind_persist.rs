//! Regression test for the Codex-review finding: when logind sends
//! `SessionRemoved` for an active session, the in-memory registry is
//! cleared but the on-disk snapshot must also be rewritten — otherwise a
//! daemon restart resurrects sessions logind has already torn down.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tessera_cli::logind::LogindSignal;
use tessera_cli::registry::{ActiveSession, RegistryStore, SessionRegistry};
use tessera_cli::state::{spawn_state_manager, Event, OnUsbRemoved, StateConfig};
use tessera_cli::udev_query::AlwaysPresent;
use tessera_proto::SessionTarget;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn session_with_logind_id(uuid_seed: u128, logind_id: &str) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(uuid_seed),
        pam_user: "alice".into(),
        pam_service: "ssh".into(),
        target: SessionTarget::logind(logind_id),
        usb_serial: Some("AB".into()),
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "alice".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
    }
}

#[tokio::test]
async fn logind_session_removed_persists_registry_snapshot() {
    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("sessions.json");
    let store = RegistryStore::new(state_path.clone());

    // Seed the registry with a session whose target is logind id "c1".
    let registry = SessionRegistry::new();
    registry.add(session_with_logind_id(1, "c1"));
    // Persist the seed so that, before the SessionRemoved signal, the
    // on-disk snapshot also lists this session — this simulates the
    // "PAM module already wrote SessionOpen" state at boot.
    store.persist(&registry.snapshot()).expect("seed persist");
    let loaded_pre = store.load().expect("load pre");
    assert_eq!(loaded_pre.len(), 1, "seed sanity");

    // Wire the state manager.
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, _action_rx) = mpsc::unbounded_channel();
    let cfg = StateConfig {
        grace_seconds: 5,
        suspend_grace_seconds: 30,
        on_usb_removed: OnUsbRemoved::Lock,
        registry_store: store.clone(),
    };
    let shutdown = CancellationToken::new();
    let _h = spawn_state_manager(
        cfg,
        registry.clone(),
        event_rx,
        action_tx,
        Arc::new(AlwaysPresent),
        shutdown.clone(),
    );

    // Fire SessionRemoved for "c1".
    event_tx
        .send(Event::Logind(LogindSignal::SessionRemoved {
            id: "c1".into(),
            object_path: "/org/freedesktop/login1/session/_3c1".into(),
        }))
        .expect("send");

    // Give the state task a moment to handle the event and persist.
    // We poll the file with a short bound rather than sleeping a fixed
    // amount so the test is responsive on a slow CI host.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let on_disk = store.load().expect("load post");
        if on_disk.is_empty() {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "registry snapshot still contains {} sessions after logind SessionRemoved",
                on_disk.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Belt-and-braces: in-memory registry is also empty.
    assert_eq!(registry.snapshot().len(), 0);

    shutdown.cancel();
}

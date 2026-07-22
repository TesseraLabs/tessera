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
use tessera_cli::state::{spawn_state_manager, ActionRequest, Event, OnUsbRemoved, StateConfig};
use tessera_cli::udev_monitor::{UdevAction, UdevEvent};
use tessera_cli::udev_query::AlwaysPresent;
use tessera_proto::SessionTarget;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn session(serial: &str) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(1),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: Some(serial.into()),
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

#[tokio::test]
async fn suspend_window_blocks_actions() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = RegistryStore::new(dir.path().join("s.json"));
    let registry = SessionRegistry::new();
    registry.add(session("AB"));
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, mut action_rx) = mpsc::unbounded_channel();
    let cfg = StateConfig {
        grace_seconds: 1,
        suspend_grace_seconds: 5,
        on_usb_removed: OnUsbRemoved::Lock,
        registry_store: store,
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
    // Enter suspend.
    event_tx
        .send(Event::Logind(LogindSignal::PrepareForSleep(true)))
        .expect("send");
    // USB removed during suspend — should be ignored.
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Remove,
            devnode: None,
            serial: Some("AB".into()),
            vid_pid: None,
            is_usb: true,
        }))
        .expect("send");
    let res = tokio::time::timeout(Duration::from_secs(2), action_rx.recv()).await;
    assert!(res.is_err(), "no action should fire while suspending");
    shutdown.cancel();
}

#[tokio::test]
async fn after_resume_grace_expires_actions_resume() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = RegistryStore::new(dir.path().join("s.json"));
    let registry = SessionRegistry::new();
    registry.add(session("AB"));
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, mut action_rx) = mpsc::unbounded_channel();
    let cfg = StateConfig {
        grace_seconds: 1,
        suspend_grace_seconds: 1, // very short suspend grace for the test
        on_usb_removed: OnUsbRemoved::Lock,
        registry_store: store,
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
    event_tx
        .send(Event::Logind(LogindSignal::PrepareForSleep(true)))
        .expect("send");
    event_tx
        .send(Event::Logind(LogindSignal::PrepareForSleep(false)))
        .expect("send");
    // Wait past the suspend grace.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Remove,
            devnode: None,
            serial: Some("AB".into()),
            vid_pid: None,
            is_usb: true,
        }))
        .expect("send");
    let req = tokio::time::timeout(Duration::from_secs(3), action_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");
    assert!(matches!(req, ActionRequest::HandleUsbRemoved { .. }));
    shutdown.cancel();
}

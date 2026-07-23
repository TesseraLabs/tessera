#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Drives the state manager directly via injected udev events.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tessera_cli::registry::{ActiveSession, RegistryStore, SessionRegistry};
use tessera_cli::state::{
    spawn_state_manager, ActionRequest, CredentialMode, Event, IpcRequest, OnUsbRemoved,
    StateConfig,
};
use tessera_cli::udev_monitor::{UdevAction, UdevEvent};
use tessera_cli::udev_query::AlwaysPresent;
use tessera_proto::{ServerMessage, SessionTarget};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn session(serial: &str) -> ActiveSession {
    session_with_topology(serial, None, None)
}

fn session_with_topology(
    serial: &str,
    vid_pid: Option<&str>,
    devnode: Option<&str>,
) -> ActiveSession {
    session_with_id_topology(1, serial, vid_pid, devnode)
}

fn session_with_id_topology(
    id: u128,
    serial: &str,
    vid_pid: Option<&str>,
    devnode: Option<&str>,
) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(id),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: Some(serial.into()),
        usb_vid_pid: vid_pid.map(str::to_string),
        usb_devnode: devnode.map(str::to_string),
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

fn setup() -> (
    mpsc::UnboundedSender<Event>,
    mpsc::UnboundedReceiver<ActionRequest>,
    SessionRegistry,
    CancellationToken,
    tempfile::TempDir,
) {
    setup_with(session("AB"))
}

fn setup_with(
    reg_session: ActiveSession,
) -> (
    mpsc::UnboundedSender<Event>,
    mpsc::UnboundedReceiver<ActionRequest>,
    SessionRegistry,
    CancellationToken,
    tempfile::TempDir,
) {
    setup_with_sessions(vec![reg_session])
}

fn setup_with_sessions(
    sessions: Vec<ActiveSession>,
) -> (
    mpsc::UnboundedSender<Event>,
    mpsc::UnboundedReceiver<ActionRequest>,
    SessionRegistry,
    CancellationToken,
    tempfile::TempDir,
) {
    setup_with_sessions_and_mode(sessions, CredentialMode::Pkcs12)
}

fn setup_with_sessions_and_mode(
    sessions: Vec<ActiveSession>,
    credential_mode: CredentialMode,
) -> (
    mpsc::UnboundedSender<Event>,
    mpsc::UnboundedReceiver<ActionRequest>,
    SessionRegistry,
    CancellationToken,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tmp");
    let store = RegistryStore::new(dir.path().join("s.json"));
    let registry = SessionRegistry::new();
    for session in sessions {
        registry.add(session);
    }
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, action_rx) = mpsc::unbounded_channel();
    let cfg = StateConfig {
        credential_mode,
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
    (event_tx, action_rx, registry, shutdown, dir)
}

async fn open_session(
    event_tx: &mpsc::UnboundedSender<Event>,
    session: ActiveSession,
) -> ServerMessage {
    let (reply, reply_rx) = oneshot::channel();
    event_tx
        .send(Event::Ipc(IpcRequest::SessionOpen {
            session: Box::new(session),
            reply,
        }))
        .expect("send open");
    reply_rx.await.expect("open reply")
}

#[tokio::test]
async fn remove_then_grace_then_action_fires() {
    let (event_tx, mut action_rx, _r, shutdown, _dir) = setup();
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
    assert!(matches!(
        req,
        ActionRequest::HandleUsbRemoved {
            action: OnUsbRemoved::Lock,
            ..
        }
    ));
    shutdown.cancel();
}

#[tokio::test]
async fn remove_then_add_within_grace_cancels() {
    let (event_tx, mut action_rx, _r, shutdown, _dir) = setup();
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Remove,
            devnode: None,
            serial: Some("AB".into()),
            vid_pid: None,
            is_usb: true,
        }))
        .expect("send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Add,
            devnode: None,
            serial: Some("AB".into()),
            vid_pid: None,
            is_usb: true,
        }))
        .expect("send");
    // Grace is 1s; wait 2s; action should NOT fire.
    let res = tokio::time::timeout(Duration::from_secs(2), action_rx.recv()).await;
    assert!(res.is_err(), "expected timeout, got {:?}", res);
    shutdown.cancel();
}

#[tokio::test]
async fn successful_duplicate_open_cancels_previous_session_grace() {
    let original = session("AB");
    let (event_tx, mut action_rx, _r, shutdown, _dir) = setup_with(original.clone());
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Remove,
            devnode: None,
            serial: Some("AB".into()),
            vid_pid: None,
            is_usb: true,
        }))
        .expect("send remove");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut replacement = original;
    replacement.cert_cn = "replacement".into();
    assert!(matches!(
        open_session(&event_tx, replacement).await,
        ServerMessage::Ack
    ));

    let res = tokio::time::timeout(Duration::from_secs(2), action_rx.recv()).await;
    assert!(
        res.is_err(),
        "successful replacement must cancel the old grace action, got {res:?}"
    );
    shutdown.cancel();
}

#[tokio::test]
async fn pkcs11_mode_ignores_colliding_usb_block_serial() {
    let (event_tx, mut action_rx, _r, shutdown, _dir) =
        setup_with_sessions_and_mode(vec![session("AB")], CredentialMode::Pkcs11);
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Remove,
            devnode: Some("/dev/sdb1".into()),
            serial: Some("AB".into()),
            vid_pid: Some((0x1234, 0x5678)),
            is_usb: true,
        }))
        .expect("send remove");

    let res = tokio::time::timeout(Duration::from_millis(1200), action_rx.recv()).await;
    assert!(
        res.is_err(),
        "PKCS#11 serials must never bind to USB block-device events"
    );
    shutdown.cancel();
}

#[tokio::test]
async fn cloned_serial_different_vid_pid_does_not_cancel_removal() {
    // Adversarial: the authenticated device is bound to VID/PID 1234:5678 on
    // /dev/sdb1. An attacker plugs in a *different* device that merely clones
    // the USB descriptor serial "AB" (different VID/PID). The re-add must NOT
    // cancel the pending removal — the action still fires after the grace.
    let reg = session_with_topology("AB", Some("1234:5678"), Some("/dev/sdb1"));
    let (event_tx, mut action_rx, _r, shutdown, _dir) = setup_with(reg);

    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Remove,
            devnode: Some("/dev/sdb1".into()),
            serial: Some("AB".into()),
            vid_pid: Some((0x1234, 0x5678)),
            is_usb: true,
        }))
        .expect("send remove");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Cloned serial, attacker's VID/PID differs.
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Add,
            devnode: Some("/dev/sdc1".into()),
            serial: Some("AB".into()),
            vid_pid: Some((0x9999, 0x9999)),
            is_usb: true,
        }))
        .expect("send add");

    // Grace is 1s; the action must still fire despite the cloned-serial add.
    let req = tokio::time::timeout(Duration::from_secs(3), action_rx.recv())
        .await
        .expect("timeout waiting for action")
        .expect("recv");
    assert!(matches!(
        req,
        ActionRequest::HandleUsbRemoved {
            action: OnUsbRemoved::Lock,
            ..
        }
    ));
    shutdown.cancel();
}

#[tokio::test]
async fn matching_topology_re_add_cancels_removal() {
    // Control for the adversarial case: the SAME device (matching VID/PID and
    // devnode) coming back within grace legitimately cancels the removal.
    let reg = session_with_topology("AB", Some("1234:5678"), Some("/dev/sdb1"));
    let (event_tx, mut action_rx, _r, shutdown, _dir) = setup_with(reg);

    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Remove,
            devnode: Some("/dev/sdb1".into()),
            serial: Some("AB".into()),
            vid_pid: Some((0x1234, 0x5678)),
            is_usb: true,
        }))
        .expect("send remove");
    tokio::time::sleep(Duration::from_millis(200)).await;

    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Add,
            devnode: Some("/dev/sdb1".into()),
            serial: Some("AB".into()),
            vid_pid: Some((0x1234, 0x5678)),
            is_usb: true,
        }))
        .expect("send add");

    // Grace is 1s; wait 2s; action must NOT fire (legitimately cancelled).
    let res = tokio::time::timeout(Duration::from_secs(2), action_rx.recv()).await;
    assert!(res.is_err(), "expected timeout (cancelled), got {:?}", res);
    shutdown.cancel();
}

#[tokio::test]
async fn same_serial_re_add_cancels_only_matching_session() {
    let first = session_with_id_topology(1, "AB", Some("1234:5678"), Some("/dev/sdb1"));
    let second = session_with_id_topology(2, "AB", Some("9999:0001"), Some("/dev/sdc1"));
    let (event_tx, mut action_rx, _r, shutdown, _dir) = setup_with_sessions(vec![first, second]);

    // Sparse hub removal cannot disambiguate the two same-serial devices, so
    // fail closed by arming an independent timer for each session.
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Remove,
            devnode: None,
            serial: Some("AB".into()),
            vid_pid: None,
            is_usb: true,
        }))
        .expect("send remove");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Only the first device returns. Its timer is cancelled; the second
    // device's timer must remain armed despite the cloned/shared serial.
    event_tx
        .send(Event::Udev(UdevEvent {
            action: UdevAction::Add,
            devnode: Some("/dev/sdb1".into()),
            serial: Some("AB".into()),
            vid_pid: Some((0x1234, 0x5678)),
            is_usb: true,
        }))
        .expect("send add");

    let req = tokio::time::timeout(Duration::from_secs(3), action_rx.recv())
        .await
        .expect("second session action timeout")
        .expect("second session action");
    match req {
        ActionRequest::HandleUsbRemoved { session, .. } => {
            assert_eq!(session.session_id, Uuid::from_u128(2));
        }
        other => panic!("expected removal action, got {other:?}"),
    }
    assert!(
        action_rx.try_recv().is_err(),
        "matching session must remain cancelled"
    );
    shutdown.cancel();
}

#[tokio::test]
async fn five_simultaneous_removes_produce_one_action() {
    let (event_tx, mut action_rx, _r, shutdown, _dir) = setup();
    for _ in 0..5 {
        event_tx
            .send(Event::Udev(UdevEvent {
                action: UdevAction::Remove,
                devnode: None,
                serial: Some("AB".into()),
                vid_pid: None,
                is_usb: true,
            }))
            .expect("send");
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut count = 0;
    while action_rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(count, 1, "hub-disconnect dedup expected, got {count}");
    shutdown.cancel();
}

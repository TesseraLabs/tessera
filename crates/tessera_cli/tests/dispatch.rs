#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Action-runner dispatch tests using the `RecordingActions` stub.

use std::sync::Arc;
use std::time::SystemTime;

use tessera_cli::actions::spawn_action_runner;
use tessera_cli::logind::LogindActionsTrait;
use tessera_cli::registry::ActiveSession;
use tessera_cli::state::{ActionRequest, OnUsbRemoved};
use tessera_cli::testing::RecordingActions;
use tessera_proto::SessionTarget;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn sample_logind_session(id: &str) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(1),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind(id),
        usb_serial: Some("AB".into()),
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
    }
}

#[tokio::test]
async fn lock_dispatches_logind_lock() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleUsbRemoved {
        session: sample_logind_session("c1"),
        action: OnUsbRemoved::Lock,
    })
    .expect("send");
    // Allow the action runner to process.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(calls.last().map(String::as_str), Some("LockSession(c1)"));
    shutdown.cancel();
}

#[tokio::test]
async fn logout_dispatches_logind_terminate() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleUsbRemoved {
        session: sample_logind_session("c2"),
        action: OnUsbRemoved::Logout,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(
        calls.last().map(String::as_str),
        Some("TerminateSession(c2)")
    );
    shutdown.cancel();
}

#[tokio::test]
async fn shutdown_calls_poweroff() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleUsbRemoved {
        session: sample_logind_session("c3"),
        action: OnUsbRemoved::Shutdown,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert_eq!(calls.last().map(String::as_str), Some("PowerOff"));
    shutdown.cancel();
}

#[tokio::test]
async fn missing_logind_id_yields_no_call_for_lock() {
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    let mut s = sample_logind_session("c4");
    s.target = SessionTarget::tty("/dev/tty1");
    tx.send(ActionRequest::HandleUsbRemoved {
        session: s,
        action: OnUsbRemoved::Lock,
    })
    .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let calls = recorder.calls.lock();
    assert!(calls.is_empty(), "no call expected, got {:?}", *calls);
    shutdown.cancel();
}

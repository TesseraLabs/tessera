#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! End-to-end IPC test for `UpdateSessionTarget`.
//!
//! Reproduces the 0.3.10 production bug fix: a session registered with a
//! `Tty` target at PAM auth time, later upgraded by `pam_sm_open_session`
//! to a `LogindSession` via `UpdateSessionTarget`, must now have a target
//! that the action-runner can dispatch `Logout` against.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tessera_cli::actions::spawn_action_runner;
use tessera_cli::logind::LogindActionsTrait;
use tessera_cli::registry::{ActiveSession, RegistryStore, SessionRegistry};
use tessera_cli::state::{ActionRequest, OnUsbRemoved};
use tessera_cli::testing::{spawn_test_server_with, RecordingActions};
use tessera_cli::udev_query::AlwaysPresent;
use tessera_core::ipc::client::MonitordClient;
use tessera_proto::SessionTarget;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn seed_session(uuid: Uuid) -> ActiveSession {
    ActiveSession {
        session_id: uuid,
        pam_user: "u".into(),
        pam_service: "login".into(),
        target: SessionTarget::tty("/dev/tty1"),
        usb_serial: Some("AB12CD".into()),
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 1000,
        session_expiry: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn update_session_target_swaps_tty_for_logind_and_dispatch_terminates() {
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("monitor.sock");
    let store_path = dir.path().join("s.json");

    // Pre-seed the registry with a Tty target (mirrors what
    // pam_sm_authenticate would have inserted at auth time before
    // pam_systemd had a chance to mint XDG_SESSION_ID).
    let uuid = Uuid::from_u128(0xDEAD_BEEF);
    let registry = SessionRegistry::from_snapshot(vec![seed_session(uuid)]);
    let store = RegistryStore::new(store_path);

    // Use a cloned handle so the test can re-inspect the registry below.
    let registry_for_server = registry.clone();
    let server = spawn_test_server_with(
        sock.clone(),
        registry_for_server,
        store,
        Arc::new(AlwaysPresent),
        OnUsbRemoved::Logout,
    )
    .await
    .expect("spawn");

    // Drive the IPC client on a blocking thread (sync API).
    let sock2 = sock.clone();
    let res = tokio::task::spawn_blocking(move || {
        let mut c = MonitordClient::connect(&sock2, Duration::from_secs(2)).expect("connect");
        c.send_update_session_target(uuid, SessionTarget::logind("c7"))
    })
    .await
    .expect("join");
    assert!(
        res.is_ok(),
        "expected SessionTargetUpdated ack, got {res:?}"
    );

    // The registry handle is shared via Arc inside SessionRegistry, so
    // the update must be visible on the original clone.
    let entry = registry
        .find_by_session_id(uuid)
        .expect("registry entry preserved");
    assert_eq!(entry.target, SessionTarget::logind("c7"));

    // Now wire a recording action runner directly and dispatch Logout
    // against the upgraded session — this is what the udev grace timer
    // would do in production.
    let recorder = Arc::new(RecordingActions::default());
    let actions: Arc<dyn LogindActionsTrait> = recorder.clone();
    let shutdown = CancellationToken::new();
    let (tx, rx) = mpsc::unbounded_channel();
    let _h = spawn_action_runner(rx, actions, shutdown.clone());
    tx.send(ActionRequest::HandleUsbRemoved {
        session: entry,
        action: OnUsbRemoved::Logout,
    })
    .expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let last_call = recorder.calls.lock().last().cloned();
    assert_eq!(
        last_call.as_deref(),
        Some("TerminateSession(c7)"),
        "expected logind terminate for c7, got {last_call:?}",
    );
    shutdown.cancel();

    server.shutdown_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn update_session_target_unknown_id_returns_bad_request() {
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("monitor.sock");
    let registry = SessionRegistry::new();
    let store = RegistryStore::new(dir.path().join("s.json"));
    let server = spawn_test_server_with(
        sock.clone(),
        registry,
        store,
        Arc::new(AlwaysPresent),
        OnUsbRemoved::Lock,
    )
    .await
    .expect("spawn");

    let sock2 = sock.clone();
    let res = tokio::task::spawn_blocking(move || {
        let mut c = MonitordClient::connect(&sock2, Duration::from_secs(2)).expect("connect");
        c.send_update_session_target(Uuid::from_u128(99), SessionTarget::logind("nope"))
    })
    .await
    .expect("join");
    let err = res.expect_err("expected BAD_REQUEST");
    match err {
        tessera_core::error::IpcError::Server { code, .. } => {
            assert_eq!(code, tessera_proto::error_codes::BAD_REQUEST);
        }
        other => panic!("expected Server BAD_REQUEST, got {other:?}"),
    }
    server.shutdown_and_join().await;
}

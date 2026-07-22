#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Server handler tests through the in-process testing harness.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tessera_cli::registry::{RegistryStore, SessionRegistry};
use tessera_cli::state::OnUsbRemoved;
use tessera_cli::testing::spawn_test_server_with;
use tessera_cli::udev_query::{AlwaysAbsent, AlwaysPresent};
use tessera_core::ipc::client::MonitordClient;
use tessera_proto::{SessionOpenPayload, SessionTarget};
use uuid::Uuid;

fn sample(usb: Option<&str>) -> SessionOpenPayload {
    SessionOpenPayload {
        session_id: Uuid::from_u128(1),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: usb.map(str::to_string),
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
        role: None,
        role_version: None,
        session_expiry: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn session_open_returns_ack_when_device_present() {
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
        c.send_session_open(&sample(Some("AB")))
    })
    .await
    .expect("join");
    assert!(res.is_ok(), "got {res:?}");
    server.shutdown_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_open_returns_device_gone_when_absent() {
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("monitor.sock");
    let registry = SessionRegistry::new();
    let store = RegistryStore::new(dir.path().join("s.json"));
    let server = spawn_test_server_with(
        sock.clone(),
        registry,
        store,
        Arc::new(AlwaysAbsent),
        OnUsbRemoved::Lock,
    )
    .await
    .expect("spawn");
    let sock2 = sock.clone();
    let res = tokio::task::spawn_blocking(move || {
        let mut c = MonitordClient::connect(&sock2, Duration::from_secs(2)).expect("connect");
        c.send_session_open(&sample(Some("AB")))
    })
    .await
    .expect("join");
    let err = res.expect_err("expected device_gone");
    assert!(
        matches!(err, tessera_core::error::IpcError::DeviceGone),
        "got {err:?}"
    );
    server.shutdown_and_join().await;
}

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use std::time::{Duration, SystemTime};

use tessera_cli::registry::{RegistryStore, SessionRegistry};
use tessera_cli::testing::spawn_test_server;
use tessera_core::ipc::client::MonitordClient;
use tessera_proto::{SessionOpenPayload, SessionTarget};
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
async fn full_session_lifecycle_via_real_socket() {
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("monitor.sock");
    let registry = SessionRegistry::new();
    let store = RegistryStore::new(dir.path().join("sessions.json"));
    let server = spawn_test_server(sock.clone(), registry.clone(), store.clone())
        .await
        .expect("spawn server");
    let sock2 = sock.clone();
    let session_id = Uuid::from_u128(42);
    let payload = SessionOpenPayload {
        session_id,
        pam_user: "alice".into(),
        pam_service: "sshd".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: Some("AB".into()),
        host_id_hash: "host".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "Alice".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
    };
    // Drive a sync client from a worker thread.
    let payload_for_thread = payload.clone();
    let join = tokio::task::spawn_blocking(move || {
        let mut c = MonitordClient::connect(&sock2, Duration::from_secs(2)).expect("connect");
        c.ping().expect("ping");
        c.send_session_open(&payload_for_thread).expect("open");
        c.send_session_close(payload_for_thread.session_id, SystemTime::now())
            .expect("close");
    });
    join.await.expect("client thread");
    // Yield to let the state manager finish persistence.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let loaded = store.load().expect("load");
    assert!(
        loaded.iter().all(|s| s.session_id != session_id),
        "session should be removed after close"
    );
    server.shutdown_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_works_in_isolation() {
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("monitor.sock");
    let registry = SessionRegistry::new();
    let store = RegistryStore::new(dir.path().join("sessions.json"));
    let server = spawn_test_server(sock.clone(), registry.clone(), store.clone())
        .await
        .expect("spawn");
    let sock2 = sock.clone();
    let join = tokio::task::spawn_blocking(move || {
        let mut c = MonitordClient::connect(&sock2, Duration::from_secs(2)).expect("connect");
        c.ping().expect("ping");
    });
    join.await.expect("client");
    server.shutdown_and_join().await;
}

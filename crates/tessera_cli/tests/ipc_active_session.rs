//! Integration tests for the `GetActiveSessionByUid` IPC round-trip.
//!
//! Drives the in-process test server (see `testing::spawn_test_server`),
//! pre-seeds the registry with a session for uid=1000, and verifies that
//! a sync client gets:
//! * `ActiveSession` for a known uid (with correct `engineer_ski`)
//! * `Error { code: NO_ACTIVE_SESSION }` for an unknown uid

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime};

use tessera_cli::registry::{ActiveSession, RegistryStore, SessionRegistry};
use tessera_cli::testing::spawn_test_server;
use tessera_proto::{
    decode_line, encode_message, error_codes, ClientMessage, ServerMessage, SessionTarget,
    PROTOCOL_VERSION,
};
use uuid::Uuid;

/// Open a connection, perform the Hello handshake, return the stream.
fn connect_handshake(path: &std::path::Path) -> (UnixStream, BufReader<UnixStream>) {
    let stream = UnixStream::connect(path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("rd-timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("wr-timeout");
    let mut writer = stream.try_clone().expect("clone");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let hello = encode_message(&ClientMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
        agent: Some("test/0".into()),
    })
    .expect("encode hello");
    writer.write_all(&hello).expect("write hello");
    let mut line = String::new();
    reader.read_line(&mut line).expect("read ack");
    let ack: ServerMessage = decode_line(&line).expect("decode ack");
    assert!(
        matches!(ack, ServerMessage::HelloAck { .. }),
        "ack: {ack:?}"
    );
    (writer, reader)
}

fn seeded_session(uid: u32, ski: &str) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(0x42),
        pam_user: "alice".into(),
        pam_service: "sshd".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: Some("AB".into()),
        host_id_hash: "host".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "Alice".into(),
        cert_serial: "01".into(),
        engineer_ski: ski.into(),
        engineer_cert_sha256: "1234".into(),
        uid,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_active_session_by_uid_returns_active_session_for_known_uid() {
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("monitor.sock");
    let registry = SessionRegistry::new();
    registry.add(seeded_session(1000, "abcd"));
    let store = RegistryStore::new(dir.path().join("sessions.json"));
    let server = spawn_test_server(sock.clone(), registry.clone(), store)
        .await
        .expect("spawn");
    let sock2 = sock.clone();
    let reply = tokio::task::spawn_blocking(move || {
        let (mut w, mut r) = connect_handshake(&sock2);
        let req =
            encode_message(&ClientMessage::GetActiveSessionByUid { uid: 1000 }).expect("encode");
        w.write_all(&req).expect("write");
        let mut line = String::new();
        r.read_line(&mut line).expect("read");
        let msg: ServerMessage = decode_line(&line).expect("decode");
        msg
    })
    .await
    .expect("client");
    match reply {
        ServerMessage::ActiveSession {
            session_id,
            engineer_ski,
            cert_cn,
            ..
        } => {
            assert_eq!(engineer_ski, "abcd");
            assert_eq!(cert_cn, "Alice");
            assert!(!session_id.is_empty());
        }
        other => panic!("expected ActiveSession, got {other:?}"),
    }
    server.shutdown_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn get_active_session_by_uid_returns_1200_for_unknown_uid() {
    let dir = tempfile::tempdir().expect("tmp");
    let sock = dir.path().join("monitor.sock");
    let registry = SessionRegistry::new();
    registry.add(seeded_session(1000, "abcd"));
    let store = RegistryStore::new(dir.path().join("sessions.json"));
    let server = spawn_test_server(sock.clone(), registry.clone(), store)
        .await
        .expect("spawn");
    let sock2 = sock.clone();
    let reply = tokio::task::spawn_blocking(move || {
        let (mut w, mut r) = connect_handshake(&sock2);
        let req =
            encode_message(&ClientMessage::GetActiveSessionByUid { uid: 999 }).expect("encode");
        w.write_all(&req).expect("write");
        let mut line = String::new();
        r.read_line(&mut line).expect("read");
        let msg: ServerMessage = decode_line(&line).expect("decode");
        msg
    })
    .await
    .expect("client");
    match reply {
        ServerMessage::Error { code, message } => {
            assert_eq!(code, error_codes::NO_ACTIVE_SESSION);
            assert!(
                message.contains("999"),
                "message should reference uid: {message}"
            );
        }
        other => panic!("expected Error 1200, got {other:?}"),
    }
    server.shutdown_and_join().await;
}

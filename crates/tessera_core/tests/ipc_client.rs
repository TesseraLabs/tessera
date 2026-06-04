#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Sync `MonitordClient` round-trip tests against an in-process mock server.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime};

use tessera_core::error::IpcError;
use tessera_core::ipc::client::MonitordClient;
use tessera_proto::wire::encode_message;
use tessera_proto::{
    error_codes, ClientMessage, ServerMessage, SessionOpenPayload, SessionTarget, PROTOCOL_VERSION,
};
use uuid::Uuid;

fn spawn_mock<F>(handler: F) -> (std::path::PathBuf, mpsc::Receiver<()>)
where
    F: FnOnce(BufReader<std::os::unix::net::UnixStream>, std::os::unix::net::UnixStream)
        + Send
        + 'static,
{
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("monitor.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let (tx, rx) = mpsc::channel();
    let path_clone = path.clone();
    thread::spawn(move || {
        // Keep dir alive for the test.
        let _dir = dir;
        let (stream, _) = listener.accept().expect("accept");
        let read_clone = stream.try_clone().expect("clone");
        let br = BufReader::new(read_clone);
        handler(br, stream);
        let _ = tx.send(());
        let _ = path_clone;
    });
    (path, rx)
}

fn payload() -> SessionOpenPayload {
    SessionOpenPayload {
        session_id: Uuid::from_u128(1),
        pam_user: "alice".into(),
        pam_service: "sshd".into(),
        target: SessionTarget::logind("c1"),
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

#[test]
fn ping_roundtrip() {
    let (path, _done) = spawn_mock(|mut br, mut stream| {
        let mut line = String::new();
        br.read_line(&mut line).expect("read hello");
        let m: ClientMessage = serde_json::from_str(line.trim()).expect("parse");
        assert!(matches!(m, ClientMessage::Hello { .. }));
        stream
            .write_all(
                &encode_message(&ServerMessage::HelloAck {
                    server_version: "test".into(),
                    protocol_version: PROTOCOL_VERSION,
                })
                .expect("encode"),
            )
            .expect("write ack");
        let mut l2 = String::new();
        br.read_line(&mut l2).expect("read ping");
        let m2: ClientMessage = serde_json::from_str(l2.trim()).expect("parse");
        assert!(matches!(m2, ClientMessage::Ping));
        stream
            .write_all(&encode_message(&ServerMessage::Pong).expect("encode"))
            .expect("write pong");
    });
    let mut c = MonitordClient::connect(&path, Duration::from_secs(2)).expect("connect");
    c.ping().expect("ping");
}

#[test]
fn session_open_roundtrip() {
    let (path, _done) = spawn_mock(|mut br, mut stream| {
        let mut line = String::new();
        br.read_line(&mut line).expect("read hello");
        stream
            .write_all(
                &encode_message(&ServerMessage::HelloAck {
                    server_version: "test".into(),
                    protocol_version: PROTOCOL_VERSION,
                })
                .expect("encode"),
            )
            .expect("write");
        let mut l = String::new();
        br.read_line(&mut l).expect("read open");
        let m: ClientMessage = serde_json::from_str(l.trim()).expect("parse");
        assert!(matches!(m, ClientMessage::SessionOpen { .. }));
        stream
            .write_all(&encode_message(&ServerMessage::Ack).expect("encode"))
            .expect("write ack");
    });
    let mut c = MonitordClient::connect(&path, Duration::from_secs(2)).expect("connect");
    c.send_session_open(&payload()).expect("send");
}

#[test]
fn session_open_returns_device_gone() {
    let (path, _done) = spawn_mock(|mut br, mut stream| {
        let mut line = String::new();
        br.read_line(&mut line).expect("read hello");
        stream
            .write_all(
                &encode_message(&ServerMessage::HelloAck {
                    server_version: "test".into(),
                    protocol_version: PROTOCOL_VERSION,
                })
                .expect("encode"),
            )
            .expect("write");
        let mut l = String::new();
        br.read_line(&mut l).expect("read open");
        stream
            .write_all(
                &encode_message(&ServerMessage::Error {
                    code: error_codes::DEVICE_GONE,
                    message: "gone".into(),
                })
                .expect("encode"),
            )
            .expect("write");
    });
    let mut c = MonitordClient::connect(&path, Duration::from_secs(2)).expect("connect");
    let err = c.send_session_open(&payload()).expect_err("expected error");
    assert!(matches!(err, IpcError::DeviceGone), "got {err:?}");
}

#[test]
fn session_close_roundtrip() {
    let (path, _done) = spawn_mock(|mut br, mut stream| {
        let mut line = String::new();
        br.read_line(&mut line).expect("read hello");
        stream
            .write_all(
                &encode_message(&ServerMessage::HelloAck {
                    server_version: "test".into(),
                    protocol_version: PROTOCOL_VERSION,
                })
                .expect("encode"),
            )
            .expect("write");
        let mut l = String::new();
        br.read_line(&mut l).expect("read close");
        let m: ClientMessage = serde_json::from_str(l.trim()).expect("parse");
        assert!(matches!(m, ClientMessage::SessionClose { .. }));
        stream
            .write_all(&encode_message(&ServerMessage::Ack).expect("encode"))
            .expect("write ack");
    });
    let mut c = MonitordClient::connect(&path, Duration::from_secs(2)).expect("connect");
    c.send_session_close(Uuid::from_u128(1), SystemTime::UNIX_EPOCH)
        .expect("close");
}

#[test]
fn protocol_mismatch_is_typed() {
    let (path, _done) = spawn_mock(|mut br, mut stream| {
        let mut line = String::new();
        br.read_line(&mut line).expect("read");
        stream
            .write_all(
                &encode_message(&ServerMessage::HelloAck {
                    server_version: "test".into(),
                    protocol_version: 99,
                })
                .expect("encode"),
            )
            .expect("write");
    });
    let res = MonitordClient::connect(&path, Duration::from_secs(2));
    let err = match res {
        Ok(_) => panic!("expected ProtocolMismatch"),
        Err(e) => e,
    };
    assert!(matches!(err, IpcError::ProtocolMismatch { server: 99 }));
}

#[test]
fn connect_unavailable_socket() {
    let dir = tempfile::tempdir().expect("tmp");
    let nope = dir.path().join("does_not_exist.sock");
    let res = MonitordClient::connect(&nope, Duration::from_millis(500));
    let err = match res {
        Ok(_) => panic!("expected Unavailable"),
        Err(e) => e,
    };
    assert!(matches!(err, IpcError::Unavailable), "got {err:?}");
}

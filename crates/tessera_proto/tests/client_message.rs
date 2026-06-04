#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_proto::{ClientMessage, SessionTarget};
use std::time::{Duration, UNIX_EPOCH};
use uuid::Uuid;

fn sample_open() -> ClientMessage {
    ClientMessage::SessionOpen {
        session_id: Uuid::nil(),
        pam_user: "alice".into(),
        pam_service: "sshd".into(),
        target: SessionTarget::tty("/dev/pts/0"),
        usb_serial: Some("AB12CD".into()),
        host_id_hash: "deadbeef".into(),
        opened_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        cert_cn: "Alice".into(),
        cert_serial: "01:02:03".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
    }
}

#[test]
fn hello_serializes_with_protocol_version() {
    let msg = ClientMessage::Hello {
        protocol_version: 1,
        agent: None,
    };
    let s = serde_json::to_string(&msg).expect("encode");
    assert!(s.contains("\"hello\""), "json = {s}");
    assert!(s.contains("\"protocol_version\":1"), "json = {s}");
}

#[test]
fn session_open_roundtrip() {
    let msg = sample_open();
    let s = serde_json::to_string(&msg).expect("encode");
    let back: ClientMessage = serde_json::from_str(&s).expect("decode");
    assert_eq!(back, msg);
}

#[test]
fn session_close_roundtrip() {
    let msg = ClientMessage::SessionClose {
        session_id: Uuid::from_u128(42),
        closed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_500),
    };
    let s = serde_json::to_string(&msg).expect("encode");
    let back: ClientMessage = serde_json::from_str(&s).expect("decode");
    assert_eq!(back, msg);
}

#[test]
fn ping_serializes() {
    let s = serde_json::to_string(&ClientMessage::Ping).expect("encode");
    assert!(s.contains("\"ping\""), "json = {s}");
}

#[test]
fn update_session_target_roundtrip() {
    let msg = ClientMessage::UpdateSessionTarget {
        session_id: Uuid::from_u128(7),
        new_target: SessionTarget::logind("c42"),
    };
    let s = serde_json::to_string(&msg).expect("encode");
    assert!(s.contains("\"update_session_target\""), "json = {s}");
    assert!(s.contains("\"logind_session\""), "json = {s}");
    let back: ClientMessage = serde_json::from_str(&s).expect("decode");
    assert_eq!(back, msg);
}

#[test]
fn rejects_negative_unix_seconds() {
    let json = r#"{"type":"session_close","session_id":"00000000-0000-0000-0000-000000000000","closed_at":-1}"#;
    let err = serde_json::from_str::<ClientMessage>(json).unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("negative"));
}

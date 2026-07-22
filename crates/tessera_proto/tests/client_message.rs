#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use std::time::{Duration, UNIX_EPOCH};
use tessera_proto::{ClientMessage, SessionTarget};
use uuid::Uuid;

fn sample_open() -> ClientMessage {
    ClientMessage::SessionOpen {
        session_id: Uuid::nil(),
        pam_user: "alice".into(),
        pam_service: "sshd".into(),
        target: SessionTarget::tty("/dev/pts/0"),
        usb_serial: Some("AB12CD".into()),
        usb_vid_pid: Some("1234:5678".into()),
        usb_devnode: Some("/dev/sdb1".into()),
        host_id_hash: "deadbeef".into(),
        opened_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        cert_cn: "Alice".into(),
        cert_serial: "01:02:03".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
        role: Some("serv".into()),
        role_version: Some(7),
        session_expiry: Some(UNIX_EPOCH + Duration::from_secs(1_700_003_600)),
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
fn session_open_with_role_serializes_and_roundtrips() {
    // 5.2: role="serv", role_version=7 are carried on the wire and survive a
    // serialize/deserialize roundtrip.
    let msg = sample_open();
    let s = serde_json::to_string(&msg).expect("encode");
    assert!(s.contains("\"role\":\"serv\""), "json = {s}");
    assert!(s.contains("\"role_version\":7"), "json = {s}");
    let back: ClientMessage = serde_json::from_str(&s).expect("decode");
    assert_eq!(back, msg);
}

#[test]
fn session_open_without_role_omits_fields_and_defaults_to_none() {
    // 5.2: a session opened with no role (enforce=false) omits role /
    // role_version entirely; the frame stays valid and decodes back to None.
    let mut msg = sample_open();
    if let ClientMessage::SessionOpen {
        role, role_version, ..
    } = &mut msg
    {
        *role = None;
        *role_version = None;
    }
    let s = serde_json::to_string(&msg).expect("encode");
    assert!(!s.contains("\"role\""), "role must be absent: {s}");
    assert!(
        !s.contains("\"role_version\""),
        "role_version must be absent: {s}"
    );
    let back: ClientMessage = serde_json::from_str(&s).expect("decode");
    assert_eq!(back, msg);

    // A frame that never mentions the fields still parses (backward compat).
    let legacy = r#"{
      "type":"session_open",
      "session_id":"00000000-0000-0000-0000-000000000000",
      "pam_user":"alice",
      "pam_service":"sshd",
      "target":{"kind":"tty","path":"/dev/pts/0"},
      "host_id_hash":"deadbeef",
      "opened_at":1700000000,
      "cert_cn":"Alice",
      "cert_serial":"01"
    }"#;
    let parsed: ClientMessage = serde_json::from_str(legacy).expect("legacy frame parses");
    match parsed {
        ClientMessage::SessionOpen {
            role, role_version, ..
        } => {
            assert_eq!(role, None);
            assert_eq!(role_version, None);
        }
        other => panic!("expected SessionOpen, got {other:?}"),
    }
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

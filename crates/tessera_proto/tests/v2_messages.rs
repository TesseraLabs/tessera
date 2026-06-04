//! Smoke-tests for the v2 wire-protocol surface.
//!
//! Three flavours of coverage:
//! 1. `GetActiveSessionByUid` round-trips through serde and tags itself as
//!    `"type":"get_active_session_by_uid"` on the wire.
//! 2. `ServerMessage::ActiveSession` includes the `engineer_ski` field so
//!    consumers know v2 carries cert metadata in the reply.
//! 3. A legacy v1 `SessionOpen` frame (no `engineer_ski` / `uid`)
//!    still deserialises — guarantees backwards-compatible upgrade paths.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use tessera_proto::{ClientMessage, ServerMessage};

#[test]
fn get_active_session_by_uid_roundtrip() {
    let m = ClientMessage::GetActiveSessionByUid { uid: 1000 };
    let j = serde_json::to_string(&m).expect("encode");
    assert!(
        j.contains("\"type\":\"get_active_session_by_uid\""),
        "wire tag should be snake_case: {j}"
    );
    let back: ClientMessage = serde_json::from_str(&j).expect("decode");
    assert!(matches!(
        back,
        ClientMessage::GetActiveSessionByUid { uid: 1000 }
    ));
}

#[test]
fn active_session_serialises_with_engineer_ski() {
    let m = ServerMessage::ActiveSession {
        session_id: "id".into(),
        cert_cn: "Alice".into(),
        engineer_ski: "abcd".into(),
        engineer_cert_sha256: "1234".into(),
        host_id_hash: "h".into(),
    };
    let j = serde_json::to_string(&m).expect("encode");
    assert!(j.contains("engineer_ski"), "engineer_ski present: {j}");
    assert!(j.contains("\"type\":\"active_session\""), "tag: {j}");
}

#[test]
fn session_open_v1_payload_still_parses() {
    // A frame produced by a v1 PAM module — no engineer_ski, no uid.
    // The session_id below is a valid UUID; the v2 decoder must accept this
    // frame and default the missing fields.
    let j = r#"{
      "type":"session_open",
      "session_id":"00000000-0000-0000-0000-00000000002a",
      "pam_user":"alice",
      "pam_service":"sudo",
      "target":{"kind":"logind_session","id":"12"},
      "usb_serial":"R1",
      "host_id_hash":"ee0b",
      "opened_at":1735689600,
      "cert_cn":"Alice",
      "cert_serial":"01"
    }"#;
    let parsed: ClientMessage =
        serde_json::from_str(j).expect("v1 session_open should still parse");
    match parsed {
        ClientMessage::SessionOpen {
            engineer_ski,
            engineer_cert_sha256,
            uid,
            ..
        } => {
            assert!(engineer_ski.is_empty());
            assert!(engineer_cert_sha256.is_empty());
            assert_eq!(uid, 0);
        }
        other => panic!("expected SessionOpen, got {other:?}"),
    }
}

#[test]
fn no_active_session_error_code_is_1200() {
    assert_eq!(tessera_proto::error_codes::NO_ACTIVE_SESSION, 1200);
}

#[test]
fn protocol_version_is_two() {
    assert_eq!(tessera_proto::PROTOCOL_VERSION, 2);
}

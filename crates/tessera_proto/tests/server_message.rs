#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_proto::{error_codes, ServerMessage};

#[test]
fn hello_ack_roundtrip() {
    let m = ServerMessage::HelloAck {
        server_version: "0.6.0".into(),
        protocol_version: 1,
    };
    let s = serde_json::to_string(&m).expect("encode");
    let back: ServerMessage = serde_json::from_str(&s).expect("decode");
    assert!(matches!(
        back,
        ServerMessage::HelloAck {
            protocol_version: 1,
            ..
        }
    ));
}

#[test]
fn ack_serializes() {
    let s = serde_json::to_string(&ServerMessage::Ack).expect("encode");
    assert!(s.contains("\"ack\""), "json = {s}");
}

#[test]
fn pong_serializes() {
    let s = serde_json::to_string(&ServerMessage::Pong).expect("encode");
    assert!(s.contains("\"pong\""), "json = {s}");
}

#[test]
fn error_roundtrip() {
    let m = ServerMessage::Error {
        code: error_codes::DEVICE_GONE,
        message: "device gone".into(),
    };
    let s = serde_json::to_string(&m).expect("encode");
    let back: ServerMessage = serde_json::from_str(&s).expect("decode");
    if let ServerMessage::Error { code, message } = back {
        assert_eq!(code, error_codes::DEVICE_GONE);
        assert_eq!(message, "device gone");
    } else {
        panic!("variant mismatch");
    }
}

#[test]
fn session_target_updated_roundtrip() {
    let m = ServerMessage::SessionTargetUpdated {
        session_id: "abc".into(),
    };
    let s = serde_json::to_string(&m).expect("encode");
    assert!(s.contains("\"session_target_updated\""), "json = {s}");
    let back: ServerMessage = serde_json::from_str(&s).expect("decode");
    if let ServerMessage::SessionTargetUpdated { session_id } = back {
        assert_eq!(session_id, "abc");
    } else {
        panic!("variant mismatch");
    }
}

#[test]
fn error_codes_are_stable() {
    assert_eq!(error_codes::PROTOCOL_MISMATCH, 1000);
    assert_eq!(error_codes::DEVICE_GONE, 1001);
    assert_eq!(error_codes::UNAUTHORIZED, 1003);
}

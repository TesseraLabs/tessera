#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_proto::wire::{decode_line, encode_message, MAX_FRAME_BYTES};
use tessera_proto::{ClientMessage, ServerMessage};

#[test]
fn encode_appends_newline_and_no_inner_newline() {
    let msg = ClientMessage::Ping;
    let bytes = encode_message(&msg).expect("encode");
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
}

#[test]
fn roundtrip_client_ping() {
    let msg = ClientMessage::Ping;
    let bytes = encode_message(&msg).expect("encode");
    let line = std::str::from_utf8(&bytes[..bytes.len() - 1]).expect("utf8");
    let parsed: ClientMessage = decode_line(line).expect("decode");
    assert!(matches!(parsed, ClientMessage::Ping));
}

#[test]
fn roundtrip_server_pong() {
    let msg = ServerMessage::Pong;
    let bytes = encode_message(&msg).expect("encode");
    let line = std::str::from_utf8(&bytes[..bytes.len() - 1]).expect("utf8");
    let parsed: ServerMessage = decode_line(line).expect("decode");
    assert!(matches!(parsed, ServerMessage::Pong));
}

#[test]
fn rejects_too_large_frame() {
    let huge = "x".repeat(MAX_FRAME_BYTES + 1);
    let err = decode_line::<ClientMessage>(&huge).unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("frame too large"), "msg = {s}");
}

#[test]
fn rejects_malformed_json() {
    let err = decode_line::<ClientMessage>("{not-json").unwrap_err();
    let s = format!("{err}").to_lowercase();
    assert!(s.contains("decode"), "msg = {s}");
}

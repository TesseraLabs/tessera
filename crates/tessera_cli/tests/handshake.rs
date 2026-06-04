#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]

use tessera_cli::server::perform_handshake;
use tessera_proto::wire::encode_message;
use tessera_proto::{ClientMessage, ServerMessage, PROTOCOL_VERSION};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[tokio::test]
async fn handshake_accepts_matching_version() {
    let (mut a, b) = UnixStream::pair().expect("pair");
    let server = tokio::spawn(async move { perform_handshake(b).await });
    a.write_all(
        &encode_message(&ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            agent: Some("test".into()),
        })
        .expect("encode"),
    )
    .await
    .expect("write");
    let mut br = BufReader::new(a);
    let mut line = String::new();
    br.read_line(&mut line).await.expect("read");
    let resp: ServerMessage = serde_json::from_str(line.trim()).expect("parse");
    assert!(matches!(
        resp,
        ServerMessage::HelloAck {
            protocol_version: v,
            ..
        } if v == PROTOCOL_VERSION
    ));
    server.await.expect("join").expect("ok");
}

#[tokio::test]
async fn handshake_rejects_mismatched_version() {
    let (mut a, b) = UnixStream::pair().expect("pair");
    let server = tokio::spawn(async move { perform_handshake(b).await });
    a.write_all(
        &encode_message(&ClientMessage::Hello {
            protocol_version: 999,
            agent: None,
        })
        .expect("encode"),
    )
    .await
    .expect("write");
    let mut br = BufReader::new(a);
    let mut line = String::new();
    br.read_line(&mut line).await.expect("read");
    let resp: ServerMessage = serde_json::from_str(line.trim()).expect("parse");
    assert!(matches!(
        resp,
        ServerMessage::Error { code, .. } if code == tessera_proto::error_codes::PROTOCOL_MISMATCH
    ));
    assert!(server.await.expect("join").is_err());
}

#[tokio::test]
async fn handshake_rejects_non_hello_first() {
    let (mut a, b) = UnixStream::pair().expect("pair");
    let server = tokio::spawn(async move { perform_handshake(b).await });
    a.write_all(&encode_message(&ClientMessage::Ping).expect("encode"))
        .await
        .expect("write");
    let _ = a.shutdown().await;
    let res = server.await.expect("join");
    assert!(res.is_err());
}

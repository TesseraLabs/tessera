//! Regression tests for P1-F (IPC hardening) and P1-G (TOCTOU-free bind).
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic,
    clippy::let_underscore_must_use
)]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use tessera_cli::server::{self, AcceptConfig};
use tessera_proto::wire::encode_message;
use tessera_proto::{
    error_codes, ClientMessage, ServerMessage, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Helper: spawn an in-process server using a temp socket, return the
/// socket path + a cancellation token. Peer-cred enforcement is
/// disabled because the test process is unprivileged.
async fn spawn(cfg: AcceptConfig) -> (TempDir, std::path::PathBuf, CancellationToken) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("m.sock");
    let listener = server::bind_listener(&socket).await.unwrap();
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    // Drain events so the server can deliver Pong replies (the state
    // manager would normally do this).
    tokio::spawn(async move {
        while let Some(ev) = event_rx.recv().await {
            if let tessera_cli::state::Event::Ipc(
                tessera_cli::state::IpcRequest::Ping { reply },
            ) = ev
            {
                let _ = reply.send(ServerMessage::Pong);
            }
        }
    });
    let token = CancellationToken::new();
    let token_for_loop = token.clone();
    tokio::spawn(async move {
        server::run_accept_loop_with(listener, event_tx, token_for_loop, cfg).await;
    });
    (dir, socket, token)
}

async fn handshake(stream: &mut UnixStream) {
    stream
        .write_all(
            &encode_message(&ClientMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                agent: Some("test".into()),
            })
            .unwrap(),
        )
        .await
        .unwrap();
    let mut br = BufReader::new(&mut *stream);
    let mut line = String::new();
    br.read_line(&mut line).await.unwrap();
    let resp: ServerMessage = serde_json::from_str(line.trim()).unwrap();
    assert!(matches!(resp, ServerMessage::HelloAck { .. }));
}

#[tokio::test]
async fn bind_listener_publishes_socket_with_mode_660() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("m.sock");
    let _listener = server::bind_listener(&socket).await.unwrap();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
    // S_IFMT covers the file type bits; mask them off.
    assert_eq!(mode & 0o777, 0o660, "socket mode = {mode:o}");
    // Tmp publish path must NOT linger.
    let tmp_glob = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .count();
    assert_eq!(tmp_glob, 0, "leftover .tmp.<pid> socket present");
}

#[tokio::test]
async fn oversize_frame_is_rejected_with_protocol_violation() {
    let cfg = AcceptConfig {
        enforce_peercred: false,
        idle_timeout: Duration::from_secs(30),
        max_concurrent_connections: 8,
    };
    let (_dir, socket, _tok) = spawn(cfg).await;
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    handshake(&mut stream).await;

    // Build an oversize "frame": MAX_FRAME_BYTES + 256 of 'x' followed
    // by a newline. The server caps allocation at MAX_FRAME_BYTES and
    // emits PROTOCOL_VIOLATION before reading the rest.
    let mut payload = vec![b'x'; MAX_FRAME_BYTES + 256];
    payload.push(b'\n');
    // Best-effort write; the server may close mid-write.
    let _ = stream.write_all(&payload).await;

    let (mut read, _w) = stream.into_split();
    let mut br = BufReader::new(&mut read);
    let mut line = String::new();
    let n = br.read_line(&mut line).await.unwrap();
    assert!(n > 0, "expected error response, got EOF");
    let resp: ServerMessage = serde_json::from_str(line.trim()).unwrap();
    assert!(
        matches!(resp, ServerMessage::Error { code, .. } if code == error_codes::PROTOCOL_VIOLATION),
        "unexpected reply: {resp:?}"
    );
}

#[tokio::test]
async fn idle_timeout_closes_silent_connection_with_protocol_violation() {
    let cfg = AcceptConfig {
        enforce_peercred: false,
        idle_timeout: Duration::from_millis(150),
        max_concurrent_connections: 8,
    };
    let (_dir, socket, _tok) = spawn(cfg).await;
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    handshake(&mut stream).await;
    // Send NOTHING after handshake. The server should close after the
    // configured idle window with a PROTOCOL_VIOLATION.
    let (mut read, _w) = stream.into_split();
    let mut br = BufReader::new(&mut read);
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(2), br.read_line(&mut line))
        .await
        .expect("server did not close within idle budget")
        .unwrap();
    assert!(n > 0);
    let resp: ServerMessage = serde_json::from_str(line.trim()).unwrap();
    assert!(
        matches!(resp, ServerMessage::Error { code, .. } if code == error_codes::PROTOCOL_VIOLATION),
        "unexpected reply: {resp:?}"
    );
}

#[tokio::test]
async fn semaphore_caps_concurrent_connections() {
    // Cap = 2, open 3 connections. The third must wait until one of
    // the first two closes before it gets handshake confirmation.
    let cfg = AcceptConfig {
        enforce_peercred: false,
        idle_timeout: Duration::from_secs(5),
        max_concurrent_connections: 2,
    };
    let (_dir, socket, _tok) = spawn(cfg).await;

    // Open and KEEP OPEN two connections.
    let mut s1 = UnixStream::connect(&socket).await.unwrap();
    handshake(&mut s1).await;
    let mut s2 = UnixStream::connect(&socket).await.unwrap();
    handshake(&mut s2).await;

    // Third connection: connect succeeds (kernel-level), but the
    // server hasn't acquired a permit so the handshake reply will
    // not arrive until we drop one of the others.
    let s3 = UnixStream::connect(&socket).await.unwrap();
    let mut s3 = s3;
    let hs_third = tokio::spawn(async move {
        handshake(&mut s3).await;
        s3
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !hs_third.is_finished(),
        "third connection handshake completed despite semaphore cap"
    );

    // Drop one slot.
    drop(s1);

    // The third handshake should now complete promptly.
    let _ = tokio::time::timeout(Duration::from_secs(2), hs_third)
        .await
        .expect("third connection never got a permit after slot freed");

    // Cleanup.
    drop(s2);
}

#[test]
fn accept_config_from_monitor_uses_validated_values_and_keeps_peercred_on() {
    use tessera_core::config::validated::{MonitorFailMode, MonitorSection, OnUsbRemoved};

    let monitor = MonitorSection {
        socket_path: "/run/tessera/monitord.sock".into(),
        timeout: Duration::from_secs(2),
        fail_mode: MonitorFailMode::Strict,
        state_file_path: "/var/lib/tessera/sessions.json".into(),
        on_usb_removed: OnUsbRemoved::Lock,
        usb_removed_grace: Duration::from_secs(10),
        suspend_grace: Duration::from_secs(15),
        on_usb_removed_hook_path: None,
        idle_timeout: Duration::from_secs(7),
        max_concurrent_connections: 11,
    };

    let cfg = AcceptConfig::from_monitor(&monitor);
    assert_eq!(cfg.idle_timeout, Duration::from_secs(7));
    assert_eq!(cfg.max_concurrent_connections, 11);
    assert!(
        cfg.enforce_peercred,
        "peer-cred enforcement must stay on regardless of config"
    );
}

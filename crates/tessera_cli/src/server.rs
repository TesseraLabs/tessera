//! IPC server: accept loop, handshake, per-connection dispatch.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tessera_core::mac::audit as mac_audit;
use tessera_core::mac::backend::MacBackend;
use tessera_core::mac::IntegrityLabel;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use tessera_proto::{
    decode_line, encode_message, error_codes, ClientMessage, ServerMessage, MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
};

use crate::peercred::verify_peer_credentials;
use crate::registry::ActiveSession;
use crate::state::{Event, IpcRequest};

/// Top-level server errors. Mostly used in handshake; per-connection IO
/// errors are logged and dropped.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Handshake exceeded its 2 s budget.
    #[error("handshake timeout")]
    HandshakeTimeout,
    /// IO error during handshake.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Decode error during handshake.
    #[error("decode: {0}")]
    Decode(serde_json::Error),
    /// Wire-level encode error.
    #[error("encode: {0}")]
    Encode(tessera_proto::WireError),
    /// First message was not Hello.
    #[error("first message must be Hello")]
    HelloExpected,
    /// Peer/server protocol mismatch.
    #[error("protocol mismatch server={server} client={client}")]
    VersionMismatch {
        /// Server protocol version.
        server: u32,
        /// Client-reported protocol version.
        client: u32,
    },
    /// Peer-cred check failed.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}

/// Bind the listener at `path`, set permissions to `0660`.
///
/// TOCTOU-free: bind to a per-PID temp path, fix permissions, then
/// atomically `rename` it into place. The default umask would otherwise
/// briefly expose the socket with world-accessible permissions between
/// `bind` and `set_permissions`.
pub async fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(feature = "astra-mac")]
    let backend = tessera_mac_parsec::ParsecBackend::new();
    #[cfg(not(feature = "astra-mac"))]
    let backend = tessera_core::mac::backend::StubBackend::new();

    // Single labeled-bind code path: bind on per-PID temp, set 0660
    // perms, label via fd (TOCTOU-safe), then atomic rename into place.
    let std_listener = bind_with_label(path, &backend)?;
    std_listener.set_nonblocking(true)?;
    UnixListener::from_std(std_listener)
}

/// Bind a Unix-domain socket at `final_path` with МКЦ irelax label
/// applied atomically: bind on `.tmp.$PID`, set mode `0660`, label via
/// [`MacBackend::set_fd_label`] on the listener's fd (`level=0`,
/// `irelax=true`) — closes the bind/label TOCTOU window that a path-based
/// labeler would leave open — emit `mac_socket_label_set`, then rename
/// into place. Returns the standard-library listener so callers may
/// adopt it into any async runtime.
///
/// # Errors
/// Returns I/O error on bind/permissions/rename, or a wrapped `MacError`
/// when the label set fails.
pub fn bind_with_label<B: MacBackend>(
    final_path: &Path,
    backend: &B,
) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;

    let tmp_path = build_tmp_socket_path(final_path);
    // Safe: tmp_path embeds our PID, so any leftover here is from a
    // prior aborted run of THIS process — never from a concurrent
    // observer. We deliberately drop the `if path.exists()` race.
    let _ = std::fs::remove_file(&tmp_path);

    let listener = std::os::unix::net::UnixListener::bind(&tmp_path)?;
    // DAC: 0660 before publish so peers never observe a world-accessible
    // socket. Path is still per-PID temp, not yet renamed.
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o660))?;
    // MAC: label by fd to close the bind→label TOCTOU window that a
    // same-uid attacker could exploit by swapping the path for a symlink.
    let label = IntegrityLabel {
        level: 0,
        categories: 0,
    };
    // Best-effort labeling: on hosts without an active МКЦ kernel (containers,
    // dev boxes, non-Astra), `pdp_set_fd` returns rc=-1. We log a warning
    // and continue — DAC `0660` + parent-dir `iinh` carry the security
    // properties on those hosts; on real Astra strict mode the label sticks.
    match backend.set_fd_label(listener.as_raw_fd(), label, true) {
        Ok(()) => mac_audit::emit_socket_label(&tmp_path.to_string_lossy()),
        Err(e) => mac_audit::emit_sessions_file_warn(
            &tmp_path.to_string_lossy(),
            Some(&format!("set_fd_label on monitord.sock: {e}")),
        ),
    }
    // Atomic publish: from this instant on, peers connecting at
    // `final_path` see a socket that is already 0660 and labeled.
    std::fs::rename(&tmp_path, final_path)?;
    Ok(listener)
}

/// Build the temp path used by [`bind_listener`].
fn build_tmp_socket_path(path: &Path) -> PathBuf {
    let pid = std::process::id();
    let mut name = path
        .file_name()
        .map_or_else(|| std::ffi::OsString::from("monitord.sock"), Into::into);
    name.push(format!(".tmp.{pid}"));
    match path.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

/// Set socket permissions to `0660`.
pub fn set_socket_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
}

/// Configuration for the accept loop.
#[derive(Debug, Clone, Copy)]
pub struct AcceptConfig {
    /// When true the loop calls `verify_peer_credentials`. Tests pass `false`
    /// because they run unprivileged.
    pub enforce_peercred: bool,
    /// Per-connection idle-timeout: max silence between client messages
    /// before the server closes the connection.
    pub idle_timeout: Duration,
    /// Maximum number of concurrent client connections accepted.
    pub max_concurrent_connections: u32,
}

impl Default for AcceptConfig {
    fn default() -> Self {
        Self {
            enforce_peercred: true,
            idle_timeout: Duration::from_secs(30),
            max_concurrent_connections: 64,
        }
    }
}

/// Outcome of a bounded frame read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameOutcome {
    /// A complete frame (terminated by `\n`) was read into the buffer.
    Frame,
    /// Peer closed the connection without sending another frame.
    Eof,
    /// The frame would have exceeded the configured byte budget; the
    /// caller should report `PROTOCOL_VIOLATION` and close.
    Oversize,
}

/// Read one newline-terminated frame into `buf`, with a hard byte cap.
///
/// Reads byte-by-byte from `reader` until it sees `\n`, EOF, or `max`
/// bytes have been buffered. The terminating newline is included in
/// `buf` when present. `Oversize` is returned the moment we see a byte
/// past the cap so we never allocate beyond `max + 1`.
async fn read_frame_bounded<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> io::Result<FrameOutcome>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut byte = [0_u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(if buf.is_empty() {
                FrameOutcome::Eof
            } else {
                FrameOutcome::Frame
            });
        }
        let b = byte[0];
        if buf.len() >= max {
            // Exceeded — drop and signal violation. We don't consume
            // the rest of the offending frame; the caller will close.
            return Ok(FrameOutcome::Oversize);
        }
        buf.push(b);
        if b == b'\n' {
            return Ok(FrameOutcome::Frame);
        }
    }
}

/// Accept loop: every accepted stream is handed off to [`serve_connection`].
pub async fn run_accept_loop(
    listener: UnixListener,
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
) {
    run_accept_loop_with(listener, event_tx, shutdown, AcceptConfig::default()).await;
}

/// Variant that accepts an explicit [`AcceptConfig`].
pub async fn run_accept_loop_with(
    listener: UnixListener,
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
    cfg: AcceptConfig,
) {
    // Per-accept-loop semaphore caps live connections. We acquire the
    // permit BEFORE spawning the handler so a client storm does not
    // create unbounded tasks; the permit moves into the spawned task
    // and is released when the connection ends.
    let sem = Arc::new(Semaphore::new(cfg.max_concurrent_connections as usize));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        if cfg.enforce_peercred {
                            if let Err(e) = verify_peer_credentials(&stream) {
                                tracing::warn!(target: "tessera.monitord", error = %e, "peer rejected");
                                continue;
                            }
                        }
                        let permit = match sem.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                // Semaphore closed → loop is shutting down.
                                break;
                            }
                        };
                        let event_tx = event_tx.clone();
                        let idle_timeout = cfg.idle_timeout;
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = serve_connection_with(stream, event_tx, idle_timeout).await {
                                tracing::debug!(target: "tessera.monitord", error = %e, "connection ended");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(target: "tessera.monitord", error = %e, "accept failed");
                    }
                }
            }
        }
    }
}

/// Drive a single client connection: handshake, then loop reading frames
/// with [default settings](AcceptConfig::default).
pub async fn serve_connection(
    stream: UnixStream,
    event_tx: mpsc::UnboundedSender<Event>,
) -> Result<(), ServerError> {
    serve_connection_with(stream, event_tx, AcceptConfig::default().idle_timeout).await
}

/// Drive a single client connection with explicit hardening parameters.
///
/// Each frame is bounded to [`MAX_FRAME_BYTES`]: oversize input results
/// in a structured `PROTOCOL_VIOLATION` error and an immediate close.
/// The connection is also closed after `idle_timeout` of silence
/// between messages — this defends against slow-loris consumers
/// holding daemon resources indefinitely.
pub async fn serve_connection_with(
    stream: UnixStream,
    event_tx: mpsc::UnboundedSender<Event>,
    idle_timeout: Duration,
) -> Result<(), ServerError> {
    let stream = perform_handshake(stream).await?;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    loop {
        buf.clear();
        // Bound the per-message read to MAX_FRAME_BYTES bytes via a
        // capped `read_until('\n')` and an outer idle-timeout. The
        // bound prevents a peer from forcing the daemon to allocate
        // unbounded memory for a single frame; the timeout caps the
        // total time a peer can hold a connection without speaking.
        let read_result = timeout(idle_timeout, async {
            read_frame_bounded(&mut reader, &mut buf, MAX_FRAME_BYTES).await
        })
        .await;
        let outcome = match read_result {
            Ok(o) => o,
            Err(_) => {
                let bytes = encode_message(&ServerMessage::Error {
                    code: error_codes::PROTOCOL_VIOLATION,
                    message: format!("idle timeout after {}s", idle_timeout.as_secs()),
                })
                .map_err(ServerError::Encode)?;
                let _ = write.write_all(&bytes).await;
                return Ok(());
            }
        };
        match outcome? {
            FrameOutcome::Eof => return Ok(()),
            FrameOutcome::Oversize => {
                let bytes = encode_message(&ServerMessage::Error {
                    code: error_codes::PROTOCOL_VIOLATION,
                    message: format!("frame exceeds {MAX_FRAME_BYTES} bytes"),
                })
                .map_err(ServerError::Encode)?;
                let _ = write.write_all(&bytes).await;
                return Ok(());
            }
            FrameOutcome::Frame => {}
        }
        let line = match std::str::from_utf8(&buf) {
            Ok(s) => s,
            Err(_) => {
                let bytes = encode_message(&ServerMessage::Error {
                    code: error_codes::BAD_REQUEST,
                    message: "frame is not valid UTF-8".into(),
                })
                .map_err(ServerError::Encode)?;
                let _ = write.write_all(&bytes).await;
                return Ok(());
            }
        };
        let msg = match decode_line::<ClientMessage>(line) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(target: "tessera.monitord", error = %e, "decode failed, closing");
                let bytes = encode_message(&ServerMessage::Error {
                    code: error_codes::BAD_REQUEST,
                    message: format!("{e}"),
                })
                .map_err(ServerError::Encode)?;
                let _ = write.write_all(&bytes).await;
                return Ok(());
            }
        };
        let reply = dispatch(msg, &event_tx).await;
        let bytes = encode_message(&reply).map_err(ServerError::Encode)?;
        write.write_all(&bytes).await?;
    }
}

/// Perform the initial Hello/HelloAck exchange.
pub async fn perform_handshake(mut stream: UnixStream) -> Result<UnixStream, ServerError> {
    let mut buf = String::new();
    let line_result = {
        let mut reader = BufReader::new(&mut stream);
        timeout(Duration::from_secs(2), reader.read_line(&mut buf))
            .await
            .map_err(|_| ServerError::HandshakeTimeout)?
    };
    let n = line_result?;
    if n == 0 {
        return Err(ServerError::HelloExpected);
    }
    let msg: ClientMessage = decode_line(&buf).map_err(|e| match e {
        tessera_proto::WireError::Decode(e) => ServerError::Decode(e),
        other => ServerError::Encode(other),
    })?;
    let pv = match msg {
        ClientMessage::Hello {
            protocol_version, ..
        } => protocol_version,
        _ => {
            send_error(
                &mut stream,
                error_codes::BAD_REQUEST,
                "expected Hello as first frame",
            )
            .await
            .ok();
            return Err(ServerError::HelloExpected);
        }
    };
    if pv != PROTOCOL_VERSION {
        send_error(
            &mut stream,
            error_codes::PROTOCOL_MISMATCH,
            &format!("server v{PROTOCOL_VERSION} != client v{pv}"),
        )
        .await
        .ok();
        return Err(ServerError::VersionMismatch {
            server: PROTOCOL_VERSION,
            client: pv,
        });
    }
    let ack = ServerMessage::HelloAck {
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: PROTOCOL_VERSION,
    };
    let bytes = encode_message(&ack).map_err(ServerError::Encode)?;
    stream.write_all(&bytes).await?;
    Ok(stream)
}

async fn send_error(stream: &mut UnixStream, code: u32, msg: &str) -> io::Result<()> {
    let bytes = encode_message(&ServerMessage::Error {
        code,
        message: msg.to_string(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    stream.write_all(&bytes).await
}

#[allow(clippy::too_many_lines)]
async fn dispatch(msg: ClientMessage, event_tx: &mpsc::UnboundedSender<Event>) -> ServerMessage {
    match msg {
        ClientMessage::Hello { .. } => ServerMessage::Error {
            code: error_codes::BAD_REQUEST,
            message: "Hello already processed".into(),
        },
        ClientMessage::Ping => {
            let (tx, rx) = oneshot::channel();
            if event_tx
                .send(Event::Ipc(IpcRequest::Ping { reply: tx }))
                .is_err()
            {
                return ServerMessage::Error {
                    code: error_codes::INTERNAL,
                    message: "state manager gone".into(),
                };
            }
            await_reply(rx).await
        }
        ClientMessage::SessionOpen {
            session_id,
            pam_user,
            pam_service,
            target,
            usb_serial,
            host_id_hash,
            opened_at,
            cert_cn,
            cert_serial,
            engineer_ski,
            engineer_cert_sha256,
            uid,
        } => {
            let session = ActiveSession {
                session_id,
                pam_user,
                pam_service,
                target,
                usb_serial,
                host_id_hash,
                opened_at,
                cert_cn,
                cert_serial,
                engineer_ski,
                engineer_cert_sha256,
                uid,
            };
            let (tx, rx) = oneshot::channel();
            if event_tx
                .send(Event::Ipc(IpcRequest::SessionOpen {
                    session: Box::new(session),
                    reply: tx,
                }))
                .is_err()
            {
                return internal_error();
            }
            await_reply(rx).await
        }
        ClientMessage::GetActiveSessionByUid { uid } => {
            let (tx, rx) = oneshot::channel();
            if event_tx
                .send(Event::Ipc(IpcRequest::GetActiveSessionByUid {
                    uid,
                    reply: tx,
                }))
                .is_err()
            {
                return internal_error();
            }
            await_reply(rx).await
        }
        ClientMessage::SessionClose {
            session_id,
            closed_at,
        } => {
            let (tx, rx) = oneshot::channel();
            if event_tx
                .send(Event::Ipc(IpcRequest::SessionClose {
                    session_id,
                    closed_at,
                    reply: tx,
                }))
                .is_err()
            {
                return internal_error();
            }
            await_reply(rx).await
        }
        ClientMessage::UpdateSessionTarget {
            session_id,
            new_target,
        } => {
            let (tx, rx) = oneshot::channel();
            if event_tx
                .send(Event::Ipc(IpcRequest::UpdateSessionTarget {
                    session_id,
                    new_target,
                    reply: tx,
                }))
                .is_err()
            {
                return internal_error();
            }
            await_reply(rx).await
        }
    }
}

async fn await_reply(rx: oneshot::Receiver<ServerMessage>) -> ServerMessage {
    match timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(m)) => m,
        _ => internal_error(),
    }
}

fn internal_error() -> ServerMessage {
    ServerMessage::Error {
        code: error_codes::INTERNAL,
        message: "monitord internal error".into(),
    }
}

#[allow(dead_code)]
fn _unused_systemtime() -> SystemTime {
    SystemTime::now()
}

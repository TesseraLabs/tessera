//! Connection handling: bounded framing, the `Hello` handshake, and the
//! dispatch of credential-provider requests.
//!
//! Nothing here knows what a named pipe is. A connection is a reader and a
//! writer, so the whole state machine — including the refusals — is exercised
//! in-process on any platform; the Windows side supplies the two ends and
//! nothing else.
//!
//! The rules are the ones the `AF_UNIX` contract already states: one frame is
//! one line of JSON, a frame over [`tessera_proto::MAX_FRAME_BYTES`] is a
//! protocol violation, and the first frame must be a `Hello` whose version
//! equals ours exactly. There is no negotiation: a client built against another
//! version is refused, not accommodated.
//!
//! # Deviation, stated
//!
//! The daemon closes on a protocol violation but keeps the connection after a
//! `BAD_REQUEST`. This server closes on both. The client of this transport is a
//! credential provider running as SYSTEM; a frame it cannot form correctly is
//! not a hiccup to recover from, and a connection kept open after one is a
//! connection kept open for whoever sent it.
//!
//! # Two clocks, and the one that is deliberately absent
//!
//! [`Budgets`] bounds how long the server waits *for a frame to arrive*, and it
//! does so with two different numbers: a short one until the handshake is done,
//! a long one afterwards. They are different because they bound different
//! things. The handshake budget bounds a program — a client that connects and
//! greets in the same breath, or is not a client of ours at all. The idle
//! budget bounds a person: between the role list and the PIN there is an
//! engineer at a keyboard, and cutting them off mid-typing would be a bug
//! dressed as a policy.
//!
//! Neither bounds the *handling* of a request. Serving an
//! `AuthenticateRequest` means waiting for removable media, and how long that
//! may take is the verification path's own business (`usb_wait`). No read is
//! outstanding while it happens, so no deadline here applies to it — which is
//! the property that lets the idle budget be shorter than the media wait
//! without ever cutting off a login in progress.
//!
//! A client has the mirror-image obligation: its own wait for a reply must
//! exceed the media wait, or it will give up on a verdict that was on its way.

use std::io::{BufRead, Write};
use std::time::Duration;

use tessera_proto::{
    error_codes, read_frame, AuthVerdict, CpClientMessage, CpServerMessage, PROTOCOL_VERSION,
};
use zeroize::Zeroize as _;

use crate::engine::{AuthEngine, AuthRequest};

/// A connection whose wait for the next frame can be bounded.
///
/// The server sets this before every read. A transport that cannot bound a read
/// cannot be served safely — a silent peer would hold the thread forever — so
/// the bound is a requirement of the transport rather than an option on it.
pub trait FrameTimeout {
    /// Bounds how long the next frame may take to arrive.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the transport refuses the deadline. The server
    /// treats that as fatal for the connection: it will not read without one.
    fn set_frame_timeout(&mut self, budget: Duration) -> std::io::Result<()>;
}

/// How long the server waits for a frame, by connection stage.
#[derive(Debug, Clone, Copy)]
pub struct Budgets {
    /// Until the handshake is done. This is a program's budget, not a person's.
    pub handshake: Duration,
    /// After the handshake, between one request and the next. This one covers
    /// an engineer choosing a role and typing a PIN.
    pub idle: Duration,
    /// How long the server lingers after a frame that closes the connection, so
    /// that the peer can read the refusal before the handle goes away.
    pub linger: Duration,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            // The same two seconds the `AF_UNIX` contract gives a handshake.
            handshake: Duration::from_secs(2),
            // Long enough for somebody to be interrupted mid-login and come
            // back to it; short enough that a dead client does not hold an
            // instance for the rest of the day. A client that is dropped here
            // reconnects — the protocol is a handshake and a request, and
            // nothing on the connection is worth preserving across it.
            idle: Duration::from_mins(3),
            linger: Duration::from_secs(1),
        }
    }
}

/// Errors that end a connection.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Reading from or writing to the peer failed.
    #[error("connection io: {0}")]
    Io(#[from] std::io::Error),
    /// A reply could not be encoded. Nothing is sent in this case, so the
    /// client sees a closed connection, which it must treat as a refusal.
    #[error("reply could not be encoded: {0}")]
    Encode(#[from] tessera_proto::WireError),
}

/// What the server does with a connection after handling one frame.
#[derive(Debug)]
pub enum Reaction {
    /// Send this and keep reading.
    Reply(CpServerMessage),
    /// Send this and close.
    ReplyAndClose(CpServerMessage),
}

/// One connection's state.
pub struct Session<'a, E: AuthEngine> {
    engine: &'a E,
    server_version: &'a str,
    greeted: bool,
}

impl<'a, E: AuthEngine> Session<'a, E> {
    /// A fresh connection that has not yet said hello.
    pub fn new(engine: &'a E, server_version: &'a str) -> Self {
        Self {
            engine,
            server_version,
            greeted: false,
        }
    }

    /// Whether the handshake has been completed on this connection.
    ///
    /// The server reads it to decide which budget the next frame gets.
    #[must_use]
    pub fn greeted(&self) -> bool {
        self.greeted
    }

    /// Handles one decoded message.
    pub fn handle(&mut self, message: CpClientMessage) -> Reaction {
        match message {
            CpClientMessage::Hello {
                protocol_version,
                agent,
            } => self.handle_hello(protocol_version, agent.as_deref()),
            other if !self.greeted => {
                tracing::warn!(
                    target: "tessera.engine.ipc",
                    frame = ?std::mem::discriminant(&other),
                    "first frame was not Hello; refusing the connection"
                );
                Reaction::ReplyAndClose(bad_request("Hello must be the first frame"))
            }
            CpClientMessage::ListRoles => self.handle_list_roles(),
            CpClientMessage::AuthenticateRequest { role, pin } => {
                self.handle_authenticate(&role, &pin)
            }
            CpClientMessage::Ping => Reaction::Reply(CpServerMessage::Pong),
        }
    }

    /// The handshake. A second `Hello` is a client that lost track of its own
    /// state, which is not a client to keep talking to.
    fn handle_hello(&mut self, protocol_version: u32, agent: Option<&str>) -> Reaction {
        if self.greeted {
            return Reaction::ReplyAndClose(bad_request("Hello was already exchanged"));
        }
        if protocol_version != PROTOCOL_VERSION {
            tracing::warn!(
                target: "tessera.engine.ipc",
                client_version = protocol_version,
                server_version = PROTOCOL_VERSION,
                "protocol version mismatch; closing"
            );
            return Reaction::ReplyAndClose(CpServerMessage::Error {
                code: error_codes::PROTOCOL_MISMATCH,
                message: format!("protocol version {protocol_version} is not {PROTOCOL_VERSION}"),
            });
        }
        self.greeted = true;
        tracing::info!(
            target: "tessera.engine.ipc",
            agent = agent.unwrap_or("<unnamed>"),
            "client accepted"
        );
        Reaction::Reply(CpServerMessage::HelloAck {
            server_version: self.server_version.to_owned(),
            protocol_version: PROTOCOL_VERSION,
        })
    }

    /// The role list is read by the service, never by the client: one device,
    /// one answer to "which roles exist here".
    fn handle_list_roles(&self) -> Reaction {
        match self.engine.list_roles() {
            Ok(roles) => Reaction::Reply(CpServerMessage::RoleList { roles }),
            Err(error) => {
                tracing::error!(
                    target: "tessera.engine.ipc",
                    error = %error,
                    "role list unavailable"
                );
                Reaction::Reply(CpServerMessage::Error {
                    code: error_codes::INTERNAL,
                    // The client is told the service failed, not which file it
                    // failed on: the tile is in front of whoever is logging in.
                    message: "role list unavailable".to_owned(),
                })
            }
        }
    }

    fn handle_authenticate(&self, role: &str, pin: &tessera_proto::WireSecret) -> Reaction {
        let verdict = match self.engine.authenticate(&AuthRequest { role, pin }) {
            Ok(admission) => AuthVerdict::Admitted(admission),
            Err(denial) => AuthVerdict::Denied(denial),
        };
        Reaction::Reply(CpServerMessage::AuthenticateResult(verdict))
    }
}

/// A `BAD_REQUEST` carrying `message`.
fn bad_request(message: &str) -> CpServerMessage {
    CpServerMessage::Error {
        code: error_codes::BAD_REQUEST,
        message: message.to_owned(),
    }
}

/// Whether an I/O error is a deadline that expired.
///
/// Two kinds, because two transports report the same event differently: a
/// bounded overlapped read reports `TimedOut`, and a socket with a read timeout
/// reports `WouldBlock` on Unix. Reading only one of them would leave the
/// timeout untested on the platform the tests run on, which is the same as not
/// having it.
fn is_deadline(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// Serves one connection to completion.
///
/// Every frame the peer sends is answered, and the connection is closed on the
/// first reaction that says so, on a read error, or at end of stream. Both the
/// request buffer and the encoded reply are wiped before they are reused or
/// dropped: a PIN travels through the first and a password through the second.
///
/// The wait for each frame is bounded by `budgets` — the handshake one until
/// the client has greeted, the idle one after that. A peer that goes silent
/// gets `1101 PROTOCOL_VIOLATION` and the connection back, which is the same
/// thing the `AF_UNIX` server does to an idle connection.
///
/// # Errors
///
/// [`ServeError`] when the transport fails or a reply cannot be encoded. The
/// caller logs it; there is nothing left to tell the peer at that point.
pub fn serve<R: BufRead + FrameTimeout, W: Write, E: AuthEngine>(
    reader: &mut R,
    writer: &mut W,
    session: &mut Session<'_, E>,
    budgets: Budgets,
) -> Result<(), ServeError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    loop {
        // Set before every read rather than once per stage: the budget that
        // applies is the one for the state the connection is in *now*, and the
        // handshake changes that state mid-loop.
        let budget = if session.greeted() {
            budgets.idle
        } else {
            budgets.handshake
        };
        reader.set_frame_timeout(budget)?;

        let frame = read_frame(reader, &mut buf);
        let reaction = match frame {
            Ok(None) => break,
            Ok(Some(())) => match tessera_proto::decode_bytes::<CpClientMessage>(&buf) {
                Ok(message) => session.handle(message),
                Err(error) => {
                    tracing::warn!(
                        target: "tessera.engine.ipc",
                        error = %error,
                        "frame did not decode; closing"
                    );
                    Reaction::ReplyAndClose(bad_request("frame did not decode"))
                }
            },
            Err(error) if is_deadline(&error) => {
                tracing::info!(
                    target: "tessera.engine.ipc",
                    budget_seconds = budget.as_secs(),
                    greeted = session.greeted(),
                    "no frame arrived within the budget; closing the connection"
                );
                Reaction::ReplyAndClose(CpServerMessage::Error {
                    code: error_codes::PROTOCOL_VIOLATION,
                    message: "no frame arrived within the connection's budget".to_owned(),
                })
            }
            Err(error) => {
                tracing::warn!(
                    target: "tessera.engine.ipc",
                    error = %error,
                    "framing violation; closing"
                );
                Reaction::ReplyAndClose(CpServerMessage::Error {
                    code: error_codes::PROTOCOL_VIOLATION,
                    message: "frame exceeds the protocol limit".to_owned(),
                })
            }
        };
        // The request buffer held the PIN until this point.
        buf.zeroize();

        let (message, close) = match reaction {
            Reaction::Reply(m) => (m, false),
            Reaction::ReplyAndClose(m) => (m, true),
        };
        let mut encoded = tessera_proto::encode_message(&message)?;
        let write = writer.write_all(&encoded).and_then(|()| writer.flush());
        // The reply buffer held the technical account's password.
        encoded.zeroize();
        write?;
        if close {
            linger(reader, budgets.linger);
            break;
        }
    }
    buf.zeroize();
    Ok(())
}

/// Gives the peer a bounded moment to read the frame that closes the
/// connection.
///
/// Without it the server can close the handle before the client has read the
/// refusal, and the client sees a dropped connection where it should have seen
/// a reason. The wait ends the moment the peer closes its own end, so a
/// well-behaved client costs nothing; a peer that neither reads nor closes
/// costs the linger budget and no more.
fn linger<R: BufRead + FrameTimeout>(reader: &mut R, budget: std::time::Duration) {
    if reader.set_frame_timeout(budget).is_err() {
        return;
    }
    let mut scratch = [0_u8; 1];
    let _read = std::io::Read::read(reader, &mut scratch);
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::let_underscore_must_use
)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tessera_proto::{Admission, Denial, DenialReason, RoleSummary, WireSecret};

    /// An engine that answers from fixtures and counts what it was asked.
    struct FakeEngine {
        roles: Vec<RoleSummary>,
        roles_fail: bool,
        admit: bool,
        attempts: AtomicUsize,
    }

    impl FakeEngine {
        fn new() -> Self {
            Self {
                roles: vec![
                    RoleSummary {
                        id: "oper".to_owned(),
                        name: "Operator".to_owned(),
                        level: 1,
                    },
                    RoleSummary {
                        id: "serv".to_owned(),
                        name: "Service".to_owned(),
                        level: 2,
                    },
                ],
                roles_fail: false,
                admit: true,
                attempts: AtomicUsize::new(0),
            }
        }
    }

    impl AuthEngine for FakeEngine {
        fn list_roles(&self) -> Result<Vec<RoleSummary>, crate::engine::EngineError> {
            if self.roles_fail {
                return Err(crate::engine::EngineError::RoleStore("no store".to_owned()));
            }
            Ok(self.roles.clone())
        }

        fn authenticate(&self, request: &AuthRequest<'_>) -> Result<Admission, Denial> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.admit && request.pin.expose() == "good" {
                Ok(Admission {
                    account: "tessera-session".to_owned(),
                    password: WireSecret::new("machine-password".to_owned()),
                    role: request.role.to_owned(),
                    role_version: 3,
                    cert_cn: Some("alice".to_owned()),
                    session_id: "s1".to_owned(),
                })
            } else {
                Err(Denial {
                    reason: DenialReason::Credential,
                    code: 7,
                })
            }
        }
    }

    /// A scripted reader that records the budgets it was given and can fall
    /// silent — the two things the deadline logic is made of.
    struct ScriptedReader {
        inner: Cursor<Vec<u8>>,
        /// Budgets handed to `set_frame_timeout`, in order.
        budgets: Rc<RefCell<Vec<Duration>>>,
        /// When true, the reader reports a deadline instead of end of stream
        /// once the script runs out — a peer that stays connected and silent
        /// rather than closing.
        goes_silent: bool,
    }

    impl ScriptedReader {
        fn new(input: Vec<u8>, goes_silent: bool) -> Self {
            Self {
                inner: Cursor::new(input),
                budgets: Rc::new(RefCell::new(Vec::new())),
                goes_silent,
            }
        }

        fn exhausted(&self) -> bool {
            usize::try_from(self.inner.position()).unwrap_or(usize::MAX)
                >= self.inner.get_ref().len()
        }
    }

    impl std::io::Read for ScriptedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.goes_silent && self.exhausted() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the scripted peer went silent",
                ));
            }
            self.inner.read(buf)
        }
    }

    impl BufRead for ScriptedReader {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.goes_silent && self.exhausted() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the scripted peer went silent",
                ));
            }
            self.inner.fill_buf()
        }

        fn consume(&mut self, amount: usize) {
            self.inner.consume(amount);
        }
    }

    impl FrameTimeout for ScriptedReader {
        fn set_frame_timeout(&mut self, budget: Duration) -> std::io::Result<()> {
            self.budgets.borrow_mut().push(budget);
            Ok(())
        }
    }

    /// The budgets used by the tests: distinguishable, and short enough that a
    /// mistake shows up as the wrong number rather than a slow test.
    fn budgets() -> Budgets {
        Budgets {
            handshake: Duration::from_secs(2),
            idle: Duration::from_mins(3),
            linger: Duration::from_millis(50),
        }
    }

    /// Drive a scripted client through one connection and return the replies.
    fn exchange(engine: &FakeEngine, frames: &[CpClientMessage]) -> Vec<CpServerMessage> {
        let mut input = Vec::new();
        for frame in frames {
            input.extend_from_slice(&tessera_proto::encode_message(frame).unwrap());
        }
        run_raw(engine, input)
    }

    fn run_raw(engine: &FakeEngine, input: Vec<u8>) -> Vec<CpServerMessage> {
        run_scripted(engine, ScriptedReader::new(input, false)).0
    }

    /// Runs one connection and returns the replies alongside the budgets the
    /// server asked the transport for.
    fn run_scripted(
        engine: &FakeEngine,
        mut reader: ScriptedReader,
    ) -> (Vec<CpServerMessage>, Vec<Duration>) {
        let budget_log = Rc::clone(&reader.budgets);
        let mut output: Vec<u8> = Vec::new();
        let mut session = Session::new(engine, "0.5.0-test");
        // A closed connection is a normal end here; the replies already sent
        // are what the assertions are about.
        let _ = serve(&mut reader, &mut output, &mut session, budgets());
        let replies = String::from_utf8(output)
            .expect("replies are UTF-8")
            .lines()
            .map(|line| tessera_proto::decode_line::<CpServerMessage>(line).unwrap())
            .collect();
        let seen = budget_log.borrow().clone();
        (replies, seen)
    }

    fn hello() -> CpClientMessage {
        CpClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            agent: Some("test".to_owned()),
        }
    }

    #[test]
    fn hello_is_acknowledged() {
        let replies = exchange(&FakeEngine::new(), &[hello()]);
        assert!(matches!(
            replies.as_slice(),
            [CpServerMessage::HelloAck {
                protocol_version, ..
            }] if *protocol_version == PROTOCOL_VERSION
        ));
    }

    /// Strict equality, both directions: there is no negotiation, so a client
    /// one version ahead is refused exactly like one a version behind.
    #[test]
    fn version_mismatch_closes_the_connection() {
        for version in [PROTOCOL_VERSION - 1, PROTOCOL_VERSION + 1] {
            let replies = exchange(
                &FakeEngine::new(),
                &[
                    CpClientMessage::Hello {
                        protocol_version: version,
                        agent: None,
                    },
                    CpClientMessage::ListRoles,
                ],
            );
            assert_eq!(replies.len(), 1, "the connection must close on mismatch");
            assert!(matches!(
                replies.as_slice(),
                [CpServerMessage::Error { code, .. }] if *code == error_codes::PROTOCOL_MISMATCH
            ));
        }
    }

    #[test]
    fn requests_before_hello_are_refused_and_close() {
        let engine = FakeEngine::new();
        let replies = exchange(
            &engine,
            &[
                CpClientMessage::AuthenticateRequest {
                    role: "serv".to_owned(),
                    pin: WireSecret::new("good".to_owned()),
                },
                hello(),
            ],
        );
        assert_eq!(replies.len(), 1);
        assert!(matches!(
            replies.as_slice(),
            [CpServerMessage::Error { code, .. }] if *code == error_codes::BAD_REQUEST
        ));
        assert_eq!(
            engine.attempts.load(Ordering::SeqCst),
            0,
            "no verification may run before the handshake"
        );
    }

    #[test]
    fn roles_are_listed_after_hello() {
        let replies = exchange(&FakeEngine::new(), &[hello(), CpClientMessage::ListRoles]);
        match replies.as_slice() {
            [_, CpServerMessage::RoleList { roles }] => {
                assert_eq!(roles.len(), 2);
                assert_eq!(roles[0].id, "oper");
            }
            other => panic!("expected a role list, got {other:?}"),
        }
    }

    /// A store the service cannot read must not present as "this device has no
    /// roles": an empty combo box and a broken one look the same to whoever is
    /// standing there.
    #[test]
    fn an_unreadable_store_is_an_error_not_an_empty_list() {
        let mut engine = FakeEngine::new();
        engine.roles_fail = true;
        let replies = exchange(&engine, &[hello(), CpClientMessage::ListRoles]);
        assert!(matches!(
            replies.as_slice(),
            [_, CpServerMessage::Error { code, .. }] if *code == error_codes::INTERNAL
        ));
    }

    #[test]
    fn an_admission_carries_the_account_and_its_password() {
        let replies = exchange(
            &FakeEngine::new(),
            &[
                hello(),
                CpClientMessage::AuthenticateRequest {
                    role: "serv".to_owned(),
                    pin: WireSecret::new("good".to_owned()),
                },
            ],
        );
        match replies.as_slice() {
            [_, CpServerMessage::AuthenticateResult(AuthVerdict::Admitted(a))] => {
                assert_eq!(a.account, "tessera-session");
                assert_eq!(a.password.expose(), "machine-password");
                assert_eq!(a.role, "serv");
            }
            other => panic!("expected an admission, got {other:?}"),
        }
    }

    /// A refusal keeps the connection: the tile lets the engineer try again
    /// without a fresh handshake, and the retry budget lives in the flow.
    #[test]
    fn a_refusal_keeps_the_connection_open() {
        let replies = exchange(
            &FakeEngine::new(),
            &[
                hello(),
                CpClientMessage::AuthenticateRequest {
                    role: "serv".to_owned(),
                    pin: WireSecret::new("wrong".to_owned()),
                },
                CpClientMessage::Ping,
            ],
        );
        assert_eq!(replies.len(), 3);
        assert!(matches!(
            replies.get(1),
            Some(CpServerMessage::AuthenticateResult(AuthVerdict::Denied(d)))
                if d.reason == DenialReason::Credential && d.code == 7
        ));
        assert!(matches!(replies.get(2), Some(CpServerMessage::Pong)));
    }

    #[test]
    fn undecodable_frames_are_refused_and_close() {
        let engine = FakeEngine::new();
        let mut input = tessera_proto::encode_message(&hello()).unwrap();
        input.extend_from_slice(b"{not json}\n");
        input.extend_from_slice(&tessera_proto::encode_message(&CpClientMessage::Ping).unwrap());
        let replies = run_raw(&engine, input);
        assert_eq!(replies.len(), 2);
        assert!(matches!(
            replies.get(1),
            Some(CpServerMessage::Error { code, .. }) if *code == error_codes::BAD_REQUEST
        ));
    }

    /// The bound is on what the server allocates, not merely on what it
    /// accepts: an oversize frame is refused without the reader growing to
    /// meet it.
    #[test]
    fn oversize_frames_are_a_protocol_violation() {
        let engine = FakeEngine::new();
        let mut input = tessera_proto::encode_message(&hello()).unwrap();
        input.extend_from_slice(&vec![b'x'; tessera_proto::MAX_FRAME_BYTES + 10]);
        input.push(b'\n');
        let replies = run_raw(&engine, input);
        assert_eq!(replies.len(), 2);
        assert!(matches!(
            replies.get(1),
            Some(CpServerMessage::Error { code, .. }) if *code == error_codes::PROTOCOL_VIOLATION
        ));
    }

    /// A frame that stops without its newline is the same failure as an
    /// oversize one — the server must not treat a truncated line as a message.
    #[test]
    fn a_truncated_frame_is_not_a_message() {
        let engine = FakeEngine::new();
        let mut input = tessera_proto::encode_message(&hello()).unwrap();
        input.extend_from_slice(br#"{"type":"ping""#);
        let replies = run_raw(&engine, input);
        assert_eq!(replies.len(), 2);
        assert!(matches!(
            replies.get(1),
            Some(CpServerMessage::Error { code, .. }) if *code == error_codes::PROTOCOL_VIOLATION
        ));
        assert_eq!(engine.attempts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_second_hello_closes_the_connection() {
        let replies = exchange(&FakeEngine::new(), &[hello(), hello(), hello()]);
        assert_eq!(replies.len(), 2);
        assert!(matches!(
            replies.get(1),
            Some(CpServerMessage::Error { code, .. }) if *code == error_codes::BAD_REQUEST
        ));
    }

    /// A peer that connects and never greets is dropped on the handshake
    /// budget: this is the client that hung before saying anything, and the
    /// instance it holds is one the next login needs.
    #[test]
    fn a_client_that_never_greets_is_dropped() {
        let engine = FakeEngine::new();
        let (replies, seen) = run_scripted(&engine, ScriptedReader::new(Vec::new(), true));
        assert!(matches!(
            replies.as_slice(),
            [CpServerMessage::Error { code, .. }] if *code == error_codes::PROTOCOL_VIOLATION
        ));
        assert_eq!(
            seen.first(),
            Some(&budgets().handshake),
            "the first frame must be bounded by the handshake budget"
        );
    }

    /// A greeted peer that then goes silent is dropped too, but on the longer
    /// budget — the one that has to allow for somebody typing a PIN.
    #[test]
    fn a_greeted_client_that_goes_silent_is_dropped_on_the_idle_budget() {
        let engine = FakeEngine::new();
        let input = tessera_proto::encode_message(&hello()).unwrap();
        let (replies, seen) = run_scripted(&engine, ScriptedReader::new(input, true));
        assert_eq!(replies.len(), 2, "the ack, then the refusal");
        assert!(matches!(
            replies.get(1),
            Some(CpServerMessage::Error { code, .. }) if *code == error_codes::PROTOCOL_VIOLATION
        ));
        assert_eq!(
            seen.first(),
            Some(&budgets().handshake),
            "the handshake frame is bounded by the short budget"
        );
        assert_eq!(
            seen.get(1),
            Some(&budgets().idle),
            "everything after the handshake is bounded by the long one"
        );
    }

    /// The counterpart: a client that keeps talking is never dropped, and every
    /// frame after the handshake is measured against the idle budget.
    #[test]
    fn an_active_client_is_not_dropped() {
        let engine = FakeEngine::new();
        let mut input = Vec::new();
        for frame in [
            hello(),
            CpClientMessage::ListRoles,
            CpClientMessage::AuthenticateRequest {
                role: "serv".to_owned(),
                pin: WireSecret::new("good".to_owned()),
            },
            CpClientMessage::Ping,
        ] {
            input.extend_from_slice(&tessera_proto::encode_message(&frame).unwrap());
        }
        // The peer closes cleanly at the end of the script rather than going
        // silent, which is how a client that is done behaves.
        let (replies, seen) = run_scripted(&engine, ScriptedReader::new(input, false));
        assert_eq!(replies.len(), 4, "every request was answered: {replies:?}");
        assert!(
            !replies.iter().any(|reply| matches!(
                reply,
                CpServerMessage::Error { code, .. } if *code == error_codes::PROTOCOL_VIOLATION
            )),
            "an active client must not be refused: {replies:?}"
        );
        assert_eq!(seen.first(), Some(&budgets().handshake));
        assert!(
            seen.iter().skip(1).all(|b| *b == budgets().idle),
            "after the handshake every frame gets the idle budget: {seen:?}"
        );
    }

    /// A long request must not be cut short by the idle budget. The budget
    /// bounds the wait for a frame, and no read is outstanding while a request
    /// is being served — this pins that down against a future refactor that
    /// moves the deadline somewhere it would also cover the work.
    #[test]
    fn a_slow_request_is_not_bounded_by_the_idle_budget() {
        struct SlowEngine;

        impl AuthEngine for SlowEngine {
            fn list_roles(&self) -> Result<Vec<RoleSummary>, crate::engine::EngineError> {
                Ok(Vec::new())
            }

            fn authenticate(&self, _request: &AuthRequest<'_>) -> Result<Admission, Denial> {
                // Longer than the linger budget the test uses, standing in for
                // a wait on removable media.
                std::thread::sleep(Duration::from_millis(120));
                Ok(Admission {
                    account: "tessera-logon".to_owned(),
                    password: WireSecret::new("pw".to_owned()),
                    role: "serv".to_owned(),
                    role_version: 1,
                    cert_cn: None,
                    session_id: "slow".to_owned(),
                })
            }
        }

        let mut input = Vec::new();
        for frame in [
            hello(),
            CpClientMessage::AuthenticateRequest {
                role: "serv".to_owned(),
                pin: WireSecret::new("good".to_owned()),
            },
        ] {
            input.extend_from_slice(&tessera_proto::encode_message(&frame).unwrap());
        }
        let mut reader = ScriptedReader::new(input, false);
        let mut output: Vec<u8> = Vec::new();
        let engine = SlowEngine;
        let mut session = Session::new(&engine, "0.5.0-test");
        let budgets = Budgets {
            handshake: Duration::from_secs(2),
            // Deliberately shorter than the engine takes: if the budget covered
            // the work, this would refuse instead of admitting.
            idle: Duration::from_millis(10),
            linger: Duration::from_millis(1),
        };
        let _served = serve(&mut reader, &mut output, &mut session, budgets);
        let replies: Vec<CpServerMessage> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| tessera_proto::decode_line::<CpServerMessage>(line).unwrap())
            .collect();
        assert!(
            matches!(
                replies.get(1),
                Some(CpServerMessage::AuthenticateResult(AuthVerdict::Admitted(
                    _
                )))
            ),
            "the verdict must survive a request slower than the idle budget: {replies:?}"
        );
    }
}

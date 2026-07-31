//! The engine service behind the named pipe.
//!
//! This is the only place the tile touches the outside world. One call is one
//! connection: open the pipe, greet, ask, read the answer, drop everything. A
//! logon screen is not a place to keep a connection alive across attempts, and
//! a fresh handshake per call means a service restarted mid-screen is picked up
//! rather than remembered as dead.
//!
//! # The deadline is the point
//!
//! `GetSerialization` is synchronous, and `LogonUI` calls it on the thread that
//! draws the logon screen. A service that accepts the connection and then never
//! answers would hold that thread forever — the logon screen of the device,
//! stuck, with no tile of any provider usable. That is a denial of service on
//! the login path, so every exchange runs on a worker thread and the caller
//! waits on a deadline. A missed deadline is the same fail-closed outcome as a
//! dropped pipe: a status line and no serialization.
//!
//! What the deadline does not do is kill the worker. There is no safe way to
//! abort a thread blocked in a synchronous read, so a timed-out worker is
//! abandoned: it holds one pipe handle and one thread until the service answers
//! or the pipe breaks, and its answer is dropped unread. The cost is bounded —
//! `LogonUI` is short-lived, and each abandoned worker corresponds to one visible
//! failed attempt — and it buys a logon screen that stays usable.
//!
//! # Layering
//!
//! [`tessera_proto::Client`] is used rather than reimplemented: two clients for
//! one protocol drift, and the one that drifts unnoticed is the one in the logon
//! path. It is taken from the protocol crate rather than from the service's,
//! which is what keeps the verification core — trust, roles, OpenSSL — out of
//! the process `LogonUI` loads this DLL into.

use std::io::{BufRead, Write};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::time::Duration;

use tessera_proto::{AuthVerdict, Client, ClientError, Denial, DenialReason, RoleSummary};
use zeroize::Zeroizing;

use crate::engine::{AuthRequest, DenialCode, EngineClient, EngineError, Grant, Verdict};
use crate::kerb::LogonTarget;
use crate::role::RoleChoice;

/// How long the tile waits for a verdict.
///
/// Long enough for a verification that reads a certificate off a removable
/// medium, short enough that an engineer facing a stuck service gets an answer
/// rather than a frozen screen. This deadline runs while somebody is waiting
/// for a logon they asked for.
pub const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the tile waits for the role list.
///
/// Much shorter, because of *when* it runs: the list is fetched while `LogonUI`
/// is building the logon screen, before anyone has asked for anything. A stuck
/// service must not hold up a screen whose other tiles have nothing to do with
/// Tessera, so this deadline is set to what a local pipe and a role-store read
/// take with room to spare, and no more.
pub const DEFAULT_LIST_TIMEOUT: Duration = Duration::from_secs(3);

/// Name this provider greets the service with.
const AGENT: &str = concat!("tessera_cp/", env!("CARGO_PKG_VERSION"));

/// Opens transports to the service.
///
/// A trait rather than a concrete pipe so that the exchange, the mapping and
/// the deadline are all exercised on a host that has no named pipes. The bounds
/// are what the worker thread needs: the connector is shared across calls, and
/// the streams it produces are used on that thread.
pub trait Connector: Send + Sync + 'static {
    /// Read half.
    type Reader: BufRead + Send;
    /// Write half.
    type Writer: Write + Send;

    /// Opens one connection.
    ///
    /// # Errors
    ///
    /// [`EngineError::Unavailable`] when there is nothing to connect to; the
    /// tile does not distinguish the reasons, because from the console they are
    /// one fact.
    fn connect(&self) -> Result<(Self::Reader, Self::Writer), EngineError>;
}

/// The engine service, reached over a [`Connector`], under a deadline.
#[derive(Debug)]
pub struct ServiceEngine<C: Connector> {
    connector: std::sync::Arc<C>,
    list_timeout: Duration,
    auth_timeout: Duration,
}

impl<C: Connector> ServiceEngine<C> {
    /// Builds an engine with explicit deadlines for the two kinds of call.
    #[must_use]
    pub fn with_timeouts(connector: C, list_timeout: Duration, auth_timeout: Duration) -> Self {
        Self {
            connector: std::sync::Arc::new(connector),
            list_timeout,
            auth_timeout,
        }
    }

    /// Builds an engine with one deadline for both kinds of call.
    #[must_use]
    pub fn with_timeout(connector: C, timeout: Duration) -> Self {
        Self::with_timeouts(connector, timeout, timeout)
    }

    /// Builds an engine with [`DEFAULT_LIST_TIMEOUT`] and
    /// [`DEFAULT_AUTH_TIMEOUT`].
    #[must_use]
    pub fn new(connector: C) -> Self {
        Self::with_timeouts(connector, DEFAULT_LIST_TIMEOUT, DEFAULT_AUTH_TIMEOUT)
    }

    /// Runs one exchange on a worker thread and waits for it until the deadline.
    ///
    /// `body` gets a greeted client. Everything it produces must cross a channel,
    /// which is why the result type is `Send`.
    fn exchange<T, F>(&self, timeout: Duration, body: F) -> Result<T, EngineError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Client<C::Reader, C::Writer>) -> Result<T, ClientError> + Send + 'static,
    {
        let connector = std::sync::Arc::clone(&self.connector);
        // Capacity one so that a worker finishing after the deadline can hand
        // its result over and exit instead of blocking on a receiver that is
        // no longer there.
        let (tx, rx) = sync_channel::<Result<T, EngineError>>(1);

        let spawned = std::thread::Builder::new()
            .name("tessera-cp-engine".to_owned())
            .spawn(move || {
                let outcome = connector.connect().and_then(|(reader, writer)| {
                    let mut client =
                        Client::connect(reader, writer, AGENT).map_err(|e| map_error(&e))?;
                    body(&mut client).map_err(|e| map_error(&e))
                });
                // The receiver is gone when the deadline passed first. Its
                // answer is not wanted, and dropping it here wipes whatever it
                // carried.
                drop(tx.send(outcome));
            });

        if let Err(error) = spawned {
            tracing::error!(
                target: "tessera.cp",
                error = %error,
                "engine worker could not be started"
            );
            return Err(EngineError::Unavailable);
        }

        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                tracing::warn!(
                    target: "tessera.cp",
                    timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                    "engine did not answer before the deadline; the worker is abandoned"
                );
                Err(EngineError::Timeout)
            }
            // The worker died without sending — a panic inside it, since every
            // other path sends. Fail-closed, like everything else here.
            Err(RecvTimeoutError::Disconnected) => Err(EngineError::Disconnected),
        }
    }
}

impl<C: Connector> EngineClient for ServiceEngine<C> {
    fn list_roles(&self) -> Result<Vec<RoleChoice>, EngineError> {
        let roles = self.exchange(self.list_timeout, Client::list_roles)?;
        Ok(roles.iter().map(role_from_wire).collect())
    }

    fn authenticate(&self, request: AuthRequest) -> Result<Verdict, EngineError> {
        let AuthRequest { role_id, pin } = request;
        let verdict = self.exchange(self.auth_timeout, move |client| {
            let answer = client.authenticate(&role_id, &pin);
            // The PIN has been on the wire; it has no further use on this side.
            drop(pin);
            answer
        })?;

        Ok(match verdict {
            AuthVerdict::Admitted(admission) => {
                tracing::info!(
                    target: "tessera.cp",
                    session_id = %admission.session_id,
                    role = %admission.role,
                    role_version = admission.role_version,
                    "engine admitted the credential"
                );
                Verdict::Granted(Grant {
                    account: LogonTarget::local(admission.account),
                    secret: Zeroizing::new(admission.password.expose().to_owned()),
                    session_id: admission.session_id,
                })
            }
            AuthVerdict::Denied(denial) => Verdict::Denied(denial_from_wire(&denial)),
        })
    }
}

/// Translates a role as the wire carries it.
fn role_from_wire(role: &RoleSummary) -> RoleChoice {
    RoleChoice::new(role.id.clone(), role.name.clone(), u32::from(role.level))
}

/// Translates a refusal category.
fn denial_from_wire(denial: &Denial) -> DenialCode {
    match denial.reason {
        DenialReason::Media => DenialCode::Media,
        DenialReason::Credential => DenialCode::Credential,
        DenialReason::Role => DenialCode::Role,
        DenialReason::Internal => DenialCode::Internal,
    }
}

/// Translates a client failure into what the tile reasons about.
///
/// The transport's own detail stops here: it goes to the log, and the tile gets
/// the category that decides its status line.
fn map_error(error: &ClientError) -> EngineError {
    tracing::warn!(target: "tessera.cp", error = %error, "engine exchange failed");
    match error {
        ClientError::Io(_) | ClientError::Closed => EngineError::Disconnected,
        ClientError::Version { .. } => EngineError::ProtocolMismatch,
        ClientError::Wire(_) | ClientError::Unexpected => EngineError::Malformed,
        ClientError::Server { code, .. } => EngineError::Service { code: *code },
    }
}

#[cfg(windows)]
pub use pipe::PipeConnector;

#[cfg(windows)]
mod pipe {
    //! The named-pipe transport.

    use std::ffi::OsString;
    use std::fs::{File, OpenOptions};
    use std::io::BufReader;

    use crate::engine::EngineError;

    use super::Connector;

    /// Default pipe the service listens on.
    pub const DEFAULT_PIPE: &str = r"\\.\pipe\tessera-engine";

    /// Connects to the service's named pipe.
    ///
    /// The pipe's security descriptor is what keeps engineers' sessions off it;
    /// nothing on this side asserts who may connect, and nothing on this side
    /// could. `LogonUI` runs as `LocalSystem`, which is the context the service
    /// admits.
    #[derive(Debug, Clone)]
    pub struct PipeConnector {
        name: OsString,
    }

    impl PipeConnector {
        /// Connects to a pipe by name.
        #[must_use]
        pub fn new(name: impl Into<OsString>) -> Self {
            Self { name: name.into() }
        }
    }

    impl Default for PipeConnector {
        fn default() -> Self {
            Self::new(DEFAULT_PIPE)
        }
    }

    impl Connector for PipeConnector {
        type Reader = BufReader<File>;
        type Writer = File;

        fn connect(&self) -> Result<(Self::Reader, Self::Writer), EngineError> {
            let handle = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.name)
                .map_err(|error| {
                    tracing::warn!(
                        target: "tessera.cp",
                        error = %error,
                        "the engine pipe could not be opened"
                    );
                    EngineError::Unavailable
                })?;
            // Two handles onto one pipe: the reader buffers, the writer does
            // not, and neither borrows the other.
            let writer = handle.try_clone().map_err(|error| {
                tracing::warn!(
                    target: "tessera.cp",
                    error = %error,
                    "the engine pipe handle could not be duplicated"
                );
                EngineError::Unavailable
            })?;
            Ok((BufReader::new(handle), writer))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use tessera_proto::{
        error_codes, Admission, CpServerMessage, RoleSummary, WireSecret, PROTOCOL_VERSION,
    };

    use super::*;

    /// A connector that replays scripted server frames.
    struct ScriptedConnector {
        frames: Vec<u8>,
        /// Set when the connector should refuse to connect at all.
        unavailable: bool,
        /// How long the worker sleeps before answering, for the deadline test.
        delay: Duration,
        /// What the provider wrote, kept so a test can inspect the request.
        written: Arc<Mutex<Vec<u8>>>,
        connections: Arc<AtomicUsize>,
    }

    /// A writer that records into a shared buffer.
    struct RecordingWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut sink) = self.0.lock() {
                sink.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ScriptedConnector {
        fn new(messages: &[CpServerMessage]) -> Self {
            let mut frames = Vec::new();
            for message in messages {
                frames.extend_from_slice(&tessera_proto::encode_message(message).unwrap());
            }
            Self {
                frames,
                unavailable: false,
                delay: Duration::ZERO,
                written: Arc::new(Mutex::new(Vec::new())),
                connections: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn unavailable() -> Self {
            let mut connector = Self::new(&[]);
            connector.unavailable = true;
            connector
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    impl Connector for ScriptedConnector {
        type Reader = Cursor<Vec<u8>>;
        type Writer = RecordingWriter;

        fn connect(&self) -> Result<(Self::Reader, Self::Writer), EngineError> {
            self.connections.fetch_add(1, Ordering::SeqCst);
            if self.unavailable {
                return Err(EngineError::Unavailable);
            }
            std::thread::sleep(self.delay);
            Ok((
                Cursor::new(self.frames.clone()),
                RecordingWriter(Arc::clone(&self.written)),
            ))
        }
    }

    fn ack() -> CpServerMessage {
        CpServerMessage::HelloAck {
            server_version: "0.5.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
        }
    }

    fn admission() -> CpServerMessage {
        CpServerMessage::AuthenticateResult(AuthVerdict::Admitted(Admission {
            account: "tessera-session".to_owned(),
            password: WireSecret::new("machine-secret".to_owned()),
            role: "serv".to_owned(),
            role_version: 3,
            cert_cn: Some("alice".to_owned()),
            session_id: "session-1".to_owned(),
        }))
    }

    fn request() -> AuthRequest {
        AuthRequest {
            role_id: "serv".to_owned(),
            pin: Zeroizing::new("1234".to_owned()),
        }
    }

    #[test]
    fn roles_arrive_in_the_tile_s_shape() {
        let engine = ServiceEngine::new(ScriptedConnector::new(&[
            ack(),
            CpServerMessage::RoleList {
                roles: vec![
                    RoleSummary {
                        id: "serv".to_owned(),
                        name: "Сервис".to_owned(),
                        level: 10,
                    },
                    RoleSummary {
                        id: "audit".to_owned(),
                        name: "Аудитор".to_owned(),
                        level: 20,
                    },
                ],
            },
        ]));

        let roles = engine.list_roles().unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].id, "serv");
        assert_eq!(roles[0].level, 10);
    }

    #[test]
    fn an_admission_carries_the_account_and_its_secret() {
        let engine = ServiceEngine::new(ScriptedConnector::new(&[ack(), admission()]));

        match engine.authenticate(request()).unwrap() {
            Verdict::Granted(grant) => {
                assert_eq!(grant.account, LogonTarget::local("tessera-session"));
                assert_eq!(grant.secret.as_str(), "machine-secret");
                assert_eq!(grant.session_id, "session-1");
            }
            Verdict::Denied(code) => panic!("expected a grant, got {code:?}"),
        }
    }

    #[test]
    fn the_role_and_pin_reach_the_service() {
        let connector = ScriptedConnector::new(&[ack(), admission()]);
        let written = Arc::clone(&connector.written);
        let engine = ServiceEngine::new(connector);

        let _ = engine.authenticate(request()).unwrap();

        let sent = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        assert!(sent.contains("\"role\":\"serv\""), "sent: {sent}");
        assert!(sent.contains("\"pin\":\"1234\""), "sent: {sent}");
    }

    #[test]
    fn every_refusal_category_comes_back_as_a_denial() {
        for (wire, expected) in [
            (DenialReason::Media, DenialCode::Media),
            (DenialReason::Credential, DenialCode::Credential),
            (DenialReason::Role, DenialCode::Role),
            (DenialReason::Internal, DenialCode::Internal),
        ] {
            let engine = ServiceEngine::new(ScriptedConnector::new(&[
                ack(),
                CpServerMessage::AuthenticateResult(AuthVerdict::Denied(Denial {
                    reason: wire,
                    code: 7,
                })),
            ]));

            match engine.authenticate(request()).unwrap() {
                Verdict::Denied(code) => assert_eq!(code, expected),
                Verdict::Granted(_) => panic!("a refusal became a grant for {wire:?}"),
            }
        }
    }

    #[test]
    fn a_service_that_is_not_there_is_unavailable() {
        let engine = ServiceEngine::new(ScriptedConnector::unavailable());
        assert_eq!(engine.list_roles().unwrap_err(), EngineError::Unavailable);
        assert_eq!(
            engine.authenticate(request()).unwrap_err(),
            EngineError::Unavailable
        );
    }

    #[test]
    fn a_connection_that_drops_mid_exchange_is_not_a_verdict() {
        // Greeting answered, then nothing: the reply the tile is waiting for
        // never arrives and the stream ends.
        let engine = ServiceEngine::new(ScriptedConnector::new(&[ack()]));
        assert_eq!(
            engine.authenticate(request()).unwrap_err(),
            EngineError::Disconnected
        );
    }

    #[test]
    fn a_version_mismatch_is_refused_before_the_pin_is_sent() {
        let connector = ScriptedConnector::new(&[CpServerMessage::HelloAck {
            server_version: "9.9.9".to_owned(),
            protocol_version: PROTOCOL_VERSION + 1,
        }]);
        let written = Arc::clone(&connector.written);
        let engine = ServiceEngine::new(connector);

        assert_eq!(
            engine.authenticate(request()).unwrap_err(),
            EngineError::ProtocolMismatch
        );
        let sent = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        assert!(
            !sent.contains("1234"),
            "the PIN reached a service of another version: {sent}"
        );
    }

    #[test]
    fn a_service_error_reply_is_reported_with_its_code() {
        let engine = ServiceEngine::new(ScriptedConnector::new(&[
            ack(),
            CpServerMessage::Error {
                code: error_codes::INTERNAL,
                message: "role store unreadable".to_owned(),
            },
        ]));

        assert_eq!(
            engine.list_roles().unwrap_err(),
            EngineError::Service {
                code: error_codes::INTERNAL
            }
        );
    }

    /// The property the deadline exists for: a service that never answers must
    /// not hold the caller. The scripted connector sleeps far longer than the
    /// deadline, and the call still returns.
    #[test]
    fn a_stuck_service_hits_the_deadline_instead_of_hanging() {
        let engine = ServiceEngine::with_timeout(
            ScriptedConnector::new(&[ack(), admission()]).with_delay(Duration::from_secs(30)),
            Duration::from_millis(50),
        );

        let started = std::time::Instant::now();
        let error = engine.authenticate(request()).unwrap_err();
        let waited = started.elapsed();

        assert_eq!(error, EngineError::Timeout);
        assert!(
            waited < Duration::from_secs(5),
            "the caller waited {waited:?}, which is not a deadline"
        );
    }

    #[test]
    fn the_deadline_also_covers_the_role_list() {
        let engine = ServiceEngine::with_timeout(
            ScriptedConnector::new(&[ack()]).with_delay(Duration::from_secs(30)),
            Duration::from_millis(50),
        );

        assert_eq!(engine.list_roles().unwrap_err(), EngineError::Timeout);
    }

    /// Each call is its own connection and its own handshake, so a service that
    /// was down when the screen appeared is picked up on the next attempt.
    #[test]
    fn each_call_opens_its_own_connection() {
        let connector = ScriptedConnector::new(&[ack(), admission()]);
        let connections = Arc::clone(&connector.connections);
        let engine = ServiceEngine::new(connector);

        let _ = engine.authenticate(request()).unwrap();
        let _ = engine.authenticate(request()).unwrap();

        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }
}

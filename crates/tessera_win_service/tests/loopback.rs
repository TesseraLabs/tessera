//! The two halves of the protocol against each other, over a real socket.
//!
//! The unit tests drive the server against scripted input and the client
//! against scripted output; neither would notice if the two disagreed. This
//! runs the shipped client against the shipped server over a loopback
//! connection, which is the same shape as the named pipe — a byte stream with a
//! reader and a writer at each end — on a platform where the test can run
//! everywhere.
//!
//! What it does not cover is the pipe itself: its security descriptor, its
//! instances, and the service that creates them. Those are Windows-only and are
//! exercised on the bench.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::BufReader;
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use tessera_proto::Client;
use tessera_proto::{Admission, AuthVerdict, Denial, DenialReason, RoleSummary, WireSecret};
use tessera_win_service::engine::{AuthEngine, AuthRequest, EngineError};
use tessera_win_service::protocol::{serve, Budgets, FrameTimeout, Session};

/// A socket that can bound its own reads, which is what the server requires of
/// a transport.
///
/// On Windows the shipped transport is an overlapped pipe; here it is a socket
/// with a read timeout. The two report an expired deadline differently —
/// `TimedOut` against `WouldBlock` — and the server accepts both, which is the
/// reason this stand-in tests something real rather than only itself.
struct BoundedStream(BufReader<TcpStream>);

impl std::io::Read for BoundedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::BufRead for BoundedStream {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.0.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.0.consume(amount);
    }
}

impl FrameTimeout for BoundedStream {
    fn set_frame_timeout(&mut self, budget: Duration) -> std::io::Result<()> {
        self.0.get_ref().set_read_timeout(Some(budget))
    }
}

/// The budgets the tests run with: short enough to observe, distinct enough to
/// tell apart.
fn budgets() -> Budgets {
    Budgets {
        handshake: Duration::from_millis(300),
        idle: Duration::from_millis(600),
        linger: Duration::from_millis(100),
    }
}

/// An engine that admits one PIN and refuses everything else.
struct Fixture;

impl AuthEngine for Fixture {
    fn list_roles(&self) -> Result<Vec<RoleSummary>, EngineError> {
        Ok(vec![
            RoleSummary {
                id: "audit".to_owned(),
                name: "Audit".to_owned(),
                level: 1,
            },
            RoleSummary {
                id: "serv".to_owned(),
                name: "Service".to_owned(),
                level: 5,
            },
        ])
    }

    fn authenticate(&self, request: &AuthRequest<'_>) -> Result<Admission, Denial> {
        if request.pin.expose() == "1234" {
            Ok(Admission {
                account: "tessera-logon".to_owned(),
                password: WireSecret::new("machine-password".to_owned()),
                role: request.role.to_owned(),
                role_version: 2,
                cert_cn: Some("alice".to_owned()),
                session_id: "win-1".to_owned(),
            })
        } else {
            Err(Denial {
                reason: DenialReason::Credential,
                code: 11,
            })
        }
    }
}

/// Serves one connection on a loopback listener and hands back the address.
fn spawn_server() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback must bind");
    let address = listener
        .local_addr()
        .expect("the socket must have an address");
    let handle = std::thread::spawn(move || {
        let (stream, _peer) = listener.accept().expect("a client must connect");
        let writer = stream.try_clone().expect("the stream must clone");
        let mut reader = BoundedStream(BufReader::new(stream));
        let mut writer = writer;
        let engine = Fixture;
        let mut session = Session::new(&engine, "0.5.0-test");
        // The client closing its end is how a connection normally ends.
        let _served = serve(&mut reader, &mut writer, &mut session, budgets());
    });
    (address, handle)
}

/// Connects a shipped client to a shipped server.
fn connect(address: std::net::SocketAddr) -> Client<BufReader<TcpStream>, TcpStream> {
    let stream = TcpStream::connect(address).expect("the server must accept");
    let writer = stream.try_clone().expect("the stream must clone");
    Client::connect(BufReader::new(stream), writer, "loopback-test")
        .expect("the handshake must succeed")
}

/// The whole tile flow in one connection: greet, list, admit.
#[test]
fn a_client_greets_lists_and_is_admitted() {
    let (address, server) = spawn_server();
    let mut client = connect(address);
    assert_eq!(client.server_version(), "0.5.0-test");

    let roles = client.list_roles().expect("roles must arrive");
    let ids: Vec<&str> = roles.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["audit", "serv"]);

    match client
        .authenticate("serv", "1234")
        .expect("a verdict must arrive")
    {
        AuthVerdict::Admitted(admission) => {
            assert_eq!(admission.account, "tessera-logon");
            assert_eq!(admission.password.expose(), "machine-password");
            assert_eq!(admission.role, "serv");
            assert_eq!(admission.cert_cn.as_deref(), Some("alice"));
        }
        AuthVerdict::Denied(denial) => panic!("expected an admission, got {denial:?}"),
    }

    drop(client);
    server.join().expect("the server thread must finish");
}

/// A refusal comes back as a verdict on a connection that stays usable.
#[test]
fn a_refusal_is_a_verdict_and_the_connection_survives_it() {
    let (address, server) = spawn_server();
    let mut client = connect(address);

    match client
        .authenticate("serv", "wrong")
        .expect("a verdict must arrive")
    {
        AuthVerdict::Denied(denial) => {
            assert_eq!(denial.reason, DenialReason::Credential);
            assert_eq!(denial.code, 11);
        }
        AuthVerdict::Admitted(a) => panic!("expected a refusal, got {a:?}"),
    }
    client
        .ping()
        .expect("the connection must survive a refusal");

    drop(client);
    server.join().expect("the server thread must finish");
}

/// A client that connects and never greets is let go on the handshake budget,
/// with a refusal it can still read.
///
/// This is the failure the deadline exists for: a credential provider that
/// hung after connecting. Before, it held a server thread and a pipe instance
/// until the service was restarted.
#[test]
fn a_silent_client_is_released_on_the_handshake_budget() {
    let (address, server) = spawn_server();
    let mut stream = TcpStream::connect(address).expect("the server must accept");
    // Say nothing at all, and read whatever the server says before it closes.
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("the client may bound its own read");

    let started = Instant::now();
    let mut reply = Vec::new();
    let read = std::io::Read::read_to_end(&mut stream, &mut reply);
    let elapsed = started.elapsed();
    assert!(read.is_ok(), "the server must close, not hang: {read:?}");

    let text = String::from_utf8(reply).expect("the refusal is UTF-8");
    let line = text.lines().next().expect("a refusal must have been sent");
    let message: tessera_proto::CpServerMessage =
        tessera_proto::decode_line(line).expect("the refusal must decode");
    assert!(
        matches!(
            message,
            tessera_proto::CpServerMessage::Error { code, .. }
                if code == tessera_proto::error_codes::PROTOCOL_VIOLATION
        ),
        "expected a protocol violation, got {message:?}"
    );
    assert!(
        elapsed >= budgets().handshake,
        "the server gave up before the budget: {elapsed:?}"
    );
    assert!(
        elapsed < budgets().idle * 4,
        "the server took far longer than the handshake budget: {elapsed:?}"
    );

    server.join().expect("the server thread must finish");
}

/// A client that greets and then falls silent is held for the longer budget,
/// not the handshake one — the engineer choosing a role and typing a PIN must
/// not be cut off by the clock meant for a program.
///
/// Driven at the byte level rather than through [`Client`], because the point
/// is what happens when the client sends *nothing*, and a client object has no
/// way to express that.
#[test]
fn a_greeted_client_gets_the_longer_budget() {
    let (address, server) = spawn_server();
    let mut stream = TcpStream::connect(address).expect("the server must accept");
    let hello = tessera_proto::encode_message(&tessera_proto::CpClientMessage::Hello {
        protocol_version: tessera_proto::PROTOCOL_VERSION,
        agent: Some("silent-after-hello".to_owned()),
    })
    .expect("the greeting must encode");
    std::io::Write::write_all(&mut stream, &hello).expect("the greeting must be sent");

    let started = Instant::now();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("the client may bound its own read");
    let mut reply = Vec::new();
    let read = std::io::Read::read_to_end(&mut stream, &mut reply);
    let elapsed = started.elapsed();
    assert!(read.is_ok(), "the server must close, not hang: {read:?}");

    let text = String::from_utf8(reply).expect("the replies are UTF-8");
    let mut lines = text.lines();
    let ack: tessera_proto::CpServerMessage =
        tessera_proto::decode_line(lines.next().expect("an acknowledgement is due"))
            .expect("the acknowledgement must decode");
    assert!(matches!(
        ack,
        tessera_proto::CpServerMessage::HelloAck { .. }
    ));
    let refusal: tessera_proto::CpServerMessage =
        tessera_proto::decode_line(lines.next().expect("a refusal is due"))
            .expect("the refusal must decode");
    assert!(matches!(
        refusal,
        tessera_proto::CpServerMessage::Error { code, .. }
            if code == tessera_proto::error_codes::PROTOCOL_VIOLATION
    ));

    assert!(
        elapsed >= budgets().idle,
        "a greeted client was measured against the wrong budget: {elapsed:?}"
    );

    server.join().expect("the server thread must finish");
}

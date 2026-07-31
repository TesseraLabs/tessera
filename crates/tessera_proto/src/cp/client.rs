//! The client half of the credential-provider protocol.
//!
//! It lives in the protocol crate, next to the messages it sends, because both
//! endpoints need it and neither may own it. The credential provider is a DLL
//! that `LogonUI` loads into the logon process; when this module lived in the
//! service's crate, depending on it dragged the whole verification core —
//! trust, roles, OpenSSL — into that process, eighteen times the binary for
//! code no path there reaches. Copying the client into the provider instead
//! would be worse: two clients for one protocol drift, and the one that drifts
//! unnoticed is the one standing on the login path.
//!
//! Like the server, it is written against a reader and a writer, so the
//! handshake and the reply handling are exercised without a pipe. The transport
//! is the caller's: a named pipe in the provider and in the service, an
//! in-memory pair in a test.
//!
//! Every call is a request and its reply on an already-greeted connection. The
//! handshake happens once, in [`Client::connect`], and a server that answers it
//! with anything but a matching acknowledgement is refused there — before a PIN
//! has been anywhere near the wire.

use std::io::{BufRead, Write};

use super::{AuthVerdict, CpClientMessage, CpServerMessage, RoleSummary, WireSecret};
use crate::PROTOCOL_VERSION;
use zeroize::Zeroize as _;

/// Why a client call did not produce an answer.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The transport failed.
    #[error("connection io: {0}")]
    Io(#[from] std::io::Error),
    /// A frame could not be encoded or decoded.
    #[error("wire: {0}")]
    Wire(#[from] crate::WireError),
    /// The server closed the connection without answering.
    #[error("the service closed the connection")]
    Closed,
    /// The server answered something other than the reply to this request.
    #[error("unexpected reply from the service")]
    Unexpected,
    /// The server reported an error.
    #[error("service error {code}: {message}")]
    Server {
        /// Numeric code from the shared table.
        code: u32,
        /// The server's message.
        message: String,
    },
    /// The server speaks another version of the protocol.
    #[error("protocol version mismatch: the service speaks {server}, this client speaks {ours}")]
    Version {
        /// Version the server reported.
        server: u32,
        /// Version this client was built with.
        ours: u32,
    },
}

/// A greeted connection to the service.
pub struct Client<R: BufRead, W: Write> {
    reader: R,
    writer: W,
    /// Version the service reported, kept for diagnostics.
    server_version: String,
}

impl<R: BufRead, W: Write> std::fmt::Debug for Client<R, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("server_version", &self.server_version)
            .finish_non_exhaustive()
    }
}

impl<R: BufRead, W: Write> Client<R, W> {
    /// Performs the handshake over `reader`/`writer`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Version`] when the service speaks another version,
    /// [`ClientError::Server`] when it refuses the greeting, and the transport
    /// errors otherwise.
    pub fn connect(reader: R, writer: W, agent: &str) -> Result<Self, ClientError> {
        let mut client = Self {
            reader,
            writer,
            server_version: String::new(),
        };
        let reply = client.exchange(&CpClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            agent: Some(agent.to_owned()),
        })?;
        match reply {
            CpServerMessage::HelloAck {
                server_version,
                protocol_version,
            } => {
                if protocol_version != PROTOCOL_VERSION {
                    return Err(ClientError::Version {
                        server: protocol_version,
                        ours: PROTOCOL_VERSION,
                    });
                }
                client.server_version = server_version;
                Ok(client)
            }
            CpServerMessage::Error { code, message } => Err(ClientError::Server { code, message }),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// The service's build version, as reported in the handshake.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Asks for the roles the tile should offer.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the service refuses or the transport fails.
    pub fn list_roles(&mut self) -> Result<Vec<RoleSummary>, ClientError> {
        match self.exchange(&CpClientMessage::ListRoles)? {
            CpServerMessage::RoleList { roles } => Ok(roles),
            CpServerMessage::Error { code, message } => Err(ClientError::Server { code, message }),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Asks for a verdict on the credential currently on removable media.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the service could not answer at all. A refusal is
    /// an answer and comes back as [`AuthVerdict::Denied`].
    pub fn authenticate(&mut self, role: &str, pin: &str) -> Result<AuthVerdict, ClientError> {
        let request = CpClientMessage::AuthenticateRequest {
            role: role.to_owned(),
            pin: WireSecret::new(pin.to_owned()),
        };
        match self.exchange(&request)? {
            CpServerMessage::AuthenticateResult(verdict) => Ok(verdict),
            CpServerMessage::Error { code, message } => Err(ClientError::Server { code, message }),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Liveness check.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the service does not answer with a pong.
    pub fn ping(&mut self) -> Result<(), ClientError> {
        match self.exchange(&CpClientMessage::Ping)? {
            CpServerMessage::Pong => Ok(()),
            CpServerMessage::Error { code, message } => Err(ClientError::Server { code, message }),
            _ => Err(ClientError::Unexpected),
        }
    }

    /// Sends one message and reads one reply.
    fn exchange(&mut self, message: &CpClientMessage) -> Result<CpServerMessage, ClientError> {
        let mut encoded = crate::encode_message(message)?;
        let sent = self
            .writer
            .write_all(&encoded)
            .and_then(|()| self.writer.flush());
        // The request buffer held the PIN.
        encoded.zeroize();
        sent?;

        let mut line = Vec::with_capacity(1024);
        if crate::wire::read_frame(&mut self.reader, &mut line)?.is_none() {
            return Err(ClientError::Closed);
        }
        let reply = crate::decode_bytes::<CpServerMessage>(&line);
        // The reply buffer held the account password.
        line.zeroize();
        Ok(reply?)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Encodes a scripted set of server replies.
    fn script(messages: &[CpServerMessage]) -> Cursor<Vec<u8>> {
        let mut bytes = Vec::new();
        for message in messages {
            bytes.extend_from_slice(&crate::encode_message(message).unwrap());
        }
        Cursor::new(bytes)
    }

    fn ack() -> CpServerMessage {
        CpServerMessage::HelloAck {
            server_version: "0.5.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
        }
    }

    #[test]
    fn a_greeted_connection_lists_roles() {
        let reader = script(&[
            ack(),
            CpServerMessage::RoleList {
                roles: vec![RoleSummary {
                    id: "serv".to_owned(),
                    name: "Service".to_owned(),
                    level: 1,
                }],
            },
        ]);
        let mut client = Client::connect(reader, Vec::new(), "test").unwrap();
        assert_eq!(client.server_version(), "0.5.0");
        let roles = client.list_roles().unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, "serv");
    }

    /// A service on another version is refused at the handshake, so no PIN is
    /// ever sent to something this client does not understand.
    #[test]
    fn a_mismatched_service_is_refused_at_the_handshake() {
        let reader = script(&[CpServerMessage::HelloAck {
            server_version: "9.9.9".to_owned(),
            protocol_version: PROTOCOL_VERSION + 1,
        }]);
        let err = Client::connect(reader, Vec::new(), "test").unwrap_err();
        assert!(matches!(err, ClientError::Version { .. }), "got {err:?}");
    }

    #[test]
    fn a_closed_connection_is_not_a_verdict() {
        let reader = script(&[ack()]);
        let mut client = Client::connect(reader, Vec::new(), "test").unwrap();
        let err = client.authenticate("serv", "1234").unwrap_err();
        assert!(matches!(err, ClientError::Closed), "got {err:?}");
    }

    #[test]
    fn a_refusal_comes_back_as_a_verdict_not_an_error() {
        let reader = script(&[
            ack(),
            CpServerMessage::AuthenticateResult(AuthVerdict::Denied(crate::cp::Denial {
                reason: crate::cp::DenialReason::Role,
                code: 6,
            })),
        ]);
        let mut client = Client::connect(reader, Vec::new(), "test").unwrap();
        match client.authenticate("serv", "1234").unwrap() {
            AuthVerdict::Denied(d) => assert_eq!(d.code, 6),
            other @ AuthVerdict::Admitted(_) => panic!("expected a denial, got {other:?}"),
        }
    }

    /// The service reporting an error to a request is an error, not a silent
    /// empty answer.
    #[test]
    fn a_server_error_surfaces() {
        let reader = script(&[
            ack(),
            CpServerMessage::Error {
                code: crate::error_codes::INTERNAL,
                message: "role list unavailable".to_owned(),
            },
        ]);
        let mut client = Client::connect(reader, Vec::new(), "test").unwrap();
        let err = client.list_roles().unwrap_err();
        assert!(matches!(err, ClientError::Server { code, .. } if code == 1500));
    }
}

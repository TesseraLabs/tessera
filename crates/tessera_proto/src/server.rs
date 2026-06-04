//! Daemon-to-client messages.

/// Server message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Hello acknowledgement (server → client after a successful Hello).
    HelloAck {
        /// Server build version, e.g. `0.6.0`.
        server_version: String,
        /// Negotiated wire-protocol version.
        protocol_version: u32,
    },
    /// Generic acknowledgement of a request.
    Ack,
    /// Reply to a [`crate::ClientMessage::UpdateSessionTarget`] request.
    ///
    /// Added in 0.3.10. A separate variant from [`Self::Ack`] so that the
    /// client can distinguish "daemon accepted the update" from "daemon
    /// accepted some other request"; this also makes it trivial for old
    /// daemons (which don't know `UpdateSessionTarget`) to fall through to
    /// `BAD_REQUEST` without the client confusing the responses.
    SessionTargetUpdated {
        /// Session id that was updated.
        session_id: String,
    },
    /// Pong (response to Ping).
    Pong,
    /// Reply to a [`crate::ClientMessage::GetActiveSessionByUid`] lookup.
    ///
    /// Carries the engineer cert metadata that PAM recorded when the
    /// session was opened.
    ActiveSession {
        /// Session id recorded at `SessionOpen` time.
        session_id: String,
        /// Common-Name from the engineer's leaf cert.
        cert_cn: String,
        /// Lowercase hex of the engineer cert's `SubjectKeyIdentifier`.
        engineer_ski: String,
        /// Lowercase hex of `SHA-256(cert DER)` of the engineer leaf.
        engineer_cert_sha256: String,
        /// Hex-encoded host id hash recorded at session open time.
        host_id_hash: String,
    },
    /// Error response.
    Error {
        /// Numeric error code (see [`error_codes`]).
        code: u32,
        /// Human-readable message.
        message: String,
    },
}

/// Numeric error codes used in [`ServerMessage::Error`].
pub mod error_codes {
    /// Client and server protocol versions disagree.
    pub const PROTOCOL_MISMATCH: u32 = 1000;
    /// USB device referenced by `SessionOpen` is gone.
    pub const DEVICE_GONE: u32 = 1001;
    /// Peer is not authorised to talk to monitord.
    pub const UNAUTHORIZED: u32 = 1003;
    /// Request was malformed.
    pub const BAD_REQUEST: u32 = 1100;
    /// Wire-protocol violation: oversize frame, idle timeout, or other
    /// framing-level breach. The server closes the connection after
    /// sending this code.
    pub const PROTOCOL_VIOLATION: u32 = 1101;
    /// Internal server error.
    pub const INTERNAL: u32 = 1500;
    /// No active session matches the requested uid.
    ///
    /// Returned by a v2 daemon in response to
    /// `GetActiveSessionByUid` when no session is currently tracked
    /// for the supplied uid.
    pub const NO_ACTIVE_SESSION: u32 = 1200;
}

/// Legacy enum-style code preserved for backwards-compat with stage-1 callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerErrorCode {
    /// Protocol mismatch.
    ProtocolMismatch,
    /// Bad request.
    BadRequest,
    /// Internal error.
    Internal,
    /// Device gone.
    DeviceGone,
    /// Unauthorized peer.
    Unauthorized,
}

impl ServerErrorCode {
    /// Map a numeric error code to its enum form.
    #[must_use]
    pub fn from_numeric(code: u32) -> Self {
        match code {
            error_codes::PROTOCOL_MISMATCH => Self::ProtocolMismatch,
            error_codes::DEVICE_GONE => Self::DeviceGone,
            error_codes::UNAUTHORIZED => Self::Unauthorized,
            error_codes::BAD_REQUEST => Self::BadRequest,
            _ => Self::Internal,
        }
    }

    /// Map an enum code to its numeric form.
    #[must_use]
    pub fn to_numeric(self) -> u32 {
        match self {
            Self::ProtocolMismatch => error_codes::PROTOCOL_MISMATCH,
            Self::DeviceGone => error_codes::DEVICE_GONE,
            Self::Unauthorized => error_codes::UNAUTHORIZED,
            Self::BadRequest => error_codes::BAD_REQUEST,
            Self::Internal => error_codes::INTERNAL,
        }
    }
}

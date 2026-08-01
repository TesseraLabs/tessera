//! Messages of the credential-provider flow, carried over the Windows named
//! pipe.
//!
//! The framing ([`crate::wire`]), the protocol version
//! ([`crate::PROTOCOL_VERSION`]) and the error codes
//! ([`crate::error_codes`]) are the ones the `AF_UNIX` contract already
//! defines; only the message catalogue is new, and only this transport carries
//! it.
//!
//! These messages are a separate pair of enums rather than new variants of
//! [`crate::ClientMessage`] / [`crate::ServerMessage`] for two reasons. The
//! first is the requirement that the `AF_UNIX` server refuse them: a frame that
//! does not decode as a `ClientMessage` at all is refused by the existing
//! `BAD_REQUEST` path, with no new arm to write and no way to forget one. The
//! second is [`WireSecret`], which is neither comparable nor printable and so
//! cannot live inside enums whose `PartialEq` half the daemon relies on.
//!
//! # Secrets on this wire
//!
//! Two fields carry secrets: the PIN travelling to the service and the
//! technical account's password travelling back. Both are [`WireSecret`], which
//! wipes itself when dropped and never prints its contents. That covers the
//! message value only — the encoded frame is ordinary bytes. The split is:
//! [`crate::encode_message`] wipes the intermediate buffers it makes itself,
//! and whoever holds the frame it returns — or the line it decoded from — wipes
//! that, because only that side knows when the frame has been written out. The
//! pipe itself is not the boundary that protects these fields: its security
//! descriptor is (see the `windows-tcb-service` delta of `ipc-protocol`).

pub mod client;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string field that must not outlive its use: wiped on drop, redacted in
/// `Debug`.
///
/// This is not encryption and not a memory-safety guarantee — a `String` that
/// reallocates leaves its old buffer behind, and the encoded frame is plain
/// bytes either way. It removes the two failure modes that actually happen:
/// a secret that lingers in freed memory for the lifetime of the process, and
/// a secret that reaches a log line because something derived `Debug`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct WireSecret(String);

impl WireSecret {
    /// Wraps `value`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The wrapped value. Every call site of this is a place where the secret
    /// exists in the clear, so there are deliberately no convenience
    /// conversions that hide one.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WireSecret([redacted])")
    }
}

/// One role as the tile's combo box needs it.
///
/// `level` is the display-ordering hint carried by the role slice. The core
/// never compares roles by it — the service sorts the list with it so that two
/// tiles on two devices present the same roles in the same order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSummary {
    /// Role id (role-format: `^[a-z][a-z0-9-]{0,15}$`).
    pub id: String,
    /// Human-readable name for the UI.
    pub name: String,
    /// Display-ordering hint from the slice.
    pub level: u8,
}

/// Credential-provider → service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CpClientMessage {
    /// Must be the first frame on any connection; the version is compared for
    /// strict equality and a mismatch closes the connection.
    Hello {
        /// Wire-protocol version (matches [`crate::PROTOCOL_VERSION`]).
        protocol_version: u32,
        /// Optional human-readable agent name (`tessera_cp/0.5.0`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<String>,
    },
    /// Ask for the roles the tile should offer.
    ListRoles,
    /// Ask for a verdict on the credential currently presented on removable
    /// media, for the selected role.
    ///
    /// No credential material travels in this message: the service finds the
    /// volume and reads the credential itself, so a compromised client cannot
    /// substitute one.
    AuthenticateRequest {
        /// Selected role id.
        role: String,
        /// PIN protecting the credential.
        pin: WireSecret,
    },
    /// Liveness check.
    Ping,
}

/// Service → credential provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CpServerMessage {
    /// Hello acknowledgement.
    HelloAck {
        /// Service build version.
        server_version: String,
        /// Wire-protocol version (equal to the client's, by construction).
        protocol_version: u32,
    },
    /// Reply to [`CpClientMessage::ListRoles`], ordered by `level` then id.
    RoleList {
        /// The roles of this device's store, without a default entry: the
        /// engineer chooses explicitly.
        roles: Vec<RoleSummary>,
    },
    /// Reply to [`CpClientMessage::AuthenticateRequest`].
    AuthenticateResult(AuthVerdict),
    /// Pong.
    Pong,
    /// Error response, using the codes of [`crate::error_codes`].
    Error {
        /// Numeric error code.
        code: u32,
        /// Human-readable message.
        message: String,
    },
}

/// What the service concluded about a presented credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum AuthVerdict {
    /// The credential was accepted.
    Admitted(Admission),
    /// The credential, the media, or the role was refused.
    Denied(Denial),
}

/// The parameters a client needs to open a session after an admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admission {
    /// Local account the session is opened under.
    pub account: String,
    /// That account's password.
    ///
    /// A wave-1 shortcut named in the design: the password is fixed rather than
    /// rotated per admission, so possession of it is possession of a login. The
    /// client must wipe it as soon as the logon structure is built.
    pub password: WireSecret,
    /// Role the attempt was made for.
    pub role: String,
    /// Resolved role slice version, recorded for audit.
    pub role_version: u32,
    /// Common Name of the validated end-entity certificate, when it carries
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_cn: Option<String>,
    /// Correlation id shared with the service's journal entry.
    pub session_id: String,
}

/// Why an attempt was refused.
///
/// The reason is deliberately coarse. The full cause — which stage refused and
/// why — is in the service's journal, where it is available to whoever
/// investigates and to nobody standing at the tile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Denial {
    /// Coarse category, for what the tile shows.
    pub reason: DenialReason,
    /// The code the same failure would return on the PAM path, so that one
    /// refusal table serves both platforms.
    pub code: i32,
}

/// Coarse refusal categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// No usable media appeared, or none carried a credential.
    Media,
    /// A credential was found and did not pass verification (chain, PIN,
    /// revocation, binding).
    Credential,
    /// The credential is valid but does not cover the requested role, or the
    /// role is not one this device offers.
    Role,
    /// The service could not reach a verdict (configuration, journal, internal
    /// invariant). Fail-closed: this is a refusal, not a pass.
    Internal,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// A secret must not reach a log line through `Debug`, however it is
    /// nested — this is the property the redaction exists for.
    #[test]
    fn secrets_are_redacted_in_debug() {
        let msg = CpClientMessage::AuthenticateRequest {
            role: "serv".to_owned(),
            pin: WireSecret::new("1234-secret".to_owned()),
        };
        let rendered = format!("{msg:?}");
        assert!(
            !rendered.contains("1234-secret"),
            "PIN leaked into Debug: {rendered}"
        );
    }

    /// The PIN crosses the wire as a plain JSON string: the transport carries
    /// it, the wrapper only bounds its lifetime in memory.
    #[test]
    fn pin_round_trips_through_the_wire() {
        let msg = CpClientMessage::AuthenticateRequest {
            role: "serv".to_owned(),
            pin: WireSecret::new("1234".to_owned()),
        };
        let bytes = crate::encode_message(&msg).unwrap();
        let back: CpClientMessage = crate::decode_bytes(&bytes).unwrap();
        match back {
            CpClientMessage::AuthenticateRequest { role, pin } => {
                assert_eq!(role, "serv");
                assert_eq!(pin.expose(), "1234");
            }
            other => panic!("expected an authenticate request, got {other:?}"),
        }
    }

    /// The client's frames must not decode as daemon frames: that is what
    /// keeps the CP catalogue off the `AF_UNIX` socket without the daemon
    /// growing a rejection arm it could forget to write.
    #[test]
    fn cp_frames_do_not_decode_as_daemon_frames() {
        for msg in [
            CpClientMessage::ListRoles,
            CpClientMessage::AuthenticateRequest {
                role: "serv".to_owned(),
                pin: WireSecret::new("1234".to_owned()),
            },
        ] {
            let bytes = crate::encode_message(&msg).unwrap();
            assert!(
                crate::decode_bytes::<crate::ClientMessage>(&bytes).is_err(),
                "a CP frame decoded as a daemon frame: {msg:?}"
            );
        }
    }

    /// A verdict keeps its shape across the wire, including the optional CN.
    #[test]
    fn verdicts_round_trip() {
        let admitted = CpServerMessage::AuthenticateResult(AuthVerdict::Admitted(Admission {
            account: "tessera-session".to_owned(),
            password: WireSecret::new("pw".to_owned()),
            role: "serv".to_owned(),
            role_version: 7,
            cert_cn: Some("alice".to_owned()),
            session_id: "abc".to_owned(),
        }));
        let bytes = crate::encode_message(&admitted).unwrap();
        match crate::decode_bytes::<CpServerMessage>(&bytes).unwrap() {
            CpServerMessage::AuthenticateResult(AuthVerdict::Admitted(a)) => {
                assert_eq!(a.password.expose(), "pw");
                assert_eq!(a.role_version, 7);
                assert_eq!(a.cert_cn.as_deref(), Some("alice"));
            }
            other => panic!("expected an admission, got {other:?}"),
        }

        let denied = CpServerMessage::AuthenticateResult(AuthVerdict::Denied(Denial {
            reason: DenialReason::Role,
            code: 6,
        }));
        let bytes = crate::encode_message(&denied).unwrap();
        match crate::decode_bytes::<CpServerMessage>(&bytes).unwrap() {
            CpServerMessage::AuthenticateResult(AuthVerdict::Denied(d)) => {
                assert_eq!(d.reason, DenialReason::Role);
                assert_eq!(d.code, 6);
            }
            other => panic!("expected a denial, got {other:?}"),
        }
    }
}

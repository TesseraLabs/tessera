//! The wire between the PAM module and the QR overlay of a graphical login.
//!
//! On a text console the device draws the QR itself ([`super::qr`]). On a
//! graphical login there is no console to draw on: the greeter owns the screen,
//! and the symbol has to be put on top of it by a separate, unprivileged
//! process. This module is the contract between the two — the frames they
//! exchange and the states an attempt can end in — and nothing else.
//!
//! # What is here and what is not
//!
//! Here: the byte layout of a frame, its bounds, and a state machine for each
//! side that says which frame is acceptable when and what an attempt ended as.
//! Not here: a socket. Nothing in this module opens, binds, reads or writes a
//! file descriptor, on purpose — the rules below are the part that has to be
//! testable without a display manager, a running greeter and an X server, and
//! a module that also did the I/O could only be tested with all three.
//!
//! # The wire runs ONE WAY
//!
//! Module to overlay, and nothing comes back. The module sends
//! [`Message::Challenge`] once, [`Message::Refresh`] on rotation and
//! [`Message::Cancel`] at the end; the overlay draws what it is given and
//! knows nothing about nonces, codes or attempts beyond the identifier in the
//! header.
//!
//! That the wire is one-way is a security property and not a simplification.
//! The module is a cdylib inside `sshd`, `login` or a display manager and runs
//! as root; the overlay is unprivileged. A reverse direction would be the one
//! place where root parses a stream produced by an unprivileged process on a
//! machine anybody can walk up to — a whole state machine's worth of parsing,
//! for the sake of telling a journal *why* a symbol could not be drawn. The
//! module shuts down the read half of the socket, so there is nothing to parse
//! and nothing to get wrong.
//!
//! What the overlay does when it cannot draw: it writes the reason to its
//! standard error, which lands wherever the greeter's own does, and exits. The
//! module sees the socket close and records an attempt whose overlay went away
//! — which is true, and is as much as it needs to know to carry on with the
//! text path.
//!
//! There is also **no `SUBMIT` message**, and never was: the engineer types
//! the code into the greeter's own field. The design of 2026-07-03 lists one
//! for the mode where the overlay collects input, and that mode is not what is
//! being built. An overlay that cannot carry a code cannot be the thing that
//! leaks one.
//!
//! # Why every frame carries the attempt identifier
//!
//! The socket is per attempt, so in the ordinary case the identifier is
//! redundant. It is in the header anyway because the interesting case is not
//! the ordinary one: a stale overlay from a previous attempt, or a process that
//! connected to a socket name it guessed, must be told apart from the overlay
//! this attempt started. The identifier makes that a check rather than an
//! assumption, and a frame carrying the wrong one ends the attempt instead of
//! being ignored.
//!
//! # The socket the caller will open
//!
//! Binding belongs to the caller, but the properties it must hold do not: they
//! are stated as constants and a name derivation here, so that the rule and the
//! code that follows it do not drift apart. Mode `0600`, an owner the greeter
//! runs as, a root-owned runtime directory, a name that is not predictable
//! before the attempt exists, one accepted connection and a peer credential
//! check on it.

use core::fmt;

use tessera_codes_contract::challenge::PAYLOAD_BUDGET;

/// Magic of every frame — four bytes no other protocol on the box starts with.
const MAGIC: [u8; 4] = *b"TQRO";

/// Version of the framing.
///
/// A version rather than a feature bit: the two sides ship in the same package
/// and are upgraded together, so a mismatch is a broken installation and the
/// right answer to it is to refuse loudly rather than to negotiate.
pub const PROTOCOL_VERSION: u8 = 1;

/// Bytes of the fixed header: magic, version, kind, attempt, body length.
pub const HEADER_LEN: usize = 4 + 1 + 1 + ATTEMPT_ID_LEN + 2;

/// Bytes of an attempt identifier.
pub const ATTEMPT_ID_LEN: usize = 16;

/// Largest body a frame may carry.
///
/// The payload of an attempt is the largest thing that travels, and its bound
/// is the channel's, not this protocol's: a frame that could carry more than a
/// QR can hold would be a second, looser opinion about the same limit. Taking
/// [`PAYLOAD_BUDGET`] directly means the two cannot drift.
pub const MAX_BODY_LEN: usize = PAYLOAD_BUDGET;

/// Largest frame on the wire, header included.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_BODY_LEN;

/// Permission bits the attempt socket is created with.
///
/// The overlay runs as the greeter's user and nothing else on the box has any
/// business connecting, so the socket is created by the module as root and
/// given to that user: mode `0600` with the greeter's uid as owner. Mode alone
/// is the weaker half of the guarantee — a mode word says who *may* open the
/// socket and says nothing about who did — and the stronger half is the peer
/// credential check on the one connection that is accepted.
pub const SOCKET_MODE: u32 = 0o600;

/// Directory the attempt socket is created in.
///
/// Root-owned, and traversable by everyone without being listable by anyone:
/// mode `0711`. Both halves matter and they are not the same guarantee. Not
/// writable, so no other process can place a socket under the name this attempt
/// is about to use and be waiting there when the overlay connects. Not
/// listable, so the random name cannot be enumerated and has to be guessed.
/// Traversable, because the overlay runs as the greeter's user and would
/// otherwise not reach a socket it has the name of.
///
/// A directory of its own beside `/run/tessera` rather than inside it. The
/// daemon's directory is `0750 tessera:tessera`, and a traversal check applies
/// to every component of a path: a subdirectory under it would be unreachable
/// for the greeter's user however it was moded. Loosening the daemon's
/// directory to make one socket reachable would widen what the daemon's own
/// state is exposed to, which is a worse trade than a second directory.
pub const SOCKET_DIRECTORY: &str = "/run/tessera-overlay";

/// Permission bits of [`SOCKET_DIRECTORY`].
pub const SOCKET_DIRECTORY_MODE: u32 = 0o711;

const KIND_CHALLENGE: u8 = 1;
const KIND_REFRESH: u8 = 2;
const KIND_CANCEL: u8 = 3;
// 4 and 5 were `CLOSE` and `ERROR`, the overlay's half of a conversation that
// no longer exists. They are not reused: a build that still spoke them would
// otherwise have its frames read as something else by a build that does not.

/// Identifier of one login attempt.
///
/// Sixteen random bytes, chosen by the module when the attempt starts. Random
/// rather than a counter because the socket is named after it: a name a
/// bystander can predict is a name a bystander can occupy before the overlay
/// gets there.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AttemptId([u8; ATTEMPT_ID_LEN]);

impl AttemptId {
    /// Wraps sixteen bytes the caller drew from a cryptographic source.
    ///
    /// The source is the caller's, not this module's: the device already has
    /// one for its nonces, and a second generator here would be a second thing
    /// to get wrong.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ATTEMPT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes of the identifier.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ATTEMPT_ID_LEN] {
        &self.0
    }

    /// The name of the socket this attempt is served on, without a directory.
    ///
    /// Lowercase hexadecimal of the identifier under a fixed prefix. The name
    /// is derived rather than stored so that a caller cannot end up serving one
    /// attempt on another attempt's socket.
    #[must_use]
    pub fn socket_name(&self) -> String {
        let mut name = String::with_capacity(8 + ATTEMPT_ID_LEN * 2);
        name.push_str("attempt-");
        for byte in self.0 {
            // Two lowercase hex digits per byte, written out rather than
            // formatted: the name is part of an interface, and `{:x}` on a
            // slice is not what it looks like.
            name.push(hex_digit(byte >> 4));
            name.push(hex_digit(byte & 0x0f));
        }
        name
    }
}

impl fmt::Debug for AttemptId {
    /// Prints the identifier as its socket name.
    ///
    /// A `Debug` that dumped the array would put sixteen decimal numbers in a
    /// failure message, and the thing a reader needs to compare it against —
    /// the socket on the box — is the hex form.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.socket_name())
    }
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

/// Why the overlay gave up.
///
/// The overlay's own account of itself, for its own standard error and its own
/// state. It does NOT travel: nothing the overlay produces reaches the module,
/// which is what keeps root out of the business of parsing an unprivileged
/// process's output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayError {
    /// The frame did not parse, or the version did not match.
    Protocol,
    /// The payload arrived but could not be turned into a symbol.
    Payload,
    /// The display refused the window.
    Display,
    /// Something else went wrong on the overlay's side.
    Internal,
}

/// One message of the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Module to overlay: draw this payload.
    Challenge(String),
    /// Module to overlay: replace the drawing with this payload.
    Refresh(String),
    /// Module to overlay: the attempt is over, take the window down.
    Cancel,
}

impl Message {
    const fn kind(&self) -> u8 {
        match self {
            Self::Challenge(_) => KIND_CHALLENGE,
            Self::Refresh(_) => KIND_REFRESH,
            Self::Cancel => KIND_CANCEL,
        }
    }
}

/// A frame that did not hold a message.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Fewer bytes than a frame needs.
    ///
    /// Not a request for more bytes: this module does not buffer. A reader that
    /// wants to wait for the rest has the length in the header and can ask for
    /// it; a reader that got this after the peer closed has a truncated frame.
    #[error("the frame is {got} bytes, and a frame needs at least {needed}")]
    Short {
        /// Bytes a frame needs before it can be read at all.
        needed: usize,
        /// Bytes there were.
        got: usize,
    },

    /// The first four bytes are not this protocol's.
    #[error("the frame does not start with the magic of this protocol")]
    Magic,

    /// A version this build does not speak.
    #[error("the frame is version {got}, and this build speaks version {PROTOCOL_VERSION}")]
    Version {
        /// The version the frame declared.
        got: u8,
    },

    /// A message kind this build does not know.
    #[error("the frame carries no message kind {got}")]
    Kind {
        /// The kind byte the frame carried.
        got: u8,
    },

    /// The declared body length is beyond the bound.
    #[error("the frame declares {got} bytes of body, and the bound is {MAX_BODY_LEN}")]
    TooLong {
        /// The body length the header declared.
        got: usize,
    },

    /// The body is not the length the header declared.
    #[error("the frame declares {declared} bytes of body and carries {got}")]
    Length {
        /// The body length the header declared.
        declared: usize,
        /// The body length the frame actually carried.
        got: usize,
    },

    /// The body of this kind of message is not what it must be.
    #[error("the body of this message does not hold what its kind requires")]
    Body,

    /// The payload is not valid UTF-8.
    #[error("the payload is not UTF-8")]
    Encoding,

    /// A payload longer than the channel allows.
    #[error("the payload is {got} bytes, and the budget is {MAX_BODY_LEN}")]
    Payload {
        /// The length of the payload the caller offered.
        got: usize,
    },
}

/// Encodes one message of an attempt into its frame.
///
/// # Errors
///
/// [`FrameError::Payload`] when the payload is longer than the channel allows.
/// A caller that hit this has a bug upstream: the payload budget is checked
/// where the payload is built, and a payload that outgrew it would not have
/// fitted in a QR either.
pub fn encode(attempt: AttemptId, message: &Message) -> Result<Vec<u8>, FrameError> {
    let body: &[u8] = match message {
        Message::Challenge(payload) | Message::Refresh(payload) => payload.as_bytes(),
        Message::Cancel => &[],
    };
    if body.len() > MAX_BODY_LEN {
        return Err(FrameError::Payload { got: body.len() });
    }

    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.extend_from_slice(&MAGIC);
    frame.push(PROTOCOL_VERSION);
    frame.push(message.kind());
    frame.extend_from_slice(attempt.as_bytes());
    // The bound above keeps this inside `u16`; `MAX` is unreachable and would
    // be caught by the length check on the other side rather than truncating.
    let declared = u16::try_from(body.len()).unwrap_or(u16::MAX);
    frame.extend_from_slice(&declared.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

/// Decodes exactly one frame, and the attempt it belongs to.
///
/// The whole frame and nothing after it: a caller that read more than one frame
/// out of the socket has to split them on the declared length, which is what
/// [`declared_frame_len`] is for. Accepting trailing bytes here would make a
/// frame with something appended to it indistinguishable from a clean one.
///
/// # Errors
///
/// Every way a frame can fail to be a frame — see [`FrameError`].
pub fn decode(frame: &[u8]) -> Result<(AttemptId, Message), FrameError> {
    // The header is taken apart by pattern rather than by offsets: an offset
    // written twice is an offset that can be written differently the second
    // time, and the two halves of this protocol are compiled from this one file.
    let Some((header, body)) = frame.split_at_checked(HEADER_LEN) else {
        return Err(FrameError::Short {
            needed: HEADER_LEN,
            got: frame.len(),
        });
    };
    let Ok(&[magic_0, magic_1, magic_2, magic_3, version, kind, ref tail @ ..]) =
        <&[u8; HEADER_LEN]>::try_from(header)
    else {
        // Unreachable: the split above yielded exactly `HEADER_LEN` bytes.
        return Err(FrameError::Short {
            needed: HEADER_LEN,
            got: frame.len(),
        });
    };
    if [magic_0, magic_1, magic_2, magic_3] != MAGIC {
        return Err(FrameError::Magic);
    }
    if version != PROTOCOL_VERSION {
        return Err(FrameError::Version { got: version });
    }
    let [attempt @ .., length_high, length_low] = *tail;
    let declared = usize::from(u16::from_be_bytes([length_high, length_low]));
    if declared > MAX_BODY_LEN {
        return Err(FrameError::TooLong { got: declared });
    }
    if body.len() != declared {
        return Err(FrameError::Length {
            declared,
            got: body.len(),
        });
    }

    let message = match kind {
        KIND_CHALLENGE | KIND_REFRESH => {
            let payload = core::str::from_utf8(body)
                .map_err(|_| FrameError::Encoding)?
                .to_owned();
            if payload.is_empty() {
                return Err(FrameError::Body);
            }
            if kind == KIND_CHALLENGE {
                Message::Challenge(payload)
            } else {
                Message::Refresh(payload)
            }
        }
        KIND_CANCEL => {
            if !body.is_empty() {
                return Err(FrameError::Body);
            }
            Message::Cancel
        }
        other => return Err(FrameError::Kind { got: other }),
    };
    Ok((AttemptId(attempt), message))
}

/// The full length of the frame beginning at `bytes`, if its header is there.
///
/// For a reader that has to know how much to take off the stream before it can
/// decode anything. [`None`] means the header is not complete yet; a header
/// declaring more than the bound is a frame this build will refuse, and saying
/// so here lets a reader stop instead of waiting for bytes it will throw away.
///
/// # Errors
///
/// [`FrameError::TooLong`] when the declared body is beyond the bound.
pub fn declared_frame_len(bytes: &[u8]) -> Result<Option<usize>, FrameError> {
    let Some((header, _)) = bytes.split_at_checked(HEADER_LEN) else {
        return Ok(None);
    };
    let Some((_, &[length_high, length_low])) = header.split_last_chunk::<2>() else {
        // Unreachable: the split above yielded exactly `HEADER_LEN` bytes.
        return Ok(None);
    };
    let declared = usize::from(u16::from_be_bytes([length_high, length_low]));
    if declared > MAX_BODY_LEN {
        return Err(FrameError::TooLong { got: declared });
    }
    Ok(Some(HEADER_LEN + declared))
}

/// How an attempt on this channel ended.
///
/// Every path out of the session lands in exactly one of these, including the
/// paths that are not messages at all — a peer that vanished, a wait that ran
/// out. That is the point of the type: the cleanup a caller has to do is the
/// same in all of them (take down the socket, unlink the name, stop drawing),
/// and a session that could end in "none of the above" would leave a caller
/// deciding for itself whether it had.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ending {
    /// The module ended the attempt: the code was accepted, refused, or the
    /// attempt was abandoned elsewhere.
    Cancelled,
    /// The overlay gave up and said why.
    Failed(OverlayError),
    /// The peer went away without a word — the overlay crashed, or the module
    /// exited under it.
    Lost,
    /// Nothing arrived in time.
    TimedOut,
    /// What arrived was not part of this conversation.
    ///
    /// A frame that did not parse, a frame out of turn, or a frame carrying
    /// another attempt's identifier. All three are the same kind of event —
    /// somebody on the other end of this socket is not the overlay this attempt
    /// started — and the session ends rather than skipping the frame, because
    /// an attempt that keeps talking to an unknown peer is the attempt an
    /// unknown peer wanted.
    Violation(SessionError),
}

/// Why a session refused a frame or a call.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The frame did not hold a message.
    #[error("the frame did not parse: {0}")]
    Frame(#[from] FrameError),

    /// The frame belongs to another attempt.
    #[error("the frame carries attempt {got:?}, and this session is attempt {expected:?}")]
    ForeignAttempt {
        /// The attempt this session belongs to.
        expected: AttemptId,
        /// The attempt the frame named.
        got: AttemptId,
    },

    /// A message that is legal in the protocol but not at this point.
    #[error("a message of this kind cannot arrive at this point of the attempt")]
    OutOfTurn,

    /// The session has already ended.
    #[error("the attempt has already ended")]
    Ended,
}

/// The frames the module sends, built for it.
///
/// A handful of functions rather than a session type. The module has no state
/// machine to run: it writes a challenge, may write a refresh, writes a cancel
/// and closes the socket. What it does NOT do is read — see the module
/// documentation — so there is nothing for a session to receive, and a type
/// that could receive would invite somebody to make it.
pub mod module {
    use super::{encode, AttemptId, FrameError, Message};

    /// The frame that opens an attempt.
    ///
    /// # Errors
    ///
    /// [`FrameError::Payload`] when the payload is over the channel's budget.
    pub fn challenge(attempt: AttemptId, payload: &str) -> Result<Vec<u8>, FrameError> {
        encode(attempt, &Message::Challenge(payload.to_owned()))
    }

    /// The frame that replaces the drawn payload with a fresh one.
    ///
    /// # Errors
    ///
    /// As [`challenge`].
    pub fn refresh(attempt: AttemptId, payload: &str) -> Result<Vec<u8>, FrameError> {
        encode(attempt, &Message::Refresh(payload.to_owned()))
    }

    /// The frame that ends the attempt.
    ///
    /// # Errors
    ///
    /// None in practice: the message carries no body. The result is kept so
    /// that a caller on a cleanup path has nothing to unwrap.
    pub fn cancel(attempt: AttemptId) -> Result<Vec<u8>, FrameError> {
        encode(attempt, &Message::Cancel)
    }
}

/// The overlay's half of one attempt.
///
/// The overlay learns the attempt identifier from the first frame rather than
/// being told it on the command line: a value on a command line is readable by
/// everything on the box, and the socket name already is.
#[derive(Debug, Default)]
pub struct OverlaySession {
    attempt: Option<AttemptId>,
    payload: Option<String>,
    ending: Option<Ending>,
}

/// What the overlay should do about a frame it just took.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlayAction {
    /// Draw this payload; nothing is on screen yet.
    Draw(String),
    /// Replace what is drawn with this payload.
    Redraw(String),
    /// The attempt is over — take the window down.
    Finish(Ending),
}

impl OverlaySession {
    /// A session that has not been connected to yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The payload currently on screen, if any.
    #[must_use]
    pub fn payload(&self) -> Option<&str> {
        self.payload.as_deref()
    }

    /// How the attempt ended, or [`None`] while it is still running.
    #[must_use]
    pub const fn ending(&self) -> Option<&Ending> {
        self.ending.as_ref()
    }

    /// Takes one frame that arrived from the module.
    ///
    /// # Errors
    ///
    /// [`SessionError::OutOfTurn`] when the first frame is not a challenge —
    /// an overlay that starts drawing on a refresh it never got a challenge for
    /// is an overlay that will draw for anybody who connects to it. The other
    /// refusals are the frame's own.
    pub fn receive(&mut self, frame: &[u8]) -> Result<OverlayAction, SessionError> {
        if self.ending.is_some() {
            return Err(SessionError::Ended);
        }
        let (attempt, message) = match decode(frame) {
            Ok(parsed) => parsed,
            Err(error) => return Err(self.violated(SessionError::Frame(error))),
        };
        match self.attempt {
            None => {
                if !matches!(message, Message::Challenge(_)) {
                    return Err(self.violated(SessionError::OutOfTurn));
                }
                self.attempt = Some(attempt);
            }
            Some(expected) if expected != attempt => {
                return Err(self.violated(SessionError::ForeignAttempt {
                    expected,
                    got: attempt,
                }))
            }
            Some(_) => {}
        }
        match message {
            Message::Challenge(payload) => {
                if self.payload.is_some() {
                    // A second challenge is not a refresh: the module sends one
                    // challenge per attempt, so a second one means the peer is
                    // replaying frames.
                    return Err(self.violated(SessionError::OutOfTurn));
                }
                self.payload = Some(payload.clone());
                Ok(OverlayAction::Draw(payload))
            }
            Message::Refresh(payload) => {
                self.payload = Some(payload.clone());
                Ok(OverlayAction::Redraw(payload))
            }
            Message::Cancel => {
                self.payload = None;
                Ok(OverlayAction::Finish(
                    self.ending.insert(Ending::Cancelled).clone(),
                ))
            }
        }
    }

    /// Records that the overlay gave up, and why.
    ///
    /// Local: the reason does not travel. The overlay says it on its standard
    /// error and stops; the module learns only that the socket closed.
    pub fn gave_up(&mut self, reason: OverlayError) -> &Ending {
        self.payload = None;
        self.ending.get_or_insert(Ending::Failed(reason))
    }

    /// Records that the module went away without a word.
    pub fn peer_lost(&mut self) -> &Ending {
        self.payload = None;
        self.ending.get_or_insert(Ending::Lost)
    }

    /// Records that nothing arrived within the wait the caller allowed.
    pub fn timed_out(&mut self) -> &Ending {
        self.payload = None;
        self.ending.get_or_insert(Ending::TimedOut)
    }

    fn violated(&mut self, error: SessionError) -> SessionError {
        self.payload = None;
        self.ending = Some(Ending::Violation(error.clone()));
        error
    }
}

#[cfg(test)]
mod tests;

//! Wire-protocol types between the PAM module and the monitord daemon.
//!
//! The wire format is newline-delimited JSON; each frame is a single line
//! ending in `\n`. See [`wire`] for encode/decode helpers.
//!
//! `ClientMessage` carries requests from the PAM module (and other clients)
//! to the daemon. `ServerMessage` is the reply. Every connection MUST start
//! with a `Hello` exchange — the daemon enforces a numeric protocol version
//! match and closes the connection on mismatch.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod client;
pub mod framing;
pub mod server;
pub mod session_target;
pub mod system_time_serde;
pub mod version;
pub mod wire;

pub use client::{ClientMessage, SessionOpenPayload};
pub use framing::{decode, encode, FramingError};
pub use server::{error_codes, ServerErrorCode, ServerMessage};
pub use session_target::SessionTarget;
pub use version::PROTOCOL_VERSION;
pub use wire::{decode_bytes, decode_line, encode_message, WireError, MAX_FRAME_BYTES};

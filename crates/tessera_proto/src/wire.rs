//! Newline-delimited JSON wire format.
//!
//! Each frame is a single line of UTF-8 JSON terminated by `\n`. Frames
//! larger than [`MAX_FRAME_BYTES`] are rejected to bound memory.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Maximum allowed frame size in bytes (excluding the trailing newline).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Wire-level errors.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Frame exceeds [`MAX_FRAME_BYTES`].
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    /// JSON encode failed.
    #[error("encode failed: {0}")]
    Encode(serde_json::Error),
    /// JSON decode failed.
    #[error("decode failed: {0}")]
    Decode(serde_json::Error),
    /// Encoded payload contains an embedded newline (impossible for valid JSON
    /// from `serde_json::to_vec`, but we double-check defensively).
    #[error("embedded newline")]
    EmbeddedNewline,
}

/// Encode a message to its on-the-wire representation.
///
/// The returned `Vec<u8>` ends with a single `b'\n'`.
///
/// # Errors
///
/// Returns [`WireError::Encode`] when `serde_json` fails, [`WireError::EmbeddedNewline`]
/// if the JSON itself contains a raw newline (impossible from `to_vec`),
/// and [`WireError::FrameTooLarge`] if the JSON body exceeds [`MAX_FRAME_BYTES`].
pub fn encode_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, WireError> {
    let bytes = serde_json::to_vec(msg).map_err(WireError::Encode)?;
    if bytes.contains(&b'\n') {
        return Err(WireError::EmbeddedNewline);
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge(bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.extend_from_slice(&bytes);
    out.push(b'\n');
    Ok(out)
}

/// Decode a single line into a message.
///
/// Trailing `\r` and `\n` characters are trimmed before decoding. Lines longer
/// than [`MAX_FRAME_BYTES`] are rejected with [`WireError::FrameTooLarge`].
///
/// # Errors
///
/// Returns [`WireError::FrameTooLarge`] when the line exceeds the limit and
/// [`WireError::Decode`] when JSON parsing fails.
pub fn decode_line<T: DeserializeOwned>(line: &str) -> Result<T, WireError> {
    if line.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge(line.len()));
    }
    let trimmed = line.trim_end_matches(['\n', '\r']);
    serde_json::from_str(trimmed).map_err(WireError::Decode)
}

/// Decode a slice of bytes into a message (parallel to [`decode_line`]).
///
/// # Errors
///
/// See [`decode_line`].
pub fn decode_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge(bytes.len()));
    }
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b'\n' || bytes[end - 1] == b'\r') {
        end -= 1;
    }
    serde_json::from_slice(&bytes[..end]).map_err(WireError::Decode)
}

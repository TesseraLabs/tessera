//! Newline-delimited JSON wire format.
//!
//! Each frame is a single line of UTF-8 JSON terminated by `\n`. Frames
//! larger than [`MAX_FRAME_BYTES`] are rejected to bound memory.

use std::io::BufRead;

use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroizing;

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
/// Messages carrying a secret are encoded through here, so the intermediate
/// JSON buffer is wiped on every path out — including the two error paths,
/// where the frame is never returned but the secret was already serialised into
/// it. Wiping the *returned* buffer stays with the caller, which is the only
/// side that knows when the frame has left.
///
/// # Errors
///
/// Returns [`WireError::Encode`] when `serde_json` fails, [`WireError::EmbeddedNewline`]
/// if the JSON itself contains a raw newline (impossible from `to_vec`),
/// and [`WireError::FrameTooLarge`] if the JSON body exceeds [`MAX_FRAME_BYTES`].
pub fn encode_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, WireError> {
    let bytes = Zeroizing::new(serde_json::to_vec(msg).map_err(WireError::Encode)?);
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
    let mut trimmed = bytes;
    while let Some((&last, rest)) = trimmed.split_last() {
        if last == b'\n' || last == b'\r' {
            trimmed = rest;
        } else {
            break;
        }
    }
    serde_json::from_slice(trimmed).map_err(WireError::Decode)
}

/// Reads one frame from a buffered stream.
///
/// This is the reading counterpart of [`encode_message`]: the encoder promises
/// one line per frame, and this is where that promise is relied on. It lives
/// beside the encoder rather than in either endpoint because a server and a
/// client that disagreed about where a frame ends would not be two
/// implementations of one protocol.
/// Reads one frame into `buf`, newline included.
///
/// Returns `Ok(None)` at a clean end of stream. The buffer never grows past
/// [`MAX_FRAME_BYTES`] plus the newline: the bound is enforced
/// while reading, not checked afterwards, so a peer that sends a gigabyte
/// without a newline cannot make the server allocate a gigabyte to find out.
///
/// # Errors
///
/// [`std::io::Error`] from the reader, or an `InvalidData` error when the frame
/// exceeds the limit or the stream ends mid-frame. The caller answers both with
/// a protocol violation and closes.
pub fn read_frame<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<Option<()>> {
    /// The limit including the terminating newline.
    const CAP: usize = MAX_FRAME_BYTES + 1;

    buf.clear();
    loop {
        let (consumed, outcome) = {
            let available = match reader.fill_buf() {
                Ok(available) => available,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if available.is_empty() {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Err(truncated());
            }
            if let Some(index) = available.iter().position(|byte| *byte == b'\n') {
                let wanted = index.saturating_add(1);
                if buf.len().saturating_add(wanted) > CAP {
                    (wanted, Frame::TooLarge)
                } else {
                    let Some(line) = available.get(..wanted) else {
                        return Err(truncated());
                    };
                    buf.extend_from_slice(line);
                    (wanted, Frame::Complete)
                }
            } else {
                let wanted = available.len();
                if buf.len().saturating_add(wanted) >= CAP {
                    (wanted, Frame::TooLarge)
                } else {
                    buf.extend_from_slice(available);
                    (wanted, Frame::More)
                }
            }
        };
        reader.consume(consumed);
        match outcome {
            Frame::Complete => return Ok(Some(())),
            Frame::TooLarge => return Err(oversize()),
            Frame::More => {}
        }
    }
}

/// What one pass over the buffered bytes established.
enum Frame {
    /// A whole frame is in the buffer.
    Complete,
    /// More bytes are needed.
    More,
    /// The frame is past the limit.
    TooLarge,
}

/// The error for a stream that ended in the middle of a frame.
fn truncated() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "the stream ended in the middle of a frame",
    )
}

/// The error for a frame past the limit.
fn oversize() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "frame exceeds the protocol limit",
    )
}

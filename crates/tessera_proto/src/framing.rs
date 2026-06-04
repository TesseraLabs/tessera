//! Newline-delimited JSON framing.

use serde::de::DeserializeOwned;

/// Framing error.
#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    /// Encode failed.
    #[error("encode failed: {0}")]
    Encode(serde_json::Error),
    /// Decode failed.
    #[error("decode failed: {0}")]
    Decode(serde_json::Error),
    /// Encoded message contains an embedded newline.
    #[error("embedded newline")]
    EmbeddedNewline,
}

/// Encode a message as newline-delimited JSON.
pub fn encode<M: serde::Serialize>(m: &M) -> Result<Vec<u8>, FramingError> {
    let mut bytes = serde_json::to_vec(m).map_err(FramingError::Encode)?;
    if bytes.contains(&b'\n') {
        return Err(FramingError::EmbeddedNewline);
    }
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decode a newline-delimited JSON message.
pub fn decode<M: DeserializeOwned>(line: &[u8]) -> Result<M, FramingError> {
    serde_json::from_slice(line).map_err(FramingError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientMessage;

    #[test]
    fn ping_round_trips() {
        let bytes = encode(&ClientMessage::Ping).unwrap_or_default();
        let decoded: ClientMessage = decode(&bytes).unwrap_or(ClientMessage::Ping);
        assert_eq!(decoded, ClientMessage::Ping);
    }
}

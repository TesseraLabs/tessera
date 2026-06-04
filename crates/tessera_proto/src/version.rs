//! Protocol version.

/// Wire-protocol version negotiated in the `Hello` exchange.
///
/// Bumped to `2` when the v2 messages were introduced:
/// - `ClientMessage::GetActiveSessionByUid`
/// - `ServerMessage::ActiveSession`
/// - new optional fields on `SessionOpen` / `SessionOpenPayload`
///   (`engineer_ski`, `engineer_cert_sha256`, `uid`)
/// - new error code `NO_ACTIVE_SESSION` (1200)
///
/// All new fields on the `SessionOpen` payload use `#[serde(default)]` so
/// frames produced by a v1 client (no new fields) still deserialise.
pub const PROTOCOL_VERSION: u32 = 2;

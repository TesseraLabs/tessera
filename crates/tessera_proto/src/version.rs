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
///
/// The role-format change adds two further optional `SessionOpen` fields
/// (`role`, `role_version`) within `PROTOCOL_VERSION` 2. They are optional NDJSON
/// fields (`#[serde(default, skip_serializing_if = "Option::is_none")]`):
/// frames without them deserialise into `None`, and a session opened with
/// `[roles].enforce = false` omits them entirely. This is backward compatible,
/// so no version bump is required (the strict-equality version rule is
/// preserved).
pub const PROTOCOL_VERSION: u32 = 2;

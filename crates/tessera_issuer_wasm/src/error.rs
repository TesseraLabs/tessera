//! The JSON error shape every binding returns on failure.
//!
//! A failure crosses the WASM boundary as a JSON object `{ "error": "...",
//! "dimension": "..."? }`: `error` is the core's technical, English message (the
//! same text the CLI surfaces), and `dimension` is present only when the failure
//! is a delegation-envelope violation, naming the widened dimension
//! (`require_tags`, `allow_roles`, `max_level`, `max_ttl`) so a caller can point
//! the operator at the exact field. The JS layer reads it from the thrown
//! value's message (see the crate documentation).

use serde::Serialize;

use tessera_issuer::IssueError;

/// A typed, JSON-serialisable binding error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ApiError {
    /// The technical, English failure message.
    pub error: String,
    /// The delegation-envelope dimension a widening violated, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimension: Option<String>,
}

impl ApiError {
    /// An error with a plain message and no dimension.
    pub(crate) fn msg(message: impl Into<String>) -> Self {
        Self {
            error: message.into(),
            dimension: None,
        }
    }

    /// An error naming a violated delegation-envelope dimension.
    pub(crate) fn dimension(message: impl Into<String>, dimension: &str) -> Self {
        Self {
            error: message.into(),
            dimension: Some(dimension.to_owned()),
        }
    }

    /// Serialises to the JSON string returned across the boundary. Serialising a
    /// two-field struct of owned strings cannot fail, but a fixed fallback keeps
    /// the path panic-free either way.
    pub(crate) fn to_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| r#"{"error":"internal: could not serialise the error"}"#.to_owned())
    }
}

impl From<IssueError> for ApiError {
    /// Maps a core issuance error to the JSON error, extracting the envelope
    /// dimension for the widening variants so the caller can highlight the field.
    fn from(err: IssueError) -> Self {
        let message = err.to_string();
        match err {
            IssueError::ScopeWidened(dimension) => {
                ApiError::dimension(message, &dimension.to_string())
            }
            IssueError::IntegrityExceedsParent { .. } => ApiError::dimension(message, "max_level"),
            IssueError::ValidityExceedsParent { .. } => ApiError::dimension(message, "max_ttl"),
            _ => ApiError::msg(message),
        }
    }
}

impl From<tessera_ext::der::DerError> for ApiError {
    fn from(err: tessera_ext::der::DerError) -> Self {
        ApiError::msg(format!("der: {err}"))
    }
}

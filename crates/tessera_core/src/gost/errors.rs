//! Error types for the gost-engine wrapper.

use std::path::PathBuf;

use thiserror::Error;

/// Errors raised while attempting to load and pin the gost-engine.
///
/// `Clone` is implemented so the cached result in
/// [`super::engine::ensure_loaded`]'s `OnceLock` can be returned to many
/// callers without consuming the original.
#[derive(Debug, Clone, Error)]
pub enum GostEngineError {
    /// The configured engine path does not exist or is not a regular file.
    #[error("gost-engine path is missing or not a regular file: {0:?}")]
    PathMissing(PathBuf),
    /// The engine could not be located by libcrypto.
    ///
    /// Returned when `ENGINE_by_id` returns NULL (the engine is not
    /// registered and is not findable on disk via `OPENSSL_ENGINES`).
    #[error("gost-engine is not available: {0}")]
    NotAvailable(String),
    /// The engine .so could not be dynamically loaded by libcrypto.
    ///
    /// Returned when the dynamic-loader engine is configured with a `SO_PATH`
    /// but the LOAD command fails (bad ABI, wrong file, missing symbol).
    #[error("gost-engine load failed: {0}")]
    LoadFailed(String),
    /// The engine loaded but could not be pinned as the default for GOST
    /// methods.
    #[error("gost-engine set_default failed: {0}")]
    SetDefaultFailed(String),
    /// A required GOST digest could not be resolved after the engine was
    /// (allegedly) loaded.
    #[error("gost digest unavailable: {name}")]
    DigestUnavailable {
        /// Symbolic name of the digest, e.g. `"md_gost12_256"`.
        name: String,
    },
}

impl GostEngineError {
    /// Convenience for the common `DigestUnavailable` case where the digest
    /// name is a `&'static str`.
    #[must_use]
    pub fn digest_unavailable(name: impl Into<String>) -> Self {
        Self::DigestUnavailable { name: name.into() }
    }
}

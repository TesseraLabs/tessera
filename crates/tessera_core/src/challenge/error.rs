//! Errors raised by the challenge-response subsystem.

use thiserror::Error;

/// Failure modes for [`crate::challenge::challenge_response`] and its
/// per-algorithm helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Failed to draw entropy from the OS RNG.
    #[error("rng failure: {0}")]
    Rng(String),
    /// Underlying OpenSSL error (signing, verification, key extraction).
    #[error("openssl: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    /// Verification rejected the signature — either the keys do not match the
    /// presented certificate or the bytes were tampered with.
    #[error("signature verification failed")]
    BadSignature,
    /// The key type embedded in the certificate is not supported by the
    /// stage-2 dispatcher (e.g. Ed25519, EC over an unnamed curve, ...).
    #[error("unsupported key type: {0}")]
    UnsupportedKey(&'static str),
    /// The certificate's public key is below the minimum accepted strength
    /// (e.g. sub-2048-bit RSA).  Refused before any challenge-response so a
    /// weak key never gets to prove possession.
    #[error("weak public key: {0}")]
    WeakKey(String),
    /// gost-engine could not be loaded for a GOST private key.
    ///
    /// Surfaced when the loaded private key is GOST-typed but the engine
    /// has not been pinned successfully.
    #[error("gost-engine unavailable for challenge signing: {source}")]
    EngineLoadFailed {
        /// Underlying engine load failure.
        #[source]
        source: crate::gost::GostEngineError,
    },
}

//! GOST cryptography integration via OpenSSL's `gost-engine`.
//!
//! See [`engine`] for the process-global loader and [`algorithms`] for
//! NID/digest helpers.  Both are no-ops when GOST OIDs are not present in
//! the configured signature whitelist (`needs_gost() == false`).

pub mod algorithms;
pub mod engine;
pub mod errors;
mod sys;

pub use errors::GostEngineError;

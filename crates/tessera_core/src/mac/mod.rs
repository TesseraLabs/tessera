//! Mandatory Access Control (МКЦ) integration: types, traits, SPI.
//!
//! See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md`.
//!
//! The open core defines the [`MacBackend`] SPI, the no-op [`StubBackend`],
//! the policy orchestrator, label algebra, and audit events. The real
//! `libpdp`/parsec FFI enforcement backend (`ParsecBackend`) lives in the
//! separate `tessera_mac_parsec` crate and is selected by callers behind
//! the `astra-mac` feature.

pub mod audit;
pub mod backend;
pub mod label;
pub mod orchestrator;

#[cfg(feature = "mac-tests")]
pub use backend::MockMacBackend;
pub use backend::{MacBackend, MacError, MacRuntime, StubBackend};
pub use label::IntegrityLabel;

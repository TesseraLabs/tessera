//! Mandatory integrity control (МКЦ) integration: types, traits, SPI.
//!
//! See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md`.
//!
//! The open core defines the [`MacBackend`] SPI, the no-op [`StubBackend`],
//! the policy orchestrator, label algebra, and audit events. The real
//! `libpdp`/parsec FFI enforcement backend lives in a separately delivered
//! runtime plugin. The open host loads it through [`crate::plugin`].

pub mod audit;
pub mod backend;
pub mod label;
pub mod orchestrator;

#[cfg(feature = "mac-tests")]
pub use backend::MockMacBackend;
pub use backend::{MacBackend, MacError, MacRuntime, MrdState, StubBackend};
pub use label::IntegrityLabel;

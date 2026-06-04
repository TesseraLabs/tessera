//! PKCS#11 backend wrapping the `cryptoki` crate (Stage 4, block 1).
//!
//! This module hosts the safe Rust types we layer on top of `cryptoki`:
//!
//! - [`Pkcs11Backend`] — owns the loaded `.so` and a single `Pkcs11`
//!   context.  `Drop` finalises the library via `cryptoki`'s own `Drop`
//!   chain.
//! - [`Pkcs11Session`] — RAII wrapper around `cryptoki::session::Session`
//!   that calls `C_Logout` (when logged in) before the underlying session
//!   `Drop` calls `C_CloseSession`.
//! - [`Pkcs11Error`] — fully-typed `thiserror` enum used by every public fn
//!   in this module.  Specific variants (`PinIncorrect`, `PinLocked`) drive
//!   the bounded PIN-retry loop in [`pin_loop`].
//! - [`pin_loop::acquire_pkcs11_session`] — bounded retry loop that maps
//!   token PIN errors to PAM error codes (T07).
//!
//! ## Safety / threading
//!
//! `cryptoki` itself encapsulates all `unsafe` FFI; this module is
//! `#![deny(unsafe_code)]` together with the rest of `tessera_core`
//! (no local `#[allow(unsafe_code)]` is needed).
//!
//! ## Test gating
//!
//! Every integration test that loads a real PKCS#11 provider lives in
//! `crates/tessera_core/tests/pkcs11_*.rs` and is guarded by:
//! 1. the `pkcs11-tests` Cargo feature (compile-time gate); and
//! 2. a runtime check for the `PKCS11_MODULE_PATH` environment variable
//!    via [`test_helpers::pkcs11_test_module_path`].
//!
//! On macOS dev hosts the env var is unset, the helper returns `None`, and
//! each test prints `skipped: PKCS#11 module not available` and exits Ok.

mod backend;
pub mod cert_lookup;
pub mod error;
pub mod info;
pub mod key_lookup;
pub mod locking;
pub mod mechanism;
pub mod pin_loop;
mod session;
pub mod sign;
pub mod test_helpers;
mod waiter;

pub use backend::{LockingMode, Pkcs11Backend};
pub use cert_lookup::FoundCertificate;
pub use error::Pkcs11Error;
pub use info::read_token_serial;
pub use key_lookup::FoundPrivateKey;
pub use mechanism::{select_mechanism, TokenSignMechanism};
pub use pin_loop::{acquire_pkcs11_session, AcquireError, PinSessionOpener};
pub use session::Pkcs11Session;
pub use sign::pkcs11_challenge_response;
pub use waiter::TokenLocator;

/// Convenience re-export so callers don't need to import `cryptoki::slot::Slot`
/// alongside our own types.
pub use cryptoki::slot::Slot;

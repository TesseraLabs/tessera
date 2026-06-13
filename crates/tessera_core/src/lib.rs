//! Core types, configuration, and traits for Tessera.
//!
//! Crate-level safety rule: `unsafe_code` is `deny`'d everywhere except in
//! `hooks::child_setup` and `hooks::fork_exec`, which `#[allow(unsafe_code)]`
//! locally because the post-fork child path requires raw FFI calls
//! (`libc::execve`, `libc::_exit`, ...) under async-signal-safe constraints.
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]

pub mod challenge;
pub mod config;
pub mod crl;
pub mod discovery;
pub mod error;
pub mod gost;
pub mod hooks;
pub mod host_binding;
pub mod host_identity;
pub mod ipc;
pub mod logging;
pub mod mac;
pub mod mapping;
pub mod mount;
pub mod mount_guard;
pub mod ocsp;
pub mod pam_conv;
pub mod pam_data;
pub mod pkcs12;
// Planned (openspec/changes/role-format/): `mod role` — on-device role store
// (TOML role slices, strict parsing, standalone/managed trust modes, signed
// manifest with anti-rollback).
pub mod secret;
pub mod self_check;
// Planned (openspec/changes/tags-delegation/): `mod tags` — device-tags store
// (generic key=value map, opaque to the Engine; managed signed manifest with
// anti-rollback, or a standalone file under FS-permission trust).
pub mod token;
pub mod trust;
pub mod usb;
pub mod x509;

pub use config::{RawConfig, ValidatedConfig};
pub use error::{Error, SelfCheckError};
pub use logging::{LogLevel, SyslogFacility};
pub use secret::Secret;
pub use x509::SignatureAlg;

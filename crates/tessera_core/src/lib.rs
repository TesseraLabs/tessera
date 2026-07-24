//! Core types, configuration, and traits for Tessera.
//!
//! Crate-level safety rule: `unsafe_code` is `deny`'d everywhere except for a
//! few narrow FFI sites that `#[allow]`/`#[expect]` it locally:
//! `hooks::child_setup` and `hooks::fork_exec`, whose post-fork child path
//! requires raw FFI calls (`libc::execve`, `libc::_exit`, ...) under
//! async-signal-safe constraints; and `x509::asn1_string_type`, which reads an
//! ASN.1 string's type tag via `ASN1_STRING_type` because the safe `openssl`
//! API exposes no accessor for it.
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
pub mod enrollment;
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
pub mod plugin;
pub mod privileged_path;
pub mod role;
pub mod secret;
pub mod self_check;
pub mod tags;
pub mod token;
pub mod trust;
pub mod usb;
pub mod x509;

pub use config::{RawConfig, ValidatedConfig};
pub use enrollment::{EnrollmentPackage, ImportError, ImportMode, ImportOutcome, InstallPaths};
pub use error::{Error, SelfCheckError};
pub use logging::{LogLevel, SyslogFacility};
pub use secret::Secret;
pub use tags::{parse_tags, DeviceTags, TagsSchemaError, TagsSourceError};
pub use x509::SignatureAlg;

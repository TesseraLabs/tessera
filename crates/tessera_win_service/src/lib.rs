//! The Windows Engine layer: a service that verifies credentials and answers a
//! credential provider over a named pipe.
//!
//! What it does is what the PAM module does on Linux, minus the parts this wave
//! deliberately leaves out. A client names a role and supplies a PIN; the
//! service finds the removable volume, reads the credential from it, and runs
//! the same `authenticate_pkcs12` a Linux login runs. On an admission it
//! answers with the technical account and that account's password, and it
//! records the identity behind the session in a hash-chained journal. On a
//! refusal it answers with a coarse reason and records the full one.
//!
//! # What this wave is not
//!
//! There is no enforcement here. The role is chosen, checked, and journaled,
//! and it changes nothing about the session that follows: no groups in the
//! token, no integrity level, no privilege removal, no TTL, no reaction to the
//! media being pulled. A session opens under one shared local account. Saying
//! this out loud is part of the deliverable — a role that is recorded but not
//! enforced is easy to mistake for one that is.
//!
//! The technical account's password is fixed rather than rotated per
//! admission, so whoever holds it can log in without any credential at all.
//! That is a bench-grade shortcut, named in the design and closed in the next
//! wave.
//!
//! # Layout
//!
//! The parts that can be reasoned about without Windows are kept that way, and
//! they are the majority: connection handling ([`protocol`]), the journal
//! ([`journal`]), the role list ([`roles`]), password generation
//! ([`password`]), the refusal mapping ([`engine`]). What genuinely needs Win32
//! — the pipe, the service control manager, the account, DPAPI, the protected
//! ACL — lives under [`windows`] and nowhere else.
//!
//! Two things that were once here now live in `tessera_proto`: the frame reader
//! and the protocol client. Both are what a *peer* of this protocol needs
//! rather than what a server does, and the credential provider is such a peer —
//! one that must not pull the verification core into the logon process to get
//! at them. What stays here is the server's own business: the budgets a
//! connection is held to, the deadline it requires of a transport, and the
//! dispatch of requests to the engine.

pub mod engine;
pub mod journal;
pub mod password;
pub mod paths;
pub mod protocol;
pub mod roles;

#[cfg(windows)]
pub mod windows;

/// The version reported in the `Hello` acknowledgement.
pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

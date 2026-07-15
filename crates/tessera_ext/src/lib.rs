//! Shared, pure-Rust definitions of the Tessera custom X.509 extensions.
//!
//! The Engine (`tessera_core`) enforces a set of project-private X.509
//! extensions — host/user binding, device tags, integrity ceiling and the
//! delegation envelope — allocated under the RFC 4530 `2.25.<UUID>` arc. The
//! issuer tooling has to *produce* exactly what the Engine *accepts*, so the
//! primitives that both sides must agree on live here rather than being copied:
//!
//! * [`oids`] — the extension OID constants (the on-the-wire contract).
//! * [`der`] — a minimal DER TLV reader/writer, an OID encoder for arcs up to
//!   [`u128`] (our `2.25.<UUID>` arcs are ~128 bits wide), and an OID decoder.
//! * [`ext`] — encoders and decoders for the leaf-scope extensions (host/user
//!   binding, allowed-roles, profile-version, max-integrity) plus a pure-Rust
//!   extension extractor that pulls an `extnValue` out of a certificate by OID.
//! * [`delegation`] — the `DelegationConstraints` schema, its raw DER
//!   parse/encode, and the monotone-narrowing predicate that decides whether a
//!   child envelope stays inside its parent.
//!
//! The crate is deliberately dependency-light (only `thiserror`) and free of
//! `openssl`, `cryptoki`, `nix` and every other system crate, so it builds for
//! `wasm32-unknown-unknown` and can back the browser-side issuer cabinet.

pub mod delegation;
pub mod der;
pub mod ext;
pub mod oids;

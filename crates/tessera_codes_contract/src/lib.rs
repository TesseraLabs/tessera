//! Contract of the Tessera Codes phone channel.
//!
//! One property justifies this crate: the device and the cabinet compute the
//! same bytes. Everything else follows from it. The same source builds for the
//! device (`x86_64-unknown-linux-gnu`) and for the cabinet
//! (`wasm32-unknown-unknown`), so the crate performs no I/O, reads no clock and
//! draws no randomness — the caller supplies whatever comes from the
//! environment.
//!
//! # What lives here
//!
//! - [`canon`] — the canonical serialisation of the MAC input — device, epoch,
//!   nonce, role, level and the personal number of the engineer — described by
//!   an explicit field table and frozen by golden vectors.
//! - [`key`] — derivation of the shared key `K` from an externally computed
//!   Diffie-Hellman secret, plus the key-agreement traits the consumers
//!   implement; the device side agrees on a pair that lives for one attempt.
//! - [`code`] — computation and constant-time verification of the code itself.
//! - [`params`] — fleet parameters, validated at parse time, comparable only as
//!   a partial order.
//! - [`nonce`] — the nonce of an attempt: one long random value, drawn outside
//!   and checked here against the width and alphabet of the fleet.
//! - [`profile`] — the key agreement profile, and the gate that keeps a fleet
//!   from starting on a profile nobody has confirmed on hardware.
//! - [`device_number`] — the device number with its ISO 7064 MOD 37,36 check
//!   character.
//! - [`challenge`] — the challenge of an attempt, ephemeral public point
//!   included: assembly, strict parsing, its canonical bytes and the grouped
//!   form the fields are shown in.
//! - [`ticket`] — the ticket of the issuing side, its term and the hash that
//!   binds it into the key derivation context.
//! - [`registry`] — the device registry record: the payload, the three
//!   signatures over it in the order they are made, and what the record says
//!   about where the device key is kept.
//! - [`engineer`] — the registry record of a person and the authorisation that
//!   says what they may ask for, kept apart on purpose.
//! - [`receipt`] — the issuance receipt, its mandatory grounds and its composed
//!   file name.
//! - [`request`] — the signed request of an engineer: one canonical object with
//!   the challenge inside it and the authorisation fields in a single copy.
//! - [`grant`] — what the issuing side answers a request with: the signed
//!   request, the signature of the issuing side, and the confirmation of a
//!   second person when the fleet asks for one.
//! - [`status`] — the status-token: what the status service says about an
//!   engineer's authorisation right now, bound to the attempt it was asked for.
//! - [`signature`] — the verifier trait the consumers implement; the crate holds
//!   no trust anchors.
//! - [`time`] — the moment a document claims, which this crate never reads from
//!   a clock.
//! - [`wire`] — the strict `key=value` form the documents travel in.
//!
//! # Compatibility
//!
//! The bytes produced by [`canon::canon`], the key derived by
//! [`key::derive_key`] and the code produced by [`code::compute_code`] are
//! frozen by the golden vectors under `tests/golden/`. Changing any of them is
//! a breaking change under the workspace compatibility policy, not a routine
//! edit — a code computed by a device of an older build must keep verifying in
//! a cabinet of a newer one.
//!
//! # Example
//!
//! ```
//! use tessera_codes_contract::canon::{CodeInput, Level};
//! use tessera_codes_contract::code::{compute_code, verify_code};
//! use tessera_codes_contract::device_number::CheckedDeviceNumber;
//! use tessera_codes_contract::key::{derive_key, Epoch, KeyContext, SharedSecret};
//! use tessera_codes_contract::params::FleetParams;
//! use tessera_codes_contract::signature::{PublicKey, Signature};
//! use tessera_codes_contract::ticket::{
//!     ServerTicket, SignedTicket, TicketNumber, TicketScope, TicketScopeInput,
//! };
//! use tessera_codes_contract::time::ClaimedTime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The ticket the operator is working under; its canonical bytes, signature
//! // included, are hashed into the key derivation context.
//! let ticket = SignedTicket::new(
//!     ServerTicket::new(
//!         "op-42",
//!         PublicKey::new(vec![0x04, 0x11, 0x22])?,
//!         TicketScope::new(TicketScopeInput {
//!             tags: vec!["dc-1".to_owned()],
//!             roles: vec!["ops.dc.senior".to_owned()],
//!             region: "ru-central".to_owned(),
//!             max_level: Level::new(3),
//!         })?,
//!         ClaimedTime::new(1_800_000_000),
//!         TicketNumber::parse("tk-17")?,
//!     )?,
//!     Signature::new(vec![0xab, 0xcd])?,
//! );
//!
//! let params = FleetParams::defaults();
//! let device_number = CheckedDeviceNumber::parse("77-000123-S")?;
//! let secret = SharedSecret::new(vec![0x42; 32])?;
//! let context = KeyContext::new(&device_number, ticket.context_hash()?);
//! let key = derive_key(&secret, &context)?;
//!
//! let input = CodeInput {
//!     device_number: &device_number,
//!     nonce: "0004200713",
//!     role_id: "ops.dc.senior",
//!     level: Level::new(2),
//!     epoch: Epoch::new(7),
//!     engineer_id: "eng-1",
//! };
//!
//! let code = compute_code(&key, &input, &params)?;
//! verify_code(&key, &input, &params, code.as_str())?;
//! # Ok(())
//! # }
//! ```

pub mod canon;
pub mod challenge;
pub mod code;
pub mod device_number;
pub mod engineer;
#[cfg(test)]
mod golden_tests;
pub mod grant;
pub mod key;
mod mac;
pub mod nonce;
pub mod outcome;
pub mod params;
pub mod profile;
pub mod receipt;
pub mod registry;
pub mod request;
pub mod signature;
pub mod status;
pub mod ticket;
pub mod time;
pub mod wire;

//! Owner-authenticated initial registry inventories and ordered legacy imports.
//!
//! These pure codecs verify signatures and caller-supplied context. They do not
//! establish a protected writer fence, live absence, durable nonce consumption,
//! current record state or an atomic compare-and-swap. Existing record formats
//! and their verification remain unchanged.
mod baseline;
mod import;
mod inventory;
mod types;

pub use baseline::*;
pub use import::*;
pub use inventory::*;
pub use types::*;

use crate::{
    canon::Encoder,
    mac::sha256,
    registration_authority::{codec, AuthorityError, AuthorityTrustContext, P256PublicKey},
    signature::Signature,
    wire,
};
use codec::Reader;

/// Maximum signed manifest or import body, before hexadecimal encoding.
pub const MAX_BODY: usize = 2 * 1024;
/// Maximum complete signed text envelope.
pub const MAX_ENVELOPE: usize = 8 * 1024;
/// Maximum complete binary inventory.
pub const MAX_INVENTORY: usize = 2 * 1024 * 1024;
/// Maximum entries in one complete inventory.
pub const MAX_ENTRIES: usize = 4096;
/// Maximum encoded inventory entry.
pub const MAX_ENTRY: usize = 512;
/// Maximum legacy record accepted by the new import companion only.
pub const MAX_IMPORT_RECORD: usize = 16 * 1024;

fn check_scope(
    fleet: &str,
    owner: &str,
    trust: &AuthorityTrustContext<'_>,
) -> Result<(), AuthorityError> {
    if fleet != trust.fleet_id || owner != trust.owner_id {
        return Err(AuthorityError::Context("registry owner/fleet scope"));
    }
    Ok(())
}
fn check_time(start: u64, end: u64, now: u64) -> Result<(), AuthorityError> {
    if now < start || now >= end {
        return Err(AuthorityError::Context("registry admission time"));
    }
    Ok(())
}
fn envelope(prefix: &str, body: &[u8], signature: &Signature) -> Result<String, AuthorityError> {
    if body.len() > MAX_BODY {
        return Err(AuthorityError::Malformed("registry body bound"));
    }
    codec::signature(signature.as_bytes())?;
    let result = wire::render(
        prefix,
        &[
            ("body", hex::encode(body)),
            ("owner_signature", hex::encode(signature.as_bytes())),
        ],
    );
    if result.len() > MAX_ENVELOPE {
        return Err(AuthorityError::Malformed("registry envelope bound"));
    }
    Ok(result)
}
fn parse_envelope(
    text: &str,
    prefix: &'static str,
) -> Result<(Vec<u8>, Signature), AuthorityError> {
    if text.len() > MAX_ENVELOPE || text.trim() != text {
        return Err(AuthorityError::Malformed("registry envelope bound/form"));
    }
    let fields = wire::parse(text, prefix, &["body", "owner_signature"])?;
    let body = codec::hex_bytes(wire::value(&fields, 0), MAX_BODY)?;
    let signature = codec::parse_signature(wire::value(&fields, 1))?;
    if envelope(prefix, &body, &signature)? != text {
        return Err(AuthorityError::Malformed(
            "registry envelope canonical form",
        ));
    }
    Ok((body, signature))
}
fn domain(reader: &mut Reader<'_>, expected: &str) -> Result<(), AuthorityError> {
    if reader.field(128)? != expected.as_bytes() {
        return Err(AuthorityError::Malformed("registry domain"));
    }
    Ok(())
}

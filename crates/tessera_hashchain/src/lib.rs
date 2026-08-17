//! The append-only, hash-chained record shared by every Tessera journal.
//!
//! Two journals in this product need the same thing: a line-oriented history
//! whose lines cannot be edited, reordered or removed without the next read
//! saying where it happened. The issuance journal of the cabinet needed it
//! first; the device audit journal needs it now. A second implementation of a
//! hash chain would be a second thing to get wrong — and, worse, a second
//! on-disk format an auditor would have to learn separately — so the
//! construction lives here once and each journal supplies only what is its own.
//!
//! # What a caller supplies
//!
//! A [`ChainPayload`]: the payload type its lines carry, and the genesis
//! preimage that anchors its chain. Two payload types never share an anchor, so
//! a line lifted out of one journal into another does not verify there.
//!
//! Everything else — the framing, the `seq`, the `prev_hash`, the head-signature
//! accounting and the verification — is the same for every journal and is
//! provided here.
//!
//! # The line format
//!
//! One line is a flat JSON object:
//!
//! ```json
//! {"seq":0,"prev_hash":"<64 hex>","ts":1700000000,"op":"annotation","kind":"acme.review","data":{}}
//! ```
//!
//! - `seq` — monotonic from 0, dense, incremented for every line without
//!   exception, head signatures and annotations included;
//! - `prev_hash` — lowercase hex SHA-256 of the previous line's bytes; at
//!   `seq == 0` it is the SHA-256 of the payload type's genesis preimage;
//! - `ts` — a caller-supplied timestamp in Unix seconds. This crate carries no
//!   clock, which is what keeps it usable from `wasm32` and out of the business
//!   of deciding whose clock is right;
//! - the rest is the payload, flattened, tagged by `op`.
//!
//! Two payloads recur in every journal, and their field definitions live here so
//! the journals cannot spell them differently: [`HeadSignature`] and
//! [`Annotation`]. A journal embeds them as variants of its own payload enum
//! under the `op` names [`OP_HEAD_SIGNATURE`] and [`OP_ANNOTATION`].
//!
//! # Head signatures
//!
//! A hash chain says that the lines it covers were not edited *relative to each
//! other*. It says nothing about the chain as a whole: a prefix of a valid chain
//! is a valid chain, so dropping the tail — or replacing the file with a shorter
//! one that was never real — passes verification. What narrows that is a
//! signature over the head, recorded as its own line: everything up to it is
//! then pinned by something outside the file.
//!
//! This crate performs no signing and holds no keys. A caller signs the 32 bytes
//! of [`Chain::head`] and appends the result; the cryptographic check on the way
//! back needs a public key this crate has no way to obtain, so it belongs to the
//! caller too. [`verify_lines`] reports the *structure*: whether a signature
//! line covers the tail, and which `seq` the last one sat at.
//!
//! # What this construction does not prevent
//!
//! Stated here because a chain is easy to oversell:
//!
//! - **Deleting the whole file is not prevented.** Nothing that lives on a
//!   machine its owner controls can be. From the file alone a fresh chain and a
//!   wiped one are indistinguishable; only something outside it — a
//!   counter-signed head that was carried away, an enrolment record — separates
//!   them.
//! - **The newest line is covered by nothing.** Every line is covered by the
//!   `prev_hash` of the line after it, and the last one has no line after it.
//!   Until a head signature lands, the tail can be truncated or its final line
//!   rewritten without the chain noticing.
//!
//! Both are properties of hash chains, not of this implementation, and each
//! journal states in its own documentation what it puts behind them.

mod chain;
mod payload;
mod verify;

pub mod storage;

pub use chain::{Chain, ChainError, ChainStorage};
pub use payload::{
    domain, sha256, Annotation, ChainPayload, EntryKind, HeadSignature, OP_ANNOTATION,
    OP_HEAD_SIGNATURE,
};
pub use verify::{verify_lines, ChainReport, ChainStatus};

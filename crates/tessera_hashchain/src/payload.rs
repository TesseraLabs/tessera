//! What a journal contributes to the shared chain, and the two payloads every
//! journal has in common.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The genesis anchors of every journal in this product.
///
/// # Why they live here and not with their journals
///
/// An anchor is not the meaning of a journal — it is the identifier of a
/// *format*: "these bytes are a chain of this kind, at this version". Format
/// identifiers belong with the format, which is what this crate is. The common
/// payloads moved here for the same reason, and leaving the anchors behind
/// would have been the inconsistent choice.
///
/// The concrete cost of the alternative is what settled it. The device anchor
/// was declared in `tessera_core`, and the reconciliation that verifies a
/// device journal lives in `tessera_issuer` — which compiles to `wasm32` and
/// cannot depend on `tessera_core`. So it held a second copy of a constant that
/// trust in the journal rests on, across a boundary where neither side can see
/// the other. A divergence would not corrupt anything, but it would make every
/// reconciliation refuse every journal, discovered at audit time.
///
/// **These values are on disk.** Changing one makes every journal already
/// written with it stop verifying, which is the point of an anchor and the
/// reason a new format version gets a new one rather than an edit to an old.
pub mod domain {
    /// The issuance journal of the cabinet.
    pub const ISSUANCE_JOURNAL: &[u8] = b"tessera-issuance-journal/v1/genesis";

    /// The hash-chained audit journal of a device.
    pub const DEVICE_AUDIT: &[u8] = b"tessera-device-audit/v1/genesis";
}

/// The `op` value of a head-signature line.
pub const OP_HEAD_SIGNATURE: &str = "head_signature";

/// The `op` value of an annotation line.
pub const OP_ANNOTATION: &str = "annotation";

/// What a line is, as far as the chain is concerned.
///
/// The chain distinguishes exactly two things, because exactly two behave
/// differently in verification: a signature closes the unsigned tail, and
/// everything else opens one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// An ordinary record — an event, an annotation, whatever the journal
    /// writes. It joins the unsigned tail.
    Record,
    /// A signature over the head as it stood before this line. It closes the
    /// unsigned tail.
    HeadSignature,
}

/// The payload of one journal's lines.
///
/// Implement this on the journal's own payload enum. The enum MUST be
/// internally tagged on `op` (`#[serde(tag = "op")]`), so a line serializes to a
/// flat JSON object, and it SHOULD carry the two common payloads
/// ([`HeadSignature`], [`Annotation`]) under [`OP_HEAD_SIGNATURE`] and
/// [`OP_ANNOTATION`] rather than inventing its own spelling of either.
pub trait ChainPayload: Serialize + DeserializeOwned + Clone {
    /// The fixed bytes whose SHA-256 anchors the first line of this journal's
    /// chain. Choose something self-describing and versioned, e.g.
    /// `b"tessera-device-audit/v1/genesis"`.
    ///
    /// The anchor is domain separation, not decoration: chains of two journals
    /// start from different anchors, so a line copied from one into the other
    /// fails verification at its position instead of blending in. It also pins
    /// the format version — a change older readers must not accept comes with a
    /// new preimage.
    const GENESIS_PREIMAGE: &'static [u8];

    /// Whether this line closes the unsigned tail or joins it.
    fn kind(&self) -> EntryKind;

    /// Whether the line is well formed beyond parsing.
    ///
    /// Parsing accepts anything the types admit; this is where a journal refuses
    /// what its format promised but its types cannot express — an annotation
    /// with no namespace tag, for one. A `false` here is a break at that
    /// position, not a warning: a line nothing in the format admits is a line
    /// somebody wrote by hand.
    fn is_structurally_valid(&self) -> bool;
}

/// A signature over the chain head as it stood before the line carrying it.
///
/// Defined here rather than in each journal so the two cannot drift: an auditor
/// reading either record sees the same two fields with the same meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadSignature {
    /// The writer's stable label for the signing algorithm. Opaque here.
    pub algorithm: String,
    /// Base64 of the raw signature over the covered head's 32 bytes.
    pub signature: String,
}

/// Writer-defined context, chained like anything else and interpreted by
/// nobody in this crate.
///
/// The point of an annotation is that a journal can carry somebody else's data
/// — a reconciliation projection, a review note — under the same chain, so that
/// removing it is as visible as removing an event. Whoever wrote it is the only
/// party that knows what it means.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Annotation {
    /// The writer's namespace tag (e.g. `"acme.review"`). Non-empty; opaque
    /// here.
    pub kind: String,
    /// An arbitrary JSON object of writer-defined context. Opaque here.
    pub data: serde_json::Value,
}

impl Annotation {
    /// Whether the annotation is one the format admits: a namespace tag that
    /// names somebody, and an object rather than a bare value.
    ///
    /// A journal's [`ChainPayload::is_structurally_valid`] delegates here for
    /// its annotation variant.
    #[must_use]
    pub fn is_structurally_valid(&self) -> bool {
        !self.kind.is_empty() && self.data.is_object()
    }
}

/// SHA-256 of `bytes` as a 32-byte array.
///
/// Public because the journals built on this crate hash certificates and
/// artefacts into their own payloads and must do it the same way the chain
/// does.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// The anchor a fresh chain of `P` points its first line at.
pub(crate) fn genesis_hash<P: ChainPayload>() -> [u8; 32] {
    sha256(P::GENESIS_PREIMAGE)
}

/// Decodes a lowercase-hex 32-byte hash, `None` on anything malformed.
pub(crate) fn decode_hash(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// One line of a chain: position, linkage, timestamp, payload.
///
/// `Eq` is not derived: an annotation carries an arbitrary
/// [`serde_json::Value`], which is only `PartialEq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Entry<P> {
    /// Monotonic position from 0, incremented for every line.
    pub(crate) seq: u64,
    /// Lowercase hex SHA-256 of the previous line's bytes; the genesis anchor
    /// at `seq == 0`.
    pub(crate) prev_hash: String,
    /// Caller-supplied time, Unix seconds.
    pub(crate) ts: u64,
    /// The payload, flattened into the same JSON object.
    #[serde(flatten)]
    pub(crate) payload: P,
}

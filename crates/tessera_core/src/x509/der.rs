//! Thin Engine-side adaptor over the shared DER primitives in
//! [`tessera_ext::der`].
//!
//! The reader, tag constants and OID codec now live in `tessera_ext` (pure
//! Rust, wasm-buildable).  This module re-exports the tag constants and the
//! borrowed [`Tlv`] type, and wraps the fallible readers so they surface the
//! Engine's [`TrustError`] — keeping every existing call site (which threads
//! `TrustError` through `?`) unchanged.

use super::TrustError;

pub(crate) use tessera_ext::der::{
    Tlv, TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};

impl From<tessera_ext::der::DerError> for TrustError {
    /// Every shared DER failure surfaces as a fail-closed certificate-parse
    /// error, preserving the original diagnostic text.
    fn from(err: tessera_ext::der::DerError) -> Self {
        TrustError::CertParse(err.to_string())
    }
}

/// Parses one TLV element from the start of `input`.
///
/// # Errors
///
/// Returns [`TrustError::CertParse`] if the buffer is truncated or uses an
/// unsupported (indefinite or > 4-byte) length form.
pub(crate) fn read_tlv(input: &[u8]) -> Result<Tlv<'_>, TrustError> {
    tessera_ext::der::read_tlv(input).map_err(TrustError::from)
}

/// Reads a tag-checked TLV from `input`.
///
/// # Errors
///
/// Returns [`TrustError::CertParse`] on a tag mismatch or truncation.
pub(crate) fn read_tlv_expect(input: &[u8], tag: u8) -> Result<Tlv<'_>, TrustError> {
    tessera_ext::der::read_tlv_expect(input, tag).map_err(TrustError::from)
}

/// Renders an OID's DER content into the canonical dotted notation
/// (e.g. `1.3.6.1.5.5.7.3.2`).
///
/// # Errors
///
/// Returns [`TrustError::CertParse`] when the encoding is malformed.
pub(crate) fn oid_to_dotted(content: &[u8]) -> Result<String, TrustError> {
    tessera_ext::der::oid_to_dotted(content).map_err(TrustError::from)
}

//! WebAssembly bindings for the Tessera issuance core — the browser cabinet's
//! engine.
//!
//! The cabinet is a static, serverless SPA: all issuance logic runs client-side,
//! and the only network it touches is the local signing agent (`issuer serve`)
//! on `127.0.0.1`, which the JS layer — not this crate — calls. These bindings
//! are therefore **pure functions over bytes and JSON**: they build and
//! self-check `TBS`/certificate DER, but never open a socket and never hold a
//! private key.
//!
//! # The split-signing flow
//!
//! 1. [`inspect_parent`] classifies a loaded parent certificate, so the UI knows
//!    whether it can issue CAs (a fleet root), leaves (an organisation CA), or
//!    nothing (a leaf/unusable certificate).
//! 2. [`build_leaf_tbs`] / [`build_ca_tbs`] / [`build_crl_tbs`] run every core
//!    check (envelope monotonicity, CSR proof of possession) and return the exact
//!    `TBS` bytes to sign plus a localized summary to preview.
//! 3. The JS layer sends the `TBS` to the local agent and receives a signature.
//! 4. [`assemble_and_verify`] frames the final artifact from that `TBS` and
//!    signature and self-checks it against the parent envelope.
//! 5. [`journal_append`] / [`journal_verify`] maintain the hash-chained issuance
//!    journal the browser holds as a file.
//!
//! [`inspect_csr`] supports the CSR key-source path (surfacing the subject,
//! self-signature status, and requested attributes for labelled prefill).
//!
//! # The JSON contract
//!
//! Every export takes **one JSON string** and returns **one JSON string**. On
//! success the returned string is the response payload; on failure the function
//! throws (returns `Err`) a JSON string `{ "error": "…", "dimension": "…"? }` —
//! `dimension` is present only for a delegation-envelope widening and names the
//! offending field. Chosen over `serde-wasm-bindgen` because a single string
//! convention keeps the whole surface testable as ordinary Rust and leaves the
//! JS side one `JSON.parse` per call:
//!
//! ```js
//! try {
//!   const { kind, envelope } = JSON.parse(inspect_parent(JSON.stringify({ cert_b64 })));
//! } catch (e) {
//!   const { error, dimension } = JSON.parse(e); // typed failure
//! }
//! ```
//!
//! **Binary values are always standard, padded Base64** in fields suffixed
//! `_b64`. Certificate and CSR inputs may be PEM or DER; the binding decodes a
//! PEM wrapper when present. Serial-number entropy (16 bytes recommended) and
//! issuance timestamps are supplied by the JS host (`crypto.getRandomValues`,
//! `Date.now()`), keeping this core free of an entropy backend and a clock.

mod api;
mod error;
mod types;

use wasm_bindgen::prelude::wasm_bindgen;

/// Classify a parent certificate to derive the cabinet's available operations.
///
/// Input `{ cert_b64 }`; output `{ kind, subject, envelope?, reason? }` where
/// `kind` is `root` (issue org CAs), `org_ca` (issue leaves), `leaf`, or
/// `unusable`.
///
/// # Errors
///
/// A JSON [`error`](crate) string on malformed input.
#[wasm_bindgen]
pub fn inspect_parent(input: &str) -> Result<String, String> {
    api::inspect_parent(input)
}

/// Build the `TBSCertificate` for an engineer shift-leaf, running every core
/// check, and return `{ tbs_b64, summary }`.
///
/// # Errors
///
/// A JSON `error` string on malformed input or any core rejection (a widened
/// envelope names the `dimension`; a bad CSR fails proof of possession).
#[wasm_bindgen]
pub fn build_leaf_tbs(input: &str) -> Result<String, String> {
    api::build_leaf_tbs(input)
}

/// Build the `TBSCertificate` for an organisation CA and return
/// `{ tbs_b64, summary }`.
///
/// # Errors
///
/// A JSON `error` string on malformed input or a widened envelope (naming the
/// `dimension`).
#[wasm_bindgen]
pub fn build_ca_tbs(input: &str) -> Result<String, String> {
    api::build_ca_tbs(input)
}

/// Build the `TBSCertList` for a CRL and return `{ tbs_b64, summary }`.
///
/// # Errors
///
/// A JSON `error` string on malformed input or a non-monotone `crlNumber`.
#[wasm_bindgen]
pub fn build_crl_tbs(input: &str) -> Result<String, String> {
    api::build_crl_tbs(input)
}

/// Inspect a CSR: return `{ subject, signature_valid, spki_b64,
/// requested_extensions }` for the CSR key-source path.
///
/// # Errors
///
/// A JSON `error` string when the CSR does not parse.
#[wasm_bindgen]
pub fn inspect_csr(input: &str) -> Result<String, String> {
    api::inspect_csr(input)
}

/// Assemble the final artifact from a signed `TBS` and self-check it against the
/// parent envelope; return `{ cert_pem, cert_b64, kind }`.
///
/// # Errors
///
/// A JSON `error` string on malformed input, a signature algorithm that
/// disagrees with the `TBS`, or a failed self-check (a scope violation names the
/// `dimension`).
#[wasm_bindgen]
pub fn assemble_and_verify(input: &str) -> Result<String, String> {
    api::assemble_and_verify(input)
}

/// Append one issuance entry to the hash-chained journal and return
/// `{ new_line }`.
///
/// # Errors
///
/// A JSON `error` string on malformed input or a storage failure.
#[wasm_bindgen]
pub fn journal_append(input: &str) -> Result<String, String> {
    api::journal_append(input)
}

/// Verify the journal's hash chain and return `{ status, position?,
/// unsigned_from_seq?, entry_count, last_signed_seq? }`.
///
/// # Errors
///
/// A JSON `error` string on malformed input.
#[wasm_bindgen]
pub fn journal_verify(input: &str) -> Result<String, String> {
    api::journal_verify(input)
}

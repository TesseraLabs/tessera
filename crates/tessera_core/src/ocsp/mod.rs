//! OCSP client: request building, HTTP transport, response verification.
//!
//! Implements the mechanism of the `ocsp` / `crl_then_ocsp` revocation
//! modes (RFC 6960 + the RFC 8954 nonce):
//!
//! 1. [`request::OcspRequestData::build`] — `OCSPRequest` from
//!    (subject, issuer) with a fresh 32-byte nonce;
//! 2. [`http::post_ocsp_request`] — one blocking HTTP/1.1 POST to the
//!    configured `ocsp_responder_url` under a single overall deadline;
//! 3. [`response::verify_ocsp_response`] — fail-closed parse + verify
//!    (signature to `[trust]` anchors, nonce, validity window) yielding a
//!    definite [`response::CertStatus`];
//! 4. [`cache::OcspCache`] — on-disk DER cache keyed by the `CertID`
//!    fields; entries are *untrusted* bytes that callers re-verify through
//!    step 3 with `request_der = None` before use.
//!
//! Mode dispatch (which certificates get checked, CRL interplay, when the
//! cache is consulted) lives with the revocation orchestration, not here.
//! All OCSP primitives come from the `openssl` crate — no home-grown
//! cryptography; the only additions are the few libcrypto helpers
//! `openssl 0.10` does not wrap (see `sys`).

pub mod cache;
pub mod http;
pub mod request;
pub mod response;
mod sys;

pub use cache::{OcspCache, OcspCacheKey};
pub use http::{post_ocsp_request, OcspScheme, OcspUrl, MAX_RESPONSE_BYTES};
pub use request::{OcspRequestData, OCSP_NONCE_LEN};
pub use response::{verify_ocsp_response, CertStatus, OcspVerifyContext};

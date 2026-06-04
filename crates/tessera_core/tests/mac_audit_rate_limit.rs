#![allow(clippy::unwrap_used)]

//! Verifies that `emit_cert_ext_parse_failed` deduplicates repeated
//! emissions for the same certificate fingerprint inside the 60-second
//! sliding window.
//!
//! We assert this via the public hook `should_emit_parse_failed`, which
//! returns `true` only when a fresh tracing event would have been
//! produced. This is sufficient because `emit_cert_ext_parse_failed`
//! short-circuits on `should_emit_parse_failed == false`.

use tessera_core::mac::audit;
use tessera_core::x509::CertIdent;

// Each test uses a fingerprint unique to that test so concurrent
// execution doesn't pollute the dedup cache. We deliberately do NOT
// call `reset_parse_failed_cache` since it would race with parallel
// tests sharing the same global state.

fn ident(fpr: &str) -> CertIdent {
    CertIdent {
        serial: "AB".into(),
        issuer: "CN=t".into(),
        cn: "x".into(),
        fingerprint: fpr.into(),
    }
}

#[test]
fn parse_failed_dedupes_same_fingerprint() {
    let fpr = "fp-rate-limit-dedupe-AAAA-bbbb-cccc";
    assert!(audit::should_emit_parse_failed(fpr), "first call must emit");
    assert!(
        !audit::should_emit_parse_failed(fpr),
        "second call within window must be suppressed"
    );
    assert!(
        !audit::should_emit_parse_failed(fpr),
        "third call within window must remain suppressed"
    );
}

#[test]
fn parse_failed_allows_distinct_fingerprints() {
    assert!(audit::should_emit_parse_failed("fp-distinct-A-1111-zzzz"));
    assert!(audit::should_emit_parse_failed("fp-distinct-B-2222-zzzz"));
    assert!(audit::should_emit_parse_failed("fp-distinct-C-3333-zzzz"));
}

#[test]
fn emit_cert_ext_parse_failed_is_callable() {
    // Smoke-test the full emitter path with a unique fingerprint.
    let cid = ident("fp-smoke-emit-XYZ-7777-uuuu");
    audit::emit_cert_ext_parse_failed("alice", &cid, "parse error: boom");
    // Second call dedupes silently — must not panic.
    audit::emit_cert_ext_parse_failed("alice", &cid, "parse error: boom2");
}

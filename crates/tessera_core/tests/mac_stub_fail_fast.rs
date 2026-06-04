//! Stub-build (`#[cfg(not(feature = "astra-mac"))]`) refuses to load a
//! config that demands `[mac].cert_integrity = "required"`.  Under
//! `astra-mac` the same config is acceptable, so this test is gated
//! out entirely under that feature.

#![cfg(not(feature = "astra-mac"))]
#![allow(clippy::unwrap_used)]

use tessera_core::config::load_validated_config;

#[test]
fn required_policy_rejected_on_stub_build() {
    let path = std::path::Path::new("tests/fixtures/policy_required_mac.toml");
    let err = load_validated_config(path).unwrap_err();
    let s = format!("{err}");
    assert!(
        s.contains("astra-mac"),
        "expected error to mention astra-mac feature, got: {s}"
    );
    assert!(
        s.contains("required"),
        "expected error to mention required, got: {s}"
    );
}

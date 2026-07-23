//! A hard MAC policy must name a runtime backend.

#![allow(clippy::unwrap_used)]

use tessera_core::config::load_validated_config;

#[test]
fn required_policy_without_backend_is_rejected() {
    let path = std::path::Path::new("tests/fixtures/policy_required_mac.toml");
    let err = load_validated_config(path).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("backend"), "unexpected error: {message}");
    assert!(message.contains("required"), "unexpected error: {message}");
}

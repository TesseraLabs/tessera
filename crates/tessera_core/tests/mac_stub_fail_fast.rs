//! A hard MAC policy must name a runtime backend.

#![allow(clippy::unwrap_used)]

// Shared with the crate's unit tests: config validation demands absolute
// paths, and what is absolute differs between Windows and Unix.
#[allow(dead_code)]
#[path = "../src/test_support.rs"]
mod test_support;

use tessera_core::config::load_validated_config;

#[test]
fn required_policy_without_backend_is_rejected() {
    // The fixture is written in POSIX terms and names no `[monitor]` section,
    // whose path defaults are POSIX too. Those paths are validated before the
    // MAC rule this test is about, so the fixture is rendered for the host and
    // loaded from there — the loader still reads a real file from disk.
    let fixture = std::fs::read_to_string("tests/fixtures/policy_required_mac.toml").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy_required_mac.toml");
    std::fs::write(&path, test_support::platform_config_toml(&fixture)).unwrap();

    let err = load_validated_config(&path).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("backend"), "unexpected error: {message}");
    assert!(message.contains("required"), "unexpected error: {message}");
}

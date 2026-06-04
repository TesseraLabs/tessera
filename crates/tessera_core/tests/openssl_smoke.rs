//! Smoke test verifying that the openssl crate links correctly.

/// Asserts that the OpenSSL/LibreSSL version banner is reachable at runtime.
#[test]
fn openssl_version_is_reachable() {
    let version = openssl::version::version();
    assert!(
        version.starts_with("OpenSSL") || version.starts_with("LibreSSL"),
        "unexpected libcrypto banner: {version}"
    );
}

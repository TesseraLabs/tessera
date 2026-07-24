//! Compile-time test support remains independent of runtime plugins.

#[cfg(feature = "mac-tests")]
#[test]
fn mac_tests_feature_enabled() {}

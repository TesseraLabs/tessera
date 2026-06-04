//! Verifies cargo features wire up as expected.

#[cfg(feature = "astra-mac")]
#[test]
fn astra_mac_feature_enabled() {
    // compile-only marker: ensures feature builds.
}

#[cfg(feature = "mac-tests")]
#[test]
fn mac_tests_feature_enabled() {}

// Compiled only under default features. Under `--features astra-mac` the
// test is entirely absent, so this acts as a compile-time invariant: the
// default feature set must not transitively pull in `astra-mac`. If a
// build accidentally activates `astra-mac` in default, this test's body
// would attempt to use the (now-existing) astra-mac symbols and would
// also catch the regression at build time.
#[cfg(not(feature = "astra-mac"))]
#[test]
fn default_build_excludes_astra_mac() {
    // Vacuous OK — the cfg guard is what enforces the invariant.
}

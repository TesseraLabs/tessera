//! Build script for `tessera_core`.
//!
//! The МКЦ FFI surface lives in a separately delivered runtime plugin. This
//! script only makes changes to the compile-time trust store invalidate the
//! crate so release builds embed the intended verification keys.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TESSERA_PLUGIN_PUBKEYS");
}

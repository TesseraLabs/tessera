//! Build script for `tessera_core`.
//!
//! The МКЦ FFI surface (and its `libpdp`/`libparsec-*` link directives) now
//! lives in the separate `tessera_mac_parsec` crate. The core crate's
//! `astra-mac` feature no longer links any native library — it only toggles
//! config-validation behaviour and audit/test gating — so this build script
//! is intentionally a no-op.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}

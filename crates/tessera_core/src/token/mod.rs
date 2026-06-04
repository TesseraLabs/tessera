//! Hardware token backends.
//!
//! Stage 4 of Tessera introduces support for PKCS#11 hardware tokens
//! (Rutoken, JaCarta-2 GOST, ESMART) where the private key is non-extractable
//! and on-device signing is performed via `C_Sign`.  Mode A (PKCS#12 software
//! bundle) lives outside this module — see [`crate::pkcs12`].
//!
//! The implementation wraps the `cryptoki` crate; on macOS dev hosts no real
//! PKCS#11 provider is shipped, so all integration tests under
//! `tests/pkcs11_*` are gated behind the `pkcs11-tests` Cargo feature **and**
//! a runtime check for [`pkcs11::test_helpers::pkcs11_test_module_path`].

pub mod pkcs11;

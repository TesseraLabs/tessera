//! Integration test for the PKCS#11 signing adapter.
//!
//! Gated by the `pkcs11-tests` feature and a runtime check for a real module,
//! mirroring `tessera_core`'s convention: when `PKCS11_MODULE_PATH` (and the
//! key/PIN env vars) are absent — as on a macOS dev host with no `SoftHSM` — the
//! test prints `skipped: ...` and returns `Ok`.
//!
//! To run against `SoftHSM2`, provision a token with an ECDSA P-256 key and set:
//!
//! ```text
//! PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
//! TESSERA_TEST_PKCS11_KEY=<private key CKA_LABEL>
//! TESSERA_TEST_PKCS11_PIN=<user PIN>
//! TESSERA_TEST_PKCS11_ALG=ecdsa-p256   # or ecdsa-p384 / rsa-sha256
//! ```

#![cfg(feature = "pkcs11-tests")]
#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use secrecy::SecretString;
use tessera_issuer::pkcs11::{Pkcs11Config, Pkcs11SignError, Pkcs11Signer};
use tessera_issuer::sign::{KeyId, SignatureAlgorithm, SignatureBackend};

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn algorithm_from_env() -> SignatureAlgorithm {
    match env_nonempty("TESSERA_TEST_PKCS11_ALG").as_deref() {
        Some("ecdsa-p384") => SignatureAlgorithm::EcdsaWithSha384,
        Some("rsa-sha256") => SignatureAlgorithm::RsaPkcs1Sha256,
        _ => SignatureAlgorithm::EcdsaWithSha256,
    }
}

#[test]
fn softhsm_signs_a_sample_tbs() {
    let Some(module) = env_nonempty("PKCS11_MODULE_PATH").map(PathBuf::from) else {
        println!("skipped: PKCS#11 module not available (set PKCS11_MODULE_PATH)");
        return;
    };
    if !module.exists() {
        println!(
            "skipped: PKCS#11 module path does not exist ({})",
            module.display()
        );
        return;
    }
    let (Some(key), Some(pin)) = (
        env_nonempty("TESSERA_TEST_PKCS11_KEY"),
        env_nonempty("TESSERA_TEST_PKCS11_PIN"),
    ) else {
        println!("skipped: set TESSERA_TEST_PKCS11_KEY and TESSERA_TEST_PKCS11_PIN");
        return;
    };

    let algorithm = algorithm_from_env();
    let config = Pkcs11Config {
        module_path: module,
        token_label: env_nonempty("TESSERA_TEST_PKCS11_TOKEN"),
        key_id: KeyId::new(key.clone()),
        algorithm,
        registry_key: None,
    };
    let pin_source =
        move || -> Result<SecretString, Pkcs11SignError> { Ok(SecretString::from(pin.clone())) };
    let signer = Pkcs11Signer::open(config, pin_source).expect("open pkcs#11 module");

    // Any bytes stand in for a TBS here — the token signs opaque input.
    let tbs = b"tessera issuer pkcs#11 integration test tbs bytes";
    let signature = signer
        .sign(tbs, &KeyId::new(key))
        .expect("token signs the sample TBS");
    assert_eq!(signature.algorithm, algorithm);
    assert!(!signature.bytes.is_empty(), "signature must be non-empty");

    // P-256 output must be a valid DER Ecdsa-Sig-Value (the adapter re-encodes
    // the token's raw r||s). P-384 is only checked for non-emptiness above,
    // since the `p256` reader is curve-specific.
    if algorithm == SignatureAlgorithm::EcdsaWithSha256 {
        p256::ecdsa::Signature::from_der(&signature.bytes)
            .expect("P-256 ECDSA signature must be DER-encoded");
    }
}

/// Opening a signer with a P-256 registry key succeeds: the startup probe reads
/// the curve from the token and accepts it.
///
/// Reuses `TESSERA_TEST_PKCS11_KEY` as the registry key, but only when it is a
/// P-256 key (the default algorithm), so the probe's accept path is exercised.
#[test]
fn softhsm_accepts_a_p256_registry_key() {
    let Some(module) = env_nonempty("PKCS11_MODULE_PATH").map(PathBuf::from) else {
        println!("skipped: PKCS#11 module not available (set PKCS11_MODULE_PATH)");
        return;
    };
    if !module.exists() {
        println!(
            "skipped: PKCS#11 module path does not exist ({})",
            module.display()
        );
        return;
    }
    let (Some(key), Some(pin)) = (
        env_nonempty("TESSERA_TEST_PKCS11_KEY"),
        env_nonempty("TESSERA_TEST_PKCS11_PIN"),
    ) else {
        println!("skipped: set TESSERA_TEST_PKCS11_KEY and TESSERA_TEST_PKCS11_PIN");
        return;
    };
    if algorithm_from_env() != SignatureAlgorithm::EcdsaWithSha256 {
        println!("skipped: TESSERA_TEST_PKCS11_KEY is not a P-256 key (set TESSERA_TEST_PKCS11_ALG=ecdsa-p256)");
        return;
    }

    let config = Pkcs11Config {
        module_path: module,
        token_label: env_nonempty("TESSERA_TEST_PKCS11_TOKEN"),
        key_id: KeyId::new("issuance-does-not-need-to-exist-for-this-probe"),
        algorithm: SignatureAlgorithm::EcdsaWithSha256,
        registry_key: Some(KeyId::new(key)),
    };
    let pin_source =
        move || -> Result<SecretString, Pkcs11SignError> { Ok(SecretString::from(pin.clone())) };
    // The probe runs inside open(): a P-256 registry key must let it construct.
    Pkcs11Signer::open(config, pin_source)
        .expect("a P-256 registry key must be accepted at startup");
}

/// Opening a signer with a non-P-256 registry key is refused at startup. Gated
/// on `TESSERA_TEST_PKCS11_P384_KEY` (a P-384 key label in the same token); when
/// unset the test skips, so CI can provision the key to exercise the reject path.
#[test]
fn softhsm_rejects_a_non_p256_registry_key() {
    let Some(module) = env_nonempty("PKCS11_MODULE_PATH").map(PathBuf::from) else {
        println!("skipped: PKCS#11 module not available (set PKCS11_MODULE_PATH)");
        return;
    };
    if !module.exists() {
        println!(
            "skipped: PKCS#11 module path does not exist ({})",
            module.display()
        );
        return;
    }
    let (Some(p384_key), Some(pin)) = (
        env_nonempty("TESSERA_TEST_PKCS11_P384_KEY"),
        env_nonempty("TESSERA_TEST_PKCS11_PIN"),
    ) else {
        println!(
            "skipped: set TESSERA_TEST_PKCS11_P384_KEY (a P-384 key) and TESSERA_TEST_PKCS11_PIN"
        );
        return;
    };

    let config = Pkcs11Config {
        module_path: module,
        token_label: env_nonempty("TESSERA_TEST_PKCS11_TOKEN"),
        key_id: KeyId::new("issuance-does-not-need-to-exist-for-this-probe"),
        algorithm: SignatureAlgorithm::EcdsaWithSha256,
        registry_key: Some(KeyId::new(p384_key)),
    };
    let pin_source =
        move || -> Result<SecretString, Pkcs11SignError> { Ok(SecretString::from(pin.clone())) };
    let err = Pkcs11Signer::open(config, pin_source)
        .expect_err("a P-384 registry key must be refused at startup");
    assert!(
        matches!(err, Pkcs11SignError::RegistryKeyNotP256(_)),
        "expected RegistryKeyNotP256, got {err:?}"
    );
}

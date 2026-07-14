//! Integration test for the Vault Transit signing adapter.
//!
//! Gated by the `vault-tests` feature and a runtime check for the `vault`
//! binary. When `vault` is not on `PATH` — as on this dev host — the test
//! prints `skipped: ...` and returns `Ok`. Otherwise it starts a throwaway
//! dev-server, creates an ECDSA P-256 Transit key, signs a sample TBS through
//! [`VaultSigner`], and verifies the returned signature locally.

#![cfg(feature = "vault-tests")]
#![allow(missing_docs)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use tessera_issuer::sign::{KeyId, SignatureAlgorithm, SignatureBackend};
use tessera_issuer::vault::{VaultConfig, VaultSigner};

const VAULT_ADDR: &str = "http://127.0.0.1:8209";
const ROOT_TOKEN: &str = "tessera-dev-root-token";
const KEY_NAME: &str = "tessera-ca";

/// A dev-server that is killed when the guard drops.
struct VaultGuard(Child);

impl Drop for VaultGuard {
    fn drop(&mut self) {
        if self.0.kill().is_err() {
            // Already exited; nothing to clean up.
        }
        if self.0.wait().is_err() {
            // Reaping best-effort.
        }
    }
}

fn vault_available() -> bool {
    Command::new("vault")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run a `vault` CLI command against the dev-server, returning stdout.
fn vault_cmd(args: &[&str]) -> Vec<u8> {
    let output = Command::new("vault")
        .args(args)
        .env("VAULT_ADDR", VAULT_ADDR)
        .env("VAULT_TOKEN", ROOT_TOKEN)
        .output()
        .expect("run vault command");
    assert!(
        output.status.success(),
        "vault {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn start_dev_server() -> VaultGuard {
    let child = Command::new("vault")
        .args([
            "server",
            "-dev",
            "-dev-root-token-id",
            ROOT_TOKEN,
            "-dev-listen-address",
            "127.0.0.1:8209",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vault dev server");
    let guard = VaultGuard(child);

    // Poll the health endpoint until the server answers.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let up = ureq::get(&format!("{VAULT_ADDR}/v1/sys/health"))
            .call()
            .is_ok();
        if up {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "vault dev-server did not come up"
        );
        std::thread::sleep(Duration::from_millis(150));
    }
    guard
}

#[test]
fn transit_signs_and_verifies_a_sample_tbs() {
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;

    if !vault_available() {
        println!("skipped: `vault` binary not found on PATH");
        return;
    }

    let _guard = start_dev_server();
    vault_cmd(&["secrets", "enable", "transit"]);
    vault_cmd(&[
        "write",
        "-f",
        &format!("transit/keys/{KEY_NAME}"),
        "type=ecdsa-p256",
    ]);

    // Read the key's public part (PEM) for local verification.
    let read = vault_cmd(&["read", "-format=json", &format!("transit/keys/{KEY_NAME}")]);
    let json: serde_json::Value = serde_json::from_slice(&read).expect("parse key read");
    let public_pem = json["data"]["keys"]["1"]["public_key"]
        .as_str()
        .expect("public key PEM present")
        .to_owned();
    let verifying_key =
        p256::ecdsa::VerifyingKey::from_public_key_pem(&public_pem).expect("parse PEM public key");

    let signer = VaultSigner::new(
        VaultConfig {
            address: VAULT_ADDR.to_owned(),
            mount: "transit".to_owned(),
            key_name: KEY_NAME.to_owned(),
            key_id: KeyId::new(KEY_NAME),
            algorithm: SignatureAlgorithm::EcdsaWithSha256,
            prehashed: false,
            ca_bundle_path: None,
        },
        SecretString::from(ROOT_TOKEN.to_owned()),
    )
    .expect("build vault signer");

    let tbs = b"tessera issuer vault transit integration test tbs";
    let signature = signer
        .sign(tbs, &KeyId::new(KEY_NAME))
        .expect("vault signs");
    assert_eq!(signature.algorithm, SignatureAlgorithm::EcdsaWithSha256);

    let der = p256::ecdsa::Signature::from_der(&signature.bytes)
        .expect("vault returns DER ECDSA (marshaling_algorithm=asn1)");
    verifying_key
        .verify(tbs, &der)
        .expect("the signature verifies under the transit key");
}

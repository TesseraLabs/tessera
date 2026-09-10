//! Integration test for the Vault Transit signing adapter.
//!
//! Gated by the `vault-tests` feature. Enabling that feature is a statement that
//! this machine has a Vault stand, so a missing `vault` binary fails the test
//! instead of skipping it: the previous version printed `skipped: ...` and
//! returned `Ok`, and that is why a defect that made **every** https request
//! panic lived here unnoticed — the test never reached a request at all.
//!
//! The server is started with `-dev-tls`, which is the only mode that exercises
//! the path the product uses: [`VaultSigner`] refuses a plaintext address, so a
//! test against `http://` never builds a signer and never touches the TLS stack.
//! A test that cannot reach the code it names is worse than no test.
//!
//! What it does: start a throwaway dev-server over TLS, create an ECDSA P-256
//! Transit key, sign a sample TBS through [`VaultSigner`] against the generated
//! CA, and verify the returned signature locally with the public half.

#![cfg(feature = "vault-tests")]
#![allow(missing_docs)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use tessera_issuer::sign::{KeyId, SignatureAlgorithm, SignatureBackend};
use tessera_issuer::vault::{VaultConfig, VaultSigner};

const VAULT_ADDR: &str = "https://127.0.0.1:8209";
const LISTEN_ADDRESS: &str = "127.0.0.1:8209";
const ROOT_TOKEN: &str = "tessera-dev-root-token";
const KEY_NAME: &str = "tessera-ca";

/// A dev-server that is killed when the guard drops, and the directory holding
/// the TLS material it generated.
struct VaultGuard {
    child: Child,
    /// The directory the server keeps its TLS material and its token cache in.
    /// Held for the lifetime of the guard: dropping it takes the CA with it.
    state: tempfile::TempDir,
    ca_bundle: PathBuf,
}

impl Drop for VaultGuard {
    fn drop(&mut self) {
        if self.child.kill().is_err() {
            // Already exited; nothing to clean up.
        }
        if self.child.wait().is_err() {
            // Reaping best-effort.
        }
    }
}

/// Fails the test when the stand this feature promises is not there.
///
/// Not a skip. `--features vault-tests` says "there is a Vault here"; if there
/// is not, the run has to say so out loud rather than report a pass for a test
/// that did nothing.
fn require_vault() {
    let present = Command::new("vault")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    assert!(
        present,
        "the `vault-tests` feature is on but no `vault` binary is on PATH; \
         build without the feature, or install Vault — this test does not pass \
         by not running"
    );
}

/// Runs a `vault` CLI command against the dev-server, returning stdout.
fn vault_cmd(guard: &VaultGuard, args: &[&str]) -> Vec<u8> {
    let output = Command::new("vault")
        .args(args)
        .env("VAULT_ADDR", VAULT_ADDR)
        .env("VAULT_CACERT", &guard.ca_bundle)
        .env("VAULT_TOKEN", ROOT_TOKEN)
        // The CLI caches a token under `$HOME`, and a test has no business
        // writing into the home directory of whoever runs it.
        .env("HOME", guard.state.path())
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
    let state = tempfile::tempdir().expect("temporary directory for the vault stand");
    let cert_dir = state.path().join("tls");
    std::fs::create_dir_all(&cert_dir).expect("create the TLS directory");

    let child = Command::new("vault")
        .args([
            "server",
            "-dev",
            "-dev-tls",
            "-dev-tls-cert-dir",
            cert_dir.to_str().expect("a UTF-8 temporary path"),
            "-dev-root-token-id",
            ROOT_TOKEN,
            "-dev-listen-address",
            LISTEN_ADDRESS,
        ])
        .env("HOME", state.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vault dev server");

    let guard = VaultGuard {
        child,
        ca_bundle: cert_dir.join("vault-ca.pem"),
        state,
    };

    // Waited for with the Vault CLI rather than with an https client of our
    // own: the client is the thing under test here, and a harness that fell
    // over on the same defect would report "the server did not come up".
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if ca_bundle_ready(&guard.ca_bundle) && vault_answers(&guard) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the vault dev-server did not come up on {VAULT_ADDR}"
        );
        std::thread::sleep(Duration::from_millis(150));
    }
    guard
}

/// Reports whether the generated CA is on disk and non-empty.
fn ca_bundle_ready(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.len() > 0)
}

/// Reports whether the server answers a status call.
fn vault_answers(guard: &VaultGuard) -> bool {
    Command::new("vault")
        .arg("status")
        .env("VAULT_ADDR", VAULT_ADDR)
        .env("VAULT_CACERT", &guard.ca_bundle)
        .env("VAULT_TOKEN", ROOT_TOKEN)
        .env("HOME", guard.state.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn transit_signs_and_verifies_a_sample_tbs() {
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;

    require_vault();

    let guard = start_dev_server();
    vault_cmd(&guard, &["secrets", "enable", "transit"]);
    vault_cmd(
        &guard,
        &[
            "write",
            "-f",
            &format!("transit/keys/{KEY_NAME}"),
            "type=ecdsa-p256",
        ],
    );

    // Read the key's public part (PEM) for local verification.
    let read = vault_cmd(
        &guard,
        &["read", "-format=json", &format!("transit/keys/{KEY_NAME}")],
    );
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
            // The CA the dev-server generated for itself. A private CA is the
            // shape a real contour has, and it is the shape this path is built
            // for — see the module docs of the adapter.
            ca_bundle_path: Some(guard.ca_bundle.clone()),
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

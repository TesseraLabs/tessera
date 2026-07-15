//! Vault / `OpenBao` Transit signing adapter.
//!
//! The CA key lives in a Transit secrets engine and never leaves it. This
//! adapter sends only the built TBS (or its digest) to the Transit `sign`
//! endpoint and gets back a signature. It deliberately does **not** use Vault
//! PKI: Go's `encoding/asn1` cannot represent OID arcs wider than `int64`, and
//! Tessera's `2.25.<UUID>` extensions carry a ~128-bit arc — so a certificate
//! with those extensions cannot be minted through Vault PKI. All validation
//! happens in the issuance core before this adapter is ever called; Vault only
//! signs.
//!
//! # What is sent
//!
//! By default the raw TBS is posted with `prehashed=false` and a
//! `hash_algorithm`, so Vault hashes and signs in one step. When the Transit
//! key is configured for pre-hashed input, [`VaultConfig::prehashed`] makes the
//! adapter compute the digest locally and post it with `prehashed=true`.
//!
//! For ECDSA keys `marshaling_algorithm=asn1` makes Vault return the DER
//! `Ecdsa-Sig-Value` the certificate `signature` `BIT STRING` needs; RSA keys
//! use `signature_algorithm=pkcs1v15`.
//!
//! # TLS trust
//!
//! A corporate Vault or `OpenBao` almost always sits behind a private CA, so
//! this adapter does **not** bundle Mozilla's root store. By default TLS trust
//! comes from the host platform's certificate store (via
//! `rustls-platform-verifier`); for air-gapped contours, set
//! [`VaultConfig::ca_bundle_path`] to a PEM file and only those roots are
//! trusted.
//!
//! # Token handling
//!
//! The Vault token authenticates every request via the `X-Vault-Token` header.
//! It is held in a [`SecretString`], never logged, and never placed in an error
//! message or the type's [`Debug`].

use std::path::{Path, PathBuf};

use base64::Engine as _;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256, Sha384};
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};
use ureq::Agent;

use crate::sign::{KeyId, SignError, Signature, SignatureAlgorithm, SignatureBackend};

/// Standard base64 (with padding) — the encoding Vault Transit uses for both
/// the `input` field and the signature payload.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Where the CA key lives inside Vault Transit, and how it signs.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Base Vault address, e.g. `https://vault.example:8200` (no trailing `/`).
    pub address: String,
    /// Transit mount path, typically `transit`.
    pub mount: String,
    /// Transit key name to sign with.
    pub key_name: String,
    /// The CA key identifier the issuance core passes to [`SignatureBackend`].
    pub key_id: KeyId,
    /// The algorithm the Transit key signs with.
    pub algorithm: SignatureAlgorithm,
    /// When `true`, hash the TBS locally and send the digest with
    /// `prehashed=true`; when `false`, send the raw TBS and let Vault hash it.
    pub prehashed: bool,
    /// Optional PEM CA bundle to trust instead of the platform store. `None`
    /// uses the host's certificate store; `Some(path)` trusts exactly the roots
    /// in that file (air-gapped / private-CA contours).
    pub ca_bundle_path: Option<PathBuf>,
}

/// A [`SignatureBackend`] backed by a Vault / `OpenBao` Transit key.
pub struct VaultSigner {
    config: VaultConfig,
    token: SecretString,
    agent: Agent,
}

// Manual `Debug` so the Vault token can never be printed.
impl core::fmt::Debug for VaultSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultSigner")
            .field("address", &self.config.address)
            .field("mount", &self.config.mount)
            .field("key_name", &self.config.key_name)
            .field("key_id", &self.config.key_id)
            .field("algorithm", &self.config.algorithm)
            .field("prehashed", &self.config.prehashed)
            .field("ca_bundle_path", &self.config.ca_bundle_path)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl VaultSigner {
    /// Build a signer with an explicit token.
    ///
    /// # Errors
    ///
    /// - [`VaultSignError::InsecureAddress`] when [`VaultConfig::address`] is not
    ///   an `https://` URL: the `X-Vault-Token` header authenticates every
    ///   request, so an `http://` endpoint would send the bearer token in the
    ///   clear. Transit signing must always run over TLS — there is no localhost
    ///   exception.
    /// - [`VaultSignError::CaBundle`] when [`VaultConfig::ca_bundle_path`] is set
    ///   but the file cannot be read or holds no valid PEM certificate.
    pub fn new(config: VaultConfig, token: SecretString) -> Result<Self, VaultSignError> {
        require_https(&config.address)?;
        let agent = build_agent(config.ca_bundle_path.as_deref())?;
        Ok(Self {
            config,
            token,
            agent,
        })
    }

    /// Build a signer, reading the token from the `VAULT_TOKEN` environment
    /// variable.
    ///
    /// # Errors
    ///
    /// - [`VaultSignError::MissingToken`] when `VAULT_TOKEN` is unset or empty.
    /// - [`VaultSignError::CaBundle`] when a configured CA bundle cannot be
    ///   loaded.
    pub fn from_env(config: VaultConfig) -> Result<Self, VaultSignError> {
        let token = std::env::var("VAULT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .ok_or(VaultSignError::MissingToken)?;
        Self::new(config, SecretString::from(token))
    }

    /// POST the TBS (or its digest) to the Transit `sign` endpoint.
    fn sign_via_transit(&self, tbs_der: &[u8]) -> Result<Vec<u8>, VaultSignError> {
        let hash_algorithm = hash_algorithm_name(self.config.algorithm)?;
        let input = if self.config.prehashed {
            B64.encode(digest_tbs(self.config.algorithm, tbs_der)?)
        } else {
            B64.encode(tbs_der)
        };

        let mut fields = serde_json::Map::new();
        fields.insert("input".to_owned(), serde_json::Value::from(input));
        fields.insert(
            "prehashed".to_owned(),
            serde_json::Value::from(self.config.prehashed),
        );
        fields.insert(
            "hash_algorithm".to_owned(),
            serde_json::Value::from(hash_algorithm),
        );
        // Shape the signature the way the certificate needs it.
        match self.config.algorithm {
            SignatureAlgorithm::EcdsaWithSha256 | SignatureAlgorithm::EcdsaWithSha384 => {
                fields.insert(
                    "marshaling_algorithm".to_owned(),
                    serde_json::Value::from("asn1"),
                );
            }
            SignatureAlgorithm::RsaPkcs1Sha256 => {
                fields.insert(
                    "signature_algorithm".to_owned(),
                    serde_json::Value::from("pkcs1v15"),
                );
            }
            SignatureAlgorithm::Ed25519 => {
                return Err(VaultSignError::UnsupportedAlgorithm(self.config.algorithm))
            }
        }
        let body = serde_json::Value::Object(fields);

        let url = format!(
            "{}/v1/{}/sign/{}",
            self.config.address.trim_end_matches('/'),
            self.config.mount,
            self.config.key_name,
        );
        let mut resp = self
            .agent
            .post(&url)
            .header("X-Vault-Token", self.token.expose_secret())
            .send_json(&body)
            .map_err(|e| VaultSignError::Http(e.to_string()))?;
        let parsed: VaultSignResponse = resp
            .body_mut()
            .read_json()
            .map_err(|e| VaultSignError::Decode(e.to_string()))?;
        decode_transit_signature(&parsed.data.signature)
    }
}

impl SignatureBackend for VaultSigner {
    fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
        if key_id == &self.config.key_id {
            Ok(self.config.algorithm)
        } else {
            Err(SignError::UnknownKey(key_id.as_str().to_owned()))
        }
    }

    fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
        if key_id != &self.config.key_id {
            return Err(SignError::UnknownKey(key_id.as_str().to_owned()));
        }
        // The Display of `VaultSignError` never contains the Vault token.
        let bytes = self
            .sign_via_transit(tbs_der)
            .map_err(|e| SignError::Backend(e.to_string()))?;
        Ok(Signature {
            algorithm: self.config.algorithm,
            bytes,
        })
    }
}

/// Rejects a Vault address that is not an `https://` URL.
///
/// The Vault token travels in the `X-Vault-Token` request header, so a plaintext
/// `http://` endpoint would expose it on the wire. TLS is mandatory for every
/// contour, including localhost, because Transit signing has no plaintext mode.
///
/// The scheme match is ASCII case-insensitive, as URL schemes are.
pub(crate) fn require_https(address: &str) -> Result<(), VaultSignError> {
    let scheme_ok = address
        .split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"));
    if scheme_ok {
        Ok(())
    } else {
        Err(VaultSignError::InsecureAddress(address.to_owned()))
    }
}

/// Build the ureq [`Agent`] with the right TLS trust anchors.
///
/// With no bundle, trust is the host's native certificate store; with a bundle,
/// only the roots parsed from that PEM file are trusted. TLS is provided by the
/// platform (native-tls), so no Mozilla root bundle is compiled in.
fn build_agent(ca_bundle_path: Option<&Path>) -> Result<Agent, VaultSignError> {
    let root_certs = match ca_bundle_path {
        Some(path) => {
            let certs = load_ca_bundle(path)?;
            RootCerts::new_with_certs(&certs)
        }
        None => RootCerts::PlatformVerifier,
    };
    let tls = TlsConfig::builder()
        .provider(TlsProvider::NativeTls)
        .root_certs(root_certs)
        .build();
    let config = ureq::config::Config::builder().tls_config(tls).build();
    Ok(config.new_agent())
}

/// Read a PEM CA bundle from disk into a list of trust anchors.
///
/// # Errors
///
/// [`VaultSignError::CaBundle`] when the file is unreadable, is not UTF-8, holds
/// a malformed certificate, or contains no certificate at all.
fn load_ca_bundle(path: &Path) -> Result<Vec<Certificate<'static>>, VaultSignError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let bytes = std::fs::read(path)
        .map_err(|e| VaultSignError::CaBundle(format!("{}: {e}", path.display())))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| VaultSignError::CaBundle("CA bundle is not valid UTF-8".to_owned()))?;

    let mut certs = Vec::new();
    // `split_inclusive` keeps each `END` marker with its block, so every block
    // that also holds a `BEGIN` is one complete PEM certificate.
    for block in text.split_inclusive(END) {
        if !block.contains(BEGIN) {
            continue;
        }
        let cert = Certificate::from_pem(block.as_bytes())
            .map_err(|e| VaultSignError::CaBundle(format!("invalid certificate: {e}")))?;
        certs.push(cert);
    }
    if certs.is_empty() {
        return Err(VaultSignError::CaBundle(format!(
            "no PEM certificate found in {}",
            path.display()
        )));
    }
    Ok(certs)
}

/// The Vault Transit `hash_algorithm` string for an algorithm.
fn hash_algorithm_name(algorithm: SignatureAlgorithm) -> Result<&'static str, VaultSignError> {
    match algorithm {
        SignatureAlgorithm::EcdsaWithSha256 | SignatureAlgorithm::RsaPkcs1Sha256 => Ok("sha2-256"),
        SignatureAlgorithm::EcdsaWithSha384 => Ok("sha2-384"),
        SignatureAlgorithm::Ed25519 => Err(VaultSignError::UnsupportedAlgorithm(algorithm)),
    }
}

/// Hash the TBS with the algorithm's digest, for the `prehashed=true` path.
fn digest_tbs(algorithm: SignatureAlgorithm, tbs_der: &[u8]) -> Result<Vec<u8>, VaultSignError> {
    match algorithm {
        SignatureAlgorithm::EcdsaWithSha256 | SignatureAlgorithm::RsaPkcs1Sha256 => {
            Ok(Sha256::digest(tbs_der).to_vec())
        }
        SignatureAlgorithm::EcdsaWithSha384 => Ok(Sha384::digest(tbs_der).to_vec()),
        SignatureAlgorithm::Ed25519 => Err(VaultSignError::UnsupportedAlgorithm(algorithm)),
    }
}

/// Strip the `vault:vN:` prefix and base64-decode the signature payload.
fn decode_transit_signature(signature: &str) -> Result<Vec<u8>, VaultSignError> {
    // Format: `vault:v<version>:<base64>` (OpenBao mirrors it). The payload is
    // the final colon-separated field.
    let payload = signature
        .rsplit(':')
        .next()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| VaultSignError::Decode("empty transit signature".to_owned()))?;
    B64.decode(payload)
        .map_err(|e| VaultSignError::Decode(format!("signature base64: {e}")))
}

/// The subset of the Transit `sign` response we read.
#[derive(serde::Deserialize)]
struct VaultSignResponse {
    data: VaultSignData,
}

#[derive(serde::Deserialize)]
struct VaultSignData {
    /// `vault:v<n>:<base64>`.
    signature: String,
}

/// Errors from the Vault Transit signing adapter.
///
/// No variant carries the Vault token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultSignError {
    /// `VAULT_TOKEN` was unset or empty when building from the environment.
    #[error("vault token missing (set VAULT_TOKEN)")]
    MissingToken,
    /// The Vault address is not `https://`; the token would travel in the clear.
    #[error("vault address must be https:// (got {0:?})")]
    InsecureAddress(String),
    /// The algorithm has no Vault Transit representation here (Ed25519 is not
    /// wired up).
    #[error("algorithm not supported by the vault adapter: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    /// The HTTP request failed or Vault returned a non-2xx status.
    #[error("vault transport error: {0}")]
    Http(String),
    /// The response could not be parsed, or the signature payload was malformed.
    #[error("vault response decode error: {0}")]
    Decode(String),
    /// The configured CA bundle could not be loaded.
    #[error("vault CA bundle error: {0}")]
    CaBundle(String),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const SECRET_TOKEN: &str = "s.SuperSecretVaultToken1234567890";

    fn config() -> VaultConfig {
        VaultConfig {
            address: "https://vault.example:8200".to_owned(),
            mount: "transit".to_owned(),
            key_name: "tessera-ca".to_owned(),
            key_id: KeyId::new("tessera-ca"),
            algorithm: SignatureAlgorithm::EcdsaWithSha256,
            prehashed: false,
            ca_bundle_path: None,
        }
    }

    #[test]
    fn debug_never_contains_the_token() {
        let signer =
            VaultSigner::new(config(), SecretString::from(SECRET_TOKEN.to_owned())).unwrap();
        let rendered = format!("{signer:?}");
        assert!(!rendered.contains(SECRET_TOKEN), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn http_address_is_rejected() {
        let mut config = config();
        config.address = "http://vault.example:8200".to_owned();
        let err = VaultSigner::new(config, SecretString::from(SECRET_TOKEN.to_owned()))
            .expect_err("an http:// Vault address must fail construction");
        assert!(matches!(err, VaultSignError::InsecureAddress(_)), "{err:?}");
    }

    #[test]
    fn http_localhost_is_rejected_too() {
        // Transit signing has no plaintext mode, so even localhost must be TLS.
        assert!(matches!(
            require_https("http://127.0.0.1:8200"),
            Err(VaultSignError::InsecureAddress(_))
        ));
    }

    #[test]
    fn https_address_is_accepted() {
        // Case-insensitive scheme, as URLs are.
        assert!(require_https("https://vault.example:8200").is_ok());
        assert!(require_https("HTTPS://vault.example:8200").is_ok());
    }

    #[test]
    fn missing_ca_bundle_reports_a_clear_error() {
        let mut config = config();
        config.ca_bundle_path = Some(PathBuf::from("/nonexistent/__tessera_ca_bundle__.pem"));
        let err = VaultSigner::new(config, SecretString::from(SECRET_TOKEN.to_owned()))
            .expect_err("a missing CA bundle must fail construction");
        match err {
            VaultSignError::CaBundle(msg) => {
                assert!(
                    msg.contains("__tessera_ca_bundle__.pem"),
                    "error should name the bundle path: {msg}"
                );
                assert!(!msg.contains(SECRET_TOKEN));
            }
            other => panic!("expected CaBundle, got {other:?}"),
        }
    }

    #[test]
    fn error_display_never_contains_the_token() {
        for err in [
            VaultSignError::MissingToken,
            VaultSignError::Http("connect refused".to_owned()),
            VaultSignError::Decode("bad base64".to_owned()),
        ] {
            let shown = format!("{err} | {err:?}");
            assert!(!shown.contains(SECRET_TOKEN), "{shown}");
        }
    }

    #[test]
    fn algorithm_query_matches_configured_key() {
        let signer =
            VaultSigner::new(config(), SecretString::from(SECRET_TOKEN.to_owned())).unwrap();
        assert_eq!(
            signer.algorithm(&KeyId::new("tessera-ca")).unwrap(),
            SignatureAlgorithm::EcdsaWithSha256
        );
        let err = signer.algorithm(&KeyId::new("other")).unwrap_err();
        assert!(matches!(err, SignError::UnknownKey(_)));
    }

    #[test]
    fn transit_signature_prefix_is_stripped_and_decoded() {
        let payload = B64.encode([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
        let raw = decode_transit_signature(&format!("vault:v1:{payload}")).unwrap();
        assert_eq!(raw, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn transit_signature_rejects_empty_payload() {
        let err = decode_transit_signature("vault:v1:").unwrap_err();
        assert!(matches!(err, VaultSignError::Decode(_)), "{err:?}");
    }

    #[test]
    fn hash_and_digest_track_the_algorithm() {
        assert_eq!(
            hash_algorithm_name(SignatureAlgorithm::EcdsaWithSha256).unwrap(),
            "sha2-256"
        );
        assert_eq!(
            hash_algorithm_name(SignatureAlgorithm::EcdsaWithSha384).unwrap(),
            "sha2-384"
        );
        assert_eq!(
            digest_tbs(SignatureAlgorithm::EcdsaWithSha256, b"abc").unwrap(),
            Sha256::digest(b"abc").to_vec()
        );
        assert_eq!(
            digest_tbs(SignatureAlgorithm::EcdsaWithSha384, b"abc")
                .unwrap()
                .len(),
            48
        );
    }

    #[test]
    fn ed25519_is_unsupported() {
        assert!(matches!(
            hash_algorithm_name(SignatureAlgorithm::Ed25519).unwrap_err(),
            VaultSignError::UnsupportedAlgorithm(_)
        ));
    }
}

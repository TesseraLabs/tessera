//! End-to-end test for the on-disk (`file`) signing backend.
//!
//! Unlike the PKCS#11 and Vault integration tests, this one needs no external
//! dependency: the CA key is a PKCS#8 file the test itself generates. It walks
//! the full issuance path — self-signed root, then a sub-CA, then a leaf —
//! through the public issuance API with a [`FileSigner`], for all three
//! supported key types (ECDSA P-256, ECDSA P-384, RSA), and cryptographically
//! verifies each issued certificate's signature against the CA public key. A
//! final case decrypts an encrypted PKCS#8 key through a passphrase source (the
//! same trait the CLI's `TESSERA_ISSUER_KEY_PASSPHRASE` fallback implements).

#![cfg(feature = "file")]
#![allow(missing_docs)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use secrecy::SecretString;
use tempfile::NamedTempFile;

use pkcs8::rand_core::{CryptoRng, RngCore};
use pkcs8::{EncodePrivateKey as _, EncryptedPrivateKeyInfo, LineEnding, PrivateKeyInfo};
use sha2::{Digest as _, Sha256};

use tessera_ext::delegation::DelegationConstraints;
use tessera_issuer::file::{FileConfig, FileSignError, FileSigner, PassphraseSource};
use tessera_issuer::journal::FileStorage;
use tessera_issuer::sign::{KeyId, SignatureAlgorithm, SignatureBackend};
use tessera_issuer::{
    issue_ca, issue_leaf, issue_root, CaRequest, Journal, LeafRequest, Serial, Validity,
};

const NOW: u64 = 1_600_000_000;
const KEY_ID: &str = "e2e-ca";
const PASSPHRASE: &str = "e2e-passphrase";

/// The ASN.1 `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2), used to verify the
/// RSA arm without aligning digest-trait versions across crates.
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// A well-formed `SubjectPublicKeyInfo` (a fixed P-256 point) for the subject
/// field of the issued certificates. The subject key is independent of the CA
/// signing key, so this fixed value stands in for every subject here.
const SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1,
    0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
    0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe,
    0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b,
    0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/// A deterministic RNG for reproducible RSA generation and PBES2 fixtures.
/// Implements the `RustCrypto` `rand_core` 0.6 and 0.10 traits used by the EC
/// and hardened RSA stacks respectively; not for production use.
struct FixtureRng(u64);

impl FixtureRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.next()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), pkcs8::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixtureRng {}

impl rsa::rand_core::TryRng for FixtureRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl rsa::rand_core::TryCryptoRng for FixtureRng {}

/// Verifies certificate signatures against the CA public key by key type.
enum Verifier {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Rsa(Box<rsa::RsaPublicKey>),
}

impl Verifier {
    fn check(&self, tbs: &[u8], sig: &[u8]) {
        match self {
            Verifier::P256(key) => {
                use p256::ecdsa::signature::Verifier as _;
                let signature = p256::ecdsa::Signature::from_der(sig).unwrap();
                key.verify(tbs, &signature).unwrap();
            }
            Verifier::P384(key) => {
                use p384::ecdsa::signature::Verifier as _;
                let signature = p384::ecdsa::Signature::from_der(sig).unwrap();
                key.verify(tbs, &signature).unwrap();
            }
            Verifier::Rsa(key) => {
                let hashed = Sha256::digest(tbs);
                let scheme = rsa::pkcs1v15::Pkcs1v15Sign {
                    hash_len: Some(hashed.len()),
                    prefix: Box::from(SHA256_DIGEST_INFO_PREFIX.as_slice()),
                };
                key.verify(scheme, &hashed, sig).unwrap();
            }
        }
    }
}

/// Write PKCS#8 bytes to a fresh 0600 temp file (kept alive by the returned
/// handle).
fn write_key(bytes: &[u8]) -> NamedTempFile {
    use std::io::Write as _;
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    file
}

/// A passphrase source that must never be consulted (plaintext keys).
fn never() -> impl PassphraseSource {
    || {
        Err(FileSignError::PassphraseUnavailable(
            "must not be asked".to_owned(),
        ))
    }
}

fn p256_ca() -> (Vec<u8>, Verifier) {
    let secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    let verifying = *p256::ecdsa::SigningKey::from(secret.clone()).verifying_key();
    let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
    (pem.as_bytes().to_vec(), Verifier::P256(verifying))
}

fn p384_ca() -> (Vec<u8>, Verifier) {
    let secret = p384::SecretKey::from_slice(&[0x22; 48]).unwrap();
    let verifying = *p384::ecdsa::SigningKey::from(secret.clone()).verifying_key();
    let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
    (pem.as_bytes().to_vec(), Verifier::P384(verifying))
}

fn rsa_ca() -> (Vec<u8>, Verifier) {
    use rsa::pkcs8::{EncodePrivateKey as _, LineEnding as RsaLineEnding};

    let mut rng = FixtureRng::new(0x00A5_1234);
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public = rsa::RsaPublicKey::from(&private);
    let pem = private.to_pkcs8_pem(RsaLineEnding::LF).unwrap();
    (pem.as_bytes().to_vec(), Verifier::Rsa(Box::new(public)))
}

/// Split a `Certificate` DER into (signed TBS bytes, signature octets).
///
/// A `Certificate` is `SEQUENCE { tbsCertificate, signatureAlgorithm, signature
/// BIT STRING }`. The TBS bytes that were signed are the first element's full
/// TLV; the signature is the BIT STRING content past its leading unused-bits
/// octet.
fn split_certificate(der: &[u8]) -> (&[u8], &[u8]) {
    let body = tlv_content(der);
    let (tbs, rest) = take_tlv(body);
    let (_algid, rest) = take_tlv(rest);
    let (bitstring, _) = take_tlv(rest);
    let bits = tlv_content(bitstring);
    (tbs, &bits[1..])
}

/// The number of length octets a definite-length TLV uses at `der` (after the
/// one-byte tag), plus the content length.
fn length_of(der: &[u8]) -> (usize, usize) {
    let first = der[1];
    if first < 0x80 {
        (usize::from(first), 1)
    } else {
        let n = usize::from(first & 0x7f);
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(der[2 + i]);
        }
        (len, 1 + n)
    }
}

/// Return one full TLV element at the front of `der` and the remainder.
fn take_tlv(der: &[u8]) -> (&[u8], &[u8]) {
    let (content_len, len_octets) = length_of(der);
    let total = 1 + len_octets + content_len;
    (&der[..total], &der[total..])
}

/// Return the content octets of the single TLV at the front of `der`.
fn tlv_content(der: &[u8]) -> &[u8] {
    let (_content_len, len_octets) = length_of(der);
    let header = 1 + len_octets;
    let (full, _) = take_tlv(der);
    &full[header..]
}

/// A root envelope allowing `oper` up to level 5, TTL one day.
fn root_request() -> CaRequest {
    CaRequest {
        subject: "CN=Tessera File E2E Root".to_owned(),
        subject_spki_der: SPKI.to_vec(),
        validity: Validity {
            not_before: NOW,
            not_after: 1_900_000_000,
        },
        constraints: DelegationConstraints {
            require_tags: vec![],
            allow_roles: vec!["oper".to_owned()],
            max_level: 5,
            max_ttl: 86_400,
        },
        profile_version: 1,
    }
}

/// A sub-CA that narrows nothing (equal envelope is allowed).
fn sub_ca_request() -> CaRequest {
    CaRequest {
        subject: "CN=Tessera File E2E Sub CA".to_owned(),
        subject_spki_der: SPKI.to_vec(),
        validity: Validity {
            not_before: NOW,
            not_after: 1_800_000_000,
        },
        constraints: DelegationConstraints {
            require_tags: vec![],
            allow_roles: vec!["oper".to_owned()],
            max_level: 5,
            max_ttl: 86_400,
        },
        profile_version: 1,
    }
}

/// A leaf inside the sub-CA envelope.
fn leaf_request() -> LeafRequest {
    LeafRequest {
        subject: "CN=ivanov".to_owned(),
        subject_spki_der: SPKI.to_vec(),
        validity: Validity {
            not_before: NOW,
            not_after: NOW + 3_600,
        },
        host_binding: vec!["*".to_owned()],
        user_binding: vec!["ivanov".to_owned()],
        allowed_roles: vec!["oper".to_owned()],
        max_integrity: None,
        profile_version: 1,
    }
}

/// Issue root → sub-CA → leaf with `signer`, verifying every signature against
/// `verifier`.
fn issue_chain_and_verify(signer: &FileSigner, verifier: &Verifier) {
    let key = KeyId::new(KEY_ID);
    // A throwaway on-disk NDJSON journal; every issuance is recorded before the
    // artifact is released, so the chain needs a real storage target.
    let journal_file = NamedTempFile::new().unwrap();
    let mut journal = Journal::load(FileStorage::new(journal_file.path())).unwrap();

    let root = issue_root(
        signer,
        &key,
        &root_request(),
        &Serial::generate(),
        &mut journal,
        NOW,
    )
    .unwrap();
    let (tbs, sig) = split_certificate(&root.der);
    verifier.check(tbs, sig);

    let ca = issue_ca(
        signer,
        &key,
        &root.der,
        &sub_ca_request(),
        &Serial::generate(),
        &mut journal,
        NOW,
    )
    .unwrap();
    let (tbs, sig) = split_certificate(&ca.der);
    verifier.check(tbs, sig);

    let leaf = issue_leaf(
        signer,
        &key,
        &ca.der,
        &leaf_request(),
        &Serial::generate(),
        &mut journal,
        NOW,
    )
    .unwrap();
    let (tbs, sig) = split_certificate(&leaf.der);
    verifier.check(tbs, sig);
}

fn config(path: std::path::PathBuf) -> FileConfig {
    FileConfig {
        path,
        key_id: KeyId::new(KEY_ID),
        requested_algorithm: None,
    }
}

#[test]
fn full_chain_with_p256_file_key() {
    let (pem, verifier) = p256_ca();
    let file = write_key(&pem);
    let signer = FileSigner::open(config(file.path().to_path_buf()), &never()).unwrap();
    assert_eq!(
        signer.algorithm(&KeyId::new(KEY_ID)).unwrap(),
        SignatureAlgorithm::EcdsaWithSha256
    );
    issue_chain_and_verify(&signer, &verifier);
}

#[test]
fn full_chain_with_p384_file_key() {
    let (pem, verifier) = p384_ca();
    let file = write_key(&pem);
    let signer = FileSigner::open(config(file.path().to_path_buf()), &never()).unwrap();
    assert_eq!(
        signer.algorithm(&KeyId::new(KEY_ID)).unwrap(),
        SignatureAlgorithm::EcdsaWithSha384
    );
    issue_chain_and_verify(&signer, &verifier);
}

#[test]
fn full_chain_with_rsa_file_key() {
    let (pem, verifier) = rsa_ca();
    let file = write_key(&pem);
    let signer = FileSigner::open(config(file.path().to_path_buf()), &never()).unwrap();
    assert_eq!(
        signer.algorithm(&KeyId::new(KEY_ID)).unwrap(),
        SignatureAlgorithm::RsaPkcs1Sha256
    );
    issue_chain_and_verify(&signer, &verifier);
}

#[test]
fn full_chain_with_encrypted_key() {
    // Encrypt a P-256 key, then decrypt it through a passphrase source and run
    // the whole chain. The passphrase is injected via the same trait the CLI's
    // environment-variable source implements; the environment itself is not
    // mutated here, since that is unsound under a multi-threaded test binary.
    let secret = p256::SecretKey::from_slice(&[0x33; 32]).unwrap();
    let verifier = Verifier::P256(*p256::ecdsa::SigningKey::from(secret.clone()).verifying_key());
    let plain = secret.to_pkcs8_der().unwrap();
    let info = PrivateKeyInfo::try_from(plain.as_bytes()).unwrap();
    let mut rng = FixtureRng::new(0x00EE_5678);
    let encrypted = info.encrypt(&mut rng, PASSPHRASE.as_bytes()).unwrap();
    let pem = encrypted
        .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
        .unwrap();
    // Confirm the fixture really is an encrypted PKCS#8 blob.
    EncryptedPrivateKeyInfo::try_from(encrypted.as_bytes()).unwrap();
    let file = write_key(pem.as_bytes());

    let passphrase = || Ok(SecretString::from(PASSPHRASE.to_owned()));
    let signer = FileSigner::open(config(file.path().to_path_buf()), &passphrase).unwrap();
    assert!(signer.key_is_encrypted());
    issue_chain_and_verify(&signer, &verifier);
}

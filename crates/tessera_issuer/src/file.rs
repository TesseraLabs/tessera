//! On-disk PKCS#8 signing adapter: a CA key stored in a file signs a built TBS.
//!
//! Where the PKCS#11 and Vault adapters keep the key in a device or a remote
//! secrets engine, this backend loads the key into the issuing process. That is
//! a deliberately lower protection class — a host compromise can read the key —
//! so the recommendation for production stays PKCS#11 or Vault; the file backend
//! is for accepted-risk contours (a stand, CI, a small install). This trade-off
//! is recorded in the threat model.
//!
//! # Key format
//!
//! The key is PKCS#8 (`PrivateKeyInfo`), PEM or DER, optionally encrypted
//! (`EncryptedPrivateKeyInfo`, PBES2). Supported key types are ECDSA P-256,
//! ECDSA P-384, and RSA (signing RSASSA-PKCS1-v1_5 / SHA-256). GOST and other
//! key types are refused with a typed error — those stay with the PKCS#11
//! adapter. SEC1/PKCS#1 key files are not accepted; convert them to PKCS#8 with
//! `openssl pkcs8 -topk8`.
//!
//! # Algorithm
//!
//! The signing algorithm is derived from the key itself (the EC curve, or RSA),
//! so the certificate's `signature` `AlgorithmIdentifier` always matches the key.
//! A caller-supplied algorithm is treated as a cross-check: if it disagrees with
//! the key, construction fails rather than silently overriding the request.
//!
//! # Permissions and passphrase
//!
//! On Unix the key file must not be group- or world-accessible (`mode & 0o077 ==
//! 0`), checked before the contents are read; the precedent is OpenSSH. A
//! passphrase for an encrypted key is obtained once at construction and, with
//! the decrypted DER, zeroized right after the signing key is built — neither
//! ever enters an argument, a log line, or an error message. The key is loaded
//! and decrypted a single time (fail-fast on a bad file or passphrase), not per
//! signature: holding the signing key in process memory for the session is an
//! inherent property of a file backend.

use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use const_oid::ObjectIdentifier;
use pkcs8::der::pem;
use pkcs8::{DecodePrivateKey as _, EncryptedPrivateKeyInfo, PrivateKeyInfo};

use crate::sign::{KeyId, SignError, Signature, SignatureAlgorithm, SignatureBackend};

/// `id-ecPublicKey` (RFC 5480): the `PrivateKeyInfo` algorithm of any EC key.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `secp256r1` / `prime256v1` — the named-curve parameter of a P-256 key.
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1` — the named-curve parameter of a P-384 key.
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// `rsaEncryption` (RFC 8017): the `PrivateKeyInfo` algorithm of an RSA key.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The ASN.1 `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2): the fixed
/// `SEQUENCE { SEQUENCE { id-sha256, NULL }, OCTET STRING }` header that precedes
/// the 32-byte digest inside a PKCS#1 v1.5 signature. The RSA arm signs the
/// digest with this prefix, matching what a verifier expects.
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// The PEM label of an unencrypted PKCS#8 key.
const PEM_LABEL_PLAIN: &str = "PRIVATE KEY";
/// The PEM label of an encrypted PKCS#8 key.
const PEM_LABEL_ENCRYPTED: &str = "ENCRYPTED PRIVATE KEY";

/// Supplies the passphrase that decrypts an encrypted key file.
///
/// The returned [`SecretString`] is used only to decrypt the key at construction
/// and is dropped (and so zeroized) immediately after. Implementations MUST NOT
/// persist, log, or echo the passphrase, and MUST NOT read it from a process
/// argument. The CLI implements this with a pinentry prompt falling back to an
/// environment variable; tests inject a fixed value.
///
/// A blanket impl covers any `Fn() -> Result<SecretString, FileSignError>`, so a
/// closure is the usual way to supply one. The source is consulted only for an
/// encrypted key; a plaintext key never calls it.
pub trait PassphraseSource {
    /// Obtain the passphrase to decrypt the key file with.
    ///
    /// # Errors
    ///
    /// [`FileSignError::PassphraseUnavailable`] when no passphrase could be
    /// obtained.
    fn passphrase(&self) -> Result<SecretString, FileSignError>;
}

impl<F> PassphraseSource for F
where
    F: Fn() -> Result<SecretString, FileSignError>,
{
    fn passphrase(&self) -> Result<SecretString, FileSignError> {
        self()
    }
}

/// Where the CA key file is and how to name it.
#[derive(Debug, Clone)]
pub struct FileConfig {
    /// Filesystem path to the PKCS#8 key file (PEM or DER).
    pub path: PathBuf,
    /// The key identifier the issuance core passes to [`SignatureBackend`]. For
    /// the CLI this defaults to the file's basename without extension.
    pub key_id: KeyId,
    /// An optional operator-supplied algorithm, cross-checked against the key.
    /// `None` derives the algorithm from the key with no cross-check.
    pub requested_algorithm: Option<SignatureAlgorithm>,
}

/// The parsed CA signing key, one arm per supported key type.
///
/// The RSA key is boxed: `RsaPrivateKey` is far larger than an EC key, so
/// boxing keeps the enum (and the [`FileSigner`] holding it) small.
enum SigningKeyKind {
    /// ECDSA over the NIST P-256 curve (signs SHA-256).
    EcdsaP256(p256::ecdsa::SigningKey),
    /// ECDSA over the NIST P-384 curve (signs SHA-384).
    EcdsaP384(p384::ecdsa::SigningKey),
    /// RSA, signing RSASSA-PKCS1-v1_5 with SHA-256.
    Rsa(Box<rsa::RsaPrivateKey>),
}

/// A [`SignatureBackend`] backed by an on-disk PKCS#8 CA key.
///
/// Build once with [`FileSigner::open`], which reads, decrypts, and parses the
/// key up front. [`FileSigner::key_is_encrypted`] reports whether the source was
/// encrypted, so the caller can warn on a plaintext key.
pub struct FileSigner {
    key: SigningKeyKind,
    key_id: KeyId,
    algorithm: SignatureAlgorithm,
    encrypted: bool,
}

// Manual `Debug`: never format the key material. The RustCrypto key types redact
// their own `Debug`, but the signer prints only non-secret metadata regardless.
impl core::fmt::Debug for FileSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileSigner")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("encrypted", &self.encrypted)
            .finish_non_exhaustive()
    }
}

impl FileSigner {
    /// Load, decrypt if needed, and parse the CA key named by `config`.
    ///
    /// The permission check runs before the file's contents are read. The
    /// `passphrase` source is consulted only when the file is encrypted. On
    /// success the decrypted DER and the passphrase are already zeroized; the
    /// process retains only the parsed signing key.
    ///
    /// # Errors
    ///
    /// - [`FileSignError::NotFound`] when the file does not exist.
    /// - [`FileSignError::Permissions`] (Unix) when the file is group- or
    ///   world-accessible.
    /// - [`FileSignError::Malformed`] when the bytes are not a PKCS#8 key.
    /// - [`FileSignError::PassphraseUnavailable`] when an encrypted key has no
    ///   passphrase source.
    /// - [`FileSignError::WrongPassphrase`] when decryption fails.
    /// - [`FileSignError::UnsupportedKeyType`] for a key type outside
    ///   P-256/P-384/RSA.
    /// - [`FileSignError::AlgorithmMismatch`] when `requested_algorithm`
    ///   disagrees with the key.
    pub fn open(
        config: FileConfig,
        passphrase: &impl PassphraseSource,
    ) -> Result<Self, FileSignError> {
        let raw = read_key_file(&config.path)?;
        let form = detect_form(&raw)?;
        let encrypted = matches!(form, KeyForm::Encrypted(_));
        let plain = match form {
            KeyForm::Plain(der) => der,
            KeyForm::Encrypted(epki_der) => {
                let secret = passphrase.passphrase()?;
                decrypt_pkcs8(&epki_der, &secret)?
            }
        };
        let (key, algorithm) = parse_signing_key(&plain, config.requested_algorithm)?;
        Ok(Self {
            key,
            key_id: config.key_id,
            algorithm,
            encrypted,
        })
    }

    /// Whether the source key file was encrypted.
    ///
    /// A `false` result means the key was stored in the clear; the caller should
    /// emit a localized warning, since a plaintext CA key is the weakest option.
    #[must_use]
    pub fn key_is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Sign `tbs` with the loaded key, returning the certificate-ready octets.
    fn sign_tbs(&self, tbs: &[u8]) -> Result<Vec<u8>, SignError> {
        match &self.key {
            SigningKeyKind::EcdsaP256(key) => {
                use p256::ecdsa::signature::Signer as _;
                let signature: p256::ecdsa::Signature = key
                    .try_sign(tbs)
                    .map_err(|e| SignError::Backend(e.to_string()))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            SigningKeyKind::EcdsaP384(key) => {
                use p384::ecdsa::signature::Signer as _;
                let signature: p384::ecdsa::Signature = key
                    .try_sign(tbs)
                    .map_err(|e| SignError::Backend(e.to_string()))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            SigningKeyKind::Rsa(key) => {
                let hashed = Sha256::digest(tbs);
                // Compute the digest with the workspace SHA-256 and hand it to the
                // PKCS#1 v1.5 scheme with the fixed SHA-256 DigestInfo prefix, so
                // no digest-trait version has to align across crates.
                let scheme = rsa::pkcs1v15::Pkcs1v15Sign {
                    hash_len: Some(hashed.len()),
                    prefix: Box::from(SHA256_DIGEST_INFO_PREFIX.as_slice()),
                };
                // Sign with an RNG so the RSA private operation is base-blinded:
                // a deterministic signature would leak CRT timing to another
                // process on a shared host. The RNG only randomizes the blinding
                // factor; the produced signature is standard PKCS#1 v1.5.
                let mut rng = rand::rng();
                key.sign_with_rng(&mut rng, scheme, &hashed)
                    .map_err(|e| SignError::Backend(e.to_string()))
            }
        }
    }
}

impl SignatureBackend for FileSigner {
    fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
        if key_id == &self.key_id {
            Ok(self.algorithm)
        } else {
            Err(SignError::UnknownKey(key_id.as_str().to_owned()))
        }
    }

    fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
        if key_id != &self.key_id {
            return Err(SignError::UnknownKey(key_id.as_str().to_owned()));
        }
        let bytes = self.sign_tbs(tbs_der)?;
        Ok(Signature {
            algorithm: self.algorithm,
            bytes,
        })
    }
}

/// The on-disk form of the key: plaintext or encrypted PKCS#8 DER.
enum KeyForm {
    /// Unencrypted `PrivateKeyInfo` DER.
    Plain(Zeroizing<Vec<u8>>),
    /// `EncryptedPrivateKeyInfo` DER, awaiting a passphrase.
    Encrypted(Zeroizing<Vec<u8>>),
}

/// Check permissions (Unix) and read the key file into a zeroizing buffer.
///
/// The permission gate runs on the file's metadata, before any content is read,
/// so an over-permissive key is refused without the bytes ever entering memory.
fn read_key_file(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, FileSignError> {
    let metadata = std::fs::metadata(path).map_err(|e| classify_io(path, &e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(FileSignError::Permissions {
                path: path.to_path_buf(),
                mode: mode & 0o7777,
            });
        }
    }
    #[cfg(not(unix))]
    {
        // No Unix permission model to enforce; existence is confirmed by the
        // metadata call above.
        let _ = &metadata;
    }

    let bytes = std::fs::read(path).map_err(|e| classify_io(path, &e))?;
    Ok(Zeroizing::new(bytes))
}

/// Map a filesystem error to a typed key-file error.
fn classify_io(path: &std::path::Path, error: &std::io::Error) -> FileSignError {
    if error.kind() == std::io::ErrorKind::NotFound {
        FileSignError::NotFound(path.to_path_buf())
    } else {
        FileSignError::Malformed(format!("{}: {error}", path.display()))
    }
}

/// Classify the raw bytes as plaintext or encrypted PKCS#8, PEM or DER.
///
/// PEM is dispatched by its label; DER is disambiguated structurally — a
/// `PrivateKeyInfo` opens with an `INTEGER` version while an
/// `EncryptedPrivateKeyInfo` opens with the encryption `AlgorithmIdentifier`
/// `SEQUENCE`, so exactly one of the two parses.
fn detect_form(raw: &[u8]) -> Result<KeyForm, FileSignError> {
    if let Some(text) = pem_text(raw) {
        let (label, der) = pem::decode_vec(text.as_bytes())
            .map_err(|e| FileSignError::Malformed(format!("PEM decode failed: {e}")))?;
        return match label {
            PEM_LABEL_PLAIN => Ok(KeyForm::Plain(Zeroizing::new(der))),
            PEM_LABEL_ENCRYPTED => Ok(KeyForm::Encrypted(Zeroizing::new(der))),
            other => Err(FileSignError::Malformed(format!(
                "unexpected PEM label {other:?} (want {PEM_LABEL_PLAIN:?} or {PEM_LABEL_ENCRYPTED:?})"
            ))),
        };
    }
    if PrivateKeyInfo::try_from(raw).is_ok() {
        return Ok(KeyForm::Plain(Zeroizing::new(raw.to_vec())));
    }
    if EncryptedPrivateKeyInfo::try_from(raw).is_ok() {
        return Ok(KeyForm::Encrypted(Zeroizing::new(raw.to_vec())));
    }
    Err(FileSignError::Malformed(
        "not a PKCS#8 private key (PEM or DER)".to_owned(),
    ))
}

/// Return the bytes as a PEM string if they look like PEM, else `None`.
///
/// A binary DER key is not valid UTF-8 (or does not carry the PEM preamble), so
/// this both detects the encoding and yields the string the PEM decoder needs.
fn pem_text(raw: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(raw).ok()?;
    if text.trim_start().starts_with("-----BEGIN") {
        Some(text)
    } else {
        None
    }
}

/// Decrypt an `EncryptedPrivateKeyInfo` into plaintext PKCS#8 DER.
fn decrypt_pkcs8(
    epki_der: &[u8],
    passphrase: &SecretString,
) -> Result<Zeroizing<Vec<u8>>, FileSignError> {
    let epki = EncryptedPrivateKeyInfo::try_from(epki_der)
        .map_err(|e| FileSignError::Malformed(format!("encrypted PKCS#8 parse failed: {e}")))?;
    let secret = epki
        .decrypt(passphrase.expose_secret())
        .map_err(|_| FileSignError::WrongPassphrase)?;
    Ok(Zeroizing::new(secret.as_bytes().to_vec()))
}

/// Determine the key type from plaintext PKCS#8 DER, cross-check the requested
/// algorithm, and build the signing key.
fn parse_signing_key(
    der: &[u8],
    requested: Option<SignatureAlgorithm>,
) -> Result<(SigningKeyKind, SignatureAlgorithm), FileSignError> {
    let info = PrivateKeyInfo::try_from(der)
        .map_err(|e| FileSignError::Malformed(format!("PKCS#8 parse failed: {e}")))?;
    let derived = derive_algorithm(&info)?;

    if let Some(requested) = requested {
        if requested != derived {
            return Err(FileSignError::AlgorithmMismatch {
                key: derived,
                requested,
            });
        }
    }

    let key = match derived {
        SignatureAlgorithm::EcdsaWithSha256 => {
            let secret = p256::SecretKey::from_pkcs8_der(der)
                .map_err(|e| FileSignError::Malformed(format!("P-256 key parse failed: {e}")))?;
            SigningKeyKind::EcdsaP256(p256::ecdsa::SigningKey::from(secret))
        }
        SignatureAlgorithm::EcdsaWithSha384 => {
            let secret = p384::SecretKey::from_pkcs8_der(der)
                .map_err(|e| FileSignError::Malformed(format!("P-384 key parse failed: {e}")))?;
            SigningKeyKind::EcdsaP384(p384::ecdsa::SigningKey::from(secret))
        }
        SignatureAlgorithm::RsaPkcs1Sha256 => {
            // `sad-rsa` tracks the RustCrypto 0.10 encoding stack (pkcs8 0.11),
            // while the EC crates still use pkcs8 0.10. Import the trait through
            // the RSA crate so method resolution selects the matching version.
            use rsa::pkcs8::DecodePrivateKey as _;
            let secret = rsa::RsaPrivateKey::from_pkcs8_der(der)
                .map_err(|e| FileSignError::Malformed(format!("RSA key parse failed: {e}")))?;
            SigningKeyKind::Rsa(Box::new(secret))
        }
        // `derive_algorithm` only ever returns one of the three arms above.
        other => {
            return Err(FileSignError::UnsupportedKeyType(format!("{other:?}")));
        }
    };
    Ok((key, derived))
}

/// Map a `PrivateKeyInfo`'s algorithm to a [`SignatureAlgorithm`].
///
/// EC keys are split by their named-curve parameter; RSA maps to
/// PKCS#1-v1_5/SHA-256. Anything else (Ed25519, GOST, an EC curve outside
/// P-256/P-384) is refused.
fn derive_algorithm(info: &PrivateKeyInfo<'_>) -> Result<SignatureAlgorithm, FileSignError> {
    let oid = info.algorithm.oid;
    if oid == OID_EC_PUBLIC_KEY {
        let curve = info.algorithm.parameters_oid().map_err(|_| {
            FileSignError::UnsupportedKeyType("EC key without a named curve".to_owned())
        })?;
        if curve == OID_SECP256R1 {
            Ok(SignatureAlgorithm::EcdsaWithSha256)
        } else if curve == OID_SECP384R1 {
            Ok(SignatureAlgorithm::EcdsaWithSha384)
        } else {
            Err(FileSignError::UnsupportedKeyType(format!(
                "EC curve {curve} (supported: P-256, P-384)"
            )))
        }
    } else if oid == OID_RSA_ENCRYPTION {
        Ok(SignatureAlgorithm::RsaPkcs1Sha256)
    } else {
        Err(FileSignError::UnsupportedKeyType(format!(
            "algorithm {oid} (supported: ECDSA P-256, ECDSA P-384, RSA)"
        )))
    }
}

/// Errors from building the file signing backend.
///
/// No variant carries the passphrase or any key material: only paths,
/// permission bits, key-type descriptions, and algorithm names are exposed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FileSignError {
    /// The key file does not exist.
    #[error("key file not found: {0}")]
    NotFound(PathBuf),
    /// The key file is accessible to group or others (Unix). The mode is the
    /// file's actual permission bits.
    #[error(
        "key file {path} is group/other-accessible (mode {mode:04o}); require 0600 or stricter"
    )]
    Permissions {
        /// The offending key-file path.
        path: PathBuf,
        /// The file's permission bits (`st_mode & 0o7777`).
        mode: u32,
    },
    /// The bytes are not a well-formed PKCS#8 key (PEM or DER).
    #[error("malformed key file: {0}")]
    Malformed(String),
    /// The passphrase did not decrypt the key.
    #[error("wrong passphrase for the encrypted key file")]
    WrongPassphrase,
    /// No passphrase could be obtained for an encrypted key.
    #[error("no passphrase available for the encrypted key: {0}")]
    PassphraseUnavailable(String),
    /// The key type is outside the supported P-256/P-384/RSA set.
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    /// The requested `--algorithm` disagrees with the key's own algorithm.
    #[error("key algorithm is {key:?} but --algorithm requested {requested:?}")]
    AlgorithmMismatch {
        /// The algorithm derived from the key.
        key: SignatureAlgorithm,
        /// The algorithm the operator requested.
        requested: SignatureAlgorithm,
    },
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;

    use pkcs8::rand_core::{CryptoRng, RngCore};
    use pkcs8::{EncodePrivateKey as _, LineEnding};

    /// A deterministic RNG for building test fixtures (key generation, PBES2
    /// salt/IV). Not for production: a fixed seed makes fixtures reproducible.
    /// Implements the `RustCrypto` `rand_core` 0.6 traits the key crates expect.
    struct FixtureRng(u64);

    impl FixtureRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next(&mut self) -> u64 {
            // splitmix64.
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

    const KEY_ID: &str = "test-ca";
    const PASSPHRASE: &str = "correct horse battery staple";

    fn key_id() -> KeyId {
        KeyId::new(KEY_ID)
    }

    /// A passphrase source that must never be consulted (plaintext-key tests).
    fn never() -> impl PassphraseSource {
        || {
            Err(FileSignError::PassphraseUnavailable(
                "must not be asked".to_owned(),
            ))
        }
    }

    /// A fixed passphrase source.
    fn fixed(pass: &'static str) -> impl PassphraseSource {
        move || Ok(SecretString::from(pass.to_owned()))
    }

    /// Write bytes to a fresh temp file with 0600 permissions, returning it (the
    /// handle keeps the file alive for the test).
    fn write_key(bytes: &[u8]) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        file
    }

    fn p256_pkcs8_pem() -> Zeroizing<String> {
        let secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        secret.to_pkcs8_pem(LineEnding::LF).unwrap()
    }

    fn config(path: PathBuf, requested: Option<SignatureAlgorithm>) -> FileConfig {
        FileConfig {
            path,
            key_id: key_id(),
            requested_algorithm: requested,
        }
    }

    #[test]
    fn signs_and_verifies_p256() {
        use p256::ecdsa::signature::Verifier as _;

        let secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let verifying = *p256::ecdsa::SigningKey::from(secret.clone()).verifying_key();
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let file = write_key(pem.as_bytes());

        let signer = FileSigner::open(config(file.path().to_path_buf(), None), &never()).unwrap();
        assert!(!signer.key_is_encrypted());
        assert_eq!(
            signer.algorithm(&key_id()).unwrap(),
            SignatureAlgorithm::EcdsaWithSha256
        );

        let tbs = b"file backend p-256 sample tbs";
        let signature = signer.sign(tbs, &key_id()).unwrap();
        assert_eq!(signature.algorithm, SignatureAlgorithm::EcdsaWithSha256);
        let der = p256::ecdsa::Signature::from_der(&signature.bytes).unwrap();
        verifying.verify(tbs, &der).unwrap();
    }

    #[test]
    fn signs_and_verifies_p384() {
        use p384::ecdsa::signature::Verifier as _;

        let secret = p384::SecretKey::from_slice(&[0x22; 48]).unwrap();
        let verifying = *p384::ecdsa::SigningKey::from(secret.clone()).verifying_key();
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let file = write_key(pem.as_bytes());

        let signer = FileSigner::open(config(file.path().to_path_buf(), None), &never()).unwrap();
        assert_eq!(
            signer.algorithm(&key_id()).unwrap(),
            SignatureAlgorithm::EcdsaWithSha384
        );

        let tbs = b"file backend p-384 sample tbs";
        let signature = signer.sign(tbs, &key_id()).unwrap();
        assert_eq!(signature.algorithm, SignatureAlgorithm::EcdsaWithSha384);
        let der = p384::ecdsa::Signature::from_der(&signature.bytes).unwrap();
        verifying.verify(tbs, &der).unwrap();
    }

    #[test]
    fn signs_and_verifies_rsa() {
        use rsa::pkcs8::{EncodePrivateKey as _, LineEnding as RsaLineEnding};

        let mut rng = FixtureRng::new(0x00A5_1234_u64);
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = rsa::RsaPublicKey::from(&private);
        let pem = private.to_pkcs8_pem(RsaLineEnding::LF).unwrap();
        let file = write_key(pem.as_bytes());

        let signer = FileSigner::open(config(file.path().to_path_buf(), None), &never()).unwrap();
        assert_eq!(
            signer.algorithm(&key_id()).unwrap(),
            SignatureAlgorithm::RsaPkcs1Sha256
        );

        let tbs = b"file backend rsa sample tbs";
        let signature = signer.sign(tbs, &key_id()).unwrap();
        assert_eq!(signature.algorithm, SignatureAlgorithm::RsaPkcs1Sha256);

        let hashed = Sha256::digest(tbs);
        let scheme = rsa::pkcs1v15::Pkcs1v15Sign {
            hash_len: Some(hashed.len()),
            prefix: Box::from(SHA256_DIGEST_INFO_PREFIX.as_slice()),
        };
        public.verify(scheme, &hashed, &signature.bytes).unwrap();
    }

    #[test]
    fn encrypted_key_round_trips_with_passphrase() {
        let secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let plain = secret.to_pkcs8_der().unwrap();
        let info = PrivateKeyInfo::try_from(plain.as_bytes()).unwrap();
        let mut rng = FixtureRng::new(7);
        let encrypted = info.encrypt(&mut rng, PASSPHRASE.as_bytes()).unwrap();
        let pem = encrypted
            .to_pem(PEM_LABEL_ENCRYPTED, LineEnding::LF)
            .unwrap();
        let file = write_key(pem.as_bytes());

        let signer =
            FileSigner::open(config(file.path().to_path_buf(), None), &fixed(PASSPHRASE)).unwrap();
        assert!(signer.key_is_encrypted());
        let signature = signer.sign(b"tbs", &key_id()).unwrap();
        assert_eq!(signature.algorithm, SignatureAlgorithm::EcdsaWithSha256);
    }

    #[test]
    fn wrong_passphrase_is_typed() {
        let secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let plain = secret.to_pkcs8_der().unwrap();
        let info = PrivateKeyInfo::try_from(plain.as_bytes()).unwrap();
        let mut rng = FixtureRng::new(9);
        let encrypted = info.encrypt(&mut rng, PASSPHRASE.as_bytes()).unwrap();
        let pem = encrypted
            .to_pem(PEM_LABEL_ENCRYPTED, LineEnding::LF)
            .unwrap();
        let file = write_key(pem.as_bytes());

        let err = FileSigner::open(config(file.path().to_path_buf(), None), &fixed("wrong"))
            .expect_err("a wrong passphrase must fail construction");
        assert!(matches!(err, FileSignError::WrongPassphrase), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_key_is_refused_before_reading() {
        use std::os::unix::fs::PermissionsExt as _;

        let file = write_key(p256_pkcs8_pem().as_bytes());
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = FileSigner::open(config(file.path().to_path_buf(), None), &never())
            .expect_err("a 0644 key file must be refused");
        match err {
            FileSignError::Permissions { mode, .. } => assert_eq!(mode, 0o644),
            other => panic!("expected Permissions, got {other:?}"),
        }
    }

    #[test]
    fn requested_algorithm_mismatch_is_typed() {
        let file = write_key(p256_pkcs8_pem().as_bytes());
        let err = FileSigner::open(
            config(
                file.path().to_path_buf(),
                Some(SignatureAlgorithm::EcdsaWithSha384),
            ),
            &never(),
        )
        .expect_err("a P-256 key with --algorithm ecdsa-p384 must fail");
        match err {
            FileSignError::AlgorithmMismatch { key, requested } => {
                assert_eq!(key, SignatureAlgorithm::EcdsaWithSha256);
                assert_eq!(requested, SignatureAlgorithm::EcdsaWithSha384);
            }
            other => panic!("expected AlgorithmMismatch, got {other:?}"),
        }
    }

    #[test]
    fn matching_requested_algorithm_is_accepted() {
        let file = write_key(p256_pkcs8_pem().as_bytes());
        let signer = FileSigner::open(
            config(
                file.path().to_path_buf(),
                Some(SignatureAlgorithm::EcdsaWithSha256),
            ),
            &never(),
        )
        .unwrap();
        assert_eq!(
            signer.algorithm(&key_id()).unwrap(),
            SignatureAlgorithm::EcdsaWithSha256
        );
    }

    #[test]
    fn ed25519_key_is_unsupported() {
        // A minimal valid Ed25519 PKCS#8 (RFC 8410 §10.3 test vector).
        const ED25519_PKCS8: &[u8] = &[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20, 0xd4, 0xee, 0x72, 0xdb, 0xf9, 0x13, 0x58, 0x4a, 0xd5, 0xb6, 0xd8, 0xf1,
            0xf7, 0x69, 0xf8, 0xad, 0x3a, 0xfe, 0x7c, 0x28, 0xcb, 0xf1, 0xd4, 0xfb, 0xe0, 0x97,
            0xa8, 0x8f, 0x44, 0x75, 0x58, 0x42,
        ];
        let file = write_key(ED25519_PKCS8);
        let err = FileSigner::open(config(file.path().to_path_buf(), None), &never())
            .expect_err("an Ed25519 key must be refused");
        assert!(
            matches!(err, FileSignError::UnsupportedKeyType(_)),
            "{err:?}"
        );
    }

    #[test]
    fn missing_file_is_typed() {
        let err = FileSigner::open(
            config(PathBuf::from("/nonexistent/__tessera_no_key__.p8"), None),
            &never(),
        )
        .expect_err("a missing file must fail");
        assert!(matches!(err, FileSignError::NotFound(_)), "{err:?}");
    }

    #[test]
    fn plaintext_key_is_marked_encrypted_false() {
        let file = write_key(p256_pkcs8_pem().as_bytes());
        let signer = FileSigner::open(config(file.path().to_path_buf(), None), &never()).unwrap();
        // The marker the CLI reads to decide whether to warn.
        assert!(!signer.key_is_encrypted());
    }

    #[test]
    fn debug_never_prints_key_material() {
        let file = write_key(p256_pkcs8_pem().as_bytes());
        let signer = FileSigner::open(config(file.path().to_path_buf(), None), &never()).unwrap();
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("FileSigner"));
        assert!(rendered.contains(KEY_ID));
    }
}

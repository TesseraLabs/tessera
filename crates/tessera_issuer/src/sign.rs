//! The signing interface: a key that never leaves its store signs already-built
//! TBS bytes.
//!
//! The issuance core builds and validates a `TBSCertificate` (or `TBSCertList`),
//! hands the DER to a [`SignatureBackend`], and gets back only a signature and
//! its algorithm — never any key material. Concrete backends (PKCS#11, Vault
//! Transit, the browser-bridging local agent) live behind this trait and are
//! out of scope for the core; the crate ships only the deterministic
//! [`MockSigner`] used by tests.

use spki::AlgorithmIdentifierOwned;

use const_oid::ObjectIdentifier;

/// `ecdsa-with-SHA256` (RFC 5758).
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `ecdsa-with-SHA384` (RFC 5758).
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// `id-Ed25519` (RFC 8410).
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// `sha256WithRSAEncryption` (RFC 8017 / PKCS#1 v1.5).
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// An opaque handle naming the CA key to sign with — a slot label, a Vault key
/// name, a PKCS#11 URI. The core never inspects it; it only forwards it to the
/// backend, so no key material is implied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(pub String);

impl KeyId {
    /// Wraps a key identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The signature algorithm a backend uses for a given key.
///
/// Named ahead of the signature because the TBS `signature` field must carry
/// the same `AlgorithmIdentifier` as the enclosing certificate — the core reads
/// it from [`SignatureBackend::algorithm`] before building the TBS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA over the signed SHA-256 digest of the TBS.
    EcdsaWithSha256,
    /// ECDSA over the signed SHA-384 digest of the TBS.
    EcdsaWithSha384,
    /// Ed25519 over the TBS.
    Ed25519,
    /// RSASSA-PKCS1-v1_5 over the SHA-256 digest of the TBS.
    RsaPkcs1Sha256,
}

impl SignatureAlgorithm {
    /// The `AlgorithmIdentifier` for this algorithm.
    ///
    /// The ECDSA and Ed25519 signature OIDs take no parameters (the field is
    /// absent). `sha256WithRSAEncryption` is the exception: RFC 4055 §5 requires
    /// an explicit `NULL`, so the RSA arm emits `parameters: NULL`.
    #[must_use]
    pub fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        let (oid, parameters) = match self {
            SignatureAlgorithm::EcdsaWithSha256 => (OID_ECDSA_SHA256, None),
            SignatureAlgorithm::EcdsaWithSha384 => (OID_ECDSA_SHA384, None),
            SignatureAlgorithm::Ed25519 => (OID_ED25519, None),
            SignatureAlgorithm::RsaPkcs1Sha256 => (OID_RSA_SHA256, Some(der::Any::null())),
        };
        AlgorithmIdentifierOwned { oid, parameters }
    }
}

/// A produced signature: the raw signature octets and the algorithm that made
/// them. No key material is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The algorithm the backend signed with.
    pub algorithm: SignatureAlgorithm,
    /// The raw signature octets, as they go into the certificate's `signature`
    /// `BIT STRING` (for ECDSA this is the DER `SEQUENCE { r, s }`).
    pub bytes: Vec<u8>,
}

/// Errors a [`SignatureBackend`] may report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// No key with the given identifier exists in the backend.
    #[error("unknown signing key: {0}")]
    UnknownKey(String),
    /// The backend could not sign (device error, PIN failure, transport error).
    #[error("signing backend failure: {0}")]
    Backend(String),
}

/// Signs already-built TBS bytes with a key that stays in its store.
///
/// Implementations MUST NOT accept, return, or otherwise route private key
/// material through this trait — only a signature and its algorithm leave the
/// boundary.
pub trait SignatureBackend {
    /// The algorithm `key_id` signs with. The core calls this before building
    /// the TBS so the TBS `signature` field matches the outer signature.
    ///
    /// # Errors
    ///
    /// [`SignError::UnknownKey`] if the backend holds no such key.
    fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError>;

    /// Signs `tbs_der` with `key_id`.
    ///
    /// # Errors
    ///
    /// [`SignError`] if the key is unknown or the backend fails to sign.
    fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError>;
}

/// A deterministic in-crate signer for tests: it produces no real cryptography,
/// only a stable, structurally valid signature blob so assembled artifacts
/// re-parse. Available under the `test-support` feature (and in this crate's own
/// tests).
///
/// The self-verification the issuer runs checks the certificate's *extensions*,
/// not the signature, so a non-cryptographic signature is sufficient to
/// exercise the full issuance and contract path.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct MockSigner {
    key_id: KeyId,
    algorithm: SignatureAlgorithm,
}

#[cfg(any(test, feature = "test-support"))]
impl MockSigner {
    /// A signer that recognises `key_id` and signs with `algorithm`.
    #[must_use]
    pub fn new(key_id: KeyId, algorithm: SignatureAlgorithm) -> Self {
        Self { key_id, algorithm }
    }

    /// A signer for `key_id` using [`SignatureAlgorithm::EcdsaWithSha256`].
    #[must_use]
    pub fn ecdsa_sha256(key_id: KeyId) -> Self {
        Self::new(key_id, SignatureAlgorithm::EcdsaWithSha256)
    }

    /// Folds the TBS into a fixed-width, deterministic pseudo-signature. Not
    /// cryptographic — it only needs to be stable and non-empty.
    fn derive_signature(tbs_der: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        for (index, &byte) in tbs_der.iter().enumerate() {
            if let Some(slot) = out.get_mut(index % 64) {
                *slot ^= byte.rotate_left(u32::try_from(index % 8).unwrap_or(0));
            }
        }
        out
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SignatureBackend for MockSigner {
    fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
        if key_id == &self.key_id {
            Ok(self.algorithm)
        } else {
            Err(SignError::UnknownKey(key_id.0.clone()))
        }
    }

    fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
        if key_id != &self.key_id {
            return Err(SignError::UnknownKey(key_id.0.clone()));
        }
        Ok(Signature {
            algorithm: self.algorithm,
            bytes: Self::derive_signature(tbs_der),
        })
    }
}

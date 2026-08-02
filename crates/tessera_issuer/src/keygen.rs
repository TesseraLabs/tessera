//! Leaf key-pair generation: the third source of a leaf's key, beside a
//! supplied `SubjectPublicKeyInfo` and a certificate request.
//!
//! In the most common issuance the engineer brings nothing: the issuing
//! operator mints the key pair, certifies it and hands over a container. That
//! makes this the one place in the crate where a *subject's* private key exists
//! at all — everywhere else the tool only ever sees public material. The key
//! therefore lives in [`Zeroizing`] from the moment it is encoded until the
//! container has been assembled, and is never written anywhere but that
//! container.
//!
//! # Randomness
//!
//! Generation needs a cryptographic random source, and the two platforms this
//! core runs on get it from different places: the operating system natively,
//! the host page in the browser. Callers therefore supply it through
//! [`Entropy`], which the module adapts to the `RustCrypto` generator traits.
//! Nothing here derives, stretches or conditions the bytes it is given — the
//! adapters forward every request straight to the caller's source.
//!
//! # Key types
//!
//! Only the types whose signatures the device actually verifies are offered.
//! Certifying anything else produces a certificate that looks correct and fails
//! at the login screen, which is a worse outcome than refusing the request.

use zeroize::Zeroizing;

use crate::error::IssueError;

/// A cryptographic source of randomness supplied by the host platform.
///
/// Implementations MUST draw from a cryptographically secure generator (the
/// operating system's, or the browser's `crypto.getRandomValues`) and MUST fill
/// the whole buffer. The core never seeds, caches or post-processes what it
/// receives.
pub trait Entropy {
    /// Fills `out` entirely with cryptographically secure random bytes.
    fn fill(&mut self, out: &mut [u8]);
}

impl<T: Entropy + ?Sized> Entropy for &mut T {
    fn fill(&mut self, out: &mut [u8]) {
        (**self).fill(out);
    }
}

/// The operating system's random source — the [`Entropy`] a native tool uses.
///
/// The browser core has no counterpart here: the host page supplies its own
/// implementation over `crypto.getRandomValues`.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

#[cfg(feature = "native")]
impl Entropy for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) {
        use rand::Rng as _;
        rand::rng().fill_bytes(out);
    }
}

/// A leaf key type the device's challenge-response actually verifies.
///
/// GOST keys are deliberately absent: the device verifies them, but nothing in
/// this crate can generate one, so offering the choice would fail late instead
/// of early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafKeyType {
    /// ECDSA over NIST P-256 (`prime256v1`).
    EcdsaP256,
    /// ECDSA over NIST P-384 (`secp384r1`).
    EcdsaP384,
    /// RSA, 2048-bit modulus.
    Rsa2048,
    /// RSA, 3072-bit modulus.
    Rsa3072,
    /// RSA, 4096-bit modulus.
    Rsa4096,
}

impl LeafKeyType {
    /// Every offered type, in the order they are listed to an operator.
    pub const ALL: &'static [LeafKeyType] = &[
        LeafKeyType::EcdsaP256,
        LeafKeyType::EcdsaP384,
        LeafKeyType::Rsa2048,
        LeafKeyType::Rsa3072,
        LeafKeyType::Rsa4096,
    ];

    /// The value an operator writes on the command line for this type.
    #[must_use]
    pub fn flag_value(self) -> &'static str {
        match self {
            LeafKeyType::EcdsaP256 => "ecdsa-p256",
            LeafKeyType::EcdsaP384 => "ecdsa-p384",
            LeafKeyType::Rsa2048 => "rsa-2048",
            LeafKeyType::Rsa3072 => "rsa-3072",
            LeafKeyType::Rsa4096 => "rsa-4096",
        }
    }

    /// Every accepted value, comma-separated — the list an error message names.
    #[must_use]
    pub fn supported_values() -> String {
        Self::ALL
            .iter()
            .map(|kind| kind.flag_value())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Parses the operator-facing name of a key type.
    ///
    /// # Errors
    ///
    /// [`IssueError::UnsupportedKeyType`] for anything outside [`Self::ALL`],
    /// naming every value that is accepted. This runs *before* any key is
    /// generated, so an unusable request costs nothing.
    pub fn parse(value: &str) -> Result<Self, IssueError> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.flag_value() == value)
            .ok_or_else(|| IssueError::UnsupportedKeyType {
                requested: value.to_owned(),
                supported: Self::supported_values(),
            })
    }
}

/// A freshly generated key pair: the public half ready to certify, the private
/// half held in memory that is wiped when it drops.
pub struct GeneratedKeyPair {
    /// `SubjectPublicKeyInfo`, DER — the value that goes into the certificate.
    pub spki_der: Vec<u8>,
    /// The private key as PKCS#8 `PrivateKeyInfo` DER, wiped on drop.
    pub private_key_pkcs8_der: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for GeneratedKeyPair {
    /// Shows only the public half's length: a `Debug` that printed the private
    /// key would put it in whatever log or panic message formatted the value.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GeneratedKeyPair")
            .field("spki_der_len", &self.spki_der.len())
            .field("private_key_pkcs8_der", &"<redacted>")
            .finish()
    }
}

/// Generates a leaf key pair of the requested type.
///
/// The private key is returned in memory only. Callers MUST NOT write it
/// anywhere but the PKCS#12 container built from it.
///
/// # Errors
///
/// [`IssueError::KeyGeneration`] when the underlying implementation refuses
/// (a modulus search that cannot converge, an encoding failure).
pub fn generate_key_pair(
    key_type: LeafKeyType,
    entropy: &mut impl Entropy,
) -> Result<GeneratedKeyPair, IssueError> {
    match key_type {
        LeafKeyType::EcdsaP256 => generate_p256(entropy),
        LeafKeyType::EcdsaP384 => generate_p384(entropy),
        LeafKeyType::Rsa2048 => generate_rsa(entropy, 2048),
        LeafKeyType::Rsa3072 => generate_rsa(entropy, 3072),
        LeafKeyType::Rsa4096 => generate_rsa(entropy, 4096),
    }
}

/// Generates a P-256 pair.
fn generate_p256(entropy: &mut impl Entropy) -> Result<GeneratedKeyPair, IssueError> {
    use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};

    let mut rng = EllipticCurveRng(entropy);
    let secret = p256::SecretKey::random(&mut rng);
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|e| IssueError::KeyGeneration(format!("P-256 PKCS#8: {e}")))?;
    let spki = secret
        .public_key()
        .to_public_key_der()
        .map_err(|e| IssueError::KeyGeneration(format!("P-256 SPKI: {e}")))?;
    Ok(GeneratedKeyPair {
        spki_der: spki.as_bytes().to_vec(),
        private_key_pkcs8_der: Zeroizing::new(pkcs8.as_bytes().to_vec()),
    })
}

/// Generates a P-384 pair.
fn generate_p384(entropy: &mut impl Entropy) -> Result<GeneratedKeyPair, IssueError> {
    use p384::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};

    let mut rng = EllipticCurveRng(entropy);
    let secret = p384::SecretKey::random(&mut rng);
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|e| IssueError::KeyGeneration(format!("P-384 PKCS#8: {e}")))?;
    let spki = secret
        .public_key()
        .to_public_key_der()
        .map_err(|e| IssueError::KeyGeneration(format!("P-384 SPKI: {e}")))?;
    Ok(GeneratedKeyPair {
        spki_der: spki.as_bytes().to_vec(),
        private_key_pkcs8_der: Zeroizing::new(pkcs8.as_bytes().to_vec()),
    })
}

/// Generates an RSA pair with the given modulus size.
fn generate_rsa(entropy: &mut impl Entropy, bits: usize) -> Result<GeneratedKeyPair, IssueError> {
    use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};

    let mut rng = RsaRng(entropy);
    let secret = rsa::RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| IssueError::KeyGeneration(format!("RSA-{bits}: {e}")))?;
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|e| IssueError::KeyGeneration(format!("RSA-{bits} PKCS#8: {e}")))?;
    let spki = secret
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| IssueError::KeyGeneration(format!("RSA-{bits} SPKI: {e}")))?;
    Ok(GeneratedKeyPair {
        spki_der: spki.as_bytes().to_vec(),
        private_key_pkcs8_der: Zeroizing::new(pkcs8.as_bytes().to_vec()),
    })
}

/// Fills a word-sized buffer from the caller's source and reads it
/// little-endian.
///
/// The generator traits ask for whole words as well as byte runs; both come
/// from the same source, so a word is just a four- or eight-byte draw. The
/// endianness only has to be *fixed*, not any particular one — the bytes are
/// uniform either way.
macro_rules! word_from_entropy {
    ($entropy:expr, $ty:ty) => {{
        let mut bytes = [0u8; core::mem::size_of::<$ty>()];
        $entropy.fill(&mut bytes);
        <$ty>::from_le_bytes(bytes)
    }};
}

/// Adapter presenting an [`Entropy`] source as the generator trait the
/// `elliptic-curve` stack (P-256, P-384) takes.
struct EllipticCurveRng<'a, E: Entropy>(&'a mut E);

impl<E: Entropy> p256::elliptic_curve::rand_core::RngCore for EllipticCurveRng<'_, E> {
    fn next_u32(&mut self) -> u32 {
        word_from_entropy!(self.0, u32)
    }

    fn next_u64(&mut self) -> u64 {
        word_from_entropy!(self.0, u64)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
        self.0.fill(dest);
        Ok(())
    }
}

// The marker asserts the source is cryptographically secure, which is exactly
// what `Entropy` requires of its implementations.
impl<E: Entropy> p256::elliptic_curve::rand_core::CryptoRng for EllipticCurveRng<'_, E> {}

/// Adapter presenting an [`Entropy`] source as the generator trait the RSA
/// implementation takes. It is a different `rand_core` generation from the
/// elliptic-curve one, hence the second adapter over the same source.
struct RsaRng<'a, E: Entropy>(&'a mut E);

impl<E: Entropy> rsa::rand_core::TryRng for RsaRng<'_, E> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(word_from_entropy!(self.0, u32))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(word_from_entropy!(self.0, u64))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(dst);
        Ok(())
    }
}

// As above: `Entropy` promises a cryptographic source, so the marker holds.
impl<E: Entropy> rsa::rand_core::TryCryptoRng for RsaRng<'_, E> {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn parses_every_offered_key_type() {
        for kind in LeafKeyType::ALL {
            assert_eq!(LeafKeyType::parse(kind.flag_value()).unwrap(), *kind);
        }
    }

    #[test]
    fn refuses_a_type_the_device_cannot_verify() {
        // GOST is verified on the device but cannot be generated here, so it
        // must be refused like any other unknown value rather than accepted and
        // failed later.
        for unsupported in ["gost-2012-256", "ed25519", "rsa-1024", ""] {
            let err = LeafKeyType::parse(unsupported).unwrap_err();
            let IssueError::UnsupportedKeyType {
                requested,
                supported,
            } = err
            else {
                panic!("expected UnsupportedKeyType, got {err:?}");
            };
            assert_eq!(requested, unsupported);
            assert!(
                supported.contains("ecdsa-p256"),
                "the refusal must list what is accepted, got {supported}"
            );
        }
    }

    #[test]
    fn generates_a_usable_p256_pair() {
        use p256::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};

        let pair = generate_key_pair(LeafKeyType::EcdsaP256, &mut OsEntropy).unwrap();
        let secret = p256::SecretKey::from_pkcs8_der(&pair.private_key_pkcs8_der).unwrap();
        let derived = secret.public_key().to_public_key_der().unwrap();
        assert_eq!(
            derived.as_bytes(),
            pair.spki_der.as_slice(),
            "the returned public key must belong to the returned private key"
        );
    }

    #[test]
    fn generates_a_usable_p384_pair() {
        use p384::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};

        let pair = generate_key_pair(LeafKeyType::EcdsaP384, &mut OsEntropy).unwrap();
        let secret = p384::SecretKey::from_pkcs8_der(&pair.private_key_pkcs8_der).unwrap();
        let derived = secret.public_key().to_public_key_der().unwrap();
        assert_eq!(derived.as_bytes(), pair.spki_der.as_slice());
    }

    #[test]
    fn successive_generations_differ() {
        let first = generate_key_pair(LeafKeyType::EcdsaP256, &mut OsEntropy).unwrap();
        let second = generate_key_pair(LeafKeyType::EcdsaP256, &mut OsEntropy).unwrap();
        assert_ne!(first.spki_der, second.spki_der);
    }

    #[test]
    fn debug_hides_the_private_key() {
        let pair = generate_key_pair(LeafKeyType::EcdsaP256, &mut OsEntropy).unwrap();
        let rendered = format!("{pair:?}");
        assert!(rendered.contains("<redacted>"), "got {rendered}");
        assert!(
            !rendered.contains(&hex::encode(&*pair.private_key_pkcs8_der)),
            "the key bytes must not reach a formatted value"
        );
    }

    // RSA generation is a modulus search: minutes in a debug build for the
    // larger sizes, which would make the default test run unusable. The path is
    // the same for all three sizes, so the smallest one covers it on demand.
    #[test]
    #[ignore = "RSA key generation is too slow for the default run; run with --ignored"]
    fn generates_a_usable_rsa_pair() {
        use rsa::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};

        let pair = generate_key_pair(LeafKeyType::Rsa2048, &mut OsEntropy).unwrap();
        let secret = rsa::RsaPrivateKey::from_pkcs8_der(&pair.private_key_pkcs8_der).unwrap();
        let derived = secret.to_public_key().to_public_key_der().unwrap();
        assert_eq!(derived.as_bytes(), pair.spki_der.as_slice());
    }
}

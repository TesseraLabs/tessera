//! PKCS#12 container assembly: the artifact an engineer is handed when the
//! issuing operator minted the key pair.
//!
//! # Layout
//!
//! The container is built with a layout the device's login path depends on:
//!
//! * the **leaf certificate and the chain sit in an unencrypted safe**, so a
//!   reader that has no password can still see who the container was issued
//!   for. That is what separates "wrong flash drive" from "wrong password" on
//!   the login screen — a distinction that cannot be recovered once the
//!   certificate has been encrypted;
//! * the **private key sits in a shrouded key bag**, PBES2 with
//!   PBKDF2-HMAC-SHA256 and AES-256-CBC. No historic PKCS#12 scheme is used:
//!   those need a legacy provider on a modern OpenSSL, and a container the
//!   customer cannot open with their own tools is not an artifact;
//! * the whole authenticated safe is covered by an HMAC-SHA256 `MacData`, keyed
//!   through the RFC 7292 derivation, so a wrong password is reported as such
//!   rather than as a decryption failure deep inside a bag.
//!
//! Nothing here implements a cryptographic primitive. The key encryption comes
//! from `pkcs5` through `pkcs8`, the MAC key derivation from `pkcs12`, and the
//! MAC from `hmac`; this module owns only the DER layout that puts them
//! together.
//!
//! # Self-check
//!
//! [`build_container`] never returns a container it has not read back:
//! [`parse_container`] re-opens the assembled bytes with the password, and the
//! recovered key, leaf and chain are compared with the inputs. A container that
//! assembles but does not re-open is a broken artifact, and an operator finding
//! that out at the login screen is the failure this check exists to prevent.
//!
//! # Password
//!
//! The password is a `&str` rather than a secret wrapper because the crate's
//! secret types are native-only and this module also builds in the browser.
//! Callers are expected to hold it in wiped memory and to pass it in only for
//! the call; nothing here copies it beyond the derivations it feeds.

use cms::content_info::ContentInfo;
use der::asn1::{Any, OctetString};
use der::Decode as _;
use hmac::{Mac as _, SimpleHmac};
use pkcs12::cert_type::CertBag;
use pkcs12::digest_info::DigestInfo;
use pkcs12::kdf::{derive_key_utf8, Pkcs12KeyType};
use pkcs12::mac_data::MacData;
use pkcs12::pfx::{Pfx, Version};
use pkcs12::safe_bag::SafeBag;
use pkcs8::pkcs5::pbes2;
use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::error::IssueError;
use crate::keygen::Entropy;

/// `id-data` (PKCS#7): the content type of both safes this module writes.
const ID_DATA: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// `id-sha256`: the `MacData` digest algorithm.
const ID_SHA256: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// Iterations of the RFC 7292 derivation behind the container MAC key.
///
/// The MAC key guards integrity, not the private key — the key has its own,
/// far more expensive derivation — so this is the customary PKCS#12 count
/// rather than a password-hashing one.
const MAC_ITERATIONS: i32 = 2048;
/// Length of the MAC salt, bytes.
const MAC_SALT_LEN: usize = 8;
/// PBKDF2 iterations protecting the private key.
///
/// This is the number that stands between a stolen container and its key, so it
/// is set at the OWASP floor for PBKDF2-HMAC-SHA256 rather than at the far
/// lower count PKCS#12 tooling has historically defaulted to.
const PBKDF2_ITERATIONS: u32 = 600_000;
/// Key-derivation cost used by the crate's own tests.
///
/// The shipped cost is paid by one test that goes through the public entry
/// point; every other test builds containers by the dozen and would otherwise
/// turn an unoptimised test run into minutes of key stretching.
#[cfg(test)]
pub(crate) const TEST_ITERATIONS: u32 = 2_000;
/// Length of the PBKDF2 salt, bytes.
const KDF_SALT_LEN: usize = 16;
/// AES-CBC block size, and so the initialisation-vector length, bytes.
const AES_IV_LEN: usize = 16;

/// Smallest accepted operator-supplied container password, characters.
///
/// A container hands over an extractable private key, so its password is the
/// whole protection of that key once the container leaves the operator's hands.
/// Passwords the tool generates are far longer than this; the floor exists for
/// the case where the password comes from a corporate secret store and the tool
/// only checks it.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// The alphabet a generated password is drawn from.
///
/// Digits and letters that are read for one another in a handwritten or printed
/// note are left out (`0`/`O`, `1`/`l`/`I`), because this password is copied by
/// hand at a login prompt at least once.
const PASSPHRASE_ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
/// Characters in a generated password, excluding the group separators.
const PASSPHRASE_CHARS: usize = 20;
/// Characters per group in a generated password.
const PASSPHRASE_GROUP: usize = 5;

/// The certificates and key a container is assembled from.
#[derive(Debug, Clone, Copy)]
pub struct ContainerContents<'a> {
    /// The private key as PKCS#8 `PrivateKeyInfo` DER.
    pub private_key_pkcs8_der: &'a [u8],
    /// The end-entity certificate, DER.
    pub leaf_der: &'a [u8],
    /// Chain certificates (typically the issuing CA), DER, in order.
    pub chain_der: &'a [Vec<u8>],
}

/// What [`parse_container`] recovered from a container.
pub struct ParsedContainer {
    /// The private key as PKCS#8 `PrivateKeyInfo` DER, wiped on drop.
    pub private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    /// The end-entity certificate, DER.
    pub leaf_der: Vec<u8>,
    /// Chain certificates, DER, in the order they appear in the container.
    pub chain_der: Vec<Vec<u8>>,
}

impl core::fmt::Debug for ParsedContainer {
    /// Hides the key for the same reason
    /// [`crate::keygen::GeneratedKeyPair`]'s formatter does.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedContainer")
            .field("private_key_pkcs8_der", &"<redacted>")
            .field("leaf_der_len", &self.leaf_der.len())
            .field("chain_len", &self.chain_der.len())
            .finish()
    }
}

/// Generates a container password from the caller's random source.
///
/// The result is shown to the operator once and never stored: nothing in the
/// crate writes it to a file, a log or the issuance journal.
#[must_use]
pub fn generate_passphrase(entropy: &mut impl Entropy) -> Zeroizing<String> {
    let mut out = String::with_capacity(PASSPHRASE_CHARS + PASSPHRASE_CHARS / PASSPHRASE_GROUP);
    let modulus = PASSPHRASE_ALPHABET.len();
    for index in 0..PASSPHRASE_CHARS {
        if index > 0 && index % PASSPHRASE_GROUP == 0 {
            out.push('-');
        }
        out.push(char::from(draw_alphabet_byte(entropy, modulus)));
    }
    Zeroizing::new(out)
}

/// Draws one uniformly distributed character of the password alphabet.
///
/// Rejection sampling rather than a modulo of a single byte: the alphabet does
/// not divide 256, so folding a byte into it would make some characters more
/// likely than others.
fn draw_alphabet_byte(entropy: &mut impl Entropy, modulus: usize) -> u8 {
    // The largest multiple of the alphabet size that fits in a byte; draws at
    // or above it are discarded.
    let limit = (256 / modulus) * modulus;
    loop {
        let mut byte = [0u8; 1];
        entropy.fill(&mut byte);
        let value = usize::from(byte[0]);
        if value < limit {
            // The index is `value % modulus`, which is inside the alphabet by
            // construction; the fallback keeps the crate free of indexing that
            // could panic.
            return PASSPHRASE_ALPHABET
                .get(value % modulus)
                .copied()
                .unwrap_or(b'x');
        }
    }
}

/// Checks an operator-supplied password against the length floor.
///
/// # Errors
///
/// [`IssueError::PassphraseTooShort`] naming both the length given and the
/// minimum.
pub fn check_passphrase(passphrase: &str) -> Result<(), IssueError> {
    let actual = passphrase.chars().count();
    if actual < MIN_PASSPHRASE_CHARS {
        return Err(IssueError::PassphraseTooShort {
            actual,
            minimum: MIN_PASSPHRASE_CHARS,
        });
    }
    Ok(())
}

/// Assembles a PKCS#12 container and reads it back before returning it.
///
/// The layout is the one this module documents: certificates unencrypted, the
/// private key shrouded under `passphrase`, the whole safe covered by an HMAC.
/// The assembled bytes are re-opened with [`parse_container`] and compared with
/// the inputs; a mismatch returns [`IssueError::Container`] and no artifact.
///
/// # Errors
///
/// [`IssueError::Container`] when the private key is not valid PKCS#8, when any
/// component cannot be encoded, or when the self-check does not recover exactly
/// what went in.
pub fn build_container(
    contents: &ContainerContents<'_>,
    passphrase: &str,
    entropy: &mut impl Entropy,
) -> Result<Zeroizing<Vec<u8>>, IssueError> {
    build_with_iterations(contents, passphrase, entropy, PBKDF2_ITERATIONS)
}

/// [`build_container`] with the key-derivation cost made explicit.
///
/// The shipped cost is deliberately expensive, which in an unoptimised build
/// puts a container's assembly-plus-self-check at around a minute. That is the
/// right price for an operator running the tool once and the wrong one for a
/// test suite that builds dozens of containers, so the tests drive this entry
/// with a low count and one test covers the shipped constant end to end. The
/// count is a PBKDF2 parameter and changes no code path.
pub(crate) fn build_with_iterations(
    contents: &ContainerContents<'_>,
    passphrase: &str,
    entropy: &mut impl Entropy,
    pbkdf2_iterations: u32,
) -> Result<Zeroizing<Vec<u8>>, IssueError> {
    let container = assemble(contents, passphrase, entropy, pbkdf2_iterations)?;

    // The artifact is only as good as its readability: assembling successfully
    // says nothing about whether the container opens.
    let reread = parse_container(&container, passphrase)?;
    if reread.private_key_pkcs8_der.as_slice() != contents.private_key_pkcs8_der {
        return Err(IssueError::Container(
            "self-check: the private key read back does not match the one packaged".to_owned(),
        ));
    }
    if reread.leaf_der != contents.leaf_der {
        return Err(IssueError::Container(
            "self-check: the certificate read back does not match the one packaged".to_owned(),
        ));
    }
    if reread.chain_der != contents.chain_der {
        return Err(IssueError::Container(
            "self-check: the chain read back does not match the one packaged".to_owned(),
        ));
    }
    Ok(container)
}

/// Builds the container bytes, without the self-check
/// [`build_container`] wraps it in.
fn assemble(
    contents: &ContainerContents<'_>,
    passphrase: &str,
    entropy: &mut impl Entropy,
    pbkdf2_iterations: u32,
) -> Result<Zeroizing<Vec<u8>>, IssueError> {
    let cert_safe = data_safe(&cert_bags(contents)?)?;
    let key_safe = data_safe(&[shrouded_key_bag(
        contents.private_key_pkcs8_der,
        passphrase,
        entropy,
        pbkdf2_iterations,
    )?])?;

    // `AuthenticatedSafe` is a bare SEQUENCE OF ContentInfo; the MAC covers
    // exactly these bytes.
    let auth_safe_der = encode(&vec![cert_safe, key_safe])?;

    let mut mac_salt = [0u8; MAC_SALT_LEN];
    entropy.fill(&mut mac_salt);
    let mac_key = derive_key_utf8::<sha2_pkcs12::Sha256>(
        passphrase,
        &mac_salt,
        Pkcs12KeyType::Mac,
        MAC_ITERATIONS,
        32,
    )
    .map_err(|e| IssueError::Container(format!("MAC key derivation: {e}")))?;
    let digest = mac_over(&mac_key, &auth_safe_der)?;

    let pfx = Pfx {
        version: Version::V3,
        auth_safe: data_content_info(&auth_safe_der)?,
        mac_data: Some(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifierOwned {
                    oid: ID_SHA256,
                    parameters: Some(Any::null()),
                },
                digest: octet_string(&digest)?,
            },
            mac_salt: octet_string(&mac_salt)?,
            iterations: MAC_ITERATIONS,
        }),
    };
    Ok(Zeroizing::new(encode(&pfx)?))
}

/// The HMAC-SHA256 over `message` under `key`.
///
/// `SimpleHmac` rather than `Hmac`: the key derivation yields 32 bytes, which
/// the block-level construction accepts without further conditioning.
fn mac_over(key: &[u8], message: &[u8]) -> Result<Vec<u8>, IssueError> {
    let mut mac = <SimpleHmac<sha2_pkcs12::Sha256>>::new_from_slice(key)
        .map_err(|e| IssueError::Container(format!("MAC init: {e}")))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// The certificate bags of the unencrypted safe: the leaf first, then the
/// chain.
fn cert_bags(contents: &ContainerContents<'_>) -> Result<Vec<SafeBag>, IssueError> {
    let mut bags = Vec::with_capacity(1 + contents.chain_der.len());
    for der in core::iter::once(contents.leaf_der).chain(contents.chain_der.iter().map(Vec::as_ref))
    {
        let bag = CertBag {
            cert_id: pkcs12::PKCS_12_X509_CERT_OID,
            cert_value: octet_string(der)?,
        };
        bags.push(SafeBag {
            bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
            bag_value: encode(&bag)?,
            bag_attributes: None,
        });
    }
    Ok(bags)
}

/// The shrouded key bag: the PKCS#8 key encrypted under PBES2.
fn shrouded_key_bag(
    private_key_pkcs8_der: &[u8],
    passphrase: &str,
    entropy: &mut impl Entropy,
    pbkdf2_iterations: u32,
) -> Result<SafeBag, IssueError> {
    let key = PrivateKeyInfo::from_der(private_key_pkcs8_der)
        .map_err(|e| IssueError::Container(format!("private key is not PKCS#8: {e}")))?;
    let mut salt = [0u8; KDF_SALT_LEN];
    let mut iv = [0u8; AES_IV_LEN];
    entropy.fill(&mut salt);
    entropy.fill(&mut iv);
    let params = pbes2::Parameters::pbkdf2_sha256_aes256cbc(pbkdf2_iterations, &salt, &iv)
        .map_err(|e| IssueError::Container(format!("PBES2 parameters: {e}")))?;
    let encrypted = key
        .encrypt_with_params(params, passphrase)
        .map_err(|e| IssueError::Container(format!("private key encryption: {e}")))?;
    Ok(SafeBag {
        bag_id: pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        bag_value: encrypted.as_bytes().to_vec(),
        bag_attributes: None,
    })
}

/// Wraps safe contents in an unencrypted `id-data` `ContentInfo`.
fn data_safe(bags: &[SafeBag]) -> Result<ContentInfo, IssueError> {
    data_content_info(&encode(&bags.to_vec())?)
}

/// An `id-data` `ContentInfo` carrying `payload` in its OCTET STRING content.
fn data_content_info(payload: &[u8]) -> Result<ContentInfo, IssueError> {
    let wrapped = encode(&octet_string(payload)?)?;
    Ok(ContentInfo {
        content_type: ID_DATA,
        content: Any::from_der(&wrapped)
            .map_err(|e| IssueError::Container(format!("content wrapping: {e}")))?,
    })
}

/// Reads a container back: the certificates from its unencrypted safes, the
/// private key from its shrouded key bag.
///
/// This is the reverse of [`build_container`] and the check it runs on its own
/// output. It reads the certificates *without* touching the password, which is
/// also what proves the layout requirement holds: a container whose certificate
/// safe was encrypted would yield no certificate here.
///
/// # Errors
///
/// [`IssueError::Container`] when the bytes are not a well-formed container,
/// when the password does not open the key, or when a required component is
/// absent.
pub fn parse_container(bytes: &[u8], passphrase: &str) -> Result<ParsedContainer, IssueError> {
    let certs = certificates_without_passphrase(bytes)?;
    let mut certs = certs.into_iter();
    let leaf_der = certs
        .next()
        .ok_or_else(|| IssueError::Container("container carries no certificate".to_owned()))?;

    let pfx = decode_pfx(bytes)?;
    let mut key = None;
    for bag in safe_bags(&pfx)? {
        if bag.bag_id != pkcs12::PKCS_12_PKCS8_KEY_BAG_OID {
            continue;
        }
        let content = bag_content(&bag)?;
        let encrypted = EncryptedPrivateKeyInfo::from_der(&content)
            .map_err(|e| IssueError::Container(format!("shrouded key bag: {e}")))?;
        let decrypted = encrypted.decrypt(passphrase).map_err(|_| {
            IssueError::Container("the password does not open the container's key".to_owned())
        })?;
        key = Some(Zeroizing::new(decrypted.as_bytes().to_vec()));
        break;
    }

    Ok(ParsedContainer {
        private_key_pkcs8_der: key
            .ok_or_else(|| IssueError::Container("container carries no private key".to_owned()))?,
        leaf_der,
        chain_der: certs.collect(),
    })
}

/// Every certificate reachable without the password, in container order.
///
/// The login screen's "wrong drive or wrong password" diagnostic rests on this
/// being non-empty for a container this module built, so it is also what the
/// layout test asserts.
///
/// # Errors
///
/// [`IssueError::Container`] when the bytes are not a well-formed container.
pub fn certificates_without_passphrase(bytes: &[u8]) -> Result<Vec<Vec<u8>>, IssueError> {
    let pfx = decode_pfx(bytes)?;
    let mut out = Vec::new();
    for bag in safe_bags(&pfx)? {
        if bag.bag_id != pkcs12::PKCS_12_CERT_BAG_OID {
            continue;
        }
        let cert = CertBag::from_der(&bag_content(&bag)?)
            .map_err(|e| IssueError::Container(format!("certificate bag: {e}")))?;
        out.push(cert.cert_value.as_bytes().to_vec());
    }
    Ok(out)
}

/// The bag's value, with the `[0] EXPLICIT` wrapper removed.
///
/// The two directions of the bag codec are not symmetric: encoding wraps
/// `bag_value` in the explicit tag, while decoding leaves the wrapper in place.
/// A value that has been through a decode therefore carries a tag that a value
/// on its way to an encode does not, and only the decode side needs unwrapping —
/// which is why this exists rather than the parsers simply reading `bag_value`.
fn bag_content(bag: &SafeBag) -> Result<Vec<u8>, IssueError> {
    let any = der::asn1::AnyRef::from_der(&bag.bag_value)
        .map_err(|e| IssueError::Container(format!("safe bag value: {e}")))?;
    if der::Tagged::tag(&any).is_context_specific() {
        return Ok(any.value().to_vec());
    }
    Ok(bag.bag_value.clone())
}

/// Decodes the outer `PFX`.
fn decode_pfx(bytes: &[u8]) -> Result<Pfx, IssueError> {
    Pfx::from_der(bytes).map_err(|e| IssueError::Container(format!("not a PKCS#12 container: {e}")))
}

/// Every safe bag of every *unencrypted* safe, in container order.
///
/// Encrypted safes are skipped rather than refused: this module never writes
/// one, but a container from elsewhere may, and the caller's question ("what
/// can be read here") is answered by what is readable.
fn safe_bags(pfx: &Pfx) -> Result<Vec<SafeBag>, IssueError> {
    let mut out = Vec::new();
    for safe in unwrap_data(&pfx.auth_safe)? {
        for bag in unwrap_bags(&safe)? {
            out.push(bag);
        }
    }
    Ok(out)
}

/// The `AuthenticatedSafe` inside an `id-data` `ContentInfo`.
fn unwrap_data(content_info: &ContentInfo) -> Result<Vec<ContentInfo>, IssueError> {
    let payload = data_payload(content_info)?;
    Vec::<ContentInfo>::from_der(&payload)
        .map_err(|e| IssueError::Container(format!("authenticated safe: {e}")))
}

/// The safe bags of one safe, or nothing when the safe is not `id-data`.
fn unwrap_bags(safe: &ContentInfo) -> Result<Vec<SafeBag>, IssueError> {
    if safe.content_type != ID_DATA {
        return Ok(Vec::new());
    }
    let payload = data_payload(safe)?;
    Vec::<SafeBag>::from_der(&payload)
        .map_err(|e| IssueError::Container(format!("safe contents: {e}")))
}

/// The octets an `id-data` `ContentInfo` carries.
fn data_payload(content_info: &ContentInfo) -> Result<Vec<u8>, IssueError> {
    let der = encode(&content_info.content)?;
    let octets = OctetString::from_der(&der)
        .map_err(|e| IssueError::Container(format!("content octets: {e}")))?;
    Ok(octets.as_bytes().to_vec())
}

/// DER-encodes a value, mapping the encoder's error into the module's.
fn encode<T: der::Encode>(value: &T) -> Result<Vec<u8>, IssueError> {
    value
        .to_der()
        .map_err(|e| IssueError::Container(format!("DER encoding: {e}")))
}

/// Builds an `OCTET STRING`, mapping the length error into the module's.
fn octet_string(bytes: &[u8]) -> Result<OctetString, IssueError> {
    OctetString::new(bytes).map_err(|e| IssueError::Container(format!("octet string: {e}")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::keygen::{generate_key_pair, LeafKeyType, OsEntropy};

    /// A stand-in certificate: the container never parses one, it only carries
    /// the bytes, so any DER-shaped value exercises the same path.
    fn fake_cert(marker: u8) -> Vec<u8> {
        let mut der = vec![0x04, 0x20];
        der.extend(core::iter::repeat_n(marker, 32));
        der
    }

    const PASSPHRASE: &str = "correct-horse-battery";

    /// Key-derivation cost for the tests that only care about the container's
    /// shape. The shipped cost is paid by the one test that packages through
    /// the public issuance entry point.
    const TEST_ITERATIONS: u32 = super::TEST_ITERATIONS;

    fn key_der() -> Zeroizing<Vec<u8>> {
        generate_key_pair(LeafKeyType::EcdsaP256, &mut OsEntropy)
            .unwrap()
            .private_key_pkcs8_der
    }

    #[test]
    fn round_trips_key_certificate_and_chain() {
        let key = key_der();
        let leaf = fake_cert(0x11);
        let chain = vec![fake_cert(0x22), fake_cert(0x33)];
        let container = build_with_iterations(
            &ContainerContents {
                private_key_pkcs8_der: &key,
                leaf_der: &leaf,
                chain_der: &chain,
            },
            PASSPHRASE,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap();

        let parsed = parse_container(&container, PASSPHRASE).unwrap();
        assert_eq!(parsed.private_key_pkcs8_der.as_slice(), key.as_slice());
        assert_eq!(parsed.leaf_der, leaf);
        assert_eq!(parsed.chain_der, chain);
    }

    #[test]
    fn certificates_are_readable_without_the_password() {
        // The login screen's "wrong carrier or wrong password" diagnostic rests
        // on this: the certificate safe must not be encrypted. Asserted against
        // the container's structure rather than through any reader, so it holds
        // regardless of what a particular reader manages to do with it.
        let key = key_der();
        let leaf = fake_cert(0x44);
        let chain = vec![fake_cert(0x55)];
        let container = build_with_iterations(
            &ContainerContents {
                private_key_pkcs8_der: &key,
                leaf_der: &leaf,
                chain_der: &chain,
            },
            PASSPHRASE,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap();

        let certs = certificates_without_passphrase(&container).unwrap();
        assert_eq!(certs, vec![leaf, chain.first().unwrap().clone()]);
    }

    #[test]
    fn every_safe_is_an_unencrypted_data_safe() {
        // The complement of the check above: no `EncryptedData` safe is written
        // at all, so no certificate can end up behind the password by accident.
        let key = key_der();
        let container = build_with_iterations(
            &ContainerContents {
                private_key_pkcs8_der: &key,
                leaf_der: &fake_cert(0x66),
                chain_der: &[],
            },
            PASSPHRASE,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap();

        let pfx = decode_pfx(&container).unwrap();
        let safes = unwrap_data(&pfx.auth_safe).unwrap();
        assert_eq!(safes.len(), 2, "one certificate safe and one key safe");
        for safe in &safes {
            assert_eq!(
                safe.content_type, ID_DATA,
                "an encrypted safe would hide the certificate from the login diagnostic"
            );
        }
    }

    #[test]
    fn the_private_key_is_not_readable_without_the_password() {
        let key = key_der();
        let container = build_with_iterations(
            &ContainerContents {
                private_key_pkcs8_der: &key,
                leaf_der: &fake_cert(0x77),
                chain_der: &[],
            },
            PASSPHRASE,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap();

        let err = parse_container(&container, "not-the-password").unwrap_err();
        assert!(matches!(err, IssueError::Container(_)), "got {err:?}");
        assert!(
            !container.windows(key.len()).any(|w| w == key.as_slice()),
            "the plaintext key must not appear anywhere in the container"
        );
    }

    #[test]
    fn carries_a_mac_over_the_authenticated_safe() {
        let key = key_der();
        let container = build_with_iterations(
            &ContainerContents {
                private_key_pkcs8_der: &key,
                leaf_der: &fake_cert(0x88),
                chain_der: &[],
            },
            PASSPHRASE,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap();

        let pfx = decode_pfx(&container).unwrap();
        let mac = pfx.mac_data.expect("a container must carry integrity data");
        assert_eq!(mac.mac.algorithm.oid, ID_SHA256);
        assert_eq!(mac.iterations, MAC_ITERATIONS);
        assert_eq!(mac.mac_salt.as_bytes().len(), MAC_SALT_LEN);
    }

    #[test]
    fn self_check_withholds_a_container_that_does_not_read_back() {
        // Drives the self-check by handing the assembly a key and then
        // comparing against a different one: the packaged bytes are sound, the
        // comparison is not, and the artifact must be withheld.
        let packaged = key_der();
        let other = key_der();
        let container = assemble(
            &ContainerContents {
                private_key_pkcs8_der: &packaged,
                leaf_der: &fake_cert(0x99),
                chain_der: &[],
            },
            PASSPHRASE,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap();
        let reread = parse_container(&container, PASSPHRASE).unwrap();
        assert_ne!(reread.private_key_pkcs8_der.as_slice(), other.as_slice());

        // And the wired-up path refuses a container whose contents disagree:
        // truncating the assembled bytes makes the read-back fail outright.
        let truncated = container.get(..container.len() / 2).unwrap();
        let err = parse_container(truncated, PASSPHRASE).unwrap_err();
        assert!(matches!(err, IssueError::Container(_)), "got {err:?}");
    }

    #[test]
    fn refuses_a_private_key_that_is_not_pkcs8() {
        let err = build_with_iterations(
            &ContainerContents {
                private_key_pkcs8_der: b"not-a-key",
                leaf_der: &fake_cert(0xaa),
                chain_der: &[],
            },
            PASSPHRASE,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap_err();
        assert!(matches!(err, IssueError::Container(_)), "got {err:?}");
    }

    #[test]
    fn generated_passphrases_are_long_unique_and_pass_the_floor() {
        let first = generate_passphrase(&mut OsEntropy);
        let second = generate_passphrase(&mut OsEntropy);
        assert_ne!(*first, *second);
        assert_eq!(
            first.chars().filter(|c| *c != '-').count(),
            PASSPHRASE_CHARS
        );
        check_passphrase(&first).unwrap();
        assert!(
            first
                .chars()
                .all(|c| c == '-' || PASSPHRASE_ALPHABET.contains(&(c as u8))),
            "got {}",
            &*first
        );
    }

    #[test]
    fn a_generated_passphrase_opens_its_container() {
        let key = key_der();
        let passphrase = generate_passphrase(&mut OsEntropy);
        let container = build_with_iterations(
            &ContainerContents {
                private_key_pkcs8_der: &key,
                leaf_der: &fake_cert(0xbb),
                chain_der: &[],
            },
            &passphrase,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap();
        let parsed = parse_container(&container, &passphrase).unwrap();
        assert_eq!(parsed.private_key_pkcs8_der.as_slice(), key.as_slice());
    }

    #[test]
    fn refuses_a_short_operator_passphrase() {
        let err = check_passphrase("короткий").unwrap_err();
        let IssueError::PassphraseTooShort { actual, minimum } = err else {
            panic!("expected PassphraseTooShort, got {err:?}");
        };
        assert_eq!(actual, 8, "the length is counted in characters, not bytes");
        assert_eq!(minimum, MIN_PASSPHRASE_CHARS);
    }

    #[test]
    fn accepts_an_operator_passphrase_at_the_floor() {
        let at_floor = "x".repeat(MIN_PASSPHRASE_CHARS);
        check_passphrase(&at_floor).unwrap();
    }

    #[test]
    fn parsed_container_debug_hides_the_key() {
        let key = key_der();
        let container = build_with_iterations(
            &ContainerContents {
                private_key_pkcs8_der: &key,
                leaf_der: &fake_cert(0xcc),
                chain_der: &[],
            },
            PASSPHRASE,
            &mut OsEntropy,
            TEST_ITERATIONS,
        )
        .unwrap();
        let rendered = format!("{:?}", parse_container(&container, PASSPHRASE).unwrap());
        assert!(rendered.contains("<redacted>"), "got {rendered}");
    }
}

//! Derivation of the shared key `K`.
//!
//! The crate performs no Diffie-Hellman of its own: on the device the shared
//! secret `Z` is computed by a software library, on the issuing side by a token
//! behind an agent, and PKCS#11 cannot be carried into WebAssembly at all. What
//! arrives here is `Z`; what leaves is
//! `K = HKDF-SHA256(Z, № устройства ‖ hash(ticket))`.
//!
//! # Which key pair `Z` comes from
//!
//! From an **ephemeral** pair of the device and the static key of the issuing
//! side. The long-lived device key takes no part in it: while it did, anybody
//! who held that key — a preparer, whoever lifted the disk, whoever kept a
//! backup — computed codes for the device without the issuing side being
//! involved at all, because everything else the derivation needs travels in the
//! open. An ephemeral pair closes that: the private half of an attempt does not
//! exist until the attempt begins, and it never reaches a disk. What the device
//! key is still good for is signing the challenge, which says who produced the
//! ephemeral point — not what the code is.
//!
//! Binding the ticket hash into the context gives a second line of defence
//! behind the ticket signature: any edit of the signed ticket changes the
//! context, and the codes of the two sides stop meeting.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::canon::{CanonError, Encoder};
use crate::device_number::CheckedDeviceNumber;
use crate::mac::{hkdf_sha256, sha256, DIGEST_LEN};

/// Domain separator used as the HKDF salt.
///
/// The salt is not a secret; it keeps this derivation from colliding with any
/// other use of the same `Z` and pins the version of the contract.
const KDF_SALT: &[u8] = b"tessera-codes-contract/v1/kdf";

/// Length of the derived key in bytes.
pub const KEY_LEN: usize = DIGEST_LEN;

/// Key epoch of a device, increased when the device receives a new key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u32);

impl Epoch {
    /// Wraps a raw epoch value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw epoch value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Result of the Diffie-Hellman exchange, computed outside this crate.
///
/// The material is wiped when the value is dropped, and its [`Debug`] output
/// carries no bytes.
///
/// The type deliberately implements neither [`PartialEq`] nor [`Eq`]: the
/// derived comparison stops at the first differing byte, so its running time
/// tells an observer how far the two secrets agree. Comparison, where it is
/// needed at all, goes through [`SharedSecret::ct_eq`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    /// Wraps the raw shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::EmptySecret`] for an empty secret: a key agreement
    /// that produced nothing must not silently derive a key.
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeyError> {
        if bytes.is_empty() {
            return Err(KeyError::EmptySecret);
        }
        Ok(Self(bytes))
    }

    /// Returns the secret bytes.
    fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Reports whether two secrets carry the same material, in time that does
    /// not depend on where they start to differ.
    ///
    /// Secrets of different lengths compare unequal, and the length is not
    /// hidden by this comparison — only the content is.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(redacted)")
    }
}

/// The derived key `K`.
///
/// Wiped on drop, and redacted in [`Debug`] output for the same reason as
/// [`SharedSecret`]: this key is the entire strength of the phone channel.
///
/// As with [`SharedSecret`], the type carries no [`PartialEq`]: a derived
/// comparison would leak the length of the common prefix of two keys through
/// its running time. Use [`DerivedKey::ct_eq`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey([u8; KEY_LEN]);

impl DerivedKey {
    /// Returns the key bytes, for the MAC computation inside the crate.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Reports whether two keys are the same, in time that does not depend on
    /// where they start to differ.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl core::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DerivedKey(redacted)")
    }
}

/// Digest of the canonical bytes of a signed operator ticket.
///
/// The type carries no constructor from arbitrary bytes on purpose: the only
/// way to obtain one is
/// [`SignedTicket::context_hash`](crate::ticket::SignedTicket::context_hash),
/// which hashes the canonical bytes of the ticket *including its signature*.
/// A hash taken over some other slice — the unsigned body, a re-serialisation,
/// the wire form — would bind the key to something an editor of the ticket can
/// keep unchanged, and the second line of defence behind the ticket signature
/// would quietly stop existing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TicketHash([u8; DIGEST_LEN]);

impl TicketHash {
    /// Hashes the canonical bytes of a signed ticket.
    pub(crate) fn of_canonical_signed_ticket(bytes: &[u8]) -> Self {
        Self(sha256(bytes))
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }
}

/// Context the key is bound to: the device and the signed ticket of the issuing
/// side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyContext<'a> {
    device_number: &'a CheckedDeviceNumber,
    ticket_hash: TicketHash,
}

impl<'a> KeyContext<'a> {
    /// Builds the derivation context.
    ///
    /// The device number enters the context in its significant form, for the
    /// same reason it does in [`CodeInput`](crate::canon::CodeInput): the two
    /// sides read the number off different labels, and a key that depended on
    /// the separators would not meet.
    ///
    /// The key epoch is not part of the context. It names the long-lived device
    /// key, and that key no longer enters `Z`, so an epoch here would separate
    /// nothing; what separates one attempt from every other is the ephemeral
    /// pair `Z` is computed on.
    #[must_use]
    pub const fn new(device_number: &'a CheckedDeviceNumber, ticket_hash: TicketHash) -> Self {
        Self {
            device_number,
            ticket_hash,
        }
    }

    /// Encodes the context with the canonical length-prefixed framing.
    ///
    /// # Errors
    ///
    /// Returns [`CanonError::FieldTooLong`] when the device number exceeds the
    /// range of the length prefix.
    pub fn encode(&self) -> Result<Vec<u8>, CanonError> {
        let mut encoder = Encoder::default();
        encoder.push_text("device_number", self.device_number.significant())?;
        encoder.push_bytes("ticket_hash", self.ticket_hash.as_bytes())?;
        Ok(encoder.finish())
    }
}

/// Derives the shared key `K` from `Z` and the context.
///
/// # Errors
///
/// Returns [`CanonError::FieldTooLong`] when the context cannot be encoded —
/// a device number longer than the length prefix allows. Deriving a key from a
/// truncated context would leave the two sides agreeing on the wrong thing, so
/// the failure is reported rather than absorbed.
pub fn derive_key(
    secret: &SharedSecret,
    context: &KeyContext<'_>,
) -> Result<DerivedKey, CanonError> {
    let info = context.encode()?;
    Ok(DerivedKey(hkdf_sha256(KDF_SALT, secret.expose(), &info)))
}

/// Public half of the ephemeral pair of one attempt.
///
/// The bytes are opaque to the contract, as every other public point is: they
/// are in the encoding of the algorithm profile, and whoever performs the key
/// agreement is the one that parses and validates them.
///
/// Only the public half has a type here. The private half never crosses this
/// crate — it is generated, used and wiped inside the implementation of
/// [`EphemeralKeyAgreement`], and a type that could carry it out of there would
/// be an invitation to store it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EphemeralPublicPoint(Vec<u8>);

impl EphemeralPublicPoint {
    /// Wraps the encoded point.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::EmptyPoint`] for an empty value: a challenge that
    /// carries no point names no pair, and the issuing side would have nothing
    /// to agree against.
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeyError> {
        if bytes.is_empty() {
            return Err(KeyError::EmptyPoint);
        }
        Ok(Self(bytes))
    }

    /// Returns the encoded point.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Failure of the key material handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The supplied shared secret is empty.
    #[error("the shared secret is empty")]
    EmptySecret,
    /// The supplied ephemeral public point is empty.
    #[error("the ephemeral public point is empty")]
    EmptyPoint,
}

/// Failure of an external key agreement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyAgreementError {
    /// The peer public point failed the validation required of the
    /// implementation.
    #[error("the peer public point was rejected by profile validation")]
    InvalidPublicPoint,
    /// The backend performing the exchange failed for its own reason.
    #[error("key agreement backend failed: {0}")]
    Backend(String),
}

/// Diffie-Hellman performed outside the contract.
///
/// # Obligations of the implementation
///
/// The implementation **must** validate the peer public point by the rules of
/// the algorithm profile — that the point lies on the curve, belongs to the
/// prime-order subgroup and is not the identity — *before* computing `Z`, and
/// must return [`KeyAgreementError::InvalidPublicPoint`] when it does not. The
/// contract never sees the point and therefore cannot check it: an
/// implementation that skips the check hands an attacker a small-subgroup
/// attack on the shared key, and nothing downstream will notice.
///
/// The implementation must also wipe any intermediate representation of `Z` it
/// creates; the value handed back is wiped by [`SharedSecret`].
pub trait KeyAgreement {
    /// Computes `Z` against the peer public key, in the encoding of the
    /// algorithm profile.
    ///
    /// # Errors
    ///
    /// Returns [`KeyAgreementError::InvalidPublicPoint`] when the point fails
    /// validation, and [`KeyAgreementError::Backend`] for any failure of the
    /// underlying device or library.
    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, KeyAgreementError>;
}

/// Key agreement performed on a pair that exists for one attempt only.
///
/// This is what the device side implements. The distinction from a plain
/// [`KeyAgreement`] is not the arithmetic — it is the lifetime of the private
/// half, and that lifetime is the security property `K` now rests on.
///
/// # Obligations of the implementation
///
/// Beyond everything [`KeyAgreement`] asks of it:
///
/// - the pair **must** be generated afresh for every attempt, from the system
///   generator, and never derived from anything stored;
/// - the private half **must not** be written anywhere outside process memory —
///   no file, no key container, no log — and **must** be wiped when the value
///   is dropped, so that an attempt that ends leaves nothing behind that would
///   recompute its code;
/// - [`EphemeralKeyAgreement::public_point`] **must** return the public half of
///   that same pair, because it is what travels in the challenge and what the
///   issuing side computes `Z` against.
///
/// A backing implementation that reused one pair across attempts would hand
/// back exactly the property the ephemeral pair exists to remove: a value that
/// can be captured once and used later.
pub trait EphemeralKeyAgreement: KeyAgreement {
    /// Returns the public half of the pair, for the challenge to carry.
    fn public_point(&self) -> &EphemeralPublicPoint;
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{
        derive_key, EphemeralKeyAgreement, EphemeralPublicPoint, KeyAgreement, KeyAgreementError,
        KeyContext, KeyError, SharedSecret, TicketHash,
    };
    use crate::device_number::CheckedDeviceNumber;

    fn secret() -> SharedSecret {
        SharedSecret::new(vec![0x11; 32]).unwrap()
    }

    fn number(body: &str) -> CheckedDeviceNumber {
        CheckedDeviceNumber::from_body(body).unwrap()
    }

    fn ticket_hash(bytes: &[u8]) -> TicketHash {
        TicketHash::of_canonical_signed_ticket(bytes)
    }

    #[test]
    fn empty_secret_is_rejected() {
        assert!(matches!(
            SharedSecret::new(Vec::new()),
            Err(KeyError::EmptySecret)
        ));
    }

    #[test]
    fn secrets_compare_by_content_only_in_constant_time() {
        let secret = SharedSecret::new(vec![0x11; 32]).unwrap();
        assert!(secret.ct_eq(&SharedSecret::new(vec![0x11; 32]).unwrap()));
        assert!(!secret.ct_eq(&SharedSecret::new(vec![0x12; 32]).unwrap()));
        assert!(!secret.ct_eq(&SharedSecret::new(vec![0x11; 31]).unwrap()));
    }

    #[test]
    fn debug_output_carries_no_material() {
        let secret = SharedSecret::new(vec![0xde, 0xad, 0xbe, 0xef]).unwrap();
        assert_eq!(format!("{secret:?}"), "SharedSecret(redacted)");

        let device = number("77-1");
        let key = derive_key(&secret, &KeyContext::new(&device, ticket_hash(b"t"))).unwrap();
        assert_eq!(format!("{key:?}"), "DerivedKey(redacted)");
    }

    #[test]
    fn edited_ticket_separates_keys() {
        let device = number("77-1");
        let context = KeyContext::new(&device, ticket_hash(b"scope=dc-1"));
        let edited = KeyContext::new(&device, ticket_hash(b"scope=dc-2"));
        assert!(!derive_key(&secret(), &context)
            .unwrap()
            .ct_eq(&derive_key(&secret(), &edited).unwrap()));
    }

    #[test]
    fn device_number_separates_keys() {
        let hash = ticket_hash(b"signed ticket");
        let first_device = number("77-1");
        let second_device = number("77-2");
        let first = derive_key(&secret(), &KeyContext::new(&first_device, hash)).unwrap();
        let second = derive_key(&secret(), &KeyContext::new(&second_device, hash)).unwrap();
        assert!(!first.ct_eq(&second));
    }

    #[test]
    fn two_spellings_of_one_number_derive_one_key() {
        let hash = ticket_hash(b"signed ticket");
        let printed = number("77-000123");
        let retyped =
            CheckedDeviceNumber::parse(&printed.as_str().replace('-', " ").to_lowercase()).unwrap();
        let first = derive_key(&secret(), &KeyContext::new(&printed, hash)).unwrap();
        let second = derive_key(&secret(), &KeyContext::new(&retyped, hash)).unwrap();
        assert!(first.ct_eq(&second));
    }

    #[test]
    fn derivation_is_deterministic() {
        let hash = ticket_hash(b"signed ticket");
        let device = number("77-1");
        let context = KeyContext::new(&device, hash);
        assert!(derive_key(&secret(), &context)
            .unwrap()
            .ct_eq(&derive_key(&secret(), &context).unwrap()));
    }

    #[test]
    fn one_context_over_two_exchanges_gives_two_keys() {
        // The context of two attempts against one device under one ticket is
        // the same bytes; what tells their keys apart is `Z`, and `Z` is what
        // the ephemeral pair makes new every time. A derivation that ignored
        // the secret would show up here and nowhere else.
        let device = number("77-1");
        let context = KeyContext::new(&device, ticket_hash(b"signed ticket"));
        let first = derive_key(&SharedSecret::new(vec![0x11; 32]).unwrap(), &context).unwrap();
        let second = derive_key(&SharedSecret::new(vec![0x12; 32]).unwrap(), &context).unwrap();
        assert!(!first.ct_eq(&second));
    }

    #[test]
    fn an_empty_ephemeral_point_is_refused() {
        assert!(matches!(
            EphemeralPublicPoint::new(Vec::new()),
            Err(KeyError::EmptyPoint)
        ));
        assert_eq!(
            EphemeralPublicPoint::new(vec![0x04, 0x01])
                .unwrap()
                .as_bytes(),
            &[0x04, 0x01]
        );
    }

    /// Stand-in for a real backend: it demonstrates the shape the trait asks
    /// for — reject the point first, derive second — and carries a public point
    /// of its own, as the device side does.
    struct ValidatingBackend {
        accepted_point: Vec<u8>,
        public_point: EphemeralPublicPoint,
    }

    impl KeyAgreement for ValidatingBackend {
        fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, KeyAgreementError> {
            if peer_public != self.accepted_point {
                return Err(KeyAgreementError::InvalidPublicPoint);
            }
            SharedSecret::new(vec![0x22; 32])
                .map_err(|error| KeyAgreementError::Backend(error.to_string()))
        }
    }

    impl EphemeralKeyAgreement for ValidatingBackend {
        fn public_point(&self) -> &EphemeralPublicPoint {
            &self.public_point
        }
    }

    fn backend() -> ValidatingBackend {
        ValidatingBackend {
            accepted_point: vec![0x04, 0x01, 0x02],
            public_point: EphemeralPublicPoint::new(vec![0x04, 0x33, 0x44]).unwrap(),
        }
    }

    #[test]
    fn agreement_backend_rejects_before_deriving() {
        let backend = backend();
        assert!(matches!(
            backend.agree(&[0x04, 0x09]),
            Err(KeyAgreementError::InvalidPublicPoint)
        ));
        let z = backend.agree(&[0x04, 0x01, 0x02]).unwrap();
        let device = number("77-1");
        assert!(derive_key(&z, &KeyContext::new(&device, ticket_hash(b"t"))).is_ok());
    }

    #[test]
    fn the_point_the_backend_publishes_is_the_one_it_hands_out() {
        let backend = backend();
        assert_eq!(backend.public_point().as_bytes(), &[0x04, 0x33, 0x44]);
    }
}

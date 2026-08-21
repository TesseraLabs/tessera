//! The device side of the key agreement.
//!
//! The contract computes no Diffie-Hellman: the shared secret arrives from
//! whatever performs the exchange, which on the issuing side is a token behind
//! an agent and on the device is this module — the software implementation
//! OpenSSL already provides, on the curve the fleet profile names.
//!
//! # Two agreements, and why the device uses the ephemeral one
//!
//! [`EphemeralAgreement`] generates a pair when an attempt begins, hands its
//! public point to the challenge and holds the private half in memory until the
//! attempt ends. That is the device path, and it is the whole reason the code
//! of an attempt cannot be computed from the contents of a disk: the private
//! half of an attempt does not exist before the attempt and is never written
//! down.
//!
//! [`StaticKeyAgreement`] performs the same exchange on a key that was stored —
//! the issuing side's key, and in the tests of this workspace the stand-in for
//! it. The device does not derive codes with the long-lived key it holds; that
//! key signs, it does not agree.
//!
//! The trait the contract defines puts one obligation on an implementation, and
//! it is the whole reason this module is not three lines: **the peer point is
//! validated before the secret is computed**. The operator public key travels
//! inside a ticket, and a ticket the authority signed is still a document an
//! operator's own tooling produced. A point off the curve or in a small
//! subgroup would leak the device key through the derived code, and nothing
//! downstream would notice, because a wrong key looks exactly like a wrong
//! code.
//!
//! `EcKey::check_key` is what performs that validation: it rejects the point at
//! infinity, a point that is not on the curve, and a point outside the
//! prime-order subgroup. P-256 has cofactor one, so subgroup membership follows
//! from curve membership there; the call is made regardless, because the check
//! belongs to the profile and not to the arithmetic of one curve.

use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};

use tessera_codes_contract::key::{
    EphemeralKeyAgreement, EphemeralPublicPoint, KeyAgreement, KeyAgreementError, SharedSecret,
};
use tessera_codes_contract::profile::AlgorithmProfile;

/// The curve this device performs `profile` on, or `None` when it has no key
/// agreement for that profile at all.
///
/// One match, consulted by both the thing that performs the agreement and the
/// thing that decides whether a fleet may be configured for it. A second list
/// somewhere else is how a device comes to accept a configuration it cannot
/// run: the configuration loads, the method announces itself, and every code
/// an operator reads out is refused at the keyboard.
const fn curve_of(profile: AlgorithmProfile) -> Option<Nid> {
    match profile {
        AlgorithmProfile::P256 => Some(Nid::X9_62_PRIME256V1),
        // No software implementation here. X25519 is a curve OpenSSL has and
        // this module does not yet drive; VKO 34.10-2012 needs the vendor
        // library, which the device reaches through PKCS#11 and not through
        // this path.
        AlgorithmProfile::X25519 | AlgorithmProfile::GostVko34102012 => None,
    }
}

/// Reports whether this device can perform the key agreement of `profile`.
///
/// Read by the configuration layer, so that a fleet parameter the device cannot
/// honour is refused when the file is loaded rather than when an engineer is
/// standing at the device with a code that will never be accepted.
#[must_use]
pub const fn device_supports(profile: AlgorithmProfile) -> bool {
    curve_of(profile).is_some()
}

/// A stored key performing the exchange.
///
/// Not the device path: what the device agrees on is [`EphemeralAgreement`].
/// This type exists for a side that legitimately holds a long-lived key — the
/// issuing side — and for the tests that stand in for it.
pub struct StaticKeyAgreement<'a> {
    private: &'a PKey<Private>,
    curve: Nid,
}

impl<'a> StaticKeyAgreement<'a> {
    /// Binds a stored private key to the profile of the fleet.
    ///
    /// # Errors
    ///
    /// Returns [`KeyAgreementError::Backend`] when the fleet profile has no
    /// software implementation here, or when the key is not a key of that
    /// profile. Both are configuration failures rather than anything about the
    /// other side, and both refuse the attempt.
    pub fn new(
        private: &'a PKey<Private>,
        profile: AlgorithmProfile,
    ) -> Result<Self, KeyAgreementError> {
        let curve = curve_of(profile).ok_or_else(|| {
            KeyAgreementError::Backend(format!(
                "the device has no key agreement for the `{}` profile",
                profile.as_str()
            ))
        })?;

        if private.id() != Id::EC {
            return Err(KeyAgreementError::Backend(
                "the device key is not an elliptic-curve key".to_owned(),
            ));
        }
        let key_curve = private
            .ec_key()
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?
            .group()
            .curve_name()
            .ok_or_else(|| {
                KeyAgreementError::Backend("the device key names no curve".to_owned())
            })?;
        if key_curve != curve {
            return Err(KeyAgreementError::Backend(
                "the device key is on a curve the fleet profile does not name".to_owned(),
            ));
        }

        Ok(Self { private, curve })
    }
}

impl KeyAgreement for StaticKeyAgreement<'_> {
    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, KeyAgreementError> {
        agree_on_curve(self.private, self.curve, peer_public)
    }
}

/// The pair of one attempt, generated when the attempt begins.
///
/// The private half lives here and nowhere else: it is not written to the
/// artefact directory, not carried in the state file and not derivable from
/// anything that is. When the value is dropped OpenSSL scrubs the key material
/// as it frees it, so an attempt that ends — accepted, refused or abandoned —
/// takes with it the only thing that could recompute its code.
///
/// # What is checked, and what is a premise
///
/// Checked by the tests of this module: the private half is reachable through
/// no public accessor, a pair is generated afresh for every attempt, and the
/// value that carries it cannot be cloned — so it cannot be duplicated into a
/// second lifetime.
///
/// **Not checked: that the bytes of the private half are actually overwritten
/// when the value is dropped.** That happens inside OpenSSL, which frees the
/// key as it scrubs it, and after the free the memory belongs to the allocator:
/// reading it back is undefined behaviour, and a test that read it would be
/// testing the allocator rather than the scrub. There is no honest way to
/// observe it from this crate, so it is stated as a premise about the library
/// instead of being dressed up as a test — a green test that never observed the
/// scrub would be worse than none, because it would end the question.
///
/// What would move it from premise to check: holding the scalar in this crate,
/// in a `Zeroizing` buffer of our own, and performing the exchange over it. That
/// is a different construction — the exchange would stop going through the key
/// type of the library — and it is written here so the choice is visible rather
/// than assumed away.
///
/// # The pair cannot be duplicated
///
/// Enforced by the compiler rather than by a runtime assertion: a value that
/// could be cloned could outlive the attempt it belongs to, and the wiping of
/// the original would say nothing about the copy.
///
/// ```compile_fail
/// use tessera_codes_contract::profile::AlgorithmProfile;
/// use tessera_core::codes::agreement::EphemeralAgreement;
///
/// let pair = EphemeralAgreement::generate(AlgorithmProfile::P256).unwrap();
/// // `EphemeralAgreement` implements no `Clone`, so this does not compile.
/// let _second = pair.clone();
/// ```
pub struct EphemeralAgreement {
    private: PKey<Private>,
    curve: Nid,
    public_point: EphemeralPublicPoint,
}

impl EphemeralAgreement {
    /// Generates the pair of one attempt on the curve of the fleet profile.
    ///
    /// # Errors
    ///
    /// Returns [`KeyAgreementError::Backend`] when the fleet profile has no
    /// software implementation here, when the generator refuses, or when the
    /// point cannot be encoded. Every one of those refuses the attempt: an
    /// attempt whose pair could not be made is not an attempt that may fall
    /// back to some other key.
    pub fn generate(profile: AlgorithmProfile) -> Result<Self, KeyAgreementError> {
        let curve = curve_of(profile).ok_or_else(|| {
            KeyAgreementError::Backend(format!(
                "the device has no key agreement for the `{}` profile",
                profile.as_str()
            ))
        })?;
        let group = EcGroup::from_curve_name(curve)
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
        let key = EcKey::generate(&group)
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
        let mut context =
            BigNumContext::new().map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
        // Uncompressed, because that is what the documents of the channel carry
        // and what the issuing side reads back; a second encoding of one point
        // is a second spelling of one attempt.
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
        let public_point = EphemeralPublicPoint::new(point)
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
        let private = PKey::from_ec_key(key)
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;

        Ok(Self {
            private,
            curve,
            public_point,
        })
    }
}

impl KeyAgreement for EphemeralAgreement {
    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, KeyAgreementError> {
        agree_on_curve(&self.private, self.curve, peer_public)
    }
}

impl EphemeralKeyAgreement for EphemeralAgreement {
    fn public_point(&self) -> &EphemeralPublicPoint {
        &self.public_point
    }
}

impl core::fmt::Debug for EphemeralAgreement {
    /// Names the type and the curve, never the key.
    ///
    /// The value is reachable from a started attempt, and an attempt is a thing
    /// callers log when something goes wrong.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EphemeralAgreement")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

/// Performs the exchange, validating the peer point before anything is derived.
///
/// One body for both agreements: the obligation the contract puts on an
/// implementation is about the check, and a second copy of it is a second place
/// for the check to be missing from.
fn agree_on_curve(
    private: &PKey<Private>,
    curve: Nid,
    peer_public: &[u8],
) -> Result<SharedSecret, KeyAgreementError> {
    let group = EcGroup::from_curve_name(curve)
        .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
    let mut context =
        BigNumContext::new().map_err(|error| KeyAgreementError::Backend(error.to_string()))?;

    // Every failure of the point itself is one answer: the point was
    // rejected. Which malformation it was says nothing a caller needs and
    // something an attacker probing point encodings would like.
    let peer = EcPoint::from_bytes(&group, peer_public, &mut context)
        .and_then(|point| EcKey::from_public_key(&group, &point))
        .map_err(|_| KeyAgreementError::InvalidPublicPoint)?;
    peer.check_key()
        .map_err(|_| KeyAgreementError::InvalidPublicPoint)?;
    let peer = PKey::from_ec_key(peer).map_err(|_| KeyAgreementError::InvalidPublicPoint)?;

    let mut deriver =
        Deriver::new(private).map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
    deriver
        .set_peer(&peer)
        .map_err(|_| KeyAgreementError::InvalidPublicPoint)?;
    let secret = deriver
        .derive_to_vec()
        .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;

    SharedSecret::new(secret).map_err(|error| KeyAgreementError::Backend(error.to_string()))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
pub(crate) mod tests {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};

    use tessera_codes_contract::key::{
        EphemeralKeyAgreement as _, KeyAgreement, KeyAgreementError,
    };
    use tessera_codes_contract::profile::AlgorithmProfile;

    use super::{EphemeralAgreement, StaticKeyAgreement};

    /// Generates a P-256 key pair and returns the private key and the
    /// uncompressed encoding of the public point.
    pub(crate) fn p256_pair() -> (PKey<Private>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut context = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut context)
            .unwrap();
        (PKey::from_ec_key(key).unwrap(), point)
    }

    #[test]
    fn both_sides_arrive_at_the_same_secret() {
        let (device, device_point) = p256_pair();
        let (operator, operator_point) = p256_pair();

        let from_device = StaticKeyAgreement::new(&device, AlgorithmProfile::P256)
            .unwrap()
            .agree(&operator_point)
            .unwrap();
        let from_operator = StaticKeyAgreement::new(&operator, AlgorithmProfile::P256)
            .unwrap()
            .agree(&device_point)
            .unwrap();
        assert!(from_device.ct_eq(&from_operator));
    }

    #[test]
    fn a_point_that_is_not_on_the_curve_is_refused() {
        let (device, _) = p256_pair();
        let agreement = StaticKeyAgreement::new(&device, AlgorithmProfile::P256).unwrap();

        // An uncompressed point whose coordinates satisfy nothing.
        let mut bogus = vec![0x04];
        bogus.extend_from_slice(&[0x01; 64]);
        assert!(matches!(
            agreement.agree(&bogus),
            Err(KeyAgreementError::InvalidPublicPoint)
        ));

        // The point at infinity, which no key agreement may accept.
        assert!(matches!(
            agreement.agree(&[0x00]),
            Err(KeyAgreementError::InvalidPublicPoint)
        ));

        // Not a point encoding at all.
        assert!(matches!(
            agreement.agree(&[0x04, 0x11, 0x22]),
            Err(KeyAgreementError::InvalidPublicPoint)
        ));
    }

    #[test]
    fn a_profile_without_a_device_implementation_is_refused() {
        let (device, _) = p256_pair();
        assert!(matches!(
            StaticKeyAgreement::new(&device, AlgorithmProfile::X25519),
            Err(KeyAgreementError::Backend(_))
        ));
        assert!(matches!(
            StaticKeyAgreement::new(&device, AlgorithmProfile::GostVko34102012),
            Err(KeyAgreementError::Backend(_))
        ));
    }

    #[test]
    fn an_ephemeral_pair_meets_the_other_side_on_the_same_secret() {
        let (peer, peer_point) = p256_pair();
        let attempt = EphemeralAgreement::generate(AlgorithmProfile::P256).unwrap();

        let from_device = attempt.agree(&peer_point).unwrap();
        let from_peer = StaticKeyAgreement::new(&peer, AlgorithmProfile::P256)
            .unwrap()
            .agree(attempt.public_point().as_bytes())
            .unwrap();
        assert!(from_device.ct_eq(&from_peer));
    }

    #[test]
    fn every_attempt_gets_its_own_pair() {
        // The property the whole derivation now rests on: two attempts against
        // one peer must not arrive at one secret, or a code captured once would
        // fit the next attempt too.
        let (_peer, peer_point) = p256_pair();
        let first = EphemeralAgreement::generate(AlgorithmProfile::P256).unwrap();
        let second = EphemeralAgreement::generate(AlgorithmProfile::P256).unwrap();

        assert_ne!(
            first.public_point().as_bytes(),
            second.public_point().as_bytes()
        );
        assert!(!first
            .agree(&peer_point)
            .unwrap()
            .ct_eq(&second.agree(&peer_point).unwrap()));
    }

    #[test]
    fn an_ephemeral_pair_validates_the_peer_point_too() {
        let attempt = EphemeralAgreement::generate(AlgorithmProfile::P256).unwrap();
        let mut bogus = vec![0x04];
        bogus.extend_from_slice(&[0x01; 64]);
        assert!(matches!(
            attempt.agree(&bogus),
            Err(KeyAgreementError::InvalidPublicPoint)
        ));
        assert!(matches!(
            attempt.agree(&[0x00]),
            Err(KeyAgreementError::InvalidPublicPoint)
        ));
    }

    #[test]
    fn an_ephemeral_pair_is_refused_on_a_profile_without_an_implementation() {
        assert!(matches!(
            EphemeralAgreement::generate(AlgorithmProfile::X25519),
            Err(KeyAgreementError::Backend(_))
        ));
        assert!(matches!(
            EphemeralAgreement::generate(AlgorithmProfile::GostVko34102012),
            Err(KeyAgreementError::Backend(_))
        ));
    }

    #[test]
    fn the_debug_form_of_a_pair_carries_no_key() {
        let attempt = EphemeralAgreement::generate(AlgorithmProfile::P256).unwrap();
        let shown = format!("{attempt:?}");
        assert!(shown.starts_with("EphemeralAgreement"), "{shown}");
        assert!(!shown.contains("private"), "{shown}");
    }

    #[test]
    fn a_device_key_of_the_wrong_shape_is_refused() {
        let rsa = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        assert!(matches!(
            StaticKeyAgreement::new(&rsa, AlgorithmProfile::P256),
            Err(KeyAgreementError::Backend(_))
        ));

        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let other_curve = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        assert!(matches!(
            StaticKeyAgreement::new(&other_curve, AlgorithmProfile::P256),
            Err(KeyAgreementError::Backend(_))
        ));
    }
}

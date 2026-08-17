//! The device side of the key agreement.
//!
//! The contract computes no Diffie-Hellman: the shared secret arrives from
//! whatever performs the exchange, which on the operator's side is a token
//! behind an agent and on the device is this module — the software
//! implementation OpenSSL already provides, on the curve the fleet profile
//! names.
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
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};

use tessera_codes_contract::key::{KeyAgreement, KeyAgreementError, SharedSecret};
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

/// The device key performing the exchange for one attempt.
pub struct DeviceKeyAgreement<'a> {
    private: &'a PKey<Private>,
    curve: Nid,
}

impl<'a> DeviceKeyAgreement<'a> {
    /// Binds a device private key to the profile of the fleet.
    ///
    /// # Errors
    ///
    /// Returns [`KeyAgreementError::Backend`] when the fleet profile has no
    /// software implementation here, or when the key is not a key of that
    /// profile. Both are configuration failures of the device rather than
    /// anything about the operator, and both refuse the attempt.
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

impl KeyAgreement for DeviceKeyAgreement<'_> {
    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, KeyAgreementError> {
        let group = EcGroup::from_curve_name(self.curve)
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

        let mut deriver = Deriver::new(self.private)
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;
        deriver
            .set_peer(&peer)
            .map_err(|_| KeyAgreementError::InvalidPublicPoint)?;
        let secret = deriver
            .derive_to_vec()
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))?;

        SharedSecret::new(secret).map_err(|error| KeyAgreementError::Backend(error.to_string()))
    }
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

    use tessera_codes_contract::key::{KeyAgreement, KeyAgreementError};
    use tessera_codes_contract::profile::AlgorithmProfile;

    use super::DeviceKeyAgreement;

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

        let from_device = DeviceKeyAgreement::new(&device, AlgorithmProfile::P256)
            .unwrap()
            .agree(&operator_point)
            .unwrap();
        let from_operator = DeviceKeyAgreement::new(&operator, AlgorithmProfile::P256)
            .unwrap()
            .agree(&device_point)
            .unwrap();
        assert!(from_device.ct_eq(&from_operator));
    }

    #[test]
    fn a_point_that_is_not_on_the_curve_is_refused() {
        let (device, _) = p256_pair();
        let agreement = DeviceKeyAgreement::new(&device, AlgorithmProfile::P256).unwrap();

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
            DeviceKeyAgreement::new(&device, AlgorithmProfile::X25519),
            Err(KeyAgreementError::Backend(_))
        ));
        assert!(matches!(
            DeviceKeyAgreement::new(&device, AlgorithmProfile::GostVko34102012),
            Err(KeyAgreementError::Backend(_))
        ));
    }

    #[test]
    fn a_device_key_of_the_wrong_shape_is_refused() {
        let rsa = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        assert!(matches!(
            DeviceKeyAgreement::new(&rsa, AlgorithmProfile::P256),
            Err(KeyAgreementError::Backend(_))
        ));

        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let other_curve = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        assert!(matches!(
            DeviceKeyAgreement::new(&other_curve, AlgorithmProfile::P256),
            Err(KeyAgreementError::Backend(_))
        ));
    }
}

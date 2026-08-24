//! The operator half of the key agreement.
//!
//! The contract computes no Diffie-Hellman: what it takes is `Z`, and where `Z`
//! comes from is the consumer's business. On the operator side it comes from
//! one of two places — a PKCS#11 token holding the operator key
//! ([`crate::codes::token`]) or, in the explicitly enabled software mode, a key
//! file on the operator's own machine (this module).
//!
//! Which of the two it was is not a detail of the tooling: a code produced with
//! a key that never left a token and a code produced with a key file on a disk
//! are different assurances, and after the fact nothing distinguishes them
//! except what was written down. [`OperatorKey::storage`] is what gets written
//! into the receipt annex.
//!
//! # The obligation the trait carries
//!
//! [`KeyAgreement`] requires the peer point to be validated *before* `Z` is
//! computed — on the curve, in the prime-order subgroup, not the identity. Here
//! the peer is the device public key out of the record, and
//! `p256::PublicKey::from_sec1_bytes` performs exactly that validation (P-256
//! has cofactor one, so subgroup membership follows from curve membership). An
//! implementation that skipped it would leak the operator key through codes
//! nobody could tell from correct ones.

use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::DecodePrivateKey as _;
use tessera_codes_contract::key::{KeyAgreement, KeyAgreementError, SharedSecret};
use tessera_codes_contract::profile::AlgorithmProfile;

use crate::codes::annex::KeyStorage;

/// The operator key of one call: it agrees the secret and says how it is held.
///
/// The public half is here because the ticket carries it too, and the two have
/// to be the same key — see [`crate::codes::issue`]. Deriving with a key the
/// ticket does not name produces a secret the device never arrives at, and the
/// operator spends the call looking for the reason at the device.
pub trait OperatorKey: KeyAgreement {
    /// The public half, in the SEC1 encoding the documents of the channel use.
    fn public_point(&self) -> Vec<u8>;

    /// How the private half is held.
    fn storage(&self) -> KeyStorage;
}

/// An operator key held in a file on the operator's own machine.
///
/// Software mode is never a default and never a fallback: a caller builds this
/// only where the operator asked for it, and the receipt records that they did.
#[derive(Clone)]
pub struct SoftwareOperatorKey {
    secret: p256::SecretKey,
}

impl SoftwareOperatorKey {
    /// Reads a PKCS#11-free operator key from PKCS#8 DER.
    ///
    /// # Errors
    ///
    /// Returns [`KeyAgreementError::Backend`] when the fleet profile is one this
    /// build cannot compute in software, and when the bytes are not a P-256
    /// private key.
    pub fn from_pkcs8_der(
        der: &[u8],
        profile: AlgorithmProfile,
    ) -> Result<Self, KeyAgreementError> {
        require_p256(profile)?;
        let secret = p256::SecretKey::from_pkcs8_der(der).map_err(|_| {
            KeyAgreementError::Backend(
                "the operator key file does not hold a PKCS#8 P-256 private key".to_owned(),
            )
        })?;
        Ok(Self { secret })
    }
}

impl core::fmt::Debug for SoftwareOperatorKey {
    /// Names the type and nothing of the key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SoftwareOperatorKey(redacted)")
    }
}

impl KeyAgreement for SoftwareOperatorKey {
    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, KeyAgreementError> {
        // Every malformation of the point is one answer: the point was
        // rejected. Which one it was says nothing the operator needs and
        // something an attacker probing point encodings would like.
        let peer = p256::PublicKey::from_sec1_bytes(peer_public)
            .map_err(|_| KeyAgreementError::InvalidPublicPoint)?;
        let secret = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        SharedSecret::new(secret.raw_secret_bytes().to_vec())
            .map_err(|error| KeyAgreementError::Backend(error.to_string()))
    }
}

impl OperatorKey for SoftwareOperatorKey {
    fn public_point(&self) -> Vec<u8> {
        self.secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn storage(&self) -> KeyStorage {
        KeyStorage::Software
    }
}

/// Refuses a fleet profile this build cannot compute.
///
/// The refusal is loud rather than a silent fall back to another curve: two
/// sides that agree keys on different curves do not fail, they simply never
/// meet on a code, and the call ends with nobody knowing why.
pub(crate) fn require_p256(profile: AlgorithmProfile) -> Result<(), KeyAgreementError> {
    match profile {
        AlgorithmProfile::P256 => Ok(()),
        AlgorithmProfile::X25519 | AlgorithmProfile::GostVko34102012 => {
            Err(KeyAgreementError::Backend(format!(
                "this build agrees keys on p256 only; the fleet runs the `{}` profile",
                profile.as_str()
            )))
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{KeyAgreement as _, OperatorKey as _, SoftwareOperatorKey};
    use crate::codes::annex::KeyStorage;
    use crate::codes::tests::fixtures;
    use tessera_codes_contract::key::KeyAgreementError;
    use tessera_codes_contract::profile::AlgorithmProfile;

    #[test]
    fn both_sides_arrive_at_the_same_secret() {
        let operator = fixtures::software_key(fixtures::OPERATOR_SEED);
        let device = fixtures::software_key(fixtures::DEVICE_SEED);

        let from_operator = operator.agree(&device.public_point()).unwrap();
        let from_device = device.agree(&operator.public_point()).unwrap();
        assert!(from_operator.ct_eq(&from_device));
    }

    #[test]
    fn a_point_that_is_not_on_the_curve_is_refused_before_anything_is_computed() {
        let operator = fixtures::software_key(fixtures::OPERATOR_SEED);
        assert_eq!(
            operator.agree(&[0x04; 65]).map(|_| ()),
            Err(KeyAgreementError::InvalidPublicPoint)
        );
        assert_eq!(
            operator.agree(&[]).map(|_| ()),
            Err(KeyAgreementError::InvalidPublicPoint)
        );
    }

    #[test]
    fn a_software_key_says_so() {
        let operator = fixtures::software_key(fixtures::OPERATOR_SEED);
        assert_eq!(operator.storage(), KeyStorage::Software);
    }

    #[test]
    fn a_profile_this_build_cannot_compute_is_refused_rather_than_substituted() {
        let der = fixtures::pkcs8_of(fixtures::OPERATOR_SEED);
        for profile in [AlgorithmProfile::X25519, AlgorithmProfile::GostVko34102012] {
            let refusal = SoftwareOperatorKey::from_pkcs8_der(&der, profile)
                .map(|_| ())
                .unwrap_err();
            assert!(matches!(refusal, KeyAgreementError::Backend(_)));
        }
    }

    #[test]
    fn bytes_that_are_not_a_key_are_refused() {
        assert!(matches!(
            SoftwareOperatorKey::from_pkcs8_der(b"not a key", AlgorithmProfile::P256).map(|_| ()),
            Err(KeyAgreementError::Backend(_))
        ));
    }
}

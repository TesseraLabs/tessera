//! Attesting the chain head with a key file held by the device.
//!
//! # Why a key of its own, and not the Codes key
//!
//! The device already holds a key pair for the telephone channel, and reusing it
//! would have saved a provisioning step. It is the wrong key on three counts,
//! and the design note of this change records the same reasoning:
//!
//! - It is an agreement key, not a signing key. The Codes key is used for
//!   Diffie-Hellman; signing with the same key pair is the reuse across
//!   primitives that cryptographic practice has warned about for decades, and
//!   the warning is not theoretical for an ECDH key asked to produce ECDSA
//!   signatures.
//! - It rotates for reasons that have nothing to do with the journal. The Codes
//!   epoch advances whenever the fleet re-keys the channel, and old epochs are
//!   deliberately not honoured afterwards — that is the anti-rollback rule.
//!   Attestations made under a retired epoch would become unverifiable, so
//!   re-keying the phone channel would silently invalidate the device's audit
//!   history.
//! - What it proves is the wrong thing. The shared key of the channel is derived
//!   with material the operator's own side holds, so a signature under it says
//!   "one of the two parties" — and the operator is exactly the party the
//!   journal is meant to be evidence against.
//!
//! So the attestation key is separate: one key pair, used for nothing else,
//! whose public half travels to the fleet at enrolment.
//!
//! # What this signer is, and is not
//!
//! It is the simplest binding that can be checked end to end: a private key in a
//! PEM file that only root can read. A device with a token puts the key there
//! instead and supplies its own [`HeadSigner`] — nothing above this module knows
//! the difference.

use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer;

use super::journal::HeadSigner;

/// The label recorded beside a signature made by an EC key.
pub const ALGORITHM_ECDSA_SHA256: &str = "ecdsa-sha256";

/// The label recorded beside a signature made by an Ed25519 key.
pub const ALGORITHM_ED25519: &str = "ed25519";

/// A head signer backed by a private key in a PEM file.
#[derive(Debug)]
pub struct KeyFileSigner {
    key: PKey<Private>,
    algorithm: &'static str,
}

impl KeyFileSigner {
    /// Loads the attestation key from `path`.
    ///
    /// # Errors
    ///
    /// A message describing why the key could not be read or is of a kind this
    /// signer does not produce signatures with. Both are refusals: a device that
    /// cannot attest says so rather than recording an attestation nobody can
    /// check.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let pem = std::fs::read(path).map_err(|error| {
            format!(
                "the attestation key at {} is unreadable: {error}",
                path.display()
            )
        })?;
        let key = PKey::private_key_from_pem(&pem).map_err(|error| {
            format!(
                "the attestation key at {} is not a PEM private key: {error}",
                path.display()
            )
        })?;
        let algorithm = match key.id() {
            Id::EC => ALGORITHM_ECDSA_SHA256,
            Id::ED25519 => ALGORITHM_ED25519,
            other => {
                return Err(format!(
                "the attestation key at {} is of a kind this build does not sign with ({other:?})",
                path.display()
            ))
            }
        };
        Ok(Self { key, algorithm })
    }
}

impl HeadSigner for KeyFileSigner {
    fn algorithm(&self) -> &str {
        self.algorithm
    }

    fn sign(&self, head: &[u8; 32]) -> Result<Vec<u8>, String> {
        let mut signer = if self.algorithm == ALGORITHM_ED25519 {
            Signer::new_without_digest(&self.key)
        } else {
            Signer::new(MessageDigest::sha256(), &self.key)
        }
        .map_err(|error| format!("the attestation key could not be prepared: {error}"))?;

        if self.algorithm == ALGORITHM_ED25519 {
            signer
                .sign_oneshot_to_vec(head)
                .map_err(|error| format!("the chain head could not be signed: {error}"))
        } else {
            signer
                .update(head)
                .and_then(|()| signer.sign_to_vec())
                .map_err(|error| format!("the chain head could not be signed: {error}"))
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{KeyFileSigner, ALGORITHM_ECDSA_SHA256};
    use crate::audit::journal::HeadSigner as _;

    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;

    fn write_p256_key(path: &std::path::Path) -> PKey<openssl::pkey::Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(ec).unwrap();
        std::fs::write(path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        key
    }

    #[test]
    fn a_head_signed_by_the_key_file_verifies_against_its_public_half() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attestation.pem");
        let key = write_p256_key(&path);

        let signer = KeyFileSigner::load(&path).unwrap();
        assert_eq!(signer.algorithm(), ALGORITHM_ECDSA_SHA256);

        let head = [7u8; 32];
        let signature = signer.sign(&head).unwrap();

        let public = PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();
        let mut verifier =
            openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public).unwrap();
        verifier.update(&head).unwrap();
        assert!(verifier.verify(&signature).unwrap());

        // A different head does not verify — the signature covers the head and
        // nothing else.
        let mut verifier =
            openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public).unwrap();
        verifier.update(&[8u8; 32]).unwrap();
        assert!(!verifier.verify(&signature).unwrap());
    }

    #[test]
    fn a_missing_or_unusable_key_is_a_refusal_rather_than_an_unsigned_head() {
        let dir = tempfile::tempdir().unwrap();
        assert!(KeyFileSigner::load(&dir.path().join("absent.pem")).is_err());

        let junk = dir.path().join("junk.pem");
        std::fs::write(&junk, b"not a key").unwrap();
        assert!(KeyFileSigner::load(&junk).is_err());
    }
}

//! The trust anchors the operator side verifies documents against.
//!
//! The contract crate holds no anchors and performs no public-key arithmetic:
//! it knows which bytes were signed and which signer a document names, and asks
//! a [`SignatureVerifier`] supplied here whether that signer is trusted. This
//! module is that answer for the operator side — the authority that issues
//! operator tickets, and the organisations that sign device records.
//!
//! Two properties are worth stating, because both are easy to lose:
//!
//! - **A named signer is resolved, never assumed.** An organisation the anchors
//!   do not carry is [`SignatureError::UnknownSigner`], not a signature check
//!   against a key the document brought along. A record that vouches for its own
//!   organisation is a record signed by whoever wrote it.
//! - **The proof of possession is checked against the key the record carries**,
//!   which is the only thing it can be checked against and proves exactly one
//!   thing: whoever assembled the record holds the private half of the device
//!   key. That the key is trusted is the other signature's job.
//!
//! # Digest
//!
//! Every signature is verified over SHA-256 of the message, on both curves. The
//! device verifies the same documents with OpenSSL over SHA-256 regardless of
//! the curve, so a P-384 anchor verified here over SHA-384 would accept
//! documents the fleet cannot, and refuse documents the fleet accepts.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};
use tessera_codes_contract::signature::{
    PublicKey, Signature, SignatureError, SignatureVerifier, SignerRef,
};

/// Length of an uncompressed SEC1 point on P-256, in bytes.
const P256_UNCOMPRESSED_LEN: usize = 65;

/// Length of a compressed SEC1 point on P-256, in bytes.
const P256_COMPRESSED_LEN: usize = 33;

/// A public key the operator side anchors on.
///
/// Only the two NIST curves of the fleet profiles are here. Ed25519 and the
/// ГОСТ profiles are verified by libraries this crate does not carry (it builds
/// for `wasm32-unknown-unknown`), and a fleet on one of them anchors its
/// operator tooling elsewhere rather than having this module quietly accept
/// nothing.
#[derive(Debug, Clone)]
pub enum AnchorKey {
    /// An ECDSA key on NIST P-256.
    P256(Box<p256::ecdsa::VerifyingKey>),
    /// An ECDSA key on NIST P-384.
    P384(Box<p384::ecdsa::VerifyingKey>),
}

impl AnchorKey {
    /// Reads an anchor from a `SubjectPublicKeyInfo` in DER.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::Unusable`] when the bytes are not a
    /// `SubjectPublicKeyInfo` of a curve this module verifies.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, AnchorError> {
        use p256::pkcs8::DecodePublicKey as _;

        if let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(der) {
            return Ok(Self::P256(Box::new(key)));
        }
        if let Ok(key) = p384::ecdsa::VerifyingKey::from_public_key_der(der) {
            return Ok(Self::P384(Box::new(key)));
        }
        Err(AnchorError::Unusable)
    }

    /// Reads a key from a SEC1 point, as the documents of the channel carry it.
    ///
    /// The curve is taken from the length of the point: the two curves have no
    /// encoding in common, so nothing is guessed.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::Unusable`] when the point is not on a curve this
    /// module verifies, or is not a point at all.
    pub fn from_sec1_point(point: &[u8]) -> Result<Self, AnchorError> {
        let on_p256 = matches!(point.len(), P256_UNCOMPRESSED_LEN | P256_COMPRESSED_LEN);
        if on_p256 {
            return p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map(|key| Self::P256(Box::new(key)))
                .map_err(|_| AnchorError::Unusable);
        }
        p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
            .map(|key| Self::P384(Box::new(key)))
            .map_err(|_| AnchorError::Unusable)
    }

    /// Verifies a signature over `message`.
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier as _;

        let digest = Sha256::digest(message);
        match self {
            Self::P256(key) => {
                let signature = p256::ecdsa::Signature::from_der(signature.as_bytes())
                    .map_err(|_| SignatureError::Rejected)?;
                key.verify_prehash(&digest, &signature)
                    .map_err(|_| SignatureError::Rejected)
            }
            Self::P384(key) => {
                let signature = p384::ecdsa::Signature::from_der(signature.as_bytes())
                    .map_err(|_| SignatureError::Rejected)?;
                key.verify_prehash(&digest, &signature)
                    .map_err(|_| SignatureError::Rejected)
            }
        }
    }
}

/// Rejection of an anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorError {
    /// The material is not a public key on a curve this module verifies.
    #[error("the anchor is not an ECDSA public key on P-256 or P-384")]
    Unusable,
}

/// The anchors of one fleet, as the operator side holds them.
#[derive(Debug, Clone)]
pub struct Anchors {
    ticket_authority: AnchorKey,
    organisations: BTreeMap<String, AnchorKey>,
}

impl Anchors {
    /// Builds the anchors around the authority that issues operator tickets.
    ///
    /// The authority is required and single: a ticket is signed by the authority
    /// of the fleet or it is not a ticket.
    #[must_use]
    pub fn new(ticket_authority: AnchorKey) -> Self {
        Self {
            ticket_authority,
            organisations: BTreeMap::new(),
        }
    }

    /// Anchors an organisation that signs device records.
    #[must_use]
    pub fn with_organisation(mut self, organisation_id: &str, key: AnchorKey) -> Self {
        self.organisations.insert(organisation_id.to_owned(), key);
        self
    }

    /// Reports whether an organisation is anchored.
    #[must_use]
    pub fn knows_organisation(&self, organisation_id: &str) -> bool {
        self.organisations.contains_key(organisation_id)
    }
}

impl SignatureVerifier for Anchors {
    /// Verifies a signature the document attributes to `signer`.
    fn verify(
        &self,
        signer: SignerRef<'_>,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        match signer {
            SignerRef::TicketAuthority => self.ticket_authority.verify(message, signature),
            SignerRef::Named(organisation) => self
                .organisations
                .get(organisation)
                .ok_or(SignatureError::UnknownSigner)?
                .verify(message, signature),
            // A key the document carries answers one question — does the holder
            // of the private half stand behind these bytes — and the record's
            // proof of possession is that question. Whether the key is trusted
            // is the organisation signature, checked separately.
            SignerRef::Key(key) => key_of(key)?.verify(message, signature),
        }
    }
}

/// Reads a key a document carries.
fn key_of(key: &PublicKey) -> Result<AnchorKey, SignatureError> {
    AnchorKey::from_sec1_point(key.as_bytes()).map_err(|_| SignatureError::Rejected)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{AnchorError, AnchorKey, Anchors};
    use crate::codes::tests::fixtures;
    use tessera_codes_contract::signature::{
        PublicKey, Signature, SignatureError, SignatureVerifier as _, SignerRef,
    };

    #[test]
    fn a_spki_of_an_unknown_shape_is_refused() {
        assert_eq!(
            AnchorKey::from_spki_der(&[0x30, 0x00]).map(|_| ()),
            Err(AnchorError::Unusable)
        );
    }

    #[test]
    fn a_point_that_is_not_on_a_curve_is_refused() {
        assert_eq!(
            AnchorKey::from_sec1_point(&[0x04; 65]).map(|_| ()),
            Err(AnchorError::Unusable)
        );
    }

    #[test]
    fn the_authority_verifies_what_it_signed_and_nothing_else() {
        let signer = fixtures::signer(fixtures::AUTHORITY_SEED);
        let anchors = Anchors::new(signer.anchor());
        let message = b"a ticket".as_slice();
        let signature = signer.sign(message);

        assert_eq!(
            anchors.verify(SignerRef::TicketAuthority, message, &signature),
            Ok(())
        );
        assert_eq!(
            anchors.verify(SignerRef::TicketAuthority, b"another ticket", &signature),
            Err(SignatureError::Rejected)
        );
    }

    #[test]
    fn an_organisation_the_anchors_do_not_carry_is_unknown() {
        let authority = fixtures::signer(fixtures::AUTHORITY_SEED);
        let organisation = fixtures::signer(fixtures::ORGANISATION_SEED);
        let anchors = Anchors::new(authority.anchor());
        let message = b"a record".as_slice();

        assert!(!anchors.knows_organisation("acme"));
        assert_eq!(
            anchors.verify(
                SignerRef::Named("acme"),
                message,
                &organisation.sign(message)
            ),
            Err(SignatureError::UnknownSigner)
        );

        let anchors = anchors.with_organisation("acme", organisation.anchor());
        assert!(anchors.knows_organisation("acme"));
        assert_eq!(
            anchors.verify(
                SignerRef::Named("acme"),
                message,
                &organisation.sign(message)
            ),
            Ok(())
        );
    }

    #[test]
    fn a_key_the_document_carries_verifies_only_its_own_signature() {
        let device = fixtures::signer(fixtures::DEVICE_SEED);
        let anchors = Anchors::new(fixtures::signer(fixtures::AUTHORITY_SEED).anchor());
        let key = PublicKey::new(device.public_point()).unwrap();
        let message = b"a proof of possession".as_slice();

        assert_eq!(
            anchors.verify(SignerRef::Key(&key), message, &device.sign(message)),
            Ok(())
        );
        let foreign = fixtures::signer(fixtures::ORGANISATION_SEED).sign(message);
        assert_eq!(
            anchors.verify(SignerRef::Key(&key), message, &foreign),
            Err(SignatureError::Rejected)
        );
    }

    #[test]
    fn a_signature_that_is_not_der_is_refused_rather_than_panicking() {
        let anchors = Anchors::new(fixtures::signer(fixtures::AUTHORITY_SEED).anchor());
        let signature = Signature::new(vec![0xff; 8]).unwrap();
        assert_eq!(
            anchors.verify(SignerRef::TicketAuthority, b"x", &signature),
            Err(SignatureError::Rejected)
        );
    }
}

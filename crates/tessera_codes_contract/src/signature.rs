//! Signatures of the documents, verified outside the contract.
//!
//! The crate holds no trust anchors and performs no public-key arithmetic. It
//! knows only which bytes were signed and which signer the document names; a
//! verifier supplied by the consumer decides whether that signer is trusted and
//! whether the signature holds.
//!
//! That split is deliberate. A trust anchor is an operational decision of a
//! fleet — which organisation, which certificate, which revocation state — and
//! a contract crate that answered it would be answering it for every fleet at
//! once, in a build that also has to run inside a browser tab.

/// A public key, in the encoding of the algorithm profile of the fleet.
///
/// The contract treats the bytes as opaque: it neither parses the point nor
/// checks that it belongs to a curve. The verifier does both, and rejects the
/// key when it cannot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    /// Wraps the raw key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::EmptyMaterial`] for an empty key: a document
    /// carrying no key is not a document a signature can be checked against.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SignatureError> {
        if bytes.is_empty() {
            return Err(SignatureError::EmptyMaterial);
        }
        Ok(Self(bytes))
    }

    /// Returns the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A signature, in the encoding of the algorithm profile of the fleet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wraps the raw signature bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::EmptyMaterial`] for an empty signature.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SignatureError> {
        if bytes.is_empty() {
            return Err(SignatureError::EmptyMaterial);
        }
        Ok(Self(bytes))
    }

    /// Returns the raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Who is supposed to have produced a signature.
///
/// The two cases are not interchangeable, and the type keeps them apart so that
/// a verifier cannot confuse them: a key carried by the document proves only
/// that whoever wrote the document holds the matching private key, while a
/// named signer is resolved against the anchors the verifier trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerRef<'a> {
    /// A key the document carries.
    ///
    /// Usable for a proof of possession and for nothing else: the document
    /// vouches for the key, so the key cannot vouch for the document.
    Key(&'a PublicKey),
    /// A signer the document names — an organisation, say — which the verifier
    /// resolves against its own anchors.
    Named(&'a str),
    /// The authority that issues operator tickets.
    ///
    /// A ticket names no signer: the fleet knows the authority that may issue
    /// them, and the verifier holds its key.
    TicketAuthority,
}

/// Rejection of a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// A key or a signature carries no bytes.
    #[error("the key or signature carries no material")]
    EmptyMaterial,
    /// The signature does not hold over the message.
    #[error("the signature does not hold")]
    Rejected,
    /// The verifier does not know the named signer, or does not trust it.
    #[error("the signer is unknown or not trusted")]
    UnknownSigner,
    /// The verifier could not run for its own reason.
    #[error("signature verification backend failed: {0}")]
    Backend(String),
}

/// Verification of the document signatures, implemented by the consumer.
///
/// # Obligations of the implementation
///
/// The implementation **must** resolve [`SignerRef::Named`] and
/// [`SignerRef::TicketAuthority`] against its own trust anchors and return
/// [`SignatureError::UnknownSigner`] when it cannot — accepting a signature
/// from a key the fleet never anchored is the same as accepting no signature at
/// all. It must verify the signature over exactly the bytes it was given: the
/// canonical encoding is what binds the fields together, and a verifier that
/// re-serialises the document on its own reintroduces the second spelling this
/// contract exists to prevent.
pub trait SignatureVerifier {
    /// Verifies `signature` over `message`, attributed to `signer`.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::Rejected`] when the signature does not hold,
    /// [`SignatureError::UnknownSigner`] when the signer is not anchored, and
    /// [`SignatureError::Backend`] for a failure of the underlying library or
    /// device.
    fn verify(
        &self,
        signer: SignerRef<'_>,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError>;
}

#[cfg(test)]
mod tests {
    use super::{PublicKey, Signature, SignatureError};

    #[test]
    fn empty_material_is_refused() {
        assert_eq!(
            PublicKey::new(Vec::new()),
            Err(SignatureError::EmptyMaterial)
        );
        assert_eq!(
            Signature::new(Vec::new()),
            Err(SignatureError::EmptyMaterial)
        );
    }

    #[test]
    fn material_is_carried_verbatim() {
        assert_eq!(
            PublicKey::new(vec![4, 1, 2]).map(|key| key.as_bytes().to_vec()),
            Ok(vec![4, 1, 2])
        );
        assert_eq!(
            Signature::new(vec![9]).map(|sig| sig.as_bytes().to_vec()),
            Ok(vec![9])
        );
    }
}

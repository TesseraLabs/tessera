//! Trust verification types.

use crate::error::TrustError;

/// Opaque DER certificate bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate(Vec<u8>);

impl Certificate {
    /// Create a certificate wrapper.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Return DER bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Verified chain.
#[derive(Debug, Clone)]
pub struct VerifiedChain {
    /// Leaf certificate.
    pub leaf: Certificate,
    /// Intermediate chain.
    pub chain: Vec<Certificate>,
}

impl VerifiedChain {
    /// Leaf accessor.
    pub fn leaf(&self) -> &Certificate {
        &self.leaf
    }
}

/// Host id hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostIdHash([u8; 32]);

impl HostIdHash {
    /// Create hash wrapper.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Trust verifier.
pub trait TrustVerifier: Send + Sync {
    /// Verify a certificate chain.
    fn verify(
        &self,
        leaf: &Certificate,
        intermediates: &[Certificate],
        host_id: &HostIdHash,
    ) -> Result<VerifiedChain, TrustError>;
}

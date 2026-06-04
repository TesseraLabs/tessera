//! Stage 1 trust verifier stub.

use crate::error::TrustError;
use crate::trust::{Certificate, HostIdHash, TrustVerifier, VerifiedChain};

/// Stub trust verifier.
pub struct StubVerifier;

impl TrustVerifier for StubVerifier {
    fn verify(
        &self,
        _leaf: &Certificate,
        _intermediates: &[Certificate],
        _host_id: &HostIdHash,
    ) -> Result<VerifiedChain, TrustError> {
        Err(TrustError::NotImplemented)
    }
}

//! Cryptographic verification of every link in a built certificate chain.
//! See `T05` in the stage-2 plan.

use super::{Certificate, TrustError};

/// Verifies that each child in the chain was signed by its parent's public
/// key, and that the final element (the anchor) is self-signed.
///
/// `chain` must be ordered leaf-first, anchor-last — i.e. the layout produced
/// by [`super::chain::build_chain`].
///
/// # Errors
///
/// * [`TrustError::PathBuild`] when the chain is shorter than 2 elements.
/// * [`TrustError::BadSignature`] (with the failing link's index) when a
///   child does not verify under its parent's key, or when the anchor's
///   self-signature is invalid.
/// * [`TrustError::Openssl`] for unexpected libcrypto failures.
pub fn verify_chain_signatures(chain: &[Certificate]) -> Result<(), TrustError> {
    if chain.len() < 2 {
        return Err(TrustError::PathBuild("chain too short"));
    }

    for (depth, pair) in chain.windows(2).enumerate() {
        let child = &pair[0];
        let parent = &pair[1];
        let pk = parent.public_key()?;
        let ok = child.x509().verify(&pk).map_err(TrustError::Openssl)?;
        if !ok {
            return Err(TrustError::BadSignature(depth));
        }
    }

    // Anchor must self-verify.
    let last_idx = chain.len() - 1;
    let Some(anchor) = chain.last() else {
        return Err(TrustError::PathBuild("internal: empty chain"));
    };
    let pk = anchor.public_key()?;
    if !anchor.x509().verify(&pk).map_err(TrustError::Openssl)? {
        return Err(TrustError::BadSignature(last_idx));
    }

    Ok(())
}

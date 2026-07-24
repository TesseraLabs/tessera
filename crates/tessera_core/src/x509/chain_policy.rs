//! Per-link policy enforcement over a fully built certificate chain.
//!
//! The crate does manual path validation: it verifies each link's signature
//! ([`super::signatures`]) and each link's `basicConstraints`
//! ([`super::basic_constraints`]), but it never invokes OpenSSL's
//! `X509_verify_cert`.  Several RFC 5280 path-validation rules that a caller
//! might assume "just happen" therefore have to be applied explicitly here,
//! for **every** certificate rather than only the leaf:
//!
//! * **Public-key strength.** Every certificate — leaf, every intermediate,
//!   and the anchor — must carry a key that meets [`super::key_strength`].  A
//!   weak key anywhere in the path undermines the whole chain.
//!
//! * **Signature-algorithm allow-listing.** Every *non-anchor* certificate's
//!   signature algorithm must be in the configured allow-list.  Verifying an
//!   intermediate's signature cryptographically is not enough: a SHA-1- or
//!   MD5-signed intermediate must be refused even when it chains to a
//!   configured root.  The anchor is excluded because trust in it is its
//!   configured public key (SPKI), not its self-signature.
//!
//! * **Extended-key-usage intersection.** RFC 5280 §4.2.1.12 makes an EKU on
//!   a CA constrain the purposes of the certificates beneath it.  The client
//!   -authentication purpose must survive the intersection of every issuing
//!   CA's EKU; an intermediate scoped to `serverAuth` only breaks engineer
//!   authentication and is refused.  A trust anchor's EKU is not processed
//!   (RFC 5280 treats anchors as unconstrained), and the leaf's own
//!   `clientAuth` requirement is enforced in [`super::pre_validate`].
//!
//! The chain is ordered leaf-first, anchor-last (the layout produced by
//! [`super::chain::build_chain`]).

use super::{Certificate, TrustError};

/// Dotted OID of the `id-kp-clientAuth` extended key usage (1.3.6.1.5.5.7.3.2).
const OID_EKU_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
/// Dotted OID of `anyExtendedKeyUsage` (2.5.29.37.0), which asserts no EKU
/// restriction and therefore always keeps `clientAuth` in the intersection.
const OID_EKU_ANY: &str = "2.5.29.37.0";

/// Inputs to [`enforce_chain_policy`] that vary per verifier configuration.
#[derive(Debug, Clone, Copy)]
pub struct ChainPolicy<'a> {
    /// Acceptable signature-algorithm display forms, matched for exact
    /// equality against each non-anchor certificate's signature algorithm.
    ///
    /// An empty slice means "no constraint", matching the semantics of
    /// [`super::pre_validate::PreValidateConfig::signature_alg_whitelist`].
    pub signature_alg_whitelist: &'a [String],
}

/// Enforces public-key strength, signature-algorithm allow-listing, and the
/// EKU intersection across the whole built `chain`.
///
/// See the [module documentation](self) for the exact rule applied to each
/// chain position.
///
/// # Errors
///
/// * [`TrustError::PathBuild`] when `chain` has fewer than two elements.
/// * [`TrustError::WeakKey`] when any certificate's public key is below the
///   minimum strength.
/// * [`TrustError::SignatureAlgorithm`] when a non-anchor certificate's
///   signature algorithm is not in the allow-list.
/// * [`TrustError::EkuChainViolation`] when an issuing CA's EKU excludes the
///   client-authentication purpose.
/// * [`TrustError::Openssl`] / [`TrustError::CertParse`] (propagated) when a
///   key or extension cannot be read.
pub fn enforce_chain_policy(
    chain: &[Certificate],
    policy: &ChainPolicy<'_>,
) -> Result<(), TrustError> {
    if chain.len() < 2 {
        return Err(TrustError::PathBuild("chain too short"));
    }
    // The anchor is the last element; every earlier element is a non-anchor.
    let anchor_idx = chain.len() - 1;

    for (idx, cert) in chain.iter().enumerate() {
        // Public-key strength applies to every position, anchor included: a
        // weak anchor key is as fatal as a weak leaf key.
        validate_key_strength(cert)?;

        let is_anchor = idx == anchor_idx;
        if !is_anchor {
            // Signature-algorithm allow-listing over every non-anchor link.
            check_signature_algorithm(cert, policy.signature_alg_whitelist)?;
        }

        // EKU intersection is contributed by the issuing CAs — the
        // intermediates strictly between the leaf and the anchor.  Position 0
        // is the leaf (its clientAuth is checked in pre-validation) and the
        // anchor is unconstrained per RFC 5280.
        let is_intermediate = idx > 0 && !is_anchor;
        if is_intermediate {
            check_eku_permits_client_auth(cert)?;
        }
    }
    Ok(())
}

/// Rejects a certificate whose public key is below the minimum strength.
fn validate_key_strength(cert: &Certificate) -> Result<(), TrustError> {
    let pk = cert.public_key()?;
    super::key_strength::validate_public_key_strength(&pk)
}

/// Rejects a certificate whose signature algorithm is outside the allow-list.
///
/// An empty allow-list imposes no constraint, matching leaf pre-validation.
fn check_signature_algorithm(cert: &Certificate, whitelist: &[String]) -> Result<(), TrustError> {
    let sig_alg = cert.signature_algorithm();
    if !whitelist.is_empty() && !whitelist.iter().any(|w| w == &sig_alg) {
        return Err(TrustError::SignatureAlgorithm(sig_alg));
    }
    Ok(())
}

/// Rejects an issuing CA whose `extendedKeyUsage` excludes `clientAuth`.
///
/// A CA with no EKU extension imposes no restriction (RFC 5280 default), so
/// the client-authentication purpose survives.  A CA that *does* carry an EKU
/// must list either `clientAuth` or `anyExtendedKeyUsage`, or the leaf below
/// it can no longer be used for engineer authentication.
fn check_eku_permits_client_auth(cert: &Certificate) -> Result<(), TrustError> {
    let ekus = cert.eku_oids()?;
    if ekus.is_empty() {
        return Ok(());
    }
    let permits_client_auth = ekus
        .iter()
        .any(|oid| oid == OID_EKU_CLIENT_AUTH || oid == OID_EKU_ANY);
    if permits_client_auth {
        Ok(())
    } else {
        Err(TrustError::EkuChainViolation(
            "issuing CA EKU excludes clientAuth",
        ))
    }
}

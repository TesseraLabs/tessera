//! Cheap leaf-certificate pre-validation that runs before any chain building
//! or signature verification.  See `T03` in the stage-2 plan.

use super::{Certificate, TrustError};
use std::time::{Duration, SystemTime};

/// Configuration consumed by [`pre_validate_end_entity`].
///
/// Constructed by the caller from validated configuration; pre-validation
/// itself does not parse strings.
#[derive(Debug, Clone)]
pub struct PreValidateConfig {
    /// How much skew to tolerate when comparing the certificate validity
    /// window against `now`.
    pub clock_skew: Duration,

    /// Acceptable signature-algorithm names.  Each entry is matched
    /// **exactly** (case-sensitive equality) against the certificate's
    /// signature-algorithm display form as rendered by OpenSSL.
    ///
    /// Accepted strings include `sha256WithRSAEncryption`,
    /// `sha384WithRSAEncryption`, `sha512WithRSAEncryption`,
    /// `ecdsa-with-SHA256`, `ecdsa-with-SHA384`, `ecdsa-with-SHA512`,
    /// `id-tc26-signwithdigest-gost3410-12-256`,
    /// `id-tc26-signwithdigest-gost3410-12-512`.
    ///
    /// **An empty whitelist is interpreted as "no constraint": every
    /// signature algorithm is accepted.**  Operators that want to deny
    /// every certificate must instead ensure the chain rejects unknown
    /// algorithms upstream — pre-validate is not the right gate for that.
    pub signature_alg_whitelist: Vec<String>,
}

/// Validates a leaf certificate's intrinsic properties.
///
/// This is the first gate during authentication: it rejects obviously
/// unsuitable certificates without spending CPU on chain building.
///
/// The checks are, in order:
///
/// 1. The certificate is X.509 v3 (per RFC 5280, all extensions require v3).
/// 2. The validity window (with `clock_skew` tolerance) covers `now`.
/// 3. The signature algorithm is in the whitelist.
/// 4. The subject public key meets the minimum strength policy
///    ([`crate::x509::key_strength`]) — a strong signature over a weak key is
///    still a weak key.
/// 5. `keyUsage` asserts `digitalSignature`.
/// 6. `extendedKeyUsage` includes `clientAuth`.
/// 7. `basicConstraints` is absent or `cA = FALSE`.
///
/// # Errors
///
/// Returns the relevant [`TrustError`] variant on the first failed check.
pub fn pre_validate_end_entity(
    cert: &Certificate,
    cfg: &PreValidateConfig,
    now: SystemTime,
) -> Result<(), TrustError> {
    // 1. version v3 (raw value 2 == X.509 v3)
    if cert.version() != 2 {
        return Err(TrustError::Validity("not X.509 v3"));
    }

    // 2. validity
    let nb = cert.not_before();
    let na = cert.not_after();
    if now + cfg.clock_skew < nb {
        return Err(TrustError::Validity("not yet valid"));
    }
    if now > na + cfg.clock_skew {
        return Err(TrustError::Validity("expired"));
    }

    // 3. signature algorithm whitelist (P1-A + P1-C):
    //    * empty whitelist == no constraint (matches operator intent of
    //      "I haven't configured this; accept anything sensible");
    //    * non-empty whitelist requires **exact** equality against the
    //      OpenSSL display form, not a substring match (substring matching
    //      let `sha1WithRSAEncryption` slip past a `sha` whitelist entry).
    let sig_alg = cert.signature_algorithm();
    if !cfg.signature_alg_whitelist.is_empty()
        && !cfg.signature_alg_whitelist.iter().any(|w| w == &sig_alg)
    {
        return Err(TrustError::SignatureAlgorithm(sig_alg));
    }

    // 4. Subject public-key strength.  Allow-listing the signature algorithm
    //    bounds how the cert was signed, not the strength of the key it
    //    carries; a 1024-bit RSA leaf signed with SHA-256 must still be
    //    refused before the challenge-response trusts that key.
    let pk = cert.public_key()?;
    crate::x509::key_strength::validate_public_key_strength(&pk)?;

    // 5. KeyUsage = digitalSignature
    if !cert.key_usage_digital_signature()? {
        return Err(TrustError::KeyUsage);
    }

    // 6. EKU = clientAuth
    if !cert.eku_client_auth()? {
        return Err(TrustError::Eku);
    }

    // 7. BasicConstraints absent OR CA=FALSE
    if let Some(bc) = cert.basic_constraints()? {
        if bc.is_ca {
            return Err(TrustError::BasicConstraints("end-entity must not be CA"));
        }
    }

    Ok(())
}

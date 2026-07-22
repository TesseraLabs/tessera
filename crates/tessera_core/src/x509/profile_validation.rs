//! Chain-intrinsic path-validation checks: the `pam_cert_profile_version`
//! version gate and the unknown-critical-extension scan
//! (`trust-chain-validation` delta spec, tasks 4.1 + 2.3, design decision 5).
//!
//! Both checks are evaluated against **every** certificate in the built chain
//! (leaf → anchor) and are fail-closed:
//!
//! * **Version gate (4.1).** A cert whose `pam_cert_profile_version` exceeds
//!   `max_supported_profile_version` rejects the chain. An absent extension is
//!   treated as baseline (version 0). A malformed extension rejects the chain.
//!   This is layer 2 of design decision 5: an old Engine refuses a newer-format
//!   cert rather than interpreting it with stale rules.
//!
//! * **Unknown-critical scan (2.3).** Every extension marked `critical` whose
//!   OID is not in [`KNOWN_CRITICAL_OIDS`] rejects the chain (RFC 5280 §4.2,
//!   the `PwnKit` lesson). This is layer 1 of design decision 5: an old Engine
//!   that does not understand a critical extension MUST NOT silently skip it.
//!
//! The reason these run as an explicit pass rather than relying on
//! `X509_verify_cert` is recorded in task 2.3: the crate's chain verifier does
//! per-link `X509::verify(&pk)` (signature only) and never invokes the OpenSSL
//! path validator, so `X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION` never fires.

use super::oids::{DELEGATION_CONSTRAINTS_OID, PROFILE_VERSION_OID};
use super::profile_version_ext::extract_profile_version;
use super::{Certificate, TrustError, VerifiedX509};

/// OIDs of `critical` extensions this Engine is allowed to encounter.
///
/// The list is deliberately conservative: it contains **only** the standard
/// PKIX criticals that the crate's manual path validation actually
/// *processes*, plus the two project-private extensions defined for this
/// change. A critical extension we parse but do not enforce would be a silent
/// bypass, so it is *not* listed (RFC 5280 §4.2 / `PwnKit` fail-closed).
///
/// Included standard OIDs and where they are handled:
/// * `2.5.29.19` basicConstraints — `x509::basic_constraints` /
///   [`VerifiedX509::is_ca`] (CA-ness and pathLen are enforced).
/// * `2.5.29.15` keyUsage — `x509::ext::key_usage_bit`
///   (`keyCertSign`/`digitalSignature` enforced per chain position).
/// * `2.5.29.37` extendedKeyUsage — `x509::ext::eku_oids` /
///   `Certificate::eku_client_auth` (clientAuth enforced on the leaf) and
///   `x509::chain_policy` (the EKU intersection enforced across issuing CAs, so
///   a critical `serverAuth`-only EKU on an intermediate now fails closed
///   instead of being silently accepted). A trust anchor's EKU is not
///   processed, per RFC 5280.
///
/// Deliberately **excluded** standard criticals (parsed by nobody here, so a
/// critical instance must reject rather than be ignored): nameConstraints
/// `2.5.29.30`, policyConstraints `2.5.29.36`, inhibitAnyPolicy `2.5.29.54`,
/// certificatePolicies `2.5.29.32`. Excluding them is the safe choice — if a
/// cert genuinely needs one of these enforced, the Engine must gain explicit
/// handling (and a profile-version bump) before it is added here.
///
/// Project-private criticals (both defined by this change, both enforced):
/// * [`PROFILE_VERSION_OID`] — the version gate ([`verify_profile_and_criticals`]).
/// * [`DELEGATION_CONSTRAINTS_OID`] — the delegation envelope
///   ([`crate::trust::delegation`]).
const KNOWN_CRITICAL_OIDS: &[&str] = &[
    "2.5.29.19", // basicConstraints
    "2.5.29.15", // keyUsage
    "2.5.29.37", // extendedKeyUsage
    PROFILE_VERSION_OID,
    DELEGATION_CONSTRAINTS_OID,
];

/// Runs the version gate (4.1) and the unknown-critical scan (2.3) over every
/// certificate in `chain` (leaf → anchor ordering, as produced by
/// [`crate::x509::chain::build_chain`]).
///
/// `max_supported_profile_version` is the highest certificate-format version
/// this Engine understands; a cert declaring a higher version rejects the
/// chain. Both passes are fail-closed.
///
/// # Errors
///
/// * [`TrustError::ProfileVersionUnsupported`] — a cert declares a version
///   above `max_supported_profile_version`.
/// * [`TrustError::ProfileVersionMalformed`] — a cert's `profile_version`
///   extension body is malformed.
/// * [`TrustError::UnhandledCriticalExtension`] — a cert carries a critical
///   extension whose OID is not in [`KNOWN_CRITICAL_OIDS`].
/// * [`TrustError::CertParse`] — a cert's DER could not be walked.
pub fn verify_profile_and_criticals(
    chain: &[Certificate],
    max_supported_profile_version: u32,
) -> Result<(), TrustError> {
    for cert in chain {
        // Layer 1 (2.3): reject any unrecognised critical extension first —
        // an unknown critical that *changes* how the version or envelope is to
        // be interpreted must never be silently skipped.
        for oid in cert.critical_extension_oids()? {
            if !KNOWN_CRITICAL_OIDS.contains(&oid.as_str()) {
                return Err(TrustError::UnhandledCriticalExtension(oid));
            }
        }

        // Layer 2 (4.1): version gate.  Extraction needs a `VerifiedX509`
        // wrapper; the chain has already passed signature + constraint
        // verification by the time this runs, so wrapping is sound.
        let verified = VerifiedX509::new(cert.x509().clone());
        let version = match extract_profile_version(&verified) {
            Ok(Some(v)) => v,
            Ok(None) => 0, // absent extension = baseline version
            Err(e) => return Err(TrustError::ProfileVersionMalformed(e.to_string())),
        };
        if version > max_supported_profile_version {
            // Audit the version-gate rejection (tags-delegation §5.1). The
            // serial identifies the offending chain cert; the engineer-facing
            // reason stays generic (a trust rejection), the detail is here.
            crate::trust::delegation_audit::emit_profile_version_rejected(
                &cert.serial_hex().to_lowercase(),
                version,
                max_supported_profile_version,
            );
            return Err(TrustError::ProfileVersionUnsupported {
                found: version,
                max: max_supported_profile_version,
            });
        }
    }
    Ok(())
}

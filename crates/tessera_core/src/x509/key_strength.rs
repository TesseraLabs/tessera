//! Minimum public-key strength policy for certificates in a verified chain.
//!
//! Signature-algorithm allow-listing (see [`super::pre_validate`] and
//! [`super::chain_policy`]) constrains *how* a certificate was signed, but it
//! does not bound the strength of the subject public key the certificate
//! carries.  A leaf that carries a 1024-bit RSA key can still be signed by a
//! strong CA with SHA-256 and would sail past a signature-only gate — yet the
//! challenge-response that proves possession of the corresponding private key
//! is only as sound as that key.
//!
//! This module is the single source of truth for "is this public key strong
//! enough to be trusted", shared by the leaf pre-validation, the per-link
//! chain policy, and the two token selection paths (PKCS#12 in-process and
//! PKCS#11 on-token).

use openssl::nid::Nid;
use openssl::pkey::{Id, PKeyRef, Public};

use super::TrustError;

/// Minimum accepted RSA modulus size, in bits.
///
/// 2048-bit RSA is rated at roughly 112-bit symmetric-equivalent security
/// (NIST SP 800-57), which remains adequate for the near term, whereas
/// 1024-bit RSA is within reach of well-resourced adversaries.  This is a hard
/// floor: exposing it as a configurable knob (with 2048 as the secure default)
/// is deliberately left out of scope here, so the value cannot be lowered
/// below the safe baseline by configuration.
pub const MIN_RSA_KEY_BITS: u32 = 2048;

/// Raw NID of `id-tc26-gost3410-12-256` (GOST R 34.10-2012, 256-bit public
/// key).  Stable across libcrypto versions that ship the `obj_mac.h` table.
const NID_ID_GOST_R3410_2012_256: i32 = 979;
/// Raw NID of `id-tc26-gost3410-12-512` (GOST R 34.10-2012, 512-bit public
/// key).
const NID_ID_GOST_R3410_2012_512: i32 = 980;

/// Validates that `pk` meets the minimum strength policy for its algorithm
/// family.
///
/// The accepted families mirror what the challenge-response and token layers
/// can actually prove possession of:
///
/// * **RSA** — modulus of at least [`MIN_RSA_KEY_BITS`] bits.
/// * **EC** — a named curve restricted to NIST P-256 or P-384.
/// * **GOST R 34.10-2012** — the 256-bit or 512-bit parameter set.
///
/// Any other key type (Ed25519, DSA, EC on an unapproved or unnamed curve, …)
/// is rejected: the authentication path has no supported way to challenge it.
///
/// # Errors
///
/// Returns [`TrustError::WeakKey`] when the key is too small or its algorithm
/// family/curve is not approved, and [`TrustError::Openssl`] if an EC key's
/// group cannot be read.
pub fn validate_public_key_strength(pk: &PKeyRef<Public>) -> Result<(), TrustError> {
    let id = pk.id();
    if id == Id::RSA {
        let bits = pk.bits();
        if bits < MIN_RSA_KEY_BITS {
            return Err(TrustError::WeakKey(format!(
                "RSA key is {bits} bits, minimum is {MIN_RSA_KEY_BITS}"
            )));
        }
        return Ok(());
    }
    if id == Id::EC {
        let ec = pk.ec_key().map_err(TrustError::Openssl)?;
        let curve = ec
            .group()
            .curve_name()
            .ok_or_else(|| TrustError::WeakKey("EC key without a named curve".to_string()))?;
        return match curve {
            Nid::X9_62_PRIME256V1 | Nid::SECP384R1 => Ok(()),
            other => Err(TrustError::WeakKey(format!(
                "EC curve nid {} is not an approved curve (P-256/P-384)",
                other.as_raw()
            ))),
        };
    }
    let raw = id.as_raw();
    if raw == NID_ID_GOST_R3410_2012_256 || raw == NID_ID_GOST_R3410_2012_512 {
        return Ok(());
    }
    Err(TrustError::WeakKey(format!(
        "unsupported public-key algorithm (nid {raw})"
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    fn rsa_public(bits: u32) -> PKey<Public> {
        let rsa = Rsa::generate(bits).unwrap();
        let der = rsa.public_key_to_der().unwrap();
        PKey::public_key_from_der(&der).unwrap()
    }

    fn ec_public(curve: Nid) -> PKey<Public> {
        let group = EcGroup::from_curve_name(curve).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let der = key.public_key_to_der().unwrap();
        PKey::public_key_from_der(&der).unwrap()
    }

    #[test]
    fn accepts_2048_bit_rsa() {
        validate_public_key_strength(&rsa_public(2048)).unwrap();
    }

    #[test]
    fn rejects_1024_bit_rsa() {
        let err = validate_public_key_strength(&rsa_public(1024)).unwrap_err();
        assert!(matches!(err, TrustError::WeakKey(_)), "{err:?}");
    }

    #[test]
    fn accepts_p256_and_p384() {
        validate_public_key_strength(&ec_public(Nid::X9_62_PRIME256V1)).unwrap();
        validate_public_key_strength(&ec_public(Nid::SECP384R1)).unwrap();
    }

    #[test]
    fn rejects_p521() {
        let err = validate_public_key_strength(&ec_public(Nid::SECP521R1)).unwrap_err();
        assert!(matches!(err, TrustError::WeakKey(_)), "{err:?}");
    }
}

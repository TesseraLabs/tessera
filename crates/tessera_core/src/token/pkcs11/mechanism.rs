//! Mechanism selection for token-side signing (Task T11).
//!
//! Given a `(KeyType, PublicKey)` pair, [`select_mechanism`] returns a
//! [`TokenSignMechanism`] describing **how** the challenge-response in
//! T12 must talk to the token:
//!
//! - For RSA/ECDSA we hand the **raw nonce** to the hashing mechanism
//!   (e.g. `Sha256RsaPkcsPss`, `EcdsaSha256`); the token does the digest
//!   and the signing in one shot.  Verification on the host then uses
//!   the matching `MessageDigest` directly with `Verifier::verify`.
//! - For GOST 2012-256/512 the standard PKCS#11 mechanism (`CKM_GOSTR3410`)
//!   expects a **pre-hashed** input, so we mark the variant `PreHashed`
//!   and the caller hashes on the host with Streebog before
//!   `session.sign`.
//!
//! ## OPEN QUESTION (cryptoki ≤ 0.7)
//!
//! cryptoki 0.7's [`cryptoki::mechanism::Mechanism`] enum does **not**
//! include any GOST signing variant — neither `CKM_GOSTR3410` nor any
//! 2012-prefixed extension.  The version of the spec it tracks
//! (PKCS#11 v2.40) carries them only as numeric constants in the
//! vendor-extension range and the upstream Rust crate does not expose
//! a `Custom`/`Raw` escape hatch.  Until cryptoki gains a variant, we
//! return [`Pkcs11Error::MechanismNotSupported`] for GOST keys.

use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::KeyType;
use cryptoki::types::Ulong;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKeyRef, Public};

use super::error::Pkcs11Error;

/// Number of bytes of salt to use with RSA-PSS — fixed at 32 to match
/// the in-process challenge-response (`crate::challenge::rsa_pss`).
const RSA_PSS_SALT_LEN: u64 = 32;

/// How the host should drive the token's signing operation.
///
/// `RawSign` — the mechanism includes message hashing.  Caller passes
/// the nonce verbatim to `session.sign` and verifies on the host with
/// the matching `MessageDigest`.
///
/// `PreHashed` — the mechanism expects an already-hashed input.  Caller
/// hashes the nonce on the host (`host_hash`), feeds the digest to
/// `session.sign`, and verifies on the host with the same `host_hash`.
///
/// `Debug` is implemented manually because [`MessageDigest`] does not
/// implement `Debug` upstream.
#[non_exhaustive]
pub enum TokenSignMechanism {
    /// Mechanism handles hashing internally; signs raw nonce.  Host
    /// `Verifier` uses `host_hash` to redo the hashing locally.
    RawSign {
        /// Mechanism passed to `session.sign`.  `'static` because all
        /// mechanism variants we use here own their parameters by value.
        mechanism: Mechanism<'static>,
        /// Hash algorithm used by the host-side `Verifier`.
        host_hash: MessageDigest,
    },
    /// Mechanism expects pre-hashed input (e.g. PKCS#11 GOST).
    PreHashed {
        /// Mechanism passed to `session.sign`.
        mechanism: Mechanism<'static>,
        /// Hash algorithm used both to pre-hash the nonce on the host and
        /// to drive the host-side `Verifier`.
        host_hash: MessageDigest,
    },
}

impl std::fmt::Debug for TokenSignMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawSign { mechanism, .. } => f
                .debug_struct("RawSign")
                .field("mechanism", mechanism)
                .field("host_hash", &"<MessageDigest>")
                .finish(),
            Self::PreHashed { mechanism, .. } => f
                .debug_struct("PreHashed")
                .field("mechanism", mechanism)
                .field("host_hash", &"<MessageDigest>")
                .finish(),
        }
    }
}

impl TokenSignMechanism {
    /// Borrow the inner [`Mechanism`] to pass to `session.sign`.
    #[must_use]
    pub fn mechanism(&self) -> &Mechanism<'static> {
        match self {
            Self::RawSign { mechanism, .. } | Self::PreHashed { mechanism, .. } => mechanism,
        }
    }

    /// The host-side [`MessageDigest`] used by the verifier.
    #[must_use]
    pub fn host_hash(&self) -> MessageDigest {
        match self {
            Self::RawSign { host_hash, .. } | Self::PreHashed { host_hash, .. } => *host_hash,
        }
    }

    /// Whether the host must pre-hash the nonce before calling
    /// `session.sign` (true) or pass the raw nonce (false).
    #[must_use]
    pub fn requires_host_pre_hash(&self) -> bool {
        matches!(self, Self::PreHashed { .. })
    }
}

/// Pick the token signing mechanism for `(key_type, pubkey)`.
///
/// # Errors
///
/// - [`Pkcs11Error::UnsupportedKeyType`] — key type outside the supported
///   matrix (currently `RSA`, `EC` on P-256/P-384, `GOSTR3410`).
/// - [`Pkcs11Error::MechanismNotSupported`] — the key type is in the
///   matrix but the binding crate exposes no matching mechanism (today
///   true for GOST under cryptoki 0.7).
pub fn select_mechanism(
    key_type: KeyType,
    pubkey: &PKeyRef<Public>,
) -> Result<TokenSignMechanism, Pkcs11Error> {
    if key_type == KeyType::RSA {
        return Ok(TokenSignMechanism::RawSign {
            mechanism: Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: Ulong::from(RSA_PSS_SALT_LEN),
            }),
            host_hash: MessageDigest::sha256(),
        });
    }
    if key_type == KeyType::EC {
        let ec = pubkey.ec_key().map_err(Pkcs11Error::Openssl)?;
        let curve = ec
            .group()
            .curve_name()
            .ok_or(Pkcs11Error::UnsupportedKeyType {
                key_type: "EC w/o named curve".into(),
            })?;
        let (mechanism, host_hash) = match curve {
            Nid::X9_62_PRIME256V1 => (Mechanism::EcdsaSha256, MessageDigest::sha256()),
            Nid::SECP384R1 => (Mechanism::EcdsaSha384, MessageDigest::sha384()),
            other => {
                return Err(Pkcs11Error::UnsupportedKeyType {
                    key_type: format!("EC curve nid {}", other.as_raw()),
                })
            }
        };
        return Ok(TokenSignMechanism::RawSign {
            mechanism,
            host_hash,
        });
    }
    if key_type == KeyType::GOSTR3410 {
        // cryptoki 0.7 does not expose CKM_GOSTR3410{,_2012_*}; surface a
        // typed error so the caller can fall through to the existing
        // openssl-engine path or return PAM_AUTHINFO_UNAVAIL.
        return Err(Pkcs11Error::MechanismNotSupported {
            mechanism: "CKM_GOSTR3410 (cryptoki 0.7 has no enum variant)".into(),
        });
    }
    Err(Pkcs11Error::UnsupportedKeyType {
        key_type: format!("{key_type}"),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::err_expect,
        clippy::panic,
        clippy::unwrap_used
    )]

    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    fn rsa_pubkey() -> PKey<Public> {
        let priv_pkey = Rsa::generate(2048).expect("rsa gen");
        let der = priv_pkey.public_key_to_der().expect("rsa pub der");
        PKey::public_key_from_der(&der).expect("pkey")
    }

    fn ec_pubkey(curve: Nid) -> PKey<Public> {
        let group = EcGroup::from_curve_name(curve).expect("group");
        let priv_pkey = EcKey::generate(&group).expect("ec gen");
        let der = priv_pkey.public_key_to_der().expect("ec pub der");
        PKey::public_key_from_der(&der).expect("pkey")
    }

    /// `MessageDigest` doesn't implement `PartialEq`/`Debug`; compare via
    /// the underlying NID, which is stable.
    fn digest_nid(m: MessageDigest) -> Nid {
        m.type_()
    }

    #[test]
    fn rsa_yields_pss_sha256_raw_sign() {
        let pk = rsa_pubkey();
        let m = select_mechanism(KeyType::RSA, &pk).expect("ok");
        assert!(matches!(m, TokenSignMechanism::RawSign { .. }));
        assert_eq!(
            digest_nid(m.host_hash()),
            digest_nid(MessageDigest::sha256())
        );
        assert!(!m.requires_host_pre_hash());
        // Mechanism shape: RSA-PSS hashed by token.
        assert!(matches!(m.mechanism(), Mechanism::Sha256RsaPkcsPss(_)));
    }

    #[test]
    fn ec_p256_yields_ecdsa_sha256() {
        let pk = ec_pubkey(Nid::X9_62_PRIME256V1);
        let m = select_mechanism(KeyType::EC, &pk).expect("ok");
        assert!(matches!(m, TokenSignMechanism::RawSign { .. }));
        assert_eq!(
            digest_nid(m.host_hash()),
            digest_nid(MessageDigest::sha256())
        );
        assert!(matches!(m.mechanism(), Mechanism::EcdsaSha256));
    }

    #[test]
    fn ec_p384_yields_ecdsa_sha384() {
        let pk = ec_pubkey(Nid::SECP384R1);
        let m = select_mechanism(KeyType::EC, &pk).expect("ok");
        assert_eq!(
            digest_nid(m.host_hash()),
            digest_nid(MessageDigest::sha384())
        );
        assert!(matches!(m.mechanism(), Mechanism::EcdsaSha384));
    }

    #[test]
    fn ec_p521_is_unsupported() {
        let pk = ec_pubkey(Nid::SECP521R1);
        let err = select_mechanism(KeyType::EC, &pk).err().expect("must fail");
        assert!(matches!(err, Pkcs11Error::UnsupportedKeyType { .. }));
    }

    #[test]
    fn gost_returns_mechanism_not_supported() {
        // pubkey value irrelevant — short-circuit before pubkey is read.
        let pk = rsa_pubkey();
        let err = select_mechanism(KeyType::GOSTR3410, &pk)
            .err()
            .expect("must fail");
        assert!(
            matches!(err, Pkcs11Error::MechanismNotSupported { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn aes_keytype_is_unsupported() {
        let pk = rsa_pubkey();
        let err = select_mechanism(KeyType::AES, &pk)
            .err()
            .expect("must fail");
        assert!(matches!(err, Pkcs11Error::UnsupportedKeyType { .. }));
    }
}

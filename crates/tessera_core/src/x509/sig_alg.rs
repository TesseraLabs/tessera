//! Signature-algorithm classification and OID helpers.
//!
//! Used by config-time whitelisting (`allowed_signature_algorithms`) and
//! by the trust verifier to decide whether the gost-engine must be loaded
//! before the chain is verified.
//!
//! The mapping is intentionally narrow: only the algorithms Tessera
//! actually accepts in the field appear as named variants.  Everything else
//! falls into [`SignatureAlg::Other`] with the original string preserved.
//!
//! Both dotted-OID strings (e.g. `"1.2.840.113549.1.1.11"`) and the human
//! aliases used in the config (e.g. `"rsa-with-sha256"`,
//! `"id-tc26-signwithdigest-gost3410-2012-256"`) are accepted by
//! [`SignatureAlg::from_oid_string`].

/// Classified signature algorithm.
///
/// `Other(String)` keeps the original token so error messages can refer
/// back to the configured value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureAlg {
    /// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
    RsaWithSha256,
    /// `sha384WithRSAEncryption` (1.2.840.113549.1.1.12).
    RsaWithSha384,
    /// `sha512WithRSAEncryption` (1.2.840.113549.1.1.13).
    RsaWithSha512,
    /// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
    EcdsaWithSha256,
    /// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3).
    EcdsaWithSha384,
    /// `ecdsa-with-SHA512` (1.2.840.10045.4.3.4).
    EcdsaWithSha512,
    /// `id-tc26-signwithdigest-gost3410-2012-256` (1.2.643.7.1.1.3.2).
    IdTc26SignWithDigestGostR341012_256,
    /// `id-tc26-signwithdigest-gost3410-2012-512` (1.2.643.7.1.1.3.3).
    IdTc26SignWithDigestGostR341012_512,
    /// Anything else — preserves the original token.
    Other(String),
}

impl SignatureAlg {
    /// Parses an OID string or human alias into a [`SignatureAlg`].
    ///
    /// Unknown inputs are returned as [`SignatureAlg::Other`] verbatim;
    /// this function never fails.
    #[must_use]
    pub fn from_oid_string(s: &str) -> Self {
        match s {
            "1.2.840.113549.1.1.11" | "rsa-with-sha256" | "sha256WithRSAEncryption" => {
                Self::RsaWithSha256
            }
            "1.2.840.113549.1.1.12" | "rsa-with-sha384" | "sha384WithRSAEncryption" => {
                Self::RsaWithSha384
            }
            "1.2.840.113549.1.1.13" | "rsa-with-sha512" | "sha512WithRSAEncryption" => {
                Self::RsaWithSha512
            }
            "1.2.840.10045.4.3.2" | "ecdsa-with-sha256" | "ecdsa-with-SHA256" => {
                Self::EcdsaWithSha256
            }
            "1.2.840.10045.4.3.3" | "ecdsa-with-sha384" | "ecdsa-with-SHA384" => {
                Self::EcdsaWithSha384
            }
            "1.2.840.10045.4.3.4" | "ecdsa-with-sha512" | "ecdsa-with-SHA512" => {
                Self::EcdsaWithSha512
            }
            "1.2.643.7.1.1.3.2" | "id-tc26-signwithdigest-gost3410-2012-256" => {
                Self::IdTc26SignWithDigestGostR341012_256
            }
            "1.2.643.7.1.1.3.3" | "id-tc26-signwithdigest-gost3410-2012-512" => {
                Self::IdTc26SignWithDigestGostR341012_512
            }
            other => Self::Other(other.to_string()),
        }
    }

    /// Returns the canonical dotted OID for known variants.
    ///
    /// For [`SignatureAlg::Other`] returns the stored token, which may or
    /// may not be a dotted OID.
    #[must_use]
    pub fn oid(&self) -> &str {
        match self {
            Self::RsaWithSha256 => "1.2.840.113549.1.1.11",
            Self::RsaWithSha384 => "1.2.840.113549.1.1.12",
            Self::RsaWithSha512 => "1.2.840.113549.1.1.13",
            Self::EcdsaWithSha256 => "1.2.840.10045.4.3.2",
            Self::EcdsaWithSha384 => "1.2.840.10045.4.3.3",
            Self::EcdsaWithSha512 => "1.2.840.10045.4.3.4",
            Self::IdTc26SignWithDigestGostR341012_256 => "1.2.643.7.1.1.3.2",
            Self::IdTc26SignWithDigestGostR341012_512 => "1.2.643.7.1.1.3.3",
            Self::Other(s) => s,
        }
    }

    /// Returns `true` for GOST R 34.10-2012 signature algorithms (any digest).
    ///
    /// The two TC26 OIDs (`1.2.643.7.1.1.3.2` for Streebog-256 and
    /// `1.2.643.7.1.1.3.3` for Streebog-512) require gost-engine to verify.
    #[must_use]
    pub const fn is_gost(&self) -> bool {
        matches!(
            self,
            Self::IdTc26SignWithDigestGostR341012_256 | Self::IdTc26SignWithDigestGostR341012_512
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SignatureAlg;

    #[test]
    fn from_oid_string_parses_gost_oids() {
        assert_eq!(
            SignatureAlg::from_oid_string("1.2.643.7.1.1.3.2"),
            SignatureAlg::IdTc26SignWithDigestGostR341012_256
        );
        assert_eq!(
            SignatureAlg::from_oid_string("1.2.643.7.1.1.3.3"),
            SignatureAlg::IdTc26SignWithDigestGostR341012_512
        );
    }

    #[test]
    fn from_oid_string_parses_gost_aliases() {
        assert_eq!(
            SignatureAlg::from_oid_string("id-tc26-signwithdigest-gost3410-2012-256"),
            SignatureAlg::IdTc26SignWithDigestGostR341012_256
        );
        assert_eq!(
            SignatureAlg::from_oid_string("id-tc26-signwithdigest-gost3410-2012-512"),
            SignatureAlg::IdTc26SignWithDigestGostR341012_512
        );
    }

    #[test]
    fn from_oid_string_parses_rsa_oids() {
        assert_eq!(
            SignatureAlg::from_oid_string("1.2.840.113549.1.1.11"),
            SignatureAlg::RsaWithSha256
        );
        assert_eq!(
            SignatureAlg::from_oid_string("rsa-with-sha384"),
            SignatureAlg::RsaWithSha384
        );
        assert_eq!(
            SignatureAlg::from_oid_string("sha512WithRSAEncryption"),
            SignatureAlg::RsaWithSha512
        );
    }

    #[test]
    fn from_oid_string_parses_ecdsa_oids() {
        assert_eq!(
            SignatureAlg::from_oid_string("1.2.840.10045.4.3.2"),
            SignatureAlg::EcdsaWithSha256
        );
        assert_eq!(
            SignatureAlg::from_oid_string("ecdsa-with-SHA384"),
            SignatureAlg::EcdsaWithSha384
        );
        assert_eq!(
            SignatureAlg::from_oid_string("ecdsa-with-sha512"),
            SignatureAlg::EcdsaWithSha512
        );
    }

    #[test]
    fn from_oid_string_falls_back_to_other() {
        let alg = SignatureAlg::from_oid_string("1.2.3.4.5");
        assert_eq!(alg, SignatureAlg::Other("1.2.3.4.5".to_string()));
    }

    #[test]
    fn is_gost_returns_true_for_gost_variants() {
        assert!(SignatureAlg::IdTc26SignWithDigestGostR341012_256.is_gost());
        assert!(SignatureAlg::IdTc26SignWithDigestGostR341012_512.is_gost());
    }

    #[test]
    fn is_gost_returns_false_for_rsa_variants() {
        assert!(!SignatureAlg::RsaWithSha256.is_gost());
        assert!(!SignatureAlg::RsaWithSha384.is_gost());
        assert!(!SignatureAlg::RsaWithSha512.is_gost());
    }

    #[test]
    fn is_gost_returns_false_for_ecdsa_variants() {
        assert!(!SignatureAlg::EcdsaWithSha256.is_gost());
        assert!(!SignatureAlg::EcdsaWithSha384.is_gost());
        assert!(!SignatureAlg::EcdsaWithSha512.is_gost());
    }

    #[test]
    fn is_gost_returns_false_for_other() {
        assert!(!SignatureAlg::Other("1.2.3.4".to_string()).is_gost());
    }

    #[test]
    fn oid_round_trips() {
        for variant in [
            SignatureAlg::RsaWithSha256,
            SignatureAlg::RsaWithSha384,
            SignatureAlg::RsaWithSha512,
            SignatureAlg::EcdsaWithSha256,
            SignatureAlg::EcdsaWithSha384,
            SignatureAlg::EcdsaWithSha512,
            SignatureAlg::IdTc26SignWithDigestGostR341012_256,
            SignatureAlg::IdTc26SignWithDigestGostR341012_512,
        ] {
            assert_eq!(SignatureAlg::from_oid_string(variant.oid()), variant);
        }
    }
}

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
//! aliases used in the config are accepted by
//! [`SignatureAlg::from_oid_string`].  The aliases are:
//!
//! * RSA — `"sha256WithRSAEncryption"`, `"sha384WithRSAEncryption"`,
//!   `"sha512WithRSAEncryption"` and the `"rsa-with-sha256"` family;
//! * ECDSA — `"ecdsa-with-SHA256"`, `"ecdsa-with-SHA384"`,
//!   `"ecdsa-with-SHA512"` (either case in the digest name);
//! * GOST R 34.10-2012 — `"id-tc26-signwithdigest-gost3410-2012-256"` and
//!   `"…-2012-512"`, each also accepted with the year written `-12-`.
//!
//! Allow-list matching therefore runs through [`whitelist_permits`] and
//! compares parsed values, never raw strings: the certificate side always
//! yields a dotted OID while the config side is whatever spelling the
//! operator chose.

/// Placeholder produced instead of a dotted OID when a certificate's
/// signature-algorithm OID cannot be decoded at all.
///
/// Kept distinct from any real OID so that [`whitelist_permits`] can refuse
/// it outright: an algorithm we failed to identify must never be accepted,
/// not even if a configuration happens to contain this same token.
pub const UNKNOWN_SIGNATURE_ALGORITHM: &str = "unknown-signature-algorithm";

/// Returns `true` if a certificate's signature-algorithm `oid` is permitted
/// by `whitelist`.
///
/// `oid` is the dotted form read from the certificate; `whitelist` entries
/// are configuration tokens, which may be dotted OIDs or the human aliases
/// listed in the module documentation.  Both sides are parsed into
/// [`SignatureAlg`] before comparison, so a config written as
/// `sha256WithRSAEncryption` still matches a certificate carrying
/// `1.2.840.113549.1.1.11`.
///
/// An algorithm outside the known table matches only a whitelist entry
/// spelled character-for-character the same way, and
/// [`UNKNOWN_SIGNATURE_ALGORITHM`] matches nothing at all.
///
/// An empty `whitelist` is *not* handled here — callers treat it as "no
/// constraint" before reaching this function.
#[must_use]
pub fn whitelist_permits(oid: &str, whitelist: &[String]) -> bool {
    if oid == UNKNOWN_SIGNATURE_ALGORITHM {
        return false;
    }
    let alg = SignatureAlg::from_oid_string(oid);
    whitelist
        .iter()
        .any(|entry| SignatureAlg::from_oid_string(entry) == alg)
}

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
            // Both spellings of the year are accepted: `-2012-` is TC26's own
            // and the one OpenSSL prints, `-12-` is what this product's
            // documentation has told operators to write since the key existed.
            "1.2.643.7.1.1.3.2"
            | "id-tc26-signwithdigest-gost3410-2012-256"
            | "id-tc26-signwithdigest-gost3410-12-256" => Self::IdTc26SignWithDigestGostR341012_256,
            "1.2.643.7.1.1.3.3"
            | "id-tc26-signwithdigest-gost3410-2012-512"
            | "id-tc26-signwithdigest-gost3410-12-512" => Self::IdTc26SignWithDigestGostR341012_512,
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
    use super::{whitelist_permits, SignatureAlg, UNKNOWN_SIGNATURE_ALGORITHM};

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn whitelist_permits_matches_alias_against_dotted_oid() {
        let whitelist = list(&["sha256WithRSAEncryption", "ecdsa-with-SHA256"]);
        assert!(whitelist_permits("1.2.840.113549.1.1.11", &whitelist));
        assert!(whitelist_permits("1.2.840.10045.4.3.2", &whitelist));
    }

    #[test]
    fn whitelist_permits_matches_gost_alias_against_dotted_oid() {
        let whitelist = list(&["id-tc26-signwithdigest-gost3410-2012-256"]);
        assert!(whitelist_permits("1.2.643.7.1.1.3.2", &whitelist));
        assert!(!whitelist_permits("1.2.643.7.1.1.3.3", &whitelist));
    }

    #[test]
    fn whitelist_permits_matches_dotted_oid_against_dotted_oid() {
        let whitelist = list(&["1.2.840.113549.1.1.11"]);
        assert!(whitelist_permits("1.2.840.113549.1.1.11", &whitelist));
        assert!(!whitelist_permits("1.2.840.113549.1.1.5", &whitelist));
    }

    #[test]
    fn whitelist_permits_matches_unknown_algorithms_only_verbatim() {
        let whitelist = list(&["1.2.3.4.5"]);
        assert!(whitelist_permits("1.2.3.4.5", &whitelist));
        assert!(!whitelist_permits("1.2.3.4.6", &whitelist));
    }

    #[test]
    fn whitelist_permits_rejects_substring_entries() {
        let whitelist = list(&["sha"]);
        assert!(!whitelist_permits("1.2.840.113549.1.1.11", &whitelist));
    }

    #[test]
    fn whitelist_permits_never_accepts_the_unknown_placeholder() {
        let whitelist = list(&[UNKNOWN_SIGNATURE_ALGORITHM, "sha256WithRSAEncryption"]);
        assert!(!whitelist_permits(UNKNOWN_SIGNATURE_ALGORITHM, &whitelist));
    }

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
    fn from_oid_string_parses_both_gost_year_spellings() {
        // `-12-` is what docs/{ru,en}/configuration.md tells operators to
        // write; a config copied from there must classify as GOST, or the
        // "gost_engine_path is required" check never fires for it.
        for (short, long) in [
            (
                "id-tc26-signwithdigest-gost3410-12-256",
                "id-tc26-signwithdigest-gost3410-2012-256",
            ),
            (
                "id-tc26-signwithdigest-gost3410-12-512",
                "id-tc26-signwithdigest-gost3410-2012-512",
            ),
        ] {
            assert_eq!(
                SignatureAlg::from_oid_string(short),
                SignatureAlg::from_oid_string(long),
                "{short} must name the same algorithm as {long}",
            );
            assert!(SignatureAlg::from_oid_string(short).is_gost());
        }
    }

    #[test]
    fn whitelist_permits_matches_short_year_gost_alias_against_dotted_oid() {
        let whitelist = list(&["id-tc26-signwithdigest-gost3410-12-512"]);
        assert!(whitelist_permits("1.2.643.7.1.1.3.3", &whitelist));
        assert!(!whitelist_permits("1.2.643.7.1.1.3.2", &whitelist));
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

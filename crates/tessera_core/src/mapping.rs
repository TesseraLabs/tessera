//! Match an end-entity certificate against a configured `[[user_mapping]]`
//! list and a target PAM user.
//!
//! The existing [`crate::config::ValidatedConfig::user_mappings`] is reused
//! verbatim; this module does not introduce a new mapping type so we don't
//! have two competing schemas in flight.

use crate::config::validated::{UserMapping, UserMatchCriteria};
use crate::x509::{Certificate, TrustError};
use thiserror::Error;

/// Reason a [`UserMapping`] matched.
///
/// Useful for log lines and downstream auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchReason {
    /// Mapping matched on `cert_subject_cn`.
    CnExact,
    /// Mapping matched on a SAN `email` entry.
    SanEmail,
    /// Mapping matched on a SAN `userPrincipalName` entry.
    SanUpn,
}

/// A successful match against a [`UserMapping`].
#[derive(Debug, Clone)]
pub struct MatchedMapping {
    /// PAM user name from the matched mapping.
    pub pam_user: String,
    /// Which criterion fired.
    pub matched_by: MatchReason,
}

/// Errors raised during mapping lookup.
#[derive(Debug, Error)]
pub enum MappingError {
    /// No mapping records the given PAM user.
    #[error("no [[user_mapping]] entry exists for pam_user={0:?}")]
    NoMappingForUser(String),

    /// Mapping list contained an entry without any match criteria.
    /// This should not normally happen because [`crate::config::ValidatedConfig`]
    /// enforces exactly-one-criterion, but we surface it explicitly for
    /// callers that build mappings programmatically.
    #[error("mapping for pam_user={0:?} has no match criteria")]
    EmptyMapping(String),

    /// At least one mapping for `pam_user` exists, but none of them matched
    /// the certificate.
    #[error(
        "subject mismatch for pam_user={pam_user:?}: \
         expected_cn={expected_cn:?} found_cn={found_cn:?} \
         expected_email={expected_email:?} found_emails={found_emails:?}"
    )]
    SubjectMismatch {
        /// PAM user being matched.
        pam_user: String,
        /// CN we wanted, if any.
        expected_cn: Option<String>,
        /// CN actually present in the cert, if any.
        found_cn: Option<String>,
        /// SAN email we wanted, if any.
        expected_email: Option<String>,
        /// SAN emails actually present in the cert.
        found_emails: Vec<String>,
    },

    /// Underlying certificate field error (CN extraction failed for a
    /// reason other than absence).
    #[error("certificate field error: {0}")]
    Cert(#[from] TrustError),
}

/// Match `end_entity` against the subset of `mappings` for `pam_user`.
///
/// The first mapping whose criterion matches the cert wins.
///
/// # Errors
///
/// See [`MappingError`].
pub fn match_user(
    end_entity: &Certificate,
    pam_user: &str,
    mappings: &[UserMapping],
) -> Result<MatchedMapping, MappingError> {
    let cn = end_entity.subject_cn().ok();
    let sans = end_entity.san_emails();

    // Restrict to mappings for this PAM user.
    let candidates: Vec<&UserMapping> =
        mappings.iter().filter(|m| m.pam_user == pam_user).collect();
    if candidates.is_empty() {
        return Err(MappingError::NoMappingForUser(pam_user.to_string()));
    }

    let mut expected_cn: Option<String> = None;
    let mut expected_email: Option<String> = None;

    for m in &candidates {
        match &m.criteria {
            UserMatchCriteria::SubjectCn(want) => {
                expected_cn.get_or_insert_with(|| want.clone());
                if cn.as_deref() == Some(want.as_str()) {
                    return Ok(MatchedMapping {
                        pam_user: m.pam_user.clone(),
                        matched_by: MatchReason::CnExact,
                    });
                }
            }
            UserMatchCriteria::SanEmail(want) => {
                expected_email.get_or_insert_with(|| want.clone());
                if sans.iter().any(|e| e == want) {
                    return Ok(MatchedMapping {
                        pam_user: m.pam_user.clone(),
                        matched_by: MatchReason::SanEmail,
                    });
                }
            }
            UserMatchCriteria::SanUpn(want) => {
                // SAN UPN is not exposed by the current Certificate accessor.
                // For now we treat it as a no-op (never matches) but keep
                // the variant so config validation continues to compile.
                // A proper UPN extractor will land alongside its dedicated
                // Certificate accessor in a follow-up.
                let _ = want;
            }
        }
    }

    // None matched — surface a structured mismatch error.
    if expected_cn.is_none() && expected_email.is_none() {
        return Err(MappingError::EmptyMapping(pam_user.to_string()));
    }
    Err(MappingError::SubjectMismatch {
        pam_user: pam_user.to_string(),
        expected_cn,
        found_cn: cn,
        expected_email,
        found_emails: sans,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn cn_mapping(user: &str, cn: &str) -> UserMapping {
        UserMapping {
            pam_user: user.to_string(),
            criteria: UserMatchCriteria::SubjectCn(cn.to_string()),
        }
    }

    fn email_mapping(user: &str, email: &str) -> UserMapping {
        UserMapping {
            pam_user: user.to_string(),
            criteria: UserMatchCriteria::SanEmail(email.to_string()),
        }
    }

    fn upn_mapping(user: &str, upn: &str) -> UserMapping {
        UserMapping {
            pam_user: user.to_string(),
            criteria: UserMatchCriteria::SanUpn(upn.to_string()),
        }
    }

    fn leaf() -> Certificate {
        Certificate::from_pem(include_bytes!("../tests/fixtures/leaf_rsa.pem")).unwrap()
    }

    #[test]
    fn matches_subject_cn() {
        let cert = leaf();
        let m = match_user(&cert, "alice", &[cn_mapping("alice", "alice")]).unwrap();
        assert_eq!(m.pam_user, "alice");
        assert_eq!(m.matched_by, MatchReason::CnExact);
    }

    #[test]
    fn matches_san_email() {
        let cert = leaf();
        let m = match_user(
            &cert,
            "alice",
            &[email_mapping("alice", "alice@example.org")],
        )
        .unwrap();
        assert_eq!(m.matched_by, MatchReason::SanEmail);
    }

    #[test]
    fn rejects_when_pam_user_has_no_mapping() {
        let cert = leaf();
        let err = match_user(&cert, "bob", &[cn_mapping("alice", "alice")]).unwrap_err();
        match err {
            MappingError::NoMappingForUser(u) => assert_eq!(u, "bob"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_when_no_criterion_matches() {
        let cert = leaf();
        let err = match_user(&cert, "alice", &[cn_mapping("alice", "eve")]).unwrap_err();
        match err {
            MappingError::SubjectMismatch {
                pam_user,
                expected_cn,
                found_cn,
                ..
            } => {
                assert_eq!(pam_user, "alice");
                assert_eq!(expected_cn.as_deref(), Some("eve"));
                assert_eq!(found_cn.as_deref(), Some("alice"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn email_mismatch_surfaces_found_emails() {
        let cert = leaf();
        let err = match_user(
            &cert,
            "alice",
            &[email_mapping("alice", "wrong@example.org")],
        )
        .unwrap_err();
        match err {
            MappingError::SubjectMismatch {
                expected_email,
                found_emails,
                ..
            } => {
                assert_eq!(expected_email.as_deref(), Some("wrong@example.org"));
                assert!(found_emails.contains(&"alice@example.org".to_string()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn upn_only_mapping_yields_empty_mapping_error() {
        // No CN/SAN-email criterion; UPN extraction is a stub today.
        let cert = leaf();
        let err = match_user(&cert, "alice", &[upn_mapping("alice", "alice@AD")]).unwrap_err();
        assert!(matches!(err, MappingError::EmptyMapping(_)));
    }

    #[test]
    fn first_matching_criterion_wins_when_multiple_cover_user() {
        let cert = leaf();
        // First mapping mismatches; second matches.  Sequence preserved.
        let mappings = vec![
            cn_mapping("alice", "ghost"),
            email_mapping("alice", "alice@example.org"),
        ];
        let m = match_user(&cert, "alice", &mappings).unwrap();
        assert_eq!(m.matched_by, MatchReason::SanEmail);
    }
}

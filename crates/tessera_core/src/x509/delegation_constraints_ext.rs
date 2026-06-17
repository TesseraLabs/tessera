//! Extracts the `pam_cert_delegation_constraints` X.509 extension from a
//! verified certificate.  Trust boundary: the caller must already have
//! validated the chain — see [`VerifiedX509`].
//!
//! ASN.1:
//! ```text
//! extnValue ::= SEQUENCE {
//!     requireTags SEQUENCE OF SEQUENCE { key UTF8String, value UTF8String },
//!     allowRoles  SEQUENCE OF UTF8String,
//!     maxLevel    INTEGER,
//!     maxTtl      INTEGER
//! }
//! ```
//!
//! This is the delegation envelope carried by an intermediate CA.  Parsing is
//! fail-closed: a malformed DER body, an invalid `role_id` in `allowRoles`, a
//! duplicate `requireTags` key, an out-of-range `maxLevel`/`maxTtl`, or the
//! extension appearing on a non-CA (leaf) certificate all reject the whole
//! extension.
//!
//! Placement rule (design decision 3): the extension is valid **only** on a
//! cert whose `basicConstraints` asserts `cA = TRUE`.  Presence on a leaf
//! (`cA = FALSE`, or `basicConstraints` absent) is malformed.

use super::der::{read_tlv, read_tlv_expect, TAG_INTEGER, TAG_SEQUENCE};
use super::der_helpers::{
    extract_extension_by_oid, parse_der_integer_i64, DerError, TAG_UTF8_STRING,
};
use super::oids::DELEGATION_CONSTRAINTS_OID;
use super::VerifiedX509;
use crate::role::RoleId;

/// `maxLevel` is the integrity ceiling: it shares the linear-level type of
/// [`crate::mac::IntegrityLabel`] (`i8`, Astra МКЦ −128..127).
pub type MaxLevel = i8;

/// The parsed delegation envelope from one CA certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationConstraints {
    /// Tags every device under this CA must carry (`key == value`, conjunctive).
    /// Empty is allowed (no tag requirement).  Keys are unique.
    pub require_tags: Vec<(String, String)>,
    /// Roles a leaf under this CA may activate.  Each is a valid `role_id`.
    pub allow_roles: Vec<RoleId>,
    /// Integrity-level ceiling (Astra МКЦ linear level, `i8`).
    pub max_level: MaxLevel,
    /// TTL ceiling for issued sessions, in seconds.
    pub max_ttl: u64,
}

/// Errors returned from [`extract_delegation_constraints`].
#[derive(Debug, thiserror::Error)]
pub enum DelegationConstraintsExtError {
    /// Cert DER could not be re-serialised by `openssl`.
    #[error("cert DER serialisation: {0}")]
    CertDer(String),
    /// Extension lookup encountered malformed cert DER.
    #[error("cert extension scan: {0}")]
    Scan(String),
    /// Reading `basicConstraints` failed.
    #[error("basic constraints: {0}")]
    BasicConstraints(String),
    /// Extension present on a non-CA (leaf) certificate — placement violation.
    #[error("delegation_constraints present on non-CA certificate")]
    NotCa,
    /// Extension present but DER body unparseable.
    #[error("parse: {0}")]
    Parse(String),
    /// A decoded `allowRoles` entry is not a valid `role_id`.
    #[error("invalid role_id in allowRoles: {0}")]
    InvalidRoleId(String),
    /// A `requireTags` key appears more than once.
    #[error("duplicate requireTags key: {0}")]
    DuplicateTagKey(String),
    /// `maxLevel` did not fit the integrity-level type.
    #[error("maxLevel out of range: {0}")]
    MaxLevelOutOfRange(i64),
    /// `maxTtl` was negative.
    #[error("negative maxTtl: {0}")]
    NegativeMaxTtl(i64),
}

/// Returns `Ok(Some(constraints))` if the cert carries a valid
/// `pam_cert_delegation_constraints` extension, `Ok(None)` if it is absent, or
/// `Err` if present but malformed (including being present on a leaf).
///
/// Parsing is fail-closed in every dimension — see the module docs.
///
/// # Errors
/// See [`DelegationConstraintsExtError`].
pub fn extract_delegation_constraints(
    cert: &VerifiedX509,
) -> Result<Option<DelegationConstraints>, DelegationConstraintsExtError> {
    let der = cert
        .as_x509()
        .to_der()
        .map_err(|e| DelegationConstraintsExtError::CertDer(e.to_string()))?;
    let value = match extract_extension_by_oid(&der, DELEGATION_CONSTRAINTS_OID) {
        Ok(Some(v)) => v,
        Ok(None) => return Ok(None),
        Err(e) => return Err(DelegationConstraintsExtError::Scan(e.to_string())),
    };

    // Placement rule: valid only on a CA certificate.  Presence on a leaf
    // (cA = FALSE or basicConstraints absent) is malformed.
    let is_ca = cert
        .is_ca()
        .map_err(|e| DelegationConstraintsExtError::BasicConstraints(e.to_string()))?;
    if !is_ca {
        return Err(DelegationConstraintsExtError::NotCa);
    }

    parse_constraints(&value).map(Some)
}

/// Parses the `extnValue` body into a [`DelegationConstraints`].  Split out so
/// the DER walk can be unit-tested without building a certificate.
fn parse_constraints(
    value_der: &[u8],
) -> Result<DelegationConstraints, DelegationConstraintsExtError> {
    let outer = read_tlv_expect(value_der, TAG_SEQUENCE).map_err(parse_err)?;
    if !outer.rest.is_empty() {
        return Err(DelegationConstraintsExtError::Parse(
            "trailing bytes after outer SEQUENCE".to_owned(),
        ));
    }

    // Field 1 — requireTags: SEQUENCE OF SEQUENCE { key UTF8String, value UTF8String }.
    let require_tags_tlv = read_tlv_expect(outer.value, TAG_SEQUENCE).map_err(parse_err)?;
    let require_tags = parse_require_tags(require_tags_tlv.value)?;

    // Field 2 — allowRoles: SEQUENCE OF UTF8String, each a valid role_id.
    let allow_roles_tlv =
        read_tlv_expect(require_tags_tlv.rest, TAG_SEQUENCE).map_err(parse_err)?;
    let allow_roles = parse_allow_roles(allow_roles_tlv.value)?;

    // Field 3 — maxLevel: INTEGER (i8 range).
    let max_level_tlv = read_tlv_expect(allow_roles_tlv.rest, TAG_INTEGER).map_err(parse_err)?;
    let max_level_raw = parse_der_integer_i64(max_level_tlv.value).map_err(parse_err)?;
    let max_level = MaxLevel::try_from(max_level_raw)
        .map_err(|_| DelegationConstraintsExtError::MaxLevelOutOfRange(max_level_raw))?;

    // Field 4 — maxTtl: INTEGER (non-negative seconds).  Must close out the body.
    let max_ttl_tlv = read_tlv_expect(max_level_tlv.rest, TAG_INTEGER).map_err(parse_err)?;
    if !max_ttl_tlv.rest.is_empty() {
        return Err(DelegationConstraintsExtError::Parse(
            "trailing bytes after maxTtl".to_owned(),
        ));
    }
    let max_ttl_raw = parse_der_integer_i64(max_ttl_tlv.value).map_err(parse_err)?;
    let max_ttl = u64::try_from(max_ttl_raw)
        .map_err(|_| DelegationConstraintsExtError::NegativeMaxTtl(max_ttl_raw))?;

    Ok(DelegationConstraints {
        require_tags,
        allow_roles,
        max_level,
        max_ttl,
    })
}

/// Maps any DER-walk error (whether [`DerError`] or the lower-level
/// [`super::TrustError`] from `read_tlv*`) into a fail-closed parse error.
fn parse_err(e: impl std::fmt::Display) -> DelegationConstraintsExtError {
    DelegationConstraintsExtError::Parse(e.to_string())
}

/// Parses the *content* of the `requireTags` SEQUENCE: a run of
/// `SEQUENCE { key UTF8String, value UTF8String }` pairs.  Rejects duplicate
/// keys (consistency with the device-tags schema).
fn parse_require_tags(
    content: &[u8],
) -> Result<Vec<(String, String)>, DelegationConstraintsExtError> {
    let mut rest = content;
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    while !rest.is_empty() {
        let pair = read_tlv_expect(rest, TAG_SEQUENCE).map_err(parse_err)?;
        rest = pair.rest;
        let key_tlv = read_tlv_expect(pair.value, TAG_UTF8_STRING).map_err(parse_err)?;
        let val_tlv = read_tlv_expect(key_tlv.rest, TAG_UTF8_STRING).map_err(parse_err)?;
        if !val_tlv.rest.is_empty() {
            return Err(DelegationConstraintsExtError::Parse(
                "trailing bytes in requireTags pair".to_owned(),
            ));
        }
        let key = std::str::from_utf8(key_tlv.value)
            .map_err(|_| {
                DelegationConstraintsExtError::Parse("invalid utf-8 in tag key".to_owned())
            })?
            .to_owned();
        let value = std::str::from_utf8(val_tlv.value)
            .map_err(|_| {
                DelegationConstraintsExtError::Parse("invalid utf-8 in tag value".to_owned())
            })?
            .to_owned();
        if !seen.insert(key.clone()) {
            return Err(DelegationConstraintsExtError::DuplicateTagKey(key));
        }
        out.push((key, value));
    }
    Ok(out)
}

/// Parses the *content* of the `allowRoles` SEQUENCE: a run of `UTF8String`s,
/// each of which must be a valid `role_id`.
fn parse_allow_roles(content: &[u8]) -> Result<Vec<RoleId>, DelegationConstraintsExtError> {
    let mut rest = content;
    let mut out: Vec<RoleId> = Vec::new();
    while !rest.is_empty() {
        let tlv = read_tlv(rest).map_err(parse_err)?;
        if tlv.tag != TAG_UTF8_STRING {
            return Err(parse_err(DerError::UnexpectedTag(tlv.tag)));
        }
        let s = std::str::from_utf8(tlv.value).map_err(|_| {
            DelegationConstraintsExtError::Parse("invalid utf-8 in role".to_owned())
        })?;
        let role = RoleId::new(s)
            .map_err(|e| DelegationConstraintsExtError::InvalidRoleId(e.to_string()))?;
        out.push(role);
        rest = tlv.rest;
    }
    Ok(out)
}

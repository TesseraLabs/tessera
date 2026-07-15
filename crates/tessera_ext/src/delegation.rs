//! The `pam_cert_delegation_constraints` schema, its raw DER parse, and the
//! monotone-narrowing predicate.
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
//! Two things live here so the issuer and the Engine share one implementation:
//!
//! * [`parse_constraints`] / [`parse_constraints_with`] turn the raw
//!   `extnValue` bytes into a [`DelegationConstraints`].  This is the "raw"
//!   parse only — extracting the extension from a certificate (which needs
//!   OpenSSL) stays in the Engine, and so does validating each `allowRoles`
//!   entry against the Engine's `role_id` grammar (injected as a closure so the
//!   Engine can reject at the exact byte position its strict parser used to).
//!
//! * [`narrows`] decides whether a child envelope stays inside its parent
//!   (`child ⊆ parent`) with AND/MIN semantics per dimension.  The issuer runs
//!   it before signing to guarantee monotone narrowing; it is the same notion
//!   of "narrower" the Engine enforces cumulatively across a chain.
//!
//! Roles are carried as [`String`] rather than a validated newtype so the crate
//! needs no `role_id` grammar (that policy is the Engine's).

use core::fmt;

use crate::der::{
    parse_der_integer_i64, read_tlv, read_tlv_expect, DerError, TAG_INTEGER, TAG_SEQUENCE,
    TAG_UTF8_STRING,
};

/// The parsed delegation envelope from one CA certificate.
///
/// `max_level` is the Astra МКЦ integrity ceiling (linear level, `i8`);
/// `max_ttl` is the session-lifetime ceiling in seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationConstraints {
    /// Tags every device under this CA must carry (`key == value`, conjunctive).
    /// Empty is allowed (no tag requirement).  Keys are unique.
    pub require_tags: Vec<(String, String)>,
    /// Roles a leaf under this CA may activate.  Not validated against any
    /// `role_id` grammar here — the Engine does that on the boundary.
    pub allow_roles: Vec<String>,
    /// Integrity-level ceiling (Astra МКЦ linear level, `i8`).
    pub max_level: i8,
    /// TTL ceiling for issued sessions, in seconds.
    pub max_ttl: u64,
}

/// Errors from [`parse_constraints_with`].  Every variant is a fail-closed
/// rejection of the extension.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The DER body was structurally malformed (bad tag, truncation, trailing
    /// bytes, or invalid UTF-8 in a string).
    #[error("delegation_constraints: {0}")]
    Malformed(String),
    /// A `requireTags` key appeared more than once.
    #[error("duplicate requireTags key: {0}")]
    DuplicateTagKey(String),
    /// An `allowRoles` entry was rejected by the caller's role validator.
    #[error("invalid role in allowRoles: {0}")]
    InvalidRole(String),
    /// `maxLevel` did not fit the integrity-level type (`i8`).
    #[error("maxLevel out of range: {0}")]
    MaxLevelOutOfRange(i64),
    /// `maxTtl` was negative.
    #[error("negative maxTtl: {0}")]
    NegativeMaxTtl(i64),
}

impl From<DerError> for ParseError {
    /// Any low-level DER failure is a fail-closed structural rejection.
    fn from(err: DerError) -> Self {
        ParseError::Malformed(err.to_string())
    }
}

/// Parses the `extnValue` body into a [`DelegationConstraints`], accepting any
/// syntactically valid role token.
///
/// # Errors
///
/// See [`ParseError`].
pub fn parse_constraints(value_der: &[u8]) -> Result<DelegationConstraints, ParseError> {
    parse_constraints_with(value_der, |_| Ok(()))
}

/// Parses the `extnValue` body into a [`DelegationConstraints`], validating each
/// `allowRoles` entry with `validate_role`.
///
/// `validate_role` is called for every role token, in order, at the point the
/// token is decoded; returning `Err(reason)` aborts the parse with
/// [`ParseError::InvalidRole`].  This lets the Engine apply its `role_id`
/// grammar without this crate depending on it, while the issuer passes a
/// permissive validator.
///
/// # Errors
///
/// See [`ParseError`].
pub fn parse_constraints_with<F>(
    value_der: &[u8],
    mut validate_role: F,
) -> Result<DelegationConstraints, ParseError>
where
    F: FnMut(&str) -> Result<(), String>,
{
    let outer = read_tlv_expect(value_der, TAG_SEQUENCE)?;
    if !outer.rest.is_empty() {
        return Err(ParseError::Malformed(
            "trailing bytes after outer SEQUENCE".to_owned(),
        ));
    }

    // Field 1 — requireTags: SEQUENCE OF SEQUENCE { key UTF8String, value UTF8String }.
    let require_tags_tlv = read_tlv_expect(outer.value, TAG_SEQUENCE)?;
    let require_tags = parse_require_tags(require_tags_tlv.value)?;

    // Field 2 — allowRoles: SEQUENCE OF UTF8String, each vetted by `validate_role`.
    let allow_roles_tlv = read_tlv_expect(require_tags_tlv.rest, TAG_SEQUENCE)?;
    let allow_roles = parse_allow_roles(allow_roles_tlv.value, &mut validate_role)?;

    // Field 3 — maxLevel: INTEGER (i8 range).
    let max_level_tlv = read_tlv_expect(allow_roles_tlv.rest, TAG_INTEGER)?;
    let max_level_raw = parse_der_integer_i64(max_level_tlv.value)?;
    let max_level =
        i8::try_from(max_level_raw).map_err(|_| ParseError::MaxLevelOutOfRange(max_level_raw))?;

    // Field 4 — maxTtl: INTEGER (non-negative seconds).  Must close out the body.
    let max_ttl_tlv = read_tlv_expect(max_level_tlv.rest, TAG_INTEGER)?;
    if !max_ttl_tlv.rest.is_empty() {
        return Err(ParseError::Malformed(
            "trailing bytes after maxTtl".to_owned(),
        ));
    }
    let max_ttl_raw = parse_der_integer_i64(max_ttl_tlv.value)?;
    let max_ttl =
        u64::try_from(max_ttl_raw).map_err(|_| ParseError::NegativeMaxTtl(max_ttl_raw))?;

    Ok(DelegationConstraints {
        require_tags,
        allow_roles,
        max_level,
        max_ttl,
    })
}

/// Parses the *content* of the `requireTags` SEQUENCE: a run of
/// `SEQUENCE { key UTF8String, value UTF8String }` pairs.  Rejects duplicate
/// keys (consistency with the device-tags schema).
fn parse_require_tags(content: &[u8]) -> Result<Vec<(String, String)>, ParseError> {
    let mut rest = content;
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    while !rest.is_empty() {
        let pair = read_tlv_expect(rest, TAG_SEQUENCE)?;
        rest = pair.rest;
        let key_tlv = read_tlv_expect(pair.value, TAG_UTF8_STRING)?;
        let val_tlv = read_tlv_expect(key_tlv.rest, TAG_UTF8_STRING)?;
        if !val_tlv.rest.is_empty() {
            return Err(ParseError::Malformed(
                "trailing bytes in requireTags pair".to_owned(),
            ));
        }
        let key = decode_utf8(key_tlv.value, "tag key")?;
        let value = decode_utf8(val_tlv.value, "tag value")?;
        if !seen.insert(key.clone()) {
            return Err(ParseError::DuplicateTagKey(key));
        }
        out.push((key, value));
    }
    Ok(out)
}

/// Parses the *content* of the `allowRoles` SEQUENCE: a run of `UTF8String`s,
/// each vetted by `validate_role`.
fn parse_allow_roles<F>(content: &[u8], validate_role: &mut F) -> Result<Vec<String>, ParseError>
where
    F: FnMut(&str) -> Result<(), String>,
{
    let mut rest = content;
    let mut out: Vec<String> = Vec::new();
    while !rest.is_empty() {
        let tlv = read_tlv(rest)?;
        if tlv.tag != TAG_UTF8_STRING {
            return Err(ParseError::Malformed(format!(
                "der: expected tag 0x{TAG_UTF8_STRING:02x}, got 0x{:02x}",
                tlv.tag
            )));
        }
        let role = decode_utf8(tlv.value, "role")?;
        validate_role(&role).map_err(ParseError::InvalidRole)?;
        out.push(role);
        rest = tlv.rest;
    }
    Ok(out)
}

/// Decodes UTF-8 content, tagging a failure with the field name.
fn decode_utf8(bytes: &[u8], field: &str) -> Result<String, ParseError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ParseError::Malformed(format!("invalid utf-8 in {field}")))
}

/// Encodes a [`DelegationConstraints`] into its `extnValue` body — the exact
/// `SEQUENCE { requireTags, allowRoles, maxLevel, maxTtl }` shape
/// [`parse_constraints`] accepts.
///
/// `require_tags` are emitted in the given order (the parser rejects duplicate
/// keys, so the caller must supply unique keys). A `max_ttl` beyond
/// [`i64::MAX`] seconds — far past any real session lifetime — saturates to
/// [`i64::MAX`]; every value that round-trips through [`parse_constraints`]
/// (which reads a non-negative `i64`) encodes losslessly.
#[must_use]
pub fn encode_constraints(constraints: &DelegationConstraints) -> Vec<u8> {
    use crate::der::{encode_der_integer_i64, encode_tlv, encode_utf8_string, TAG_SEQUENCE};

    let mut require_tags_body = Vec::new();
    for (key, value) in &constraints.require_tags {
        let mut pair = encode_utf8_string(key);
        pair.extend_from_slice(&encode_utf8_string(value));
        require_tags_body.extend_from_slice(&encode_tlv(TAG_SEQUENCE, &pair));
    }

    let mut body = encode_tlv(TAG_SEQUENCE, &require_tags_body);
    body.extend_from_slice(&crate::ext::encode_seq_of_utf8(&constraints.allow_roles));
    body.extend_from_slice(&encode_der_integer_i64(i64::from(constraints.max_level)));
    body.extend_from_slice(&encode_der_integer_i64(
        i64::try_from(constraints.max_ttl).unwrap_or(i64::MAX),
    ));
    encode_tlv(TAG_SEQUENCE, &body)
}

/// A single dimension of the delegation envelope, named when monotone narrowing
/// is violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDimension {
    /// The `requireTags` set (a child must require *at least* the parent's tags).
    RequireTags,
    /// The `allowRoles` set (a child may allow *at most* the parent's roles).
    AllowRoles,
    /// The `maxLevel` ceiling (a child's ceiling must be *no higher*).
    MaxLevel,
    /// The `maxTtl` ceiling (a child's ceiling must be *no longer*).
    MaxTtl,
}

impl fmt::Display for ScopeDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ScopeDimension::RequireTags => "require_tags",
            ScopeDimension::AllowRoles => "allow_roles",
            ScopeDimension::MaxLevel => "max_level",
            ScopeDimension::MaxTtl => "max_ttl",
        };
        f.write_str(name)
    }
}

/// A child envelope widens its parent along one dimension — the issuer-side
/// monotonicity failure, naming the first dimension that broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("delegation scope widens the parent envelope along {dimension}")]
pub struct ScopeWidened {
    /// The first dimension along which the child was found wider than the parent.
    pub dimension: ScopeDimension,
}

/// Returns `Ok(())` if `child` narrows-or-equals `parent` along every dimension
/// (`child ⊆ parent`), or `Err` naming the first dimension the child widened.
///
/// Narrowing is non-strict (equality passes) and defined per dimension:
///
/// * **`require_tags`** — the child must require a *superset* of the parent's
///   tags: every parent `(key, value)` pair must also be required by the child.
/// * **`allow_roles`** — the child may allow only a *subset* of the parent's
///   roles: every child role must appear in the parent's list.
/// * **`max_level`** — the child's ceiling must be `≤` the parent's.
/// * **`max_ttl`** — the child's ceiling must be `≤` the parent's.
///
/// # Errors
///
/// [`ScopeWidened`] naming the first violated dimension, checked in the order
/// `require_tags`, `allow_roles`, `max_level`, `max_ttl`.
pub fn narrows(
    child: &DelegationConstraints,
    parent: &DelegationConstraints,
) -> Result<(), ScopeWidened> {
    // require_tags: child ⊇ parent — every parent pair must be required by the child.
    let child_requires = |key: &str, value: &str| {
        child
            .require_tags
            .iter()
            .any(|(k, v)| k == key && v == value)
    };
    if !parent
        .require_tags
        .iter()
        .all(|(k, v)| child_requires(k, v))
    {
        return Err(ScopeWidened {
            dimension: ScopeDimension::RequireTags,
        });
    }

    // allow_roles: child ⊆ parent — every child role must be allowed by the parent.
    if !child
        .allow_roles
        .iter()
        .all(|role| parent.allow_roles.iter().any(|p| p == role))
    {
        return Err(ScopeWidened {
            dimension: ScopeDimension::AllowRoles,
        });
    }

    // max_level / max_ttl: the child ceiling must not exceed the parent's.
    if child.max_level > parent.max_level {
        return Err(ScopeWidened {
            dimension: ScopeDimension::MaxLevel,
        });
    }
    if child.max_ttl > parent.max_ttl {
        return Err(ScopeWidened {
            dimension: ScopeDimension::MaxTtl,
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A baseline envelope every narrowing test starts from.
    fn parent() -> DelegationConstraints {
        DelegationConstraints {
            require_tags: vec![("region".to_owned(), "north".to_owned())],
            allow_roles: vec!["oper".to_owned(), "serv".to_owned()],
            max_level: 5,
            max_ttl: 3600,
        }
    }

    #[test]
    fn equal_scope_narrows() {
        assert!(narrows(&parent(), &parent()).is_ok());
    }

    #[test]
    fn require_tags_narrowing_passes() {
        // Child requires the parent's tag plus one more — strictly narrower.
        let mut child = parent();
        child
            .require_tags
            .push(("rack".to_owned(), "a1".to_owned()));
        assert!(narrows(&child, &parent()).is_ok());
    }

    #[test]
    fn require_tags_widening_rejected() {
        // Child drops the parent's required tag — wider.
        let mut child = parent();
        child.require_tags.clear();
        let err = narrows(&child, &parent()).unwrap_err();
        assert_eq!(err.dimension, ScopeDimension::RequireTags);
    }

    #[test]
    fn require_tags_different_value_rejected() {
        // Same key, different value: does not cover the parent pair — wider.
        let mut child = parent();
        child.require_tags = vec![("region".to_owned(), "south".to_owned())];
        let err = narrows(&child, &parent()).unwrap_err();
        assert_eq!(err.dimension, ScopeDimension::RequireTags);
    }

    #[test]
    fn allow_roles_narrowing_passes() {
        // Child allows a subset of the parent's roles.
        let mut child = parent();
        child.allow_roles = vec!["oper".to_owned()];
        assert!(narrows(&child, &parent()).is_ok());
    }

    #[test]
    fn allow_roles_widening_rejected() {
        // Child allows a role the parent does not.
        let mut child = parent();
        child.allow_roles.push("admin".to_owned());
        let err = narrows(&child, &parent()).unwrap_err();
        assert_eq!(err.dimension, ScopeDimension::AllowRoles);
    }

    #[test]
    fn max_level_narrowing_passes() {
        let mut child = parent();
        child.max_level = 4;
        assert!(narrows(&child, &parent()).is_ok());
    }

    #[test]
    fn max_level_widening_rejected() {
        let mut child = parent();
        child.max_level = 6;
        let err = narrows(&child, &parent()).unwrap_err();
        assert_eq!(err.dimension, ScopeDimension::MaxLevel);
    }

    #[test]
    fn max_ttl_narrowing_passes() {
        let mut child = parent();
        child.max_ttl = 1800;
        assert!(narrows(&child, &parent()).is_ok());
    }

    #[test]
    fn max_ttl_widening_rejected() {
        let mut child = parent();
        child.max_ttl = 7200;
        let err = narrows(&child, &parent()).unwrap_err();
        assert_eq!(err.dimension, ScopeDimension::MaxTtl);
    }

    #[test]
    fn scope_dimension_display_matches_field_names() {
        assert_eq!(ScopeDimension::RequireTags.to_string(), "require_tags");
        assert_eq!(ScopeDimension::AllowRoles.to_string(), "allow_roles");
        assert_eq!(ScopeDimension::MaxLevel.to_string(), "max_level");
        assert_eq!(ScopeDimension::MaxTtl.to_string(), "max_ttl");
    }

    /// One INTEGER TLV from a signed one-byte value.
    fn int_i8(v: i8) -> Vec<u8> {
        vec![TAG_INTEGER, 0x01, v.to_be_bytes()[0]]
    }

    fn utf8(s: &str) -> Vec<u8> {
        let mut out = vec![TAG_UTF8_STRING, u8::try_from(s.len()).unwrap()];
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn seq(body: &[u8]) -> Vec<u8> {
        let mut out = vec![TAG_SEQUENCE, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn parse_round_trips_a_valid_body() {
        let mut tag_pair = utf8("region");
        tag_pair.extend_from_slice(&utf8("north"));
        let require_tags = seq(&seq(&tag_pair));
        let mut roles = utf8("oper");
        roles.extend_from_slice(&utf8("serv"));
        let allow_roles = seq(&roles);

        let mut body = require_tags;
        body.extend_from_slice(&allow_roles);
        body.extend_from_slice(&int_i8(5));
        body.extend_from_slice(&int_i8(60));
        let der = seq(&body);

        let parsed = parse_constraints(&der).expect("valid body parses");
        assert_eq!(
            parsed.require_tags,
            vec![("region".to_owned(), "north".to_owned())]
        );
        assert_eq!(
            parsed.allow_roles,
            vec!["oper".to_owned(), "serv".to_owned()]
        );
        assert_eq!(parsed.max_level, 5);
        assert_eq!(parsed.max_ttl, 60);
    }

    #[test]
    fn encode_constraints_round_trips_through_parser() {
        let original = DelegationConstraints {
            require_tags: vec![
                ("region".to_owned(), "north".to_owned()),
                ("rack".to_owned(), "a1".to_owned()),
            ],
            allow_roles: vec!["oper".to_owned(), "serv".to_owned()],
            max_level: -7,
            max_ttl: 86_400,
        };
        let der = encode_constraints(&original);
        let parsed = parse_constraints(&der).expect("issuer output re-parses");
        assert_eq!(parsed, original);
    }

    #[test]
    fn encode_constraints_empty_envelope_round_trips() {
        let original = DelegationConstraints {
            require_tags: vec![],
            allow_roles: vec![],
            max_level: 0,
            max_ttl: 0,
        };
        let der = encode_constraints(&original);
        assert_eq!(parse_constraints(&der).expect("re-parses"), original);
    }

    #[test]
    fn parse_role_validator_rejects() {
        let require_tags = seq(&[]);
        let allow_roles = seq(&utf8("Admin"));
        let mut body = require_tags;
        body.extend_from_slice(&allow_roles);
        body.extend_from_slice(&int_i8(0));
        body.extend_from_slice(&int_i8(30));
        let der = seq(&body);

        let err = parse_constraints_with(&der, |r| {
            if r == "Admin" {
                Err("uppercase not allowed".to_owned())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(matches!(err, ParseError::InvalidRole(_)));
    }
}

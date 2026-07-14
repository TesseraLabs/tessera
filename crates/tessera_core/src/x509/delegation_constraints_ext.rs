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
//! The raw byte-level parse of the `extnValue` body lives in
//! [`tessera_ext::delegation`] so the issuer and the Engine agree on it; this
//! module keeps the OpenSSL glue (pulling the extension out of the certificate,
//! checking `basicConstraints`) and validates each `allowRoles` entry against
//! the Engine's [`RoleId`] grammar.
//!
//! Placement rule (design decision 3): the extension is valid **only** on a
//! cert whose `basicConstraints` asserts `cA = TRUE`.  Presence on a leaf
//! (`cA = FALSE`, or `basicConstraints` absent) is malformed.

use super::der_helpers::extract_extension_by_oid;
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

/// Parses the `extnValue` body into a [`DelegationConstraints`].  The raw DER
/// walk is shared with the issuer via [`tessera_ext::delegation`]; the injected
/// validator applies the Engine's `role_id` grammar to each `allowRoles` entry
/// at the exact position the strict Engine parser used to, so error precedence
/// is unchanged.
fn parse_constraints(
    value_der: &[u8],
) -> Result<DelegationConstraints, DelegationConstraintsExtError> {
    let mut allow_roles: Vec<RoleId> = Vec::new();
    let raw =
        tessera_ext::delegation::parse_constraints_with(value_der, |role| {
            match RoleId::new(role) {
                Ok(id) => {
                    allow_roles.push(id);
                    Ok(())
                }
                Err(e) => Err(e.to_string()),
            }
        })
        .map_err(map_parse_err)?;

    Ok(DelegationConstraints {
        require_tags: raw.require_tags,
        allow_roles,
        max_level: raw.max_level,
        max_ttl: raw.max_ttl,
    })
}

/// Maps the shared parse error into the Engine-facing error, preserving each
/// fail-closed variant.
fn map_parse_err(err: tessera_ext::delegation::ParseError) -> DelegationConstraintsExtError {
    use tessera_ext::delegation::ParseError as Ext;
    match err {
        Ext::Malformed(s) => DelegationConstraintsExtError::Parse(s),
        Ext::DuplicateTagKey(k) => DelegationConstraintsExtError::DuplicateTagKey(k),
        Ext::InvalidRole(s) => DelegationConstraintsExtError::InvalidRoleId(s),
        Ext::MaxLevelOutOfRange(v) => DelegationConstraintsExtError::MaxLevelOutOfRange(v),
        Ext::NegativeMaxTtl(v) => DelegationConstraintsExtError::NegativeMaxTtl(v),
    }
}

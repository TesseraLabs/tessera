//! Version-two work authorisation syntax and pure consistency checks.
//!
//! A signature or matching catalogue reference is NOT current authority to
//! issue. Publication, chain ceilings, approvals, device identity, directory
//! state and exact-grant revocation/status remain mandatory consumer checks.
//! No consumer is activated by this module; the Codes v1 format is unchanged.

mod codec;

use sha2::{Digest, Sha256};
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::engineer::Devices;
use tessera_codes_contract::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::mac::IntegrityLabel;
use crate::role::{RoleId, RoleOs, VerifiedRoleCatalogue};

/// Exact wire marker; this is not a Codes-only document.
pub const WIRE_PREFIX: &str = "tessera-work/v2/authorisation";
/// Domain included in the signed body.
pub const SIGNING_LABEL: &str = "tessera-work-contract/v2/authorisation";
/// Maximum complete ASCII envelope size.
pub const MAX_WIRE_BYTES: usize = 65_536;
/// Maximum decoded canonical body size.
pub const MAX_BODY_BYTES: usize = 24_576;
/// Maximum opaque signature size; the verifier checks its algorithm profile.
pub const MAX_SIGNATURE_BYTES: usize = 4_096;
/// Maximum number of explicit role/OS rows, also bounded by body size.
pub const MAX_ROLE_ROWS: usize = 256;
/// Maximum number of literal site tags.
pub const MAX_TAGS: usize = 64;

/// Failure of syntax, signature or a pure consistency/coverage check.
#[derive(Debug, thiserror::Error)]
pub enum WorkAuthorisationError {
    /// A field is malformed, noncanonical or inconsistent.
    #[error("invalid work authorisation field: {0}")]
    Invalid(&'static str),
    /// A bounded input exceeds its limit.
    #[error("work authorisation size limit exceeded: {0}")]
    Oversize(&'static str),
    /// Signed identity disagrees with the caller's independently verified context.
    #[error("work authorisation context mismatch: {0}")]
    Context(&'static str),
    /// A catalogue reference or cap is not supported by supplied verified facts.
    #[error("work authorisation catalogue mismatch: {0}")]
    Catalogue(&'static str),
    /// A requested method/scope exceeds the signed bounds.
    #[error("work authorisation does not cover: {0}")]
    Coverage(&'static str),
    /// The existing signature verifier refused the document.
    #[error(transparent)]
    Signature(#[from] SignatureError),
}

/// Builder input for one immutable role/OS row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBoundsFields {
    /// Existing validated role identifier; no wildcard.
    pub role_id: RoleId,
    /// Target OS of the signed role bundle.
    pub target_os: RoleOs,
    /// Deployment-owned publication stream identifier.
    pub stream_id: String,
    /// SHA-256 of the trusted catalogue signing key's SPKI DER.
    pub trust_sha256: [u8; 32],
    /// Monotonic role bundle version.
    pub bundle_version: u64,
    /// SHA-256 of the complete raw manifest, including its signature.
    pub manifest_sha256: [u8; 32],
    /// Version of the exact signed role slice.
    pub slice_version: u32,
    /// SHA-256 of the raw role slice bytes.
    pub slice_sha256: [u8; 32],
    /// Explicit Codes bound, 0..=127; absence means unavailable.
    pub codes_max_level: Option<u8>,
    /// Explicit certificate bound; absence means unavailable.
    pub certificate: Option<IntegrityLabel>,
}

/// Validated immutable row; it grants nothing without its consumer checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBounds {
    fields: RoleBoundsFields,
}

impl RoleBounds {
    /// Validate and preserve a row, without normalizing or repairing it.
    pub fn new(fields: RoleBoundsFields) -> Result<Self, WorkAuthorisationError> {
        if fields.stream_id.is_empty()
            || fields.stream_id.len() > 128
            || !fields
                .stream_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(WorkAuthorisationError::Invalid("stream_id"));
        }
        if fields.codes_max_level.is_some_and(|level| level > 127) {
            return Err(WorkAuthorisationError::Invalid("codes_max_level"));
        }
        if fields.codes_max_level.is_none() && fields.certificate.is_none() {
            return Err(WorkAuthorisationError::Invalid("methods"));
        }
        Ok(Self { fields })
    }

    /// Read-only fields. A modified clone must pass the constructor again.
    pub fn fields(&self) -> &RoleBoundsFields {
        &self.fields
    }
}

/// Builder input for a common work intent. Device and tag semantics are v1's;
/// role bounds explicitly separate methods and OS targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkIntentFields {
    /// Existing decision/intent UUID; never nil.
    pub authorisation_id: Uuid,
    /// Fleet UUID in the signed scope; never nil.
    pub fleet_id: Uuid,
    /// Tenant-node UUID in the signed scope; never nil.
    pub tenant_node_id: Uuid,
    /// Engineer identifier, not a display name inferred by this parser.
    pub engineer: String,
    /// Existing organisation identifier.
    pub organisation: String,
    /// Engineer key fingerprint. Zero means explicitly unverified, not any key.
    pub key_fingerprint: [u8; 32],
    /// Explicit Any or nonempty canonical device list.
    pub devices: Devices,
    /// Nonempty, strictly sorted unique literal tags.
    pub tags: Vec<String>,
    /// Inclusive start, Unix seconds.
    pub not_before: u64,
    /// Exclusive end, Unix seconds.
    pub not_after: u64,
    /// Strictly sorted unique (role id, OS) rows.
    pub roles: Vec<RoleBounds>,
}

/// Immutable, schema-valid intent. Neither a signature nor current authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkIntent {
    fields: WorkIntentFields,
}

impl WorkIntent {
    /// Construct with exactly the same invariants and budgets as the parser.
    pub fn new(fields: WorkIntentFields) -> Result<Self, WorkAuthorisationError> {
        for (id, name) in [
            (fields.authorisation_id, "authorisation_id"),
            (fields.fleet_id, "fleet_id"),
            (fields.tenant_node_id, "tenant_node_id"),
        ] {
            if id.is_nil() {
                return Err(WorkAuthorisationError::Invalid(name));
            }
        }
        text(&fields.engineer, 128, false, "engineer")?;
        text(&fields.organisation, 128, false, "organisation")?;
        if let Devices::Only(devices) = &fields.devices {
            for device in devices.as_slice() {
                if !(2..=64).contains(&device.significant().len())
                    || !device.significant().is_ascii()
                {
                    return Err(WorkAuthorisationError::Invalid("device"));
                }
            }
        }
        if fields.tags.is_empty() || fields.tags.len() > MAX_TAGS {
            return Err(WorkAuthorisationError::Invalid("tag_count"));
        }
        for tag in &fields.tags {
            text(tag, 256, true, "tag")?;
        }
        if fields
            .tags
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a >= b))
        {
            return Err(WorkAuthorisationError::Invalid("tag_order"));
        }
        if fields.not_before >= fields.not_after {
            return Err(WorkAuthorisationError::Invalid("period"));
        }
        if fields.roles.is_empty() || fields.roles.len() > MAX_ROLE_ROWS {
            return Err(WorkAuthorisationError::Invalid("role_count"));
        }
        let mut previous = None;
        let mut bundles: Vec<&RoleBoundsFields> = Vec::with_capacity(3);
        for row in &fields.roles {
            let row = row.fields();
            let identity = (row.role_id.as_str(), row.target_os.as_str());
            if previous.is_some_and(|old| old >= identity) {
                return Err(WorkAuthorisationError::Invalid("role_order"));
            }
            previous = Some(identity);
            if let Some(old) = bundles.iter().find(|old| old.target_os == row.target_os) {
                if old.stream_id != row.stream_id
                    || old.trust_sha256 != row.trust_sha256
                    || old.bundle_version != row.bundle_version
                    || old.manifest_sha256 != row.manifest_sha256
                {
                    return Err(WorkAuthorisationError::Invalid("conflicting_os_bundle"));
                }
            } else {
                bundles.push(row);
            }
        }
        let intent = Self { fields };
        intent.encode_body()?;
        Ok(intent)
    }

    /// Read-only validated fields, not evidence of currentness or approval.
    pub fn fields(&self) -> &WorkIntentFields {
        &self.fields
    }

    /// Exact signing message, including the domain and every signed axis.
    pub fn encode_body(&self) -> Result<Vec<u8>, WorkAuthorisationError> {
        codec::encode(self)
    }

    /// Decode a complete canonical body; there is no signature in this input.
    pub fn parse_body(bytes: &[u8]) -> Result<Self, WorkAuthorisationError> {
        codec::decode(bytes)
    }

    /// SHA-256 of canonical body bytes, independent of signature encoding.
    pub fn body_digest(&self) -> Result<[u8; 32], WorkAuthorisationError> {
        Ok(Sha256::digest(self.encode_body()?).into())
    }

    /// Exact human-approval draft envelope. `00` is only a placeholder.
    pub fn draft_wire(&self) -> Result<String, WorkAuthorisationError> {
        Ok(format!(
            "{WIRE_PREFIX};body={};signature=00",
            hex::encode(self.encode_body()?)
        ))
    }

    /// Digest of the exact draft UTF-8 bytes; distinct from the body digest.
    pub fn approval_digest(&self) -> Result<[u8; 32], WorkAuthorisationError> {
        Ok(Sha256::digest(self.draft_wire()?.as_bytes()).into())
    }

    /// Pure membership check, requiring a separately authenticated device context.
    pub fn covers_device(&self, device: &CheckedDeviceNumber) -> bool {
        self.fields.devices.covers(device)
    }

    /// Literal tag equality as in v1; `*` acquires no wildcard meaning.
    pub fn covers_tag(&self, tag: &str) -> bool {
        self.fields.tags.iter().any(|item| item == tag)
    }

    /// Half-open period membership, not status, clock trust or freshness.
    pub fn applies_at(&self, now: u64) -> bool {
        self.fields.not_before <= now && now < self.fields.not_after
    }
}

/// Independently established caller identity. Matching these fields does not
/// establish record validity or proof of possession; callers must do that first.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedIdentity<'a> {
    /// Expected fleet, also the scope in which the verifier resolves its key.
    pub fleet_id: Uuid,
    /// Expected tenant node.
    pub tenant_node_id: Uuid,
    /// Verified engineer identifier.
    pub engineer: &'a str,
    /// Verified organisation identifier.
    pub organisation: &'a str,
    /// Verified engineer key fingerprint, or explicit unverified zero marker.
    pub key_fingerprint: &'a [u8; 32],
}

/// Structurally valid signed envelope. `parse` does not verify its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkAuthorisation {
    intent: WorkIntent,
    signature: Signature,
}

impl WorkAuthorisation {
    /// Attach an opaque signature; it remains unverified.
    pub fn new(intent: WorkIntent, signature: Signature) -> Result<Self, WorkAuthorisationError> {
        if signature.as_bytes().len() > MAX_SIGNATURE_BYTES {
            return Err(WorkAuthorisationError::Oversize("signature"));
        }
        let document = Self { intent, signature };
        if document.to_wire()?.len() > MAX_WIRE_BYTES {
            return Err(WorkAuthorisationError::Oversize("wire"));
        }
        Ok(document)
    }

    /// Parse only the exact v2 envelope, without trim, normalization or verification.
    pub fn parse(wire: &str) -> Result<Self, WorkAuthorisationError> {
        if wire.len() > MAX_WIRE_BYTES {
            return Err(WorkAuthorisationError::Oversize("wire"));
        }
        let fields = wire
            .strip_prefix(WIRE_PREFIX)
            .and_then(|s| s.strip_prefix(";body="))
            .ok_or(WorkAuthorisationError::Invalid("prefix"))?;
        let (body, signature) = fields
            .split_once(";signature=")
            .ok_or(WorkAuthorisationError::Invalid("envelope"))?;
        let body = decode_hex(body, MAX_BODY_BYTES, "body")?;
        let signature = Signature::new(decode_hex(signature, MAX_SIGNATURE_BYTES, "signature")?)?;
        Self::new(WorkIntent::parse_body(&body)?, signature)
    }

    /// The immutable intent; its facts still require signature and consumer checks.
    pub fn intent(&self) -> &WorkIntent {
        &self.intent
    }

    /// The unverified opaque signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Exact canonical ASCII envelope.
    pub fn to_wire(&self) -> Result<String, WorkAuthorisationError> {
        Ok(format!(
            "{WIRE_PREFIX};body={};signature={}",
            hex::encode(self.intent.encode_body()?),
            hex::encode(self.signature.as_bytes())
        ))
    }

    /// Verify the existing authorisation-key signature and match the signed
    /// identity against independent context. The verifier MUST resolve
    /// `AuthorisationKey` in `expected.fleet_id`'s trust domain.
    ///
    /// The result proves these checks only, never current publication or status.
    pub fn verify<'a>(
        &'a self,
        verifier: &impl SignatureVerifier,
        expected: ExpectedIdentity<'_>,
    ) -> Result<SignatureChecked<'a>, WorkAuthorisationError> {
        let fields = self.intent.fields();
        for (matches, name) in [
            (fields.fleet_id == expected.fleet_id, "fleet"),
            (fields.tenant_node_id == expected.tenant_node_id, "node"),
            (fields.engineer == expected.engineer, "engineer"),
            (fields.organisation == expected.organisation, "organisation"),
            (
                &fields.key_fingerprint == expected.key_fingerprint,
                "key_fingerprint",
            ),
        ] {
            if !matches {
                return Err(WorkAuthorisationError::Context(name));
            }
        }
        verifier.verify(
            SignerRef::AuthorisationKey,
            &self.intent.encode_body()?,
            &self.signature,
        )?;
        Ok(SignatureChecked { document: self })
    }
}

/// Signature and expected identity matched. This is deliberately not named an
/// authorisation decision: exact-grant status and all runtime authority are absent.
#[derive(Debug, Clone, Copy)]
pub struct SignatureChecked<'a> {
    document: &'a WorkAuthorisation,
}

/// Catalogue evidence paired with its independently protected source binding.
/// A caller must not populate this binding from the untrusted intent's rows.
#[derive(Debug, Clone, Copy)]
pub struct CatalogueContext<'a> {
    /// Fleet that owns the configured source.
    pub fleet_id: Uuid,
    /// Node whose publication scope the source belongs to.
    pub tenant_node_id: Uuid,
    /// Configured stream, not a caller-selected path or key.
    pub stream_id: &'a str,
    /// Fingerprint of the trusted key used to verify this catalogue.
    pub trust_sha256: [u8; 32],
    /// Raw-byte verified catalogue; verification alone is not publication.
    pub catalogue: &'a VerifiedRoleCatalogue,
}

impl SignatureChecked<'_> {
    /// Read-only intent whose signature and identity were checked.
    pub fn intent(&self) -> &WorkIntent {
        self.document.intent()
    }

    /// Compare references and caps to exact independently bound catalogue facts.
    /// Does not establish chain ceilings, current publication, TTL or status.
    pub fn check_references(
        &self,
        sources: &[CatalogueContext<'_>],
    ) -> Result<(), WorkAuthorisationError> {
        if sources.len() > 3 {
            return Err(WorkAuthorisationError::Catalogue("source_count"));
        }
        for (index, source) in sources.iter().enumerate() {
            if sources
                .iter()
                .take(index)
                .any(|old| old.catalogue.os() == source.catalogue.os())
            {
                return Err(WorkAuthorisationError::Catalogue("duplicate_os"));
            }
        }
        let intent = self.intent().fields();
        for row in &intent.roles {
            let row = row.fields();
            let source = sources
                .iter()
                .find(|source| source.catalogue.os() == row.target_os)
                .ok_or(WorkAuthorisationError::Catalogue("missing_os"))?;
            let checkpoint = source.catalogue.checkpoint();
            if source.fleet_id != intent.fleet_id
                || source.tenant_node_id != intent.tenant_node_id
                || source.stream_id != row.stream_id
                || source.trust_sha256 != row.trust_sha256
                || source.catalogue.trust_sha256() != source.trust_sha256
                || checkpoint.bundle_version() != row.bundle_version
                || checkpoint.manifest_sha256() != row.manifest_sha256
            {
                return Err(WorkAuthorisationError::Catalogue("binding"));
            }
            let role = source
                .catalogue
                .roles()
                .get(&row.role_id)
                .ok_or(WorkAuthorisationError::Catalogue("role"))?;
            let hash = hex::decode(role.pin().sha256.trim())
                .map_err(|_| WorkAuthorisationError::Catalogue("slice_hash"))?;
            if role.pin().version != row.slice_version || hash.as_slice() != row.slice_sha256 {
                return Err(WorkAuthorisationError::Catalogue("slice"));
            }
            let bounds = role
                .issuance()
                .ok_or(WorkAuthorisationError::Catalogue("metadata"))?;
            if let Some(level) = row.codes_max_level {
                if bounds.codes().is_none_or(|cap| level > cap.max_level()) {
                    return Err(WorkAuthorisationError::Catalogue("codes_cap"));
                }
            }
            if let Some(label) = row.certificate {
                if !bounds.certificate().is_some_and(|cap| cap.covers(&label)) {
                    return Err(WorkAuthorisationError::Catalogue("certificate_cap"));
                }
            }
        }
        Ok(())
    }

    /// Pure Codes coverage. Never borrows a certificate bound or clamps a request.
    pub fn check_codes_coverage(
        &self,
        role: &RoleId,
        os: RoleOs,
        requested: u32,
    ) -> Result<(), WorkAuthorisationError> {
        let row = self.row(role, os)?;
        if row
            .codes_max_level
            .is_some_and(|cap| requested <= u32::from(cap))
        {
            Ok(())
        } else {
            Err(WorkAuthorisationError::Coverage("codes"))
        }
    }

    /// Pure signed-level/category-subset coverage; not a certificate issuance decision.
    pub fn check_certificate_coverage(
        &self,
        role: &RoleId,
        os: RoleOs,
        requested: IntegrityLabel,
    ) -> Result<(), WorkAuthorisationError> {
        let row = self.row(role, os)?;
        if row.certificate.is_some_and(|cap| cap.covers(&requested)) {
            Ok(())
        } else {
            Err(WorkAuthorisationError::Coverage("certificate"))
        }
    }

    fn row(&self, role: &RoleId, os: RoleOs) -> Result<&RoleBoundsFields, WorkAuthorisationError> {
        self.intent()
            .fields
            .roles
            .iter()
            .map(RoleBounds::fields)
            .find(|row| &row.role_id == role && row.target_os == os)
            .ok_or(WorkAuthorisationError::Coverage("role_os"))
    }
}

fn text(
    value: &str,
    maximum: usize,
    list: bool,
    field: &'static str,
) -> Result<(), WorkAuthorisationError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.nfc().eq(value.chars())
        || value
            .chars()
            .any(|c| c.is_control() || c == ';' || c == '=' || (list && c == ','))
    {
        return Err(WorkAuthorisationError::Invalid(field));
    }
    Ok(())
}

fn decode_hex(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<Vec<u8>, WorkAuthorisationError> {
    if value.len() > maximum * 2 {
        return Err(WorkAuthorisationError::Oversize(field));
    }
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(WorkAuthorisationError::Invalid(field));
    }
    hex::decode(value).map_err(|_| WorkAuthorisationError::Invalid(field))
}

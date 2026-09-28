//! Owner-signed bounded device-registration authority. Pure parsing and proof
//! checks do not establish that a source is currently published or rollback-safe.
//! Admission requires an exact checkpoint supplied by protected caller state.
pub(crate) mod codec;
use crate::{
    canon::{CanonError, Encoder},
    mac::sha256,
    registry::KeyProtection,
    signature::{Signature, SignatureError},
    time::ClaimedTime,
    wire::{self, WireError},
};
use codec::Reader;

/// Authority wire marker.
pub const AUTHORITY_PREFIX: &str = "tessera-codes/v1/device-registration-authority";
/// Signed authority body domain.
pub const AUTHORITY_DOMAIN: &str = "tessera-codes-contract/v1/device-registration-authority";
/// Immutable grant-core domain.
pub const GRANT_DOMAIN: &str = "tessera-codes-contract/v1/device-registration-grant";
/// The only initial registration profile.
pub const REGISTRATION_PROFILE: &str = "self-join-registration-v1";
/// Maximum complete authority wire size.
pub const MAX_AUTHORITY_WIRE: usize = 64 * 1024;
/// Maximum decoded authority body size.
pub const MAX_AUTHORITY_BODY: usize = 24 * 1024;
/// Maximum immutable grant-core size.
pub const MAX_GRANT_BYTES: usize = 2 * 1024;
/// Maximum grants in one current snapshot.
pub const MAX_GRANTS: usize = 16;

/// Parse, signature or context refusal; never an authorization success default.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// A closed format invariant failed.
    #[error("registration contract malformed: {0}")]
    Malformed(&'static str),
    /// Existing canonical encoder failure.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// Existing text-wire failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Cryptographic backend refused the proof/key.
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// Existing record/payload parser refusal.
    #[error(transparent)]
    Record(#[from] crate::registry::RecordError),
    /// Trusted context and the claim differ.
    #[error("registration context refused: {0}")]
    Context(&'static str),
}

/// Compressed P-256 point *shape*. Construction alone does not prove on-curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256PublicKey([u8; 33]);
impl P256PublicKey {
    /// Validate width/prefix; the verification backend must also validate curve membership.
    /// # Errors
    /// Rejects anything other than compressed SEC1 P-256 shape.
    pub fn new(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let bytes: [u8; 33] = bytes
            .try_into()
            .map_err(|_| AuthorityError::Malformed("P256 point width"))?;
        if !matches!(bytes.first(), Some(2 | 3)) {
            return Err(AuthorityError::Malformed("P256 compressed point prefix"));
        }
        Ok(Self(bytes))
    }
    /// Exact canonical compressed bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}
/// Real P-256 public-key arithmetic supplied by the consumer. No permissive
/// default exists. Implementations must reject off-curve/infinity points and
/// noncanonical DER/scalars, and verify ECDSA-SHA256 over the exact message.
pub trait P256SignatureVerifier {
    /// Validate the actual point, not merely its length and prefix.
    /// # Errors
    /// Rejects an invalid point or backend failure.
    fn validate_public_key(&self, key: &P256PublicKey) -> Result<(), SignatureError>;
    /// Verify exact-message P-256 ECDSA-SHA256 using this already scoped public key.
    /// # Errors
    /// Rejects invalid points/DER/scalars, wrong signatures or backend failures.
    fn verify_p256(
        &self,
        key: &P256PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError>;
}

/// Current owner-selected mode; absence of a grant is revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantMode {
    /// New registration and existing proof verification within signed bounds.
    Register,
    /// Existing proof verification only; no new registration.
    VerifyOnly,
}
impl GrantMode {
    /// Exact closed wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::VerifyOnly => "verify-only",
        }
    }
}
/// Inputs to an immutable grant. Times are explicit Unix seconds, never defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantFields {
    /// Nonzero lowercase canonical UUID.
    pub delegation_id: String,
    /// Exact registration node UUID.
    pub tenant_node_id: String,
    /// Existing named organisation identity.
    pub organisation_id: String,
    /// Owner-authorized delegate point, whose curve membership is checked by the backend.
    pub delegate_public_key: P256PublicKey,
    /// Positive custody key version.
    pub delegate_key_version: u64,
    /// Closed profile token.
    pub profile: String,
    /// Exact signed operator-policy body digest for new registration.
    pub operator_policy_digest: [u8; 32],
    /// Inclusive beginning of grant validity.
    pub not_before: u64,
    /// Exclusive new-registration deadline.
    pub register_until: u64,
    /// Exclusive existing-record verification deadline.
    pub verify_until: u64,
    /// Positive maximum record duration.
    pub max_record_lifetime_seconds: u64,
    /// Inclusive minimum key epoch.
    pub minimum_epoch: u32,
    /// Inclusive maximum key epoch.
    pub maximum_epoch: u32,
    /// Existing declared protection floor; not hardware attestation.
    pub key_protection_floor: KeyProtection,
    /// Whether explicitly evidenced replacement is within this grant.
    pub allow_replacement: bool,
}
/// Immutable owner-granted scope, independent of current mode/authority sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantCore {
    fields: GrantFields,
}
impl GrantCore {
    /// Validate a bounded immutable grant.
    /// # Errors
    /// Refuses malformed scope, profile, intervals, epochs or oversized encoding.
    pub fn new(fields: GrantFields) -> Result<Self, AuthorityError> {
        codec::uuid(&fields.delegation_id)?;
        codec::uuid(&fields.tenant_node_id)?;
        codec::text(&fields.organisation_id)?;
        if fields.delegate_key_version == 0
            || fields.profile != REGISTRATION_PROFILE
            || fields.not_before >= fields.register_until
            || fields.register_until > fields.verify_until
            || fields.max_record_lifetime_seconds == 0
            || fields.minimum_epoch > fields.maximum_epoch
        {
            return Err(AuthorityError::Malformed("grant bounds/profile"));
        }
        let result = Self { fields };
        if result.encode()?.len() > MAX_GRANT_BYTES {
            return Err(AuthorityError::Malformed("grant byte bound"));
        }
        Ok(result)
    }
    /// Immutable validated fields.
    #[must_use]
    pub const fn fields(&self) -> &GrantFields {
        &self.fields
    }
    /// Canonical body whose SHA256 identifies this immutable grant.
    /// # Errors
    /// Propagates canonical encoder bounds.
    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        let f = &self.fields;
        let mut e = Encoder::default();
        e.push_text("domain", GRANT_DOMAIN)?;
        for (name, value) in [
            ("delegation_id", &f.delegation_id),
            ("tenant_node_id", &f.tenant_node_id),
            ("organisation_id", &f.organisation_id),
        ] {
            e.push_text(name, value)?;
        }
        e.push_bytes("delegate_public_key", f.delegate_public_key.as_bytes())?;
        e.push_u64("delegate_key_version", f.delegate_key_version)?;
        e.push_text("profile", &f.profile)?;
        e.push_bytes("operator_policy_digest", &f.operator_policy_digest)?;
        for (name, value) in [
            ("not_before", f.not_before),
            ("register_until", f.register_until),
            ("verify_until", f.verify_until),
            ("max_record_lifetime_seconds", f.max_record_lifetime_seconds),
        ] {
            e.push_u64(name, value)?;
        }
        e.push_u32("minimum_epoch", f.minimum_epoch)?;
        e.push_u32("maximum_epoch", f.maximum_epoch)?;
        e.push_text("key_protection_floor", f.key_protection_floor.as_str())?;
        e.push_bytes("allow_replacement", &[u8::from(f.allow_replacement)])?;
        Ok(e.finish())
    }
    /// Digest excludes mutable current mode and authority sequence.
    /// # Errors
    /// Propagates canonical encoding failure.
    pub fn digest(&self) -> Result<[u8; 32], AuthorityError> {
        Ok(sha256(&self.encode()?))
    }
    fn parse(bytes: &[u8]) -> Result<Self, AuthorityError> {
        if bytes.len() > MAX_GRANT_BYTES {
            return Err(AuthorityError::Malformed("grant byte bound"));
        }
        let mut r = Reader::new(bytes);
        if r.string(128)? != GRANT_DOMAIN {
            return Err(AuthorityError::Malformed("grant domain"));
        }
        let fields = GrantFields {
            delegation_id: r.string(36)?,
            tenant_node_id: r.string(36)?,
            organisation_id: r.string(128)?,
            delegate_public_key: P256PublicKey::new(r.field(33)?)?,
            delegate_key_version: r.u64()?,
            profile: r.string(128)?,
            operator_policy_digest: r.digest()?,
            not_before: r.u64()?,
            register_until: r.u64()?,
            verify_until: r.u64()?,
            max_record_lifetime_seconds: r.u64()?,
            minimum_epoch: r.u32()?,
            maximum_epoch: r.u32()?,
            key_protection_floor: KeyProtection::parse(&r.string(64)?)
                .ok_or(AuthorityError::Malformed("protection floor"))?,
            allow_replacement: match r.field(1)? {
                [0] => false,
                [1] => true,
                _ => return Err(AuthorityError::Malformed("boolean")),
            },
        };
        r.finish()?;
        let result = Self::new(fields)?;
        if result.encode()? != bytes {
            return Err(AuthorityError::Malformed("grant canonical form"));
        }
        Ok(result)
    }
}
/// Immutable grant plus the current owner-signed mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityGrant {
    core: GrantCore,
    mode: GrantMode,
}
impl AuthorityGrant {
    /// Pair a validated grant core with an explicit mode.
    #[must_use]
    pub const fn new(core: GrantCore, mode: GrantMode) -> Self {
        Self { core, mode }
    }
    /// Immutable scope.
    #[must_use]
    pub const fn core(&self) -> &GrantCore {
        &self.core
    }
    /// Current signed mode.
    #[must_use]
    pub const fn mode(&self) -> GrantMode {
        self.mode
    }
}
/// Owner-signed authority body inputs. Grants must already be strictly ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFields {
    /// Expected fleet UUID.
    pub fleet_id: String,
    /// Pretrusted named owner identity, not a key locator.
    pub owner_id: String,
    /// Positive protected sequence.
    pub sequence: u64,
    /// Inclusive validity start.
    pub not_before: u64,
    /// Exclusive validity end.
    pub not_after: u64,
    /// At most16 unique grants sorted by delegation UUID.
    pub grants: Vec<AuthorityGrant>,
}
/// Validated canonical body, without an owner signature or currentness claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    fields: AuthorityFields,
}
impl AuthoritySnapshot {
    /// Construct a bounded canonical authority body.
    /// # Errors
    /// Rejects invalid scope, intervals, counts/order or encoded limits.
    pub fn new(fields: AuthorityFields) -> Result<Self, AuthorityError> {
        codec::uuid(&fields.fleet_id)?;
        codec::text(&fields.owner_id)?;
        if fields.sequence == 0
            || fields.not_before >= fields.not_after
            || fields.grants.len() > MAX_GRANTS
            || fields.grants.windows(2).any(|w| {
                w.first().zip(w.get(1)).is_some_and(|(a, b)| {
                    a.core.fields.delegation_id >= b.core.fields.delegation_id
                })
            })
        {
            return Err(AuthorityError::Malformed("authority bounds/order"));
        }
        let result = Self { fields };
        if result.encode()?.len() > MAX_AUTHORITY_BODY {
            return Err(AuthorityError::Malformed("authority body bound"));
        }
        Ok(result)
    }
    /// Immutable body fields.
    #[must_use]
    pub const fn fields(&self) -> &AuthorityFields {
        &self.fields
    }
    /// Canonical signed body; its digest excludes the ECDSA signature envelope.
    /// # Errors
    /// Propagates encoder limits.
    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        let f = &self.fields;
        let mut e = Encoder::default();
        e.push_text("domain", AUTHORITY_DOMAIN)?;
        e.push_text("fleet_id", &f.fleet_id)?;
        e.push_text("owner_id", &f.owner_id)?;
        e.push_u64("sequence", f.sequence)?;
        e.push_u64("not_before", f.not_before)?;
        e.push_u64("not_after", f.not_after)?;
        e.push_u32(
            "grant_count",
            u32::try_from(f.grants.len()).map_err(|_| AuthorityError::Malformed("grant count"))?,
        )?;
        for grant in &f.grants {
            e.push_bytes("grant_core", &grant.core.encode()?)?;
            e.push_text("mode", grant.mode.as_str())?;
        }
        Ok(e.finish())
    }
    /// Claimed checkpoint. This calculation alone authenticates nothing.
    /// # Errors
    /// Propagates canonical encoding failure.
    pub fn checkpoint(&self) -> Result<AuthorityCheckpoint, AuthorityError> {
        AuthorityCheckpoint::new(self.fields.sequence, sha256(&self.encode()?))
    }
    fn parse(bytes: &[u8]) -> Result<Self, AuthorityError> {
        if bytes.len() > MAX_AUTHORITY_BODY {
            return Err(AuthorityError::Malformed("authority body bound"));
        }
        let mut r = Reader::new(bytes);
        if r.string(128)? != AUTHORITY_DOMAIN {
            return Err(AuthorityError::Malformed("authority domain"));
        }
        let mut f = AuthorityFields {
            fleet_id: r.string(36)?,
            owner_id: r.string(128)?,
            sequence: r.u64()?,
            not_before: r.u64()?,
            not_after: r.u64()?,
            grants: Vec::new(),
        };
        let count = r.u32()?;
        if count > 16 {
            return Err(AuthorityError::Malformed("grant count"));
        }
        for _ in 0..count {
            let core = GrantCore::parse(r.field(MAX_GRANT_BYTES)?)?;
            let mode = match r.string(16)?.as_str() {
                "register" => GrantMode::Register,
                "verify-only" => GrantMode::VerifyOnly,
                _ => return Err(AuthorityError::Malformed("grant mode")),
            };
            f.grants.push(AuthorityGrant::new(core, mode));
        }
        r.finish()?;
        let result = Self::new(f)?;
        if result.encode()? != bytes {
            return Err(AuthorityError::Malformed("authority canonical form"));
        }
        Ok(result)
    }
}
/// Sequence and SHA256 canonical authority BODY; never a signature-envelope hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityCheckpoint {
    sequence: u64,
    body_digest: [u8; 32],
}
impl AuthorityCheckpoint {
    /// Restore a checkpoint from independently protected state.
    /// # Errors
    /// Refuses sequence0.
    pub fn new(sequence: u64, body_digest: [u8; 32]) -> Result<Self, AuthorityError> {
        if sequence == 0 {
            return Err(AuthorityError::Malformed("sequence"));
        }
        Ok(Self {
            sequence,
            body_digest,
        })
    }
    /// Protected sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Body identity, independent of alternate valid owner signatures.
    #[must_use]
    pub const fn body_digest(self) -> [u8; 32] {
        self.body_digest
    }
}
/// Authority body and separately carried owner proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAuthority {
    snapshot: AuthoritySnapshot,
    signature: Signature,
}
impl SignedAuthority {
    /// Attach a bounded canonical DER signature; this does not verify it.
    /// # Errors
    /// Rejects invalid signature/wire bounds.
    pub fn new(snapshot: AuthoritySnapshot, signature: Signature) -> Result<Self, AuthorityError> {
        codec::signature(signature.as_bytes())?;
        let result = Self {
            snapshot,
            signature,
        };
        if result.to_wire()?.len() > MAX_AUTHORITY_WIRE {
            return Err(AuthorityError::Malformed("authority wire bound"));
        }
        Ok(result)
    }
    /// Exact canonical snapshot body.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthoritySnapshot {
        &self.snapshot
    }
    /// Owner signature, outside checkpoint identity.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
    /// Render the closed authority envelope.
    /// # Errors
    /// Propagates body encoding failure.
    pub fn to_wire(&self) -> Result<String, AuthorityError> {
        Ok(wire::render(
            AUTHORITY_PREFIX,
            &[
                ("body", hex::encode(self.snapshot.encode()?)),
                ("owner_signature", hex::encode(self.signature.as_bytes())),
            ],
        ))
    }
    /// Parse exact canonical wire; no legacy whitespace/hex normalization.
    /// # Errors
    /// Rejects unknown/out-of-order fields, noncanonical forms or bounds.
    pub fn parse(text: &str) -> Result<Self, AuthorityError> {
        if text.len() > MAX_AUTHORITY_WIRE || text.trim() != text {
            return Err(AuthorityError::Malformed(
                "authority wire bound/canonical form",
            ));
        }
        let v = wire::parse(text, AUTHORITY_PREFIX, &["body", "owner_signature"])?;
        let body = codec::hex_bytes(wire::value(&v, 0), MAX_AUTHORITY_BODY)?;
        let result = Self::new(
            AuthoritySnapshot::parse(&body)?,
            codec::parse_signature(wire::value(&v, 1))?,
        )?;
        if result.to_wire()? != text {
            return Err(AuthorityError::Malformed("authority wire form"));
        }
        Ok(result)
    }
    /// Verify scope, time, all actual public points and owner signature. This
    /// returns a candidate only; runtime must protect/publish its checkpoint.
    /// # Errors
    /// Rejects malformed crypto, wrong pretrusted owner/scope or expired authority.
    pub fn verify_candidate(
        &self,
        trust: &AuthorityTrustContext<'_>,
        backend: &impl P256SignatureVerifier,
    ) -> Result<SignatureCheckedAuthority, AuthorityError> {
        check_scope(&self.snapshot, trust)?;
        backend.validate_public_key(trust.owner_key)?;
        for grant in &self.snapshot.fields.grants {
            backend.validate_public_key(&grant.core.fields.delegate_public_key)?;
        }
        backend.verify_p256(trust.owner_key, &self.snapshot.encode()?, &self.signature)?;
        Ok(SignatureCheckedAuthority {
            authority: self.clone(),
            owner_key: *trust.owner_key,
        })
    }
}
/// Independently supplied owner pin/scope/time. Never copy trust from the input.
pub struct AuthorityTrustContext<'a> {
    /// Configured fleet.
    pub fleet_id: &'a str,
    /// Configured owner identity.
    pub owner_id: &'a str,
    /// Actual independently pinned owner key.
    pub owner_key: &'a P256PublicKey,
    /// Caller-vouched current time.
    pub now: ClaimedTime,
}
/// Protected current-authority context required for every admission.
pub struct CurrentAuthorityContext<'a> {
    /// Independently configured trust and time.
    pub trust: AuthorityTrustContext<'a>,
    /// Exact accepted/published protected checkpoint, not a last-successful cache.
    pub checkpoint: AuthorityCheckpoint,
}
/// Cryptographic facts only, with actual owner-key provenance retained.
#[derive(Debug, Clone)]
pub struct SignatureCheckedAuthority {
    authority: SignedAuthority,
    owner_key: P256PublicKey,
}
impl SignatureCheckedAuthority {
    /// Verified candidate's body checkpoint, for a separate protected CAS.
    /// # Errors
    /// Propagates canonical encoding failure.
    pub fn checkpoint(&self) -> Result<AuthorityCheckpoint, AuthorityError> {
        self.authority.snapshot.checkpoint()
    }
    /// Require an exact caller-provided current checkpoint; never accept a
    /// larger sequence as implicitly current or mutate a floor here.
    /// # Errors
    /// Refuses changed owner, scope, time or checkpoint.
    pub fn require_current(
        &self,
        context: &CurrentAuthorityContext<'_>,
    ) -> Result<(), AuthorityError> {
        check_scope(&self.authority.snapshot, &context.trust)?;
        if self.owner_key != *context.trust.owner_key || self.checkpoint()? != context.checkpoint {
            return Err(AuthorityError::Context(
                "authority is not the protected current checkpoint",
            ));
        }
        Ok(())
    }
    pub(crate) fn grant(
        &self,
        id: &str,
        context: &CurrentAuthorityContext<'_>,
    ) -> Result<&AuthorityGrant, AuthorityError> {
        self.require_current(context)?;
        self.authority
            .snapshot
            .fields
            .grants
            .iter()
            .find(|g| g.core.fields.delegation_id == id)
            .ok_or(AuthorityError::Context("grant absent or revoked"))
    }
    /// Check a selected immutable grant for a new registration, not a generic
    /// signing permission. Protected approval/custody checks remain external.
    /// # Errors
    /// Refuses verify-only, changed policy/key/scope, time, epoch or replacement.
    pub fn registration_grant(
        &self,
        id: &str,
        current: &CurrentAuthorityContext<'_>,
        request: &RegistrationContext<'_>,
    ) -> Result<&GrantCore, AuthorityError> {
        let grant = self.grant(id, current)?;
        let f = &grant.core.fields;
        let now = current.trust.now.get();
        if grant.mode != GrantMode::Register
            || request.tenant_node_id != f.tenant_node_id
            || request.organisation_id != f.organisation_id
            || request.delegate_public_key != &f.delegate_public_key
            || request.delegate_key_version != f.delegate_key_version
            || request.operator_policy_digest != f.operator_policy_digest
            || now < f.not_before
            || now >= f.register_until
            || request.epoch < f.minimum_epoch
            || request.epoch > f.maximum_epoch
            || !request.key_protection.is_at_least(f.key_protection_floor)
            || request.replacement && !f.allow_replacement
        {
            return Err(AuthorityError::Context("registration outside grant"));
        }
        Ok(&grant.core)
    }
}
/// Independently verified facts of a proposed registration.
pub struct RegistrationContext<'a> {
    /// Configured node UUID.
    pub tenant_node_id: &'a str,
    /// Verified organisation identity.
    pub organisation_id: &'a str,
    /// Actual custody public point, not a key path or caller label.
    pub delegate_public_key: &'a P256PublicKey,
    /// Actual custody key version.
    pub delegate_key_version: u64,
    /// Current approved operator policy digest.
    pub operator_policy_digest: [u8; 32],
    /// Device epoch.
    pub epoch: u32,
    /// Existing declared key-protection rung.
    pub key_protection: KeyProtection,
    /// Explicit verified replacement mode.
    pub replacement: bool,
}
fn check_scope(
    snapshot: &AuthoritySnapshot,
    trust: &AuthorityTrustContext<'_>,
) -> Result<(), AuthorityError> {
    let f = &snapshot.fields;
    codec::uuid(trust.fleet_id)?;
    codec::text(trust.owner_id)?;
    if f.fleet_id != trust.fleet_id
        || f.owner_id != trust.owner_id
        || trust.now.get() < f.not_before
        || trust.now.get() >= f.not_after
    {
        return Err(AuthorityError::Context("owner/fleet/time"));
    }
    Ok(())
}

use super::{
    check_scope, check_time, codec, domain, envelope, parse_envelope, sha256, AuthorityError,
    AuthorityTrustContext, BaselineIdentity, BaselineInventory, Encoder, P256PublicKey,
    ProtectedActivationCut, Reader, Signature, MAX_BODY, MAX_ENTRIES, MAX_INVENTORY,
};
use crate::registration_authority::P256SignatureVerifier;

/// Baseline envelope marker.
pub const BASELINE_PREFIX: &str = "tessera-codes/v1/registry-baseline";
/// Signed baseline body domain.
pub const BASELINE_DOMAIN: &str = "tessera-codes-contract/v1/registry-baseline";
/// Explicit owner assertion; an absent file never represents an empty registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// No previous registrations in this fleet scope, including retired numbers.
    EmptyHistory,
    /// Complete current heads and historical-number tombstones, with at least one row.
    CompleteHistory,
}
impl Completeness {
    /// Frozen wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyHistory => "empty-history",
            Self::CompleteHistory => "complete-history",
        }
    }
}
/// Explicit caller input to an immutable owner-signed baseline manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineFields {
    /// Configured nonzero fleet UUID.
    pub fleet_id: String,
    /// Existing independently trusted owner identity.
    pub owner_id: String,
    /// Unique baseline UUID.
    pub baseline_id: String,
    /// Exact independently protected quiesced activation cut.
    pub cut: ProtectedActivationCut,
    /// Inclusive bootstrap acceptance time; not a default or clock read.
    pub not_before: u64,
    /// Exclusive bootstrap acceptance deadline; committed state does not expire with this window.
    pub accept_until: u64,
    /// Explicit completeness assertion.
    pub completeness: Completeness,
}
/// Immutable signed-body shape. It authenticates only after real signature checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineManifest {
    fields: BaselineFields,
    entry_count: u32,
    inventory_length: u64,
    inventory_digest: [u8; 32],
}
impl BaselineManifest {
    /// Bind the exact canonical inventory artifact and its count/length.
    /// # Errors
    /// Rejects scope/time/completeness mismatch or encoding bounds.
    pub fn new(
        fields: BaselineFields,
        inventory: &BaselineInventory,
    ) -> Result<Self, AuthorityError> {
        let bytes = inventory.encode()?;
        let count = u32::try_from(inventory.entries().len())
            .map_err(|_| AuthorityError::Malformed("inventory count"))?;
        let length = u64::try_from(bytes.len())
            .map_err(|_| AuthorityError::Malformed("inventory length"))?;
        Self::parts(fields, count, length, sha256(&bytes))
    }
    fn parts(
        fields: BaselineFields,
        entry_count: u32,
        inventory_length: u64,
        inventory_digest: [u8; 32],
    ) -> Result<Self, AuthorityError> {
        codec::uuid(&fields.fleet_id)?;
        codec::uuid(&fields.baseline_id)?;
        codec::text(&fields.owner_id)?;
        if fields.not_before >= fields.accept_until
            || usize::try_from(entry_count).map_or(true, |n| n > MAX_ENTRIES)
            || usize::try_from(inventory_length).map_or(true, |n| n == 0 || n > MAX_INVENTORY)
            || (entry_count == 0) != (fields.completeness == Completeness::EmptyHistory)
        {
            return Err(AuthorityError::Malformed("baseline bounds/completeness"));
        }
        let result = Self {
            fields,
            entry_count,
            inventory_length,
            inventory_digest,
        };
        result.encode()?;
        Ok(result)
    }
    /// Immutable signed fields.
    #[must_use]
    pub const fn fields(&self) -> &BaselineFields {
        &self.fields
    }
    /// Declared exact inventory entry count.
    #[must_use]
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }
    /// Declared exact binary inventory length.
    #[must_use]
    pub const fn inventory_length(&self) -> u64 {
        self.inventory_length
    }
    /// SHA256 of complete canonical binary inventory bytes.
    #[must_use]
    pub const fn inventory_digest(&self) -> [u8; 32] {
        self.inventory_digest
    }
    /// Canonical signed body, excluding ECDSA envelope bytes.
    /// # Errors
    /// Rejects canonical encoder overflow or body bounds.
    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        let mut e = Encoder::default();
        let f = &self.fields;
        e.push_text("domain", BASELINE_DOMAIN)?;
        e.push_text("fleet", &f.fleet_id)?;
        e.push_text("owner", &f.owner_id)?;
        e.push_text("baseline", &f.baseline_id)?;
        f.cut.encode(&mut e)?;
        e.push_u64("not_before", f.not_before)?;
        e.push_u64("accept_until", f.accept_until)?;
        e.push_text("completeness", f.completeness.as_str())?;
        e.push_u32("count", self.entry_count)?;
        e.push_u64("inventory_length", self.inventory_length)?;
        e.push_bytes("inventory_digest", &self.inventory_digest)?;
        let result = e.finish();
        if result.len() > MAX_BODY {
            return Err(AuthorityError::Malformed("baseline body bound"));
        }
        Ok(result)
    }
    fn parse(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let mut r = Reader::new(bytes);
        domain(&mut r, BASELINE_DOMAIN)?;
        let fleet_id = r.string(36)?;
        let owner_id = r.string(128)?;
        let baseline_id = r.string(36)?;
        let cut = ProtectedActivationCut::parse(&mut r)?;
        let not_before = r.u64()?;
        let accept_until = r.u64()?;
        let completeness = match r.string(32)?.as_str() {
            "empty-history" => Completeness::EmptyHistory,
            "complete-history" => Completeness::CompleteHistory,
            _ => return Err(AuthorityError::Malformed("baseline completeness")),
        };
        let count = r.u32()?;
        let length = r.u64()?;
        let digest = r.digest()?;
        r.finish()?;
        let result = Self::parts(
            BaselineFields {
                fleet_id,
                owner_id,
                baseline_id,
                cut,
                not_before,
                accept_until,
                completeness,
            },
            count,
            length,
            digest,
        )?;
        if result.encode()? != bytes {
            return Err(AuthorityError::Malformed("baseline body form"));
        }
        Ok(result)
    }
}
/// Owner signature envelope for a complete initial inventory manifest.
#[derive(Debug, Clone)]
pub struct SignedBaseline {
    manifest: BaselineManifest,
    signature: Signature,
}
impl SignedBaseline {
    /// Attach bounded DER without authenticating it.
    /// # Errors
    /// Rejects signature/envelope bounds.
    pub fn new(manifest: BaselineManifest, signature: Signature) -> Result<Self, AuthorityError> {
        let result = Self {
            manifest,
            signature,
        };
        result.to_wire()?;
        Ok(result)
    }
    /// Exact manifest, not mutable through this envelope.
    #[must_use]
    pub const fn manifest(&self) -> &BaselineManifest {
        &self.manifest
    }
    /// Exact owner signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
    /// Serialize the canonical owner-signed text envelope.
    /// # Errors
    /// Rejects encoder/envelope bounds.
    pub fn to_wire(&self) -> Result<String, AuthorityError> {
        envelope(BASELINE_PREFIX, &self.manifest.encode()?, &self.signature)
    }
    /// Parse bounded canonical syntax; does not accept a registry or verify its owner.
    /// # Errors
    /// Rejects unknown/noncanonical/malformed fields.
    pub fn parse(text: &str) -> Result<Self, AuthorityError> {
        let (body, signature) = parse_envelope(text, BASELINE_PREFIX)?;
        Self::new(BaselineManifest::parse(&body)?, signature)
    }
    /// Verify actual pinned owner point/signature, scope and exact inventory.
    /// Historical replay remains possible after the bootstrap window; only
    /// `check_initialisation` can validate a fresh initialization proposal.
    /// # Errors
    /// Rejects wrong proof/scope or inventory count/hash/length mismatch.
    pub fn verify_candidate(
        &self,
        inventory: &BaselineInventory,
        trust: &AuthorityTrustContext<'_>,
        backend: &impl P256SignatureVerifier,
    ) -> Result<SignatureCheckedBaseline, AuthorityError> {
        let m = &self.manifest;
        check_scope(&m.fields.fleet_id, &m.fields.owner_id, trust)?;
        let bytes = inventory.encode()?;
        if u64::try_from(bytes.len()).ok() != Some(m.inventory_length)
            || u32::try_from(inventory.entries().len()).ok() != Some(m.entry_count)
            || sha256(&bytes) != m.inventory_digest
        {
            return Err(AuthorityError::Context("baseline inventory binding"));
        }
        backend.validate_public_key(trust.owner_key)?;
        backend.verify_p256(trust.owner_key, &m.encode()?, &self.signature)?;
        Ok(SignatureCheckedBaseline {
            signed: self.clone(),
            inventory: inventory.clone(),
            owner_key: *trust.owner_key,
        })
    }
}
/// Bootstrap state supplied by the independently protected runtime, not SQL or the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapState {
    /// No baseline has ever been installed at this registry instance.
    Uninitialised,
    /// Already initialized; even a valid different owner baseline cannot reset it.
    Installed,
}
/// Independent context for a proposal to initialize protected state.
pub struct BootstrapContext<'a> {
    /// Fresh independently configured scope/key/time.
    pub trust: AuthorityTrustContext<'a>,
    /// Exact still-held protected writer barrier.
    pub cut: &'a ProtectedActivationCut,
    /// Protected initialization status.
    pub state: BootstrapState,
}
/// Immutable cryptographic candidate; no protected registry has been installed by this value.
#[derive(Debug, Clone)]
pub struct SignatureCheckedBaseline {
    signed: SignedBaseline,
    inventory: BaselineInventory,
    owner_key: P256PublicKey,
}
impl SignatureCheckedBaseline {
    /// Authenticated historical rows, never an ongoing currentness/absence source.
    #[must_use]
    pub const fn inventory(&self) -> &BaselineInventory {
        &self.inventory
    }
    /// Actual verified owner identity and exact signed body identity.
    /// # Errors
    /// Propagates bounded canonical encoding errors.
    pub fn identity(&self) -> Result<BaselineIdentity, AuthorityError> {
        let m = &self.signed.manifest;
        let f = &m.fields;
        BaselineIdentity::new(
            f.fleet_id.clone(),
            f.owner_id.clone(),
            self.owner_key,
            f.baseline_id.clone(),
            sha256(&m.encode()?),
            f.cut.clone(),
        )
    }
    /// Check a fresh initialization proposal. Caller must CAS the same cut/state while
    /// retaining its writer fence; this method does not install state or prove completeness.
    /// # Errors
    /// Refuses installed state, changed cut/owner/scope or expired admission window.
    pub fn check_initialisation(
        &self,
        context: &BootstrapContext<'_>,
    ) -> Result<BaselineIdentity, AuthorityError> {
        let f = &self.signed.manifest.fields;
        check_scope(&f.fleet_id, &f.owner_id, &context.trust)?;
        check_time(f.not_before, f.accept_until, context.trust.now.get())?;
        if self.owner_key != *context.trust.owner_key
            || context.cut != &f.cut
            || context.state != BootstrapState::Uninitialised
        {
            return Err(AuthorityError::Context(
                "baseline initialization state/cut/owner",
            ));
        }
        self.identity()
    }
}

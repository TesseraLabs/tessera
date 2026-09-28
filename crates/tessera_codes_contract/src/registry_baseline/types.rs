use super::{codec, AuthorityError, Encoder, P256PublicKey, Reader};

/// Existing exact signed-record digest recipes, not interchangeable hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDigestKind {
    /// SHA256 of the exact retained direct-v1 wire bytes.
    DirectV1WireSha256,
    /// Existing delegated v2 `record_digest`: framed proof message AND actual signature.
    DelegatedV2CurrentDigest,
}
impl RecordDigestKind {
    /// Frozen wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectV1WireSha256 => "direct-v1-wire-sha256",
            Self::DelegatedV2CurrentDigest => "delegated-v2-current-digest",
        }
    }
    pub(super) fn parse(text: &str) -> Result<Self, AuthorityError> {
        match text {
            "direct-v1-wire-sha256" => Ok(Self::DirectV1WireSha256),
            "delegated-v2-current-digest" => Ok(Self::DelegatedV2CurrentDigest),
            _ => Err(AuthorityError::Malformed("record digest kind")),
        }
    }
}
/// Exact record identity at a positive protected-index generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryHead {
    generation: u64,
    kind: RecordDigestKind,
    pub(super) digest: [u8; 32],
}
impl RegistryHead {
    /// Restore a caller-trusted head; this validates shape, not protected provenance.
    /// # Errors
    /// Rejects generation zero.
    pub fn new(
        generation: u64,
        kind: RecordDigestKind,
        digest: [u8; 32],
    ) -> Result<Self, AuthorityError> {
        if generation == 0 {
            return Err(AuthorityError::Malformed("head generation"));
        }
        Ok(Self {
            generation,
            kind,
            digest,
        })
    }
    /// Protected-index generation, not a historical v1 registration count.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Exact digest recipe.
    #[must_use]
    pub const fn kind(self) -> RecordDigestKind {
        self.kind
    }
    /// Exact retained record digest.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}
/// Quiesced activation barrier supplied by protected runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedActivationCut {
    registry_instance_id: String,
    barrier_id: String,
    sequence: u64,
    digest: [u8; 32],
}
impl ProtectedActivationCut {
    /// Restore a barrier; the caller must hold its writer fence through initialization CAS.
    /// Sequence zero permits an independently defined journal genesis.
    /// # Errors
    /// Rejects malformed UUIDs. Does not attest the fence or journal.
    pub fn new(
        registry_instance_id: String,
        barrier_id: String,
        sequence: u64,
        digest: [u8; 32],
    ) -> Result<Self, AuthorityError> {
        codec::uuid(&registry_instance_id)?;
        codec::uuid(&barrier_id)?;
        Ok(Self {
            registry_instance_id,
            barrier_id,
            sequence,
            digest,
        })
    }
    /// Independently protected registry instance UUID.
    #[must_use]
    pub fn registry_instance_id(&self) -> &str {
        &self.registry_instance_id
    }
    /// Unique protected activation barrier UUID.
    #[must_use]
    pub fn barrier_id(&self) -> &str {
        &self.barrier_id
    }
    /// Exact quiesced journal sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact journal head digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(super) fn encode(&self, e: &mut Encoder) -> Result<(), AuthorityError> {
        e.push_text("registry_instance", &self.registry_instance_id)?;
        e.push_text("barrier", &self.barrier_id)?;
        e.push_u64("cut_sequence", self.sequence)?;
        e.push_bytes("cut_digest", &self.digest)?;
        Ok(())
    }
    pub(super) fn parse(r: &mut Reader<'_>) -> Result<Self, AuthorityError> {
        Self::new(r.string(36)?, r.string(36)?, r.u64()?, r.digest()?)
    }
}
/// Independently protected baseline identity, restored from committed runtime state.
/// Construction validates shape only; never copy this trust context from an import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineIdentity {
    pub(super) fleet_id: String,
    pub(super) owner_id: String,
    pub(super) owner_key: P256PublicKey,
    pub(super) baseline_id: String,
    pub(super) body_digest: [u8; 32],
    pub(super) cut: ProtectedActivationCut,
}
impl BaselineIdentity {
    /// Restore a protected identity. Actual owner point is checked during cryptographic admission.
    /// # Errors
    /// Rejects malformed scope identifiers.
    pub fn new(
        fleet_id: String,
        owner_id: String,
        owner_key: P256PublicKey,
        baseline_id: String,
        body_digest: [u8; 32],
        cut: ProtectedActivationCut,
    ) -> Result<Self, AuthorityError> {
        codec::uuid(&fleet_id)?;
        codec::uuid(&baseline_id)?;
        codec::text(&owner_id)?;
        Ok(Self {
            fleet_id,
            owner_id,
            owner_key,
            baseline_id,
            body_digest,
            cut,
        })
    }
    /// Exact owner-authenticated manifest body digest, excluding its signature envelope.
    #[must_use]
    pub const fn body_digest(&self) -> [u8; 32] {
        self.body_digest
    }
    /// Baseline UUID.
    #[must_use]
    pub fn baseline_id(&self) -> &str {
        &self.baseline_id
    }
    /// Fleet scope.
    #[must_use]
    pub fn fleet_id(&self) -> &str {
        &self.fleet_id
    }
    /// Named owner scope.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }
    /// Actual owner key provenance.
    #[must_use]
    pub const fn owner_key(&self) -> P256PublicKey {
        self.owner_key
    }
    /// Activation checkpoint bound by the owner.
    #[must_use]
    pub const fn cut(&self) -> &ProtectedActivationCut {
        &self.cut
    }
}

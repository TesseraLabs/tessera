use super::{
    check_scope, check_time, codec, domain, envelope, parse_envelope, sha256, AuthorityError,
    AuthorityTrustContext, BaselineIdentity, Encoder, Reader, RecordDigestKind, RegistryHead,
    Signature, MAX_BODY, MAX_IMPORT_RECORD,
};
use crate::{
    device_number::CheckedDeviceNumber, registration_authority::P256SignatureVerifier,
    registry::DeviceRecord, signature::SignatureVerifier,
};

/// Owner import envelope marker; does not replace existing direct-v1 record bytes.
pub const IMPORT_PREFIX: &str = "tessera-codes/v1/registry-import";
/// Exact signed owner import domain.
pub const IMPORT_DOMAIN: &str = "tessera-codes-contract/v1/registry-import";
/// Owner-selected predecessor precondition for one ordered import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedHead {
    /// Confirmed no completed historical registration, under a complete protected baseline.
    Absent,
    /// Exact currently published record.
    Current(RegistryHead),
    /// Exact retained retired record; missing predecessor requires separate controlled repair.
    Retired(RegistryHead),
}
impl ExpectedHead {
    fn parts(self) -> (&'static str, Option<RegistryHead>) {
        match self {
            Self::Absent => ("absent", None),
            Self::Current(h) => ("current", Some(h)),
            Self::Retired(h) => ("retired", Some(h)),
        }
    }
    fn encode(self, e: &mut Encoder) -> Result<(), AuthorityError> {
        let (state, head) = self.parts();
        e.push_text("expected_state", state)?;
        e.push_u64(
            "expected_generation",
            head.map_or(0, RegistryHead::generation),
        )?;
        e.push_text("expected_kind", head.map_or("none", |h| h.kind().as_str()))?;
        e.push_bytes(
            "expected_digest",
            head.as_ref().map_or(&[][..], |h| &h.digest),
        )?;
        Ok(())
    }
    fn parse(r: &mut Reader<'_>) -> Result<Self, AuthorityError> {
        let state = r.string(16)?;
        let generation = r.u64()?;
        let kind = r.string(32)?;
        let digest = r.field(32)?;
        match (state.as_str(), generation, kind.as_str(), digest) {
            ("absent", 0, "none", []) => Ok(Self::Absent),
            ("current" | "retired", _, _, _) => {
                let digest = digest
                    .try_into()
                    .map_err(|_| AuthorityError::Malformed("import predecessor digest"))?;
                let head = RegistryHead::new(generation, RecordDigestKind::parse(&kind)?, digest)?;
                Ok(if state == "current" {
                    Self::Current(head)
                } else {
                    Self::Retired(head)
                })
            }
            _ => Err(AuthorityError::Malformed("import predecessor")),
        }
    }
}
/// Explicit owner-signed import inputs. None of these fields is trusted runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFields {
    /// Nonzero canonical fleet UUID.
    pub fleet_id: String,
    /// Independently named owner.
    pub owner_id: String,
    /// Exact installed baseline UUID.
    pub baseline_id: String,
    /// Exact owner-signed baseline BODY identity.
    pub baseline_body_digest: [u8; 32],
    /// Independently protected registry instance UUID.
    pub registry_instance_id: String,
    /// Unique owner operation UUID, consumed durably by the runtime.
    pub operation_id: String,
    /// Canonical significant number identity.
    pub number: CheckedDeviceNumber,
    /// Existing registration node UUID.
    pub node_id: String,
    /// Existing organisation identifier.
    pub organisation_id: String,
    /// Inclusive admission time.
    pub not_before: u64,
    /// Exclusive admission deadline; no production default.
    pub not_after: u64,
    /// Exact predecessor, not an editable currentness flag.
    pub expected: ExpectedHead,
    /// SHA256 of the exact carried direct-v1 wire bytes, without rewriting signatures.
    pub new_record_digest: [u8; 32],
}
/// Immutable canonical owner import body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryImport {
    fields: ImportFields,
}
impl RegistryImport {
    /// Construct a bounded import claim; does not authorize its predecessor or nonce.
    /// # Errors
    /// Rejects invalid scope/time/number or byte bounds.
    pub fn new(mut fields: ImportFields) -> Result<Self, AuthorityError> {
        for id in [
            &fields.fleet_id,
            &fields.baseline_id,
            &fields.registry_instance_id,
            &fields.operation_id,
            &fields.node_id,
        ] {
            codec::uuid(id)?;
        }
        codec::text(&fields.owner_id)?;
        codec::text(&fields.organisation_id)?;
        if fields.not_before >= fields.not_after || fields.number.significant().len() > 32 {
            return Err(AuthorityError::Malformed("import time/number"));
        }
        fields.number = CheckedDeviceNumber::parse(fields.number.significant())
            .map_err(|_| AuthorityError::Malformed("import number"))?;
        let result = Self { fields };
        result.encode()?;
        Ok(result)
    }
    /// Immutable owner claims.
    #[must_use]
    pub const fn fields(&self) -> &ImportFields {
        &self.fields
    }
    /// Canonical signed body.
    /// # Errors
    /// Rejects encoding/body bounds.
    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        let mut e = Encoder::default();
        let f = &self.fields;
        e.push_text("domain", IMPORT_DOMAIN)?;
        e.push_text("fleet", &f.fleet_id)?;
        e.push_text("owner", &f.owner_id)?;
        e.push_text("baseline", &f.baseline_id)?;
        e.push_bytes("baseline_digest", &f.baseline_body_digest)?;
        e.push_text("instance", &f.registry_instance_id)?;
        e.push_text("operation", &f.operation_id)?;
        e.push_text("number", f.number.significant())?;
        e.push_text("node", &f.node_id)?;
        e.push_text("organisation", &f.organisation_id)?;
        e.push_u64("not_before", f.not_before)?;
        e.push_u64("not_after", f.not_after)?;
        f.expected.encode(&mut e)?;
        e.push_bytes("new_record_digest", &f.new_record_digest)?;
        let bytes = e.finish();
        if bytes.len() > MAX_BODY {
            return Err(AuthorityError::Malformed("import body bound"));
        }
        Ok(bytes)
    }
    fn parse(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let mut r = Reader::new(bytes);
        domain(&mut r, IMPORT_DOMAIN)?;
        let fleet_id = r.string(36)?;
        let owner_id = r.string(128)?;
        let baseline_id = r.string(36)?;
        let baseline_body_digest = r.digest()?;
        let registry_instance_id = r.string(36)?;
        let operation_id = r.string(36)?;
        let number_text = r.string(32)?;
        let number = CheckedDeviceNumber::parse(&number_text)
            .map_err(|_| AuthorityError::Malformed("import number"))?;
        if number.significant() != number_text {
            return Err(AuthorityError::Malformed("import number form"));
        }
        let node_id = r.string(36)?;
        let organisation_id = r.string(128)?;
        let not_before = r.u64()?;
        let not_after = r.u64()?;
        let expected = ExpectedHead::parse(&mut r)?;
        let new_record_digest = r.digest()?;
        r.finish()?;
        let result = Self::new(ImportFields {
            fleet_id,
            owner_id,
            baseline_id,
            baseline_body_digest,
            registry_instance_id,
            operation_id,
            number,
            node_id,
            organisation_id,
            not_before,
            not_after,
            expected,
            new_record_digest,
        })?;
        if result.encode()? != bytes {
            return Err(AuthorityError::Malformed("import body form"));
        }
        Ok(result)
    }
}
/// Fresh protected number state supplied by the consumer, never copied from the companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedNumberState {
    /// Complete protected history confirms no completed registration for this number.
    Absent,
    /// Exact currently published head.
    Current(RegistryHead),
    /// Exact retained retired head.
    Retired(RegistryHead),
    /// Historical number whose predecessor is unavailable; refuses this import helper.
    RetiredUnknown,
    /// A protected plan already reserves this number.
    Reserved,
    /// Protected state is unavailable or not initialized; not absence.
    Unavailable,
}
impl ProtectedNumberState {
    fn matches(self, expected: ExpectedHead) -> bool {
        match (self, expected) {
            (Self::Absent, ExpectedHead::Absent) => true,
            (Self::Current(a), ExpectedHead::Current(b))
            | (Self::Retired(a), ExpectedHead::Retired(b)) => a == b,
            _ => false,
        }
    }
}
/// Nonce status from protected state for the exact queried operation UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    /// No committed/reserved use of the operation UUID.
    Unseen,
    /// Already consumed or reserved; never returns new transition authority.
    Seen,
}
/// Independent protected context required for an ordered import proposal.
pub struct ImportContext<'a> {
    /// Independently pinned current owner/fleet/time.
    pub trust: AuthorityTrustContext<'a>,
    /// Exact protected installed baseline identity.
    pub baseline: &'a BaselineIdentity,
    /// Actual number whose protected state was read.
    pub number: &'a CheckedDeviceNumber,
    /// Node read with the protected current row; for confirmed absence, the
    /// independently configured registration node. Never copy the import claim.
    pub node_id: &'a str,
    /// Organisation read with the protected row (or independently configured
    /// for absence), with its existing trusted chain checks.
    pub organisation_id: &'a str,
    /// Exact operation UUID queried in protected nonce state.
    pub operation_id: &'a str,
    /// Fresh protected number state.
    pub number_state: ProtectedNumberState,
    /// Highest allocated generation, including failed possibly signed attempts.
    pub last_allocated_generation: u64,
    /// Protected nonce state for `operation_id`.
    pub operation_state: OperationState,
}
/// Owner signature on an ordered direct-v1 import, separate from the old record wire.
#[derive(Debug, Clone)]
pub struct SignedRegistryImport {
    import: RegistryImport,
    signature: Signature,
}
impl SignedRegistryImport {
    /// Attach bounded DER; verification is separate.
    /// # Errors
    /// Rejects signature/envelope bounds.
    pub fn new(import: RegistryImport, signature: Signature) -> Result<Self, AuthorityError> {
        let result = Self { import, signature };
        result.to_wire()?;
        Ok(result)
    }
    /// Immutable owner-signed import body.
    #[must_use]
    pub const fn import(&self) -> &RegistryImport {
        &self.import
    }
    /// Exact owner signature.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
    /// Frozen canonical text envelope.
    /// # Errors
    /// Rejects encoding/envelope bounds.
    pub fn to_wire(&self) -> Result<String, AuthorityError> {
        envelope(IMPORT_PREFIX, &self.import.encode()?, &self.signature)
    }
    /// Parse bounded exact syntax; does not consume a nonce or authorize currentness.
    /// # Errors
    /// Rejects malformed/unknown/noncanonical data.
    pub fn parse(text: &str) -> Result<Self, AuthorityError> {
        let (body, signature) = parse_envelope(text, IMPORT_PREFIX)?;
        Self::new(RegistryImport::parse(&body)?, signature)
    }
    /// Verify an ordered transition proposal, including unchanged direct-v1 proofs.
    /// Caller must atomically consume the nonce and CAS the same head/allocation/
    /// reservation state. This method does not enforce those durable operations.
    /// Existing organisation-chain, approval and replacement-stop rules remain prerequisites.
    /// # Errors
    /// Refuses scope, time, proof, exact-byte, predecessor, nonce or generation mismatch.
    pub fn verify_transition(
        &self,
        record_bytes: &[u8],
        context: &ImportContext<'_>,
        backend: &(impl P256SignatureVerifier + SignatureVerifier),
    ) -> Result<VerifiedRegistryImport, AuthorityError> {
        let f = &self.import.fields;
        let b = context.baseline;
        check_scope(&f.fleet_id, &f.owner_id, &context.trust)?;
        check_time(f.not_before, f.not_after, context.trust.now.get())?;
        if b.fleet_id != f.fleet_id
            || b.owner_id != f.owner_id
            || b.owner_key != *context.trust.owner_key
            || b.baseline_id != f.baseline_id
            || b.body_digest != f.baseline_body_digest
            || b.cut.registry_instance_id() != f.registry_instance_id
            || context.number.significant() != f.number.significant()
            || context.node_id != f.node_id
            || context.organisation_id != f.organisation_id
            || context.operation_id != f.operation_id
            || context.operation_state != OperationState::Unseen
            || !context.number_state.matches(f.expected)
        {
            return Err(AuthorityError::Context(
                "import protected scope/predecessor/operation",
            ));
        }
        let predecessor_generation = f.expected.parts().1.map_or(0, RegistryHead::generation);
        if context.last_allocated_generation < predecessor_generation {
            return Err(AuthorityError::Context("import allocation floor"));
        }
        let generation = context
            .last_allocated_generation
            .checked_add(1)
            .ok_or(AuthorityError::Context("import generation overflow"))?;
        if record_bytes.len() > MAX_IMPORT_RECORD || sha256(record_bytes) != f.new_record_digest {
            return Err(AuthorityError::Context("import exact record bytes"));
        }
        let text = core::str::from_utf8(record_bytes)
            .map_err(|_| AuthorityError::Malformed("import record UTF8"))?;
        let record = DeviceRecord::parse(text)?;
        if record.device_number().significant() != f.number.significant()
            || record.organisation_id() != f.organisation_id
            || record.owner_id() != f.owner_id
        {
            return Err(AuthorityError::Context("import record scope"));
        }
        backend.validate_public_key(context.trust.owner_key)?;
        backend.verify_p256(
            context.trust.owner_key,
            &self.import.encode()?,
            &self.signature,
        )?;
        // Direct-v1 device keys retain their existing verifier/curve semantics;
        // only the new owner's baseline/import profile is restricted to P-256.
        record.verify(backend)?;
        backend.verify_p256(
            context.trust.owner_key,
            &record.owner_message()?,
            record.owner_signature(),
        )?;
        Ok(VerifiedRegistryImport {
            baseline: b.clone(),
            number: f.number.clone(),
            node_id: f.node_id.clone(),
            organisation_id: f.organisation_id.clone(),
            operation_id: f.operation_id.clone(),
            body_digest: sha256(&self.import.encode()?),
            expected: f.expected,
            previous_allocation_floor: context.last_allocated_generation,
            new_head: RegistryHead::new(
                generation,
                RecordDigestKind::DirectV1WireSha256,
                f.new_record_digest,
            )?,
        })
    }
}
/// Immutable verified proposal, not a committed record or persistent replay protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistryImport {
    baseline: BaselineIdentity,
    number: CheckedDeviceNumber,
    node_id: String,
    organisation_id: String,
    operation_id: String,
    body_digest: [u8; 32],
    expected: ExpectedHead,
    previous_allocation_floor: u64,
    new_head: RegistryHead,
}
impl VerifiedRegistryImport {
    /// Independently checked protected baseline identity and owner provenance.
    #[must_use]
    pub const fn baseline(&self) -> &BaselineIdentity {
        &self.baseline
    }
    /// Exact verified number; do not select a different registry row at commit.
    #[must_use]
    pub const fn number(&self) -> &CheckedDeviceNumber {
        &self.number
    }
    /// Verified registration node scope.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    /// Verified organisation scope.
    #[must_use]
    pub fn organisation_id(&self) -> &str {
        &self.organisation_id
    }
    /// Operation UUID to atomically consume with the registry CAS.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    /// Canonical owner import body identity, excluding signature envelope variations.
    #[must_use]
    pub const fn body_digest(&self) -> [u8; 32] {
        self.body_digest
    }
    /// Exact predecessor precondition that must still hold at commit.
    #[must_use]
    pub const fn expected(&self) -> ExpectedHead {
        self.expected
    }
    /// Exact allocation floor inspected; caller must CAS this too.
    #[must_use]
    pub const fn previous_allocation_floor(&self) -> u64 {
        self.previous_allocation_floor
    }
    /// Proposed direct-v1 head; never current until protected commit succeeds.
    #[must_use]
    pub const fn new_head(&self) -> RegistryHead {
        self.new_head
    }
}

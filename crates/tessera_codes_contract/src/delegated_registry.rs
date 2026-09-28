//! Explicit delegated device-record v2. The old direct-owner v1 type is not
//! reinterpreted. Verification requires externally protected authority and
//! current-record identities; neither input document establishes currentness.
use crate::{
    canon::Encoder,
    device_number::CheckedDeviceNumber,
    key::Epoch,
    mac::sha256,
    registration_authority::{
        codec, AuthorityError, CurrentAuthorityContext, P256PublicKey, P256SignatureVerifier,
        SignatureCheckedAuthority,
    },
    registry::{
        self, DeviceRecord, KeyProtection, MonotonicAnchor, PayloadFields, RecordError,
        RecordPayload, SerialNumber,
    },
    signature::{PublicKey, Signature, SignatureVerifier, SignerRef},
    wire,
};
use std::collections::BTreeSet;

/// Versioned record marker; legacy parsers intentionally reject it.
pub const RECORD_PREFIX: &str = "tessera-codes/v2/device-record";
/// Closed delegated proof domain.
pub const PROOF_DOMAIN: &str = "tessera-codes-contract/v1/registry-owner-delegated";
/// Maximum complete v2 text record.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
/// Maximum ordered, distinct legacy serial facts in a v2 record.
pub const MAX_SERIALS: usize = 16;
const KEYS: [&str; 25] = [
    "device",
    "key",
    "epoch",
    "serials",
    "key_protection",
    "anchor",
    "batch",
    "baseline",
    "organisation",
    "owner",
    "possession_signature",
    "organisation_signature",
    "owner_proof",
    "fleet_id",
    "tenant_node_id",
    "delegation_id",
    "grant_digest",
    "request_digest",
    "plan_digest",
    "registration_generation",
    "previous_record_digest",
    "registered_at",
    "not_after",
    "authority_sequence_at_registration",
    "delegate_signature",
];

/// Fixed delegated-proof claims. Construction validates shape, not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedProofFields {
    /// Exact fleet UUID.
    pub fleet_id: String,
    /// Exact registration node UUID.
    pub tenant_node_id: String,
    /// Immutable owner grant UUID.
    pub delegation_id: String,
    /// SHA256 immutable grant core, excluding mode/authority sequence.
    pub grant_digest: [u8; 32],
    /// Exact verified request digest.
    pub request_digest: [u8; 32],
    /// Exact approved closed-plan digest.
    pub plan_digest: [u8; 32],
    /// Positive protected registration generation.
    pub registration_generation: u64,
    /// Previous exact signed-record identity for an explicit replacement.
    pub previous_record_digest: Option<[u8; 32]>,
    /// Fixed signer-recorded registration time.
    pub registered_at: u64,
    /// Exclusive finite record expiration.
    pub not_after: u64,
    /// Positive authority sequence actually used for registration.
    pub authority_sequence_at_registration: u64,
}
/// Inputs to the explicitly delegated record; no direct-owner signature slot.
#[derive(Debug, Clone)]
pub struct DelegatedRecordFields {
    /// Existing v1 payload and canonical semantics.
    pub payload: RecordPayload,
    /// Existing independently verified organisation identity.
    pub organisation_id: String,
    /// Expected configured owner identity.
    pub owner_id: String,
    /// Existing device proof over the v1 possession message.
    pub possession_signature: Signature,
    /// Existing organisation proof over its v1 message.
    pub organisation_signature: Signature,
    /// Versioned delegation claims.
    pub proof: DelegatedProofFields,
}
/// Bounded immutable record draft with the original device/organisation proofs.
#[derive(Debug, Clone)]
pub struct DelegatedRecordDraft {
    fields: DelegatedRecordFields,
}
impl DelegatedRecordDraft {
    /// Validate closed fields before computing any proof message.
    /// # Errors
    /// Rejects invalid scope/encoding, signatures, times or payload bounds.
    pub fn new(fields: DelegatedRecordFields) -> Result<Self, AuthorityError> {
        codec::text(&fields.organisation_id)?;
        codec::text(&fields.owner_id)?;
        let p = &fields.proof;
        for id in [&p.fleet_id, &p.tenant_node_id, &p.delegation_id] {
            codec::uuid(id)?;
        }
        if p.registration_generation == 0
            || p.authority_sequence_at_registration == 0
            || p.registered_at >= p.not_after
        {
            return Err(AuthorityError::Malformed("record times/generation"));
        }
        let payload = &fields.payload;
        P256PublicKey::new(payload.public_key().as_bytes())?;
        codec::text(payload.batch())?;
        if payload.device_number().significant().len() > 32
            || payload.device_number().as_str().len() > 64
            || payload.serials().len() > MAX_SERIALS
        {
            return Err(AuthorityError::Malformed("record payload bounds"));
        }
        let mut seen = BTreeSet::new();
        for serial in payload.serials() {
            codec::text(serial.kind())?;
            codec::text(serial.value())?;
            if !seen.insert((serial.kind(), serial.value())) {
                return Err(AuthorityError::Malformed("duplicate serial"));
            }
        }
        codec::signature(fields.possession_signature.as_bytes())?;
        codec::signature(fields.organisation_signature.as_bytes())?;
        Ok(Self { fields })
    }
    /// Immutable validated fields; no mutable grant or record setters.
    #[must_use]
    pub const fn fields(&self) -> &DelegatedRecordFields {
        &self.fields
    }
    /// Exact message to be signed by the owner-authorized delegate.
    /// # Errors
    /// Propagates canonical encoder limits.
    pub fn proof_message(&self) -> Result<Vec<u8>, AuthorityError> {
        let f = &self.fields;
        let p = &f.proof;
        let mut e = Encoder::default();
        e.push_text("domain", PROOF_DOMAIN)?;
        e.push_bytes("payload_canonical", &f.payload.encode()?)?;
        e.push_bytes("possession_signature", f.possession_signature.as_bytes())?;
        e.push_text("organisation_id", &f.organisation_id)?;
        e.push_bytes(
            "organisation_signature",
            f.organisation_signature.as_bytes(),
        )?;
        e.push_text("owner_id", &f.owner_id)?;
        for (name, value) in [
            ("fleet_id", &p.fleet_id),
            ("tenant_node_id", &p.tenant_node_id),
            ("delegation_id", &p.delegation_id),
        ] {
            e.push_text(name, value)?;
        }
        for (name, value) in [
            ("grant_digest", &p.grant_digest),
            ("request_digest", &p.request_digest),
            ("plan_digest", &p.plan_digest),
        ] {
            e.push_bytes(name, value)?;
        }
        e.push_u64("registration_generation", p.registration_generation)?;
        e.push_bytes(
            "previous_record_digest",
            p.previous_record_digest
                .as_ref()
                .map_or(&[][..], |d| d.as_slice()),
        )?;
        e.push_u64("registered_at", p.registered_at)?;
        e.push_u64("not_after", p.not_after)?;
        e.push_u64(
            "authority_sequence_at_registration",
            p.authority_sequence_at_registration,
        )?;
        Ok(e.finish())
    }
}
/// Completed v2 record; no implicit alias to v1 `owner_signature`.
#[derive(Debug, Clone)]
pub struct DelegatedDeviceRecord {
    draft: DelegatedRecordDraft,
    delegate_signature: Signature,
}
impl DelegatedDeviceRecord {
    /// Attach a bounded canonical delegate signature; verification is separate.
    /// # Errors
    /// Refuses invalid DER or record size.
    pub fn new(
        draft: DelegatedRecordDraft,
        delegate_signature: Signature,
    ) -> Result<Self, AuthorityError> {
        codec::signature(delegate_signature.as_bytes())?;
        let result = Self {
            draft,
            delegate_signature,
        };
        if result.to_wire().len() > MAX_RECORD_BYTES {
            return Err(AuthorityError::Malformed("record wire bound"));
        }
        Ok(result)
    }
    /// Immutable signed claims.
    #[must_use]
    pub const fn draft(&self) -> &DelegatedRecordDraft {
        &self.draft
    }
    /// Exact retained delegate DER signature; never re-sign/normalize on replay.
    #[must_use]
    pub const fn delegate_signature(&self) -> &Signature {
        &self.delegate_signature
    }
    /// SHA256 of `LP(proof_message) || LP(delegate_signature)`. This identifies
    /// the exact retained signed artifact, unlike authority BODY-only identity.
    /// # Errors
    /// Propagates canonical encoding failure.
    pub fn record_digest(&self) -> Result<[u8; 32], AuthorityError> {
        let mut e = Encoder::default();
        e.push_bytes("proof_message", &self.draft.proof_message()?)?;
        e.push_bytes("delegate_signature", self.delegate_signature.as_bytes())?;
        Ok(sha256(&e.finish()))
    }
    /// Render fixed-order v2 wire, with '-' only for an absent previous digest.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let f = &self.draft.fields;
        let p = &f.proof;
        let payload = &f.payload;
        wire::render(
            RECORD_PREFIX,
            &[
                ("device", payload.device_number().significant().to_owned()),
                ("key", hex::encode(payload.public_key().as_bytes())),
                ("epoch", payload.epoch().get().to_string()),
                (
                    "serials",
                    payload
                        .serials()
                        .iter()
                        .map(SerialNumber::to_wire)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "key_protection",
                    payload.key_protection().as_str().to_owned(),
                ),
                ("anchor", payload.anchor().as_str().to_owned()),
                ("batch", payload.batch().to_owned()),
                ("baseline", hex::encode(payload.baseline())),
                ("organisation", f.organisation_id.clone()),
                ("owner", f.owner_id.clone()),
                (
                    "possession_signature",
                    hex::encode(f.possession_signature.as_bytes()),
                ),
                (
                    "organisation_signature",
                    hex::encode(f.organisation_signature.as_bytes()),
                ),
                ("owner_proof", "delegation-v1".to_owned()),
                ("fleet_id", p.fleet_id.clone()),
                ("tenant_node_id", p.tenant_node_id.clone()),
                ("delegation_id", p.delegation_id.clone()),
                ("grant_digest", hex::encode(p.grant_digest)),
                ("request_digest", hex::encode(p.request_digest)),
                ("plan_digest", hex::encode(p.plan_digest)),
                (
                    "registration_generation",
                    p.registration_generation.to_string(),
                ),
                (
                    "previous_record_digest",
                    p.previous_record_digest
                        .map_or_else(|| "-".to_owned(), hex::encode),
                ),
                ("registered_at", p.registered_at.to_string()),
                ("not_after", p.not_after.to_string()),
                (
                    "authority_sequence_at_registration",
                    p.authority_sequence_at_registration.to_string(),
                ),
                (
                    "delegate_signature",
                    hex::encode(self.delegate_signature.as_bytes()),
                ),
            ],
        )
    }
    /// Parse v2 only; strict text/hex/integers and field order are round-tripped.
    /// # Errors
    /// Rejects legacy/unknown proof, bounds, malformed or noncanonical fields.
    pub fn parse(text: &str) -> Result<Self, AuthorityError> {
        if text.len() > MAX_RECORD_BYTES || text.trim() != text {
            return Err(AuthorityError::Malformed(
                "record wire bound/canonical form",
            ));
        }
        let values = wire::parse(text, RECORD_PREFIX, &KEYS)?;
        let v = |i| wire::value(&values, i);
        if v(12) != "delegation-v1" {
            return Err(AuthorityError::Malformed("owner proof kind"));
        }
        if v(3).split(',').count() > MAX_SERIALS {
            return Err(AuthorityError::Malformed("serial count"));
        }
        let payload = RecordPayload::new(PayloadFields {
            device_number: CheckedDeviceNumber::parse(v(0)).map_err(RecordError::from)?,
            public_key: PublicKey::new(codec::hex_bytes(v(1), 33)?)?,
            epoch: Epoch::new(
                u32::try_from(codec::decimal(v(2))?)
                    .map_err(|_| AuthorityError::Malformed("epoch"))?,
            ),
            serials: v(3)
                .split(',')
                .map(SerialNumber::parse)
                .collect::<Result<Vec<_>, _>>()?,
            key_protection: KeyProtection::parse(v(4))
                .ok_or(AuthorityError::Malformed("protection"))?,
            anchor: MonotonicAnchor::parse(v(5)).ok_or(AuthorityError::Malformed("anchor"))?,
            batch: v(6),
            baseline: codec::hash(v(7))?,
        })?;
        let fields = DelegatedRecordFields {
            payload,
            organisation_id: v(8).to_owned(),
            owner_id: v(9).to_owned(),
            possession_signature: codec::parse_signature(v(10))?,
            organisation_signature: codec::parse_signature(v(11))?,
            proof: DelegatedProofFields {
                fleet_id: v(13).to_owned(),
                tenant_node_id: v(14).to_owned(),
                delegation_id: v(15).to_owned(),
                grant_digest: codec::hash(v(16))?,
                request_digest: codec::hash(v(17))?,
                plan_digest: codec::hash(v(18))?,
                registration_generation: codec::decimal(v(19))?,
                previous_record_digest: if v(20) == "-" {
                    None
                } else {
                    Some(codec::hash(v(20))?)
                },
                registered_at: codec::decimal(v(21))?,
                not_after: codec::decimal(v(22))?,
                authority_sequence_at_registration: codec::decimal(v(23))?,
            },
        };
        let result = Self::new(
            DelegatedRecordDraft::new(fields)?,
            codec::parse_signature(v(24))?,
        )?;
        if result.to_wire() != text {
            return Err(AuthorityError::Malformed("record canonical form"));
        }
        Ok(result)
    }
    /// Verify all proofs against the exact protected current authority/record
    /// supplied independently by the consumer. This is not a chain/CRL resolver
    /// or evidence that an operator ceremony took place; those remain required.
    /// # Errors
    /// Rejects revoked/out-of-scope/expired/superseded records or bad signatures.
    pub fn verify<'a>(
        &'a self,
        authority: &SignatureCheckedAuthority,
        context: &RecordVerificationContext<'_>,
        backend: &(impl SignatureVerifier + P256SignatureVerifier),
    ) -> Result<VerifiedDelegatedRecord<'a>, AuthorityError> {
        let f = &self.draft.fields;
        let p = &f.proof;
        let now = context.authority.trust.now.get();
        if p.fleet_id != context.authority.trust.fleet_id
            || f.owner_id != context.authority.trust.owner_id
            || p.tenant_node_id != context.tenant_node_id
            || f.organisation_id != context.organisation_id
            || context.current_record.generation != p.registration_generation
            || context.current_record.digest != self.record_digest()?
        {
            return Err(AuthorityError::Context("record scope/current identity"));
        }
        let grant = authority.grant(&p.delegation_id, &context.authority)?;
        let core = grant.core();
        let g = core.fields();
        if p.grant_digest != core.digest()?
            || g.tenant_node_id != p.tenant_node_id
            || g.organisation_id != f.organisation_id
            || p.registered_at < g.not_before
            || p.registered_at >= g.register_until
            || p.registered_at > now
            || now >= p.not_after
            || now >= g.verify_until
            || p.not_after > g.verify_until
            || p.registered_at
                .checked_add(g.max_record_lifetime_seconds)
                .is_none_or(|end| p.not_after > end)
            || f.payload.epoch().get() < g.minimum_epoch
            || f.payload.epoch().get() > g.maximum_epoch
            || !f
                .payload
                .key_protection()
                .is_at_least(g.key_protection_floor)
            || p.previous_record_digest.is_some() && !g.allow_replacement
            || p.authority_sequence_at_registration > context.authority.checkpoint.sequence()
        {
            return Err(AuthorityError::Context("record outside immutable grant"));
        }
        backend.validate_public_key(&P256PublicKey::new(f.payload.public_key().as_bytes())?)?;
        backend.verify(
            SignerRef::Key(f.payload.public_key()),
            &registry::possession_message(&f.payload)?,
            &f.possession_signature,
        )?;
        backend.verify(
            SignerRef::Named(&f.organisation_id),
            &registry::organisation_message(
                &f.payload,
                &f.possession_signature,
                &f.organisation_id,
            )?,
            &f.organisation_signature,
        )?;
        backend.verify_p256(
            &g.delegate_public_key,
            &self.draft.proof_message()?,
            &self.delegate_signature,
        )?;
        Ok(VerifiedDelegatedRecord { record: self })
    }
}
/// Exact current-record identity obtained from protected registration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentRecord {
    generation: u64,
    digest: [u8; 32],
}
impl CurrentRecord {
    /// Restore trusted current state, not data copied from the record being checked.
    /// # Errors
    /// Rejects generation0.
    pub fn new(generation: u64, digest: [u8; 32]) -> Result<Self, AuthorityError> {
        if generation == 0 {
            return Err(AuthorityError::Malformed("generation"));
        }
        Ok(Self { generation, digest })
    }
}
/// Scope/currentness supplied by the consumer's protected sources.
pub struct RecordVerificationContext<'a> {
    /// Independently current authority checkpoint, owner pin and time.
    pub authority: CurrentAuthorityContext<'a>,
    /// Configured registration node.
    pub tenant_node_id: &'a str,
    /// Verified organisation/chain identity.
    pub organisation_id: &'a str,
    /// Exact protected current record; no SQL boolean or optional fallback.
    pub current_record: CurrentRecord,
}
/// Proof verification at the supplied context/time; no independent live-state claim.
pub struct VerifiedDelegatedRecord<'a> {
    record: &'a DelegatedDeviceRecord,
}
impl VerifiedDelegatedRecord<'_> {
    /// Common immutable device facts after the selected proofs were checked.
    #[must_use]
    pub fn payload(&self) -> &RecordPayload {
        &self.record.draft.fields.payload
    }
}
/// Explicit version dispatch; parsing is not proof verification or admission.
#[derive(Debug, Clone)]
pub enum RegistryRecord {
    /// Unchanged direct-owner v1 record and verifier.
    Direct(Box<DeviceRecord>),
    /// Explicit delegated v2 record requiring the new trusted contexts.
    Delegated(Box<DelegatedDeviceRecord>),
}
impl RegistryRecord {
    /// Dispatch by exact version marker; retain the legacy parser's own semantics.
    /// # Errors
    /// Rejects unknown versions or malformed selected documents.
    pub fn parse(text: &str) -> Result<Self, AuthorityError> {
        if text.trim().starts_with("tessera-codes/v1/device-record;") {
            Ok(Self::Direct(Box::new(DeviceRecord::parse(text)?)))
        } else {
            Ok(Self::Delegated(Box::new(DelegatedDeviceRecord::parse(
                text,
            )?)))
        }
    }
}

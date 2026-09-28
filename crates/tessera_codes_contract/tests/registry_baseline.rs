//! Independent owner baseline/import fixtures; all keys and data are test-only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature as EcSignature, SigningKey, VerifyingKey,
};
use tessera_codes_contract::{
    delegated_registry::DelegatedDeviceRecord,
    device_number::CheckedDeviceNumber,
    registration_authority::*,
    registry::DeviceRecord,
    registry_baseline::*,
    signature::{Signature, SignatureError, SignatureVerifier, SignerRef},
    time::ClaimedTime,
};
const FLEET: &str = "11111111-1111-1111-1111-111111111111";
const NODE: &str = "22222222-2222-2222-2222-222222222222";
const BASE: &str = "44444444-4444-4444-4444-444444444444";
const INSTANCE: &str = "55555555-5555-5555-5555-555555555555";
const CUT: &str = "66666666-6666-6666-6666-666666666666";
const OP: &str = "77777777-7777-7777-7777-777777777777";
const LEGACY: &str = include_str!("golden/registration/legacy-record.wire");
const V2: &str = include_str!("golden/registration/record.wire");
struct Backend;
fn key(n: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    SigningKey::from_slice(&bytes).unwrap()
}
fn point(n: u8) -> P256PublicKey {
    P256PublicKey::new(key(n).verifying_key().to_encoded_point(true).as_bytes()).unwrap()
}
fn sign(n: u8, message: &[u8]) -> Signature {
    let signature: EcSignature = key(n).sign(message);
    Signature::new(signature.to_der().as_bytes().to_vec()).unwrap()
}
impl P256SignatureVerifier for Backend {
    fn validate_public_key(&self, key: &P256PublicKey) -> Result<(), SignatureError> {
        let parsed =
            VerifyingKey::from_sec1_bytes(key.as_bytes()).map_err(|_| SignatureError::Rejected)?;
        if parsed.to_encoded_point(true).as_bytes() != key.as_bytes() {
            return Err(SignatureError::Rejected);
        }
        Ok(())
    }
    fn verify_p256(
        &self,
        key: &P256PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        self.validate_public_key(key)?;
        let signature_parsed =
            EcSignature::from_der(signature.as_bytes()).map_err(|_| SignatureError::Rejected)?;
        if signature_parsed.to_der().as_bytes() != signature.as_bytes() {
            return Err(SignatureError::Rejected);
        }
        VerifyingKey::from_sec1_bytes(key.as_bytes())
            .map_err(|_| SignatureError::Rejected)?
            .verify(message, &signature_parsed)
            .map_err(|_| SignatureError::Rejected)
    }
}
impl SignatureVerifier for Backend {
    fn verify(
        &self,
        signer: SignerRef<'_>,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        let point = match signer {
            SignerRef::Key(public) => {
                if public.as_bytes().len() == 97 {
                    use p384::ecdsa::{
                        signature::hazmat::PrehashVerifier as _, Signature as P384Signature,
                        VerifyingKey as P384Key,
                    };
                    let key = P384Key::from_sec1_bytes(public.as_bytes())
                        .map_err(|_| SignatureError::Rejected)?;
                    let sig = P384Signature::from_der(signature.as_bytes())
                        .map_err(|_| SignatureError::Rejected)?;
                    return key
                        .verify_prehash(&sha(message), &sig)
                        .map_err(|_| SignatureError::Rejected);
                }
                let key = VerifyingKey::from_sec1_bytes(public.as_bytes())
                    .map_err(|_| SignatureError::Rejected)?;
                let sig = EcSignature::from_der(signature.as_bytes())
                    .map_err(|_| SignatureError::Rejected)?;
                return key
                    .verify(message, &sig)
                    .map_err(|_| SignatureError::Rejected);
            }
            SignerRef::Named("fixture-org") => point(4),
            SignerRef::Named("fixture-owner") => point(1),
            _ => return Err(SignatureError::UnknownSigner),
        };
        self.verify_p256(&point, message, signature)
    }
}
fn trust(now: u64, owner: &P256PublicKey) -> AuthorityTrustContext<'_> {
    AuthorityTrustContext {
        fleet_id: FLEET,
        owner_id: "fixture-owner",
        owner_key: owner,
        now: ClaimedTime::new(now),
    }
}
fn inventory(empty: bool) -> BaselineInventory {
    let hex = if empty {
        include_str!("golden/registry-baseline/empty.inventory.hex")
    } else {
        include_str!("golden/registry-baseline/complete.inventory.hex")
    };
    BaselineInventory::parse(&hex::decode(hex.trim()).unwrap()).unwrap()
}
fn baseline(empty: bool) -> SignedBaseline {
    let wire = if empty {
        include_str!("golden/registry-baseline/empty.wire")
    } else {
        include_str!("golden/registry-baseline/complete.wire")
    };
    SignedBaseline::parse(wire.trim()).unwrap()
}
fn cut() -> ProtectedActivationCut {
    ProtectedActivationCut::new(INSTANCE.into(), CUT.into(), 42, [0xaa; 32]).unwrap()
}
fn number() -> CheckedDeviceNumber {
    CheckedDeviceNumber::parse("77000123S").unwrap()
}
fn companion(new: bool) -> SignedRegistryImport {
    let wire = if new {
        include_str!("golden/registry-baseline/import-new.wire")
    } else {
        include_str!("golden/registry-baseline/import-replacement.wire")
    };
    SignedRegistryImport::parse(wire.trim()).unwrap()
}
fn checked(empty: bool) -> SignatureCheckedBaseline {
    baseline(empty)
        .verify_candidate(&inventory(empty), &trust(150, &point(1)), &Backend)
        .unwrap()
}
fn context<'a>(
    identity: &'a BaselineIdentity,
    num: &'a CheckedDeviceNumber,
    owner: &'a P256PublicKey,
    state: ProtectedNumberState,
    floor: u64,
) -> ImportContext<'a> {
    ImportContext {
        trust: trust(150, owner),
        baseline: identity,
        number: num,
        node_id: NODE,
        organisation_id: "fixture-org",
        operation_id: OP,
        number_state: state,
        last_allocated_generation: floor,
        operation_state: OperationState::Unseen,
    }
}
fn signed_import(fields: ImportFields) -> SignedRegistryImport {
    let body = RegistryImport::new(fields).unwrap();
    let sig = sign(1, &body.encode().unwrap());
    SignedRegistryImport::new(body, sig).unwrap()
}
fn signed_baseline(fields: BaselineFields, inv: &BaselineInventory) -> SignedBaseline {
    let body = BaselineManifest::new(fields, inv).unwrap();
    let sig = sign(1, &body.encode().unwrap());
    SignedBaseline::new(body, sig).unwrap()
}

#[test]
fn independent_openssl_baselines_bind_complete_and_explicit_empty_artifacts() {
    for empty in [true, false] {
        let inv = inventory(empty);
        let signed = baseline(empty);
        let wire = signed.to_wire().unwrap();
        assert_eq!(
            SignedBaseline::parse(&wire).unwrap().to_wire().unwrap(),
            wire
        );
        assert_eq!(
            BaselineInventory::parse(&inv.encode().unwrap()).unwrap(),
            inv
        );
        let verified = signed
            .verify_candidate(&inv, &trust(150, &point(1)), &Backend)
            .unwrap();
        let id = verified
            .check_initialisation(&BootstrapContext {
                trust: trust(150, &point(1)),
                cut: &cut(),
                state: BootstrapState::Uninitialised,
            })
            .unwrap();
        assert_eq!(id.baseline_id(), BASE);
        assert_eq!(id.owner_key(), point(1));
        assert_eq!(id.cut(), &cut());
        assert_eq!(
            hex::encode(id.body_digest()),
            if empty {
                "3cc2c515df571c15d84ed0aa42917d5f3faab2e694d810e1fdf123642cb57087"
            } else {
                "bc4d39baba5558cc21a5607b2a25a88e2bc5e27ca83b7048f229ebaf0ad15dad"
            }
        );
    }
}

#[test]
fn historical_absence_is_distinct_from_current_retired_and_unknown_tombstones() {
    let baseline = checked(false);
    let inv = baseline.inventory();
    assert!(matches!(
        inv.lookup_at_cut(&number()).unwrap().state(),
        InventoryState::Current(_)
    ));
    let retired = CheckedDeviceNumber::from_body("77000124").unwrap();
    let actual = DelegatedDeviceRecord::parse(V2.trim())
        .unwrap()
        .record_digest()
        .unwrap();
    assert!(
        matches!(inv.lookup_at_cut(&retired).unwrap().state(),InventoryState::Retired(h) if h.kind()==RecordDigestKind::DelegatedV2CurrentDigest && h.digest()==actual)
    );
    let unknown = CheckedDeviceNumber::from_body("77000125").unwrap();
    assert_eq!(
        inv.lookup_at_cut(&unknown).unwrap().state(),
        InventoryState::RetiredUnknown { generation: 1 }
    );
    assert!(inv
        .lookup_at_cut(&CheckedDeviceNumber::from_body("99999").unwrap())
        .is_none());
    assert!(checked(true).inventory().entries().is_empty());
    // A historical lookup supplies no live overlay/currentness context to an import.
    let id = baseline.identity().unwrap();
    let num = number();
    let owner = point(1);
    assert!(companion(false)
        .verify_transition(
            LEGACY.trim().as_bytes(),
            &context(&id, &num, &owner, ProtectedNumberState::Unavailable, 1),
            &Backend
        )
        .is_err());
}

#[test]
fn bootstrap_requires_exact_held_cut_uninitialised_state_owner_and_time() {
    let verified = checked(false);
    let owner = point(1);
    let good = cut();
    let bad = [
        ProtectedActivationCut::new(BASE.into(), CUT.into(), 42, [0xaa; 32]).unwrap(),
        ProtectedActivationCut::new(INSTANCE.into(), BASE.into(), 42, [0xaa; 32]).unwrap(),
        ProtectedActivationCut::new(INSTANCE.into(), CUT.into(), 43, [0xaa; 32]).unwrap(),
        ProtectedActivationCut::new(INSTANCE.into(), CUT.into(), 42, [0xab; 32]).unwrap(),
    ];
    for cut in &bad {
        assert!(verified
            .check_initialisation(&BootstrapContext {
                trust: trust(150, &owner),
                cut,
                state: BootstrapState::Uninitialised
            })
            .is_err());
    }
    assert!(verified
        .check_initialisation(&BootstrapContext {
            trust: trust(150, &owner),
            cut: &good,
            state: BootstrapState::Installed
        })
        .is_err());
    for now in [99, 200, u64::MAX] {
        assert!(verified
            .check_initialisation(&BootstrapContext {
                trust: trust(now, &owner),
                cut: &good,
                state: BootstrapState::Uninitialised
            })
            .is_err());
    }
    for now in [100, 199] {
        assert!(verified
            .check_initialisation(&BootstrapContext {
                trust: trust(now, &owner),
                cut: &good,
                state: BootstrapState::Uninitialised
            })
            .is_ok());
    }
    assert!(verified
        .check_initialisation(&BootstrapContext {
            trust: trust(150, &point(2)),
            cut: &good,
            state: BootstrapState::Uninitialised
        })
        .is_err());
}

#[test]
fn historical_baseline_verification_survives_expired_bootstrap_window_without_reinitialisation() {
    let owner = point(1);
    let signed = baseline(false);
    let inv = inventory(false);
    let replayed = signed
        .verify_candidate(&inv, &trust(500, &owner), &Backend)
        .unwrap();
    assert_eq!(
        replayed.identity().unwrap(),
        checked(false).identity().unwrap()
    );
    assert!(replayed
        .check_initialisation(&BootstrapContext {
            trust: trust(500, &owner),
            cut: &cut(),
            state: BootstrapState::Uninitialised
        })
        .is_err());
    assert!(replayed
        .check_initialisation(&BootstrapContext {
            trust: trust(150, &owner),
            cut: &cut(),
            state: BootstrapState::Installed
        })
        .is_err());
}

#[test]
fn signatures_bind_actual_owner_point_scope_and_exact_inventory_not_just_shapes() {
    let inv = inventory(false);
    let signed = baseline(false);
    let owner = point(1);
    assert!(signed
        .verify_candidate(&inv, &trust(150, &point(2)), &Backend)
        .is_err());
    let mut off = [0xff; 33];
    off[0] = 2;
    let off = P256PublicKey::new(&off).unwrap();
    assert!(signed
        .verify_candidate(&inv, &trust(150, &off), &Backend)
        .is_err());
    assert!(signed
        .verify_candidate(&inventory(true), &trust(150, &owner), &Backend)
        .is_err());
    let mut wrong = trust(150, &owner);
    wrong.fleet_id = BASE;
    assert!(signed.verify_candidate(&inv, &wrong, &Backend).is_err());
    let mut wrong = trust(150, &owner);
    wrong.owner_id = "other-owner";
    assert!(signed.verify_candidate(&inv, &wrong, &Backend).is_err());
    let body = signed.manifest().clone();
    let sig = sign(1, &body.encode().unwrap());
    let alternate = SignedBaseline::new(body, sig)
        .unwrap()
        .verify_candidate(&inv, &trust(150, &owner), &Backend)
        .unwrap();
    assert_eq!(
        alternate.identity().unwrap(),
        checked(false).identity().unwrap()
    );
    let mut fields = signed.manifest().fields().clone();
    fields.accept_until += 1;
    let changed = signed_baseline(fields, &inv)
        .verify_candidate(&inv, &trust(150, &owner), &Backend)
        .unwrap();
    assert_ne!(
        changed.identity().unwrap().body_digest(),
        alternate.identity().unwrap().body_digest()
    );
}

#[test]
fn inventory_order_completeness_bounds_and_constructor_parser_parity() {
    let inv = inventory(false);
    let rows = inv.entries().to_vec();
    assert!(BaselineInventory::new(vec![rows[0].clone(), rows[0].clone()]).is_err());
    assert!(BaselineInventory::new(vec![rows[1].clone(), rows[0].clone()]).is_err());
    assert!(BaselineInventory::new(vec![rows[0].clone(); MAX_ENTRIES + 1]).is_err());
    let formatted = CheckedDeviceNumber::parse("77-000123S").unwrap();
    let duplicate = BaselineEntry::new(
        &formatted,
        NODE.into(),
        "fixture-org".into(),
        rows[0].state(),
    )
    .unwrap();
    assert!(BaselineInventory::new(vec![rows[0].clone(), duplicate]).is_err());
    assert!(BaselineEntry::new(
        &number(),
        NODE.into(),
        "fixture-org".into(),
        InventoryState::RetiredUnknown { generation: 0 }
    )
    .is_err());
    let long = CheckedDeviceNumber::from_body(&"1".repeat(33)).unwrap();
    assert!(BaselineEntry::new(&long, NODE.into(), "fixture-org".into(), rows[0].state()).is_err());
    let mut fields = baseline(false).manifest().fields().clone();
    assert!(BaselineManifest::new(fields.clone(), &inventory(true)).is_err());
    fields.completeness = Completeness::EmptyHistory;
    assert!(BaselineManifest::new(fields.clone(), &inv).is_err());
    fields.not_before = fields.accept_until;
    assert!(BaselineManifest::new(fields, &inventory(true)).is_err());
    assert!(BaselineInventory::parse(&vec![0; MAX_INVENTORY + 1]).is_err());
    let mut bytes = inventory(true).encode().unwrap();
    let last = bytes.len();
    bytes[last - 4..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(BaselineInventory::parse(&bytes).is_err());
}

#[test]
fn independent_courier_imports_preserve_existing_v1_verification_and_assign_protected_generations()
{
    DeviceRecord::parse(LEGACY.trim())
        .unwrap()
        .verify(&Backend)
        .unwrap();
    let num = number();
    let owner = point(1);
    for new in [true, false] {
        let id = checked(new).identity().unwrap();
        let import = companion(new);
        let expected = import.import().fields().expected;
        let (state, floor) = match expected {
            ExpectedHead::Absent => (ProtectedNumberState::Absent, 0),
            ExpectedHead::Current(h) => (ProtectedNumberState::Current(h), h.generation()),
            ExpectedHead::Retired(_) => panic!("fixture"),
        };
        let ctx = context(&id, &num, &owner, state, floor);
        let proposal = import
            .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
            .unwrap();
        assert_eq!(proposal.new_head().generation(), floor + 1);
        assert_eq!(
            proposal.new_head().kind(),
            RecordDigestKind::DirectV1WireSha256
        );
        assert_eq!(proposal.baseline(), &id);
        assert_eq!(proposal.number().significant(), num.significant());
        assert_eq!(proposal.node_id(), NODE);
        assert_eq!(proposal.organisation_id(), "fixture-org");
        assert_eq!(proposal.operation_id(), OP);
        assert_eq!(proposal.expected(), expected);
        assert_eq!(proposal.previous_allocation_floor(), floor);
        let wire = import.to_wire().unwrap();
        assert_eq!(
            SignedRegistryImport::parse(&wire)
                .unwrap()
                .to_wire()
                .unwrap(),
            wire
        );
    }
}

#[test]
fn imports_refuse_replay_reservations_unavailability_and_predecessor_substitution() {
    let id = checked(false).identity().unwrap();
    let num = number();
    let owner = point(1);
    let import = companion(false);
    let ExpectedHead::Current(head) = import.import().fields().expected else {
        panic!("fixture")
    };
    for state in [
        ProtectedNumberState::Absent,
        ProtectedNumberState::Retired(head),
        ProtectedNumberState::RetiredUnknown,
        ProtectedNumberState::Reserved,
        ProtectedNumberState::Unavailable,
        ProtectedNumberState::Current(RegistryHead::new(2, head.kind(), head.digest()).unwrap()),
        ProtectedNumberState::Current(
            RegistryHead::new(1, RecordDigestKind::DelegatedV2CurrentDigest, head.digest())
                .unwrap(),
        ),
        ProtectedNumberState::Current(RegistryHead::new(1, head.kind(), [0x55; 32]).unwrap()),
    ] {
        assert!(import
            .verify_transition(
                LEGACY.trim().as_bytes(),
                &context(&id, &num, &owner, state, 5),
                &Backend
            )
            .is_err());
    }
    let mut ctx = context(&id, &num, &owner, ProtectedNumberState::Current(head), 1);
    ctx.operation_state = OperationState::Seen;
    assert!(import
        .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
        .is_err());
    ctx.operation_state = OperationState::Unseen;
    ctx.operation_id = BASE;
    assert!(import
        .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
        .is_err());
    ctx.operation_id = OP;
    ctx.last_allocated_generation = 0;
    assert!(import
        .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
        .is_err());
    ctx.last_allocated_generation = u64::MAX;
    assert!(import
        .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
        .is_err());
    ctx.last_allocated_generation = 8;
    assert_eq!(
        import
            .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
            .unwrap()
            .new_head()
            .generation(),
        9
    );
    let mut fields = import.import().fields().clone();
    fields.expected = ExpectedHead::Retired(head);
    let retired = signed_import(fields);
    ctx.number_state = ProtectedNumberState::Retired(head);
    assert!(retired
        .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
        .is_ok());
}

#[test]
fn imports_bind_scope_owner_baseline_exact_bytes_and_admission_window() {
    let id = checked(true).identity().unwrap();
    let num = number();
    let owner = point(1);
    let import = companion(true);
    let mut ctx = context(&id, &num, &owner, ProtectedNumberState::Absent, 0);
    for now in [119, 180, u64::MAX] {
        ctx.trust.now = ClaimedTime::new(now);
        assert!(import
            .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
            .is_err());
    }
    ctx.trust.now = ClaimedTime::new(150);
    assert!(import
        .verify_transition(LEGACY.as_bytes(), &ctx, &Backend)
        .is_err()); // retained exact bytes, including no newline
    assert!(import
        .verify_transition(&vec![0; MAX_IMPORT_RECORD + 1], &ctx, &Backend)
        .is_err());
    for change in 0..9 {
        let mut fields = import.import().fields().clone();
        match change {
            0 => fields.fleet_id = BASE.into(),
            1 => fields.owner_id = "other-owner".into(),
            2 => fields.baseline_id = OP.into(),
            3 => fields.baseline_body_digest = [1; 32],
            4 => fields.registry_instance_id = OP.into(),
            5 => fields.operation_id = BASE.into(),
            6 => fields.node_id = BASE.into(),
            7 => fields.organisation_id = "another-org".into(),
            _ => fields.number = CheckedDeviceNumber::from_body("99999").unwrap(),
        }
        assert!(signed_import(fields)
            .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
            .is_err());
    }
    let bad = BaselineIdentity::new(
        FLEET.into(),
        "fixture-owner".into(),
        point(2),
        BASE.into(),
        id.body_digest(),
        cut(),
    )
    .unwrap();
    ctx.baseline = &bad;
    assert!(import
        .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
        .is_err());
}

#[test]
fn owner_companion_does_not_replace_the_carried_v1_cryptographic_proofs() {
    let id = checked(true).identity().unwrap();
    let num = number();
    let owner = point(1);
    let ctx = context(&id, &num, &owner, ProtectedNumberState::Absent, 0);
    let original = DeviceRecord::parse(LEGACY.trim()).unwrap();
    for field in [
        "possession_signature",
        "organisation_signature",
        "owner_signature",
    ] {
        let text = LEGACY.trim();
        let start = text.find(&format!(";{field}=")).unwrap() + field.len() + 2;
        let end = text[start..].find(';').map_or(text.len(), |n| start + n);
        let bad = sign(2, b"wrong signed domain");
        let mutated = format!(
            "{}{}{}",
            &text[..start],
            hex::encode(bad.as_bytes()),
            &text[end..]
        );
        let mut fields = companion(true).import().fields().clone();
        fields.new_record_digest = sha(mutated.as_bytes());
        assert!(signed_import(fields)
            .verify_transition(mutated.as_bytes(), &ctx, &Backend)
            .is_err());
    }
    assert_eq!(original.to_wire(), LEGACY.trim());
}
fn sha(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

#[test]
fn signed_body_inventory_tampering_and_bounded_malformed_inputs_fail_closed() {
    let inv = inventory(false);
    let signed = baseline(false);
    let body = signed.manifest().encode().unwrap();
    let owner = point(1);
    for i in 0..body.len() {
        let mut bytes = body.clone();
        bytes[i] ^= 1;
        let wire = format!(
            "{BASELINE_PREFIX};body={};owner_signature={}",
            hex::encode(bytes),
            hex::encode(signed.signature().as_bytes())
        );
        if let Ok(candidate) = SignedBaseline::parse(&wire) {
            assert!(candidate
                .verify_candidate(&inv, &trust(150, &owner), &Backend)
                .is_err());
        }
    }
    for end in 0..body.len() {
        let wire = format!(
            "{BASELINE_PREFIX};body={};owner_signature={}",
            hex::encode(&body[..end]),
            hex::encode(signed.signature().as_bytes())
        );
        assert!(SignedBaseline::parse(&wire).is_err());
    }
    let bytes = inv.encode().unwrap();
    for i in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[i] ^= 1;
        if let Ok(other) = BaselineInventory::parse(&bad) {
            assert!(signed
                .verify_candidate(&other, &trust(150, &owner), &Backend)
                .is_err());
        }
    }
    for end in 0..bytes.len() {
        assert!(BaselineInventory::parse(&bytes[..end]).is_err());
    }
    let id = checked(true).identity().unwrap();
    let num = number();
    let ctx = context(&id, &num, &owner, ProtectedNumberState::Absent, 0);
    let original = companion(true);
    let body = original.import().encode().unwrap();
    for end in 0..body.len() {
        let wire = format!(
            "{IMPORT_PREFIX};body={};owner_signature={}",
            hex::encode(&body[..end]),
            hex::encode(original.signature().as_bytes())
        );
        assert!(SignedRegistryImport::parse(&wire).is_err());
    }
    for i in 0..body.len() {
        let mut bad = body.clone();
        bad[i] ^= 1;
        let wire = format!(
            "{IMPORT_PREFIX};body={};owner_signature={}",
            hex::encode(bad),
            hex::encode(original.signature().as_bytes())
        );
        if let Ok(parsed) = SignedRegistryImport::parse(&wire) {
            assert!(parsed
                .verify_transition(LEGACY.trim().as_bytes(), &ctx, &Backend)
                .is_err());
        }
    }
    for (prefix, wire) in [
        (BASELINE_PREFIX, baseline(true).to_wire().unwrap()),
        (IMPORT_PREFIX, original.to_wire().unwrap()),
    ] {
        for bad in [
            format!(" {wire}"),
            format!("{wire};unknown=1"),
            wire.replace(";body=", ";BODY="),
            format!(
                "{prefix};body={};owner_signature=00",
                "00".repeat(MAX_BODY + 1)
            ),
            wire.replacen("body=", "body=A", 1),
        ] {
            assert!(if prefix == BASELINE_PREFIX {
                SignedBaseline::parse(&bad).is_err()
            } else {
                SignedRegistryImport::parse(&bad).is_err()
            });
        }
    }
    let mut seed = 7u64;
    for len in 0..1024 {
        let mut data = vec![0; len % 512];
        for byte in &mut data {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *byte = seed.to_be_bytes()[0];
        }
        assert!(BaselineInventory::parse(&data).is_err());
    }
}

fn legacy_wide_import(record: &str, companion: &str, width: usize) {
    let owner = point(1);
    let id = checked(true).identity().unwrap();
    let num = number();
    let ctx = context(&id, &num, &owner, ProtectedNumberState::Absent, 0);
    let record = record.trim();
    let parsed = DeviceRecord::parse(record).unwrap();
    assert_eq!(parsed.public_key().as_bytes().len(), width);
    parsed
        .verify(&Backend)
        .expect("the existing v1 proof backend accepts this real record");
    let import = SignedRegistryImport::parse(companion.trim()).unwrap();
    let proposal = import
        .verify_transition(record.as_bytes(), &ctx, &Backend)
        .expect("ordered import must preserve the existing v1 device-key semantics");
    assert_eq!(proposal.new_head().digest(), sha(record.as_bytes()));
    assert_eq!(
        parsed.to_wire(),
        record,
        "do not rewrite the carried v1 wire"
    );
}
#[test]
fn legacy_device_proof_uncompressed_p256_import() {
    legacy_wide_import(
        include_str!("golden/registry-baseline/legacy-p256-uncompressed.record.wire"),
        include_str!("golden/registry-baseline/legacy-p256-uncompressed-import.wire"),
        65,
    );
}
#[test]
fn legacy_device_proof_p384_import() {
    legacy_wide_import(
        include_str!("golden/registry-baseline/legacy-p384.record.wire"),
        include_str!("golden/registry-baseline/legacy-p384-import.wire"),
        97,
    );
}

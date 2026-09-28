//! Independent OpenSSL fixtures checked with the pure-Rust P-256 backend.
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
    delegated_registry::*,
    registration_authority::*,
    registry::{DeviceRecord, KeyProtection},
    signature::{Signature, SignatureError, SignatureVerifier, SignerRef},
    time::ClaimedTime,
};
const FLEET: &str = "11111111-1111-1111-1111-111111111111";
const NODE: &str = "22222222-2222-2222-2222-222222222222";
const GRANT: &str = "33333333-3333-3333-3333-333333333333";
const REGISTER: &str = include_str!("golden/registration/authority-register.wire");
const VERIFY_ONLY: &str = include_str!("golden/registration/authority-verify-only.wire");
const RECORD: &str = include_str!("golden/registration/record.wire");
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
                P256PublicKey::new(public.as_bytes()).map_err(|_| SignatureError::Rejected)?
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
fn authority() -> SignedAuthority {
    SignedAuthority::parse(REGISTER.trim()).unwrap()
}
fn record() -> DelegatedDeviceRecord {
    DelegatedDeviceRecord::parse(RECORD.trim()).unwrap()
}
fn signed(fields: AuthorityFields) -> SignedAuthority {
    let body = AuthoritySnapshot::new(fields).unwrap();
    let signature = sign(1, &body.encode().unwrap());
    SignedAuthority::new(body, signature).unwrap()
}
fn signed_record(fields: DelegatedRecordFields) -> DelegatedDeviceRecord {
    let draft = DelegatedRecordDraft::new(fields).unwrap();
    let signature = sign(2, &draft.proof_message().unwrap());
    DelegatedDeviceRecord::new(draft, signature).unwrap()
}
fn verify_record(authority: &SignedAuthority, record: &DelegatedDeviceRecord, now: u64) -> bool {
    let owner = point(1);
    let Ok(candidate) = authority.verify_candidate(&trust(now, &owner), &Backend) else {
        return false;
    };
    let context = RecordVerificationContext {
        authority: CurrentAuthorityContext {
            trust: trust(now, &owner),
            checkpoint: authority.snapshot().checkpoint().unwrap(),
        },
        tenant_node_id: NODE,
        organisation_id: "fixture-org",
        current_record: CurrentRecord::new(
            record.draft().fields().proof.registration_generation,
            record.record_digest().unwrap(),
        )
        .unwrap(),
    };
    record.verify(&candidate, &context, &Backend).is_ok()
}
fn registration(delegate: &P256PublicKey) -> RegistrationContext<'_> {
    RegistrationContext {
        tenant_node_id: NODE,
        organisation_id: "fixture-org",
        delegate_public_key: delegate,
        delegate_key_version: 1,
        operator_policy_digest: [0x44; 32],
        epoch: 1,
        key_protection: KeyProtection::Pkcs12Envelope,
        replacement: false,
    }
}

#[test]
fn independent_golden_bodies_and_all_real_signatures_match() {
    for (wire, body, digest) in [
        (
            include_str!("golden/registration/authority-empty.wire"),
            include_str!("golden/registration/authority-empty.body.hex"),
            "87142448381efdbe4351f64d6eec921b70942a19a915694c5ecddb943be778e7",
        ),
        (
            REGISTER,
            include_str!("golden/registration/authority-register.body.hex"),
            "d4b494550e9a08088f634806bb065c4fd53f2d2ff2960abcf7c6688a9a481af4",
        ),
        (
            VERIFY_ONLY,
            include_str!("golden/registration/authority-verify-only.body.hex"),
            "704c8b9d1ef4883fe5ea319db355ce1878e695a711bada535a0609fb2f8393f4",
        ),
    ] {
        let authority = SignedAuthority::parse(wire.trim()).unwrap();
        assert_eq!(authority.to_wire().unwrap(), wire.trim());
        assert_eq!(
            hex::encode(authority.snapshot().encode().unwrap()),
            body.trim()
        );
        assert_eq!(
            hex::encode(authority.snapshot().checkpoint().unwrap().body_digest()),
            digest
        );
        authority
            .verify_candidate(&trust(150, &point(1)), &Backend)
            .unwrap();
    }
    let a = authority();
    let core = a.snapshot().fields().grants[0].core();
    assert_eq!(
        hex::encode(core.encode().unwrap()),
        include_str!("golden/registration/grant.body.hex").trim()
    );
    assert_eq!(
        hex::encode(core.digest().unwrap()),
        "f12cceed1aa2f893a880df42e793fdc37daa6dc399513418fb078780c10ad4b1"
    );
    let r = record();
    assert_eq!(r.to_wire(), RECORD.trim());
    assert_eq!(
        hex::encode(r.draft().proof_message().unwrap()),
        include_str!("golden/registration/record.proof.hex").trim()
    );
    assert_eq!(
        hex::encode(r.record_digest().unwrap()),
        "2663902d4cbcc3d116c910dc77a5cedcfe19f8e63f0e125cb518a990b1233ee1"
    );
    assert!(verify_record(&a, &r, 150));
    assert!(DeviceRecord::parse(RECORD.trim()).is_err());
    assert!(matches!(
        RegistryRecord::parse(RECORD.trim()).unwrap(),
        RegistryRecord::Delegated(_)
    ));
}
#[test]
fn alternate_owner_signature_keeps_body_identity_but_record_signature_is_exact_artifact() {
    let a = authority();
    let alternate = SignedAuthority::new(
        a.snapshot().clone(),
        sign(1, &a.snapshot().encode().unwrap()),
    )
    .unwrap();
    assert_ne!(a.signature(), alternate.signature());
    assert_eq!(a.snapshot().checkpoint(), alternate.snapshot().checkpoint());
    alternate
        .verify_candidate(&trust(150, &point(1)), &Backend)
        .unwrap();
    let r = record();
    let alternate_record = DelegatedDeviceRecord::new(
        r.draft().clone(),
        sign(2, &r.draft().proof_message().unwrap()),
    )
    .unwrap();
    assert_ne!(r.record_digest(), alternate_record.record_digest());
    assert!(verify_record(&a, &alternate_record, 150));
    let owner = point(1);
    let checked = a.verify_candidate(&trust(150, &owner), &Backend).unwrap();
    let ctx = RecordVerificationContext {
        authority: CurrentAuthorityContext {
            trust: trust(150, &owner),
            checkpoint: a.snapshot().checkpoint().unwrap(),
        },
        tenant_node_id: NODE,
        organisation_id: "fixture-org",
        current_record: CurrentRecord::new(1, r.record_digest().unwrap()).unwrap(),
    };
    assert!(alternate_record.verify(&checked, &ctx, &Backend).is_err());
}
#[test]
fn exact_current_context_is_mandatory_and_candidate_never_advances_it() {
    let a = authority();
    let owner = point(1);
    let candidate = a.verify_candidate(&trust(150, &owner), &Backend).unwrap();
    let checkpoint = a.snapshot().checkpoint().unwrap();
    for supplied in [
        AuthorityCheckpoint::new(6, checkpoint.body_digest()).unwrap(),
        AuthorityCheckpoint::new(8, checkpoint.body_digest()).unwrap(),
        AuthorityCheckpoint::new(7, [9; 32]).unwrap(),
    ] {
        assert!(candidate
            .require_current(&CurrentAuthorityContext {
                trust: trust(150, &owner),
                checkpoint: supplied
            })
            .is_err());
    }
    let wrong = point(2);
    assert!(a.verify_candidate(&trust(150, &wrong), &Backend).is_err());
    assert!(candidate
        .require_current(&CurrentAuthorityContext {
            trust: trust(150, &wrong),
            checkpoint
        })
        .is_err());
    for now in [89, 400, u64::MAX] {
        assert!(a.verify_candidate(&trust(now, &owner), &Backend).is_err());
    }
    for owner_id in ["different", "fixture-owner "] {
        let mut t = trust(150, &owner);
        t.owner_id = owner_id;
        assert!(a.verify_candidate(&t, &Backend).is_err());
    }
    let mut t = trust(150, &owner);
    t.fleet_id = NODE;
    assert!(a.verify_candidate(&t, &Backend).is_err());
    let r = record();
    let ctx = RecordVerificationContext {
        authority: CurrentAuthorityContext {
            trust: trust(150, &owner),
            checkpoint,
        },
        tenant_node_id: NODE,
        organisation_id: "fixture-org",
        current_record: CurrentRecord::new(2, r.record_digest().unwrap()).unwrap(),
    };
    assert!(r.verify(&candidate, &ctx, &Backend).is_err());
}
#[test]
fn verify_only_preserves_bounded_records_but_removal_or_core_change_revokes() {
    let a = SignedAuthority::parse(VERIFY_ONLY.trim()).unwrap();
    let owner = point(1);
    let delegate = point(2);
    let candidate = a.verify_candidate(&trust(150, &owner), &Backend).unwrap();
    let context = CurrentAuthorityContext {
        trust: trust(150, &owner),
        checkpoint: a.snapshot().checkpoint().unwrap(),
    };
    assert!(candidate
        .registration_grant(GRANT, &context, &registration(&delegate))
        .is_err());
    assert!(verify_record(&a, &record(), 150));
    assert_eq!(
        a.snapshot().fields().grants[0].core().digest(),
        authority().snapshot().fields().grants[0].core().digest()
    );
    let mut fields = a.snapshot().fields().clone();
    fields.sequence = 9;
    fields.grants.clear();
    assert!(!verify_record(&signed(fields), &record(), 150));
    let mut fields = a.snapshot().fields().clone();
    let mut core = fields.grants[0].core().fields().clone();
    core.operator_policy_digest[0] ^= 1;
    fields.grants = vec![AuthorityGrant::new(
        GrantCore::new(core).unwrap(),
        GrantMode::VerifyOnly,
    )];
    assert!(!verify_record(&signed(fields), &record(), 150));
}
#[test]
fn register_mode_checks_all_independent_scope_key_policy_and_protection_facts() {
    let a = authority();
    let owner = point(1);
    let delegate = point(2);
    let candidate = a.verify_candidate(&trust(150, &owner), &Backend).unwrap();
    let current = CurrentAuthorityContext {
        trust: trust(150, &owner),
        checkpoint: a.snapshot().checkpoint().unwrap(),
    };
    candidate
        .registration_grant(GRANT, &current, &registration(&delegate))
        .unwrap();
    for change in 0..7 {
        let mut request = registration(&delegate);
        match change {
            0 => request.tenant_node_id = FLEET,
            1 => request.organisation_id = "other",
            2 => request.delegate_public_key = &owner,
            3 => request.delegate_key_version = 2,
            4 => request.operator_policy_digest = [0; 32],
            5 => request.epoch = 4,
            _ => request.replacement = true,
        }
        assert!(candidate
            .registration_grant(GRANT, &current, &request)
            .is_err());
    }
    for (now, expected) in [(99, false), (100, true), (199, true), (200, false)] {
        let current = CurrentAuthorityContext {
            trust: trust(now, &owner),
            checkpoint: a.snapshot().checkpoint().unwrap(),
        };
        assert_eq!(
            candidate
                .registration_grant(GRANT, &current, &registration(&delegate))
                .is_ok(),
            expected
        );
    }
    let mut f = a.snapshot().fields().clone();
    let mut core = f.grants[0].core().fields().clone();
    core.key_protection_floor = KeyProtection::Pkcs11ReportedNonExtractable;
    f.grants = vec![AuthorityGrant::new(
        GrantCore::new(core).unwrap(),
        GrantMode::Register,
    )];
    let high = signed(f);
    let checked = high
        .verify_candidate(&trust(150, &owner), &Backend)
        .unwrap();
    assert!(checked
        .registration_grant(
            GRANT,
            &CurrentAuthorityContext {
                trust: trust(150, &owner),
                checkpoint: high.snapshot().checkpoint().unwrap()
            },
            &registration(&delegate)
        )
        .is_err());
}
#[test]
fn shape_correct_off_curve_delegate_is_refused_even_under_valid_owner_signature() {
    let mut raw = [0xff; 33];
    raw[0] = 2;
    let invalid = P256PublicKey::new(&raw).unwrap();
    assert!(Backend.validate_public_key(&invalid).is_err());
    let mut f = authority().snapshot().fields().clone();
    let mut g = f.grants[0].core().fields().clone();
    g.delegate_public_key = invalid;
    f.grants = vec![AuthorityGrant::new(
        GrantCore::new(g).unwrap(),
        GrantMode::Register,
    )];
    let a = signed(f);
    Backend
        .verify_p256(&point(1), &a.snapshot().encode().unwrap(), a.signature())
        .unwrap();
    assert!(a
        .verify_candidate(&trust(150, &point(1)), &Backend)
        .is_err());
}
#[test]
fn every_signed_body_and_proof_byte_is_bound_by_real_crypto() {
    let a = authority();
    let body = a.snapshot().encode().unwrap();
    for i in 0..body.len() {
        let mut bad = body.clone();
        bad[i] ^= 1;
        let wire = format!(
            "{AUTHORITY_PREFIX};body={};owner_signature={}",
            hex::encode(bad),
            hex::encode(a.signature().as_bytes())
        );
        if let Ok(parsed) = SignedAuthority::parse(&wire) {
            assert!(
                parsed
                    .verify_candidate(&trust(150, &point(1)), &Backend)
                    .is_err(),
                "authority byte {i}"
            );
        }
    }
    let r = record();
    let proof = r.draft().proof_message().unwrap();
    for i in 0..proof.len() {
        let mut bad = proof.clone();
        bad[i] ^= 1;
        assert!(
            Backend
                .verify_p256(&point(2), &bad, r.delegate_signature())
                .is_err(),
            "proof byte {i}"
        );
    }
}
#[test]
fn record_lifetime_replacement_epoch_and_sequence_are_checked_even_when_resigned() {
    let a = authority();
    let r = record();
    for change in 0..5 {
        let mut f = r.draft().fields().clone();
        match change {
            0 => f.proof.registered_at = 99,
            1 => f.proof.not_after = 321,
            2 => f.proof.previous_record_digest = Some([1; 32]),
            3 => f.proof.authority_sequence_at_registration = 8,
            _ => f.proof.not_after = 501,
        }
        assert!(!verify_record(&a, &signed_record(f), 150));
    }
    for now in [119, 300] {
        assert!(!verify_record(&a, &r, now));
    }
    let mut af = a.snapshot().fields().clone();
    let mut g = af.grants[0].core().fields().clone();
    g.max_record_lifetime_seconds = u64::MAX;
    let core = GrantCore::new(g).unwrap();
    let mut rf = r.draft().fields().clone();
    rf.proof.grant_digest = core.digest().unwrap();
    af.grants = vec![AuthorityGrant::new(core, GrantMode::Register)];
    assert!(!verify_record(&signed(af), &signed_record(rf), 150));
}
#[test]
fn strict_envelopes_counts_widths_and_constructor_bounds_reject_without_panics() {
    let a = authority();
    let wire = a.to_wire().unwrap();
    for bad in [
        format!(" {wire}"),
        format!("{wire};unknown=1"),
        wire.replace("owner_signature=", "signature="),
        wire.replace("body=", "body=A"),
        format!("{wire}\n"),
        "x".repeat(MAX_AUTHORITY_WIRE + 1),
    ] {
        assert!(SignedAuthority::parse(&bad).is_err());
    }
    let body = a.snapshot().encode().unwrap();
    for n in 0..body.len() {
        let bad = format!(
            "{AUTHORITY_PREFIX};body={};owner_signature={}",
            hex::encode(&body[..n]),
            hex::encode(a.signature().as_bytes())
        );
        assert!(SignedAuthority::parse(&bad).is_err());
    }
    let mut f = a.snapshot().fields().clone();
    f.grants = vec![f.grants[0].clone(); 17];
    assert!(AuthoritySnapshot::new(f).is_err());
    let mut f = a.snapshot().fields().clone();
    f.grants.push(f.grants[0].clone());
    assert!(AuthoritySnapshot::new(f).is_err());
    let mut f = a.snapshot().fields().clone();
    f.sequence = 0;
    assert!(AuthoritySnapshot::new(f).is_err());
    for change in 0..7 {
        let mut f = a.snapshot().fields().grants[0].core().fields().clone();
        match change {
            0 => f.delegate_key_version = 0,
            1 => f.max_record_lifetime_seconds = 0,
            2 => f.register_until = f.not_before,
            3 => f.minimum_epoch = 4,
            4 => f.organisation_id = "x".repeat(129),
            5 => f.profile = "other".to_owned(),
            _ => f.delegation_id = "00000000-0000-0000-0000-000000000000".to_owned(),
        }
        assert!(GrantCore::new(f).is_err());
    }
    let r = record().to_wire();
    for bad in [
        r.replace("epoch=1;", "epoch=01;"),
        r.replace("owner_proof=delegation-v1", "owner_proof=owner_signature"),
        r.replace("previous_record_digest=-", "previous_record_digest="),
        r.replace("previous_record_digest=-", "previous_record_digest=00"),
        r.replace(
            "serials=host:fixture-1",
            "serials=host:fixture-1,host:fixture-1",
        ),
        format!("{r};extra=1"),
        "x".repeat(MAX_RECORD_BYTES + 1),
    ] {
        assert!(DelegatedDeviceRecord::parse(&bad).is_err());
    }
    let mut seed = 7u64;
    for length in 0..1024 {
        let mut bytes = vec![0; length];
        for b in &mut bytes {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = seed.to_be_bytes()[3];
        }
        let candidate = format!(
            "{AUTHORITY_PREFIX};body={};owner_signature={}",
            hex::encode(bytes),
            hex::encode(a.signature().as_bytes())
        );
        assert!(SignedAuthority::parse(&candidate).is_err());
    }
}

#[test]
fn canonical_text_order_count_and_raw_body_bounds_are_explicit() {
    let base = authority();
    for name in ["e\u{301}", " owner", "owner\n"] {
        let mut fields = base.snapshot().fields().clone();
        fields.owner_id = name.to_owned();
        assert!(AuthoritySnapshot::new(fields).is_err());
    }
    let core = base.snapshot().fields().grants[0].core().fields().clone();
    let mut fields = base.snapshot().fields().clone();
    fields.grants.clear();
    for number in 1..=16 {
        let mut grant = core.clone();
        grant.delegation_id = format!("{number:08x}-0000-0000-0000-000000000001");
        fields.grants.push(AuthorityGrant::new(
            GrantCore::new(grant).unwrap(),
            GrantMode::Register,
        ));
    }
    assert!(AuthoritySnapshot::new(fields.clone()).is_ok());
    fields.grants.reverse();
    assert!(AuthoritySnapshot::new(fields).is_err());
    let oversized = format!(
        "{AUTHORITY_PREFIX};body={};owner_signature={}",
        "00".repeat(MAX_AUTHORITY_BODY + 1),
        hex::encode(base.signature().as_bytes())
    );
    assert!(oversized.len() < MAX_AUTHORITY_WIRE);
    assert!(SignedAuthority::parse(&oversized).is_err());
    for raw in [vec![0; 0], vec![2; 32], vec![4; 33], vec![2; 34]] {
        assert!(P256PublicKey::new(&raw).is_err());
    }
    let mut malformed = base.signature().as_bytes().to_vec();
    malformed.push(0);
    assert!(
        SignedAuthority::new(base.snapshot().clone(), Signature::new(malformed).unwrap()).is_err()
    );
    assert!(DelegatedDeviceRecord::parse(&record().to_wire().replace("key=", "key=04")).is_err());
}

#[test]
fn constructor_bounds_raw_number_spelling_before_retaining_legacy_payload() {
    use tessera_codes_contract::{
        device_number::CheckedDeviceNumber,
        registry::{PayloadFields, RecordPayload},
    };
    let mut fields = record().draft().fields().clone();
    let original = fields.payload.clone();
    fields.payload = RecordPayload::new(PayloadFields {
        device_number: CheckedDeviceNumber::parse(&format!("{}77000123S", " ".repeat(65))).unwrap(),
        public_key: original.public_key().clone(),
        epoch: original.epoch(),
        serials: original.serials().to_vec(),
        key_protection: original.key_protection(),
        anchor: original.anchor(),
        batch: original.batch(),
        baseline: *original.baseline(),
    })
    .unwrap();
    assert!(DelegatedRecordDraft::new(fields).is_err());
}

#[test]
fn independent_direct_v1_record_still_verifies_and_dispatches_without_delegation_alias() {
    let wire = include_str!("golden/registration/legacy-record.wire").trim();
    let direct = DeviceRecord::parse(wire).unwrap();
    direct.verify(&Backend).unwrap();
    assert_eq!(direct.to_wire(), wire);
    assert!(matches!(
        RegistryRecord::parse(wire).unwrap(),
        RegistryRecord::Direct(_)
    ));
    assert!(DelegatedDeviceRecord::parse(wire).is_err());
}

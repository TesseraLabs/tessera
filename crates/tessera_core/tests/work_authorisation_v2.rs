//! Independent wire goldens and test-only cryptographic boundary checks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use openssl::pkey::{Id, PKey, Private};
use openssl::sign::{Signer, Verifier};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::engineer::{Devices, EngineerAuthorisation};
use tessera_codes_contract::signature::{Signature, SignatureError, SignatureVerifier, SignerRef};
use tessera_core::mac::IntegrityLabel;
use tessera_core::role::{verify_catalogue, CatalogueError, RoleId, RoleOs, VerifiedRoleCatalogue};
use tessera_core::work_authorisation::*;
use uuid::Uuid;

fn role(codes: Option<u8>, certificate: Option<IntegrityLabel>) -> RoleBounds {
    RoleBounds::new(RoleBoundsFields {
        role_id: RoleId::new("oper").unwrap(),
        target_os: RoleOs::Astra,
        stream_id: "roles-astra".into(),
        trust_sha256: [0x22; 32],
        bundle_version: 9,
        manifest_sha256: [0x33; 32],
        slice_version: 3,
        slice_sha256: [0x44; 32],
        codes_max_level: codes,
        certificate,
    })
    .unwrap()
}

fn intent(variant: usize) -> WorkIntent {
    let (id, devices, codes, certificate) = match variant {
        0 => (
            1,
            Devices::Any,
            Some(0),
            Some(IntegrityLabel {
                level: -128,
                categories: u64::MAX,
            }),
        ),
        1 => (
            4,
            Devices::only(&[CheckedDeviceNumber::parse("AH").unwrap()]).unwrap(),
            Some(127),
            None,
        ),
        _ => (
            5,
            Devices::only(&[CheckedDeviceNumber::parse("AH").unwrap()]).unwrap(),
            None,
            Some(IntegrityLabel {
                level: 127,
                categories: 0,
            }),
        ),
    };
    WorkIntent::new(WorkIntentFields {
        authorisation_id: Uuid::from_u128(id),
        fleet_id: Uuid::from_u128(2),
        tenant_node_id: Uuid::from_u128(3),
        engineer: "eng-1".into(),
        organisation: "org-1".into(),
        key_fingerprint: [0x11; 32],
        devices,
        tags: vec!["site-a".into()],
        not_before: 10,
        not_after: 20,
        roles: vec![role(codes, certificate)],
    })
    .unwrap()
}

fn expected(intent: &WorkIntent) -> ExpectedIdentity<'_> {
    let f = intent.fields();
    ExpectedIdentity {
        fleet_id: f.fleet_id,
        tenant_node_id: f.tenant_node_id,
        engineer: &f.engineer,
        organisation: &f.organisation,
        key_fingerprint: &f.key_fingerprint,
    }
}

fn key(seed: u8) -> PKey<Private> {
    // Public deterministic fixture seeds, never product keys.
    PKey::private_key_from_raw_bytes(&[seed; 32], Id::ED25519).unwrap()
}

struct TestVerifier(PKey<Private>);
impl SignatureVerifier for TestVerifier {
    fn verify(
        &self,
        signer: SignerRef<'_>,
        bytes: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        if !matches!(signer, SignerRef::AuthorisationKey) {
            return Err(SignatureError::UnknownSigner);
        }
        let mut verifier = Verifier::new_without_digest(&self.0)
            .map_err(|e| SignatureError::Backend(e.to_string()))?;
        if verifier
            .verify_oneshot(signature.as_bytes(), bytes)
            .unwrap_or(false)
        {
            Ok(())
        } else {
            Err(SignatureError::Rejected)
        }
    }
}

fn signed(intent: WorkIntent) -> WorkAuthorisation {
    let signature = Signer::new_without_digest(&key(0x42))
        .unwrap()
        .sign_oneshot_to_vec(&intent.encode_body().unwrap())
        .unwrap();
    WorkAuthorisation::new(intent, Signature::new(signature).unwrap()).unwrap()
}

#[test]
fn independent_canonical_goldens_hold_without_changing_v1() {
    let goldens = [
        include_str!("fixtures/work_authorisation_v2/a.hex"),
        include_str!("fixtures/work_authorisation_v2/b.hex"),
        include_str!("fixtures/work_authorisation_v2/c.hex"),
    ];
    let hashes = [
        "dd28dac7f96514f8e73e46b231520be7fea3f0566864a448d58682d7051a3f37",
        "6daa553907e3ee71fab79e121003917751884918186c611f08682433d9f1a10e",
        "b80c8769ade7f0caa6e5f17b0e334c4bc931ecdbf68d044bdb3931f497d61704",
    ];
    let draft_hashes = [
        "e7e7bc9b6425c7a03b51b6e37d1f77579f12711d1e9a765fc1f6a37a9698b601",
        "0f95f8ec9b398d73bd9c1bf1c2dca6ca14b1db4ad4d193c30d01582893955153",
        "0cbe2afd48caf17c221ce5dc2fee2b2d937cf48e314e7162d814045ddf97116a",
    ];
    for (i, golden) in goldens.iter().enumerate() {
        let expected_body = hex::decode(golden.split_whitespace().collect::<String>()).unwrap();
        let original = intent(i);
        assert_eq!(original.encode_body().unwrap(), expected_body);
        assert_eq!(hex::encode(original.body_digest().unwrap()), hashes[i]);
        assert_eq!(
            hex::encode(original.approval_digest().unwrap()),
            draft_hashes[i]
        );
        assert_eq!(WorkIntent::parse_body(&expected_body).unwrap(), original);
        assert!(EngineerAuthorisation::parse(&original.draft_wire().unwrap()).is_err());
        let document = signed(original);
        assert_eq!(
            WorkAuthorisation::parse(&document.to_wire().unwrap()).unwrap(),
            document
        );
        assert!(document
            .verify(&TestVerifier(key(0x42)), expected(document.intent()))
            .is_ok());
        assert!(document
            .verify(&TestVerifier(key(0x43)), expected(document.intent()))
            .is_err());
    }
    assert!(WorkAuthorisation::parse(
        "tessera-codes/v1/engineer-authorisation;body=00;signature=00"
    )
    .is_err());
}

#[test]
fn every_body_byte_is_covered_and_placeholders_are_not_signatures() {
    let original = intent(0);
    let document = signed(original.clone());
    let verifier = TestVerifier(key(0x42));
    let body = original.encode_body().unwrap();
    let mut well_formed_mutations = 0;
    for index in 0..body.len() {
        let mut changed = body.clone();
        changed[index] ^= 1;
        if let Ok(changed) = WorkIntent::parse_body(&changed) {
            well_formed_mutations += 1;
            let tampered = WorkAuthorisation::new(changed, document.signature().clone()).unwrap();
            assert!(
                tampered.verify(&verifier, expected(&original)).is_err(),
                "byte {index}"
            );
        }
    }
    assert!(well_formed_mutations > 150);
    let placeholder = WorkAuthorisation::parse(&original.draft_wire().unwrap()).unwrap();
    assert!(placeholder.verify(&verifier, expected(&original)).is_err());
    let mut signature = document.signature().as_bytes().to_vec();
    signature[0] ^= 1;
    assert!(
        WorkAuthorisation::new(original.clone(), Signature::new(signature).unwrap())
            .unwrap()
            .verify(&verifier, expected(&original))
            .is_err()
    );
}

#[test]
fn caller_context_including_fingerprint_is_mandatory_and_zero_is_not_wildcard() {
    let document = signed(intent(0));
    let verifier = TestVerifier(key(0x42));
    let identity = expected(document.intent());
    for wrong in [
        ExpectedIdentity {
            fleet_id: Uuid::from_u128(8),
            ..identity
        },
        ExpectedIdentity {
            tenant_node_id: Uuid::from_u128(8),
            ..identity
        },
        ExpectedIdentity {
            engineer: "other",
            ..identity
        },
        ExpectedIdentity {
            organisation: "other",
            ..identity
        },
        ExpectedIdentity {
            key_fingerprint: &[0; 32],
            ..identity
        },
    ] {
        assert!(matches!(
            document.verify(&verifier, wrong),
            Err(WorkAuthorisationError::Context(_))
        ));
    }
    let mut fields = document.intent().fields().clone();
    fields.key_fingerprint = [0; 32];
    let unverified_key = signed(WorkIntent::new(fields).unwrap());
    assert!(unverified_key.verify(&verifier, identity).is_err());
    assert!(unverified_key
        .verify(&verifier, expected(unverified_key.intent()))
        .is_ok());
}

#[test]
fn methods_are_independent_missing_means_unavailable_and_scopes_keep_old_semantics() {
    let verifier = TestVerifier(key(0x42));
    let role_id = RoleId::new("oper").unwrap();
    let other = RoleId::new("other").unwrap();
    for variant in 0..3 {
        let document = signed(intent(variant));
        let checked = document
            .verify(&verifier, expected(document.intent()))
            .unwrap();
        assert_eq!(
            checked
                .check_codes_coverage(&role_id, RoleOs::Astra, 0)
                .is_ok(),
            variant != 2
        );
        assert_eq!(
            checked
                .check_codes_coverage(&role_id, RoleOs::Astra, 1)
                .is_ok(),
            variant == 1
        );
        assert!(checked
            .check_codes_coverage(&role_id, RoleOs::Astra, 128)
            .is_err());
        assert!(checked
            .check_codes_coverage(&role_id, RoleOs::Linux, 0)
            .is_err());
        assert!(checked
            .check_codes_coverage(&other, RoleOs::Astra, 0)
            .is_err());
        assert_eq!(
            checked
                .check_certificate_coverage(
                    &role_id,
                    RoleOs::Astra,
                    IntegrityLabel {
                        level: -128,
                        categories: 0
                    }
                )
                .is_ok(),
            variant != 1
        );
        assert_eq!(
            checked
                .check_certificate_coverage(
                    &role_id,
                    RoleOs::Astra,
                    IntegrityLabel {
                        level: 0,
                        categories: 0
                    }
                )
                .is_ok(),
            variant == 2
        );
        assert_eq!(
            checked
                .check_certificate_coverage(
                    &role_id,
                    RoleOs::Astra,
                    IntegrityLabel {
                        level: -128,
                        categories: 1
                    }
                )
                .is_ok(),
            variant == 0
        );
        let intent = checked.intent();
        assert!(!intent.applies_at(9));
        assert!(intent.applies_at(10));
        assert!(intent.applies_at(19));
        assert!(!intent.applies_at(20));
        assert!(intent.covers_device(&CheckedDeviceNumber::parse("AH").unwrap()));
        assert_eq!(
            intent.covers_device(&CheckedDeviceNumber::from_body("B").unwrap()),
            variant == 0
        );
        assert!(intent.covers_tag("site-a"));
        assert!(!intent.covers_tag("*"));
    }
}

// Every body field, including list counts, is LP framed, so this independent
// walker can target malformed lengths/counts without calling the decoder.
fn spans(bytes: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut offset = 0;
    let mut out = Vec::new();
    while offset < bytes.len() {
        let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        out.push((offset, offset + 4, len));
        offset += 4 + len;
    }
    out
}

#[test]
fn malformed_lengths_counts_flags_ranges_and_noncanonical_envelopes_fail() {
    let original = intent(0);
    let body = original.encode_body().unwrap();
    for end in 0..body.len() {
        assert!(WorkIntent::parse_body(&body[..end]).is_err(), "end {end}");
    }
    let mut extra = body.clone();
    extra.push(0);
    assert!(WorkIntent::parse_body(&extra).is_err());
    assert!(WorkIntent::parse_body(&vec![0; MAX_BODY_BYTES + 1]).is_err());
    let fields = spans(&body);
    for index in [9, 10, 14] {
        let mut changed = body.clone();
        let (_, at, _) = fields[index];
        changed[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(WorkIntent::parse_body(&changed).is_err());
    }
    for (index, value) in [(8, 2), (23, 2), (24, 128), (25, 2)] {
        let mut changed = body.clone();
        changed[fields[index].1] = value;
        assert!(WorkIntent::parse_body(&changed).is_err());
    }
    for index in [1, 2, 7, 12, 18, 21, 26, 27] {
        let mut changed = body.clone();
        let (at, _, length) = fields[index];
        changed[at..at + 4].copy_from_slice(&u32::try_from(length + 1).unwrap().to_be_bytes());
        assert!(WorkIntent::parse_body(&changed).is_err());
    }
    let wire = original.draft_wire().unwrap();
    for invalid in [
        format!(" {wire}"),
        format!("{wire}\n"),
        wire.replace(";body=", ";unknown="),
        wire.replace("signature=00", "signature=0"),
        wire.replace("signature=00", "signature=AA"),
        wire.replace("signature=00", "signature="),
        format!("{wire};extra=1"),
        "x".repeat(MAX_WIRE_BYTES + 1),
    ] {
        assert!(WorkAuthorisation::parse(&invalid).is_err());
    }
    assert!(WorkAuthorisation::new(
        original,
        Signature::new(vec![0; MAX_SIGNATURE_BYTES + 1]).unwrap()
    )
    .is_err());
}

#[test]
fn constructors_enforce_identical_structure_and_aggregate_budgets() {
    let base = intent(0).fields().clone();
    let mut invalid = Vec::new();
    let mut f = base.clone();
    f.fleet_id = Uuid::nil();
    invalid.push(f);
    let mut f = base.clone();
    f.engineer = "a\u{301}".into();
    invalid.push(f);
    let mut f = base.clone();
    f.organisation = "x;bad".into();
    invalid.push(f);
    let mut f = base.clone();
    f.tags = vec!["b".into(), "a".into()];
    invalid.push(f);
    let mut f = base.clone();
    f.tags = vec!["a".into(), "a".into()];
    invalid.push(f);
    let mut f = base.clone();
    f.tags = vec!["a".repeat(257)];
    invalid.push(f);
    let mut f = base.clone();
    f.tags = vec!["a".into(); MAX_TAGS + 1];
    invalid.push(f);
    let mut f = base.clone();
    f.not_after = f.not_before;
    invalid.push(f);
    let mut f = base.clone();
    f.roles.push(f.roles[0].clone());
    invalid.push(f);
    let mut f = base.clone();
    f.roles.clear();
    invalid.push(f);
    let mut f = base.clone();
    f.roles = vec![base.roles[0].clone(); MAX_ROLE_ROWS + 1];
    invalid.push(f);
    let mut f = base.clone();
    let mut row = base.roles[0].fields().clone();
    row.role_id = RoleId::new("z").unwrap();
    row.bundle_version += 1;
    f.roles.push(RoleBounds::new(row).unwrap());
    invalid.push(f);
    for fields in invalid {
        assert!(WorkIntent::new(fields).is_err());
    }
    let mut row = base.roles[0].fields().clone();
    row.codes_max_level = Some(128);
    assert!(RoleBounds::new(row).is_err());
    let mut row = base.roles[0].fields().clone();
    row.codes_max_level = None;
    row.certificate = None;
    assert!(RoleBounds::new(row).is_err());
    let mut large = base;
    large.roles = (0..256)
        .map(|i| {
            let mut row = large.roles[0].fields().clone();
            row.role_id = RoleId::new(&format!("r{i:03}")).unwrap();
            RoleBounds::new(row).unwrap()
        })
        .collect();
    assert!(matches!(
        WorkIntent::new(large),
        Err(WorkAuthorisationError::Oversize("body"))
    ));
}

type CatalogueFixture = (
    VerifiedRoleCatalogue,
    Vec<u8>,
    BTreeMap<RoleId, Vec<u8>>,
    Vec<u8>,
);

fn catalogue(seed: u8, uppercase: bool, metadata: bool) -> CatalogueFixture {
    let key = key(seed);
    let slice = b"role = \"oper\"\nversion = 3\nos = \"astra\"\nname = \"Operator\"\nlevel = 250\n";
    let hash = hex::encode(Sha256::digest(slice));
    let pin = if uppercase {
        format!("  {}  ", hash.to_ascii_uppercase())
    } else {
        hash
    };
    let metadata = if metadata {
        "\n[issuance]\nschema_version = 1\n[issuance.roles.oper.codes]\nmax_level = 7\n[issuance.roles.oper.certificate]\nmax_level = 5\nmax_categories = \"0x3\"\n"
    } else {
        ""
    };
    let unsigned = format!("bundle_version = 9\nos = \"astra\"\n[roles.oper]\nversion = 3\nsha256 = \"{pin}\"\n{metadata}");
    let signature = Signer::new_without_digest(&key)
        .unwrap()
        .sign_oneshot_to_vec(unsigned.as_bytes())
        .unwrap();
    let manifest = format!("signature = \"{}\"\n{unsigned}", hex::encode(signature)).into_bytes();
    let files = BTreeMap::from([(RoleId::new("oper").unwrap(), slice.to_vec())]);
    let pem = key.public_key_to_pem().unwrap();
    (
        verify_catalogue(&manifest, &files, &pem, None, None).unwrap(),
        manifest,
        files,
        pem,
    )
}

fn bound_intent(catalogue: &VerifiedRoleCatalogue) -> WorkIntent {
    let mut f = intent(0).fields().clone();
    let mut row = f.roles[0].fields().clone();
    row.trust_sha256 = catalogue.trust_sha256();
    row.bundle_version = catalogue.checkpoint().bundle_version();
    row.manifest_sha256 = catalogue.checkpoint().manifest_sha256();
    row.slice_sha256 = hex::decode(
        catalogue
            .roles()
            .values()
            .next()
            .unwrap()
            .pin()
            .sha256
            .trim(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    row.codes_max_level = Some(7);
    row.certificate = Some(IntegrityLabel {
        level: 5,
        categories: 3,
    });
    f.roles = vec![RoleBounds::new(row).unwrap()];
    WorkIntent::new(f).unwrap()
}

fn source(catalogue: &VerifiedRoleCatalogue) -> CatalogueContext<'_> {
    CatalogueContext {
        fleet_id: Uuid::from_u128(2),
        tenant_node_id: Uuid::from_u128(3),
        stream_id: "roles-astra",
        trust_sha256: catalogue.trust_sha256(),
        catalogue,
    }
}

#[test]
fn exact_verified_references_caps_and_normalized_pins_are_checked() {
    let (catalogue, _, _, _) = catalogue(0x51, true, true);
    let original = bound_intent(&catalogue);
    let document = signed(original.clone());
    let verifier = TestVerifier(key(0x42));
    let checked = document.verify(&verifier, expected(&original)).unwrap();
    assert!(checked.check_references(&[source(&catalogue)]).is_ok());
    assert!(checked.check_references(&[]).is_err());
    assert!(checked
        .check_references(&[source(&catalogue), source(&catalogue)])
        .is_err());
    for incorrect in [
        CatalogueContext {
            stream_id: "other",
            ..source(&catalogue)
        },
        CatalogueContext {
            trust_sha256: [0; 32],
            ..source(&catalogue)
        },
        CatalogueContext {
            fleet_id: Uuid::from_u128(8),
            ..source(&catalogue)
        },
        CatalogueContext {
            tenant_node_id: Uuid::from_u128(8),
            ..source(&catalogue)
        },
    ] {
        assert!(checked.check_references(&[incorrect]).is_err());
    }
    for change in 0..10 {
        let mut f = original.fields().clone();
        let mut row = f.roles[0].fields().clone();
        match change {
            0 => row.bundle_version += 1,
            1 => row.manifest_sha256[0] ^= 1,
            2 => row.slice_version += 1,
            3 => row.slice_sha256[0] ^= 1,
            4 => row.codes_max_level = Some(8),
            5 => {
                row.certificate = Some(IntegrityLabel {
                    level: 6,
                    categories: 3,
                });
            }
            6 => {
                row.certificate = Some(IntegrityLabel {
                    level: 5,
                    categories: 4,
                });
            }
            7 => row.role_id = RoleId::new("other").unwrap(),
            8 => row.target_os = RoleOs::Linux,
            _ => row.stream_id = "other".into(),
        }
        f.roles = vec![RoleBounds::new(row).unwrap()];
        let modified = signed(WorkIntent::new(f).unwrap());
        assert!(
            modified
                .verify(&verifier, expected(&original))
                .unwrap()
                .check_references(&[source(&catalogue)])
                .is_err(),
            "change {change}"
        );
    }
}

#[test]
fn retained_actual_key_identity_cannot_be_relabelled_by_context() {
    let (a, manifest, files, _) = catalogue(0x51, false, true);
    let der = key(0x51).public_key_to_der().unwrap();
    let same = verify_catalogue(&manifest, &files, &der, None, None).unwrap();
    assert_eq!(a.trust_sha256(), same.trust_sha256());
    assert_eq!(a.trust_sha256(), <[u8; 32]>::from(Sha256::digest(&der)));
    let (b, _, _, _) = catalogue(0x52, false, true);
    let mut fields = bound_intent(&b).fields().clone();
    let mut row = fields.roles[0].fields().clone();
    row.trust_sha256 = a.trust_sha256(); // All hashes/versions match B, falsely labelled A.
    fields.roles = vec![RoleBounds::new(row).unwrap()];
    let document = signed(WorkIntent::new(fields).unwrap());
    let checked = document
        .verify(&TestVerifier(key(0x42)), expected(document.intent()))
        .unwrap();
    let dishonest_context = CatalogueContext {
        trust_sha256: a.trust_sha256(),
        ..source(&b)
    };
    assert!(checked.check_references(&[dishonest_context]).is_err());
    let rsa = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap())
        .unwrap()
        .public_key_to_der()
        .unwrap();
    assert!(matches!(
        verify_catalogue(&manifest, &files, &rsa, None, None),
        Err(CatalogueError::SigningKeyProfile)
    ));
}

#[test]
fn legacy_catalogue_remains_valid_but_cannot_supply_method_bounds() {
    let (legacy, _, _, _) = catalogue(0x51, false, false);
    let document = signed(bound_intent(&legacy));
    let checked = document
        .verify(&TestVerifier(key(0x42)), expected(document.intent()))
        .unwrap();
    assert!(matches!(
        checked.check_references(&[source(&legacy)]),
        Err(WorkAuthorisationError::Catalogue("metadata"))
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn arbitrary_bounded_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..MAX_BODY_BYTES + 8)) {
        if let Ok(intent) = WorkIntent::parse_body(&bytes) {
            prop_assert_eq!(intent.encode_body().unwrap(), bytes.clone());
        }
        let text = String::from_utf8_lossy(&bytes);
        if let Ok(document) = WorkAuthorisation::parse(&text) {
            prop_assert_eq!(document.to_wire().unwrap(), text.into_owned());
        }
    }
}

#[test]
fn canonical_device_lists_and_unique_role_os_pairs_are_not_repaired() {
    let mut fields = intent(1).fields().clone();
    fields.devices = Devices::only(&[
        CheckedDeviceNumber::from_body("A").unwrap(),
        CheckedDeviceNumber::from_body("B").unwrap(),
    ])
    .unwrap();
    let body = WorkIntent::new(fields).unwrap().encode_body().unwrap();
    let positions = spans(&body);
    let (_, a, alen) = positions[10];
    let (_, b, blen) = positions[11];
    assert_eq!(alen, blen);
    let mut duplicate = body.clone();
    duplicate[b..b + blen].copy_from_slice(&body[a..a + alen]);
    assert!(WorkIntent::parse_body(&duplicate).is_err());
    let mut unsorted = body.clone();
    unsorted[a..a + alen].copy_from_slice(&body[b..b + blen]);
    unsorted[b..b + blen].copy_from_slice(&body[a..a + alen]);
    assert!(WorkIntent::parse_body(&unsorted).is_err());
    let mut lowercase = body.clone();
    lowercase[a] = b'a';
    assert!(WorkIntent::parse_body(&lowercase).is_err());
    let mut fields = intent(0).fields().clone();
    let mut linux = fields.roles[0].fields().clone();
    linux.target_os = RoleOs::Linux;
    linux.stream_id = "roles-linux".into();
    fields.roles.push(RoleBounds::new(linux).unwrap());
    let original = WorkIntent::new(fields).unwrap();
    assert_eq!(
        WorkIntent::parse_body(&original.encode_body().unwrap()).unwrap(),
        original
    );
    let mut reversed = original.fields().clone();
    reversed.roles.reverse();
    assert!(WorkIntent::new(reversed).is_err());
}

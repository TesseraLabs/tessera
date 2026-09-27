//! Owner-signed catalogue boundary, using test-only deterministic Ed25519 keys.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use openssl::pkey::{Id, PKey};
use openssl::sign::Signer;
use sha2::{Digest, Sha256};
use tessera_core::role::catalogue::{verify_catalogue, CatalogueCheckpoint, CatalogueError};
use tessera_core::role::issuance::RoleIssuance;
use tessera_core::role::manifest::{
    last_accepted_bundle_version, parse_manifest, persist_bundle_version, signed_payload,
    verify_manifest, ManifestError, MAX_MANIFEST_BYTES,
};
use tessera_core::role::schema::MAX_SLICE_BYTES;
use tessera_core::role::{RoleId, RoleOs, MAX_ROLES};

const SLICE: &str = "role = \"oper\"\nversion = 3\nos = \"astra\"\nname = \"Operator\"\nlevel = 250\n[payload]\nmac_mask = \"0x3\"\n[session]\nmax_ttl_seconds = 60\n";
const METADATA: &str = "\n[issuance]\nschema_version = 1\n[issuance.roles.oper.codes]\nmax_level = 7\n[issuance.roles.oper.certificate]\nmax_level = -128\nmax_categories = \"0xffffffffffffffff\"\n";

fn sign(unsigned: &str) -> (Vec<u8>, Vec<u8>) {
    // Public fixture seed, never an owner or product key.
    let key = PKey::private_key_from_raw_bytes(&[0x42; 32], Id::ED25519).unwrap();
    let mut signer = Signer::new_without_digest(&key).unwrap();
    let signature = hex::encode(signer.sign_oneshot_to_vec(unsigned.as_bytes()).unwrap());
    (
        format!("signature = \"{signature}\"\n{unsigned}").into_bytes(),
        key.public_key_to_pem().unwrap(),
    )
}

type Fixture = (Vec<u8>, BTreeMap<RoleId, Vec<u8>>, Vec<u8>);

fn fixture(metadata: &str) -> Fixture {
    let unsigned = format!(
        "bundle_version = 9\nos = \"astra\"\n[roles.oper]\nversion = 3\nsha256 = \"{}\"\n{metadata}",
        hex::encode(Sha256::digest(SLICE.as_bytes()))
    );
    let (manifest, key) = sign(&unsigned);
    let files = BTreeMap::from([(RoleId::new("oper").unwrap(), SLICE.as_bytes().to_vec())]);
    (manifest, files, key)
}

#[test]
fn legacy_bytes_and_role_semantics_stay_unchanged() {
    let (manifest, files, key) = fixture("");
    let unsigned = signed_payload(&manifest).unwrap();
    assert_eq!(
        std::str::from_utf8(&unsigned).unwrap(),
        concat!(
            "bundle_version = 9\nos = \"astra\"\n[roles.oper]\nversion = 3\n",
            "sha256 = \"109a03553490a712c34cbe11093f070655324dcb50abd3e2c34272b091f68140\"\n"
        )
    );
    // Signature verification consumes the original bytes, not a serialization
    // of the new schema. A legacy file has no fabricated issuance fields.
    assert_eq!(parse_manifest(&manifest).unwrap().issuance, None);
    assert_eq!(sign(std::str::from_utf8(&unsigned).unwrap()).0, manifest);
    let catalogue = verify_catalogue(&manifest, &files, &key, None, None).unwrap();
    assert_eq!(catalogue.issuance_schema_version(), None);
    assert_eq!(catalogue.os(), RoleOs::Astra);
    let role = catalogue.roles().values().next().unwrap();
    assert_eq!(role.slice().level, 250);
    assert_eq!(
        role.slice().session.as_ref().unwrap().max_ttl_seconds,
        Some(60)
    );
    assert_eq!(
        role.slice().payload.as_ref().unwrap().mac_mask.as_deref(),
        Some("0x3")
    );
    assert!(role.issuance().is_none());
    assert_eq!(
        catalogue.checkpoint().manifest_sha256(),
        <[u8; 32]>::from(Sha256::digest(&manifest))
    );
}

#[test]
fn explicit_bounds_are_independent_of_display_level_mask_and_host() {
    let (manifest, files, key) = fixture(METADATA);
    let catalogue = verify_catalogue(&manifest, &files, &key, Some(9), None).unwrap();
    assert_eq!(catalogue.issuance_schema_version(), Some(1));
    let role = catalogue.roles().values().next().unwrap();
    let bounds = role.issuance().unwrap();
    assert_eq!(bounds.codes().unwrap().max_level(), 7);
    assert_eq!(bounds.certificate().unwrap().level, -128);
    assert_eq!(bounds.certificate().unwrap().categories, u64::MAX);
    assert_eq!(role.pin().version, 3);
    assert_eq!(role.slice().level, 250);
    for metadata in [
        "[issuance]\nschema_version = 1\n[issuance.roles.oper.codes]\nmax_level = 127\n",
        "[issuance]\nschema_version = 1\n[issuance.roles.oper.certificate]\nmax_level = 127\nmax_categories = \"0\"\n",
        "[issuance]\nschema_version = 1\n[issuance.roles.oper]\n",
        "[issuance]\nschema_version = 1\nroles = {}\n",
    ] {
        let (manifest, files, key) = fixture(metadata);
        let catalogue = verify_catalogue(&manifest, &files, &key, None, None).unwrap();
        let role = catalogue.roles().values().next().unwrap();
        assert_eq!(role.issuance().and_then(RoleIssuance::codes).is_some(), metadata.contains(".codes]"));
        assert_eq!(role.issuance().and_then(RoleIssuance::certificate).is_some(), metadata.contains(".certificate]"));
    }
}

#[test]
fn closed_schema_rejects_unknown_missing_and_malformed_bounds() {
    let invalid = [
        METADATA.replace("schema_version = 1", "schema_version = 2"),
        METADATA.replace("schema_version = 1", "schema_version = -1"),
        METADATA.replace("schema_version = 1", "extra = 1\nschema_version = 1"),
        METADATA.replace("schema_version = 1", ""),
        METADATA.replace("roles.oper", "roles.other"),
        METADATA.replace(".codes]", ".unknown]"),
        METADATA.replace("max_level = 7", "max_level = 128"),
        METADATA.replace("max_level = 7", "max_level = -1"),
        METADATA.replace("max_level = 7", "max_level = 1.5"),
        METADATA.replace("max_level = 7", "max_level = \"7\""),
        METADATA.replace("max_level = 7", "max_level = 7\nextra = 1"),
        METADATA.replace("max_level = 7", ""),
        METADATA.replace("max_level = -128", "max_level = -129"),
        METADATA.replace("max_level = -128", "max_level = 128"),
        METADATA.replace(
            "max_categories = \"0xffffffffffffffff\"",
            "max_categories = \"0x10000000000000000\"",
        ),
        METADATA.replace(
            "max_categories = \"0xffffffffffffffff\"",
            "max_categories = \"-1\"",
        ),
        METADATA.replace(
            "max_categories = \"0xffffffffffffffff\"",
            "max_categories = 1",
        ),
        METADATA.replace("max_categories = \"0xffffffffffffffff\"", ""),
        format!("{METADATA}\n[issuance.roles.oper.codes]\nmax_level = 2\n"),
    ];
    for metadata in invalid {
        let (manifest, files, key) = fixture(&metadata);
        assert!(parse_manifest(&manifest).is_err(), "{metadata}");
        assert!(
            verify_catalogue(&manifest, &files, &key, None, None).is_err(),
            "{metadata}"
        );
    }
}

#[test]
fn signature_pins_schema_versions_and_role_files_are_all_required() {
    let (manifest, files, key) = fixture(METADATA);
    let tampered = String::from_utf8(manifest.clone())
        .unwrap()
        .replace("max_level = 7", "max_level = 8");
    assert!(matches!(
        verify_catalogue(tampered.as_bytes(), &files, &key, None, None),
        Err(CatalogueError::Manifest(ManifestError::BadSignature))
    ));
    assert!(matches!(
        verify_catalogue(&manifest, &BTreeMap::new(), &key, None, None),
        Err(CatalogueError::Manifest(ManifestError::SliceMissing { .. }))
    ));
    let mut modified = files.clone();
    modified.values_mut().next().unwrap().push(b'\n');
    assert!(matches!(
        verify_catalogue(&manifest, &modified, &key, None, None),
        Err(CatalogueError::Manifest(ManifestError::HashMismatch { .. }))
    ));
    let unsigned = String::from_utf8(signed_payload(&manifest).unwrap()).unwrap();
    let (wrong_pin, _) = sign(&unsigned.replace("version = 3", "version = 4"));
    assert!(matches!(
        verify_catalogue(&wrong_pin, &files, &key, None, None),
        Err(CatalogueError::SliceVersion { .. })
    ));
    modified = files.clone();
    modified.insert(RoleId::new("other").unwrap(), Vec::new());
    assert!(matches!(
        verify_catalogue(&manifest, &modified, &key, None, None),
        Err(CatalogueError::UnlistedRole { .. })
    ));
    let malformed = SLICE.replace("role = \"oper\"", "role = \"other\"");
    modified = BTreeMap::from([(RoleId::new("oper").unwrap(), malformed.as_bytes().to_vec())]);
    let (wrong_slice, _) = sign(&unsigned.replace(
        &hex::encode(Sha256::digest(SLICE.as_bytes())),
        &hex::encode(Sha256::digest(malformed.as_bytes())),
    ));
    assert!(matches!(
        verify_catalogue(&wrong_slice, &modified, &key, None, None),
        Err(CatalogueError::Slice { .. })
    ));
}

#[test]
fn checkpoint_rejects_rollback_and_equal_version_equivocation() {
    let (manifest, files, key) = fixture(METADATA);
    let accepted = verify_catalogue(&manifest, &files, &key, None, None)
        .unwrap()
        .checkpoint();
    assert!(verify_catalogue(&manifest, &files, &key, None, Some(&accepted)).is_ok());
    assert!(matches!(
        verify_catalogue(&manifest, &files, &key, Some(10), None),
        Err(CatalogueError::Manifest(ManifestError::Rollback { .. }))
    ));
    let higher = CatalogueCheckpoint::new(10, accepted.manifest_sha256());
    assert!(matches!(
        verify_catalogue(&manifest, &files, &key, None, Some(&higher)),
        Err(CatalogueError::Manifest(ManifestError::Rollback { .. }))
    ));
    let unsigned = String::from_utf8(signed_payload(&manifest).unwrap()).unwrap();
    let (changed, _) = sign(&unsigned.replace("max_level = 7", "max_level = 8"));
    assert!(matches!(
        verify_catalogue(&changed, &files, &key, None, Some(&accepted)),
        Err(CatalogueError::Equivocation { version: 9 })
    ));
    let (next, _) = sign(&unsigned.replace("bundle_version = 9", "bundle_version = 10"));
    assert!(verify_catalogue(&next, &files, &key, None, Some(&accepted)).is_ok());
}

#[test]
fn projection_is_bounded() {
    let (manifest, mut files, key) = fixture(METADATA);
    assert!(matches!(
        verify_catalogue(
            &vec![b' '; MAX_MANIFEST_BYTES + 1],
            &files,
            &key,
            None,
            None
        ),
        Err(CatalogueError::Manifest(ManifestError::Oversize { .. }))
    ));
    files
        .values_mut()
        .next()
        .unwrap()
        .resize(MAX_SLICE_BYTES + 1, b' ');
    assert!(matches!(
        verify_catalogue(&manifest, &files, &key, None, None),
        Err(CatalogueError::Slice {
            source: tessera_core::role::RoleSchemaError::Oversize { .. },
            ..
        })
    ));
    files = (0..=MAX_ROLES)
        .map(|i| (RoleId::new(&format!("r{i}")).unwrap(), Vec::new()))
        .collect();
    assert!(matches!(
        verify_catalogue(&manifest, &files, &key, None, None),
        Err(CatalogueError::TooManyRoles)
    ));
}

#[cfg(unix)]
#[test]
fn invalid_issuance_never_establishes_or_advances_device_floor() {
    let (manifest, files, key) = fixture(&METADATA.replace("max_level = 7", "max_level = 128"));
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("manifest.toml"), manifest).unwrap();
    for (role, bytes) in files {
        std::fs::write(directory.path().join(format!("{role}.toml")), bytes).unwrap();
    }
    let persist = tempfile::tempdir().unwrap();
    assert!(verify_manifest(directory.path(), RoleOs::Astra, &key, persist.path()).is_err());
    assert_eq!(last_accepted_bundle_version(persist.path()).unwrap(), None);
    persist_bundle_version(persist.path(), 8).unwrap();
    assert!(verify_manifest(directory.path(), RoleOs::Astra, &key, persist.path()).is_err());
    assert_eq!(
        last_accepted_bundle_version(persist.path()).unwrap(),
        Some(8)
    );
}

#[test]
fn old_closed_reader_requires_upgrade_before_issuance_publication() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OldManifest {
        #[serde(rename = "bundle_version")]
        _bundle_version: u64,
        #[serde(rename = "os")]
        _os: RoleOs,
        #[serde(rename = "signature")]
        _signature: String,
        #[serde(rename = "roles")]
        _roles: BTreeMap<RoleId, tessera_core::role::ManifestRole>,
    }
    let (legacy, _, _) = fixture("");
    assert!(toml::from_str::<OldManifest>(std::str::from_utf8(&legacy).unwrap()).is_ok());
    let (metadata, _, _) = fixture(METADATA);
    assert!(toml::from_str::<OldManifest>(std::str::from_utf8(&metadata).unwrap()).is_err());
}

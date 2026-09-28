#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use super::*;
use crate::codes::tickets::tests::{ticket, Authority};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    sign::Signer,
    x509::{X509NameBuilder, X509},
};
use std::fmt::Write as _;

struct Fixture {
    _temp: tempfile::TempDir,
    source: PathBuf,
    keys: LocalEnrollmentKeys,
    paths: PublicInstallPaths,
    owner: PKey<Private>,
    leaf: Vec<u8>,
    unsigned: String,
}
fn leaf(keys: &LocalEnrollmentKeys) -> Vec<u8> {
    let ca = PKey::generate_ed25519().unwrap();
    let public = PKey::public_key_from_der(&keys.tls_spki().unwrap()).unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    let serial = Asn1Integer::from_bn(&BigNum::from_u32(3).unwrap()).unwrap();
    cert.set_serial_number(&serial).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "fixture-only").unwrap();
    let name = name.build();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&public).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&ca, MessageDigest::null()).unwrap();
    cert.build().to_der().unwrap()
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let source = temp.path().join("public");
        disk::make_directory(&source).unwrap();
        let keys = LocalEnrollmentKeys::create_new(&temp.path().join("local")).unwrap();
        let leaf = leaf(&keys);
        let owner = PKey::private_key_from_raw_bytes(&[0x46; 32], Id::ED25519).unwrap();
        let output = temp.path().join("installed");
        disk::make_directory(&output).unwrap();
        let paths = PublicInstallPaths {
            roles_dir: output.join("roles"),
            persist_dir: output.join("floor"),
            crl_path: output.join("device.crl"),
            tls_leaf_path: output.join("transport.der"),
            codes: CodesPaths::under(&output.join("codes")),
        };
        let slice =
            b"role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"Operator\"\nlevel = 1\n";
        fs::write(source.join("oper.toml"), slice).unwrap();
        let authority = Authority::new();
        let tickets = authority.sign(ticket("fixture", 3, "T-001")).to_wire();
        fs::write(source.join("tickets.txt"), tickets.as_bytes()).unwrap();
        fs::write(source.join("anchor.pem"), authority.public_key_pem()).unwrap();
        fs::write(source.join("urls.txt"), b"https://codes.example.test/\n").unwrap();
        fs::write(source.join("revoked.txt"), b"T-009\n").unwrap();
        let mut unsigned=format!("bundle_version = 7\nos = \"linux\"\n[roles.oper]\nversion = 1\nsha256 = \"{}\"\n[codes]\nepoch = 1\n",hex::encode(Sha256::digest(slice)));
        for (name, file) in [
            ("tickets", "tickets.txt"),
            ("ticket_authority", "anchor.pem"),
            ("page_urls", "urls.txt"),
            ("ticket_revocations", "revoked.txt"),
        ] {
            write!(
                unsigned,
                "[codes.{name}]\nfile = \"{file}\"\nsha256 = \"{}\"\n",
                hex::encode(Sha256::digest(fs::read(source.join(file)).unwrap()))
            )
            .unwrap();
        }
        let fixture = Self {
            _temp: temp,
            source,
            keys,
            paths,
            owner,
            leaf,
            unsigned,
        };
        fixture.sign(&fixture.unsigned);
        fixture
    }
    fn sign(&self, unsigned: &str) {
        let mut signer = Signer::new_without_digest(&self.owner).unwrap();
        let signature = hex::encode(signer.sign_oneshot_to_vec(unsigned.as_bytes()).unwrap());
        fs::write(
            self.source.join("manifest.toml"),
            format!("signature = \"{signature}\"\n{unsigned}"),
        )
        .unwrap();
    }
    fn prepare(&self) -> io::Result<PreparedPublicEnrollment> {
        PreparedPublicEnrollment::prepare(
            &self.source,
            RoleOs::Linux,
            &self.owner.public_key_to_pem().unwrap(),
            &self.paths.persist_dir,
            &self.keys,
            &self.leaf,
        )
    }
}

#[test]
fn public_bytes_apply_with_locally_owned_keys_and_exact_repeat() {
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    assert_eq!(
        prepared.state(&f.paths, &f.keys).unwrap(),
        PublicApplyState::Absent
    );
    let before = f.keys.codes_public_key().unwrap();
    let result = prepared
        .apply(
            &f.paths,
            &f.keys,
            Some(Epoch::new(1)),
            SystemAccounts::empty(),
        )
        .unwrap();
    assert_eq!(result.bundle_version(), 7);
    assert_eq!(
        prepared.state(&f.paths, &f.keys).unwrap(),
        PublicApplyState::Complete
    );
    assert_eq!(f.keys.codes_public_key().unwrap(), before);
    let stored =
        crate::codes::store::load_device_key(&f.paths.codes.device_key_container, None).unwrap();
    assert!(stored.public_eq(f.keys.codes_key()));
    assert_eq!(
        prepared
            .apply(
                &f.paths,
                &f.keys,
                Some(Epoch::new(1)),
                SystemAccounts::empty()
            )
            .unwrap(),
        result
    );
    fs::write(f.source.join("oper.toml"), b"source changed after prepare").unwrap();
    assert_eq!(
        prepared
            .apply(
                &f.paths,
                &f.keys,
                Some(Epoch::new(1)),
                SystemAccounts::empty()
            )
            .unwrap(),
        result
    );
    disk::replace(&f.paths.tls_leaf_path, b"damaged", 0o644).unwrap();
    assert_eq!(
        prepared.state(&f.paths, &f.keys).unwrap(),
        PublicApplyState::Pending
    );
    prepared
        .apply(&f.paths, &f.keys, None, SystemAccounts::empty())
        .unwrap();
    assert_eq!(
        prepared.state(&f.paths, &f.keys).unwrap(),
        PublicApplyState::Complete
    );
}
#[test]
fn invalid_public_inputs_never_touch_installation_or_floor() {
    for kind in [
        "signature",
        "role",
        "private-pin",
        "key-container",
        "extra-private",
        "foreign-os",
        "leaf",
        "ticket-signature",
        "anchor",
    ] {
        let mut f = Fixture::new();
        match kind {
            "signature" => {
                let file = f.source.join("manifest.toml");
                let mut b = fs::read(&file).unwrap();
                b[14] = if b[14] == b'a' { b'b' } else { b'a' };
                fs::write(file, b).unwrap();
            }
            "role" => fs::write(f.source.join("oper.toml"), b"tamper").unwrap(),
            "private-pin" => f.sign(&format!(
                "p12_sha256 = \"{}\"\n{}",
                "00".repeat(32),
                f.unsigned
            )),
            "key-container" => f.sign(&format!(
                "{}\n[codes.key_container]\nfile = \"secret.p12\"\nsha256 = \"{}\"\n",
                f.unsigned,
                "00".repeat(32)
            )),
            "extra-private" => fs::write(f.source.join("secret.p12"), b"private").unwrap(),
            "foreign-os" => f.sign(&f.unsigned.replace("os = \"linux\"", "os = \"windows\"")),
            "leaf" => f.leaf = leaf(&Fixture::new().keys),
            "ticket-signature" => {
                let old = fs::read(f.source.join("tickets.txt")).unwrap();
                let wire = String::from_utf8(old.clone()).unwrap();
                let changed = wire.replace("signature=", "signature=00");
                fs::write(f.source.join("tickets.txt"), &changed).unwrap();
                f.sign(&f.unsigned.replace(
                    &hex::encode(Sha256::digest(old)),
                    &hex::encode(Sha256::digest(changed.as_bytes())),
                ));
            }
            "anchor" => {
                let path = f.source.join("anchor.pem");
                let old = fs::read(&path).unwrap();
                let new = PKey::generate_ed25519()
                    .unwrap()
                    .public_key_to_pem()
                    .unwrap();
                fs::write(path, &new).unwrap();
                f.sign(&f.unsigned.replace(
                    &hex::encode(Sha256::digest(old)),
                    &hex::encode(Sha256::digest(new)),
                ));
            }
            _ => unreachable!(),
        }
        assert!(f.prepare().is_err(), "{kind}");
        assert!(!f.paths.roles_dir.exists());
        assert!(!f.paths.persist_dir.exists());
        assert!(!f.keys.root().join(STATE_FILE).exists());
    }
}
#[test]
fn durable_interruptions_resume_same_bytes_and_refuse_different_attempt() {
    for phase in ["pending", "leaf", "codes", "verified"] {
        let f = Fixture::new();
        let prepared = f.prepare().unwrap();
        FAILURE.set(Some(phase));
        let result = prepared.apply(&f.paths, &f.keys, None, SystemAccounts::empty());
        FAILURE.set(None);
        assert!(result.is_err(), "{phase}");
        assert_eq!(
            prepared.state(&f.paths, &f.keys).unwrap(),
            PublicApplyState::Pending
        );
        let reloaded = LocalEnrollmentKeys::load(f.keys.root()).unwrap();
        let mut other = f.paths.clone();
        other.tls_leaf_path.set_file_name("different.der");
        assert!(prepared
            .apply(&other, &reloaded, None, SystemAccounts::empty())
            .is_err());
        prepared
            .apply(&f.paths, &reloaded, None, SystemAccounts::empty())
            .unwrap();
        assert_eq!(
            prepared.state(&f.paths, &reloaded).unwrap(),
            PublicApplyState::Complete
        );
    }
}
#[test]
fn floor_epoch_revocation_and_same_version_equivocation_are_refused() {
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    assert!(prepared
        .apply(
            &f.paths,
            &f.keys,
            Some(Epoch::new(2)),
            SystemAccounts::empty()
        )
        .is_err());
    assert!(!f.paths.persist_dir.exists());
    prepared
        .apply(&f.paths, &f.keys, None, SystemAccounts::empty())
        .unwrap();
    let changed = f.unsigned.replace("version = 7", "version = 6");
    f.sign(&changed);
    assert!(f.prepare().is_err());
    f.sign(&format!("# different signed bytes\n{}", f.unsigned));
    let equivocation = f.prepare().unwrap();
    assert!(equivocation
        .apply(&f.paths, &f.keys, None, SystemAccounts::empty())
        .is_err());
    disk::replace(&f.paths.codes.ticket_revocations, b"T-009\nT-010\n", 0o644).unwrap();
    assert!(prepared
        .apply(&f.paths, &f.keys, None, SystemAccounts::empty())
        .is_err());
}
#[test]
fn unsafe_or_overlapping_destinations_cannot_replace_keys() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    let before = f.keys.codes_public_key().unwrap();
    let mut paths = f.paths.clone();
    paths.tls_leaf_path = f.keys.root().join("keys/codes.p12");
    assert!(prepared
        .apply(&paths, &f.keys, None, SystemAccounts::empty())
        .is_err());
    assert_eq!(f.keys.codes_public_key().unwrap(), before);
    symlink(f.keys.root().join("keys/codes.p12"), &f.paths.tls_leaf_path).unwrap();
    assert!(prepared
        .apply(&f.paths, &f.keys, None, SystemAccounts::empty())
        .is_err());
    assert!(!f.paths.persist_dir.exists());
}

#[test]
fn pending_after_floor_before_swap_can_repair_and_plain_equal_floor_cannot_bootstrap() {
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    disk::make_directory(&f.paths.persist_dir).unwrap();
    role::manifest::persist_bundle_version(&f.paths.persist_dir, 7).unwrap();
    assert!(prepared
        .apply(&f.paths, &f.keys, None, SystemAccounts::empty())
        .is_err());
    write_journal(
        f.keys.root(),
        prepared.application_digest(&f.paths).unwrap(),
        false,
    )
    .unwrap();
    assert_eq!(
        prepared.state(&f.paths, &f.keys).unwrap(),
        PublicApplyState::Pending
    );
    prepared
        .apply(&f.paths, &f.keys, None, SystemAccounts::empty())
        .unwrap();
    assert_eq!(
        prepared.state(&f.paths, &f.keys).unwrap(),
        PublicApplyState::Complete
    );
}

#[test]
fn legacy_atomic_writer_refuses_symlinks_without_truncating_the_target() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let target = temp.path().join("target");
    fs::write(&target, b"unchanged").unwrap();
    let link = temp.path().join("temporary");
    symlink(&target, &link).unwrap();
    assert!(crate::fs_mode::create_with_mode(&link, 0o600).is_err());
    assert_eq!(fs::read(target).unwrap(), b"unchanged");
}

#[test]
fn oversized_files_and_package_links_are_refused_before_targets_exist() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let path = f.source.join("oper.toml");
    fs::write(&path, vec![b'x'; role::schema::MAX_SLICE_BYTES + 1]).unwrap();
    assert!(f.prepare().is_err());
    assert!(!f.paths.roles_dir.exists());
    fs::remove_file(&path).unwrap();
    symlink(f.keys.root().join("keys/codes.p12"), &path).unwrap();
    assert!(f.prepare().is_err());
    assert!(!f.paths.persist_dir.exists());
    let mut f = Fixture::new();
    f.leaf = vec![0; 64 * 1024 + 1];
    assert!(f.prepare().is_err());
    assert!(!f.keys.root().join(STATE_FILE).exists());
}

#[test]
fn unsafe_existing_file_is_refused_before_any_publication() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    fs::write(&f.paths.tls_leaf_path, b"old").unwrap();
    fs::set_permissions(&f.paths.tls_leaf_path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(prepared
        .apply(&f.paths, &f.keys, None, SystemAccounts::empty())
        .is_err());
    assert_eq!(fs::read(&f.paths.tls_leaf_path).unwrap(), b"old");
    assert!(!f.keys.root().join(STATE_FILE).exists());
    assert!(!f.paths.persist_dir.exists());
}

#[test]
fn role_swap_and_backup_cannot_contain_the_local_key_root() {
    for backup in [false, true] {
        let f = Fixture::new();
        let prepared = f.prepare().unwrap();
        let container = if backup {
            f.paths.roles_dir.with_file_name("roles.bak")
        } else {
            f.paths.roles_dir.clone()
        };
        disk::make_directory(&container).unwrap();
        let nested = container.join("client-keys");
        disk::make_directory(&nested).unwrap();
        disk::make_directory(&nested.join("keys")).unwrap();
        let files = [
            ("codes.p12", 0o600),
            ("tls.p12", 0o600),
            ("tls.csr.der", 0o644),
        ];
        let before: Vec<_> = files
            .iter()
            .map(|(name, mode)| {
                let bytes = fs::read(f.keys.root().join("keys").join(name)).unwrap();
                disk::write_new(&nested.join("keys").join(name), &bytes, *mode).unwrap();
                (*name, bytes)
            })
            .collect();
        let nested_keys = LocalEnrollmentKeys::load(&nested).unwrap();
        assert!(prepared
            .apply(&f.paths, &nested_keys, None, SystemAccounts::empty())
            .is_err());
        for (name, bytes) in before {
            assert_eq!(fs::read(nested.join("keys").join(name)).unwrap(), bytes);
        }
        assert!(!nested.join(STATE_FILE).exists());
        assert!(!f.paths.tls_leaf_path.exists());
        assert!(!f.paths.persist_dir.exists());
    }
}

#[test]
fn role_backup_cannot_overlap_codes_files_or_state() {
    for state in [false, true] {
        let f = Fixture::new();
        let prepared = f.prepare().unwrap();
        let backup = f.paths.roles_dir.with_file_name("roles.bak");
        disk::make_directory(&backup).unwrap();
        let sentinel = backup.join("sentinel");
        disk::write_new(&sentinel, b"retain", 0o600).unwrap();
        let mut paths = f.paths.clone();
        if state {
            paths.codes.state_dir = backup.clone();
        } else {
            paths.codes.tickets = backup.join("tickets.txt");
        }
        assert!(prepared
            .apply(&paths, &f.keys, None, SystemAccounts::empty())
            .is_err());
        assert_eq!(fs::read(sentinel).unwrap(), b"retain");
        assert!(!f.keys.root().join(STATE_FILE).exists());
        assert!(!paths.tls_leaf_path.exists());
        assert!(!paths.persist_dir.exists());
    }
}

#[test]
fn shared_floor_parent_and_codes_files_beneath_state_remain_supported() {
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    let mut paths = f.paths.clone();
    paths.persist_dir = paths.roles_dir.parent().unwrap().to_path_buf();
    disk::make_directory(paths.codes.device_key_container.parent().unwrap()).unwrap();
    disk::make_directory(&paths.codes.state_dir).unwrap();
    paths.codes.tickets = paths.codes.state_dir.join("tickets.txt");
    paths.codes.ticket_revocations = paths.codes.state_dir.join("revoked.txt");
    paths.codes.ticket_authority = paths.codes.state_dir.join("anchor.pem");
    paths.codes.page_urls = paths.codes.state_dir.join("urls.txt");
    prepared
        .apply(&paths, &f.keys, None, SystemAccounts::empty())
        .unwrap();
    assert_eq!(
        prepared.state(&paths, &f.keys).unwrap(),
        PublicApplyState::Complete
    );
}

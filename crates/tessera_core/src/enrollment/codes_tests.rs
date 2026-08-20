//! Tests of the Codes part of an enrollment package.
//!
//! The point most of them make is the same one: a package that carries no Codes
//! part has to import the way it always did. The rest are the refusals — an
//! unpinned file in a signed package, a pin that does not match, a named file
//! that is not there — because every one of them decides which operators may
//! hand this device a code.

#![expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]

use std::fs;
use std::path::Path;

use openssl::pkey::PKey;
use secrecy::SecretString;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use tessera_codes_contract::key::Epoch;

use crate::codes::CodesPaths;
use crate::enrollment::audit::EnrollAuditIds;
use crate::enrollment::import::{CodesImport, EnrollmentPackage, ImportError, ImportMode};
use crate::enrollment::InstallPaths;
use crate::role::manifest::MANIFEST_FILENAME;
use crate::role::RoleOs;

/// PIN the delivery container of the fixture package is closed with.
const DELIVERY_PIN: &str = "delivery-pin";

/// Bare name of the delivery container inside the package.
const CONTAINER_FILE: &str = "codes-device.p12";

/// Bare name of the ticket set inside the package.
const TICKETS_FILE: &str = "codes-tickets.txt";

/// Bare name of the anchor inside the package.
const ANCHOR_FILE: &str = "codes-authority.pem";

/// The Codes files of a fixture package, in memory.
struct CodesFixture {
    container: Vec<u8>,
    tickets: Vec<u8>,
    anchor: Vec<u8>,
}

impl CodesFixture {
    fn new() -> Self {
        let authority = crate::codes::tickets::tests::Authority::new();
        let ticket = authority.sign(crate::codes::tickets::tests::ticket("op-42", 1, "tk-17"));
        Self {
            container: container(),
            tickets: format!("{}\n", ticket.to_wire()).into_bytes(),
            anchor: authority.public_key_pem(),
        }
    }

    /// Writes the files into a package directory.
    fn write(&self, root: &Path) {
        fs::write(root.join(CONTAINER_FILE), &self.container).unwrap();
        fs::write(root.join(TICKETS_FILE), &self.tickets).unwrap();
        fs::write(root.join(ANCHOR_FILE), &self.anchor).unwrap();
    }

    /// The `[codes]` section of a signed manifest, with every pin in place.
    fn manifest_section(&self) -> String {
        format!(
            "[codes]\nepoch = 3\n\
             [codes.key_container]\nfile = \"{CONTAINER_FILE}\"\nsha256 = \"{}\"\n\
             [codes.tickets]\nfile = \"{TICKETS_FILE}\"\nsha256 = \"{}\"\n\
             [codes.ticket_authority]\nfile = \"{ANCHOR_FILE}\"\nsha256 = \"{}\"\n",
            hex::encode(Sha256::digest(&self.container)),
            hex::encode(Sha256::digest(&self.tickets)),
            hex::encode(Sha256::digest(&self.anchor)),
        )
    }

    /// The standalone `codes.toml`, which pins nothing.
    fn standalone_section() -> String {
        format!(
            "epoch = 3\n\
             [key_container]\nfile = \"{CONTAINER_FILE}\"\n\
             [tickets]\nfile = \"{TICKETS_FILE}\"\n\
             [ticket_authority]\nfile = \"{ANCHOR_FILE}\"\n"
        )
    }
}

/// A PKCS#12 holding a fresh P-256 key, closed with the delivery PIN.
fn container() -> Vec<u8> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let key = crate::codes::agreement::tests::p256_pair().0;
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "codes device")
        .unwrap();
    let name = name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder
        .sign(&key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let cert = builder.build();

    openssl::pkcs12::Pkcs12::builder()
        .name("delivery")
        .pkey(&key)
        .cert(&cert)
        .build2(DELIVERY_PIN)
        .unwrap()
        .to_der()
        .unwrap()
}

/// A signing key and the PEM of its public half.
struct SigningKey {
    private: PKey<openssl::pkey::Private>,
    public_pem: Vec<u8>,
}

fn signing_key() -> SigningKey {
    let private = PKey::generate_ed25519().unwrap();
    let public_pem = private.public_key_to_pem().unwrap();
    SigningKey {
        private,
        public_pem,
    }
}

/// Builds a managed package whose manifest carries `codes_section` verbatim.
fn managed_package(key: &SigningKey, codes_section: &str) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let slice = "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"oper\"\nlevel = 1\n";
    fs::write(dir.path().join("oper.toml"), slice.as_bytes()).unwrap();
    let slice_sha = hex::encode(Sha256::digest(slice.as_bytes()));

    let body = format!(
        "bundle_version = 1\nos = \"linux\"\n[tags]\nregion = \"ru-south\"\n{codes_section}\
         [roles.oper]\nversion = 1\nsha256 = \"{slice_sha}\"\n"
    );
    let mut signer = openssl::sign::Signer::new_without_digest(&key.private).unwrap();
    let signature = hex::encode(signer.sign_oneshot_to_vec(body.as_bytes()).unwrap());
    let manifest = format!(
        "bundle_version = 1\nos = \"linux\"\nsignature = \"{signature}\"\n[tags]\nregion = \"ru-south\"\n{codes_section}\
         [roles.oper]\nversion = 1\nsha256 = \"{slice_sha}\"\n"
    );
    fs::write(dir.path().join(MANIFEST_FILENAME), manifest.as_bytes()).unwrap();
    fs::write(dir.path().join("host-abc.p12"), b"\x30\x82PKCS12-OPAQUE").unwrap();
    dir
}

/// Builds a standalone package, optionally with a `codes.toml`.
fn standalone_package(codes_section: Option<&str>) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let slice = "role = \"oper\"\nversion = 1\nos = \"linux\"\nname = \"oper\"\nlevel = 1\n";
    fs::write(dir.path().join("oper.toml"), slice.as_bytes()).unwrap();
    fs::write(
        dir.path().join("tags.toml"),
        b"[tags]\nregion = \"ru-south\"\n",
    )
    .unwrap();
    fs::write(dir.path().join("host-xyz.p12"), b"\x30\x82PKCS12-OPAQUE").unwrap();
    if let Some(section) = codes_section {
        fs::write(dir.path().join("codes.toml"), section.as_bytes()).unwrap();
    }
    dir
}

/// Device paths rooted at a fresh temporary directory.
fn device(root: &TempDir) -> (InstallPaths, CodesPaths) {
    let base = root.path();
    (
        InstallPaths {
            roles_dir: base.join("roles"),
            tags_file: base.join("tags.toml"),
            crl_path: base.join("device.crl"),
            p12_path: base.join("host.p12"),
            persist_dir: base.join("persist"),
        },
        CodesPaths::under(&base.join("codes")),
    )
}

/// The Codes options an operator supplies for an import.
fn codes_import<'a>(paths: &CodesPaths, pin: Option<&'a SecretString>) -> CodesImport<'a> {
    CodesImport {
        paths: paths.clone(),
        container_pin: pin,
        gost_engine_path: None,
        // The store of a test lives under a temporary directory, which no
        // ownership policy accepts; the modes it is written with are asserted
        // in the artefact tests instead.
        store_check: crate::codes::artefacts::StoreCheck::Skipped,
    }
}

#[test]
fn a_standalone_package_without_a_codes_part_imports_as_before() {
    let package = standalone_package(None);
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let parsed = EnrollmentPackage::parse(package.path(), ImportMode::Standalone).unwrap();
    let outcome = parsed
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap();

    assert!(outcome.codes.is_none());
    assert!(
        install.tags_file.is_file(),
        "the Access part still installs"
    );
    assert!(!codes.device_key_container.exists());
    assert!(!codes.state_dir.exists());
}

#[test]
fn a_managed_package_without_a_codes_part_imports_as_before() {
    let key = signing_key();
    let package = managed_package(&key, "");
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);

    let parsed = EnrollmentPackage::parse(package.path(), ImportMode::Managed).unwrap();
    let outcome = parsed
        .install_with_codes(
            &install,
            RoleOs::Linux,
            Some(&key.public_pem),
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, None)),
        )
        .unwrap();

    assert!(outcome.codes.is_none());
    assert_eq!(outcome.bundle_version, 1);
    assert!(!codes.device_key_container.exists());
}

#[test]
fn a_managed_package_with_a_codes_part_makes_the_device_ready() {
    let key = signing_key();
    let fixture = CodesFixture::new();
    let package = managed_package(&key, &fixture.manifest_section());
    fixture.write(package.path());
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let parsed = EnrollmentPackage::parse(package.path(), ImportMode::Managed).unwrap();
    // The delivery container does not make the package ambiguous: the per-host
    // identity is still the one `.p12` the section does not name.
    assert_eq!(parsed.p12_file(), "host-abc.p12");

    let outcome = parsed
        .install_with_codes(
            &install,
            RoleOs::Linux,
            Some(&key.public_pem),
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap();

    let applied = outcome.codes.unwrap();
    assert_eq!(applied.epoch, Some(Epoch::new(3)));
    assert!(applied.key_replaced);
    assert!(codes.artefacts_present());
    // The delivery copy of the key does not stay on the medium.
    assert!(!package.path().join(CONTAINER_FILE).exists());
}

#[test]
fn a_standalone_package_with_a_codes_part_makes_the_device_ready() {
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(&CodesFixture::standalone_section()));
    fixture.write(package.path());
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let parsed = EnrollmentPackage::parse(package.path(), ImportMode::Standalone).unwrap();
    let outcome = parsed
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap();

    assert_eq!(outcome.codes.unwrap().epoch, Some(Epoch::new(3)));
    assert!(codes.artefacts_present());
}

#[test]
fn an_import_that_did_not_ask_for_codes_leaves_the_part_alone() {
    // The Access-only import of a package that happens to carry a Codes part:
    // nothing is applied and nothing is removed from the package.
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(&CodesFixture::standalone_section()));
    fixture.write(package.path());
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);

    let outcome = EnrollmentPackage::parse(package.path(), ImportMode::Standalone)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            None,
        )
        .unwrap();

    assert!(outcome.codes.is_none());
    assert!(!codes.device_key_container.exists());
    assert!(package.path().join(CONTAINER_FILE).is_file());
}

#[test]
fn a_managed_codes_file_without_a_pin_is_refused() {
    let key = signing_key();
    let fixture = CodesFixture::new();
    let section = format!(
        "[codes]\nepoch = 3\n[codes.key_container]\nfile = \"{CONTAINER_FILE}\"\nsha256 = \"{}\"\n\
         [codes.tickets]\nfile = \"{TICKETS_FILE}\"\n",
        hex::encode(Sha256::digest(&fixture.container)),
    );
    let package = managed_package(&key, &section);
    fixture.write(package.path());
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Managed)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            Some(&key.public_pem),
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap_err();

    assert!(matches!(error, ImportError::CodesUnpinned { .. }));
    assert!(!codes.device_key_container.exists());
}

#[test]
fn a_codes_file_that_does_not_match_its_pin_is_refused() {
    let key = signing_key();
    let fixture = CodesFixture::new();
    let package = managed_package(&key, &fixture.manifest_section());
    fixture.write(package.path());
    // The medium changed under the pin.
    fs::write(package.path().join(TICKETS_FILE), b"tampered\n").unwrap();
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Managed)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            Some(&key.public_pem),
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap_err();

    assert!(matches!(error, ImportError::CodesHashMismatch { .. }));
    assert!(!codes.tickets.exists());
    // The container is still on the medium: a refused import consumed nothing.
    assert!(package.path().join(CONTAINER_FILE).is_file());
}

#[test]
fn a_codes_file_the_section_names_but_the_package_lacks_is_refused() {
    let key = signing_key();
    let fixture = CodesFixture::new();
    let package = managed_package(&key, &fixture.manifest_section());
    fixture.write(package.path());
    fs::remove_file(package.path().join(ANCHOR_FILE)).unwrap();
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Managed)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            Some(&key.public_pem),
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap_err();

    assert!(matches!(error, ImportError::CodesMissing { .. }));
    assert!(!codes.tickets.exists());
}

#[test]
fn a_container_without_a_pin_is_refused_rather_than_half_applied() {
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(&CodesFixture::standalone_section()));
    fixture.write(package.path());
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Standalone)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, None)),
        )
        .unwrap_err();

    assert!(matches!(error, ImportError::CodesPinRequired));
    assert!(!codes.tickets.exists());
    assert!(!codes.device_key_container.exists());
}

#[test]
fn a_section_naming_a_path_instead_of_a_file_is_refused() {
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(
        "epoch = 3\n[key_container]\nfile = \"../outside.p12\"\n",
    ));
    fixture.write(package.path());

    // The refusal comes from the parse: a name that is not a bare file name is
    // refused before the package is read as a package at all.
    let error = EnrollmentPackage::parse(package.path(), ImportMode::Standalone).unwrap_err();
    assert!(matches!(error, ImportError::UnsafeName { .. }));
}

#[test]
fn a_codes_section_larger_than_the_cap_is_refused() {
    // The section is a document of a few lines. The file is sparse, so making it
    // enormous costs nothing — and reading it whole in order to find out how
    // large it is would cost the import process its life.
    let package = standalone_package(None);
    let section = std::fs::File::create(package.path().join("codes.toml")).unwrap();
    section.set_len(4 * 1024 * 1024 * 1024).unwrap();
    drop(section);

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Standalone).unwrap_err();
    assert!(matches!(error, ImportError::Oversize { .. }), "{error:?}");
}

#[test]
fn a_codes_file_that_is_a_symlink_is_refused() {
    // The name is bare, so nothing about it looks like an escape. What it
    // resolves to is the medium's business, and a medium is what this whole
    // path refuses to trust: a link to a character device would be read until
    // the process died.
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(&CodesFixture::standalone_section()));
    fixture.write(package.path());
    let tickets = package.path().join(TICKETS_FILE);
    std::fs::remove_file(&tickets).unwrap();
    std::os::unix::fs::symlink(package.path().join(ANCHOR_FILE), &tickets).unwrap();

    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Standalone)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap_err();

    assert!(matches!(error, ImportError::Io { .. }), "{error:?}");
    assert!(!codes.tickets.exists());
}

#[test]
fn a_codes_file_that_is_a_fifo_is_refused_rather_than_waited_on() {
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(&CodesFixture::standalone_section()));
    fixture.write(package.path());
    let tickets = package.path().join(TICKETS_FILE);
    std::fs::remove_file(&tickets).unwrap();
    nix::unistd::mkfifo(
        &tickets,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();

    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Standalone)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap_err();

    assert!(matches!(error, ImportError::Io { .. }), "{error:?}");
    assert!(!codes.tickets.exists());
}

#[test]
fn a_codes_section_that_does_not_parse_is_refused() {
    let fixture = CodesFixture::new();
    let package = standalone_package(Some("epoch = \"three\"\n"));
    fixture.write(package.path());

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Standalone).unwrap_err();
    assert!(matches!(error, ImportError::CodesSection { .. }));
}

#[test]
fn an_anchor_that_is_not_a_public_key_is_refused_at_the_import() {
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(&CodesFixture::standalone_section()));
    fixture.write(package.path());
    fs::write(package.path().join(ANCHOR_FILE), b"not a key\n").unwrap();
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let error = EnrollmentPackage::parse(package.path(), ImportMode::Standalone)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap_err();

    assert!(matches!(error, ImportError::CodesSection { .. }));
    assert!(!codes.ticket_authority.exists());
}

#[test]
fn a_repeated_import_of_the_same_package_is_a_no_op_for_the_key() {
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(&CodesFixture::standalone_section()));
    fixture.write(package.path());
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let parsed = EnrollmentPackage::parse(package.path(), ImportMode::Standalone).unwrap();
    parsed
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap();
    // The device has been talking since.
    crate::codes::counter::write_issued(&codes.state_dir, 17).unwrap();

    // The medium is presented again. The container was shredded by the first
    // import, so the operator re-stages it — the same bytes, the same epoch.
    fixture.write(package.path());
    let applied = parsed
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap()
        .codes
        .unwrap();

    assert!(!applied.counter_reset);
    assert_eq!(
        crate::codes::counter::read_issued(&codes.state_dir)
            .unwrap()
            .unwrap()
            .get(),
        17,
        "a second run of the same medium must not resurrect consumed nonces"
    );
}

#[test]
fn a_codes_section_reaches_the_store_only_under_a_signature_that_held() {
    // The section names the ticket authority — it decides whose codes this
    // device lets in. So it may only ever come out of bytes whose signature
    // verified, and the manifest is therefore read once, with the signature
    // checked before anything at all is decided from its contents.
    //
    // The re-import of an already-applied `bundle_version` is the case that
    // makes this visible: the Access half has nothing to do, so a signature
    // checked "as part of installing" would not be checked at all, and a
    // section read afterwards would ride into the store unsigned.
    let key = signing_key();
    let fixture = CodesFixture::new();
    let package = managed_package(&key, &fixture.manifest_section());
    fixture.write(package.path());
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    let parsed = EnrollmentPackage::parse(package.path(), ImportMode::Managed).unwrap();
    parsed
        .install_with_codes(
            &install,
            RoleOs::Linux,
            Some(&key.public_pem),
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap();
    let anchor_after_first = fs::read(&codes.ticket_authority).unwrap();

    // The medium is rewritten: same `bundle_version`, a Codes section naming a
    // different anchor, and a signature that no longer covers any of it.
    let tampered = fs::read_to_string(package.path().join(MANIFEST_FILENAME))
        .unwrap()
        .replace(ANCHOR_FILE, "codes-other-authority.pem");
    fs::write(package.path().join(MANIFEST_FILENAME), tampered.as_bytes()).unwrap();
    fixture.write(package.path());
    fs::write(
        package.path().join("codes-other-authority.pem"),
        signing_key().public_pem.as_slice(),
    )
    .unwrap();

    let error = parsed
        .install_with_codes(
            &install,
            RoleOs::Linux,
            Some(&key.public_pem),
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        // A manifest whose signature no longer holds must not be acted on.
        .unwrap_err();
    assert!(
        matches!(error, ImportError::Manifest(_)),
        "expected a manifest refusal, got {error:?}"
    );
    assert_eq!(
        fs::read(&codes.ticket_authority).unwrap(),
        anchor_after_first,
        "the anchor of the device must not come from bytes nobody signed"
    );
}

#[test]
fn the_codes_section_of_a_package_does_not_ride_into_the_role_directory() {
    // `codes.toml` is a package file, not a role slice. Carried into the role
    // directory it is re-parsed as a slice on every load, fails every time, and
    // writes a line to the journal for a fault nobody can fix; worse, it counts
    // against the bound on candidates in the role base, so a package shipping a
    // full complement of slices would stop loading over a file that is not one.
    let fixture = CodesFixture::new();
    let package = standalone_package(Some(&CodesFixture::standalone_section()));
    fixture.write(package.path());
    let root = tempfile::tempdir().unwrap();
    let (install, codes) = device(&root);
    let pin = SecretString::from(DELIVERY_PIN.to_owned());

    EnrollmentPackage::parse(package.path(), ImportMode::Standalone)
        .unwrap()
        .install_with_codes(
            &install,
            RoleOs::Linux,
            None,
            EnrollAuditIds::default(),
            Some(&codes_import(&codes, Some(&pin))),
        )
        .unwrap();

    assert!(
        !install.roles_dir.join("codes.toml").exists(),
        "the Codes section of the package must not be installed as a role slice"
    );
    // The slice the package really carries is there, so the exclusion is by
    // name and not a filter that swallowed the role base with it.
    assert!(install.roles_dir.join("oper.toml").exists());
}

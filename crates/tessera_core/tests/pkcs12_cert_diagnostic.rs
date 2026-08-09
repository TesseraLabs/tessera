//! The password-free certificate read behind the login screen's diagnostic.
//!
//! When the PIN attempts run out, the login screen has to tell an engineer
//! whether they typed the password wrong or brought the wrong drive — and the
//! only thing that can tell those apart is the certificate the container was
//! issued with. Every issued container encrypts its private key, so this read
//! is worth nothing unless it works on a container it cannot open: that is what
//! this suite pins down, on containers written by our own tooling and by
//! `openssl` alike.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]

use secrecy::SecretString;
use tessera_core::pkcs12::{
    try_extract_cert_without_pin, try_extract_unambiguous_cert_without_pin, LoadedKeyMaterial,
    Pkcs12Error,
};

/// Certificates encrypted (`-certpbe AES-256-CBC`): the older layout, which
/// keeps nothing readable without the password.
const ENCRYPTED_CERTS: &[u8] = include_bytes!("fixtures/leaf_rsa.p12");

/// Certificates in the clear, key encrypted (`-certpbe NONE`): the layout
/// issuance writes, here produced by `openssl` rather than by our own writer.
const CLEAR_CERTS: &[u8] = include_bytes!("fixtures/leaf_rsa_plaincert.p12");

/// Certificates in the clear with the CA written ahead of the leaf: the reading
/// order a foreign writer may produce.
const CA_BEFORE_LEAF: &[u8] = include_bytes!("fixtures/ca_before_leaf.p12");

/// The password that opens the fixture containers. Public test material.
const FIXTURE_PIN: &str = "correct-pin";

/// The password [`our_container`] shrouds its key under. Public test material.
const CONTAINER_PASS: &str = "container-pass";

/// A container our own issuer assembles, with `leaf_der` and `chain_der` as
/// given.
///
/// The certificates are the committed fixtures rather than freshly minted ones:
/// what is under test is the container layout, and taking the certificates as
/// arguments is what lets a test put the CA ahead of the leaf.
fn our_container(leaf_der: &[u8], chain_der: &[Vec<u8>]) -> Vec<u8> {
    use tessera_issuer::keygen::OsEntropy;
    use tessera_issuer::pkcs12::{build_container, ContainerContents};
    use tessera_issuer::{generate_key_pair, LeafKeyType};

    let pair = generate_key_pair(LeafKeyType::EcdsaP256, &mut OsEntropy)
        .expect("a P-256 pair is generatable");
    build_container(
        &ContainerContents {
            private_key_pkcs8_der: &pair.private_key_pkcs8_der,
            leaf_der,
            chain_der,
        },
        CONTAINER_PASS,
        &mut OsEntropy,
    )
    .expect("the issuer assembles its own container")
    .to_vec()
}

/// DER of a committed PEM fixture.
fn fixture_der(name: &str) -> Vec<u8> {
    let pem = std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture is committed next to the tests");
    openssl::x509::X509::from_pem(&pem)
        .expect("fixture is a certificate")
        .to_der()
        .expect("a parsed certificate re-encodes")
}

#[test]
fn a_container_from_our_issuer_yields_its_leaf_without_a_password() {
    let leaf = fixture_der("leaf_rsa.pem");
    let bytes = our_container(&leaf, &[fixture_der("int.pem")]);

    let cert = try_extract_cert_without_pin(&bytes)
        .expect("the certificate of an issued container is readable without its password");
    assert_eq!(cert.subject_cn().unwrap(), "alice");
}

#[test]
fn an_encrypted_key_does_not_stop_the_read() {
    // The container's key is encrypted — the condition that used to swallow the
    // certificates — and the password is never supplied here.
    let cert = try_extract_cert_without_pin(CLEAR_CERTS)
        .expect("an encrypted key bag must not hide the certificates beside it");
    assert_eq!(cert.subject_cn().unwrap(), "alice");
    // The serial is read here too, though the import report reaches it by its
    // own call: an unreadable certificate is what an empty serial used to mean.
    assert_eq!(
        cert.serial_hex(),
        "44E056A8B426D4727A82EC2A41EDFFFEA4B3D0E3"
    );

    // The same bytes still need the password for the key: nothing above weakened
    // the authentication path.
    let material =
        LoadedKeyMaterial::from_p12(CLEAR_CERTS, &SecretString::from(FIXTURE_PIN.to_owned()))
            .expect("the fixture opens with its own password");
    assert_eq!(material.end_entity.subject_cn().unwrap(), "alice");
}

#[test]
fn a_container_without_clear_certificates_yields_nothing() {
    assert!(
        try_extract_cert_without_pin(ENCRYPTED_CERTS).is_none(),
        "a container of the older layout has no certificate to show, which is an outcome, not an error"
    );
}

#[test]
fn malformed_bytes_yield_nothing() {
    for (what, bytes) in [
        ("random bytes", &b"not a container at all"[..]),
        ("empty buffer", &b""[..]),
        ("truncated container", &CLEAR_CERTS[..64]),
        ("header only", &CLEAR_CERTS[..4]),
    ] {
        assert!(
            try_extract_cert_without_pin(bytes).is_none(),
            "{what} must yield no certificate rather than panic"
        );
    }

    // A container whose body is shredded but whose outer length prefixes still
    // hold: the walk has to survive garbage that looks structurally plausible.
    let mut shredded = CLEAR_CERTS.to_vec();
    for byte in shredded.iter_mut().skip(32) {
        *byte ^= 0xA5;
    }
    assert!(try_extract_cert_without_pin(&shredded).is_none());
}

#[test]
fn a_destroyed_key_bag_leaves_the_certificate_readable() {
    // Overwrite the shrouded key bag's own bytes in place. The lengths do not
    // move, so the container stays structurally intact and every certificate bag
    // is untouched — a read that decoded the key material would now fail, and a
    // read that steps over it cannot notice.
    let mut bytes = CLEAR_CERTS.to_vec();
    let start = shrouded_key_bag_offset(CLEAR_CERTS);
    for byte in bytes.iter_mut().skip(start).take(64) {
        *byte ^= 0xFF;
    }

    let cert = try_extract_cert_without_pin(&bytes)
        .expect("the certificate is readable regardless of the key bag beside it");
    assert_eq!(cert.subject_cn().unwrap(), "alice");

    // And the damage is real: the authentication path no longer opens these
    // bytes even with the right password.
    let err = LoadedKeyMaterial::from_p12(&bytes, &SecretString::from(FIXTURE_PIN.to_owned()))
        .expect_err("a shredded key bag must not authenticate");
    assert!(
        matches!(err, Pkcs12Error::WrongPin | Pkcs12Error::Corrupt(_)),
        "got {err:?}"
    );
}

#[test]
fn the_non_ca_is_chosen_over_a_ca_that_precedes_it() {
    // A foreign writer is free to put the chain first — our own refuses to, so
    // this container comes from `openssl`. Bag order must not decide: the
    // certificate named is the one that is not a CA.
    let cert = try_extract_cert_without_pin(CA_BEFORE_LEAF)
        .expect("a container holding both still shows a certificate");
    assert_eq!(
        cert.subject_cn().unwrap(),
        "alice",
        "the CA that came first must not be mistaken for the end-entity"
    );

    // And the rule really is this path's own: the fixture was built around the
    // intermediate's key, so `PKCS12_parse` — which decrypts the key and takes
    // the first certificate whose public key matches it — returns the
    // intermediate. The two answers differ here by construction, and nothing
    // claims otherwise; the conservative rule is what keeps the diagnostic quiet
    // whenever the choice is open, which is what the tests below pin down.
    let material =
        LoadedKeyMaterial::from_p12(CA_BEFORE_LEAF, &SecretString::from(FIXTURE_PIN.to_owned()))
            .expect("the fixture opens with its own password");
    assert_eq!(
        material.end_entity.subject_cn().unwrap(),
        "CertAuth Test Intermediate"
    );
}

/// The serial of `leaf_rsa.pem`, pinned by `tests/fixtures/gen.sh`.
const LEAF_RSA_SERIAL: &str = "44E056A8B426D4727A82EC2A41EDFFFEA4B3D0E3";

#[test]
fn a_container_of_our_issuance_records_the_serial_of_its_leaf() {
    // The ordinary issued container: the leaf and its chain together in the
    // clear, the key paired with the leaf. This is what every enrollment
    // carries, so an empty serial here is an empty serial in every report and
    // in every `device_enrolled` event.
    let leaf = fixture_der("leaf_rsa.pem");
    let bytes = our_container(&leaf, &[fixture_der("int.pem")]);

    let cert = try_extract_unambiguous_cert_without_pin(&bytes)
        .expect("an issued container names the certificate its key belongs to");
    assert_eq!(cert.subject_cn().unwrap(), "alice");
    assert_eq!(
        cert.serial_hex(),
        LEAF_RSA_SERIAL,
        "the serial recorded is the leaf's, and it is not empty"
    );
}

#[test]
fn a_foreign_container_records_the_certificate_both_rules_agree_on() {
    // Written by `openssl`, not by us: leaf and chain in the clear, key
    // shrouded and labelled with the leaf, nothing kept in an `id-encryptedData`
    // section. Nothing about the layout is our own convention.
    let cert = try_extract_unambiguous_cert_without_pin(CLEAR_CERTS)
        .expect("a container written by openssl leaves the same choice open to nobody");
    assert_eq!(cert.subject_cn().unwrap(), "alice");
    assert_eq!(cert.serial_hex(), LEAF_RSA_SERIAL);

    // And it is the certificate the device will authenticate with: this
    // fixture's key really is the leaf's, so `PKCS12_parse` can be asked with
    // the password and has to give the same answer. That agreement is not
    // something the read above established — it cannot, without the password —
    // it is what the read is built to be quiet whenever it is in doubt about.
    let authenticated =
        LoadedKeyMaterial::from_p12(CLEAR_CERTS, &SecretString::from(FIXTURE_PIN.to_owned()))
            .expect("the fixture opens with its own password")
            .end_entity;
    assert_eq!(cert.serial_hex(), authenticated.serial_hex());
}

#[test]
fn a_key_labelled_with_a_certificate_authority_records_nothing() {
    // `ca_before_leaf.p12` was built around the intermediate's key, so
    // `PKCS12_parse` — matching the decrypted key against each certificate's
    // public key — returns the intermediate, which the assertion below fixes.
    // The label points there too. But an audit event must not call a
    // certificate authority the device's credential, and the container's one
    // non-CA certificate is the leaf, not the labelled bag: two reasons, either
    // of which alone keeps the record empty.
    let authenticated =
        LoadedKeyMaterial::from_p12(CA_BEFORE_LEAF, &SecretString::from(FIXTURE_PIN.to_owned()))
            .expect("the fixture opens with its own password")
            .end_entity;
    assert_eq!(
        authenticated.subject_cn().unwrap(),
        "CertAuth Test Intermediate"
    );
    assert!(
        authenticated
            .basic_constraints()
            .unwrap()
            .is_some_and(|bc| bc.is_ca),
        "the certificate the key is paired with is a CA, which is what the guard turns away"
    );

    assert!(
        try_extract_unambiguous_cert_without_pin(CA_BEFORE_LEAF).is_none(),
        "a CA must not be recorded as the device's certificate"
    );

    // The login screen keeps its own answer: there a certificate is named to a
    // human, and the two rules are allowed to differ.
    assert_eq!(
        try_extract_cert_without_pin(CA_BEFORE_LEAF)
            .expect("the diagnostic still names one")
            .subject_cn()
            .unwrap(),
        "alice"
    );
}

#[test]
fn the_bag_order_does_not_decide_which_certificate_is_recorded() {
    // The CA bag comes first and the leaf second, both carrying a pairing
    // token; only the leaf's matches the key's. A reader that took the first
    // bag, or the first one that parses, would record the CA.
    let bytes = paired_container(
        &[
            (fixture_der("int.pem"), Some(b"ca-token".as_slice())),
            (fixture_der("leaf_rsa.pem"), Some(b"leaf-token".as_slice())),
        ],
        KeyBag::Paired(b"leaf-token"),
    );
    let cert = try_extract_unambiguous_cert_without_pin(&bytes)
        .expect("the bag carrying the key's token is the one recorded");
    assert_eq!(cert.serial_hex(), LEAF_RSA_SERIAL);
}

#[test]
fn a_label_and_the_single_end_entity_pointing_apart_record_nothing() {
    // The label is written by whoever assembled the container, so on its own it
    // proves nothing about which certificate the key belongs to — an attacker
    // who hands over a drive chooses it. Only where the label and the
    // "one non-CA certificate" rule land on the same bag is the answer worth
    // writing into an audit event.
    let leaf = fixture_der("leaf_rsa.pem");

    // Two end-entities, the label naming one of them: reading the label alone
    // would record it, and the container gives no reason to believe the key is
    // that one's.
    let two_end_entities = paired_container(
        &[
            (leaf.clone(), Some(b"labelled".as_slice())),
            (fixture_der("leaf_ecdsa.pem"), Some(b"other".as_slice())),
        ],
        KeyBag::Paired(b"labelled"),
    );
    assert!(
        try_extract_unambiguous_cert_without_pin(&two_end_entities).is_none(),
        "a label picking one of two end-entities must not settle the record"
    );

    // And the other way round: the label names the CA while the container's one
    // end-entity is the leaf beside it.
    let label_on_the_ca = paired_container(
        &[
            (fixture_der("int.pem"), Some(b"labelled".as_slice())),
            (leaf, Some(b"other".as_slice())),
        ],
        KeyBag::Paired(b"labelled"),
    );
    assert!(
        try_extract_unambiguous_cert_without_pin(&label_on_the_ca).is_none(),
        "the two rules disagreeing must silence the record"
    );
}

#[test]
fn a_container_with_an_encrypted_section_records_nothing() {
    use der::Encode as _;

    // Everything visible is unambiguous: one leaf, one key bag, the label on
    // both. But a section nobody can open without the password may hold another
    // certificate or another key, so "exactly one" is not a fact about this
    // container — it is a fact about the part of it that happened to be legible.
    let bags = vec![
        cert_bag_with(
            &fixture_der("leaf_rsa.pem"),
            Some(pairing_attributes(b"label")),
        ),
        filler_key_bag(Some(b"label")),
    ];
    let visible = id_data_holding(&bags.to_der().unwrap());

    let with_encrypted = container_of_safes(&[visible.clone(), encrypted_data_section()]);
    assert!(
        try_extract_unambiguous_cert_without_pin(&with_encrypted).is_none(),
        "a container with a section this path cannot see into must record nothing"
    );

    // The same container without that section records the serial: what silenced
    // the read is the encrypted section, not the hand-built layout.
    let alone = container_of_safes(&[visible]);
    assert_eq!(
        try_extract_unambiguous_cert_without_pin(&alone)
            .expect("the visible part alone is unambiguous")
            .serial_hex(),
        LEAF_RSA_SERIAL
    );
}

#[test]
fn a_key_bag_hidden_in_a_nested_bag_list_is_counted() {
    // RFC 7292 lets a bag list hold a bag list, and OpenSSL descends into it. A
    // reader that did not would see one key bag here — the decoy at the top —
    // and would record the certificate its label names, while the container
    // carries a second key the authentication path will find.
    let decoy = container_of_bags(&[
        cert_bag_with(
            &fixture_der("leaf_rsa.pem"),
            Some(pairing_attributes(b"decoy")),
        ),
        filler_key_bag(Some(b"decoy")),
        nested_bag(&[filler_key_bag(Some(b"real"))]),
    ]);
    assert!(
        try_extract_unambiguous_cert_without_pin(&decoy).is_none(),
        "a key bag nested one level down still makes the container's key ambiguous"
    );

    // And the descent is a real read, not a blanket refusal: with the
    // certificate nested and one key bag in the whole container, the record is
    // written.
    let nested_certificate = container_of_bags(&[
        nested_bag(&[cert_bag_with(
            &fixture_der("leaf_rsa.pem"),
            Some(pairing_attributes(b"label")),
        )]),
        filler_key_bag(Some(b"label")),
    ]);
    assert_eq!(
        try_extract_unambiguous_cert_without_pin(&nested_certificate)
            .expect("a nested certificate bag is read, not stepped over")
            .serial_hex(),
        LEAF_RSA_SERIAL
    );

    // Past the depth limit the walk stops descending — and says so, rather than
    // answering about the part above it.
    let mut deep = nested_bag(&[filler_key_bag(Some(b"label"))]);
    for _ in 0..6 {
        deep = nested_bag(&[deep]);
    }
    let too_deep = container_of_bags(&[
        cert_bag_with(
            &fixture_der("leaf_rsa.pem"),
            Some(pairing_attributes(b"label")),
        ),
        filler_key_bag(Some(b"label")),
        deep,
    ]);
    assert!(
        try_extract_unambiguous_cert_without_pin(&too_deep).is_none(),
        "nesting the walk refuses to enter is content it has not seen"
    );
}

#[test]
fn a_label_encoded_otherwise_than_pkcs9_allows_records_nothing() {
    // PKCS#9 defines `localKeyId` as an `OCTET STRING`, and OpenSSL refuses the
    // whole container over anything else — so a bag carrying another shape
    // describes a container the authentication path will never open. An empty
    // attribute is the sharper case: an empty `SET OF` encodes identically on
    // the key bag and on the certificate bag, so a reader comparing encodings
    // would call two bags that say nothing about each other a pair.
    let leaf = || fixture_der("leaf_rsa.pem");
    let utf8_label = || {
        use der::Decode as _;
        // `0C 05 "label"`: a UTF8String where an OCTET STRING is required.
        der::asn1::Any::from_der(&[0x0C, 0x05, b'l', b'a', b'b', b'e', b'l']).unwrap()
    };

    for (what, bytes) in [
        (
            "an empty attribute on both bags",
            container_of_bags(&[
                cert_bag_with(&leaf(), Some(local_key_id_attributes(Vec::new()))),
                filler_key_bag_with(Some(local_key_id_attributes(Vec::new()))),
            ]),
        ),
        (
            "an empty octet string on both bags",
            container_of_bags(&[
                cert_bag_with(&leaf(), Some(pairing_attributes(b""))),
                filler_key_bag_with(Some(pairing_attributes(b""))),
            ]),
        ),
        (
            "a label that is not an octet string",
            container_of_bags(&[
                cert_bag_with(&leaf(), Some(local_key_id_attributes(vec![utf8_label()]))),
                filler_key_bag_with(Some(local_key_id_attributes(vec![utf8_label()]))),
            ]),
        ),
        (
            "two labels on the key bag",
            container_of_bags(&[
                cert_bag_with(&leaf(), Some(pairing_attributes(b"first"))),
                filler_key_bag_with(Some(local_key_id_attributes(vec![
                    any_octets(b"first"),
                    any_octets(b"second"),
                ]))),
            ]),
        ),
        (
            "a malformed label on a certificate bag beside a well-formed pair",
            container_of_bags(&[
                cert_bag_with(&leaf(), Some(pairing_attributes(b"label"))),
                cert_bag_with(
                    &fixture_der("ca.pem"),
                    Some(local_key_id_attributes(vec![utf8_label()])),
                ),
                filler_key_bag(Some(b"label")),
            ]),
        ),
    ] {
        assert!(
            try_extract_unambiguous_cert_without_pin(&bytes).is_none(),
            "{what} must be recorded without a serial"
        );
    }
}

#[test]
fn a_certificate_without_basic_constraints_is_named_but_not_recorded() {
    // The login screen follows RFC 5280: an absent `basicConstraints` means
    // `cA = FALSE`, and naming that certificate to an engineer standing at the
    // prompt is right. A record is a different promise — old roots are routinely
    // issued without the extension, and an audit event must not call one the
    // device's credential on the strength of something that is not there.
    let bytes = paired_container(
        &[(
            without_basic_constraints("alone"),
            Some(b"label".as_slice()),
        )],
        KeyBag::Paired(b"label"),
    );

    assert_eq!(
        try_extract_cert_without_pin(&bytes)
            .expect("the login screen still names it")
            .subject_cn()
            .unwrap(),
        "alone"
    );
    assert!(
        try_extract_unambiguous_cert_without_pin(&bytes).is_none(),
        "a record must rest on a stated cA = FALSE, not on a missing extension"
    );
}

#[test]
fn a_container_that_names_no_pairing_records_nothing() {
    let leaf = || fixture_der("leaf_rsa.pem");
    for (what, bytes) in [
        (
            "no key bag at all",
            paired_container(&[(leaf(), Some(b"token".as_slice()))], KeyBag::Absent),
        ),
        (
            "a key bag carrying no localKeyId",
            paired_container(&[(leaf(), Some(b"token".as_slice()))], KeyBag::Unpaired),
        ),
        (
            "a key whose token no certificate repeats",
            paired_container(
                &[(leaf(), Some(b"token".as_slice()))],
                KeyBag::Paired(b"another-token"),
            ),
        ),
        (
            "certificates carrying no localKeyId",
            paired_container(&[(leaf(), None)], KeyBag::Paired(b"token")),
        ),
        (
            "two bags claiming the same key",
            paired_container(
                &[
                    (leaf(), Some(b"token".as_slice())),
                    (fixture_der("leaf_ecdsa.pem"), Some(b"token".as_slice())),
                ],
                KeyBag::Paired(b"token"),
            ),
        ),
        ("two key bags, each with its own token", two_key_bags()),
    ] {
        assert!(
            try_extract_unambiguous_cert_without_pin(&bytes).is_none(),
            "{what} must be recorded without a serial"
        );
    }
}

#[test]
fn a_container_with_nothing_readable_records_nothing() {
    for (what, bytes) in [
        ("certificates kept encrypted", ENCRYPTED_CERTS),
        ("random bytes", &b"not a container at all"[..]),
        ("an empty buffer", &b""[..]),
        ("a truncated container", &CLEAR_CERTS[..64]),
        (
            "a container without a key bag",
            &container_with_certificates(&[fixture_der("leaf_rsa.pem")]),
        ),
    ] {
        assert!(
            try_extract_unambiguous_cert_without_pin(bytes).is_none(),
            "{what} must yield no certificate rather than panic"
        );
    }

    // Structurally plausible garbage: the walk reads bag attributes now, and
    // that must not become a way to panic on hostile bytes.
    let mut shredded = CLEAR_CERTS.to_vec();
    for byte in shredded.iter_mut().skip(32) {
        *byte ^= 0xA5;
    }
    assert!(try_extract_unambiguous_cert_without_pin(&shredded).is_none());
}

/// A certificate a hand-assembled container carries, with the pairing token its
/// bag is to declare (`None` for a bag with no attributes).
type PairedCertificate<'a> = (Vec<u8>, Option<&'a [u8]>);

/// What key bag a hand-assembled container carries.
#[derive(Clone, Copy)]
enum KeyBag<'a> {
    /// None at all — a certificate-only container.
    Absent,
    /// A key bag with no attributes, so nothing to pair against.
    Unpaired,
    /// A key bag carrying the given pairing token.
    Paired(&'a [u8]),
}

/// An ASN.1 `OCTET STRING` carrying the given bytes.
fn any_octets(bytes: &[u8]) -> der::asn1::Any {
    use der::asn1::{Any, OctetString};
    use der::{Decode as _, Encode as _};

    let octets = OctetString::new(bytes.to_vec()).unwrap();
    Any::from_der(&octets.to_der().unwrap()).unwrap()
}

/// A `localKeyId` attribute set carrying the given values verbatim.
///
/// The values are handed in already encoded so that a test can put something
/// there that PKCS#9 does not allow — which is exactly what a hostile container
/// is free to do.
fn local_key_id_attributes(values: Vec<der::asn1::Any>) -> x509_cert::attr::Attributes {
    use der::asn1::{ObjectIdentifier, SetOfVec};
    use x509_cert::attr::{Attribute, Attributes};

    let mut set = SetOfVec::new();
    for value in values {
        set.insert(value).unwrap();
    }
    let mut attributes = Attributes::new();
    attributes
        .insert(Attribute {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21"),
            values: set,
        })
        .unwrap();
    attributes
}

/// The `localKeyId` attribute set carrying `token`, as PKCS#9 requires it.
fn pairing_attributes(token: &[u8]) -> x509_cert::attr::Attributes {
    local_key_id_attributes(vec![any_octets(token)])
}

/// A key bag whose value is opaque filler, carrying the given attributes.
///
/// Nothing on the password-free path looks inside a key bag's value, so the
/// bytes only have to be a well-formed TLV — which is the point: a test that
/// packaged a real key would be testing the writer, not the labelling.
fn filler_key_bag_with(
    attributes: Option<x509_cert::attr::Attributes>,
) -> pkcs12::safe_bag::SafeBag {
    use der::asn1::OctetString;
    use der::Encode as _;

    pkcs12::safe_bag::SafeBag {
        bag_id: pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        bag_value: OctetString::new(b"an encrypted key would be here".to_vec())
            .unwrap()
            .to_der()
            .unwrap(),
        bag_attributes: attributes,
    }
}

/// A key bag whose value is opaque filler, labelled with `token`.
fn filler_key_bag(token: Option<&[u8]>) -> pkcs12::safe_bag::SafeBag {
    filler_key_bag_with(token.map(pairing_attributes))
}

/// A certificate bag holding `der`, carrying the given attributes.
fn cert_bag_with(
    der: &[u8],
    attributes: Option<x509_cert::attr::Attributes>,
) -> pkcs12::safe_bag::SafeBag {
    use der::asn1::OctetString;
    use der::Encode as _;
    use pkcs12::cert_type::CertBag;

    pkcs12::safe_bag::SafeBag {
        bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
        bag_value: CertBag {
            cert_id: pkcs12::PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(der.to_vec()).unwrap(),
        }
        .to_der()
        .unwrap(),
        bag_attributes: attributes,
    }
}

/// A `safeContentsBag` holding the given bags.
fn nested_bag(bags: &[pkcs12::safe_bag::SafeBag]) -> pkcs12::safe_bag::SafeBag {
    use der::Encode as _;

    pkcs12::safe_bag::SafeBag {
        bag_id: pkcs12::PKCS_12_SAFE_CONTENTS_BAG_OID,
        // The bag codec is asymmetric: encoding adds the `[0] EXPLICIT` wrapper
        // that decoding leaves in place, so what goes in here is the bare value.
        bag_value: bags.to_vec().to_der().unwrap(),
        bag_attributes: None,
    }
}

/// A container holding the given bags in one `id-data` safe and nothing else.
fn container_of_bags(bags: &[pkcs12::safe_bag::SafeBag]) -> Vec<u8> {
    use der::Encode as _;
    container_of_safes(&[id_data_holding(&bags.to_vec().to_der().unwrap())])
}

/// A section declaring itself `id-encryptedData` — a part of the container no
/// password-free reader can look into.
///
/// The content is filler: what matters is the declared type, which is what makes
/// the section opaque and the rest of the container an unknown fraction of it.
fn encrypted_data_section() -> cms::content_info::ContentInfo {
    use der::asn1::ObjectIdentifier;

    cms::content_info::ContentInfo {
        content_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.6"),
        content: any_octets(b"an encrypted safe would be here"),
    }
}

/// A self-signed certificate with no `basicConstraints` extension at all.
///
/// Absent means `cA = FALSE` (RFC 5280) — the convention the login screen
/// follows and the record refuses to. No committed fixture leaves the extension
/// out, so this one is minted here.
fn without_basic_constraints(cn: &str) -> Vec<u8> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
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
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

/// A container holding the given certificates — each with the pairing token it
/// is to carry — beside the given key bag.
///
/// Assembled here rather than by our own writer, which pairs its key with the
/// leaf and refuses anything else. The layouts that need answering are the ones
/// a foreign drive can carry.
fn paired_container(certs: &[PairedCertificate<'_>], key: KeyBag<'_>) -> Vec<u8> {
    use pkcs12::safe_bag::SafeBag;

    let mut bags: Vec<SafeBag> = certs
        .iter()
        .map(|(der, token)| cert_bag_with(der, token.map(pairing_attributes)))
        .collect();
    match key {
        KeyBag::Absent => {}
        KeyBag::Unpaired => bags.push(filler_key_bag(None)),
        KeyBag::Paired(token) => bags.push(filler_key_bag(Some(token))),
    }

    container_of_bags(&bags)
}

/// A container carrying one certificate and two key bags, each with its own
/// token — one of which the certificate repeats.
///
/// Two keys leave no single "the container's key" to pair against, and picking
/// the one that happens to match would be picking the answer that produces an
/// answer.
fn two_key_bags() -> Vec<u8> {
    container_of_bags(&[
        cert_bag_with(
            &fixture_der("leaf_rsa.pem"),
            Some(pairing_attributes(b"first")),
        ),
        filler_key_bag(Some(b"first")),
        filler_key_bag(Some(b"second")),
    ])
}

#[test]
fn a_container_carrying_two_end_entities_names_neither() {
    // Two non-CA certificates in one container — a foreign drive, a mis-issue,
    // two bundles concatenated. Naming either would point an engineer at a
    // device that has nothing to do with the failure in front of them. Our own
    // writer refuses to assemble this, so the container is built here.
    let bytes =
        container_with_certificates(&[fixture_der("leaf_rsa.pem"), fixture_der("leaf_ecdsa.pem")]);
    assert!(
        try_extract_cert_without_pin(&bytes).is_none(),
        "an ambiguous container must yield the generic message, not a guess"
    );

    // The same container with one of them removed is unambiguous again: what
    // silenced the diagnostic was the second end-entity, not the hand-built
    // container.
    let single = container_with_certificates(&[fixture_der("leaf_rsa.pem")]);
    assert_eq!(
        try_extract_cert_without_pin(&single)
            .expect("one end-entity is unambiguous")
            .subject_cn()
            .unwrap(),
        "alice"
    );
}

#[test]
fn a_container_of_certificate_authorities_names_nobody() {
    let bytes = container_with_certificates(&[fixture_der("ca.pem"), fixture_der("int.pem")]);
    assert!(
        try_extract_cert_without_pin(&bytes).is_none(),
        "a container with no end-entity has nobody to name"
    );
}

/// The number of certificates a container may hold and still be answered about.
///
/// Mirrors `MAX_CERTIFICATES`, which is private to the crate. Keeping the
/// number here rather than deriving it is the point: the boundary is a promise
/// to the reader of the message, and a test that followed the constant would
/// not notice it moving.
const CERTIFICATE_LIMIT: usize = 16;

/// The number of safes a container may hold and still be answered about.
const SAFE_LIMIT: usize = 16;

/// The total certificate bytes a container may hold and still be answered about.
const CERTIFICATE_BYTE_LIMIT: usize = 256 * 1024;

#[test]
fn a_container_that_piles_up_certificates_yields_nothing() {
    // The certificate an honest container would be read for is at the end, so
    // a walk that just kept going would still find it. Right up to the limit it
    // does; one bag past it, the container stops being one this path answers
    // about at all.
    let ca = fixture_der("ca.pem");
    let leaf = fixture_der("leaf_rsa.pem");

    let mut at_the_limit = vec![ca.clone(); CERTIFICATE_LIMIT - 1];
    at_the_limit.push(leaf.clone());
    assert_eq!(
        try_extract_cert_without_pin(&container_with_certificates(&at_the_limit))
            .expect("a container exactly at the limit is still read")
            .subject_cn()
            .unwrap(),
        "alice"
    );

    let mut one_past = vec![ca; CERTIFICATE_LIMIT];
    one_past.push(leaf);
    assert!(
        try_extract_cert_without_pin(&container_with_certificates(&one_past)).is_none(),
        "one certificate past the limit must yield nothing"
    );
}

#[test]
fn a_container_that_piles_up_safes_yields_nothing() {
    let safe_of_a_ca = || certificate_safe(&[fixture_der("ca.pem")]);
    let safe_of_the_leaf = || certificate_safe(&[fixture_der("leaf_rsa.pem")]);

    let mut at_the_limit: Vec<cms::content_info::ContentInfo> =
        (0..SAFE_LIMIT - 1).map(|_| safe_of_a_ca()).collect();
    at_the_limit.push(safe_of_the_leaf());
    assert_eq!(
        try_extract_cert_without_pin(&container_of_safes(&at_the_limit))
            .expect("a container exactly at the limit is still read")
            .subject_cn()
            .unwrap(),
        "alice"
    );

    let mut one_past: Vec<cms::content_info::ContentInfo> =
        (0..SAFE_LIMIT).map(|_| safe_of_a_ca()).collect();
    one_past.push(safe_of_the_leaf());
    assert!(
        try_extract_cert_without_pin(&container_of_safes(&one_past)).is_none(),
        "one safe past the limit must yield nothing"
    );
}

#[test]
fn a_container_of_oversized_certificate_bags_yields_nothing() {
    // A handful of bags can still carry megabytes, so the count is not the only
    // thing the container is measured by. The bags are not certificates — this
    // path does not require them to be, and the byte cap has to hold before
    // anything tries to parse them.
    let bulky = vec![0xAA_u8; CERTIFICATE_BYTE_LIMIT / 2];
    let leaf = fixture_der("leaf_rsa.pem");

    let under = container_with_certificates(&[bulky.clone(), leaf.clone()]);
    assert_eq!(
        try_extract_cert_without_pin(&under)
            .expect("bulk under the cap does not hide the certificate beside it")
            .subject_cn()
            .unwrap(),
        "alice"
    );

    let over = container_with_certificates(&[bulky.clone(), bulky, leaf]);
    assert!(
        try_extract_cert_without_pin(&over).is_none(),
        "bulk past the cap must yield nothing"
    );
}

#[test]
fn a_container_past_a_limit_yields_nothing_rather_than_what_was_read_first() {
    // The leaf comes first, so a walk that stopped at the limit and kept what it
    // had would name it — and would name it just as confidently in a container
    // whose later bags held a second end-entity. Silence past a limit is what
    // keeps "one certificate, no doubt" from degrading into "the first one".
    let bulky = vec![0xAA_u8; CERTIFICATE_BYTE_LIMIT / 2];
    let bytes = container_with_certificates(&[
        fixture_der("leaf_rsa.pem"),
        bulky.clone(),
        bulky,
        fixture_der("leaf_ecdsa.pem"),
    ]);
    assert!(
        try_extract_cert_without_pin(&bytes).is_none(),
        "what was collected before the limit must not become the answer"
    );
}

/// An `id-data` `ContentInfo` carrying the given octets.
fn id_data_holding(payload: &[u8]) -> cms::content_info::ContentInfo {
    use der::asn1::{Any, ObjectIdentifier, OctetString};
    use der::{Decode as _, Encode as _};

    let octets = OctetString::new(payload).expect("the payload fits an octet string");
    cms::content_info::ContentInfo {
        content_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1"),
        content: Any::from_der(&octets.to_der().expect("octets encode"))
            .expect("octets are an ASN.1 value"),
    }
}

/// An `id-data` safe holding one certificate bag per given certificate.
fn certificate_safe(cert_ders: &[Vec<u8>]) -> cms::content_info::ContentInfo {
    use der::asn1::OctetString;
    use der::Encode as _;
    use pkcs12::cert_type::CertBag;
    use pkcs12::safe_bag::SafeBag;

    let bags: Vec<SafeBag> = cert_ders
        .iter()
        .map(|der| {
            let cert_bag = CertBag {
                cert_id: pkcs12::PKCS_12_X509_CERT_OID,
                cert_value: OctetString::new(der.clone()).expect("a certificate fits"),
            };
            SafeBag {
                // The bag codec is asymmetric: encoding adds the `[0] EXPLICIT`
                // wrapper that decoding leaves in place, so what goes in here is
                // the bare value.
                bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
                bag_value: cert_bag.to_der().expect("the bag encodes"),
                bag_attributes: None,
            }
        })
        .collect();

    id_data_holding(&bags.to_der().expect("the safe encodes"))
}

/// A container holding the given safes and nothing else.
fn container_of_safes(safes: &[cms::content_info::ContentInfo]) -> Vec<u8> {
    use der::Encode as _;
    container_around(
        &safes
            .to_vec()
            .to_der()
            .expect("the authenticated safe encodes"),
    )
}

/// A container holding the given certificates in the clear and nothing else.
///
/// Assembled here rather than by our own writer, which refuses layouts it would
/// never issue — and those are exactly the ones a foreign drive can carry.
fn container_with_certificates(cert_ders: &[Vec<u8>]) -> Vec<u8> {
    container_of_safes(&[certificate_safe(cert_ders)])
}

/// A container whose `AuthenticatedSafe` is the given DER, with no MAC.
///
/// Everything below arrives on a device nobody has authenticated, so the walk
/// has to survive DER that is structurally plausible and hostile.
fn container_around(auth_safe_payload: &[u8]) -> Vec<u8> {
    use der::Encode as _;
    use pkcs12::pfx::{Pfx, Version};

    Pfx {
        version: Version::V3,
        auth_safe: id_data_holding(auth_safe_payload),
        mac_data: None,
    }
    .to_der()
    .expect("the skeleton encodes")
}

/// `depth` SEQUENCE headers wrapped around one another, innermost first.
///
/// Every length is written in the two-byte long form, which DER only permits
/// when the content is at least 256 bytes — hence the padding at the centre.
/// Short-form lengths would cap the whole structure at 127 bytes and with it
/// the depth at a few dozen levels, which is no test of anything: a decoder
/// that descended per level would return from that without noticing.
fn nested_sequences(depth: usize) -> Vec<u8> {
    // A 300-byte OCTET STRING: large enough that every length above it needs
    // two bytes, so no wrapper has to fall back to the short form.
    let mut out = vec![0x04, 0x82, 0x01, 0x2C];
    out.extend(std::iter::repeat_n(0x00, 300));

    for _ in 0..depth {
        let len = u16::try_from(out.len()).expect("the nesting stays inside a two-byte length");
        let mut wrapped = vec![0x30, 0x82];
        wrapped.extend_from_slice(&len.to_be_bytes());
        wrapped.extend_from_slice(&out);
        out = wrapped;
    }

    // The depth is the property under test, so it is checked rather than
    // assumed: every level contributes one `30 82` header at the front.
    let levels = out
        .chunks_exact(4)
        .take_while(|header| header[0] == 0x30 && header[1] == 0x82)
        .count();
    assert_eq!(levels, depth, "the nesting is only as deep as it is built");
    out
}

#[test]
fn hostile_but_well_formed_containers_yield_nothing() {
    // A SEQUENCE header claiming a length no buffer could hold.
    let overlong_length = vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF];
    let deep = nested_sequences(4000);

    for (what, payload) in [
        ("no safes at all", vec![0x30, 0x00]),
        (
            "a safe that is not a safe",
            vec![0x30, 0x03, 0x02, 0x01, 0x00],
        ),
        ("an overlong length", overlong_length),
        ("four thousand levels of nesting", deep),
        ("a bare NULL", vec![0x05, 0x00]),
        ("nothing", Vec::new()),
    ] {
        let bytes = container_around(&payload);
        assert!(
            try_extract_cert_without_pin(&bytes).is_none(),
            "{what} must yield no certificate rather than panic"
        );
    }
}

#[test]
fn a_certificate_bag_holding_garbage_yields_nothing() {
    use der::asn1::{OctetString, SetOfVec};
    use der::Encode as _;
    use pkcs12::safe_bag::SafeBag;

    // A well-formed `id-data` safe holding a well-formed certificate bag whose
    // certificate is not one: the walk must drop it, not hand it on.
    let garbage = OctetString::new(b"not a certificate".to_vec()).unwrap();
    let bags = vec![SafeBag {
        bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
        bag_value: garbage.to_der().unwrap(),
        bag_attributes: Some(SetOfVec::new()),
    }];
    let safe = id_data_holding(&bags.to_der().unwrap());
    let bytes = container_around(&vec![safe].to_der().unwrap());
    assert!(try_extract_cert_without_pin(&bytes).is_none());
}

/// Offset of the shrouded key bag's encrypted value inside a container.
///
/// Found by looking for the bag's own DER: the container is a concatenation of
/// its parts, so the bytes the writer produced for that bag appear verbatim.
fn shrouded_key_bag_offset(bytes: &[u8]) -> usize {
    use der::{Decode as _, Encode as _};
    use pkcs12::pfx::Pfx;
    use pkcs12::safe_bag::SafeBag;

    let pfx = Pfx::from_der(bytes).expect("the fixture is a container");
    let auth_safe = der::asn1::OctetString::from_der(
        &pfx.auth_safe.content.to_der().expect("content re-encodes"),
    )
    .expect("the authenticated safe is carried in octets");
    let safes = Vec::<cms::content_info::ContentInfo>::from_der(auth_safe.as_bytes())
        .expect("the authenticated safe is a sequence of safes");

    for safe in &safes {
        let Ok(der) = safe.content.to_der() else {
            continue;
        };
        let Ok(payload) = der::asn1::OctetString::from_der(&der) else {
            continue;
        };
        let Ok(bags) = Vec::<SafeBag>::from_der(payload.as_bytes()) else {
            continue;
        };
        for bag in &bags {
            if bag.bag_id != pkcs12::PKCS_12_PKCS8_KEY_BAG_OID {
                continue;
            }
            let needle = &bag.bag_value;
            if let Some(pos) = bytes
                .windows(needle.len())
                .position(|window| window == needle.as_slice())
            {
                return pos;
            }
        }
    }
    panic!("the fixture is expected to carry a shrouded key bag");
}

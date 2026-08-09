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
use tessera_core::pkcs12::{try_extract_cert_without_pin, LoadedKeyMaterial, Pkcs12Error};

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
    assert_eq!(cert.serial_hex(), LEAF_RSA_SERIAL);

    // The same bytes still need the password for the key: nothing above weakened
    // the authentication path.
    let material = LoadedKeyMaterial::from_p12(
        CLEAR_CERTS,
        &SecretString::from(FIXTURE_PIN.to_owned()),
        None,
    )
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
    let err =
        LoadedKeyMaterial::from_p12(&bytes, &SecretString::from(FIXTURE_PIN.to_owned()), None)
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
    let material = LoadedKeyMaterial::from_p12(
        CA_BEFORE_LEAF,
        &SecretString::from(FIXTURE_PIN.to_owned()),
        None,
    )
    .expect("the fixture opens with its own password");
    assert_eq!(
        material.end_entity.subject_cn().unwrap(),
        "CertAuth Test Intermediate"
    );
}

/// The serial of `leaf_rsa.pem`, pinned by `tests/fixtures/gen.sh`.
const LEAF_RSA_SERIAL: &str = "44E056A8B426D4727A82EC2A41EDFFFEA4B3D0E3";

#[test]
fn a_certificate_in_a_nested_bag_list_is_read() {
    // RFC 7292 lets a bag list hold a bag list, and OpenSSL descends into it.
    // This walk did not, so a container whose writer wrapped its bags opened
    // normally at the login prompt while showing the diagnostic nothing.
    let nested = container_of_bags(&[nested_bag(&[cert_bag(&fixture_der("leaf_rsa.pem"))])]);
    assert_eq!(
        try_extract_cert_without_pin(&nested)
            .expect("a nested certificate bag is read, not stepped over")
            .serial_hex(),
        LEAF_RSA_SERIAL
    );

    // Two levels down, beside a CA at the top: the descent is not a special case
    // for a container that holds nothing else.
    let deeper = container_of_bags(&[
        cert_bag(&fixture_der("ca.pem")),
        nested_bag(&[nested_bag(&[cert_bag(&fixture_der("leaf_rsa.pem"))])]),
    ]);
    assert_eq!(
        try_extract_cert_without_pin(&deeper)
            .expect("the nested leaf is found beside a CA at the top level")
            .serial_hex(),
        LEAF_RSA_SERIAL
    );

    // And the descent is bounded: past the depth limit the walk stops, so a
    // certificate buried below it is one the diagnostic does not see. The bytes
    // arrive on a device nobody has authenticated, and a bounded read that says
    // nothing is the outcome this path is built around.
    let mut deep = nested_bag(&[cert_bag(&fixture_der("leaf_rsa.pem"))]);
    for _ in 0..6 {
        deep = nested_bag(&[deep]);
    }
    assert!(
        try_extract_cert_without_pin(&container_of_bags(&[deep])).is_none(),
        "nesting the walk refuses to enter must not yield a certificate"
    );
}

/// A certificate bag holding `der`, with no bag attributes.
///
/// The attributes are where a writer puts `friendlyName` and `localKeyID`;
/// nothing on this path reads them, so leaving them out is the honest shape for
/// a test of what it does read.
fn cert_bag(der: &[u8]) -> pkcs12::safe_bag::SafeBag {
    use der::asn1::OctetString;
    use der::Encode as _;
    use pkcs12::cert_type::CertBag;

    pkcs12::safe_bag::SafeBag {
        bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
        // The bag codec is asymmetric: encoding adds the `[0] EXPLICIT` wrapper
        // that decoding leaves in place, so what goes in here is the bare value.
        bag_value: CertBag {
            cert_id: pkcs12::PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(der.to_vec()).unwrap(),
        }
        .to_der()
        .unwrap(),
        bag_attributes: None,
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
    use der::Encode as _;
    use pkcs12::safe_bag::SafeBag;

    let bags: Vec<SafeBag> = cert_ders.iter().map(|der| cert_bag(der)).collect();
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

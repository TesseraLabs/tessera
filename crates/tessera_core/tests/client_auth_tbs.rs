//! Public, test-only CSR/TBS/PKIX and Engine separation checks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use der::{Decode, Encode};
use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::stack::Stack;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{
    X509Extension, X509NameBuilder, X509PurposeId, X509Req, X509StoreContext, X509,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use tessera_core::role::{
    resolve_and_cover, Resolution, RoleDenyReason, RoleId, RoleOs, RoleStore, SystemAccounts,
    TrustMode,
};
use tessera_core::x509::{Certificate, TrustError};
use tessera_ext::oids::*;
use tessera_issuer::client_auth::*;
use tessera_issuer::{
    assemble_signed_certificate, serial::Serial, sign::SignatureAlgorithm, Validity,
};

const NOW: i64 = 1_800_000_000;
const URI: &str = "urn:example:client:one";

fn key(value: u32) -> PKey<Private> {
    // Public deterministic fixture scalars, never production keys.
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let secret = BigNum::from_u32(value).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.mul_generator2(&group, &secret, &mut context).unwrap();
    PKey::from_ec_key(EcKey::from_private_components(&group, &secret, &point).unwrap()).unwrap()
}

fn point(key: &PKey<Private>, compressed: bool) -> Vec<u8> {
    let ec = key.ec_key().unwrap();
    let mut context = BigNumContext::new().unwrap();
    ec.public_key()
        .to_bytes(
            ec.group(),
            if compressed {
                PointConversionForm::COMPRESSED
            } else {
                PointConversionForm::UNCOMPRESSED
            },
            &mut context,
        )
        .unwrap()
}

fn custom(oid: &str, critical: bool, value: &[u8]) -> X509Extension {
    X509Extension::new_from_der(
        &Asn1Object::from_str(oid).unwrap(),
        critical,
        &Asn1OctetString::new_from_bytes(value).unwrap(),
    )
    .unwrap()
}

fn ca(key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>, access: bool) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Fixture CA").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder
        .set_issuer_name(issuer.map_or(name.as_ref(), |(cert, _)| cert.subject_name()))
        .unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(NOW - 100).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(NOW + 10_000).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(issuer.map(|(cert, _)| cert.as_ref()), None))
        .unwrap();
    builder.append_extension(ski).unwrap();
    if let Some((parent, _)) = issuer {
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(parent), None))
            .unwrap();
        builder.append_extension(aki).unwrap();
    }
    if access {
        builder
            .append_extension(custom(
                PROFILE_VERSION_OID,
                true,
                &tessera_ext::ext::encode_profile_version(1),
            ))
            .unwrap();
        builder
            .append_extension(custom(
                DELEGATION_CONSTRAINTS_OID,
                true,
                &tessera_ext::delegation::encode_constraints(
                    &tessera_ext::delegation::DelegationConstraints {
                        require_tags: vec![],
                        allow_roles: vec!["oper".into()],
                        max_level: 7,
                        max_ttl: 10_000,
                    },
                ),
            ))
            .unwrap();
    }
    builder
        .sign(
            issuer.map_or(key, |(_, signer)| signer),
            MessageDigest::sha256(),
        )
        .unwrap();
    builder.build()
}

fn csr(key: &PKey<Private>, hostile: bool) -> Vec<u8> {
    let mut builder = X509Req::builder().unwrap();
    builder.set_version(0).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text(
        "CN",
        if hostile {
            "admin"
        } else {
            "untrusted requester"
        },
    )
    .unwrap();
    builder.set_subject_name(&name.build()).unwrap();
    builder.set_pubkey(key).unwrap();
    if hostile {
        let mut extensions = Stack::new().unwrap();
        extensions
            .push(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        extensions
            .push(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        extensions
            .push(
                SubjectAlternativeName::new()
                    .uri("urn:attacker:identity")
                    .build(&builder.x509v3_context(None))
                    .unwrap(),
            )
            .unwrap();
        extensions
            .push(custom(
                ALLOWED_ROLES_OID,
                false,
                &tessera_ext::ext::encode_seq_of_utf8(&["admin"]),
            ))
            .unwrap();
        extensions
            .push(custom(
                HOST_BINDING_OID,
                false,
                &tessera_ext::ext::encode_seq_of_utf8(&["*"]),
            ))
            .unwrap();
        builder.add_extensions(&extensions).unwrap();
    }
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

struct Fixture {
    issuer: PKey<Private>,
    ca: X509,
    csr: Vec<u8>,
    other: Vec<u8>,
    serial: Serial,
}
impl Fixture {
    fn new() -> Self {
        let issuer = key(2);
        let ca = ca(&issuer, None, false);
        Self {
            issuer,
            ca,
            csr: csr(&key(3), false),
            other: point(&key(4), true),
            serial: Serial::from_entropy(&[0x12; 16]),
        }
    }
    fn request<'a>(&'a self, ca_der: &'a [u8]) -> ClientAuthCsrTbsRequest<'a> {
        ClientAuthCsrTbsRequest {
            csr_der: &self.csr,
            subject_uri: URI,
            distinct_from_sec1: &self.other,
            issuer_certificate_der: ca_der,
            validity: Validity {
                not_before: u64::try_from(NOW).unwrap(),
                not_after: u64::try_from(NOW + 3600).unwrap(),
            },
            serial: &self.serial,
            signature_algorithm: SignatureAlgorithm::EcdsaWithSha256,
        }
    }
}

fn sign_fixture(prepared: &PreparedClientAuthTbs, issuer: &PKey<Private>) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha256(), issuer).unwrap();
    signer.update(prepared.tbs_der()).unwrap();
    assemble_signed_certificate(
        prepared.tbs_der(),
        SignatureAlgorithm::EcdsaWithSha256,
        &signer.sign_to_vec().unwrap(),
    )
    .unwrap()
}

fn pkix_client(root: &X509, intermediates: &[X509], leaf: &X509, purpose: X509PurposeId) -> bool {
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(root.clone()).unwrap();
    store.set_purpose(purpose).unwrap();
    let mut params = X509VerifyParam::new().unwrap();
    params.set_time(NOW);
    params.set_flags(X509VerifyFlags::X509_STRICT).unwrap();
    store.set_param(&params).unwrap();
    let mut chain = Stack::new().unwrap();
    for cert in intermediates {
        chain.push(cert.clone()).unwrap();
    }
    X509StoreContext::new()
        .unwrap()
        .init(&store.build(), leaf, &chain, |context| {
            context.verify_cert()
        })
        .unwrap()
}

#[test]
fn real_pkix_client_profile_is_deterministic_but_not_an_engine_credential() {
    let f = Fixture::new();
    let ca_der = f.ca.to_der().unwrap();
    let request = f.request(&ca_der);
    let prepared = prepare_client_auth_tbs(&request).unwrap();
    assert_eq!(
        prepared.tbs_der(),
        prepare_client_auth_tbs(&request).unwrap().tbs_der()
    );
    assert_eq!(
        prepared.csr_sha256(),
        <[u8; 32]>::from(Sha256::digest(&f.csr))
    );
    assert_eq!(
        prepared.issuer_sha256(),
        <[u8; 32]>::from(Sha256::digest(&ca_der))
    );
    assert_eq!(prepared.subject_uri(), URI);
    let der = sign_fixture(&prepared, &f.issuer);
    let cert = X509::from_der(&der).unwrap();
    assert!(cert.verify(&f.issuer).unwrap());
    assert_eq!(
        cert.authority_key_id().unwrap().as_slice(),
        f.ca.subject_key_id().unwrap().as_slice()
    );
    assert!(pkix_client(&f.ca, &[], &cert, X509PurposeId::SSL_CLIENT));
    assert!(!pkix_client(&f.ca, &[], &cert, X509PurposeId::SSL_SERVER));
    assert_eq!(cert.subject_name().entries().count(), 0);
    assert_eq!(
        cert.subject_name().entries_by_nid(Nid::COMMONNAME).count(),
        0
    );
    assert_eq!(
        cert.subject_alt_names()
            .unwrap()
            .iter()
            .filter_map(|n| n.uri())
            .collect::<Vec<_>>(),
        [URI]
    );
    for oid in [
        ALLOWED_ROLES_OID,
        HOST_BINDING_OID,
        MAX_INTEGRITY_OID,
        PROFILE_VERSION_OID,
        DELEGATION_CONSTRAINTS_OID,
        USER_BINDING_OID,
    ] {
        assert!(tessera_ext::ext::extract_extension_value(&der, oid)
            .unwrap()
            .is_none());
    }
    let engine_cert = Certificate::from_der(&der).unwrap();
    assert!(
        matches!(tessera_core::x509::profile_validation::verify_profile_and_criticals(&[engine_cert], 1), Err(TrustError::UnhandledCriticalExtension(oid)) if oid == "2.5.29.17")
    );
    assert!(matches!(
        tessera_core::host_binding::verify_host_binding(&cert, &"0".repeat(64)),
        Err(tessera_core::host_binding::HostBindingError::HostExtensionMissing)
    ));
    // This leaf is deliberately not a VerifiedX509 in the Engine: its trust
    // profile rejects it above. Independently prove that the absent role list
    // cannot cover a login even if a future Engine understands critical SAN.
    let roles: Option<Vec<RoleId>> = None;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("oper.toml"),
        "role=\"oper\"\nversion=1\nos=\"linux\"\nname=\"Operator\"\nlevel=1\n",
    )
    .unwrap();
    let store = RoleStore::load(
        dir.path(),
        RoleOs::Linux,
        TrustMode::Standalone,
        SystemAccounts::empty(),
    )
    .unwrap();
    assert!(matches!(
        resolve_and_cover(
            &store,
            Some(&RoleId::new("oper").unwrap()),
            roles.as_deref(),
            "oper"
        ),
        Resolution::Denied {
            reason: RoleDenyReason::NotCovered
        }
    ));
    // Optional export of this public fixture certificate for independent consumer tests.
    if let Some(path) = std::env::var_os("TESSERA_CLIENT_AUTH_TEST_CERT_DER") {
        std::fs::write(path, &der).unwrap();
    }
}

#[test]
fn issuer_key_identifier_and_leaf_authority_identifier_are_closed_and_bounded() {
    let f = Fixture::new();
    let ca_der = f.ca.to_der().unwrap();
    for change in 0..6 {
        let mut parent = x509_cert::Certificate::from_der(&ca_der).unwrap();
        let extensions = parent.tbs_certificate.extensions.as_mut().unwrap();
        let index = extensions
            .iter()
            .position(|item| item.extn_id.to_string() == "2.5.29.14")
            .unwrap();
        match change {
            0 => {
                extensions.remove(index);
            }
            1 => {
                extensions[index].critical = true;
            }
            2 => {
                extensions.push(extensions[index].clone());
            }
            value => {
                let encoded = match value {
                    3 => vec![0x04, 0x00],
                    4 => tessera_ext::der::encode_tlv(0x04, &[1; MAX_KEY_IDENTIFIER_BYTES + 1]),
                    _ => vec![0x04, 0x01, 0x01, 0x00],
                };
                extensions[index].extn_value = der::asn1::OctetString::new(encoded).unwrap();
            }
        }
        assert!(prepare_client_auth_tbs(&f.request(&parent.to_der().unwrap())).is_err());
    }
    let prepared = prepare_client_auth_tbs(&f.request(&ca_der)).unwrap();
    for change in 0..5 {
        let mut tbs = x509_cert::TbsCertificate::from_der(prepared.tbs_der()).unwrap();
        let aki = &mut tbs.extensions.as_mut().unwrap()[4];
        if change == 0 {
            aki.critical = true;
        } else {
            let fields = match change {
                1 => vec![0x80, 0x00],
                2 => tessera_ext::der::encode_tlv(0x80, &[1; MAX_KEY_IDENTIFIER_BYTES + 1]),
                3 => vec![0x80, 0x01, 0x01, 0x82, 0x01, 0x01],
                _ => vec![0x04, 0x01, 0x01],
            };
            aki.extn_value =
                der::asn1::OctetString::new(tessera_ext::der::encode_tlv(0x30, &fields)).unwrap();
        }
        assert!(validate_client_auth_tbs(&tbs.to_der().unwrap()).is_err());
    }
}

#[test]
fn csr_subject_and_requested_privileges_do_not_shape_the_certificate() {
    let f = Fixture::new();
    let ca_der = f.ca.to_der().unwrap();
    let ordinary = prepare_client_auth_tbs(&f.request(&ca_der)).unwrap();
    let hostile = csr(&key(3), true);
    let mut request = f.request(&ca_der);
    request.csr_der = &hostile;
    let prepared = prepare_client_auth_tbs(&request).unwrap();
    assert_eq!(ordinary.tbs_der(), prepared.tbs_der());
    assert_ne!(ordinary.csr_sha256(), prepared.csr_sha256());
    assert_eq!(ordinary.spki_sha256(), prepared.spki_sha256());
}

#[test]
fn reused_actual_curve_point_and_bad_csr_pop_or_algorithm_are_refused() {
    let f = Fixture::new();
    let ca_der = f.ca.to_der().unwrap();
    for compressed in [false, true] {
        let same = point(&key(3), compressed);
        let mut request = f.request(&ca_der);
        request.distinct_from_sec1 = &same;
        assert!(matches!(
            prepare_client_auth_tbs(&request),
            Err(ClientAuthError::Invalid("reused_signing_key"))
        ));
    }
    let mut tampered = f.csr.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut request = f.request(&ca_der);
    request.csr_der = &tampered;
    assert!(prepare_client_auth_tbs(&request).is_err());
    let mut parsed = x509_cert::request::CertReq::from_der(&f.csr).unwrap();
    parsed.algorithm.parameters = Some(der::Any::null());
    let malformed = parsed.to_der().unwrap();
    request.csr_der = &malformed;
    assert!(matches!(
        prepare_client_auth_tbs(&request),
        Err(ClientAuthError::Invalid("csr_signature_algorithm"))
    ));
    let rsa = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let unsupported = csr(&rsa, false);
    request.csr_der = &unsupported;
    assert!(prepare_client_auth_tbs(&request).is_err());
}

#[test]
fn input_limits_exact_der_issuer_window_and_profile_are_enforced() {
    let f = Fixture::new();
    let ca_der = f.ca.to_der().unwrap();
    for bad in [
        Vec::new(),
        vec![0; MAX_CSR_BYTES + 1],
        [f.csr.as_slice(), &[0]].concat(),
        X509Req::from_der(&f.csr).unwrap().to_pem().unwrap(),
    ] {
        let mut request = f.request(&ca_der);
        request.csr_der = &bad;
        assert!(prepare_client_auth_tbs(&request).is_err());
    }
    for uri in [
        "",
        "not a URI",
        "1:thing",
        "urn:thing%Q2",
        "urn:\nthing",
        "urn:é",
    ] {
        let mut request = f.request(&ca_der);
        request.subject_uri = uri;
        assert!(prepare_client_auth_tbs(&request).is_err());
    }
    let long_uri = format!("urn:{}", "x".repeat(MAX_URI_BYTES));
    let mut request = f.request(&ca_der);
    request.subject_uri = &long_uri;
    assert!(prepare_client_auth_tbs(&request).is_err());
    let mut request = f.request(&ca_der);
    request.validity.not_after = u64::try_from(NOW + 20_000).unwrap();
    assert!(prepare_client_auth_tbs(&request).is_err());
    let mut request = f.request(&ca_der);
    request.validity.not_before = request.validity.not_after;
    assert!(prepare_client_auth_tbs(&request).is_err());
    let mut request = f.request(&ca_der);
    request.signature_algorithm = SignatureAlgorithm::RsaPkcs1Sha256;
    assert!(prepare_client_auth_tbs(&request).is_err());
    let trailing = [ca_der.as_slice(), &[0]].concat();
    let mut request = f.request(&trailing);
    assert!(prepare_client_auth_tbs(&request).is_err());
    request.issuer_certificate_der = &[];
    assert!(prepare_client_auth_tbs(&request).is_err());
    let prepared = prepare_client_auth_tbs(&f.request(&ca_der)).unwrap();
    for cut in 0..prepared.tbs_der().len() {
        assert!(validate_client_auth_tbs(&prepared.tbs_der()[..cut]).is_err());
    }
    for change in 0..5 {
        let mut tbs = x509_cert::TbsCertificate::from_der(prepared.tbs_der()).unwrap();
        match change {
            0 => tbs.extensions.as_mut().unwrap()[3].critical = false,
            1 => tbs.extensions.as_mut().unwrap().pop().map(|_| ()).unwrap(),
            2 => {
                let item = tbs.extensions.as_ref().unwrap()[0].clone();
                tbs.extensions.as_mut().unwrap().push(item);
            }
            3 => {
                tbs.subject = x509_cert::name::Name::from_der(
                    f.ca.subject_name().to_der().unwrap().as_slice(),
                )
                .unwrap();
            }
            _ => {
                tbs.extensions.as_mut().unwrap()[1].extn_value =
                    der::asn1::OctetString::new(vec![0x03, 0x02, 0x01, 0x06]).unwrap();
            }
        }
        assert!(validate_client_auth_tbs(&tbs.to_der().unwrap()).is_err());
    }
}

#[test]
fn access_ca_critical_extensions_are_not_silently_ignored_by_stock_tls() {
    let root_key = key(5);
    let root = ca(&root_key, None, false);
    let issuer_key = key(2);
    let intermediate = ca(&issuer_key, Some((&root, &root_key)), true);
    let f = Fixture::new();
    let parent = intermediate.to_der().unwrap();
    let prepared = prepare_client_auth_tbs(&f.request(&parent)).unwrap();
    let certificate = X509::from_der(&sign_fixture(&prepared, &issuer_key)).unwrap();
    assert!(!pkix_client(
        &root,
        &[intermediate],
        &certificate,
        X509PurposeId::SSL_CLIENT
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn bounded_arbitrary_inputs_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..MAX_CSR_BYTES + 8)) {
        let f = Fixture::new(); let ca_der = f.ca.to_der().unwrap(); let mut request = f.request(&ca_der); request.csr_der = &bytes;
        let _result = prepare_client_auth_tbs(&request);
        let _validation = validate_client_auth_tbs(&bytes);
        request.csr_der = &f.csr;
        request.issuer_certificate_der = &bytes;
        let _issuer = prepare_client_auth_tbs(&request);
    }
}

#[test]
fn csr_unused_signature_bits_and_issuer_padding_cannot_assert_capabilities() {
    let f = Fixture::new();
    let ca_der = f.ca.to_der().unwrap();
    let mut parsed = x509_cert::request::CertReq::from_der(&f.csr).unwrap();
    parsed.signature = der::asn1::BitString::new(1, parsed.signature.raw_bytes().to_vec()).unwrap();
    let malformed = parsed.to_der().unwrap();
    let mut request = f.request(&ca_der);
    request.csr_der = &malformed;
    assert!(prepare_client_auth_tbs(&request).is_err());
    let mut parent = x509_cert::Certificate::from_der(&ca_der).unwrap();
    let usage = parent
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|ext| ext.extn_id.to_string() == "2.5.29.15")
        .unwrap();
    // The keyCertSign bit is padding, not a declared usage, in this BIT STRING.
    usage.extn_value = der::asn1::OctetString::new(vec![0x03, 0x02, 0x06, 0x04]).unwrap();
    let malformed = parent.to_der().unwrap();
    assert!(matches!(
        prepare_client_auth_tbs(&f.request(&malformed)),
        Err(ClientAuthError::Invalid("issuer_key_cert_sign"))
    ));
}

fn der_parts(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let item = tessera_ext::der::read_tlv(bytes).unwrap();
        out.push(bytes[..bytes.len() - item.rest.len()].to_vec());
        bytes = item.rest;
    }
    out
}
fn der_content(bytes: &[u8]) -> &[u8] {
    tessera_ext::der::read_tlv(bytes).unwrap().value
}
fn der_wrap(tag: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    tessera_ext::der::encode_tlv(tag, &parts.concat())
}

#[test]
fn explicit_default_false_extension_is_not_canonical_der() {
    let f = Fixture::new();
    let ca_der = f.ca.to_der().unwrap();
    let prepared = prepare_client_auth_tbs(&f.request(&ca_der)).unwrap();
    let mut fields = der_parts(der_content(prepared.tbs_der()));
    let wrapper = fields.pop().unwrap();
    let mut extensions = der_parts(der_content(der_content(&wrapper)));
    let mut eku = der_parts(der_content(&extensions[2]));
    eku.insert(1, vec![0x01, 0x01, 0x00]); // Explicit DEFAULT false, not DER.
    extensions[2] = der_wrap(0x30, &eku);
    fields.push(tessera_ext::der::encode_tlv(
        0xA3,
        &der_wrap(0x30, &extensions),
    ));
    let malformed = der_wrap(0x30, &fields);
    assert!(validate_client_auth_tbs(&malformed).is_err());
}

#[test]
fn serial_limit_counts_sign_padding_and_refuses_negative_values() {
    let f = Fixture::new();
    let ca_der = f.ca.to_der().unwrap();
    for entropy in [[0x7f; 20], [0x80; 20]] {
        let serial = Serial::from_entropy(&entropy);
        let mut request = f.request(&ca_der);
        request.serial = &serial;
        let prepared = prepare_client_auth_tbs(&request).unwrap();
        assert!(validate_client_auth_tbs(prepared.tbs_der()).is_ok());
    }
    let prepared = prepare_client_auth_tbs(&f.request(&ca_der)).unwrap();
    for value in [vec![0x80; 20], [vec![0], vec![0x80; 20]].concat()] {
        let mut fields = der_parts(der_content(prepared.tbs_der()));
        fields[1] = tessera_ext::der::encode_tlv(0x02, &value);
        let malformed = der_wrap(0x30, &fields);
        assert!(
            validate_client_auth_tbs(&malformed).is_err(),
            "serial content length {}",
            value.len()
        );
    }
}

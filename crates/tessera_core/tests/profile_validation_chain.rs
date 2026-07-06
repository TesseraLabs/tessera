//! Tests for the chain-intrinsic profile-version gate and unknown-critical
//! extension scan (`trust-chain-validation` delta spec, tasks 4.1 + 2.3).
//!
//! These exercise [`tessera_core::x509::profile_validation::verify_profile_and_criticals`]
//! over synthetic certificate chains built in-memory.  Requires the
//! `mac-tests` feature.  Run with:
//!
//! ```bash
//! cargo test -p tessera_core --features mac-tests --test profile_validation_chain
//! ```

#![cfg(feature = "mac-tests")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(missing_docs)]

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};
use tessera_core::x509::oids::{DELEGATION_CONSTRAINTS_OID, PROFILE_VERSION_OID};
use tessera_core::x509::profile_validation::verify_profile_and_criticals;
use tessera_core::x509::{Certificate, TrustError};

const TAG_INTEGER: u8 = 0x02;

/// One DER INTEGER from an unsigned small value.
fn der_integer(v: u32) -> Vec<u8> {
    // Minimal big-endian encoding with a leading 0x00 only when the high bit
    // would otherwise make it negative.
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    let mut out = vec![TAG_INTEGER, u8::try_from(bytes.len()).unwrap()];
    out.extend_from_slice(&bytes);
    out
}

/// Adds an extension with the given dotted OID, critical flag, and raw
/// `extnValue` DER bytes.
fn add_ext(b: &mut X509Builder, oid: &str, critical: bool, value_der: &[u8]) {
    let oid_obj = Asn1Object::from_str(oid).unwrap();
    let octet = Asn1OctetString::new_from_bytes(value_der).unwrap();
    let ext = X509Extension::new_from_der(&oid_obj, critical, &octet).unwrap();
    b.append_extension(ext).unwrap();
}

/// Build a self-signed cert (CA or leaf).  `extra` is a closure that may append
/// further extensions before signing.
fn build_cert<F: FnOnce(&mut X509Builder)>(is_ca: bool, extra: F) -> Certificate {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_text("CN", "t").unwrap();
    let name = nb.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&serial).unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    if is_ca {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    } else {
        b.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    }
    extra(&mut b);
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    Certificate::from_der(&b.build().to_der().unwrap()).unwrap()
}

const MAX_SUPPORTED: u32 = 1;

#[test]
fn baseline_chain_with_only_known_criticals_accepted() {
    // A leaf + CA carrying only basicConstraints/keyUsage (both critical) and
    // a supported profile_version is accepted.
    let leaf = build_cert(false, |b| {
        add_ext(b, PROFILE_VERSION_OID, true, &der_integer(1));
    });
    let ca = build_cert(true, |b| {
        add_ext(b, PROFILE_VERSION_OID, true, &der_integer(0));
    });
    let chain = vec![leaf, ca];
    verify_profile_and_criticals(&chain, MAX_SUPPORTED).expect("baseline chain accepted");
}

#[test]
fn absent_profile_version_treated_as_baseline() {
    let leaf = build_cert(false, |_b| {});
    let ca = build_cert(true, |_b| {});
    let chain = vec![leaf, ca];
    verify_profile_and_criticals(&chain, MAX_SUPPORTED).expect("absent version is baseline");
}

#[test]
fn profile_version_above_supported_rejected() {
    // tasks.md 4.1 / scenario "Версия профиля выше поддерживаемой".
    let leaf = build_cert(false, |b| {
        add_ext(b, PROFILE_VERSION_OID, true, &der_integer(2));
    });
    let ca = build_cert(true, |_b| {});
    let chain = vec![leaf, ca];
    let err = verify_profile_and_criticals(&chain, MAX_SUPPORTED).unwrap_err();
    assert!(
        matches!(
            err,
            TrustError::ProfileVersionUnsupported { found: 2, max: 1 }
        ),
        "{err:?}"
    );
}

#[test]
fn profile_version_above_supported_on_ca_rejected() {
    // Every cert in the chain is gated, not just the leaf.
    let leaf = build_cert(false, |_b| {});
    let ca = build_cert(true, |b| {
        add_ext(b, PROFILE_VERSION_OID, true, &der_integer(9));
    });
    let chain = vec![leaf, ca];
    let err = verify_profile_and_criticals(&chain, MAX_SUPPORTED).unwrap_err();
    assert!(
        matches!(err, TrustError::ProfileVersionUnsupported { found: 9, .. }),
        "{err:?}"
    );
}

#[test]
fn known_custom_criticals_accepted() {
    // task 2.3: a cert bearing only known criticals (incl. our two custom
    // OIDs) is accepted.  delegation_constraints is critical and lives on a CA.
    let leaf = build_cert(false, |b| {
        add_ext(b, PROFILE_VERSION_OID, true, &der_integer(1));
    });
    let ca = build_cert(true, |b| {
        // A well-formed delegation_constraints body is not required here — the
        // critical scan only checks the OID is recognised, not the body.
        add_ext(b, DELEGATION_CONSTRAINTS_OID, true, &[0x30, 0x00]);
    });
    let chain = vec![leaf, ca];
    verify_profile_and_criticals(&chain, MAX_SUPPORTED).expect("known criticals accepted");
}

#[test]
fn unknown_critical_extension_rejected() {
    // task 2.3 / scenario "Непонятое critical-расширение": an unknown OID
    // marked critical rejects the whole chain.
    // 2.5.29.32 = certificatePolicies, NOT in the allowlist; mark critical.
    let leaf = build_cert(false, |b| {
        add_ext(b, "2.5.29.32", true, &[0x30, 0x00]);
    });
    let ca = build_cert(true, |_b| {});
    let chain = vec![leaf, ca];
    let err = verify_profile_and_criticals(&chain, MAX_SUPPORTED).unwrap_err();
    assert!(
        matches!(err, TrustError::UnhandledCriticalExtension(ref oid) if oid == "2.5.29.32"),
        "{err:?}"
    );
}

#[test]
fn unknown_extension_noncritical_accepted() {
    // The same unknown OID marked NON-critical does not reject (RFC 5280: a
    // verifier may ignore non-critical extensions it does not understand).
    let leaf = build_cert(false, |b| {
        add_ext(b, "2.5.29.32", false, &[0x30, 0x00]);
    });
    let ca = build_cert(true, |_b| {});
    let chain = vec![leaf, ca];
    verify_profile_and_criticals(&chain, MAX_SUPPORTED)
        .expect("non-critical unknown extension ignored");
}

#[test]
fn unknown_critical_on_ca_rejected() {
    let leaf = build_cert(false, |_b| {});
    let ca = build_cert(true, |b| {
        add_ext(b, "2.5.29.32", true, &[0x30, 0x00]);
    });
    let chain = vec![leaf, ca];
    let err = verify_profile_and_criticals(&chain, MAX_SUPPORTED).unwrap_err();
    assert!(
        matches!(err, TrustError::UnhandledCriticalExtension(_)),
        "{err:?}"
    );
}

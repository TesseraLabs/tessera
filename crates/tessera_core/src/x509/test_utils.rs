//! Test-only helpers for building self-signed X.509 certs with arbitrary
//! extensions.  Shared across the binding/scopes extension parsers so each
//! test module does not re-implement ~50 lines of cert plumbing.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::{X509Builder, X509Extension, X509Name, X509};

const TAG_SEQUENCE: u8 = 0x30;
const TAG_UTF8_STRING: u8 = 0x0C;

/// Encodes a short-form (length < 0x80) DER TLV.
pub(crate) fn encode_short_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 0x80);
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(tag);
    out.push(u8::try_from(body.len()).unwrap());
    out.extend_from_slice(body);
    out
}

/// Encodes `SEQUENCE OF UTF8String { items... }` using short-form lengths.
pub(crate) fn encode_seq_of_utf8(items: &[&str]) -> Vec<u8> {
    let mut inner = Vec::new();
    for s in items {
        inner.extend_from_slice(&encode_short_tlv(TAG_UTF8_STRING, s.as_bytes()));
    }
    encode_short_tlv(TAG_SEQUENCE, &inner)
}

/// Generates a fresh 2048-bit RSA keypair.
pub(crate) fn make_keypair() -> PKey<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

/// Builds a self-signed X.509 v3 leaf cert with the given (OID, DER value)
/// extensions appended verbatim.
pub(crate) fn build_cert(extensions: &[(&str, Vec<u8>)]) -> X509 {
    let pkey = make_keypair();
    let mut nb = X509Name::builder().unwrap();
    nb.append_entry_by_text("CN", "test-leaf").unwrap();
    let name = nb.build();

    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        Asn1Integer::from_bn(&bn).unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    for (oid, value) in extensions {
        let oid_obj = Asn1Object::from_str(oid).unwrap();
        let octet = Asn1OctetString::new_from_bytes(value).unwrap();
        let ext = X509Extension::new_from_der(&oid_obj, false, &octet).unwrap();
        b.append_extension(ext).unwrap();
    }
    // SubjectKeyIdentifier is required by `CertClaims::from_cert`; compute it
    // from the cert's public key context and append before signing.
    let ski = {
        let ctx = b.x509v3_context(None, None);
        SubjectKeyIdentifier::new().build(&ctx).unwrap()
    };
    b.append_extension(ski).unwrap();
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    b.build()
}

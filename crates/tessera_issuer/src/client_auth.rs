//! Unsigned, fixed client-authentication certificate profile.
//!
//! The caller supplies an independently derived URI and trusted issuer context.
//! CSR subjects and requested extensions never supply identity or permissions.
//! This module signs nothing and validates no enrollment plan or trust chain.
//! It is separate from the existing engineer shift-leaf profile.

use std::collections::BTreeSet;

use der::{Decode, Encode};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use tessera_ext::der::{
    encode_oid, encode_tlv, oid_to_dotted, read_tlv_expect, TAG_BIT_STRING, TAG_BOOLEAN,
    TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};
use tessera_ext::ext::{extract_basic_constraints, extract_extension_value};
use x509_cert::request::CertReq;

use crate::{csr::Csr, serial::Serial, sign::SignatureAlgorithm, tbs, IssueError, Validity};

/// Maximum exact DER CSR size, before parsing or allocating its attributes.
pub const MAX_CSR_BYTES: usize = 16 * 1024;
/// Maximum public issuer certificate or TBS size.
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Maximum caller-derived URI, in ASCII bytes.
pub const MAX_URI_BYTES: usize = 256;
const SAN_OID: &str = "2.5.29.17";
const CLIENT_AUTH_OID: &str = "1.3.6.1.5.5.7.3.2";
const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";

/// Rejection before any signing operation exists.
#[derive(Debug, thiserror::Error)]
pub enum ClientAuthError {
    /// Input exceeded a bounded parser budget.
    #[error("client-auth input exceeds size limit: {0}")]
    Oversize(&'static str),
    /// Input does not meet this fixed profile.
    #[error("invalid client-auth profile input: {0}")]
    Invalid(&'static str),
    /// Existing CSR/DER/issuer primitive rejected input.
    #[error(transparent)]
    Issuer(#[from] IssueError),
}

/// Public inputs to deterministic unsigned preparation. No private key, clock,
/// randomness, signing backend or caller-selected extension set is accepted.
pub struct ClientAuthCsrTbsRequest<'a> {
    /// Exact DER PKCS#10 carrying a P-256 key and ECDSA/SHA-256 proof of possession.
    pub csr_der: &'a [u8],
    /// Identity URI derived by the caller from its protected context, not the CSR.
    pub subject_uri: &'a str,
    /// Another signing key that MUST differ from the CSR key, in P-256 SEC1 form.
    /// Compressed and uncompressed encodings are compared as actual curve points.
    pub distinct_from_sec1: &'a [u8],
    /// Public issuer certificate. Shape checks here do NOT establish its trust.
    pub issuer_certificate_der: &'a [u8],
    /// Exact window fixed by the caller before approval; no default lifetime.
    pub validity: Validity,
    /// Already allocated canonical serial; preparation never allocates another.
    pub serial: &'a Serial,
    /// Algorithm of the independently selected issuer key, not the CSR algorithm.
    pub signature_algorithm: SignatureAlgorithm,
}

/// Immutable unsigned output. Neither an issued credential nor approved authority.
#[derive(Debug, Clone)]
pub struct PreparedClientAuthTbs {
    tbs_der: Vec<u8>,
    csr_sha256: [u8; 32],
    subject_spki_der: Vec<u8>,
    subject_uri: String,
    issuer_sha256: [u8; 32],
}

impl PreparedClientAuthTbs {
    /// Exact bytes to bind to an approval and, separately, a signing operation.
    #[must_use]
    pub fn tbs_der(&self) -> &[u8] {
        &self.tbs_der
    }
    /// SHA-256 of the exact CSR input, including its proof of possession.
    #[must_use]
    pub fn csr_sha256(&self) -> [u8; 32] {
        self.csr_sha256
    }
    /// Canonical uncompressed P-256 SPKI that the TBS carries.
    #[must_use]
    pub fn subject_spki_der(&self) -> &[u8] {
        &self.subject_spki_der
    }
    /// SHA-256 of the SPKI actually placed into the TBS.
    #[must_use]
    pub fn spki_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.subject_spki_der).into()
    }
    /// Caller-derived identity URI; never derived from CSR subject or attributes.
    #[must_use]
    pub fn subject_uri(&self) -> &str {
        &self.subject_uri
    }
    /// SHA-256 of the exact public issuer certificate supplied by the caller.
    #[must_use]
    pub fn issuer_sha256(&self) -> [u8; 32] {
        self.issuer_sha256
    }
    /// SHA-256 of the exact unsigned TBS.
    #[must_use]
    pub fn tbs_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.tbs_der).into()
    }
}

/// Prepare a fixed clientAuth-only, CA=false certificate TBS from a verified CSR.
///
/// The issuer is checked for CA/keyCertSign, matching public-key algorithm and
/// containing validity. No issuer signature, chain, revocation or caller plan
/// is verified here. Access CA critical extensions remain a separate TLS
/// verifier compatibility concern; this function does not ignore them on a path.
///
/// # Errors
/// Refuses oversize/non-DER/bad-PoP/non-P256 input, reused signing keys, invalid
/// URI/validity/issuer and anything outside the fixed profile.
pub fn prepare_client_auth_tbs(
    request: &ClientAuthCsrTbsRequest<'_>,
) -> Result<PreparedClientAuthTbs, ClientAuthError> {
    bound(request.csr_der, MAX_CSR_BYTES, "csr")?;
    bound(
        request.issuer_certificate_der,
        MAX_CERTIFICATE_BYTES,
        "issuer",
    )?;
    validate_uri(request.subject_uri)?;
    crate::check_validity(request.validity)?;
    // Strict DER only; the reusable Csr parser itself also supports PEM.
    let parsed =
        CertReq::from_der(request.csr_der).map_err(|_| ClientAuthError::Invalid("csr_der"))?;
    if parsed
        .to_der()
        .map_err(|_| ClientAuthError::Invalid("csr_der"))?
        != request.csr_der
    {
        return Err(ClientAuthError::Invalid("noncanonical_csr_der"));
    }
    if parsed.algorithm.oid.to_string() != ECDSA_SHA256_OID
        || parsed.algorithm.parameters.is_some()
        || parsed.signature.has_unused_bits()
        || parsed.info.public_key.subject_public_key.has_unused_bits()
    {
        return Err(ClientAuthError::Invalid("csr_signature_algorithm"));
    }
    let csr = Csr::parse(request.csr_der)?;
    let public = p256::PublicKey::from_public_key_der(csr.subject_spki_der())
        .map_err(|_| ClientAuthError::Invalid("csr_p256_key"))?;
    csr.verify_proof_of_possession()?;
    if !matches!(request.distinct_from_sec1.len(), 33 | 65) {
        return Err(ClientAuthError::Invalid("distinct_signing_key"));
    }
    let other = p256::PublicKey::from_sec1_bytes(request.distinct_from_sec1)
        .map_err(|_| ClientAuthError::Invalid("distinct_signing_key"))?;
    if public == other {
        return Err(ClientAuthError::Invalid("reused_signing_key"));
    }
    let spki = public
        .to_public_key_der()
        .map_err(|_| ClientAuthError::Invalid("csr_spki"))?;
    let parent = issuer_parts(request.issuer_certificate_der)?;
    if request.validity.not_before < parent.validity.not_before
        || request.validity.not_after > parent.validity.not_after
    {
        return Err(ClientAuthError::Invalid("validity_outside_issuer"));
    }
    check_issuer_algorithm(&parent.spki, request.signature_algorithm)?;
    let algorithm = tbs::algorithm_identifier_der(request.signature_algorithm)?;
    let validity = tbs::validity_der(&request.validity)?;
    let extensions = extensions(request.subject_uri)?;
    let tbs_der = tbs::assemble_tbs(
        request.serial,
        &algorithm,
        &parent.subject,
        &validity,
        &[0x30, 0],
        spki.as_bytes(),
        &extensions,
    );
    validate_client_auth_tbs(&tbs_der)?;
    Ok(PreparedClientAuthTbs {
        tbs_der,
        csr_sha256: Sha256::digest(request.csr_der).into(),
        subject_spki_der: spki.as_bytes().to_vec(),
        subject_uri: request.subject_uri.to_owned(),
        issuer_sha256: Sha256::digest(request.issuer_certificate_der).into(),
    })
}

/// Reparse an unsigned TBS and enforce the complete fixed leaf profile.
///
/// Does not establish who selected its URI, whether its issuer is trusted, or
/// whether a signing/activation decision exists. Compare exact bytes to the
/// independently prepared TBS as a separate step.
///
/// # Errors
/// Any malformed or extra field/extension, noncanonical key, invalid URI/window
/// or signature-algorithm shape rejects the whole object.
pub fn validate_client_auth_tbs(bytes: &[u8]) -> Result<(), ClientAuthError> {
    bound(bytes, MAX_CERTIFICATE_BYTES, "tbs")?;
    let parsed = x509_cert::TbsCertificate::from_der(bytes)
        .map_err(|_| ClientAuthError::Invalid("tbs_der"))?;
    if parsed
        .to_der()
        .map_err(|_| ClientAuthError::Invalid("tbs_der"))?
        != bytes
    {
        return Err(ClientAuthError::Invalid("noncanonical_tbs_der"));
    }
    let serial_der = parsed
        .serial_number
        .to_der()
        .map_err(|_| ClientAuthError::Invalid("serial"))?;
    der::asn1::UintRef::from_der(&serial_der).map_err(|_| ClientAuthError::Invalid("serial"))?;
    let serial_content = contents(&serial_der, TAG_INTEGER)?;
    if serial_content.len() > 20 || serial_content.iter().all(|b| *b == 0) {
        return Err(ClientAuthError::Invalid("serial"));
    }
    if parsed.version != x509_cert::certificate::Version::V3
        || !parsed.subject.0.is_empty()
        || parsed.issuer.0.is_empty()
        || parsed.issuer_unique_id.is_some()
        || parsed.subject_unique_id.is_some()
    {
        return Err(ClientAuthError::Invalid("tbs_fields"));
    }
    let allowed = [
        SignatureAlgorithm::EcdsaWithSha256,
        SignatureAlgorithm::EcdsaWithSha384,
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::RsaPkcs1Sha256,
    ];
    if !allowed
        .iter()
        .any(|a| a.algorithm_identifier() == parsed.signature)
    {
        return Err(ClientAuthError::Invalid("signature_algorithm"));
    }
    crate::check_validity(window(parsed.validity))?;
    let spki_der = parsed
        .subject_public_key_info
        .to_der()
        .map_err(|_| ClientAuthError::Invalid("spki"))?;
    let public = p256::PublicKey::from_public_key_der(&spki_der)
        .map_err(|_| ClientAuthError::Invalid("p256_key"))?;
    if public
        .to_public_key_der()
        .map_err(|_| ClientAuthError::Invalid("spki"))?
        .as_bytes()
        != spki_der
    {
        return Err(ClientAuthError::Invalid("noncanonical_spki"));
    }
    let ext = parsed
        .extensions
        .ok_or(ClientAuthError::Invalid("extensions"))?;
    if ext.len() != 4 {
        return Err(ClientAuthError::Invalid("extensions"));
    }
    let san = ext.get(3).ok_or(ClientAuthError::Invalid("san"))?;
    if san.extn_id.to_string() != SAN_OID {
        return Err(ClientAuthError::Invalid("san"));
    }
    let mut names = sequence(san.extn_value.as_bytes())?;
    let uri = take(&mut names, 0x86)?;
    if !names.is_empty() {
        return Err(ClientAuthError::Invalid("multiple_sans"));
    }
    let uri =
        std::str::from_utf8(contents(uri, 0x86)?).map_err(|_| ClientAuthError::Invalid("uri"))?;
    validate_uri(uri)?;
    let mut actual = Vec::new();
    for item in &ext {
        actual.extend_from_slice(
            &item
                .to_der()
                .map_err(|_| ClientAuthError::Invalid("extension"))?,
        );
    }
    if actual != extensions(uri)? {
        return Err(ClientAuthError::Invalid("extension_profile"));
    }
    Ok(())
}

fn extensions(uri: &str) -> Result<Vec<u8>, ClientAuthError> {
    let mut out = Vec::new();
    for (oid, critical, value) in [
        ("2.5.29.19", true, vec![0x30, 0]),
        ("2.5.29.15", true, vec![0x03, 0x02, 0x07, 0x80]),
        (
            "2.5.29.37",
            false,
            encode_tlv(
                TAG_SEQUENCE,
                &encode_tlv(
                    TAG_OID,
                    &encode_oid(CLIENT_AUTH_OID).map_err(IssueError::from)?,
                ),
            ),
        ),
        (
            SAN_OID,
            true,
            encode_tlv(TAG_SEQUENCE, &encode_tlv(0x86, uri.as_bytes())),
        ),
    ] {
        out.extend_from_slice(&tbs::encode_extension(oid, critical, &value)?);
    }
    Ok(out)
}

fn bound(bytes: &[u8], maximum: usize, name: &'static str) -> Result<(), ClientAuthError> {
    if bytes.len() > maximum {
        Err(ClientAuthError::Oversize(name))
    } else {
        Ok(())
    }
}

fn validate_uri(uri: &str) -> Result<(), ClientAuthError> {
    let (scheme, rest) = uri.split_once(':').ok_or(ClientAuthError::Invalid("uri"))?;
    if uri.len() > MAX_URI_BYTES
        || rest.is_empty()
        || !uri.is_ascii()
        || !scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        || uri
            .bytes()
            .any(|b| !b.is_ascii_graphic() || b"\"<>\\^`{|}".contains(&b))
    {
        return Err(ClientAuthError::Invalid("uri"));
    }
    let mut bytes = uri.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && !(bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                && bytes.next().is_some_and(|b| b.is_ascii_hexdigit()))
        {
            return Err(ClientAuthError::Invalid("uri_percent_encoding"));
        }
    }
    Ok(())
}

struct IssuerParts {
    subject: Vec<u8>,
    spki: Vec<u8>,
    validity: Validity,
}

// The issuing CA may have wide Tessera extension OIDs. Parse its standard fields
// strictly while keeping the existing wide-OID extension codec; do not claim
// that this shape check is a TLS path validator or that it ignores criticals.
fn issuer_parts(bytes: &[u8]) -> Result<IssuerParts, ClientAuthError> {
    let mut outer = sequence(bytes)?;
    let tbs = take(&mut outer, TAG_SEQUENCE)?;
    let outer_algorithm = take(&mut outer, TAG_SEQUENCE)?;
    let signature = der::asn1::BitStringRef::from_der(take(&mut outer, TAG_BIT_STRING)?)
        .map_err(|_| ClientAuthError::Invalid("issuer_signature"))?;
    if !outer.is_empty() || signature.is_empty() || signature.has_unused_bits() {
        return Err(ClientAuthError::Invalid("issuer_der"));
    }
    let mut fields = sequence(tbs)?;
    let version = take(&mut fields, 0xA0)?;
    if u8::from_der(contents(version, 0xA0)?).ok() != Some(2) {
        return Err(ClientAuthError::Invalid("issuer_version"));
    }
    der::asn1::UintRef::from_der(take(&mut fields, TAG_INTEGER)?)
        .map_err(|_| ClientAuthError::Invalid("issuer_serial"))?;
    let algorithm = take(&mut fields, TAG_SEQUENCE)?;
    AlgorithmIdentifierOwned::from_der(algorithm)
        .map_err(|_| ClientAuthError::Invalid("issuer_algorithm"))?;
    if algorithm != outer_algorithm {
        return Err(ClientAuthError::Invalid("issuer_algorithm"));
    }
    x509_cert::name::Name::from_der(take(&mut fields, TAG_SEQUENCE)?)
        .map_err(|_| ClientAuthError::Invalid("issuer_name"))?;
    let validity = x509_cert::time::Validity::from_der(take(&mut fields, TAG_SEQUENCE)?)
        .map_err(|_| ClientAuthError::Invalid("issuer_validity"))?;
    let subject = take(&mut fields, TAG_SEQUENCE)?.to_vec();
    if x509_cert::name::Name::from_der(&subject)
        .map_err(|_| ClientAuthError::Invalid("issuer_subject"))?
        .0
        .is_empty()
    {
        return Err(ClientAuthError::Invalid("issuer_subject"));
    }
    let spki = take(&mut fields, TAG_SEQUENCE)?.to_vec();
    let ext = take(&mut fields, 0xA3)?;
    if !fields.is_empty() {
        return Err(ClientAuthError::Invalid("issuer_fields"));
    }
    unique_extensions(contents(ext, 0xA3)?)?;
    if !extract_basic_constraints(bytes)
        .map_err(IssueError::from)?
        .is_some_and(|bc| bc.ca)
    {
        return Err(ClientAuthError::Invalid("issuer_not_ca"));
    }
    let ku = extract_extension_value(bytes, "2.5.29.15")
        .map_err(IssueError::from)?
        .ok_or(ClientAuthError::Invalid("issuer_key_usage"))?;
    let ku = der::asn1::BitStringRef::from_der(&ku)
        .map_err(|_| ClientAuthError::Invalid("issuer_key_usage"))?;
    let padding = (1_u8 << ku.unused_bits()).saturating_sub(1);
    if ku.bits().nth(5) != Some(true)
        || ku.raw_bytes().last().is_none_or(|byte| byte & padding != 0)
    {
        return Err(ClientAuthError::Invalid("issuer_key_cert_sign"));
    }
    Ok(IssuerParts {
        subject,
        spki,
        validity: window(validity),
    })
}

fn unique_extensions(bytes: &[u8]) -> Result<(), ClientAuthError> {
    let mut extensions = sequence(bytes)?;
    let mut seen = BTreeSet::new();
    while !extensions.is_empty() {
        if seen.len() >= 64 {
            return Err(ClientAuthError::Invalid("issuer_extension_count"));
        }
        let mut fields = sequence(take(&mut extensions, TAG_SEQUENCE)?)?;
        let oid_bytes = contents(take(&mut fields, TAG_OID)?, TAG_OID)?;
        let oid = oid_to_dotted(oid_bytes).map_err(IssueError::from)?;
        if encode_oid(&oid).map_err(IssueError::from)? != oid_bytes {
            return Err(ClientAuthError::Invalid("issuer_oid_encoding"));
        }
        if !seen.insert(oid) {
            return Err(ClientAuthError::Invalid("duplicate_issuer_extension"));
        }
        if fields.first() == Some(&TAG_BOOLEAN)
            && !bool::from_der(take(&mut fields, TAG_BOOLEAN)?)
                .map_err(|_| ClientAuthError::Invalid("issuer_critical"))?
        {
            return Err(ClientAuthError::Invalid("default_issuer_critical"));
        }
        take(&mut fields, TAG_OCTET_STRING)?;
        if !fields.is_empty() {
            return Err(ClientAuthError::Invalid("issuer_extension"));
        }
    }
    Ok(())
}

fn check_issuer_algorithm(
    spki: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<(), ClientAuthError> {
    let valid = match algorithm {
        SignatureAlgorithm::EcdsaWithSha256 => p256::PublicKey::from_public_key_der(spki).is_ok(),
        SignatureAlgorithm::EcdsaWithSha384 => p384::PublicKey::from_public_key_der(spki).is_ok(),
        SignatureAlgorithm::RsaPkcs1Sha256 => {
            use rsa::pkcs8::DecodePublicKey as _;
            use rsa::traits::PublicKeyParts;
            rsa::RsaPublicKey::from_public_key_der(spki).is_ok_and(|key| key.n().bits() >= 2048)
        }
        SignatureAlgorithm::Ed25519 => {
            spki::SubjectPublicKeyInfoOwned::from_der(spki).is_ok_and(|key| {
                key.algorithm.oid.to_string() == "1.3.101.112"
                    && key.algorithm.parameters.is_none()
                    && key
                        .subject_public_key
                        .as_bytes()
                        .is_some_and(|b| b.len() == 32)
            })
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ClientAuthError::Invalid("issuer_key_algorithm"))
    }
}

fn window(validity: x509_cert::time::Validity) -> Validity {
    Validity {
        not_before: validity.not_before.to_unix_duration().as_secs(),
        not_after: validity.not_after.to_unix_duration().as_secs(),
    }
}

fn sequence(bytes: &[u8]) -> Result<&[u8], ClientAuthError> {
    contents(bytes, TAG_SEQUENCE)
}
fn contents(bytes: &[u8], tag: u8) -> Result<&[u8], ClientAuthError> {
    der::AnyRef::from_der(bytes).map_err(|_| ClientAuthError::Invalid("der"))?;
    let value = read_tlv_expect(bytes, tag).map_err(IssueError::from)?;
    if !value.rest.is_empty() {
        return Err(ClientAuthError::Invalid("trailing_der"));
    }
    Ok(value.value)
}
fn take<'a>(rest: &mut &'a [u8], tag: u8) -> Result<&'a [u8], ClientAuthError> {
    let value = read_tlv_expect(rest, tag).map_err(IssueError::from)?;
    let length = rest
        .len()
        .checked_sub(value.rest.len())
        .ok_or(ClientAuthError::Invalid("der"))?;
    let encoded = rest.get(..length).ok_or(ClientAuthError::Invalid("der"))?;
    der::AnyRef::from_der(encoded).map_err(|_| ClientAuthError::Invalid("der"))?;
    *rest = value.rest;
    Ok(encoded)
}

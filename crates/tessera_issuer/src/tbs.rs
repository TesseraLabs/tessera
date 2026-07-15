//! Hand-assembly of the `TBSCertificate` and enclosing `Certificate`.
//!
//! A Tessera certificate carries the project's `2.25.<UUID>` extension OIDs,
//! whose single arc is ~128 bits wide — beyond what the `RustCrypto` `const-oid`
//! parser (32-bit arcs) can represent. So the extension block and the outer
//! `SEQUENCE` framing are built byte-for-byte with [`tessera_ext`]'s DER writer,
//! while the standard components that need no wide OID — the subject `Name`, the
//! `Validity`, and the `SubjectPublicKeyInfo` re-canonicalisation — are encoded
//! by `x509-cert`/`spki` and spliced in.

use core::time::Duration;
use std::str::FromStr;

use der::asn1::{GeneralizedTime, UtcTime};
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::name::Name;
use x509_cert::time::{Time, Validity as X509Validity};

use tessera_ext::der::{
    encode_oid, encode_tlv, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};
use tessera_ext::ext::{
    encode_max_integrity, encode_profile_version, encode_seq_of_utf8, BASIC_CONSTRAINTS_OID,
};
use tessera_ext::oids::{
    ALLOWED_ROLES_OID, DELEGATION_CONSTRAINTS_OID, HOST_BINDING_OID, MAX_INTEGRITY_OID,
    PROFILE_VERSION_OID, USER_BINDING_OID,
};

use crate::error::IssueError;
use crate::profile::{CaRequest, LeafRequest, Validity};
use crate::serial::Serial;
use crate::sign::SignatureAlgorithm;

/// The standard `keyUsage` extension OID.
const KEY_USAGE_OID: &str = "2.5.29.15";

/// `keyUsage` `extnValue` asserting `keyCertSign | cRLSign` — a `BIT STRING`
/// with one unused bit and the two high named bits set (`0x06`).
const KEY_USAGE_CERT_AND_CRL_SIGN: [u8; 4] = [0x03, 0x02, 0x01, 0x06];

/// Encodes one `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT
/// FALSE, extnValue OCTET STRING }`.
///
/// `critical` is emitted only when `true` (DER forbids encoding the default).
fn encode_extension(oid: &str, critical: bool, extn_value: &[u8]) -> Result<Vec<u8>, IssueError> {
    let oid_content = encode_oid(oid)?;
    let mut inner = encode_tlv(TAG_OID, &oid_content);
    if critical {
        inner.extend_from_slice(&encode_tlv(TAG_BOOLEAN, &[0xFF]));
    }
    inner.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, extn_value));
    Ok(encode_tlv(TAG_SEQUENCE, &inner))
}

/// Builds the concatenated `Extension` elements for a shift-leaf: `basic
/// Constraints` (cA=FALSE, critical), host/user binding, allowed-roles,
/// `profile_version` (critical), and the optional `max_integrity`.
pub(crate) fn leaf_extensions(req: &LeafRequest) -> Result<Vec<u8>, IssueError> {
    let mut out = Vec::new();
    // basicConstraints cA=FALSE: the default is omitted, so the value is an
    // empty SEQUENCE. Critical, per the standard.
    out.extend_from_slice(&encode_extension(
        BASIC_CONSTRAINTS_OID,
        true,
        &encode_tlv(TAG_SEQUENCE, &[]),
    )?);
    out.extend_from_slice(&encode_extension(
        HOST_BINDING_OID,
        false,
        &encode_seq_of_utf8(&req.host_binding),
    )?);
    out.extend_from_slice(&encode_extension(
        USER_BINDING_OID,
        false,
        &encode_seq_of_utf8(&req.user_binding),
    )?);
    out.extend_from_slice(&encode_extension(
        ALLOWED_ROLES_OID,
        false,
        &encode_seq_of_utf8(&req.allowed_roles),
    )?);
    out.extend_from_slice(&encode_extension(
        PROFILE_VERSION_OID,
        true,
        &encode_profile_version(req.profile_version),
    )?);
    if let Some(ceiling) = req.max_integrity {
        out.extend_from_slice(&encode_extension(
            MAX_INTEGRITY_OID,
            false,
            &encode_max_integrity(ceiling.level, ceiling.categories),
        )?);
    }
    Ok(out)
}

/// Builds the concatenated `Extension` elements for an organisation CA: `basic
/// Constraints` (cA=TRUE, critical), `keyUsage` (keyCertSign|cRLSign, critical),
/// the delegation envelope (critical), and `profile_version` (critical).
pub(crate) fn ca_extensions(req: &CaRequest) -> Result<Vec<u8>, IssueError> {
    let mut out = Vec::new();
    let basic_constraints = encode_tlv(TAG_SEQUENCE, &encode_tlv(TAG_BOOLEAN, &[0xFF]));
    out.extend_from_slice(&encode_extension(
        BASIC_CONSTRAINTS_OID,
        true,
        &basic_constraints,
    )?);
    out.extend_from_slice(&encode_extension(
        KEY_USAGE_OID,
        true,
        &KEY_USAGE_CERT_AND_CRL_SIGN,
    )?);
    out.extend_from_slice(&encode_extension(
        DELEGATION_CONSTRAINTS_OID,
        true,
        &tessera_ext::delegation::encode_constraints(&req.constraints),
    )?);
    out.extend_from_slice(&encode_extension(
        PROFILE_VERSION_OID,
        true,
        &encode_profile_version(req.profile_version),
    )?);
    Ok(out)
}

/// Encodes the signature `AlgorithmIdentifier` to DER.
pub(crate) fn algorithm_identifier_der(alg: SignatureAlgorithm) -> Result<Vec<u8>, IssueError> {
    Ok(alg.algorithm_identifier().to_der()?)
}

/// Encodes a subject distinguished name (RFC 4514) to a DER `Name`.
pub(crate) fn subject_name_der(dn: &str) -> Result<Vec<u8>, IssueError> {
    let name = Name::from_str(dn).map_err(|e| IssueError::InvalidSubject(e.to_string()))?;
    Ok(name.to_der()?)
}

/// The first Unix second that falls in year 2050 — the RFC 5280 boundary above
/// which `Time` must be a `GeneralizedTime` rather than a `UTCTime`.
const YEAR_2050_UNIX_SECS: u64 = 2_524_608_000;

/// Builds a `Time`, choosing `UTCTime` (through 2049) or `GeneralizedTime`
/// (2050 and later) per RFC 5280.
fn build_time(secs: u64) -> Result<Time, IssueError> {
    let duration = Duration::from_secs(secs);
    if secs < YEAR_2050_UNIX_SECS {
        Ok(Time::UtcTime(UtcTime::from_unix_duration(duration)?))
    } else {
        Ok(Time::GeneralTime(GeneralizedTime::from_unix_duration(
            duration,
        )?))
    }
}

/// Encodes a single `Time` (`UTCTime`/`GeneralizedTime`) to DER.
pub(crate) fn time_der(secs: u64) -> Result<Vec<u8>, IssueError> {
    Ok(build_time(secs)?.to_der()?)
}

/// Encodes a [`Validity`] window to DER.
pub(crate) fn validity_der(validity: &Validity) -> Result<Vec<u8>, IssueError> {
    let validity = X509Validity {
        not_before: build_time(validity.not_before)?,
        not_after: build_time(validity.not_after)?,
    };
    Ok(validity.to_der()?)
}

/// Validates and re-canonicalises a caller-supplied `SubjectPublicKeyInfo`.
pub(crate) fn validated_spki_der(spki_der: &[u8]) -> Result<Vec<u8>, IssueError> {
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| IssueError::InvalidSpki(e.to_string()))?;
    Ok(spki.to_der()?)
}

/// Concatenates the encoded `TBSCertificate` fields (v3) and wraps them in the
/// outer `SEQUENCE`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_tbs(
    serial: &Serial,
    algorithm_identifier_der: &[u8],
    issuer_der: &[u8],
    validity_der: &[u8],
    subject_der: &[u8],
    spki_der: &[u8],
    extensions_body: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    // version [0] EXPLICIT INTEGER 2 (v3).
    body.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
    body.extend_from_slice(&encode_tlv(TAG_INTEGER, serial.as_bytes()));
    body.extend_from_slice(algorithm_identifier_der);
    body.extend_from_slice(issuer_der);
    body.extend_from_slice(validity_der);
    body.extend_from_slice(subject_der);
    body.extend_from_slice(spki_der);
    // extensions [3] EXPLICIT SEQUENCE OF Extension.
    let ext_seq = encode_tlv(TAG_SEQUENCE, extensions_body);
    body.extend_from_slice(&encode_tlv(0xA3, &ext_seq));
    encode_tlv(TAG_SEQUENCE, &body)
}

/// Assembles the final `Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signatureValue }`.
pub(crate) fn assemble_certificate(
    tbs_der: &[u8],
    algorithm_identifier_der: &[u8],
    signature_bytes: &[u8],
) -> Vec<u8> {
    // signatureValue BIT STRING: one leading "unused bits" octet (always 0).
    let mut bit_string = Vec::with_capacity(signature_bytes.len() + 1);
    bit_string.push(0x00);
    bit_string.extend_from_slice(signature_bytes);
    let signature = encode_tlv(tessera_ext::der::TAG_BIT_STRING, &bit_string);

    let mut body =
        Vec::with_capacity(tbs_der.len() + algorithm_identifier_der.len() + signature.len());
    body.extend_from_slice(tbs_der);
    body.extend_from_slice(algorithm_identifier_der);
    body.extend_from_slice(&signature);
    encode_tlv(TAG_SEQUENCE, &body)
}

//! Certificate revocation lists: a client-side operation of the core.
//!
//! A CRL is signed by the same shared code path as a certificate — the core
//! builds the `TBSCertList`, checks the `crlNumber` is strictly monotone against
//! the last one the caller recorded, and hands the DER to the signing backend.
//! State (the last `crlNumber`) is the caller's; the core only enforces the
//! monotonicity rule (design decision D7).

use tessera_ext::der::{
    encode_oid, encode_tlv, TAG_ENUMERATED, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};
use tessera_ext::ext::extract_subject_der;

use crate::error::IssueError;
use crate::journal::{Journal, JournalStorage};
use crate::sign::{KeyId, SignatureBackend};
use crate::tbs::{algorithm_identifier_der, assemble_certificate, time_der};

/// The standard `cRLNumber` extension OID.
const CRL_NUMBER_OID: &str = "2.5.29.20";
/// The standard `cRLReason` CRL-entry extension OID.
const CRL_REASON_OID: &str = "2.5.29.21";

/// An RFC 5280 `CRLReason` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CrlReason {
    /// `unspecified (0)`.
    Unspecified,
    /// `keyCompromise (1)`.
    KeyCompromise,
    /// `cACompromise (2)`.
    CaCompromise,
    /// `affiliationChanged (3)`.
    AffiliationChanged,
    /// `superseded (4)`.
    Superseded,
    /// `cessationOfOperation (5)`.
    CessationOfOperation,
    /// `certificateHold (6)`.
    CertificateHold,
}

impl CrlReason {
    /// The `ENUMERATED` code for this reason.
    fn code(self) -> u8 {
        match self {
            CrlReason::Unspecified => 0,
            CrlReason::KeyCompromise => 1,
            CrlReason::CaCompromise => 2,
            CrlReason::AffiliationChanged => 3,
            CrlReason::Superseded => 4,
            CrlReason::CessationOfOperation => 5,
            CrlReason::CertificateHold => 6,
        }
    }
}

/// One revoked certificate entry.
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    /// The revoked certificate's serial, as DER `INTEGER` *content* octets
    /// (positive, big-endian) — the same bytes the issued serial carried.
    pub serial: Vec<u8>,
    /// Revocation timestamp, Unix seconds.
    pub revocation_date: u64,
    /// Optional revocation reason.
    pub reason: Option<CrlReason>,
}

/// A request to issue a CRL.
#[derive(Debug, Clone)]
pub struct CrlRequest {
    /// `thisUpdate`, Unix seconds.
    pub this_update: u64,
    /// `nextUpdate`, Unix seconds (optional but recommended).
    pub next_update: Option<u64>,
    /// The `crlNumber` for this issuance — must strictly exceed the last one.
    pub crl_number: u64,
    /// The revoked certificates.
    pub revoked: Vec<RevokedEntry>,
}

/// A signed CRL and the `crlNumber` it carried.
#[derive(Debug, Clone)]
pub struct IssuedCrl {
    /// The DER-encoded `CertificateList`.
    pub der: Vec<u8>,
    /// The `crlNumber` recorded in the CRL — feed this back as `last_crl_number`
    /// on the next issuance.
    pub crl_number: u64,
}

/// Issues a CRL signed by the CA whose certificate is `issuer_cert_der`.
///
/// `last_crl_number` is the highest `crlNumber` previously issued by this CA's
/// state (0 if none). The request's `crl_number` MUST strictly exceed it, or
/// issuance is rejected before signing. The issuance is journaled before the
/// CRL is returned (timestamped `now_unix`, Unix seconds); a failed journal
/// append withholds the CRL (fail-closed).
///
/// # Errors
///
/// [`IssueError::CrlNumberNotIncreasing`] on a non-monotone `crlNumber`, a
/// DER/sign error, or [`IssueError::Journal`] on a journal-append failure.
#[expect(
    clippy::too_many_arguments,
    reason = "CRL issuance threads the signer, key, issuer cert, request, last \
              crlNumber, and a journaling target and clock; each is a distinct \
              required input and grouping them would obscure the call"
)]
pub fn issue_crl<B: SignatureBackend, S: JournalStorage>(
    backend: &B,
    key_id: &KeyId,
    issuer_cert_der: &[u8],
    req: &CrlRequest,
    last_crl_number: u64,
    journal: &mut Journal<S>,
    now_unix: u64,
) -> Result<IssuedCrl, IssueError> {
    if req.crl_number <= last_crl_number {
        return Err(IssueError::CrlNumberNotIncreasing {
            proposed: req.crl_number,
            minimum: last_crl_number.saturating_add(1),
        });
    }

    let algorithm = backend.algorithm(key_id)?;
    let algid_der = algorithm_identifier_der(algorithm)?;
    let issuer_der = extract_subject_der(issuer_cert_der)?;

    let tbs = assemble_tbs_cert_list(&algid_der, &issuer_der, req)?;
    let signature = backend.sign(&tbs, key_id)?;
    if signature.algorithm != algorithm {
        return Err(IssueError::AlgorithmMismatch {
            declared: algorithm,
            returned: signature.algorithm,
        });
    }
    let der = assemble_certificate(&tbs, &algid_der, &signature.bytes);
    // Journal before releasing the artifact; a failed write withholds it.
    journal.record_crl(req.crl_number, issuer_cert_der, now_unix)?;
    Ok(IssuedCrl {
        der,
        crl_number: req.crl_number,
    })
}

/// Concatenates the `TBSCertList` (v2) fields and wraps them in a `SEQUENCE`.
fn assemble_tbs_cert_list(
    algid_der: &[u8],
    issuer_der: &[u8],
    req: &CrlRequest,
) -> Result<Vec<u8>, IssueError> {
    let mut body = Vec::new();
    // version v2 (INTEGER 1) — present because crlExtensions are used.
    body.extend_from_slice(&encode_tlv(TAG_INTEGER, &[0x01]));
    body.extend_from_slice(algid_der);
    body.extend_from_slice(issuer_der);
    body.extend_from_slice(&time_der(req.this_update)?);
    if let Some(next) = req.next_update {
        body.extend_from_slice(&time_der(next)?);
    }
    if !req.revoked.is_empty() {
        body.extend_from_slice(&encode_revoked_certificates(&req.revoked)?);
    }
    // crlExtensions [0] EXPLICIT SEQUENCE OF Extension { crlNumber }.
    let crl_ext_seq = encode_tlv(TAG_SEQUENCE, &encode_crl_number_extension(req.crl_number)?);
    body.extend_from_slice(&encode_tlv(0xA0, &crl_ext_seq));

    Ok(encode_tlv(TAG_SEQUENCE, &body))
}

/// Encodes the `revokedCertificates SEQUENCE OF SEQUENCE { serial, date,
/// entryExtensions? }`.
fn encode_revoked_certificates(revoked: &[RevokedEntry]) -> Result<Vec<u8>, IssueError> {
    let mut list = Vec::new();
    for entry in revoked {
        let mut fields = encode_tlv(TAG_INTEGER, &entry.serial);
        fields.extend_from_slice(&time_der(entry.revocation_date)?);
        if let Some(reason) = entry.reason {
            fields.extend_from_slice(&encode_reason_extension(reason)?);
        }
        list.extend_from_slice(&encode_tlv(TAG_SEQUENCE, &fields));
    }
    Ok(encode_tlv(TAG_SEQUENCE, &list))
}

/// Encodes the `crlEntryExtensions` block holding a single `cRLReason`.
fn encode_reason_extension(reason: CrlReason) -> Result<Vec<u8>, IssueError> {
    let reason_value = encode_tlv(TAG_ENUMERATED, &[reason.code()]);
    let extension = encode_extension(CRL_REASON_OID, &reason_value)?;
    Ok(encode_tlv(TAG_SEQUENCE, &extension))
}

/// Encodes the `cRLNumber` extension.
fn encode_crl_number_extension(number: u64) -> Result<Vec<u8>, IssueError> {
    let number_value = encode_tlv(TAG_INTEGER, &crl_number_content(number));
    encode_extension(CRL_NUMBER_OID, &number_value)
}

/// Minimal big-endian DER `INTEGER` content for a non-negative `crlNumber`.
fn crl_number_content(number: u64) -> Vec<u8> {
    let bytes = number.to_be_bytes();
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes.get(start..).unwrap_or(&[0]).to_vec();
    // A leading high bit would read as negative — prepend a zero sign octet.
    if content.first().copied().unwrap_or(0) & 0x80 != 0 {
        content.insert(0, 0x00);
    }
    content
}

/// Encodes one non-critical `Extension { extnID, extnValue }` (no `critical`
/// flag — both CRL extensions here default to non-critical).
fn encode_extension(oid: &str, extn_value: &[u8]) -> Result<Vec<u8>, IssueError> {
    let oid_content = encode_oid(oid)?;
    let mut inner = encode_tlv(TAG_OID, &oid_content);
    inner.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, extn_value));
    Ok(encode_tlv(TAG_SEQUENCE, &inner))
}

//! The JSON request and response shapes of the bindings.
//!
//! Every binding takes one JSON string and returns one JSON string; these are
//! the `serde` structs behind those strings. The single cross-boundary
//! convention is: **all binary values are standard, padded Base64 strings**
//! (fields suffixed `_b64`), and everything else is plain JSON. Certificates and
//! CSRs accepted as input may be either PEM text or DER — both are Base64-encoded
//! as raw file bytes; the binding decodes the PEM wrapper when present.

use serde::{Deserialize, Serialize};

// --- inspect_parent ---------------------------------------------------------

/// Input to `inspect_parent`.
#[derive(Debug, Deserialize)]
pub(crate) struct InspectParentInput {
    /// Base64 of the parent certificate file bytes (PEM or DER).
    pub cert_b64: String,
}

/// A delegation envelope, mirrored from the core's `DelegationConstraints`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EnvelopeJson {
    /// Conjunctive `key=value` tag requirements.
    pub require_tags: Vec<(String, String)>,
    /// Roles a certificate beneath this envelope may allow.
    pub allow_roles: Vec<String>,
    /// Integrity-level ceiling (Astra МКЦ linear level).
    pub max_level: i8,
    /// Session-TTL ceiling, seconds.
    pub max_ttl: u64,
}

/// Output of `inspect_parent`.
#[derive(Debug, Serialize)]
pub(crate) struct InspectParentResponse {
    /// `root` (issue org CAs), `org_ca` (issue leaves), `leaf`, or `unusable`.
    pub kind: String,
    /// The certificate subject (RFC 4514), empty when unreadable.
    pub subject: String,
    /// The delegation envelope the parent carries, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<EnvelopeJson>,
    /// Why the parent is `unusable`, when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// --- shared request fragments -----------------------------------------------

/// A validity window, Unix seconds.
#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) struct ValidityJson {
    /// `notBefore`.
    pub not_before: u64,
    /// `notAfter`.
    pub not_after: u64,
}

/// An optional leaf integrity ceiling.
#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) struct IntegrityJson {
    /// Astra МКЦ linear integrity level.
    pub level: i8,
    /// Category bitmask.
    pub categories: u64,
}

// --- build_leaf_tbs ---------------------------------------------------------

/// The leaf-issuance request the operator fills in.
///
/// Exactly one of `spki_b64` or `csr_b64` supplies the leaf's public key. With
/// `spki_b64`, `subject` is required; with `csr_b64`, the subject and key come
/// from the (proof-of-possession-verified) request and `subject` is ignored.
#[derive(Debug, Deserialize)]
pub(crate) struct LeafRequestJson {
    /// Subject DN (RFC 4514); required with `spki_b64`.
    #[serde(default)]
    pub subject: Option<String>,
    /// Base64 DER `SubjectPublicKeyInfo`.
    #[serde(default)]
    pub spki_b64: Option<String>,
    /// Base64 of a PKCS#10 CSR (PEM or DER).
    #[serde(default)]
    pub csr_b64: Option<String>,
    /// Validity window.
    pub validity: ValidityJson,
    /// Host descriptors bound by the leaf.
    pub host_binding: Vec<String>,
    /// User descriptors bound by the leaf.
    pub user_binding: Vec<String>,
    /// Roles the leaf may activate.
    pub allowed_roles: Vec<String>,
    /// Optional integrity ceiling.
    #[serde(default)]
    pub max_integrity: Option<IntegrityJson>,
    /// Certificate-format version.
    pub profile_version: u32,
}

/// Input to `build_leaf_tbs`.
#[derive(Debug, Deserialize)]
pub(crate) struct BuildLeafInput {
    /// Base64 of the parent CA certificate (PEM or DER).
    pub parent_b64: String,
    /// Signature algorithm the local agent will sign with (`ecdsa-p256`,
    /// `ecdsa-p384`, `rsa-sha256`, or `ed25519`).
    pub algorithm: String,
    /// Base64 of the serial-number entropy (16 bytes recommended), from the
    /// browser's CSPRNG.
    pub serial_entropy_b64: String,
    /// Summary locale (`en` or `ru`); defaults to English.
    #[serde(default)]
    pub locale: Option<String>,
    /// The leaf request.
    pub request: LeafRequestJson,
}

// --- build_ca_tbs -----------------------------------------------------------

/// The CA-issuance request the operator fills in.
#[derive(Debug, Deserialize)]
pub(crate) struct CaRequestJson {
    /// Subject DN (RFC 4514).
    pub subject: String,
    /// Base64 DER `SubjectPublicKeyInfo`.
    pub spki_b64: String,
    /// Validity window.
    pub validity: ValidityJson,
    /// The delegation envelope assigned to the new CA.
    pub constraints: EnvelopeJson,
    /// Certificate-format version.
    pub profile_version: u32,
}

/// Input to `build_ca_tbs`.
#[derive(Debug, Deserialize)]
pub(crate) struct BuildCaInput {
    /// Base64 of the parent certificate (PEM or DER).
    pub parent_b64: String,
    /// Signature algorithm the local agent will sign with.
    pub algorithm: String,
    /// Base64 of the serial-number entropy (16 bytes recommended).
    pub serial_entropy_b64: String,
    /// Summary locale (`en` or `ru`); defaults to English.
    #[serde(default)]
    pub locale: Option<String>,
    /// The CA request.
    pub request: CaRequestJson,
}

// --- build_crl_tbs ----------------------------------------------------------

/// One revoked-certificate entry.
#[derive(Debug, Deserialize)]
pub(crate) struct RevokedJson {
    /// Base64 of the revoked serial's DER `INTEGER` content octets.
    pub serial_b64: String,
    /// Revocation timestamp, Unix seconds.
    pub revocation_date: u64,
    /// Optional RFC 5280 reason code (0–6).
    #[serde(default)]
    pub reason: Option<u8>,
}

/// The CRL-issuance request.
#[derive(Debug, Deserialize)]
pub(crate) struct CrlRequestJson {
    /// `thisUpdate`, Unix seconds.
    pub this_update: u64,
    /// `nextUpdate`, Unix seconds (optional).
    #[serde(default)]
    pub next_update: Option<u64>,
    /// The `crlNumber` for this issuance (must exceed `last_crl_number`).
    pub crl_number: u64,
    /// The revoked certificates.
    pub revoked: Vec<RevokedJson>,
}

/// Input to `build_crl_tbs`.
#[derive(Debug, Deserialize)]
pub(crate) struct BuildCrlInput {
    /// Base64 of the issuing CA certificate (PEM or DER).
    pub issuer_b64: String,
    /// Signature algorithm the local agent will sign with.
    pub algorithm: String,
    /// Summary locale (`en` or `ru`); defaults to English.
    #[serde(default)]
    pub locale: Option<String>,
    /// The CRL request.
    pub request: CrlRequestJson,
    /// The highest `crlNumber` previously issued by this CA's state (0 if none).
    #[serde(default)]
    pub last_crl_number: u64,
}

// --- build_* responses ------------------------------------------------------

/// One rendered summary detail line.
#[derive(Debug, Serialize)]
pub(crate) struct SummaryLineJson {
    /// The localized field caption.
    pub label: String,
    /// The technical value (identical in every locale).
    pub value: String,
}

/// A localized, structured operation summary shown before signing.
#[derive(Debug, Serialize)]
pub(crate) struct SummaryJson {
    /// Stable operation-kind key: `shift_leaf`, `org_ca`, or `crl`.
    pub kind: String,
    /// The certificate subject or CRL issuer (RFC 4514).
    pub subject: String,
    /// Start of the validity window.
    pub not_before: String,
    /// End of the validity window.
    pub not_after: String,
    /// Detail lines (roles, bindings, envelope, `crlNumber`).
    pub lines: Vec<SummaryLineJson>,
    /// The full multi-line block, ready to display verbatim.
    pub rendered: String,
}

/// Output of the `build_*_tbs` bindings.
#[derive(Debug, Serialize)]
pub(crate) struct BuildTbsResponse {
    /// Base64 of the built `TBSCertificate`/`TBSCertList` to send to the agent.
    pub tbs_b64: String,
    /// The operation summary to show the operator before signing.
    pub summary: SummaryJson,
}

// --- inspect_csr ------------------------------------------------------------

/// Input to `inspect_csr`.
#[derive(Debug, Deserialize)]
pub(crate) struct InspectCsrInput {
    /// Base64 of the CSR file bytes (PEM or DER).
    pub csr_b64: String,
}

/// One extension a CSR requested (advisory; never shapes issuance).
#[derive(Debug, Serialize)]
pub(crate) struct RequestedExtensionJson {
    /// The requested extension's OID (dotted decimal).
    pub oid: String,
    /// Whether the request marked it critical.
    pub critical: bool,
    /// Base64 of the requested `extnValue` (DER).
    pub value_b64: String,
}

/// The requested integrity ceiling, semantically decoded.
#[derive(Debug, Serialize)]
pub(crate) struct ParsedIntegrityJson {
    /// Astra МКЦ linear integrity level.
    pub level: i8,
    /// Category bitmask.
    pub categories: u64,
}

/// Semantically decoded *known* Tessera extensions from a CSR's requested
/// attributes, for labelled form prefill.
///
/// A field is present only when the matching extension was requested **and**
/// decoded cleanly with the shared [`tessera_ext`] parsers; an unrecognized or
/// malformed extension is left out here (it still appears in the raw
/// `requested_extensions`). None of this influences issuance — the operator sets
/// the scope.
#[derive(Debug, Default, Serialize)]
pub(crate) struct RequestedParsedJson {
    /// Roles the CSR asked its leaf to allow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_roles: Option<Vec<String>>,
    /// Host descriptors the CSR asked to bind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_binding: Option<Vec<String>>,
    /// User descriptors the CSR asked to bind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_binding: Option<Vec<String>>,
    /// The integrity ceiling the CSR asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_integrity: Option<ParsedIntegrityJson>,
    /// The certificate-format version the CSR asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_version: Option<u32>,
}

/// Output of `inspect_csr`.
#[derive(Debug, Serialize)]
pub(crate) struct InspectCsrResponse {
    /// The CSR subject (RFC 4514).
    pub subject: String,
    /// Whether the self-signature verifies (proof of possession).
    pub signature_valid: bool,
    /// Base64 DER of the CSR's `SubjectPublicKeyInfo`.
    pub spki_b64: String,
    /// Every extension the CSR requested, raw (including unrecognized and
    /// malformed ones), for reference.
    pub requested_extensions: Vec<RequestedExtensionJson>,
    /// The known Tessera extensions among them, semantically decoded for prefill.
    pub requested_parsed: RequestedParsedJson,
}

// --- assemble_and_verify ----------------------------------------------------

/// The signature returned by the local agent.
#[derive(Debug, Deserialize)]
pub(crate) struct SignatureJson {
    /// The algorithm the agent signed with (must match the TBS).
    pub algorithm: String,
    /// Base64 of the raw signature octets.
    pub bytes_b64: String,
}

/// Input to `assemble_and_verify`.
#[derive(Debug, Deserialize)]
pub(crate) struct AssembleInput {
    /// Base64 of the exact TBS the agent signed.
    pub tbs_b64: String,
    /// The agent's signature.
    pub signature: SignatureJson,
    /// Base64 of the parent certificate (PEM or DER), for the self-check.
    pub parent_b64: String,
}

/// Output of `assemble_and_verify`.
#[derive(Debug, Serialize)]
pub(crate) struct AssembleResponse {
    /// The assembled, self-checked artifact as PEM (a certificate, or a CRL when
    /// `kind` is `crl`), ready to hand to the operator for download.
    pub cert_pem: String,
    /// Base64 DER of the same artifact.
    pub cert_b64: String,
    /// The artifact kind: `shift_leaf`, `org_ca`, or `crl`.
    pub kind: String,
}

// --- journal ----------------------------------------------------------------

/// The operation a journal entry records. Tagged by `op`; binary values are
/// Base64.
#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
pub(crate) enum JournalEntryJson {
    /// A shift-leaf issuance.
    #[serde(rename = "issue_leaf")]
    Leaf {
        /// Base64 of the serial's DER `INTEGER` content octets.
        serial_b64: String,
        /// Base64 of the parent certificate DER.
        parent_b64: String,
        /// The issued certificate's subject (RFC 4514).
        subject: String,
    },
    /// An organisation-CA issuance.
    #[serde(rename = "issue_ca")]
    Ca {
        /// Base64 of the serial's DER `INTEGER` content octets.
        serial_b64: String,
        /// Base64 of the parent certificate DER.
        parent_b64: String,
        /// The issued certificate's subject (RFC 4514).
        subject: String,
    },
    /// A CRL issuance.
    #[serde(rename = "issue_crl")]
    Crl {
        /// The `crlNumber` the CRL carried.
        crl_number: u64,
        /// Base64 of the issuing CA certificate DER.
        parent_b64: String,
    },
}

/// Input to `journal_append`.
#[derive(Debug, Deserialize)]
pub(crate) struct JournalAppendInput {
    /// The existing journal lines (NDJSON, in append order); the browser holds
    /// these as the journal file.
    pub prev_lines: Vec<String>,
    /// The operation to record.
    pub entry: JournalEntryJson,
    /// Issuance time, Unix seconds (from the JS layer).
    pub now_unix: u64,
}

/// Output of `journal_append`.
#[derive(Debug, Serialize)]
pub(crate) struct JournalAppendResponse {
    /// The single new NDJSON line to append to the journal file.
    pub new_line: String,
}

/// Input to `journal_verify`.
#[derive(Debug, Deserialize)]
pub(crate) struct JournalVerifyInput {
    /// The journal lines (NDJSON, in append order) to verify.
    pub lines: Vec<String>,
}

/// Output of `journal_verify`.
#[derive(Debug, Serialize)]
pub(crate) struct JournalVerifyResponse {
    /// `intact`, `intact_unsigned_tail`, or `broken`.
    pub status: String,
    /// Position of the first invalid entry, when `broken`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<u64>,
    /// The `seq` of the first unsigned record, when `intact_unsigned_tail`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_from_seq: Option<u64>,
    /// The number of lines examined.
    pub entry_count: u64,
    /// The `seq` of the last head-signature line, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_signed_seq: Option<u64>,
}

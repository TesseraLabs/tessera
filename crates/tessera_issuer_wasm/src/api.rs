//! The binding implementations: pure `&str` → `Result<String, String>` mappings
//! over the [`tessera_issuer`] core, with no `wasm-bindgen` in sight.
//!
//! Keeping the logic here (rather than in the `#[wasm_bindgen]` shells) makes it
//! ordinary Rust that the native test suite exercises directly — the WASM layer
//! is a one-line forward per export. Each function parses one JSON request,
//! drives the shared core, and renders one JSON response; a failure is the
//! JSON-encoded [`ApiError`] returned through `Err`.
//!
//! Signing never happens here. The two `build_*_tbs` functions run every core
//! check and emit the exact `TBS` bytes to be signed elsewhere; the JS layer
//! sends those to the local agent and feeds the returned signature back into
//! [`assemble_and_verify`], which frames and self-checks the final artifact.

use core::cell::RefCell;

use base64::Engine as _;
use der::{Decode as _, Encode as _};
use serde::de::DeserializeOwned;
use serde::Serialize;

use tessera_ext::delegation::{narrows, DelegationConstraints};
use tessera_ext::der::{
    encode_oid, oid_to_dotted, read_tlv, read_tlv_expect, DerError, TAG_BOOLEAN, TAG_INTEGER,
    TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
};
use tessera_ext::ext::{
    extract_basic_constraints, extract_extension_value, extract_issuer_der, extract_subject_der,
    parse_max_integrity, parse_profile_version, parse_seq_of_utf8,
};
use tessera_ext::oids::{
    ALLOWED_ROLES_OID, DELEGATION_CONSTRAINTS_OID, HOST_BINDING_OID, MAX_INTEGRITY_OID,
    PROFILE_VERSION_OID, USER_BINDING_OID,
};

use tessera_issuer::l10n::Locale;
use tessera_issuer::monotonicity::parent_constraints;
use tessera_issuer::{
    assemble_signed_certificate, issue_ca, issue_crl, issue_leaf, issue_leaf_from_csr,
    parse_operation_summary, verify_lines, CaRequest, CrlReason, CrlRequest, Csr, IntegrityCeiling,
    Journal, JournalError, JournalStatus, JournalStorage, KeyId, LeafRequest, LeafRequestFromCsr,
    LeafScope, OperationKind, RevokedEntry, Serial, SignError, Signature, SignatureAlgorithm,
    SignatureBackend, Validity,
};

use crate::error::ApiError;
use crate::types::{
    AssembleInput, AssembleResponse, BuildCaInput, BuildCrlInput, BuildLeafInput, BuildTbsResponse,
    CaRequestJson, CrlRequestJson, EnvelopeJson, InspectCsrInput, InspectCsrResponse,
    InspectParentInput, InspectParentResponse, IntegrityJson, JournalAppendInput,
    JournalAppendResponse, JournalEntryJson, JournalVerifyInput, JournalVerifyResponse,
    ParsedIntegrityJson, RequestedExtensionJson, RequestedParsedJson, SummaryJson, SummaryLineJson,
    ValidityJson,
};

/// The standard `keyUsage` extension OID (asserted on every CA).
const KEY_USAGE_OID: &str = "2.5.29.15";
/// PKCS#9 `extensionRequest` attribute OID — the CSR's requested-extensions
/// carrier.
const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";
/// DER tag for `[0] IMPLICIT` — the CSR `attributes` wrapper.
const TAG_CONTEXT_0: u8 = 0xA0;
/// DER tag for `SET`/`SET OF`.
const TAG_SET: u8 = 0x31;
/// The opaque key handle the capturing backend answers to; a real key never
/// enters the WASM core.
const CABINET_KEY: &str = "cabinet";

// --- boundary plumbing ------------------------------------------------------

/// Serialise a binding's typed result into the JSON strings that cross the
/// boundary: the payload on success, the [`ApiError`] JSON on failure.
fn finish<T: Serialize>(result: Result<T, ApiError>) -> Result<String, String> {
    match result {
        Ok(value) => serde_json::to_string(&value).map_err(|e| {
            ApiError::msg(format!("internal: response serialisation failed: {e}")).to_json()
        }),
        Err(err) => Err(err.to_json()),
    }
}

/// Parse one JSON request, mapping a malformed body to an [`ApiError`].
fn parse_input<T: DeserializeOwned>(input: &str) -> Result<T, ApiError> {
    serde_json::from_str(input).map_err(|e| ApiError::msg(format!("invalid request JSON: {e}")))
}

/// Standard, padded Base64 decode.
fn b64_decode(value: &str) -> Result<Vec<u8>, ApiError> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| ApiError::msg(format!("invalid base64: {e}")))
}

/// Standard, padded Base64 encode.
fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Return the certificate/CSR DER, decoding a PEM wrapper when the bytes begin
/// (after whitespace) with `-`; otherwise pass the DER through unchanged.
fn pem_or_der(bytes: &[u8]) -> Result<Vec<u8>, ApiError> {
    let looks_pem = bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|&byte| byte == b'-');
    if !looks_pem {
        return Ok(bytes.to_vec());
    }
    let text = core::str::from_utf8(bytes).map_err(|_| ApiError::msg("PEM is not UTF-8"))?;
    let mut body = String::new();
    let mut in_body = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_body = true;
        } else if trimmed.starts_with("-----END") {
            break;
        } else if in_body {
            body.push_str(trimmed);
        }
    }
    if body.is_empty() {
        return Err(ApiError::msg("no PEM body found"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| ApiError::msg(format!("PEM base64: {e}")))
}

/// PEM-encode DER under `label`, wrapping the Base64 body at 64 columns.
fn encode_pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // The Base64 alphabet is ASCII, so every chunk is valid UTF-8.
        out.push_str(core::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Map an algorithm tag to a [`SignatureAlgorithm`].
fn parse_algorithm(value: &str) -> Result<SignatureAlgorithm, ApiError> {
    match value {
        "ecdsa-p256" => Ok(SignatureAlgorithm::EcdsaWithSha256),
        "ecdsa-p384" => Ok(SignatureAlgorithm::EcdsaWithSha384),
        "rsa-sha256" => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
        "ed25519" => Ok(SignatureAlgorithm::Ed25519),
        other => Err(ApiError::msg(format!(
            "unknown signature algorithm `{other}`"
        ))),
    }
}

/// Resolve the summary locale from the request tag (`ru*` → Russian, else the
/// English default). The core never reads the environment in the browser.
fn parse_locale(tag: Option<&str>) -> Locale {
    match tag {
        Some(value) if value.trim().to_ascii_lowercase().starts_with("ru") => Locale::Ru,
        _ => Locale::En,
    }
}

/// Map an RFC 5280 reason code (0–6) to a [`CrlReason`].
fn parse_reason(code: u8) -> Result<CrlReason, ApiError> {
    match code {
        0 => Ok(CrlReason::Unspecified),
        1 => Ok(CrlReason::KeyCompromise),
        2 => Ok(CrlReason::CaCompromise),
        3 => Ok(CrlReason::AffiliationChanged),
        4 => Ok(CrlReason::Superseded),
        5 => Ok(CrlReason::CessationOfOperation),
        6 => Ok(CrlReason::CertificateHold),
        other => Err(ApiError::msg(format!("unknown CRL reason code {other}"))),
    }
}

impl From<ValidityJson> for Validity {
    fn from(value: ValidityJson) -> Self {
        Validity {
            not_before: value.not_before,
            not_after: value.not_after,
        }
    }
}

impl From<IntegrityJson> for IntegrityCeiling {
    fn from(value: IntegrityJson) -> Self {
        IntegrityCeiling {
            level: value.level,
            categories: value.categories,
        }
    }
}

impl From<EnvelopeJson> for DelegationConstraints {
    fn from(value: EnvelopeJson) -> Self {
        DelegationConstraints {
            require_tags: value.require_tags,
            allow_roles: value.allow_roles,
            max_level: value.max_level,
            max_ttl: value.max_ttl,
        }
    }
}

/// The reverse mapping, for surfacing a parent's envelope back to the cabinet.
fn envelope_json(constraints: &DelegationConstraints) -> EnvelopeJson {
    EnvelopeJson {
        require_tags: constraints.require_tags.clone(),
        allow_roles: constraints.allow_roles.clone(),
        max_level: constraints.max_level,
        max_ttl: constraints.max_ttl,
    }
}

// --- in-core adapters -------------------------------------------------------

/// A signing backend that never signs: it captures the TBS the core hands it and
/// returns a throwaway signature.
///
/// This lets `build_*_tbs` run the whole core issuance path — every monotonicity
/// and proof-of-possession check, the exact extension encoding, and the post-
/// assembly self-check — while extracting only the bytes that a real key will
/// later sign. The dummy signature satisfies the core's structural self-check,
/// which inspects the certificate's extensions, not its signature.
struct CapturingBackend {
    algorithm: SignatureAlgorithm,
    captured: RefCell<Option<Vec<u8>>>,
}

impl CapturingBackend {
    fn new(algorithm: SignatureAlgorithm) -> Self {
        Self {
            algorithm,
            captured: RefCell::new(None),
        }
    }

    /// The captured TBS, taken out after a successful build.
    fn into_captured(self) -> Option<Vec<u8>> {
        self.captured.into_inner()
    }
}

impl SignatureBackend for CapturingBackend {
    fn algorithm(&self, _key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
        Ok(self.algorithm)
    }

    fn sign(&self, tbs_der: &[u8], _key_id: &KeyId) -> Result<Signature, SignError> {
        *self.captured.borrow_mut() = Some(tbs_der.to_vec());
        Ok(Signature {
            algorithm: self.algorithm,
            bytes: vec![0u8; 64],
        })
    }
}

/// A `Vec`-backed journal store: the browser holds the journal as lines of text,
/// so [`journal_append`] loads them into one of these, appends, and reads back
/// the single new line.
#[derive(Default)]
struct VecJournalStorage {
    lines: Vec<String>,
}

impl VecJournalStorage {
    fn from_lines(lines: Vec<String>) -> Self {
        Self { lines }
    }
}

impl JournalStorage for VecJournalStorage {
    fn append(&mut self, line: &str) -> Result<(), JournalError> {
        self.lines.push(line.to_owned());
        Ok(())
    }

    fn read_lines(&self) -> Result<Vec<String>, JournalError> {
        Ok(self.lines.clone())
    }
}

/// A throwaway journal for the build phase: the core mandates a journal target,
/// but the cabinet journals explicitly (via [`journal_append`]) only once the
/// real signature is in, so the build's entry is discarded.
fn throwaway_journal() -> Result<Journal<VecJournalStorage>, ApiError> {
    Journal::load(VecJournalStorage::default()).map_err(|e| ApiError::msg(e.to_string()))
}

// --- summary rendering ------------------------------------------------------

/// Turn a bare TBS into the localized, structured summary the cabinet previews.
fn summary_json(tbs_der: &[u8], locale: Locale) -> Result<SummaryJson, ApiError> {
    let summary =
        parse_operation_summary(tbs_der).map_err(|e| ApiError::msg(format!("summary: {e}")))?;
    let kind = match summary.kind {
        OperationKind::ShiftLeaf => "shift_leaf",
        OperationKind::OrgCa => "org_ca",
        OperationKind::Crl => "crl",
    };
    let lines = summary
        .lines
        .iter()
        .map(|line| SummaryLineJson {
            label: line.caption.text(locale).to_owned(),
            value: line.value.clone(),
        })
        .collect();
    Ok(SummaryJson {
        kind: kind.to_owned(),
        subject: summary.subject.clone(),
        not_before: summary.not_before.clone(),
        not_after: summary.not_after.clone(),
        lines,
        rendered: summary.render(locale),
    })
}

/// The RFC 4514 subject `Name` of a certificate, best-effort (empty on any
/// decode failure — the caller has already classified the certificate).
fn subject_string(cert_der: &[u8]) -> String {
    extract_subject_der(cert_der)
        .ok()
        .and_then(|name_der| x509_cert::name::Name::from_der(&name_der).ok())
        .map(|name| name.to_string())
        .unwrap_or_default()
}

// --- inspect_parent ---------------------------------------------------------

/// See the crate documentation for the JSON contract.
///
/// # Errors
///
/// JSON-encoded [`ApiError`] on malformed input.
pub(crate) fn inspect_parent(input: &str) -> Result<String, String> {
    finish(inspect_parent_inner(input))
}

fn inspect_parent_inner(input: &str) -> Result<InspectParentResponse, ApiError> {
    let request: InspectParentInput = parse_input(input)?;
    let der = pem_or_der(&b64_decode(&request.cert_b64)?)?;

    let unusable = |reason: &str| InspectParentResponse {
        kind: "unusable".to_owned(),
        subject: subject_string(&der),
        envelope: None,
        reason: Some(reason.to_owned()),
    };

    let Ok(basic) = extract_basic_constraints(&der) else {
        return Ok(unusable("certificate is malformed or unreadable"));
    };

    // A non-CA certificate (leaf) cannot issue anything.
    if !basic.is_some_and(|constraints| constraints.ca) {
        return Ok(InspectParentResponse {
            kind: "leaf".to_owned(),
            subject: subject_string(&der),
            envelope: None,
            reason: None,
        });
    }

    // A self-signed CA is a fleet root (issue org CAs); an issued CA is an
    // organisation CA (issue leaves).
    let self_signed = match (extract_issuer_der(&der), extract_subject_der(&der)) {
        (Ok(issuer), Ok(subject)) => issuer == subject,
        _ => false,
    };
    let envelope = parent_constraints(&der);

    if self_signed {
        return Ok(InspectParentResponse {
            kind: "root".to_owned(),
            subject: subject_string(&der),
            envelope: envelope.ok().flatten().as_ref().map(envelope_json),
            reason: None,
        });
    }

    match envelope {
        Ok(Some(constraints)) => Ok(InspectParentResponse {
            kind: "org_ca".to_owned(),
            subject: subject_string(&der),
            envelope: Some(envelope_json(&constraints)),
            reason: None,
        }),
        Ok(None) => Ok(unusable(
            "the CA carries no delegation envelope to bound leaves",
        )),
        Err(e) => Ok(unusable(&format!("delegation envelope is malformed: {e}"))),
    }
}

// --- build_leaf_tbs ---------------------------------------------------------

/// See the crate documentation for the JSON contract.
///
/// # Errors
///
/// JSON-encoded [`ApiError`] on malformed input or any core rejection (a
/// widened envelope names the `dimension`; a bad CSR fails proof of possession).
pub(crate) fn build_leaf_tbs(input: &str) -> Result<String, String> {
    finish(build_leaf_inner(input))
}

fn build_leaf_inner(input: &str) -> Result<BuildTbsResponse, ApiError> {
    let request: BuildLeafInput = parse_input(input)?;
    let parent = pem_or_der(&b64_decode(&request.parent_b64)?)?;
    let algorithm = parse_algorithm(&request.algorithm)?;
    let serial = Serial::from_entropy(&b64_decode(&request.serial_entropy_b64)?);
    let locale = parse_locale(request.locale.as_deref());
    let backend = CapturingBackend::new(algorithm);
    let key = KeyId::new(CABINET_KEY);
    let mut journal = throwaway_journal()?;
    let leaf = request.request;

    match (leaf.spki_b64.as_ref(), leaf.csr_b64.as_ref()) {
        (Some(_), Some(_)) => {
            return Err(ApiError::msg("spki_b64 and csr_b64 are mutually exclusive"))
        }
        (None, None) => {
            return Err(ApiError::msg(
                "one of spki_b64 or csr_b64 is required for a leaf",
            ))
        }
        (Some(spki), None) => {
            let subject = leaf
                .subject
                .clone()
                .ok_or_else(|| ApiError::msg("subject is required with an spki_b64 key source"))?;
            let req = LeafRequest {
                subject,
                subject_spki_der: b64_decode(spki)?,
                validity: leaf.validity.into(),
                host_binding: leaf.host_binding,
                user_binding: leaf.user_binding,
                allowed_roles: leaf.allowed_roles,
                max_integrity: leaf.max_integrity.map(Into::into),
                profile_version: leaf.profile_version,
            };
            issue_leaf(&backend, &key, &parent, &req, &serial, &mut journal, 0)?;
        }
        (None, Some(csr)) => {
            let scope = LeafScope {
                validity: leaf.validity.into(),
                host_binding: leaf.host_binding,
                user_binding: leaf.user_binding,
                allowed_roles: leaf.allowed_roles,
                max_integrity: leaf.max_integrity.map(Into::into),
                profile_version: leaf.profile_version,
            };
            let req = LeafRequestFromCsr {
                csr: b64_decode(csr)?,
                scope,
            };
            issue_leaf_from_csr(&backend, &key, &parent, &req, &serial, &mut journal, 0)?;
        }
    }

    let tbs = backend
        .into_captured()
        .ok_or_else(|| ApiError::msg("internal: issuance did not reach the signing step"))?;
    let summary = summary_json(&tbs, locale)?;
    Ok(BuildTbsResponse {
        tbs_b64: b64_encode(&tbs),
        summary,
    })
}

// --- build_ca_tbs -----------------------------------------------------------

/// See the crate documentation for the JSON contract.
///
/// # Errors
///
/// JSON-encoded [`ApiError`] on malformed input or a core rejection (a widened
/// envelope names the `dimension`).
pub(crate) fn build_ca_tbs(input: &str) -> Result<String, String> {
    finish(build_ca_inner(input))
}

fn build_ca_inner(input: &str) -> Result<BuildTbsResponse, ApiError> {
    let request: BuildCaInput = parse_input(input)?;
    let parent = pem_or_der(&b64_decode(&request.parent_b64)?)?;
    let algorithm = parse_algorithm(&request.algorithm)?;
    let serial = Serial::from_entropy(&b64_decode(&request.serial_entropy_b64)?);
    let locale = parse_locale(request.locale.as_deref());
    let backend = CapturingBackend::new(algorithm);
    let key = KeyId::new(CABINET_KEY);
    let mut journal = throwaway_journal()?;
    let ca: CaRequestJson = request.request;

    let req = CaRequest {
        subject: ca.subject,
        subject_spki_der: b64_decode(&ca.spki_b64)?,
        validity: ca.validity.into(),
        constraints: ca.constraints.into(),
        profile_version: ca.profile_version,
    };
    issue_ca(&backend, &key, &parent, &req, &serial, &mut journal, 0)?;

    let tbs = backend
        .into_captured()
        .ok_or_else(|| ApiError::msg("internal: issuance did not reach the signing step"))?;
    let summary = summary_json(&tbs, locale)?;
    Ok(BuildTbsResponse {
        tbs_b64: b64_encode(&tbs),
        summary,
    })
}

// --- build_crl_tbs ----------------------------------------------------------

/// See the crate documentation for the JSON contract.
///
/// # Errors
///
/// JSON-encoded [`ApiError`] on malformed input or a non-monotone `crlNumber`.
pub(crate) fn build_crl_tbs(input: &str) -> Result<String, String> {
    finish(build_crl_inner(input))
}

fn build_crl_inner(input: &str) -> Result<BuildTbsResponse, ApiError> {
    let request: BuildCrlInput = parse_input(input)?;
    let issuer = pem_or_der(&b64_decode(&request.issuer_b64)?)?;
    let algorithm = parse_algorithm(&request.algorithm)?;
    let locale = parse_locale(request.locale.as_deref());
    let backend = CapturingBackend::new(algorithm);
    let key = KeyId::new(CABINET_KEY);
    let mut journal = throwaway_journal()?;
    let crl: CrlRequestJson = request.request;

    let mut revoked = Vec::with_capacity(crl.revoked.len());
    for entry in crl.revoked {
        let reason = match entry.reason {
            Some(code) => Some(parse_reason(code)?),
            None => None,
        };
        revoked.push(RevokedEntry {
            serial: b64_decode(&entry.serial_b64)?,
            revocation_date: entry.revocation_date,
            reason,
        });
    }
    let req = CrlRequest {
        this_update: crl.this_update,
        next_update: crl.next_update,
        crl_number: crl.crl_number,
        revoked,
    };
    issue_crl(
        &backend,
        &key,
        &issuer,
        &req,
        request.last_crl_number,
        &mut journal,
        0,
    )?;

    let tbs = backend
        .into_captured()
        .ok_or_else(|| ApiError::msg("internal: CRL issuance did not reach the signing step"))?;
    let summary = summary_json(&tbs, locale)?;
    Ok(BuildTbsResponse {
        tbs_b64: b64_encode(&tbs),
        summary,
    })
}

// --- inspect_csr ------------------------------------------------------------

/// See the crate documentation for the JSON contract.
///
/// # Errors
///
/// JSON-encoded [`ApiError`] when the CSR does not parse.
pub(crate) fn inspect_csr(input: &str) -> Result<String, String> {
    finish(inspect_csr_inner(input))
}

fn inspect_csr_inner(input: &str) -> Result<InspectCsrResponse, ApiError> {
    let request: InspectCsrInput = parse_input(input)?;
    let der = pem_or_der(&b64_decode(&request.csr_b64)?)?;
    let csr = Csr::parse(&der)?;
    let signature_valid = csr.verify_proof_of_possession().is_ok();

    // Walk the requested extensions with the shared DER primitives rather than
    // `x509-cert`: `const-oid` cannot represent the project's wide `2.25.<UUID>`
    // arcs, so an `x509-cert` decode would silently drop exactly the Tessera
    // extensions this prefill needs. This walk is best-effort and advisory.
    let requested = csr_requested_extensions(&der);
    let requested_parsed = parse_known_extensions(&requested);
    let requested_extensions = requested
        .into_iter()
        .map(|ext| RequestedExtensionJson {
            oid: ext.oid,
            critical: ext.critical,
            value_b64: b64_encode(&ext.value_der),
        })
        .collect();

    Ok(InspectCsrResponse {
        subject: csr.subject().to_owned(),
        signature_valid,
        spki_b64: b64_encode(csr.subject_spki_der()),
        requested_extensions,
        requested_parsed,
    })
}

/// One requested extension as walked out of a CSR's `extensionRequest`
/// attribute: its dotted OID, criticality, and raw `extnValue` bytes.
struct RawRequestedExtension {
    oid: String,
    critical: bool,
    value_der: Vec<u8>,
}

/// Best-effort extraction of every extension in a CSR's PKCS#9
/// `extensionRequest` attribute, robust to the wide `2.25.<UUID>` OIDs. A
/// malformed attribute framing yields an empty list — this is advisory data and
/// never blocks issuance.
fn csr_requested_extensions(csr_der: &[u8]) -> Vec<RawRequestedExtension> {
    walk_csr_requested_extensions(csr_der).unwrap_or_default()
}

/// The fallible walk behind [`csr_requested_extensions`].
fn walk_csr_requested_extensions(csr_der: &[u8]) -> Result<Vec<RawRequestedExtension>, DerError> {
    // CertificationRequest -> CertificationRequestInfo.
    let outer = read_tlv_expect(csr_der, TAG_SEQUENCE)?;
    let info = read_tlv_expect(outer.value, TAG_SEQUENCE)?;

    // Skip version INTEGER, subject SEQUENCE, subjectPKInfo SEQUENCE.
    let mut rest = read_tlv_expect(info.value, TAG_INTEGER)?.rest;
    rest = read_tlv_expect(rest, TAG_SEQUENCE)?.rest;
    rest = read_tlv_expect(rest, TAG_SEQUENCE)?.rest;

    // attributes [0] IMPLICIT SET OF Attribute — optional; absent means none.
    let Ok(attributes) = read_tlv(rest) else {
        return Ok(Vec::new());
    };
    if attributes.tag != TAG_CONTEXT_0 {
        return Ok(Vec::new());
    }

    let extension_request = encode_oid(EXTENSION_REQUEST_OID)?;
    let mut out = Vec::new();
    let mut attrs = attributes.value;
    while !attrs.is_empty() {
        let attribute = read_tlv_expect(attrs, TAG_SEQUENCE)?;
        attrs = attribute.rest;
        let type_oid = read_tlv_expect(attribute.value, TAG_OID)?;
        if type_oid.value != extension_request.as_slice() {
            continue;
        }
        // values SET { ExtensionRequest ::= SEQUENCE OF Extension }.
        let values = read_tlv_expect(type_oid.rest, TAG_SET)?;
        let mut sequences = values.value;
        while !sequences.is_empty() {
            let ext_seq = read_tlv_expect(sequences, TAG_SEQUENCE)?;
            sequences = ext_seq.rest;
            let mut exts = ext_seq.value;
            while !exts.is_empty() {
                let extension = read_tlv_expect(exts, TAG_SEQUENCE)?;
                exts = extension.rest;
                out.push(read_one_extension(extension.value)?);
            }
        }
    }
    Ok(out)
}

/// Decode one `Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE,
/// extnValue OCTET STRING }` from its `SEQUENCE` content.
fn read_one_extension(fields: &[u8]) -> Result<RawRequestedExtension, DerError> {
    let oid = read_tlv_expect(fields, TAG_OID)?;
    let mut inner = oid.rest;
    let mut critical = false;
    let peek = read_tlv(inner)?;
    if peek.tag == TAG_BOOLEAN {
        critical = peek.value.first().copied().unwrap_or(0) != 0;
        inner = peek.rest;
    }
    let octet = read_tlv_expect(inner, TAG_OCTET_STRING)?;
    Ok(RawRequestedExtension {
        oid: oid_to_dotted(oid.value)?,
        critical,
        value_der: octet.value.to_vec(),
    })
}

/// Semantically decode the *known* Tessera extensions among the requested ones,
/// with the same [`tessera_ext`] parsers the Engine uses. A known extension whose
/// value does not decode is skipped (it stays only in the raw list); an unknown
/// OID is ignored here.
fn parse_known_extensions(extensions: &[RawRequestedExtension]) -> RequestedParsedJson {
    let mut parsed = RequestedParsedJson::default();
    for extension in extensions {
        match extension.oid.as_str() {
            ALLOWED_ROLES_OID => {
                if let Ok(roles) = parse_seq_of_utf8(&extension.value_der) {
                    parsed.allowed_roles = Some(roles);
                }
            }
            HOST_BINDING_OID => {
                if let Ok(hosts) = parse_seq_of_utf8(&extension.value_der) {
                    parsed.host_binding = Some(hosts);
                }
            }
            USER_BINDING_OID => {
                if let Ok(users) = parse_seq_of_utf8(&extension.value_der) {
                    parsed.user_binding = Some(users);
                }
            }
            MAX_INTEGRITY_OID => {
                if let Ok((level, categories)) = parse_max_integrity(&extension.value_der) {
                    parsed.max_integrity = Some(ParsedIntegrityJson { level, categories });
                }
            }
            PROFILE_VERSION_OID => {
                if let Ok(version) = parse_profile_version(&extension.value_der) {
                    parsed.profile_version = Some(version);
                }
            }
            _ => {}
        }
    }
    parsed
}

// --- assemble_and_verify ----------------------------------------------------

/// See the crate documentation for the JSON contract.
///
/// # Errors
///
/// JSON-encoded [`ApiError`] on malformed input, a signature algorithm that
/// disagrees with the TBS, or a self-check failure against the parent envelope.
pub(crate) fn assemble_and_verify(input: &str) -> Result<String, String> {
    finish(assemble_inner(input))
}

fn assemble_inner(input: &str) -> Result<AssembleResponse, ApiError> {
    let request: AssembleInput = parse_input(input)?;
    let tbs = b64_decode(&request.tbs_b64)?;
    let algorithm = parse_algorithm(&request.signature.algorithm)?;
    let signature = b64_decode(&request.signature.bytes_b64)?;
    let parent = pem_or_der(&b64_decode(&request.parent_b64)?)?;

    let is_crl = tbs_is_crl(&tbs)?;
    verify_tbs_algorithm(&tbs, algorithm, is_crl)?;
    let artifact = assemble_signed_certificate(&tbs, algorithm, &signature)?;

    let (pem_label, kind) = if is_crl {
        // A CRL's self-check is that the finished bytes re-parse as a coherent
        // revocation list (the monotonicity check already ran at build time).
        parse_operation_summary(&tbs).map_err(|e| ApiError::msg(format!("summary: {e}")))?;
        ("X509 CRL", "crl")
    } else {
        let kind = self_check_against_parent(&artifact, &parent)?;
        ("CERTIFICATE", kind)
    };

    Ok(AssembleResponse {
        cert_pem: encode_pem(pem_label, &artifact),
        cert_b64: b64_encode(&artifact),
        kind: kind.to_owned(),
    })
}

/// Whether a TBS is a `TBSCertList` (CRL) rather than a `TBSCertificate`: a
/// certificate opens with `version [0]` (tag `0xA0`), a CRL with `version
/// INTEGER`.
fn tbs_is_crl(tbs_der: &[u8]) -> Result<bool, ApiError> {
    let seq = read_tlv_expect(tbs_der, TAG_SEQUENCE)?;
    let first = read_tlv(seq.value)?;
    match first.tag {
        0xA0 => Ok(false),
        TAG_INTEGER => Ok(true),
        _ => Err(ApiError::msg("TBS is neither a certificate nor a CRL")),
    }
}

/// Confirm the TBS's inner `signature` `AlgorithmIdentifier` matches the outer
/// algorithm the agent signed with, so the assembled artifact is internally
/// consistent.
fn verify_tbs_algorithm(
    tbs_der: &[u8],
    algorithm: SignatureAlgorithm,
    is_crl: bool,
) -> Result<(), ApiError> {
    let seq = read_tlv_expect(tbs_der, TAG_SEQUENCE)?;
    let mut rest = seq.value;
    if is_crl {
        // version INTEGER, then the AlgorithmIdentifier.
        rest = read_tlv_expect(rest, TAG_INTEGER)?.rest;
    } else {
        // Optional version [0], then serialNumber, then the AlgorithmIdentifier.
        let peek = read_tlv(rest)?;
        if peek.tag == 0xA0 {
            rest = peek.rest;
        }
        rest = read_tlv(rest)?.rest;
    }
    let algid = read_tlv_expect(rest, TAG_SEQUENCE)?;
    let consumed = rest.len().saturating_sub(algid.rest.len());
    let algid_bytes = rest.get(..consumed).unwrap_or(&[]);
    let expected = algorithm
        .algorithm_identifier()
        .to_der()
        .map_err(|e| ApiError::msg(format!("der: {e}")))?;
    if algid_bytes != expected.as_slice() {
        return Err(ApiError::msg(
            "signature algorithm does not match the TBS signature field",
        ));
    }
    Ok(())
}

/// Reads one custom extension's `extnValue`, rejecting if it is absent.
fn require_extension(cert_der: &[u8], oid: &str, name: &str) -> Result<Vec<u8>, ApiError> {
    extract_extension_value(cert_der, oid)?.ok_or_else(|| {
        ApiError::msg(format!(
            "assembled artifact is missing the {name} extension"
        ))
    })
}

/// Re-parse the assembled certificate with the shared parsers and re-affirm it
/// stays inside the parent envelope. Returns the artifact kind on success.
fn self_check_against_parent(cert_der: &[u8], parent_der: &[u8]) -> Result<&'static str, ApiError> {
    let basic = extract_basic_constraints(cert_der)?
        .ok_or_else(|| ApiError::msg("assembled certificate has no basicConstraints"))?;
    let parent = parent_constraints(parent_der)?;

    if basic.ca {
        // An organisation CA: envelope, keyUsage and profile_version present, and
        // the envelope narrows the parent's.
        let value = require_extension(
            cert_der,
            DELEGATION_CONSTRAINTS_OID,
            "delegation_constraints",
        )?;
        let child = tessera_ext::delegation::parse_constraints(&value)
            .map_err(|e| ApiError::msg(format!("delegation_constraints reparse failed: {e}")))?;
        require_extension(cert_der, KEY_USAGE_OID, "keyUsage")?;
        parse_profile_version(&require_extension(
            cert_der,
            PROFILE_VERSION_OID,
            "profile_version",
        )?)?;
        if let Some(parent) = parent {
            narrows(&child, &parent)
                .map_err(|w| ApiError::dimension(w.to_string(), &w.dimension.to_string()))?;
        }
        Ok("org_ca")
    } else {
        // A shift-leaf: mandatory bindings present and non-empty, no delegation
        // envelope, and the scope stays inside the parent's.
        if extract_extension_value(cert_der, DELEGATION_CONSTRAINTS_OID)?.is_some() {
            return Err(ApiError::msg(
                "leaf carries a delegation_constraints extension",
            ));
        }
        let hosts = parse_seq_of_utf8(&require_extension(
            cert_der,
            HOST_BINDING_OID,
            "host_binding",
        )?)?;
        if hosts.is_empty() {
            return Err(ApiError::msg("host_binding is empty"));
        }
        let users = parse_seq_of_utf8(&require_extension(
            cert_der,
            USER_BINDING_OID,
            "user_binding",
        )?)?;
        if users.is_empty() {
            return Err(ApiError::msg("user_binding is empty"));
        }
        let roles = parse_seq_of_utf8(&require_extension(
            cert_der,
            ALLOWED_ROLES_OID,
            "allowed_roles",
        )?)?;
        parse_profile_version(&require_extension(
            cert_der,
            PROFILE_VERSION_OID,
            "profile_version",
        )?)?;

        if let Some(parent) = parent {
            for role in &roles {
                if !parent.allow_roles.iter().any(|allowed| allowed == role) {
                    return Err(ApiError::dimension(
                        format!("allowed role `{role}` is not in the parent envelope"),
                        "allow_roles",
                    ));
                }
            }
            if let Some(value) = extract_extension_value(cert_der, MAX_INTEGRITY_OID)? {
                let (level, _categories) = parse_max_integrity(&value)?;
                if level > parent.max_level {
                    return Err(ApiError::dimension(
                        format!(
                            "leaf max_integrity level {level} exceeds parent ceiling {}",
                            parent.max_level
                        ),
                        "max_level",
                    ));
                }
            }
        }
        Ok("shift_leaf")
    }
}

// --- journal ----------------------------------------------------------------

/// See the crate documentation for the JSON contract.
///
/// # Errors
///
/// JSON-encoded [`ApiError`] on malformed input or a storage failure.
pub(crate) fn journal_append(input: &str) -> Result<String, String> {
    finish(journal_append_inner(input))
}

fn journal_append_inner(input: &str) -> Result<JournalAppendResponse, ApiError> {
    let request: JournalAppendInput = parse_input(input)?;
    let storage = VecJournalStorage::from_lines(request.prev_lines);
    let mut journal = Journal::load(storage).map_err(|e| ApiError::msg(e.to_string()))?;

    match request.entry {
        JournalEntryJson::Leaf {
            serial_b64,
            parent_b64,
            subject,
        } => journal
            .record_leaf(
                &b64_decode(&serial_b64)?,
                &b64_decode(&parent_b64)?,
                &subject,
                request.now_unix,
            )
            .map_err(|e| ApiError::msg(e.to_string()))?,
        JournalEntryJson::Ca {
            serial_b64,
            parent_b64,
            subject,
        } => journal
            .record_ca(
                &b64_decode(&serial_b64)?,
                &b64_decode(&parent_b64)?,
                &subject,
                request.now_unix,
            )
            .map_err(|e| ApiError::msg(e.to_string()))?,
        JournalEntryJson::Crl {
            crl_number,
            parent_b64,
        } => journal
            .record_crl(crl_number, &b64_decode(&parent_b64)?, request.now_unix)
            .map_err(|e| ApiError::msg(e.to_string()))?,
    }

    let new_line = journal
        .storage()
        .read_lines()
        .map_err(|e| ApiError::msg(e.to_string()))?
        .pop()
        .ok_or_else(|| ApiError::msg("internal: journal produced no new line"))?;
    Ok(JournalAppendResponse { new_line })
}

/// See the crate documentation for the JSON contract.
///
/// # Errors
///
/// JSON-encoded [`ApiError`] on malformed input.
pub(crate) fn journal_verify(input: &str) -> Result<String, String> {
    finish(journal_verify_inner(input))
}

fn journal_verify_inner(input: &str) -> Result<JournalVerifyResponse, ApiError> {
    let request: JournalVerifyInput = parse_input(input)?;
    let report = verify_lines(&request.lines);
    let (status, position, unsigned_from_seq) = match report.status {
        JournalStatus::Intact => ("intact", None, None),
        JournalStatus::IntactUnsignedTail { unsigned_from_seq } => {
            ("intact_unsigned_tail", None, Some(unsigned_from_seq))
        }
        JournalStatus::Broken { position } => ("broken", Some(position), None),
        // `JournalStatus` is `#[non_exhaustive]`; a future variant surfaces as
        // an explicit unknown status rather than panicking.
        _ => ("unknown", None, None),
    };
    Ok(JournalVerifyResponse {
        status: status.to_owned(),
        position,
        unsigned_from_seq,
        entry_count: report.entry_count,
        last_signed_seq: report.last_signed_seq,
    })
}

#[cfg(test)]
mod tests;

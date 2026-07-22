//! Parsing a bare TBS into a human-readable operation summary.
//!
//! Before anything is signed, an operator surface — the browser cabinet's
//! preview — has to show *what* the TBS actually is: an engineer shift-leaf, an
//! organisation CA, or a CRL, with its subject, validity and the scope it
//! carries. That decoding is done here with the shared [`tessera_ext`]
//! definitions (the same ones the Engine enforces) plus `x509-cert` for the
//! standard `Name`/`Time` fields, so a summary reflects exactly the bytes that
//! will be signed.
//!
//! The module is pure and `wasm32`-compatible: it pulls in no process, socket,
//! or system dependency, so it backs the browser cabinet's WASM core. Only the
//! parsing and rendering live here.

use der::Decode as _;
use x509_cert::name::Name;
use x509_cert::time::{Time, Validity};

use tessera_ext::delegation::parse_constraints;
use tessera_ext::der::{encode_tlv, read_tlv, read_tlv_expect, TAG_INTEGER, TAG_SEQUENCE};
use tessera_ext::ext::{
    extract_basic_constraints, extract_extension_value, extract_subject_der, parse_max_integrity,
    parse_profile_version, parse_seq_of_utf8,
};
use tessera_ext::oids::{
    ALLOWED_ROLES_OID, DELEGATION_CONSTRAINTS_OID, HOST_BINDING_OID, MAX_INTEGRITY_OID,
    PROFILE_VERSION_OID, USER_BINDING_OID,
};

use crate::l10n::{Caption, Locale};

/// DER tag for `[0] EXPLICIT` — the `TBSCertificate` version wrapper (a cert)
/// and the `TBSCertList` `crlExtensions` wrapper (a CRL).
const TAG_CONTEXT_0: u8 = 0xA0;
/// DER tag for `UTCTime`.
const TAG_UTC_TIME: u8 = 0x17;
/// DER tag for `GeneralizedTime`.
const TAG_GENERALIZED_TIME: u8 = 0x18;
/// The standard `cRLNumber` extension OID.
const CRL_NUMBER_OID: &str = "2.5.29.20";

/// What kind of operation a summary describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// An engineer shift-leaf certificate.
    ShiftLeaf,
    /// An organisation CA certificate.
    OrgCa,
    /// A certificate revocation list.
    Crl,
    /// An exported device registry signed with the dedicated registry key. It
    /// carries no certificate subject or validity window; its identifying data
    /// (key label, payload digest, size) is carried in the detail lines.
    DeviceRegistry,
}

impl OperationKind {
    /// The operation's name in `locale`.
    #[must_use]
    pub fn label(self, locale: Locale) -> &'static str {
        self.caption().text(locale)
    }

    /// The caption naming this kind.
    fn caption(self) -> Caption {
        match self {
            OperationKind::ShiftLeaf => Caption::KindShiftLeaf,
            OperationKind::OrgCa => Caption::KindOrgCa,
            OperationKind::Crl => Caption::KindCrl,
            OperationKind::DeviceRegistry => Caption::KindDeviceRegistry,
        }
    }
}

/// One detail line of an [`OperationSummary`]: a localizable caption and its
/// value.
///
/// The value is a technical datum (a role list, a bound host, a `crlNumber`) and
/// is identical in every locale; only the caption is translated when rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryLine {
    /// The field caption.
    pub caption: Caption,
    /// The already-formatted value shown beside the caption.
    pub value: String,
}

/// A human-readable summary of the operation the agent is being asked to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationSummary {
    /// The operation kind.
    pub kind: OperationKind,
    /// The certificate subject, or the CRL issuer, as an RFC 4514 string.
    pub subject: String,
    /// Start of the validity window (`notBefore`, or a CRL's `thisUpdate`).
    pub not_before: String,
    /// End of the validity window (`notAfter`, or a CRL's `nextUpdate`).
    pub not_after: String,
    /// Extra detail lines: roles, bindings, envelope, `crlNumber`.
    pub lines: Vec<SummaryLine>,
}

impl OperationSummary {
    /// Renders the summary as a multi-line block, captioned in `locale`.
    ///
    /// Only the captions are translated; every value is reproduced verbatim, so
    /// a Russian and an English rendering carry byte-identical data.
    #[must_use]
    pub fn render(&self, locale: Locale) -> String {
        let mut out = format!(
            "{}: {}",
            Caption::Operation.text(locale),
            self.kind.label(locale),
        );
        // A device registry has neither a certificate subject nor a validity
        // window; only the operation line and the detail lines are shown. Every
        // certificate/CRL kind keeps the subject and validity block verbatim.
        if self.kind != OperationKind::DeviceRegistry {
            out.push('\n');
            out.push_str(Caption::Subject.text(locale));
            out.push_str(": ");
            out.push_str(&neutralize_bidi(&self.subject));
            out.push('\n');
            out.push_str(Caption::Validity.text(locale));
            out.push_str(": ");
            out.push_str(&neutralize_bidi(&self.not_before));
            out.push_str(" .. ");
            out.push_str(&neutralize_bidi(&self.not_after));
        }
        for line in &self.lines {
            out.push_str("\n  ");
            out.push_str(line.caption.text(locale));
            out.push_str(": ");
            out.push_str(&neutralize_bidi(&line.value));
        }
        out
    }
}

/// Whether `c` is a Unicode bidirectional-control codepoint.
///
/// These reorder surrounding text visually without changing its logical order,
/// the basis of the "Trojan Source" spoof: a right-to-left override inside a
/// subject can make a displayed distinguished name read as something other than
/// the bytes that will be signed. None of them belong in a certificate subject
/// or a scope value, so a summary must not display them raw.
fn is_bidi_control(c: char) -> bool {
    matches!(c,
        '\u{200E}' | '\u{200F}'          // LRM, RLM
        | '\u{202A}'..='\u{202E}'        // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}') // LRI, RLI, FSI, PDI
}

/// Replaces every bidi-control codepoint in `value` with a visible `\uXXXX`
/// marker, so a rendered summary cannot be visually reordered to mislead the
/// operator. The underlying [`OperationSummary`] value is untouched — this
/// neutralizes only what is shown, not the data itself.
fn neutralize_bidi(value: &str) -> String {
    if !value.contains(is_bidi_control) {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if is_bidi_control(c) {
            // A stable, operator-legible `\uXXXX` marker; the codepoint never
            // reaches the terminal or pinentry as an active control. Every
            // neutralized codepoint fits in four hex digits.
            out.push('\\');
            out.push('u');
            let cp = u32::from(c);
            for shift in [12u32, 8, 4, 0] {
                let nibble = (cp >> shift) & 0xF;
                out.push(hex_upper_nibble(nibble));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// One uppercase hex digit for a nibble (`0..=15`).
fn hex_upper_nibble(nibble: u32) -> char {
    char::from_digit(nibble, 16).map_or('0', |c| c.to_ascii_uppercase())
}

/// Why a TBS could not be turned into a summary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SummaryError {
    /// The bytes are not a well-formed `TBSCertificate`/`TBSCertList`.
    #[error("TBS is malformed or not a recognized issuance operation")]
    Malformed,
}

/// Parse a bare TBS (certificate or CRL) into an [`OperationSummary`].
///
/// The first field discriminates: a `TBSCertificate` opens with `version [0]`
/// (tag `0xA0`), a `TBSCertList` with `version INTEGER`. Anything else is
/// rejected.
///
/// # Errors
///
/// [`SummaryError::Malformed`] when the bytes are not a parseable issuance
/// operation — the caller MUST refuse to sign such a TBS.
pub fn parse_operation_summary(tbs_der: &[u8]) -> Result<OperationSummary, SummaryError> {
    let tbs = read_tlv_expect(tbs_der, TAG_SEQUENCE).map_err(|_| SummaryError::Malformed)?;
    if !tbs.rest.is_empty() {
        return Err(SummaryError::Malformed);
    }
    let first = read_tlv(tbs.value).map_err(|_| SummaryError::Malformed)?;
    match first.tag {
        TAG_CONTEXT_0 => parse_certificate_summary(tbs_der),
        TAG_INTEGER => parse_crl_summary(tbs.value),
        _ => Err(SummaryError::Malformed),
    }
}

/// Build a certificate summary from a `TBSCertificate`.
fn parse_certificate_summary(tbs_der: &[u8]) -> Result<OperationSummary, SummaryError> {
    // The shared extractors walk a `Certificate`; wrap the bare TBS in an outer
    // SEQUENCE so `Certificate -> tbsCertificate` resolves to it.
    let cert_like = encode_tlv(TAG_SEQUENCE, tbs_der);

    let basic = extract_basic_constraints(&cert_like).map_err(|_| SummaryError::Malformed)?;
    let is_ca = basic.is_some_and(|b| b.ca);

    let subject_der = extract_subject_der(&cert_like).map_err(|_| SummaryError::Malformed)?;
    let subject = Name::from_der(&subject_der)
        .map(|n| n.to_string())
        .map_err(|_| SummaryError::Malformed)?;
    let (not_before, not_after) = certificate_validity(tbs_der)?;

    let mut lines = Vec::new();
    let kind = if is_ca {
        if let Some(value) = extract_extension_value(&cert_like, DELEGATION_CONSTRAINTS_OID)
            .map_err(|_| SummaryError::Malformed)?
        {
            let envelope = parse_constraints(&value).map_err(|_| SummaryError::Malformed)?;
            lines.push(SummaryLine {
                caption: Caption::Roles,
                value: join_or_none(&envelope.allow_roles),
            });
            lines.push(SummaryLine {
                caption: Caption::MaxLevel,
                value: envelope.max_level.to_string(),
            });
            lines.push(SummaryLine {
                caption: Caption::MaxTtl,
                value: format!("{} s", envelope.max_ttl),
            });
            if !envelope.require_tags.is_empty() {
                let tags = envelope
                    .require_tags
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(SummaryLine {
                    caption: Caption::RequiredTags,
                    value: tags,
                });
            }
        }
        OperationKind::OrgCa
    } else {
        push_seq_line(&cert_like, HOST_BINDING_OID, Caption::Hosts, &mut lines)?;
        push_seq_line(&cert_like, USER_BINDING_OID, Caption::Users, &mut lines)?;
        push_seq_line(&cert_like, ALLOWED_ROLES_OID, Caption::Roles, &mut lines)?;
        if let Some(value) = extract_extension_value(&cert_like, MAX_INTEGRITY_OID)
            .map_err(|_| SummaryError::Malformed)?
        {
            let (level, categories) =
                parse_max_integrity(&value).map_err(|_| SummaryError::Malformed)?;
            lines.push(SummaryLine {
                caption: Caption::Integrity,
                value: format!("level {level}, categories {categories:#x}"),
            });
        }
        if let Some(value) = extract_extension_value(&cert_like, PROFILE_VERSION_OID)
            .map_err(|_| SummaryError::Malformed)?
        {
            let version = parse_profile_version(&value).map_err(|_| SummaryError::Malformed)?;
            lines.push(SummaryLine {
                caption: Caption::Profile,
                value: format!("v{version}"),
            });
        }
        OperationKind::ShiftLeaf
    };

    Ok(OperationSummary {
        kind,
        subject,
        not_before,
        not_after,
        lines,
    })
}

/// Read one `SEQUENCE OF UTF8String` extension and push it as a summary line.
fn push_seq_line(
    cert_like: &[u8],
    oid: &str,
    caption: Caption,
    lines: &mut Vec<SummaryLine>,
) -> Result<(), SummaryError> {
    if let Some(value) =
        extract_extension_value(cert_like, oid).map_err(|_| SummaryError::Malformed)?
    {
        let items = parse_seq_of_utf8(&value).map_err(|_| SummaryError::Malformed)?;
        lines.push(SummaryLine {
            caption,
            value: join_or_none(&items),
        });
    }
    Ok(())
}

/// `", "`-join, or `(none)` when empty.
fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_owned()
    } else {
        items.join(", ")
    }
}

/// Isolate and decode the `validity` `SEQUENCE` of a `TBSCertificate`.
fn certificate_validity(tbs_der: &[u8]) -> Result<(String, String), SummaryError> {
    let tbs = read_tlv_expect(tbs_der, TAG_SEQUENCE).map_err(|_| SummaryError::Malformed)?;
    let mut rest = tbs.value;
    // Skip version [0] if present, then serialNumber, signature, issuer.
    let peek = read_tlv(rest).map_err(|_| SummaryError::Malformed)?;
    if peek.tag == TAG_CONTEXT_0 {
        rest = peek.rest;
    }
    for _ in 0..3 {
        rest = read_tlv(rest).map_err(|_| SummaryError::Malformed)?.rest;
    }
    let validity_bytes = element_bytes(rest, TAG_SEQUENCE)?;
    let validity = Validity::from_der(validity_bytes).map_err(|_| SummaryError::Malformed)?;
    Ok((
        validity.not_before.to_string(),
        validity.not_after.to_string(),
    ))
}

/// Build a CRL summary from a `TBSCertList` (the fields inside its `SEQUENCE`).
fn parse_crl_summary(fields: &[u8]) -> Result<OperationSummary, SummaryError> {
    // version INTEGER, then signature AlgorithmIdentifier.
    let rest = read_tlv_expect(fields, TAG_INTEGER)
        .map_err(|_| SummaryError::Malformed)?
        .rest;
    let rest = read_tlv_expect(rest, TAG_SEQUENCE)
        .map_err(|_| SummaryError::Malformed)?
        .rest;

    // issuer Name.
    let issuer_bytes = element_bytes(rest, TAG_SEQUENCE)?;
    let subject = Name::from_der(issuer_bytes)
        .map(|n| n.to_string())
        .map_err(|_| SummaryError::Malformed)?;
    let mut rest = read_tlv_expect(rest, TAG_SEQUENCE)
        .map_err(|_| SummaryError::Malformed)?
        .rest;

    // thisUpdate Time.
    let this_update = read_time(rest)?;
    rest = read_tlv(rest).map_err(|_| SummaryError::Malformed)?.rest;

    // Optional nextUpdate Time.
    let mut next_update = "(none)".to_owned();
    if let Ok(peek) = read_tlv(rest) {
        if peek.tag == TAG_UTC_TIME || peek.tag == TAG_GENERALIZED_TIME {
            next_update = read_time(rest)?;
            rest = peek.rest;
        }
    }

    // Best-effort crlNumber from crlExtensions [0].
    let mut lines = Vec::new();
    if let Some(number) = crl_number(rest) {
        lines.push(SummaryLine {
            caption: Caption::CrlNumber,
            value: number.to_string(),
        });
    }

    Ok(OperationSummary {
        kind: OperationKind::Crl,
        subject,
        not_before: this_update,
        not_after: next_update,
        lines,
    })
}

/// Decode the leading `Time` element (UTC or Generalized) to a string.
fn read_time(bytes: &[u8]) -> Result<String, SummaryError> {
    let tlv = read_tlv(bytes).map_err(|_| SummaryError::Malformed)?;
    let consumed = bytes.len().saturating_sub(tlv.rest.len());
    let time_der = bytes.get(..consumed).unwrap_or(&[]);
    let time = Time::from_der(time_der).map_err(|_| SummaryError::Malformed)?;
    Ok(time.to_string())
}

/// Return the full DER bytes (header + content) of the next element, requiring
/// its tag.
fn element_bytes(bytes: &[u8], tag: u8) -> Result<&[u8], SummaryError> {
    let tlv = read_tlv_expect(bytes, tag).map_err(|_| SummaryError::Malformed)?;
    let consumed = bytes.len().saturating_sub(tlv.rest.len());
    Ok(bytes.get(..consumed).unwrap_or(&[]))
}

/// Best-effort extraction of `crlNumber` from the remaining `TBSCertList` bytes.
///
/// Returns `None` (rather than failing) when the extension is absent or the
/// tail is shaped unexpectedly — the summary is still valid without it.
fn crl_number(mut rest: &[u8]) -> Option<u64> {
    // Walk forward to the crlExtensions [0] wrapper.
    let ext_octets = loop {
        let tlv = read_tlv(rest).ok()?;
        if tlv.tag == TAG_CONTEXT_0 {
            break tlv.value;
        }
        rest = tlv.rest;
    };
    let ext_seq = read_tlv_expect(ext_octets, TAG_SEQUENCE).ok()?;
    let target = tessera_ext::der::encode_oid(CRL_NUMBER_OID).ok()?;
    let mut walker = ext_seq.value;
    while !walker.is_empty() {
        let ext = read_tlv_expect(walker, TAG_SEQUENCE).ok()?;
        walker = ext.rest;
        let oid = read_tlv(ext.value).ok()?;
        if oid.value != target.as_slice() {
            continue;
        }
        // Skip an optional critical BOOLEAN, then read the OCTET STRING value.
        let mut inner = oid.rest;
        let peek = read_tlv(inner).ok()?;
        if peek.tag == 0x01 {
            inner = peek.rest;
        }
        let octet = read_tlv(inner).ok()?;
        let int = read_tlv_expect(octet.value, TAG_INTEGER).ok()?;
        let mut value: u64 = 0;
        for &byte in int.value {
            value = value.checked_shl(8)?.checked_add(u64::from(byte))?;
        }
        return Some(value);
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::sign::{KeyId, MockSigner};
    use crate::test_support::MemoryStorage;
    use crate::{issue_ca, issue_crl, issue_leaf, CaRequest, CrlRequest, Journal, LeafRequest};
    use crate::{IntegrityCeiling, RevokedEntry, Serial, Validity as IssueValidity};
    use tessera_ext::delegation::DelegationConstraints;

    /// A fixed issuance timestamp for these fixtures (Unix seconds).
    const TS: u64 = 1_600_000_000;

    /// A throwaway in-memory journal for the fixtures (mandatory-journaled).
    fn fresh_journal() -> Journal<MemoryStorage> {
        Journal::load(MemoryStorage::new()).unwrap()
    }

    fn key() -> KeyId {
        KeyId::new("ca-key")
    }

    fn envelope() -> DelegationConstraints {
        DelegationConstraints {
            require_tags: vec![],
            allow_roles: vec!["oper".to_owned()],
            max_level: 5,
            max_ttl: 86_400,
        }
    }

    fn root_der(signer: &MockSigner) -> Vec<u8> {
        let req = CaRequest {
            subject: "CN=Tessera Root".to_owned(),
            subject_spki_der: crate::test_support::spki_fixture(),
            validity: IssueValidity {
                not_before: 1_600_000_000,
                not_after: 1_900_000_000,
            },
            constraints: envelope(),
            profile_version: 1,
        };
        crate::test_support::self_signed_ca(
            signer,
            &key(),
            &req,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .unwrap()
        .der
    }

    /// Extract the `TBSCertificate` bytes from a full certificate DER.
    fn tbs_of(cert_der: &[u8]) -> Vec<u8> {
        let outer = read_tlv_expect(cert_der, TAG_SEQUENCE).unwrap();
        let start = outer.value;
        let tbs = read_tlv_expect(start, TAG_SEQUENCE).unwrap();
        let consumed = start.len() - tbs.rest.len();
        start[..consumed].to_vec()
    }

    #[test]
    fn parses_a_leaf_tbs() {
        let signer = MockSigner::ecdsa_sha256(key());
        let root = root_der(&signer);
        let leaf_req = LeafRequest {
            subject: "CN=ivanov".to_owned(),
            subject_spki_der: crate::test_support::spki_fixture(),
            validity: IssueValidity {
                not_before: 1_600_000_000,
                not_after: 1_600_003_600,
            },
            host_binding: vec!["*".to_owned()],
            user_binding: vec!["oper".to_owned()],
            allowed_roles: vec!["oper".to_owned()],
            max_integrity: Some(IntegrityCeiling {
                level: 5,
                categories: 0,
            }),
            profile_version: 1,
        };
        let leaf = issue_leaf(
            &signer,
            &key(),
            &root,
            &leaf_req,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .unwrap();
        let summary = parse_operation_summary(&tbs_of(&leaf.der)).expect("leaf summary");
        assert_eq!(summary.kind, OperationKind::ShiftLeaf);
        assert!(summary.subject.contains("ivanov"), "{}", summary.subject);
        let rendered = summary.render(Locale::En);
        assert!(rendered.contains("shift-leaf"));
        assert!(rendered.contains("ivanov"));
        assert!(summary.lines.iter().any(|l| l.value.contains("oper")));

        // The Russian rendering translates captions but reproduces every value
        // byte-for-byte (the data never changes with locale).
        let ru = summary.render(Locale::Ru);
        assert!(ru.contains("сертификат смены"), "{ru}");
        assert!(ru.contains("ivanov"), "{ru}");
        assert!(
            summary.lines.iter().all(|l| ru.contains(l.value.as_str())),
            "{ru}"
        );
    }

    #[test]
    fn parses_a_ca_tbs() {
        let signer = MockSigner::ecdsa_sha256(key());
        let root = root_der(&signer);
        let ca_req = CaRequest {
            subject: "CN=Org CA".to_owned(),
            subject_spki_der: crate::test_support::spki_fixture(),
            validity: IssueValidity {
                not_before: 1_600_000_000,
                not_after: 1_800_000_000,
            },
            constraints: envelope(),
            profile_version: 1,
        };
        let ca = issue_ca(
            &signer,
            &key(),
            &root,
            &ca_req,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .unwrap();
        let summary = parse_operation_summary(&tbs_of(&ca.der)).expect("ca summary");
        assert_eq!(summary.kind, OperationKind::OrgCa);
        assert!(summary.subject.contains("Org CA"));
        assert!(summary.lines.iter().any(|l| l.caption == Caption::MaxLevel));
    }

    #[test]
    fn parses_a_crl_tbs() {
        let signer = MockSigner::ecdsa_sha256(key());
        let root = root_der(&signer);
        let req = CrlRequest {
            this_update: 1_600_000_000,
            next_update: Some(1_600_086_400),
            crl_number: 7,
            revoked: vec![RevokedEntry {
                serial: vec![0x2a],
                revocation_date: 1_600_000_500,
                reason: None,
            }],
        };
        let crl = issue_crl(&signer, &key(), &root, &req, 0, &mut fresh_journal(), TS).unwrap();
        let summary = parse_operation_summary(&tbs_of(&crl.der)).expect("crl summary");
        assert_eq!(summary.kind, OperationKind::Crl);
        assert!(
            summary
                .lines
                .iter()
                .any(|l| l.caption == Caption::CrlNumber && l.value == "7"),
            "{:?}",
            summary.lines
        );
    }

    #[test]
    fn render_neutralizes_bidi_control_in_subject() {
        // A subject carrying a right-to-left override and a pop marker: raw, it
        // could reorder the displayed distinguished name to spoof the operator.
        let summary = OperationSummary {
            kind: OperationKind::ShiftLeaf,
            subject: "CN=admin\u{202E}elor\u{202C}, O=Corp".to_owned(),
            not_before: "a".to_owned(),
            not_after: "b".to_owned(),
            lines: vec![SummaryLine {
                caption: Caption::Users,
                value: "\u{2066}root\u{2069}".to_owned(),
            }],
        };
        let rendered = summary.render(Locale::En);
        // No raw bidi-control codepoint survives into the rendered text.
        for bad in ['\u{202E}', '\u{202C}', '\u{2066}', '\u{2069}'] {
            assert!(
                !rendered.contains(bad),
                "raw bidi control {:#06X} leaked into render",
                u32::from(bad)
            );
        }
        // The neutralized markers are shown instead, and ordinary characters of
        // the subject are preserved.
        assert!(rendered.contains("\\u202E"), "{rendered}");
        assert!(rendered.contains("\\u2069"), "{rendered}");
        assert!(rendered.contains("admin"), "{rendered}");
        assert!(rendered.contains("root"), "{rendered}");

        // The stored value is untouched — neutralization is display-only.
        assert!(summary.subject.contains('\u{202E}'));
    }

    #[test]
    fn rejects_garbage_tbs() {
        assert!(parse_operation_summary(b"not a der structure at all").is_err());
        assert!(parse_operation_summary(&[]).is_err());
        // A SEQUENCE whose first field is neither version [0] nor INTEGER.
        let bogus = encode_tlv(TAG_SEQUENCE, &encode_tlv(TAG_SEQUENCE, &[]));
        assert!(parse_operation_summary(&bogus).is_err());
    }
}

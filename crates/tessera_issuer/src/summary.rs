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
    PROFILE_VERSION_OID,
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
    /// Only the captions are translated, so a Russian and an English rendering
    /// carry byte-identical data. Values are reproduced verbatim except for
    /// bidi controls, C0/C1 controls and the `U+2028`/`U+2029` separators, which
    /// are shown as `\uXXXX` markers: a value must not be able to hide, truncate
    /// or forge a line of the summary the operator signs against.
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
            out.push_str(&neutralize_for_display(&self.subject));
            out.push('\n');
            out.push_str(Caption::Validity.text(locale));
            out.push_str(": ");
            out.push_str(&neutralize_for_display(&self.not_before));
            out.push_str(" .. ");
            out.push_str(&neutralize_for_display(&self.not_after));
        }
        for line in &self.lines {
            out.push_str("\n  ");
            out.push_str(line.caption.text(locale));
            out.push_str(": ");
            out.push_str(&neutralize_for_display(&line.value));
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
    // The complete `Bidi_Control=Yes` set: ten codepoints, no more and no less.
    // `ALM` is the one that hides from a category check — it is `Cf`, not `Cc`,
    // so a control-character filter walks straight past it while it still gives
    // neighbouring neutral characters a strong right-to-left direction.
    matches!(c,
        '\u{061C}'                       // ALM
        | '\u{200E}' | '\u{200F}'        // LRM, RLM
        | '\u{202A}'..='\u{202E}'        // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}') // LRI, RLI, FSI, PDI
}

/// Whether `c` must not reach an operator surface in its active form.
///
/// Two ways a value can lie to the operator, one predicate. Bidi controls
/// reorder what is displayed; the remaining codepoints hide or forge it. `NUL`
/// terminates the C string a pinentry renderer receives, so everything after it
/// silently vanishes from the dialog, and a line break lets a value grow a line
/// the operator reads as another field of the summary. Line breaks in a summary
/// belong to the renderer.
///
/// The set is spelled out rather than delegated to [`char::is_control`], which
/// covers C0 and C1 but not `U+2028`/`U+2029` — those are `Zl`/`Zp`, yet line
/// separators for a part of the renderers we feed.
fn needs_neutralizing(c: char) -> bool {
    is_bidi_control(c)
        || matches!(c,
            '\u{0000}'..='\u{001F}'      // C0 controls, including NUL and LF
            | '\u{007F}'                 // DEL
            | '\u{0080}'..='\u{009F}'    // C1 controls, invisible in a terminal
            | '\u{2028}' | '\u{2029}') // line and paragraph separators
}

/// Replaces every codepoint that could hide, truncate, forge, or visually
/// reorder a summary line with a visible `\uXXXX` marker, so what the operator
/// reads is what the TBS carries. The underlying [`OperationSummary`] value is
/// untouched — this neutralizes only what is shown, not the data itself.
///
/// One pass over one predicate: the marker is built from `\`, `u` and hex
/// digits, none of which the predicate matches, so a neutralized value never
/// needs a second pass.
fn neutralize_for_display(value: &str) -> String {
    if !value.contains(needs_neutralizing) {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if needs_neutralizing(c) {
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
///
/// The argument is masked to four bits, so the fallback digit below is
/// unreachable. It is kept rather than replaced by a panic because this runs on
/// the path to a signature; what it must never do is fire silently, since a
/// quiet `'0'` would complete the marker into a `\u00XX` shape carrying the very
/// codepoint the marker exists to expose.
fn hex_upper_nibble(nibble: u32) -> char {
    debug_assert!(nibble < 16, "callers must pass a four-bit nibble");
    char::from_digit(nibble & 0xF, 16).map_or('0', |c| c.to_ascii_uppercase())
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
                caption: Caption::Roles,
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

    /// A summary whose lines carry `value` as the single role entry.
    fn summary_with_role(value: &str) -> OperationSummary {
        OperationSummary {
            kind: OperationKind::ShiftLeaf,
            subject: "CN=ivanov".to_owned(),
            not_before: "2020-09-13".to_owned(),
            not_after: "2020-09-14".to_owned(),
            lines: vec![SummaryLine {
                caption: Caption::Roles,
                value: value.to_owned(),
            }],
        }
    }

    /// Every codepoint the renderer must not display raw.
    fn neutralized_set() -> Vec<char> {
        let ranges = [
            0x0000..=0x001F,
            0x007F..=0x007F,
            0x0080..=0x009F,
            0x061C..=0x061C,
            0x200E..=0x200F,
            0x202A..=0x202E,
            0x2028..=0x2029,
            0x2066..=0x2069,
        ];
        ranges
            .into_iter()
            .flatten()
            .filter_map(char::from_u32)
            .collect()
    }

    #[test]
    fn render_neutralizes_nul_and_keeps_the_rest_of_the_summary() {
        // A NUL reaches pinentry as a real byte (the Assuan escaping is
        // reversible) and terminates the C string it renders, so everything
        // after it would silently disappear from the operator's dialog.
        let summary = summary_with_role("root\u{0000}hidden");
        let rendered = summary.render(Locale::En);

        assert!(
            !rendered.contains('\u{0000}'),
            "raw NUL leaked: {rendered:?}"
        );
        assert!(rendered.contains("\\u0000"), "{rendered}");
        assert!(rendered.contains("hidden"), "{rendered}");
        // Lines that follow the role in the rendered block survive intact.
        assert!(rendered.contains("CN=ivanov"), "{rendered}");
        assert!(rendered.contains("2020-09-14"), "{rendered}");
        // Display-only: the parsed summary still carries the original bytes.
        assert!(summary.lines[0].value.contains('\u{0000}'));
    }

    #[test]
    fn render_line_count_is_owned_by_the_renderer() {
        let clean = summary_with_role("root").render(Locale::En);
        for forged in [
            "root\nRoles: admin",
            "root\u{2028}Roles: admin",
            "root\u{000D}Roles: admin",
            "root\u{2029}Roles: admin",
        ] {
            let rendered = summary_with_role(forged).render(Locale::En);
            assert_eq!(
                rendered.lines().count(),
                clean.lines().count(),
                "value {forged:?} added a summary line: {rendered}"
            );
        }
    }

    /// This one has no red phase by construction: it guards against the
    /// neutralized set *growing* — someone reaching for `char::is_control` or
    /// "escape everything unprintable" and turning ordinary Cyrillic summaries
    /// into a wall of markers. It never reproduced a defect and never will.
    #[test]
    fn render_leaves_ordinary_values_byte_for_byte() {
        let value = "CN=Иванов И. И., O=ООО «Ромашка»; roles: oper, admin (v1) — 100%";
        let summary = summary_with_role(value);
        let rendered = summary.render(Locale::En);
        assert!(rendered.contains(value), "{rendered}");
        assert_eq!(neutralize_for_display(value), value);
    }

    #[test]
    fn render_keeps_the_characters_bordering_the_neutralized_ranges() {
        // The characters immediately outside each neutralized range. An
        // off-by-one in a range bound shows up here and nowhere else: the other
        // tests all aim at the middle of a range. Two range edges have no free
        // neighbour and so cannot be listed — `DEL` is followed by the C1 block,
        // and the bidi run at `U+202A` is preceded by `U+2029`.
        //
        // Passing here says only that a character is outside the neutralized
        // set, not that it is harmless: the invisible `Cf` codepoints (`ZWJ`
        // among them) and homoglyphs are deliberately out of scope, because no
        // list of codepoints closes that class.
        let borders = [
            '\u{0020}', // SPACE, right after the C0 block
            '\u{007E}', // TILDE, right before DEL
            '\u{00A0}', // NBSP, right after the C1 block
            '\u{061B}', // ARABIC SEMICOLON, right before ALM
            '\u{061D}', // right after ALM
            '\u{200D}', // ZWJ, right before LRM
            '\u{2010}', // HYPHEN, right after RLM
            '\u{2027}', // HYPHENATION POINT, right before U+2028
            '\u{202F}', // NARROW NBSP, right after RLO
            '\u{2065}', // right before LRI
            '\u{206A}', // right after PDI
        ];
        for c in borders {
            let value = c.to_string();
            assert_eq!(
                neutralize_for_display(&value),
                value,
                "border character {:#06X} was neutralized",
                u32::from(c)
            );
            let rendered = summary_with_role(&value).render(Locale::En);
            assert!(
                rendered.contains(c),
                "border character {:#06X} did not survive render: {rendered:?}",
                u32::from(c)
            );
        }
    }

    #[test]
    fn neutralization_marker_uses_only_hex_digits() {
        for c in neutralized_set() {
            let marker = neutralize_for_display(&c.to_string());
            let digits = marker
                .strip_prefix("\\u")
                .unwrap_or_else(|| panic!("no marker for {:#06X}: {marker:?}", u32::from(c)));
            assert_eq!(digits.len(), 4, "{:#06X} -> {marker:?}", u32::from(c));
            assert!(
                digits.chars().all(|d| matches!(d, '0'..='9' | 'A'..='F')),
                "{:#06X} -> {marker:?}",
                u32::from(c)
            );
            // The marker is built only from characters the predicate lets
            // through, so a rendered value never needs a second pass.
            assert!(
                !marker.contains(needs_neutralizing),
                "{:#06X} -> {marker:?}",
                u32::from(c)
            );
        }
    }

    #[test]
    fn render_neutralizes_c1_controls() {
        // C1 controls are invisible in a terminal, so a value carrying one
        // reads as clean while the byte still reaches the renderer.
        let summary = summary_with_role("root\u{0085}admin");
        let rendered = summary.render(Locale::En);
        assert!(!rendered.contains('\u{0085}'), "{rendered:?}");
        assert!(rendered.contains("\\u0085"), "{rendered}");
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

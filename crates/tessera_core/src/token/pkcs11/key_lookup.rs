//! PKCS#11 private-key object lookup (Task T09).
//!
//! [`Pkcs11Session::find_private_key_for_cert`] runs a `C_FindObjects`
//! query for `CKO_PRIVATE_KEY` constrained by the `CKA_ID` of the
//! certificate object discovered earlier (T08).  The convention in
//! PKCS#11 is to set the same `CKA_ID` on every key/cert pair belonging
//! to the same identity, which is how we find the right private key
//! without ever leaving the token.
//!
//! The function then reads back `CKA_KEY_TYPE` and `CKA_EXTRACTABLE` so
//! the next step (mechanism selection — T11) can decide which signing
//! mechanism to use, and so the mode-B invariant ("private key never
//! leaves the token") can be enforced when a misconfigured token ships
//! with an extractable private key.
//!
//! # Extractable-key policy
//!
//! `CKA_EXTRACTABLE = TRUE` breaks the mode-B invariant, so by default
//! the lookup fails closed with [`Pkcs11Error::ExtractableKeyRejected`].
//! Operators who knowingly run such tokens can opt out with
//! `pkcs11_allow_extractable_keys = true`, which downgrades the refusal
//! to the WARN below.
//!
//! A provider is not obliged to answer at all: `C_GetAttributeValue` may
//! report the attribute as sensitive, as not applicable to the object, or
//! as unavailable, and the `cryptoki` wrapper then simply omits it from
//! the returned attribute list.  Treating that silence as "the key is
//! non-extractable" would leave the invariant resting on the provider's
//! good will, so it is a third, distinct state
//! ([`ExtractableState::Unavailable`]) which also fails closed — with its
//! own error ([`Pkcs11Error::ExtractableAttributeUnavailable`]) and its
//! own WARN, so the audit trail never confuses "not reported" with
//! "reported extractable".
//!
//! Before refusing on that third state the lookup takes a second look.
//! The value read asks for `CKA_KEY_TYPE` and `CKA_EXTRACTABLE` in one
//! template, and a provider may fail a whole template because of one
//! entry while answering a single-attribute request for the same value
//! perfectly well.  So when the size query says the attribute *is*
//! readable, `CKA_EXTRACTABLE` is re-read on its own; a successful
//! single-attribute read is direct evidence and is honoured as such.
//!
//! The two escape hatches are independent, because the situations are:
//! `pkcs11_allow_extractable_keys` governs a key that says it is
//! exportable, `pkcs11_allow_unreported_extractable` governs a token that
//! will not say.  Neither key implies the other.
//!
//! # Logging
//!
//! - `pkcs11_extractable_key`: WARN — the matched private key has
//!   `CKA_EXTRACTABLE = TRUE` but `pkcs11_allow_extractable_keys = true`
//!   lets it through.  Production deployments should treat this line as
//!   an audit finding.
//! - `pkcs11_extractable_attribute_unavailable`: WARN — the token did not
//!   report `CKA_EXTRACTABLE`, and the single-attribute re-read did not
//!   establish it either, so non-extractability could not be proven;
//!   `pkcs11_allow_unreported_extractable = true` lets it through.  The
//!   `probe` field carries the reason the provider gave.
//! - `pkcs11_multiple_private_keys`: WARN — more than one private key
//!   shares the same `CKA_ID`.  We pick the first and continue.
//!
//! No raw bytes (`CKA_ID`, key material) ever land in log lines — only
//! lengths and a short hex prefix when needed for correlation.

use std::fmt;

use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::Session;
use tracing::warn;

use super::backend::LockingMode;
use super::cert_lookup::FoundCertificate;
use super::error::Pkcs11Error;
use super::locking::with_global_lock;
use super::session::Pkcs11Session;

/// What the token said about `CKA_EXTRACTABLE` for a private key.
///
/// A provider may decline to report the attribute; that is neither `No`
/// nor `Yes` and must not be collapsed into either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractableState {
    /// `CKA_EXTRACTABLE = FALSE` — the key cannot leave the token.
    No,
    /// `CKA_EXTRACTABLE = TRUE` — the key can be exported.
    Yes,
    /// The token returned no value for `CKA_EXTRACTABLE`, so nothing is
    /// known about extractability.
    Unavailable,
}

impl fmt::Display for ExtractableState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match *self {
            Self::No => "no",
            Self::Yes => "yes",
            Self::Unavailable => "unavailable",
        };
        f.write_str(text)
    }
}

/// Why the token did not return a value for `CKA_EXTRACTABLE`.
///
/// Obtained from a follow-up `C_GetAttributeValue` size query on the cold
/// path where the attribute was missing from the value read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractableProbe {
    /// The token considers the attribute sensitive and withholds it.
    Sensitive,
    /// The token does not consider the attribute valid for this object.
    TypeInvalid,
    /// The token reports the attribute as unavailable.
    Unavailable,
    /// The token reports the attribute as readable even though the batched
    /// value read omitted it.  This is what a provider looks like when it
    /// fails a whole template over one entry, so it is not a refusal — it
    /// is the signal to re-read `CKA_EXTRACTABLE` on its own.
    Available,
    /// The follow-up query itself failed.
    Failed,
}

impl fmt::Display for ExtractableProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match *self {
            Self::Sensitive => "sensitive",
            Self::TypeInvalid => "type_invalid",
            Self::Unavailable => "unavailable",
            Self::Available => "available_but_not_returned",
            Self::Failed => "probe_failed",
        };
        f.write_str(text)
    }
}

/// A value the token actually gave for `CKA_EXTRACTABLE`.
///
/// Deliberately narrower than [`ExtractableState`]: it has no "unknown"
/// case, so a resolved re-check cannot claim to have established a value
/// while carrying none.  Without that, the policy code would have to
/// invent a probe reason for a token that never gave one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtractableAnswer {
    /// `CKA_EXTRACTABLE = FALSE`.
    No,
    /// `CKA_EXTRACTABLE = TRUE`.
    Yes,
}

/// Result of the second look at `CKA_EXTRACTABLE` on the cold path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtractableRecheck {
    /// A single-attribute read established the value after all.
    Resolved(ExtractableAnswer),
    /// Extractability remains unknown; the reason the token gave.
    Unresolved(ExtractableProbe),
}

/// Operator policy for private keys whose non-extractability is not
/// established by the token.
///
/// Both fields default to `false` (refuse), and they are independent:
/// a token that merely withholds the attribute must not force the
/// operator to also accept keys that admit to being exportable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtractableKeyPolicy {
    /// Accept a key that reports `CKA_EXTRACTABLE = TRUE`
    /// (`pkcs11_allow_extractable_keys`).
    pub allow_extractable: bool,
    /// Accept a key whose token returns no `CKA_EXTRACTABLE` value
    /// (`pkcs11_allow_unreported_extractable`).
    pub allow_unreported: bool,
}

/// A private-key object discovered on the token.
#[derive(Debug)]
pub struct FoundPrivateKey {
    /// Raw `CK_OBJECT_HANDLE` of the private-key object.
    pub object: ObjectHandle,
    /// `CKA_KEY_TYPE` (RSA, EC, GOSTR3410, ...).
    pub key_type: KeyType,
    /// What the token established about `CKA_EXTRACTABLE`, after the
    /// single-attribute re-read where one was warranted.
    ///
    /// Anything other than [`ExtractableState::No`] can only appear here
    /// when the operator opted in through the matching config key; under
    /// the default policy both a `Yes` and an unreported attribute abort
    /// the lookup.  [`ExtractableState::Unavailable`] is reported as-is
    /// and never rewritten to `No`: the token declined to answer, which is
    /// not the same as answering "not extractable".
    pub extractable: ExtractableState,
}

/// Pure-attribute view used by [`Pkcs11Session::find_private_key_for_cert`].
///
/// Excludes the [`ObjectHandle`] (which the live caller already owns)
/// so the parser can be unit-tested without a real PKCS#11 provider —
/// cryptoki 0.7 keeps `ObjectHandle::new` crate-private, so we cannot
/// synthesize a handle from outside the crate.
#[derive(Debug)]
pub(crate) struct ParsedPrivateKey {
    /// `CKA_KEY_TYPE`.
    pub key_type: KeyType,
    /// `CKA_EXTRACTABLE`, or [`ExtractableState::Unavailable`] when the
    /// attribute is absent from the read.
    pub extractable: ExtractableState,
}

/// Pure attribute parser used by [`Pkcs11Session::find_private_key_for_cert`].
///
/// An absent `CKA_EXTRACTABLE` yields [`ExtractableState::Unavailable`],
/// never `No`: `cryptoki` drops attributes the token refuses to return, so
/// absence carries no information about the key.
///
/// # Errors
///
/// - [`Pkcs11Error::KeyTypeAttributeMissing`] when `CKA_KEY_TYPE` is not
///   present in `attrs`.
fn parse_private_key_attributes(attrs: &[Attribute]) -> Result<ParsedPrivateKey, Pkcs11Error> {
    let extractable = extractable_state(attrs);
    let key_type = attrs
        .iter()
        .find_map(|attr| match *attr {
            Attribute::KeyType(kt) => Some(kt),
            _ => None,
        })
        .ok_or(Pkcs11Error::KeyTypeAttributeMissing)?;
    Ok(ParsedPrivateKey {
        key_type,
        extractable,
    })
}

/// Read `CKA_EXTRACTABLE` out of an attribute list.
///
/// Absence maps to [`ExtractableState::Unavailable`], never `No`.
fn extractable_state(attrs: &[Attribute]) -> ExtractableState {
    attrs
        .iter()
        .find_map(|attr| match *attr {
            Attribute::Extractable(true) => Some(ExtractableState::Yes),
            Attribute::Extractable(false) => Some(ExtractableState::No),
            _ => None,
        })
        .unwrap_or(ExtractableState::Unavailable)
}

/// Enforce the mode-B non-extractable invariant on a matched key.
///
/// Keys that report `CKA_EXTRACTABLE = FALSE` always pass.  A key that
/// reports `TRUE` is rejected unless `policy.allow_extractable`; a key
/// whose token would not report the attribute at all is rejected unless
/// `policy.allow_unreported`.  Each opt-in only covers its own case and
/// downgrades the refusal to a WARN under its own event name.
///
/// `recheck` is consulted only when the value read carried no
/// `CKA_EXTRACTABLE`.  It takes a second look at the attribute on its own
/// and may still establish the value; it is deliberately lazy, because it
/// costs further FFI round-trips that a conforming provider never
/// triggers.  A value it establishes is treated exactly like one from the
/// first read — including a `TRUE`, which lands on the extractable-key
/// refusal rather than the unreported one.
///
/// # Errors
///
/// - [`Pkcs11Error::ExtractableKeyRejected`] when `CKA_EXTRACTABLE = TRUE`
///   and `policy.allow_extractable` is `false`.
/// - [`Pkcs11Error::ExtractableAttributeUnavailable`] when no read
///   established `CKA_EXTRACTABLE` and `policy.allow_unreported` is
///   `false`.
fn enforce_extractable_policy(
    parsed: &ParsedPrivateKey,
    policy: ExtractableKeyPolicy,
    cka_id: &[u8],
    recheck: impl FnOnce() -> ExtractableRecheck,
) -> Result<ExtractableState, Pkcs11Error> {
    // Either the token answered — and then the answer cannot be "unknown"
    // — or it did not, and then there is always a reason to report.  The
    // two are mutually exclusive by construction, so no arm below has to
    // guess at a missing half.
    let answer = match parsed.extractable {
        ExtractableState::No => Ok(ExtractableAnswer::No),
        ExtractableState::Yes => Ok(ExtractableAnswer::Yes),
        ExtractableState::Unavailable => match recheck() {
            ExtractableRecheck::Resolved(answer) => Ok(answer),
            ExtractableRecheck::Unresolved(probe) => Err(probe),
        },
    };

    match answer {
        Ok(ExtractableAnswer::No) => Ok(ExtractableState::No),
        Ok(ExtractableAnswer::Yes) => {
            if !policy.allow_extractable {
                return Err(Pkcs11Error::ExtractableKeyRejected {
                    key_type: parsed.key_type.to_string(),
                    cka_id_hex: cka_id_log_prefix(cka_id),
                });
            }
            warn!(
                target: "tessera.pkcs11",
                key_type = %parsed.key_type,
                cka_id_prefix = %cka_id_log_prefix(cka_id),
                "pkcs11_extractable_key"
            );
            Ok(ExtractableState::Yes)
        }
        Err(probe) => {
            if !policy.allow_unreported {
                return Err(Pkcs11Error::ExtractableAttributeUnavailable {
                    key_type: parsed.key_type.to_string(),
                    cka_id_hex: cka_id_log_prefix(cka_id),
                    probe,
                });
            }
            warn!(
                target: "tessera.pkcs11",
                key_type = %parsed.key_type,
                cka_id_prefix = %cka_id_log_prefix(cka_id),
                probe = %probe,
                "pkcs11_extractable_attribute_unavailable"
            );
            Ok(ExtractableState::Unavailable)
        }
    }
}

/// Take a second look at `CKA_EXTRACTABLE` after a read that omitted it.
///
/// First asks the token *why* it withheld the value.  If the token says
/// the attribute is readable after all, the value is re-read on its own:
/// the first read batches `CKA_KEY_TYPE` and `CKA_EXTRACTABLE` into one
/// template, and a provider may fail an entire template because of one
/// entry while answering a single-attribute request correctly.  A
/// successful single-attribute read is direct evidence about the key, not
/// an inference from provider behaviour, so it is honoured.
///
/// Both calls run under [`with_global_lock`] like every other cryptoki
/// call in this module: some providers take the process down when entered
/// from two threads at once, and an unserialized call here would be
/// exactly such an entry.
fn recheck_extractable_attribute(
    session: &Session,
    mode: LockingMode,
    handle: ObjectHandle,
) -> ExtractableRecheck {
    let probe = probe_extractable_attribute(session, mode, handle);
    if probe != ExtractableProbe::Available {
        return ExtractableRecheck::Unresolved(probe);
    }
    let attrs = with_global_lock(mode, || {
        session.get_attributes(handle, &[AttributeType::Extractable])
    });
    // `Ok(_)` and `Err(_)` mean different things to the operator, so the
    // error is not folded into "the read carried no value".
    let reread = attrs.as_deref().ok().map(extractable_state);
    resolve_extractable_recheck(probe, reread)
}

/// Ask the token why it did not return `CKA_EXTRACTABLE` for `handle`.
///
/// Serialized like every other cryptoki call in this module; the
/// classification itself lives in [`classify_extractable_info`].
fn probe_extractable_attribute(
    session: &Session,
    mode: LockingMode,
    handle: ObjectHandle,
) -> ExtractableProbe {
    let info = with_global_lock(mode, || {
        session.get_attribute_info(handle, &[AttributeType::Extractable])
    });
    classify_extractable_info(info.as_deref().map_err(|_| ()))
}

/// Map a single-attribute `C_GetAttributeValue` size query onto a probe.
///
/// A list of any length other than one, and a failed call, are equally
/// uninformative: the provider did not answer the question that was asked.
fn classify_extractable_info(info: Result<&[AttributeInfo], ()>) -> ExtractableProbe {
    match info {
        Ok([AttributeInfo::Sensitive]) => ExtractableProbe::Sensitive,
        Ok([AttributeInfo::TypeInvalid]) => ExtractableProbe::TypeInvalid,
        Ok([AttributeInfo::Unavailable]) => ExtractableProbe::Unavailable,
        Ok([AttributeInfo::Available(_)]) => ExtractableProbe::Available,
        Ok(_) | Err(()) => ExtractableProbe::Failed,
    }
}

/// Decide the cold-path outcome from the probe and the re-read it may
/// have warranted.
///
/// `reread` is `None` when the single-attribute read itself failed, and
/// `Some(Unavailable)` when it succeeded but still carried no value.  Only
/// a re-read that actually produced a value resolves the question; the
/// other two leave the key unproven under *different* reasons, because
/// "the call failed" and "the token withheld it again" are different
/// facts about the provider and the operator reads that field to tell
/// them apart.
fn resolve_extractable_recheck(
    probe: ExtractableProbe,
    reread: Option<ExtractableState>,
) -> ExtractableRecheck {
    if probe != ExtractableProbe::Available {
        return ExtractableRecheck::Unresolved(probe);
    }
    match reread {
        Some(ExtractableState::No) => ExtractableRecheck::Resolved(ExtractableAnswer::No),
        Some(ExtractableState::Yes) => ExtractableRecheck::Resolved(ExtractableAnswer::Yes),
        Some(ExtractableState::Unavailable) => ExtractableRecheck::Unresolved(probe),
        None => ExtractableRecheck::Unresolved(ExtractableProbe::Failed),
    }
}

/// Hex-encode (lowercase) the leading 4 bytes of `id` for log correlation.
///
/// Matches the policy in `secret.rs` of *not* logging full identifiers
/// even when the underlying spec considers them public — the PAM event
/// log is shipped to operators who don't need raw token internals.
fn cka_id_log_prefix(id: &[u8]) -> String {
    use std::fmt::Write as _;
    let take = id.len().min(4);
    let mut out = String::with_capacity(take * 2 + 4);
    for byte in id.iter().take(take) {
        // Hex formatting into a String never errors.
        #[allow(clippy::let_underscore_must_use)]
        let _ = write!(out, "{byte:02x}");
    }
    if id.len() > take {
        out.push_str("...");
    }
    out
}

impl Pkcs11Session {
    /// Find the private key object that pairs with `cert` (matched by
    /// `CKA_ID`).
    ///
    /// `policy` mirrors the two config keys
    /// `pkcs11_allow_extractable_keys` and
    /// `pkcs11_allow_unreported_extractable`.  With the default (both
    /// `false`) a key that is extractable, and a key whose token would not
    /// say, are each rejected (fail-closed); each key on its own downgrades
    /// its own case to a WARN and leaves the other refusal standing.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11Error::PrivateKeyNotFound`] when no private-key object
    ///   matches the certificate's `CKA_ID`.
    /// - [`Pkcs11Error::KeyTypeAttributeMissing`] when the matched object
    ///   reports no `CKA_KEY_TYPE`.
    /// - [`Pkcs11Error::ExtractableKeyRejected`] when the matched key has
    ///   `CKA_EXTRACTABLE = TRUE` and `policy.allow_extractable` is `false`.
    /// - [`Pkcs11Error::ExtractableAttributeUnavailable`] when neither the
    ///   batched read nor the single-attribute re-read established
    ///   `CKA_EXTRACTABLE` — so non-extractability could not be shown — and
    ///   `policy.allow_unreported` is `false`.
    /// - [`Pkcs11Error::Cryptoki`] for any FFI failure from
    ///   `C_FindObjects` / `C_GetAttributeValue`.
    pub fn find_private_key_for_cert(
        &self,
        cert: &FoundCertificate,
        policy: ExtractableKeyPolicy,
    ) -> Result<FoundPrivateKey, Pkcs11Error> {
        let session = self.raw().ok_or(Pkcs11Error::PrivateKeyNotFound {
            cka_id_hex: cka_id_log_prefix(&cert.cka_id),
        })?;

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(cert.cka_id.clone()),
        ];

        let mode = self.locking_mode();
        let handles = with_global_lock(mode, || session.find_objects(&template))?;
        if handles.is_empty() {
            return Err(Pkcs11Error::PrivateKeyNotFound {
                cka_id_hex: cka_id_log_prefix(&cert.cka_id),
            });
        }
        if handles.len() > 1 {
            warn!(
                target: "tessera.pkcs11",
                count = handles.len(),
                cka_id_prefix = %cka_id_log_prefix(&cert.cka_id),
                "pkcs11_multiple_private_keys"
            );
        }
        // Safe: just verified handles is non-empty.
        let Some(handle) = handles.into_iter().next() else {
            return Err(Pkcs11Error::PrivateKeyNotFound {
                cka_id_hex: cka_id_log_prefix(&cert.cka_id),
            });
        };

        let attrs = with_global_lock(mode, || {
            session.get_attributes(
                handle,
                &[AttributeType::KeyType, AttributeType::Extractable],
            )
        })?;
        let parsed = parse_private_key_attributes(&attrs)?;
        let extractable = enforce_extractable_policy(&parsed, policy, &cert.cka_id, || {
            recheck_extractable_attribute(session, mode, handle)
        })?;
        Ok(FoundPrivateKey {
            object: handle,
            key_type: parsed.key_type,
            extractable,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::err_expect,
        clippy::panic,
        clippy::unwrap_used
    )]

    use super::*;
    use cryptoki::object::{Attribute, AttributeInfo, KeyType};

    /// Recheck stand-in for the tests that must never reach the cold path.
    fn recheck_must_not_run() -> ExtractableRecheck {
        panic!("the second look must only happen when the value read carried no CKA_EXTRACTABLE");
    }

    /// Recheck stand-in that gives up with `probe` as the reason.
    fn unresolved(probe: ExtractableProbe) -> impl FnOnce() -> ExtractableRecheck {
        move || ExtractableRecheck::Unresolved(probe)
    }

    /// Recheck stand-in where the single-attribute read succeeded.
    fn resolved(answer: ExtractableAnswer) -> impl FnOnce() -> ExtractableRecheck {
        move || ExtractableRecheck::Resolved(answer)
    }

    /// Both opt-ins off — the shipped default.
    const FAIL_CLOSED: ExtractableKeyPolicy = ExtractableKeyPolicy {
        allow_extractable: false,
        allow_unreported: false,
    };
    /// Only `pkcs11_allow_extractable_keys`.
    const ALLOW_EXTRACTABLE: ExtractableKeyPolicy = ExtractableKeyPolicy {
        allow_extractable: true,
        allow_unreported: false,
    };
    /// Only `pkcs11_allow_unreported_extractable`.
    const ALLOW_UNREPORTED: ExtractableKeyPolicy = ExtractableKeyPolicy {
        allow_extractable: false,
        allow_unreported: true,
    };
    /// Both opt-ins on.
    const ALLOW_BOTH: ExtractableKeyPolicy = ExtractableKeyPolicy {
        allow_extractable: true,
        allow_unreported: true,
    };

    #[test]
    fn parses_rsa_with_extractable_false() {
        let attrs = vec![
            Attribute::KeyType(KeyType::RSA),
            Attribute::Extractable(false),
        ];
        let parsed = parse_private_key_attributes(&attrs).expect("parse");
        assert_eq!(parsed.key_type, KeyType::RSA);
        assert_eq!(parsed.extractable, ExtractableState::No);
    }

    #[test]
    fn parses_ec_with_extractable_true() {
        let attrs = vec![
            Attribute::KeyType(KeyType::EC),
            Attribute::Extractable(true),
        ];
        let parsed = parse_private_key_attributes(&attrs).expect("parse");
        assert_eq!(parsed.key_type, KeyType::EC);
        assert_eq!(parsed.extractable, ExtractableState::Yes);
    }

    #[test]
    fn parses_gostr3410() {
        let attrs = vec![Attribute::KeyType(KeyType::GOSTR3410)];
        let parsed = parse_private_key_attributes(&attrs).expect("parse");
        assert_eq!(parsed.key_type, KeyType::GOSTR3410);
        // The provider returned no CKA_EXTRACTABLE, which says nothing
        // about the key — it must never be read as "not extractable".
        assert_eq!(parsed.extractable, ExtractableState::Unavailable);
    }

    #[test]
    fn missing_key_type_is_error() {
        let attrs = vec![Attribute::Extractable(false)];
        let err = parse_private_key_attributes(&attrs)
            .err()
            .expect("must fail");
        assert!(matches!(err, Pkcs11Error::KeyTypeAttributeMissing));
    }

    #[test]
    fn dropped_extractable_and_dropped_whole_template_are_distinguishable() {
        // A provider that fails one template entry and one that fails the
        // whole template look alike in the returned list length but not in
        // what they mean, so the parser must not collapse them.
        let only_key_type = parse_private_key_attributes(&[Attribute::KeyType(KeyType::RSA)])
            .expect("CKA_KEY_TYPE alone is enough to parse");
        assert_eq!(only_key_type.key_type, KeyType::RSA);
        assert_eq!(only_key_type.extractable, ExtractableState::Unavailable);

        let err = parse_private_key_attributes(&[])
            .err()
            .expect("an empty read cannot yield a key type");
        assert!(matches!(err, Pkcs11Error::KeyTypeAttributeMissing));
    }

    #[test]
    fn default_policy_is_fail_closed() {
        // The shipped default must refuse both cases; a flipped default
        // would silently weaken the mode-B invariant for every deployment.
        assert_eq!(ExtractableKeyPolicy::default(), FAIL_CLOSED);
    }

    #[test]
    fn ignores_unrelated_attributes() {
        let attrs = vec![
            Attribute::KeyType(KeyType::EC),
            Attribute::Sign(true),
            Attribute::Token(true),
            Attribute::Extractable(false),
        ];
        let parsed = parse_private_key_attributes(&attrs).expect("parse");
        assert_eq!(parsed.key_type, KeyType::EC);
        assert_eq!(parsed.extractable, ExtractableState::No);
    }

    #[test]
    fn extractable_key_rejected_by_default() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::RSA,
            extractable: ExtractableState::Yes,
        };
        let err = enforce_extractable_policy(
            &parsed,
            FAIL_CLOSED,
            b"\xde\xad\xbe\xef\xca\xfe",
            recheck_must_not_run,
        )
        .err()
        .expect("must fail closed");
        match err {
            Pkcs11Error::ExtractableKeyRejected {
                key_type,
                cka_id_hex,
            } => {
                assert_eq!(key_type, KeyType::RSA.to_string());
                // Short prefix only — never the full CKA_ID bytes.
                assert_eq!(cka_id_hex, "deadbeef...");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn extractable_key_allowed_when_operator_opted_in() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::EC,
            extractable: ExtractableState::Yes,
        };
        // Opt-out path: WARN only, lookup continues.
        let state = enforce_extractable_policy(
            &parsed,
            ALLOW_EXTRACTABLE,
            b"\x01\x02",
            recheck_must_not_run,
        )
        .expect("opt-in must pass");
        // The caller learns what the token actually said, not a laundered
        // "no" — `FoundPrivateKey.extractable` feeds the audit trail.
        assert_eq!(state, ExtractableState::Yes);
    }

    #[test]
    fn unavailable_extractable_attribute_rejected_by_default() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::GOSTR3410,
            extractable: ExtractableState::Unavailable,
        };
        let err = enforce_extractable_policy(
            &parsed,
            FAIL_CLOSED,
            b"\xde\xad\xbe\xef\xca\xfe",
            unresolved(ExtractableProbe::TypeInvalid),
        )
        .err()
        .expect("must fail closed");
        match err {
            Pkcs11Error::ExtractableAttributeUnavailable {
                key_type,
                cka_id_hex,
                probe,
            } => {
                assert_eq!(key_type, KeyType::GOSTR3410.to_string());
                assert_eq!(cka_id_hex, "deadbeef...");
                assert_eq!(probe, ExtractableProbe::TypeInvalid);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unresolved_recheck_carries_its_own_probe_into_the_error() {
        // Whatever the token said must survive verbatim into the error, or
        // the operator cannot tell a sensitive attribute from a dead probe.
        for probe in [
            ExtractableProbe::Sensitive,
            ExtractableProbe::TypeInvalid,
            ExtractableProbe::Unavailable,
            ExtractableProbe::Available,
            ExtractableProbe::Failed,
        ] {
            let parsed = ParsedPrivateKey {
                key_type: KeyType::EC,
                extractable: ExtractableState::Unavailable,
            };
            let err =
                enforce_extractable_policy(&parsed, FAIL_CLOSED, b"\x01\x02", unresolved(probe))
                    .err()
                    .expect("must fail closed");
            match err {
                Pkcs11Error::ExtractableAttributeUnavailable { probe: got, .. } => {
                    assert_eq!(got, probe);
                }
                other => panic!("unexpected error for {probe}: {other:?}"),
            }
        }
    }

    #[test]
    fn unavailable_extractable_attribute_is_not_reported_as_extractable_key() {
        // The two refusals must stay distinguishable in the audit trail.
        let parsed = ParsedPrivateKey {
            key_type: KeyType::EC,
            extractable: ExtractableState::Unavailable,
        };
        let err = enforce_extractable_policy(
            &parsed,
            FAIL_CLOSED,
            b"\x01\x02",
            unresolved(ExtractableProbe::Sensitive),
        )
        .err()
        .expect("must fail closed");
        assert!(!matches!(err, Pkcs11Error::ExtractableKeyRejected { .. }));
        let rendered = err.to_string();
        assert!(
            rendered.contains("did not report CKA_EXTRACTABLE"),
            "message must name the real cause: {rendered}"
        );
        assert!(
            rendered.contains("probe=sensitive"),
            "message must carry the provider's reason: {rendered}"
        );
    }

    #[test]
    fn unavailable_extractable_attribute_allowed_when_operator_opted_in() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::EC,
            extractable: ExtractableState::Unavailable,
        };
        let state = enforce_extractable_policy(
            &parsed,
            ALLOW_UNREPORTED,
            b"\x01\x02",
            unresolved(ExtractableProbe::Unavailable),
        )
        .expect("opt-in must pass");
        // Still `Unavailable` — the opt-in waives the refusal, not the fact.
        assert_eq!(state, ExtractableState::Unavailable);
    }

    #[test]
    fn allowing_extractable_keys_does_not_allow_an_unreported_attribute() {
        // The two opt-ins cover different situations and must not leak into
        // each other: a token that will not answer is still refused.
        let parsed = ParsedPrivateKey {
            key_type: KeyType::RSA,
            extractable: ExtractableState::Unavailable,
        };
        let err = enforce_extractable_policy(
            &parsed,
            ALLOW_EXTRACTABLE,
            b"\x01\x02",
            unresolved(ExtractableProbe::Sensitive),
        )
        .err()
        .expect("allow_extractable must not cover an unreported attribute");
        assert!(matches!(
            err,
            Pkcs11Error::ExtractableAttributeUnavailable { .. }
        ));
    }

    #[test]
    fn allowing_an_unreported_attribute_does_not_allow_an_extractable_key() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::RSA,
            extractable: ExtractableState::Yes,
        };
        let err = enforce_extractable_policy(
            &parsed,
            ALLOW_UNREPORTED,
            b"\x01\x02",
            recheck_must_not_run,
        )
        .err()
        .expect("allow_unreported must not cover a confirmed CKA_EXTRACTABLE");
        assert!(matches!(err, Pkcs11Error::ExtractableKeyRejected { .. }));
    }

    #[test]
    fn policy_matrix_covers_both_flags_against_every_state() {
        // Expected outcome per (allow_extractable, allow_unreported) and the
        // state the token reported.  `None` means "must be refused".
        let cases = [
            (
                FAIL_CLOSED,
                ExtractableState::No,
                Some(ExtractableState::No),
            ),
            (FAIL_CLOSED, ExtractableState::Yes, None),
            (FAIL_CLOSED, ExtractableState::Unavailable, None),
            (
                ALLOW_EXTRACTABLE,
                ExtractableState::No,
                Some(ExtractableState::No),
            ),
            (
                ALLOW_EXTRACTABLE,
                ExtractableState::Yes,
                Some(ExtractableState::Yes),
            ),
            (ALLOW_EXTRACTABLE, ExtractableState::Unavailable, None),
            (
                ALLOW_UNREPORTED,
                ExtractableState::No,
                Some(ExtractableState::No),
            ),
            (ALLOW_UNREPORTED, ExtractableState::Yes, None),
            (
                ALLOW_UNREPORTED,
                ExtractableState::Unavailable,
                Some(ExtractableState::Unavailable),
            ),
            (ALLOW_BOTH, ExtractableState::No, Some(ExtractableState::No)),
            (
                ALLOW_BOTH,
                ExtractableState::Yes,
                Some(ExtractableState::Yes),
            ),
            (
                ALLOW_BOTH,
                ExtractableState::Unavailable,
                Some(ExtractableState::Unavailable),
            ),
        ];

        for (policy, reported, expected) in cases {
            let parsed = ParsedPrivateKey {
                key_type: KeyType::EC,
                extractable: reported,
            };
            let outcome = enforce_extractable_policy(
                &parsed,
                policy,
                b"\x01\x02",
                unresolved(ExtractableProbe::Sensitive),
            );
            match (expected, outcome) {
                (Some(want), Ok(got)) => assert_eq!(got, want, "{policy:?} + {reported}"),
                (None, Err(_)) => {}
                (Some(want), Err(err)) => {
                    panic!("{policy:?} + {reported}: expected {want}, got error {err:?}")
                }
                (None, Ok(got)) => panic!("{policy:?} + {reported}: expected refusal, got {got}"),
            }
        }
    }

    #[test]
    fn recheck_is_only_consulted_when_attribute_is_unavailable() {
        // The second look costs extra FFI round-trips, so a token that
        // answered the first time must never pay for it.
        for state in [ExtractableState::No, ExtractableState::Yes] {
            let parsed = ParsedPrivateKey {
                key_type: KeyType::EC,
                extractable: state,
            };
            // `recheck_must_not_run` panics if the cold path is entered.
            let got =
                enforce_extractable_policy(&parsed, ALLOW_BOTH, b"\x01\x02", recheck_must_not_run)
                    .expect("opt-in accepts both reported states");
            assert_eq!(got, state);
        }
    }

    #[test]
    fn recheck_resolving_to_false_accepts_the_key_under_the_default_policy() {
        // Single-attribute read succeeded where the batched one did not:
        // that is direct evidence, so the default policy must let it pass.
        let parsed = ParsedPrivateKey {
            key_type: KeyType::EC,
            extractable: ExtractableState::Unavailable,
        };
        let state = enforce_extractable_policy(
            &parsed,
            FAIL_CLOSED,
            b"\x01\x02",
            resolved(ExtractableAnswer::No),
        )
        .expect("a re-read that proves CKA_EXTRACTABLE = FALSE must pass");
        assert_eq!(state, ExtractableState::No);
    }

    #[test]
    fn recheck_resolving_to_true_lands_on_the_extractable_key_refusal() {
        // A value the re-read established is a value the token gave, so it
        // must be judged as such — not as "the token would not say".
        let parsed = ParsedPrivateKey {
            key_type: KeyType::RSA,
            extractable: ExtractableState::Unavailable,
        };
        let err = enforce_extractable_policy(
            &parsed,
            FAIL_CLOSED,
            b"\xde\xad\xbe\xef",
            resolved(ExtractableAnswer::Yes),
        )
        .err()
        .expect("must fail closed");
        match err {
            Pkcs11Error::ExtractableKeyRejected {
                key_type,
                cka_id_hex,
            } => {
                assert_eq!(key_type, KeyType::RSA.to_string());
                assert_eq!(cka_id_hex, "deadbeef");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn recheck_resolving_to_true_is_governed_by_the_extractable_opt_in() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::RSA,
            extractable: ExtractableState::Unavailable,
        };
        // The unreported opt-in does not cover it...
        let err = enforce_extractable_policy(
            &parsed,
            ALLOW_UNREPORTED,
            b"\x01\x02",
            resolved(ExtractableAnswer::Yes),
        )
        .err()
        .expect("allow_unreported must not cover a re-read that says TRUE");
        assert!(matches!(err, Pkcs11Error::ExtractableKeyRejected { .. }));
        // ...but the extractable-key one does.
        let state = enforce_extractable_policy(
            &parsed,
            ALLOW_EXTRACTABLE,
            b"\x01\x02",
            resolved(ExtractableAnswer::Yes),
        )
        .expect("allow_extractable must cover it");
        assert_eq!(state, ExtractableState::Yes);
    }

    #[test]
    fn non_extractable_key_passes_regardless_of_policy() {
        let parsed = ParsedPrivateKey {
            key_type: KeyType::EC,
            extractable: ExtractableState::No,
        };
        for policy in [FAIL_CLOSED, ALLOW_EXTRACTABLE, ALLOW_UNREPORTED, ALLOW_BOTH] {
            let state =
                enforce_extractable_policy(&parsed, policy, b"\x01\x02", recheck_must_not_run)
                    .unwrap_or_else(|err| panic!("{policy:?} must pass: {err:?}"));
            assert_eq!(state, ExtractableState::No);
        }
    }

    #[test]
    fn classifies_every_single_attribute_size_query_outcome() {
        assert_eq!(
            classify_extractable_info(Ok(&[AttributeInfo::Sensitive])),
            ExtractableProbe::Sensitive
        );
        assert_eq!(
            classify_extractable_info(Ok(&[AttributeInfo::TypeInvalid])),
            ExtractableProbe::TypeInvalid
        );
        assert_eq!(
            classify_extractable_info(Ok(&[AttributeInfo::Unavailable])),
            ExtractableProbe::Unavailable
        );
        assert_eq!(
            classify_extractable_info(Ok(&[AttributeInfo::Available(1)])),
            ExtractableProbe::Available
        );
        assert_eq!(
            classify_extractable_info(Err(())),
            ExtractableProbe::Failed,
            "a failed size query answers nothing"
        );
        // A list of the wrong length is equally uninformative: the provider
        // did not answer the single question that was asked.
        assert_eq!(
            classify_extractable_info(Ok(&[])),
            ExtractableProbe::Failed,
            "empty list"
        );
        assert_eq!(
            classify_extractable_info(Ok(&[AttributeInfo::Sensitive, AttributeInfo::Sensitive])),
            ExtractableProbe::Failed,
            "over-long list"
        );
    }

    #[test]
    fn recheck_resolves_only_on_a_re_read_that_produced_a_value() {
        // A refusing probe short-circuits: no re-read can have happened.
        for probe in [
            ExtractableProbe::Sensitive,
            ExtractableProbe::TypeInvalid,
            ExtractableProbe::Unavailable,
            ExtractableProbe::Failed,
        ] {
            assert_eq!(
                resolve_extractable_recheck(probe, None),
                ExtractableRecheck::Unresolved(probe),
                "{probe}"
            );
        }
        assert_eq!(
            resolve_extractable_recheck(ExtractableProbe::Available, Some(ExtractableState::No)),
            ExtractableRecheck::Resolved(ExtractableAnswer::No)
        );
        assert_eq!(
            resolve_extractable_recheck(ExtractableProbe::Available, Some(ExtractableState::Yes)),
            ExtractableRecheck::Resolved(ExtractableAnswer::Yes)
        );
        // "Available" but the re-read still carried nothing: unproven, and
        // the size query's answer is the honest reason.
        assert_eq!(
            resolve_extractable_recheck(
                ExtractableProbe::Available,
                Some(ExtractableState::Unavailable)
            ),
            ExtractableRecheck::Unresolved(ExtractableProbe::Available)
        );
    }

    #[test]
    fn a_failed_re_read_is_reported_as_a_failure_not_as_available() {
        // The size query said the attribute was readable and the read then
        // errored.  Reporting "available_but_not_returned" here would tell
        // the operator the token withheld a value it never got asked for.
        assert_eq!(
            resolve_extractable_recheck(ExtractableProbe::Available, None),
            ExtractableRecheck::Unresolved(ExtractableProbe::Failed)
        );
        // And that reason reaches the operator intact.
        let parsed = ParsedPrivateKey {
            key_type: KeyType::EC,
            extractable: ExtractableState::Unavailable,
        };
        let err = enforce_extractable_policy(&parsed, FAIL_CLOSED, b"\x01\x02", || {
            resolve_extractable_recheck(ExtractableProbe::Available, None)
        })
        .err()
        .expect("must fail closed");
        match err {
            Pkcs11Error::ExtractableAttributeUnavailable { probe, .. } => {
                assert_eq!(probe, ExtractableProbe::Failed);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn each_refusal_names_the_config_key_that_lifts_it() {
        // An operator who follows the remedy in the message must land on
        // the key that actually covers their case; naming the other one
        // undoes the whole reason the two refusals are kept apart.
        let extractable = Pkcs11Error::ExtractableKeyRejected {
            key_type: KeyType::RSA.to_string(),
            cka_id_hex: "deadbeef".to_owned(),
        }
        .to_string();
        assert!(
            extractable.contains("set pkcs11_allow_extractable_keys = true"),
            "extractable-key refusal must name its own key: {extractable}"
        );
        assert!(
            !extractable.contains("pkcs11_allow_unreported_extractable"),
            "extractable-key refusal must not point at the other key: {extractable}"
        );

        let unreported = Pkcs11Error::ExtractableAttributeUnavailable {
            key_type: KeyType::RSA.to_string(),
            cka_id_hex: "deadbeef".to_owned(),
            probe: ExtractableProbe::Sensitive,
        }
        .to_string();
        assert!(
            unreported.contains("set pkcs11_allow_unreported_extractable = true"),
            "unreported-attribute refusal must name its own key: {unreported}"
        );
        assert!(
            !unreported.contains("set pkcs11_allow_extractable_keys = true"),
            "unreported-attribute refusal must not point at the other key: {unreported}"
        );
    }

    #[test]
    fn extractable_state_display_is_stable() {
        assert_eq!(ExtractableState::No.to_string(), "no");
        assert_eq!(ExtractableState::Yes.to_string(), "yes");
        assert_eq!(ExtractableState::Unavailable.to_string(), "unavailable");
    }

    #[test]
    fn extractable_probe_display_is_stable() {
        assert_eq!(ExtractableProbe::Sensitive.to_string(), "sensitive");
        assert_eq!(ExtractableProbe::TypeInvalid.to_string(), "type_invalid");
        assert_eq!(ExtractableProbe::Unavailable.to_string(), "unavailable");
        assert_eq!(
            ExtractableProbe::Available.to_string(),
            "available_but_not_returned"
        );
        assert_eq!(ExtractableProbe::Failed.to_string(), "probe_failed");
    }

    #[test]
    fn cka_id_log_prefix_truncates_long_ids() {
        let id = b"\xde\xad\xbe\xef\xca\xfe\x00\x01";
        let log = cka_id_log_prefix(id);
        assert_eq!(log, "deadbeef...");
    }

    #[test]
    fn cka_id_log_prefix_short_id_no_ellipsis() {
        let id = b"\xab\xcd";
        let log = cka_id_log_prefix(id);
        assert_eq!(log, "abcd");
    }

    #[test]
    fn cka_id_log_prefix_empty() {
        assert_eq!(cka_id_log_prefix(&[]), "");
    }
}

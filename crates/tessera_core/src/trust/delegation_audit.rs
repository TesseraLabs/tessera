//! Audit events for delegation-envelope enforcement and the profile
//! version-gate (tags-delegation §5.1, `logging-audit` delta spec).
//!
//! Mirrors `role::audit` / `tags::audit`: a dedicated tracing target, plain
//! field names, and `emit_*` helpers that freeze the event name + field schema
//! in code so tests assert on the `EVENT_*` constants without mistyping a
//! literal.
//!
//! ## Generic engineer message vs. full audit vector
//!
//! The `logging-audit` spec mandates that the reason shown to the engineer be
//! GENERIC — the envelope structure (which CA link, which `requireTags`) must
//! not leak before authentication completes. The full reason vector (culprit
//! link serial, violated check, device-tags snapshot) goes ONLY to these audit
//! events. Callers surface [`GENERIC_DELEGATION_DENIED_MESSAGE`] to the
//! engineer and emit [`emit_delegation_denied`] to audit.

use crate::tags::DeviceTags;
use crate::trust::delegation::DelegationError;

/// `delegation_denied` — a chain was rejected by the delegation envelope,
/// a role/level/TTL ceiling, or the leaf allowed-roles/`max_integrity` cap.
/// Severity critical → tracing `error` level.
pub const EVENT_DELEGATION_DENIED: &str = "delegation_denied";

/// `tag_manifest_applied` — a signed device-tags manifest bundle was accepted
/// and applied (informational breadcrumb for tag provenance).
pub const EVENT_TAG_MANIFEST_APPLIED: &str = "tag_manifest_applied";

/// `profile_version_rejected` — a chain cert declared a `pam_cert_profile_version`
/// above the Engine's `max_supported`. Severity critical → tracing `error`.
pub const EVENT_PROFILE_VERSION_REJECTED: &str = "profile_version_rejected";

/// `delegation_denied` violated-check tag: the device tags did not satisfy a
/// CA's `requireTags` envelope.
pub const CHECK_TAGS: &str = "tags";
/// `delegation_denied` violated-check tag: the requested role was not in a CA's
/// `allowRoles` (or the leaf allowed-roles list).
pub const CHECK_ROLE: &str = "role";
/// `delegation_denied` violated-check tag: the requested level exceeded a CA's
/// `maxLevel` (or the leaf `max_integrity` ceiling).
pub const CHECK_LEVEL: &str = "level";
/// `delegation_denied` violated-check tag: a link's lifetime exceeded a parent
/// CA's `maxTtl`.
pub const CHECK_TTL: &str = "ttl";
/// `delegation_denied` violated-check tag: a `delegation_constraints` extension
/// was malformed or mis-placed (treated as a version/format violation).
pub const CHECK_VERSION: &str = "version";

/// Generic, structure-free message surfaced to the ENGINEER on any delegation
/// denial. The full reason vector lives only in the `delegation_denied` audit
/// event (`logging-audit`: «инженеру — обобщённая причина»).
pub const GENERIC_DELEGATION_DENIED_MESSAGE: &str =
    "Доступ запрещён политикой делегирования. Обратитесь к администратору.";

/// Map a [`DelegationError`] to its `violated_check` audit tag.
#[must_use]
pub fn violated_check(err: &DelegationError) -> &'static str {
    match err {
        DelegationError::TagEnvelope { .. } => CHECK_TAGS,
        DelegationError::RoleNotAllowed { .. } => CHECK_ROLE,
        DelegationError::LevelCeiling { .. } => CHECK_LEVEL,
        DelegationError::TtlCeiling { .. } => CHECK_TTL,
        DelegationError::Malformed { .. } => CHECK_VERSION,
    }
}

/// Render a stable, sorted `k=v,k=v` snapshot of the device tags for audit.
///
/// `DeviceTags::iter` already yields keys in sorted order (backed by a
/// `BTreeMap`), so the output is deterministic. An empty set renders as the
/// empty string. This is audit-only (the full set is permitted here); the
/// engineer never sees it.
#[must_use]
pub fn snapshot_tags(tags: &DeviceTags) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(tags.len());
    for (k, v) in tags.iter() {
        parts.push(format!("{k}={v}"));
    }
    parts.join(",")
}

/// Emit `delegation_denied` — a chain was rejected by `enforce_delegation`.
///
/// `culprit_serial` is the serial (lowercase hex) of the chain link that
/// triggered the rejection (the CA whose envelope/ceiling was violated, or the
/// malformed cert). `device_tags` is a snapshot of the device's applied tags.
/// The full reason vector is recorded here ONLY; the engineer sees the generic
/// [`GENERIC_DELEGATION_DENIED_MESSAGE`].
pub fn emit_delegation_denied(
    culprit_serial: &str,
    err: &DelegationError,
    device_tags: &DeviceTags,
) {
    tracing::error!(
        target: "trust.audit",
        event = EVENT_DELEGATION_DENIED,
        culprit_serial,
        violated_check = violated_check(err),
        device_tags = snapshot_tags(device_tags).as_str(),
        detail = %err,
    );
}

/// Emit `tag_manifest_applied` — a signed device-tags bundle was applied.
pub fn emit_tag_manifest_applied(device_id: &str, bundle_version: u64) {
    tracing::info!(
        target: "trust.audit",
        event = EVENT_TAG_MANIFEST_APPLIED,
        device_id,
        bundle_version,
    );
}

/// Emit `profile_version_rejected` — a chain cert's `pam_cert_profile_version`
/// exceeded the Engine's `max_supported`.
pub fn emit_profile_version_rejected(serial: &str, cert_version: u32, max_supported: u32) {
    tracing::error!(
        target: "trust.audit",
        event = EVENT_PROFILE_VERSION_REJECTED,
        serial,
        cert_version,
        max_supported,
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::x509::delegation_constraints_ext::DelegationConstraintsExtError;

    #[test]
    fn violated_check_maps_every_variant() {
        assert_eq!(
            violated_check(&DelegationError::TagEnvelope { index: 1 }),
            CHECK_TAGS
        );
        assert_eq!(
            violated_check(&DelegationError::RoleNotAllowed {
                role: "oper".into(),
                scope: "leaf".into()
            }),
            CHECK_ROLE
        );
        assert_eq!(
            violated_check(&DelegationError::LevelCeiling {
                requested: 3,
                ceiling: 1,
                scope: "leaf".into()
            }),
            CHECK_LEVEL
        );
        assert_eq!(
            violated_check(&DelegationError::TtlCeiling {
                link_index: 0,
                parent_index: 1,
                link_ttl_secs: 100,
                max_ttl_secs: 10,
            }),
            CHECK_TTL
        );
        assert_eq!(
            violated_check(&DelegationError::Malformed {
                index: 0,
                source: DelegationConstraintsExtError::NotCa,
            }),
            CHECK_VERSION
        );
    }

    #[test]
    fn snapshot_tags_is_sorted_and_empty_safe() {
        assert_eq!(snapshot_tags(&DeviceTags::empty()), "");
        let tags = DeviceTags::from_pairs(
            [("region", "north"), ("class", "terminal")]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned())),
        )
        .unwrap();
        // BTreeMap ordering: class before region.
        assert_eq!(snapshot_tags(&tags), "class=terminal,region=north");
    }
}

//! Device-tags schema types and strict TOML parser.
//!
//! A device-tags set is an opaque `key → value` map (both non-empty UTF-8
//! strings, exactly one value per key). Tags are **opaque to the Engine**: no
//! key name (`region`, `class`, …) carries special semantics — every key is
//! handled uniformly as data (design decision 1). New keys/values are data and
//! never require an Engine code change.
//!
//! Parsing is strict and fail-closed (the role-store `schema.rs` model): a
//! duplicate key in the source is a *format error*, not a last-wins merge; an
//! empty key or empty value is an error; non-UTF-8 bytes return an error rather
//! than panicking.

use std::collections::BTreeMap;

/// Maximum size of a device-tags source document, in bytes (64 KiB cap, parity
/// with the role-slice cap).
pub const MAX_TAGS_BYTES: usize = 64 * 1024;

/// A validated, opaque set of device tags: `key → value`, both non-empty
/// UTF-8 strings, with exactly one value per key.
///
/// `BTreeMap` gives deterministic iteration order (audit/snapshot stability).
/// The Engine treats every key uniformly as data; there is no special-casing
/// of any key name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceTags {
    /// The validated key→value pairs.
    tags: BTreeMap<String, String>,
}

impl DeviceTags {
    /// An empty tag set (the device has no applied tags).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            tags: BTreeMap::new(),
        }
    }

    /// Look up a tag value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.tags.get(key).map(String::as_str)
    }

    /// Number of tags in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Whether the device has no applied tags.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Iterate the `(key, value)` pairs in deterministic (sorted) key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.tags.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Whether this device's tags satisfy `require`: a generic superset check
    /// `self ⊇ require`, i.e. `∀(k,v)∈require: self.get(k) == Some(v)`.
    ///
    /// No key name is special-cased — every key is matched as data (design
    /// decision 1). An empty `require` is vacuously satisfied. If the device
    /// has no tags, any non-empty `require` is unsatisfiable → `false`
    /// (fail-closed for group delegation; consumed by path validation).
    #[must_use]
    pub fn satisfies(&self, require: &DeviceTags) -> bool {
        require
            .tags
            .iter()
            .all(|(k, v)| self.tags.get(k).is_some_and(|have| have == v))
    }

    /// Build a [`DeviceTags`] from validated pairs, enforcing the schema
    /// invariants (non-empty key/value, no duplicate key). Shared by the TOML
    /// parser and constructed sources.
    ///
    /// # Errors
    ///
    /// [`TagsSchemaError::EmptyKey`], [`TagsSchemaError::EmptyValue`], or
    /// [`TagsSchemaError::DuplicateKey`].
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, TagsSchemaError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut tags: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in pairs {
            let key: String = k.into();
            let value: String = v.into();
            if key.is_empty() {
                return Err(TagsSchemaError::EmptyKey);
            }
            if value.is_empty() {
                return Err(TagsSchemaError::EmptyValue { key });
            }
            if tags.insert(key.clone(), value).is_some() {
                return Err(TagsSchemaError::DuplicateKey { key });
            }
        }
        Ok(Self { tags })
    }
}

/// Errors from parsing or validating a device-tags set.
#[derive(Debug, thiserror::Error)]
pub enum TagsSchemaError {
    /// Source exceeds the size cap.
    #[error("device-tags source is {size} bytes, exceeds the {max}-byte cap")]
    Oversize {
        /// Actual byte length.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Source bytes are not valid UTF-8.
    #[error("device-tags source is not valid UTF-8: {reason}")]
    NotUtf8 {
        /// Underlying decode error message.
        reason: String,
    },
    /// TOML parse / type / unknown-field error.
    #[error("device-tags TOML is invalid: {reason}")]
    TomlParse {
        /// Underlying TOML error message.
        reason: String,
    },
    /// A key appears more than once in the source (fail-closed; *not*
    /// last-wins).
    #[error("duplicate tag key {key:?}: a key may appear only once")]
    DuplicateKey {
        /// The offending key.
        key: String,
    },
    /// A key is the empty string.
    #[error("empty tag key: keys must be non-empty UTF-8")]
    EmptyKey,
    /// A value is the empty string.
    #[error("empty value for tag key {key:?}: values must be non-empty UTF-8")]
    EmptyValue {
        /// The key whose value was empty.
        key: String,
    },
}

/// Parse and validate a device-tags set from raw source bytes.
///
/// The on-disk form is a flat TOML table of `key = "value"` pairs under a
/// `[tags]` section (parity with the role manifest's `[tags]` table). Steps:
/// size cap → UTF-8 → TOML → per-pair non-empty + duplicate-key validation.
///
/// A duplicate key is rejected by TOML itself (the format forbids redefining a
/// key), surfacing as [`TagsSchemaError::TomlParse`]; if a duplicate ever
/// reaches [`DeviceTags::from_pairs`] it is rejected there too. Either path is
/// fail-closed — never last-wins.
///
/// # Errors
///
/// Any [`TagsSchemaError`].
pub fn parse_tags(bytes: &[u8]) -> Result<DeviceTags, TagsSchemaError> {
    if bytes.len() > MAX_TAGS_BYTES {
        return Err(TagsSchemaError::Oversize {
            size: bytes.len(),
            max: MAX_TAGS_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|e| TagsSchemaError::NotUtf8 {
        reason: e.to_string(),
    })?;
    let doc: TagsDoc = toml::from_str(text).map_err(|e| TagsSchemaError::TomlParse {
        reason: e.to_string(),
    })?;
    DeviceTags::from_pairs(doc.tags)
}

/// Strict outer shape of a device-tags source: a single `[tags]` table of
/// `string → string`. Unknown top-level keys or non-string values are TOML
/// errors (fail-closed). The duplicate-key / empty-key / empty-value
/// invariants are enforced afterwards by [`DeviceTags::from_pairs`].
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TagsDoc {
    #[serde(default)]
    tags: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_docs_in_private_items,
        clippy::let_underscore_must_use
    )]

    use super::*;

    // ---- 1.1: schema + strict parsing ------------------------------------

    #[test]
    fn valid_tags_parse() {
        let doc = "[tags]\nregion = \"north\"\nclass = \"terminal\"\n";
        let tags = parse_tags(doc.as_bytes()).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags.get("region"), Some("north"));
        assert_eq!(tags.get("class"), Some("terminal"));
        assert_eq!(tags.get("absent"), None);
    }

    #[test]
    fn empty_doc_is_empty_tags() {
        let tags = parse_tags(b"").unwrap();
        assert!(tags.is_empty());
        assert_eq!(tags.len(), 0);

        let tags = parse_tags(b"[tags]\n").unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn duplicate_key_is_format_error_not_last_wins() {
        // A duplicate key in TOML is rejected by the format (fail-closed),
        // NOT silently last-wins.
        let doc = "[tags]\nregion = \"north\"\nregion = \"south\"\n";
        let err = parse_tags(doc.as_bytes()).unwrap_err();
        assert!(matches!(err, TagsSchemaError::TomlParse { .. }));
        // And the explicit from_pairs path rejects a duplicate too.
        let err = DeviceTags::from_pairs([("region", "north"), ("region", "south")]).unwrap_err();
        assert!(matches!(err, TagsSchemaError::DuplicateKey { key } if key == "region"));
    }

    #[test]
    fn empty_key_rejected() {
        let doc = "[tags]\n\"\" = \"x\"\n";
        let err = parse_tags(doc.as_bytes()).unwrap_err();
        assert!(matches!(err, TagsSchemaError::EmptyKey));
    }

    #[test]
    fn empty_value_rejected() {
        let doc = "[tags]\nregion = \"\"\n";
        let err = parse_tags(doc.as_bytes()).unwrap_err();
        assert!(matches!(err, TagsSchemaError::EmptyValue { key } if key == "region"));
    }

    #[test]
    fn non_utf8_bytes_do_not_panic() {
        // Invalid UTF-8 must return an error, never panic.
        let bytes = [b'[', b't', b'a', b'g', b's', b']', b'\n', 0xff, 0xfe, 0x00];
        let err = parse_tags(&bytes).unwrap_err();
        assert!(matches!(err, TagsSchemaError::NotUtf8 { .. }));
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        let doc = "bogus = 1\n[tags]\nregion = \"north\"\n";
        let err = parse_tags(doc.as_bytes()).unwrap_err();
        assert!(matches!(err, TagsSchemaError::TomlParse { .. }));
    }

    #[test]
    fn non_string_value_rejected() {
        let doc = "[tags]\nregion = 42\n";
        let err = parse_tags(doc.as_bytes()).unwrap_err();
        assert!(matches!(err, TagsSchemaError::TomlParse { .. }));
    }

    #[test]
    fn oversize_rejected() {
        let bytes = vec![b'#'; MAX_TAGS_BYTES + 1];
        let err = parse_tags(&bytes).unwrap_err();
        assert!(matches!(err, TagsSchemaError::Oversize { .. }));
    }

    // ---- 1.3: generic superset match -------------------------------------

    #[test]
    fn satisfies_superset_generic() {
        let device = parse_tags(b"[tags]\nregion = \"north\"\nclass = \"terminal\"\n").unwrap();
        // Subset requirement is satisfied.
        let req = DeviceTags::from_pairs([("region", "north")]).unwrap();
        assert!(device.satisfies(&req));
        // Full match satisfied.
        let req = DeviceTags::from_pairs([("region", "north"), ("class", "terminal")]).unwrap();
        assert!(device.satisfies(&req));
        // Wrong value not satisfied.
        let req = DeviceTags::from_pairs([("region", "south")]).unwrap();
        assert!(!device.satisfies(&req));
        // Missing key not satisfied.
        let req = DeviceTags::from_pairs([("vendor", "acme")]).unwrap();
        assert!(!device.satisfies(&req));
    }

    #[test]
    fn empty_require_is_vacuously_satisfied() {
        let device = parse_tags(b"[tags]\nregion = \"north\"\n").unwrap();
        assert!(device.satisfies(&DeviceTags::empty()));
        // Even a device with no tags satisfies an empty requirement.
        assert!(DeviceTags::empty().satisfies(&DeviceTags::empty()));
    }

    #[test]
    fn no_tags_makes_any_requirement_unsatisfiable() {
        // "Absence of tags" rule: a device with no applied tags fails any
        // non-empty requireTags (fail-closed for group delegation).
        let device = DeviceTags::empty();
        let req = DeviceTags::from_pairs([("region", "north")]).unwrap();
        assert!(!device.satisfies(&req));
    }
}

#[cfg(test)]
mod proptests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_docs_in_private_items,
        clippy::let_underscore_must_use
    )]

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_tags_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_tags(&data);
        }

        /// An arbitrary, previously-unseen key is handled as plain data: the
        /// superset predicate is correct (no panic, no special-casing) for any
        /// key name.
        #[test]
        fn arbitrary_key_handled_as_data(
            key in proptest::string::string_regex("[a-zA-Z][a-zA-Z0-9_-]{0,30}").unwrap(),
            value in proptest::string::string_regex("[a-zA-Z0-9][a-zA-Z0-9_-]{0,30}").unwrap(),
            other in proptest::string::string_regex("[a-zA-Z0-9][a-zA-Z0-9_-]{0,30}").unwrap(),
        ) {
            let device = DeviceTags::from_pairs([(key.clone(), value.clone())]).unwrap();
            // The exact pair is a satisfied requirement.
            let exact = DeviceTags::from_pairs([(key.clone(), value.clone())]).unwrap();
            prop_assert!(device.satisfies(&exact));
            // A different value for the same key is unsatisfiable iff it differs.
            let req_other = DeviceTags::from_pairs([(key.clone(), other.clone())]).unwrap();
            prop_assert_eq!(device.satisfies(&req_other), value == other);
            // The empty device never satisfies the non-empty requirement.
            prop_assert!(!DeviceTags::empty().satisfies(&exact));
        }
    }
}

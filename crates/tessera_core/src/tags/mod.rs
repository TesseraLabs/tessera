//! Device tags: an opaque `key → value` map describing this device, used to
//! satisfy group-delegation `requireTags` envelopes.
//!
//! Tags are **opaque to the Engine** (design decision 1): no key name carries
//! special meaning — every key is handled uniformly as data, so a new tag is
//! data, never a code change. The envelope check is the generic superset
//! `device.tags ⊇ requireTags` ([`DeviceTags::satisfies`]).
//!
//! The trusted source mirrors the role-store (design decision 2): in
//! **managed** mode tags ride in the SAME signed manifest under the SAME
//! `bundle_version` anti-rollback floor as the role base (`tags::source`
//! reuses [`crate::role::verify_manifest`]); in **standalone** mode a local
//! file is trusted by filesystem permissions. Verification is fail-closed: a
//! broken signature, a `bundle_version` rollback, or a malformed payload means
//! no tags are applied and the previous set is retained.

pub mod audit;
pub mod schema;
pub mod source;

pub use schema::{parse_tags, DeviceTags, TagsSchemaError, MAX_TAGS_BYTES};
pub use source::{
    load_managed, load_standalone, load_standalone_optional, TagsSourceError, DEFAULT_TAGS_FILE,
};

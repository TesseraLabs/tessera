//! The one filter that decides whether a field name may appear in a record.
//!
//! The rule "secrets never reach the log" has until now been discipline: every
//! `tracing::` call site was written by somebody who knew not to pass the PIN.
//! Discipline holds for call sites a reviewer reads. It does not hold for the
//! annotation path, where the fields are chosen at runtime by a writer this
//! crate has never seen, and it does not hold for a chain, where a leaked field
//! cannot be deleted afterwards without breaking the chain that proves nothing
//! was deleted.
//!
//! So the rule gets a mechanism, and this is it. Records with a fixed shape
//! ([`super::AuditRecord`]) are safe by construction — their fields are named in
//! the type and no secret is among them. Everything free-form goes through
//! [`find_secret_field`] before it reaches the chain.
//!
//! # What it matches, and what it deliberately does not
//!
//! Matching is on the *name*, normalised (lowercased, separators dropped), never
//! on the value: a filter that guessed from values would refuse a certificate
//! fingerprint for looking like key material and pass a PIN for looking like a
//! number.
//!
//! Two lists, for two different risks:
//!
//! - [`SECRET_SUBSTRINGS`] — fragments that cannot occur innocently. Anything
//!   containing `password` is a password.
//! - [`SECRET_NAMES`] — whole names that are secrets on their own but are common
//!   words inside longer ones. `code` is the one-time code; `country_code` is
//!   not. Matching `code` as a substring would refuse half the fields in the
//!   product and teach writers to work around the filter.
//!
//! A name this list does not know still gets through. The filter narrows a
//! class of accident; it is not a proof that the record is clean, and the
//! documentation of every writer says what its annotation carries.

/// Name fragments that are a secret wherever they occur.
pub const SECRET_SUBSTRINGS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "privatekey",
    "privkey",
    "secretkey",
    "sharedsecret",
    "derivedkey",
    "keymaterial",
    "keybytes",
    "pkcs12",
    "ckaid",
];

/// Whole names that are a secret, and are ordinary words inside longer names.
pub const SECRET_NAMES: &[&str] = &[
    "pin",
    "code",
    "otp",
    "secret",
    "key",
    "token",
    "seed",
    "credential",
    "credentials",
    "p12",
    "pfx",
];

/// Normalises a field name for matching: lowercase, separators dropped.
///
/// `CKA_ID`, `cka-id` and `ckaId` are the same field with three spellings, and a
/// filter that knew only one of them would be a filter in name only.
fn normalise(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Whether a field of this name may never appear in a record.
#[must_use]
pub fn is_secret_field_name(name: &str) -> bool {
    let normalised = normalise(name);
    SECRET_NAMES.contains(&normalised.as_str())
        || SECRET_SUBSTRINGS
            .iter()
            .any(|fragment| normalised.contains(fragment))
}

/// Walks `value` and returns the path of the first field whose name may never
/// be recorded, or [`None`] when nothing matched.
///
/// The walk goes through objects and arrays alike: a secret nested three levels
/// down in an annotation is exactly as permanent as one at the top.
#[must_use]
pub fn find_secret_field(value: &serde_json::Value) -> Option<String> {
    fn walk(value: &serde_json::Value, path: &str, found: &mut Option<String>) {
        if found.is_some() {
            return;
        }
        match value {
            serde_json::Value::Object(map) => {
                for (name, child) in map {
                    let child_path = if path.is_empty() {
                        name.clone()
                    } else {
                        format!("{path}.{name}")
                    };
                    if is_secret_field_name(name) {
                        *found = Some(child_path);
                        return;
                    }
                    walk(child, &child_path, found);
                    if found.is_some() {
                        return;
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    walk(child, &format!("{path}[{index}]"), found);
                    if found.is_some() {
                        return;
                    }
                }
            }
            _ => {}
        }
    }

    let mut found = None;
    walk(value, "", &mut found);
    found
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{find_secret_field, is_secret_field_name};

    /// One case per class of sensitive field the product actually holds. A
    /// class without a test here is a class the filter is not known to cover.
    #[test]
    fn every_class_of_secret_is_refused() {
        // What a person types.
        assert!(is_secret_field_name("pin"));
        assert!(is_secret_field_name("PIN"));
        assert!(is_secret_field_name("password"));
        assert!(is_secret_field_name("container_password"));
        assert!(is_secret_field_name("passphrase"));

        // The one-time code and everything it is derived from.
        assert!(is_secret_field_name("code"));
        assert!(is_secret_field_name("otp"));
        assert!(is_secret_field_name("shared_secret"));
        assert!(is_secret_field_name("derived_key"));
        assert!(is_secret_field_name("seed"));

        // Key material and the objects that hold it.
        assert!(is_secret_field_name("private_key"));
        assert!(is_secret_field_name("privKey"));
        assert!(is_secret_field_name("key_material"));
        assert!(is_secret_field_name("key_bytes"));
        assert!(is_secret_field_name("CKA_ID"));
        assert!(is_secret_field_name("cka-id"));
        assert!(is_secret_field_name("pkcs12"));
        assert!(is_secret_field_name("p12"));

        // Bearer material.
        assert!(is_secret_field_name("token"));
        assert!(is_secret_field_name("credentials"));
    }

    /// The other half of the filter's job: a name that merely contains a
    /// dangerous word is not a secret, and refusing it would push writers into
    /// renaming fields to get past the filter.
    #[test]
    fn ordinary_fields_are_not_refused() {
        for name in [
            "country_code",
            "reason_code",
            "exit_code",
            "role_id",
            "nonce_ref",
            "ticket_no",
            "key_origin",
            "epoch",
            "public_key_fingerprint",
            "host_id_prefix8",
        ] {
            assert!(!is_secret_field_name(name), "{name} was refused");
        }
    }

    #[test]
    fn a_secret_nested_in_an_annotation_is_found_with_its_path() {
        let value = serde_json::json!({
            "operator": "op-42",
            "calls": [
                { "ticket_no": "tk-17" },
                { "ticket_no": "tk-18", "derived_key": "…" }
            ]
        });
        assert_eq!(
            find_secret_field(&value).unwrap(),
            "calls[1].derived_key".to_owned()
        );
    }

    #[test]
    fn a_clean_annotation_passes() {
        let value = serde_json::json!({
            "operator": "op-42",
            "receipts": 3,
            "calls": [{ "ticket_no": "tk-17", "nonce_ref": "0000014711" }]
        });
        assert_eq!(find_secret_field(&value), None);
    }
}

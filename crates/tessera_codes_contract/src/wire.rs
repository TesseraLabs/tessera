//! The wire form shared by the documents of the channel.
//!
//! Every document of the contract travels as one line: a prefix that names the
//! format and its version, then the fields as `key=value` pairs in a fixed
//! order, separated by `;`. The form is written by hand for the same reason the
//! canonical encoding is — a derived format changes its shape when a dependency
//! is updated, and a document written by one build has to be readable by
//! another for as long as the compatibility policy says it does.
//!
//! Parsing is strict, and strict here means all three of:
//!
//! - a field the format does not describe is an error, never a field dropped;
//! - a field out of order, missing, or not a `key=value` pair is an error;
//! - a value the target type cannot hold is an error, never a substituted
//!   default.
//!
//! A document is a claim about who may do what; a parser that repairs one is
//! deciding on behalf of the operator who signed it.

/// Separator between the fields of a document.
pub(crate) const FIELD_SEPARATOR: char = ';';

/// Separator between a key and its value.
pub(crate) const KEY_SEPARATOR: char = '=';

/// Separator between the items of a list-valued field.
pub(crate) const LIST_SEPARATOR: char = ',';

/// Rejection of the wire form of a document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The text does not open with the format marker of the document.
    #[error("the document does not open with `{expected}`")]
    WrongPrefix {
        /// Marker the format expects.
        expected: &'static str,
    },
    /// The text carries the wrong number of fields.
    #[error("the document carries {got} fields where the format has {expected}")]
    FieldCount {
        /// Number of fields the format has.
        expected: usize,
        /// Number of fields the text carried.
        got: usize,
    },
    /// A field carries no `key=value` pair.
    #[error("the field for `{expected}` is not a `key=value` pair")]
    MalformedField {
        /// Key the format expects in this position.
        expected: &'static str,
    },
    /// A field is unknown, or known but out of order.
    #[error("expected the field `{expected}`, found `{got}`")]
    UnexpectedField {
        /// Key the format expects in this position.
        expected: &'static str,
        /// Key the text carried instead.
        got: String,
    },
    /// A field carries an empty value.
    #[error("the document field `{field}` is empty")]
    EmptyValue {
        /// Name of the empty field.
        field: &'static str,
    },
    /// A field carries a character the format cannot hold.
    #[error("the document field `{field}` carries a character the format cannot hold")]
    UnusableValue {
        /// Name of the offending field.
        field: &'static str,
    },
    /// A numeric field does not parse.
    #[error("the document field `{field}` is not a number the format holds")]
    NotANumber {
        /// Name of the offending field.
        field: &'static str,
    },
    /// A binary field is not hexadecimal.
    #[error("the document field `{field}` is not hexadecimal")]
    NotHex {
        /// Name of the offending field.
        field: &'static str,
    },
}

/// Renders a document: the prefix, then the fields in the given order.
///
/// The values are expected to have passed [`check_free_text`] or to be produced
/// by the crate itself; the writer adds no escaping, because a format with an
/// escape is a format with two spellings of one document.
pub(crate) fn render(prefix: &str, fields: &[(&'static str, String)]) -> String {
    let mut text = String::from(prefix);
    for (key, value) in fields {
        text.push(FIELD_SEPARATOR);
        text.push_str(key);
        text.push(KEY_SEPARATOR);
        text.push_str(value);
    }
    text
}

/// Parses a document into the values of `keys`, in that exact order.
///
/// # Errors
///
/// Returns the [`WireError`] describing the first violation: a wrong prefix, a
/// field count that does not match, a field that is not a `key=value` pair, a
/// key out of order or unknown, or an empty value.
pub(crate) fn parse<'a>(
    text: &'a str,
    prefix: &'static str,
    keys: &[&'static str],
) -> Result<Vec<&'a str>, WireError> {
    let mut parts = text.trim().split(FIELD_SEPARATOR);
    if parts.next().unwrap_or_default() != prefix {
        return Err(WireError::WrongPrefix { expected: prefix });
    }

    let mut values: Vec<&str> = Vec::with_capacity(keys.len());
    for (index, part) in parts.enumerate() {
        let expected = keys.get(index).copied().ok_or(WireError::FieldCount {
            expected: keys.len(),
            got: index + 1,
        })?;
        let (key, value) = part
            .split_once(KEY_SEPARATOR)
            .ok_or(WireError::MalformedField { expected })?;
        if key != expected {
            return Err(WireError::UnexpectedField {
                expected,
                got: key.to_owned(),
            });
        }
        if value.is_empty() {
            return Err(WireError::EmptyValue { field: expected });
        }
        values.push(value);
    }

    if values.len() != keys.len() {
        return Err(WireError::FieldCount {
            expected: keys.len(),
            got: values.len(),
        });
    }
    Ok(values)
}

/// Returns the value at `index` of a parsed document.
///
/// The index comes from the field table of the document, which is the same
/// table [`parse`] was called with, so a value is always there; the total form
/// avoids a panic path for a branch that cannot be taken.
pub(crate) fn value<'a>(values: &[&'a str], index: usize) -> &'a str {
    values.get(index).copied().unwrap_or_default()
}

/// Checks a free-text value against what the wire form can carry.
///
/// # Errors
///
/// Returns [`WireError::EmptyValue`] for an empty value and
/// [`WireError::UnusableValue`] when it carries a separator of the format or a
/// control character.
pub(crate) fn check_free_text(field: &'static str, value: &str) -> Result<(), WireError> {
    if value.is_empty() {
        return Err(WireError::EmptyValue { field });
    }
    if value
        .chars()
        .any(|symbol| symbol == FIELD_SEPARATOR || symbol == KEY_SEPARATOR || symbol.is_control())
    {
        return Err(WireError::UnusableValue { field });
    }
    Ok(())
}

/// Checks one item of a list-valued field, which additionally cannot carry the
/// list separator.
///
/// # Errors
///
/// The errors of [`check_free_text`], plus [`WireError::UnusableValue`] for an
/// item carrying the list separator.
pub(crate) fn check_list_item(field: &'static str, value: &str) -> Result<(), WireError> {
    check_free_text(field, value)?;
    if value.contains(LIST_SEPARATOR) {
        return Err(WireError::UnusableValue { field });
    }
    Ok(())
}

/// Parses an unsigned 32-bit field.
///
/// # Errors
///
/// Returns [`WireError::NotANumber`] for anything but a run of decimal digits
/// that fits the type. A leading sign or space is a malformed document, not a
/// number to be read leniently.
pub(crate) fn parse_u32(field: &'static str, value: &str) -> Result<u32, WireError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireError::NotANumber { field });
    }
    value
        .parse::<u32>()
        .map_err(|_| WireError::NotANumber { field })
}

/// Parses an unsigned 64-bit field.
///
/// # Errors
///
/// Returns [`WireError::NotANumber`], on the same terms as [`parse_u32`].
pub(crate) fn parse_u64(field: &'static str, value: &str) -> Result<u64, WireError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireError::NotANumber { field });
    }
    value
        .parse::<u64>()
        .map_err(|_| WireError::NotANumber { field })
}

/// Parses a binary field written in lowercase hexadecimal.
///
/// # Errors
///
/// Returns [`WireError::NotHex`] when the value is not an even run of
/// hexadecimal digits, and [`WireError::EmptyValue`] when it decodes to nothing
/// — a key or a signature of zero length is not a value any consumer can use.
pub(crate) fn parse_hex(field: &'static str, value: &str) -> Result<Vec<u8>, WireError> {
    let bytes = hex::decode(value).map_err(|_| WireError::NotHex { field })?;
    if bytes.is_empty() {
        return Err(WireError::EmptyValue { field });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{check_free_text, check_list_item, parse, parse_hex, parse_u32, render, WireError};

    const PREFIX: &str = "test/v1/doc";
    const KEYS: [&str; 2] = ["left", "right"];

    fn document() -> String {
        render(
            PREFIX,
            &[("left", "a".to_owned()), ("right", "b".to_owned())],
        )
    }

    #[test]
    fn a_rendered_document_parses_back() {
        assert_eq!(parse(&document(), PREFIX, &KEYS), Ok(vec!["a", "b"]));
    }

    #[test]
    fn a_wrong_prefix_is_refused() {
        assert_eq!(
            parse("other/v1/doc;left=a;right=b", PREFIX, &KEYS),
            Err(WireError::WrongPrefix { expected: PREFIX })
        );
    }

    #[test]
    fn an_extra_field_is_refused() {
        assert_eq!(
            parse(&format!("{};extra=1", document()), PREFIX, &KEYS),
            Err(WireError::FieldCount {
                expected: 2,
                got: 3
            })
        );
    }

    #[test]
    fn a_field_out_of_order_is_refused() {
        assert_eq!(
            parse("test/v1/doc;right=b;left=a", PREFIX, &KEYS),
            Err(WireError::UnexpectedField {
                expected: "left",
                got: "right".to_owned()
            })
        );
    }

    #[test]
    fn a_field_without_a_value_is_refused() {
        assert_eq!(
            parse("test/v1/doc;left;right=b", PREFIX, &KEYS),
            Err(WireError::MalformedField { expected: "left" })
        );
        assert_eq!(
            parse("test/v1/doc;left=;right=b", PREFIX, &KEYS),
            Err(WireError::EmptyValue { field: "left" })
        );
    }

    #[test]
    fn separators_and_control_characters_are_refused_in_values() {
        assert_eq!(
            check_free_text("left", "a;b"),
            Err(WireError::UnusableValue { field: "left" })
        );
        assert_eq!(
            check_free_text("left", "a=b"),
            Err(WireError::UnusableValue { field: "left" })
        );
        assert_eq!(
            check_free_text("left", "a\nb"),
            Err(WireError::UnusableValue { field: "left" })
        );
        assert_eq!(
            check_list_item("left", "a,b"),
            Err(WireError::UnusableValue { field: "left" })
        );
        assert_eq!(check_list_item("left", "a-b"), Ok(()));
    }

    #[test]
    fn numbers_are_read_without_leniency() {
        assert_eq!(parse_u32("n", "42"), Ok(42));
        assert_eq!(
            parse_u32("n", "+42"),
            Err(WireError::NotANumber { field: "n" })
        );
        assert_eq!(
            parse_u32("n", " 42"),
            Err(WireError::NotANumber { field: "n" })
        );
        assert_eq!(
            parse_u32("n", "4294967296"),
            Err(WireError::NotANumber { field: "n" })
        );
    }

    #[test]
    fn binary_fields_are_hexadecimal_and_non_empty() {
        assert_eq!(parse_hex("k", "0a0b"), Ok(vec![0x0a, 0x0b]));
        assert_eq!(parse_hex("k", "0a0"), Err(WireError::NotHex { field: "k" }));
        assert_eq!(parse_hex("k", "zz"), Err(WireError::NotHex { field: "k" }));
    }
}

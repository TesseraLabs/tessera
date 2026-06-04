//! Parser for `pam_tessera.so` module arguments.
//!
//! The cdylib's `pam_sm_*` entries collect raw `key=value` strings off the
//! C `argv` pointer; the parser here turns that into a typed
//! [`ParsedPamArgs`] struct that the auth flow consumes. New top-level
//! arguments live here so the C boundary keeps a single source of truth
//! for shape + defaults.
//!
//! Currently understood top-level arguments:
//!
//! - `config=<path>`              — override the config TOML path.
//!
//! Unrecognised `key=value` pairs are kept in [`ParsedPamArgs::extra`] so
//! later phases can extend the surface without breaking older builds.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Typed projection of the raw PAM arg vector.
#[derive(Debug, Clone, Default)]
pub struct ParsedPamArgs {
    /// Optional path override for the config TOML.
    pub config_path: Option<PathBuf>,
    /// Any `key=value` we did not recognise; available for diagnostic
    /// logging / forward compatibility tests.
    pub extra: BTreeMap<String, String>,
}

/// Parse a slice of `key=value` strings into a [`ParsedPamArgs`].
#[must_use]
pub fn parse_pam_args(args: &[&str]) -> ParsedPamArgs {
    let mut out = ParsedPamArgs::default();
    for raw in args {
        let Some((k, v)) = raw.split_once('=') else {
            continue;
        };
        match k {
            "config" => out.config_path = Some(PathBuf::from(v)),
            _ => {
                out.extra.insert(k.to_string(), v.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn config_path_parsed() {
        let parsed = parse_pam_args(&["config=/tmp/c.toml"]);
        assert_eq!(
            parsed.config_path.as_deref().map(std::path::Path::to_str),
            Some(Some("/tmp/c.toml"))
        );
    }

    #[test]
    fn unknown_keys_go_to_extra() {
        let parsed = parse_pam_args(&["foo=bar", "baz=qux"]);
        assert_eq!(parsed.extra.get("foo").map(String::as_str), Some("bar"));
        assert_eq!(parsed.extra.get("baz").map(String::as_str), Some("qux"));
    }
}

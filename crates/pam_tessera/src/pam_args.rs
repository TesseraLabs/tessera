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
//! - `method=cert|code`           — which login method this stack line drives;
//!   see [`method_from_args`].
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

/// Which login method a stack line drives.
///
/// A device can offer both: the certificate on the console where a token can
/// be plugged in, the code on the one that is reachable only by telephone.
/// They are separate lines in the PAM stack rather than one line choosing at
/// runtime, so which credential a service accepts is written down where an
/// administrator reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMethod {
    /// X.509 certificate on a token or a USB carrier.
    #[default]
    Certificate,
    /// One-time code, dictated over the telephone.
    Code,
}

/// The method a stack line names, or the value it named instead.
///
/// A `method=` nobody recognises is an error rather than a fallback. Reading
/// an unknown value as the default would let a typo in one stack line quietly
/// change which credential a service accepts, which is the one mistake this
/// argument must not be able to make.
///
/// # Errors
///
/// The unrecognised value, for the caller to report.
pub fn method_from_args(args: &BTreeMap<String, String>) -> Result<AuthMethod, &str> {
    match args.get("method").map(String::as_str) {
        None | Some("cert" | "certificate") => Ok(AuthMethod::Certificate),
        Some("code" | "codes") => Ok(AuthMethod::Code),
        Some(other) => Err(other),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn a_stack_line_without_a_method_drives_the_certificate() {
        assert_eq!(
            method_from_args(&args(&[])).unwrap(),
            AuthMethod::Certificate
        );
    }

    #[test]
    fn the_code_method_is_named_explicitly() {
        for value in ["code", "codes"] {
            assert_eq!(
                method_from_args(&args(&[("method", value)])).unwrap(),
                AuthMethod::Code,
                "method={value}"
            );
        }
    }

    #[test]
    fn an_unrecognised_method_is_not_the_default() {
        // A typo must not quietly change which credential a service accepts.
        assert_eq!(method_from_args(&args(&[("method", "cod")])), Err("cod"));
        assert_eq!(method_from_args(&args(&[("method", "")])), Err(""));
    }

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

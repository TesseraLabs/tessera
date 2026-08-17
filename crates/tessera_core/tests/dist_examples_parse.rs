//! Verifies that the example config files shipped in the .deb parse cleanly
//! against the live `RawConfig` schema.
//!
//! This pins the contract: never let `dist/config/*.example` drift from the
//! schema enforced by the core crate.
//!
//! Note: full `ValidatedConfig` validation requires PEM anchors / module
//! files to actually exist on disk (paths in the example point at
//! `/etc/tessera/...` which only exist on a deployed system). We
//! therefore parse the raw form here and run an additional
//! "swap-in-real-paths" validate pass to confirm the example exercises every
//! validation branch end-to-end.

#![allow(clippy::panic, missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;

use tessera_core::config::RawConfig;
// The validating test below runs only where the example's POSIX paths mean
// something.
#[cfg(unix)]
use tessera_core::config::ValidatedConfig;

fn dist_dir() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("../../dist/config")
}

#[test]
fn config_example_parses_as_raw() {
    let path = dist_dir().join("config.toml.example");
    let text = std::fs::read_to_string(&path).expect("read config example");
    let _raw: RawConfig = toml::from_str(&text).expect("parse config example");
}

/// Minimal self-signed PEM cert good enough to satisfy the trust-section PEM
/// sniff (which only checks for the `-----BEGIN CERTIFICATE-----` marker).
#[cfg(unix)]
const FAKE_PEM_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBfTCCAS6gAwIBAgIUcheCkYc5VvuuVlZ8KqfA8R6Bvs8wCgYIKoZIzj0EAwIw\n\
-----END CERTIFICATE-----\n";

/// Stronger contract: rewrite the example so its file-paths point into a
/// scratch directory, then run full `ValidatedConfig` validation. If the
/// example drifts in a way that breaks validation (typo'd field, removed
/// section, invalid range), this test catches it.
// The file under test is the example shipped in the .deb: it describes a
// Linux deployment, and its absolute paths (`/run/tessera`, `/var/lib/tessera`,
// `/usr/lib/...`) are POSIX by construction. Rewriting them for another
// platform would validate a mutant instead of the artefact. The raw-parse test
// above, which is what guards against schema drift, keeps running everywhere.
#[cfg(unix)]
#[test]
fn config_example_validates_with_real_paths() {
    let path = dist_dir().join("config.toml.example");
    let text = std::fs::read_to_string(&path).expect("read config example");

    validate_example(&text).expect("validate rewritten example");
}

/// Run full validation over an example whose documented paths are swapped for
/// scratch ones that exist.
///
/// Shared by the whole-file test above and the per-value test below: the values
/// an operator is invited to write have to survive the same validation the file
/// itself does, and running two different validations would let them disagree.
#[cfg(unix)]
fn validate_example(text: &str) -> Result<ValidatedConfig, String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = dir.path().join("anchor.pem");
    std::fs::write(&anchor, FAKE_PEM_CERT).expect("write anchor");
    let pkcs11_module = dir.path().join("dummy_pkcs11.so");
    std::fs::write(&pkcs11_module, b"\x7fELF").expect("write pkcs11 module");

    // Substitute the documented placeholder paths with our scratch ones.
    let rewritten = text
        .replace(
            "/etc/tessera/ca/bundle.pem",
            anchor.to_str().expect("utf8 anchor"),
        )
        .replace(
            "/usr/lib/librtpkcs11ecp.so",
            pkcs11_module.to_str().expect("utf8 pkcs11 module"),
        );

    let raw: RawConfig = toml::from_str(&rewritten).map_err(|e| e.to_string())?;
    ValidatedConfig::try_from(&raw).map_err(|e| e.to_string())
}

/// Every value the example *names* in a comment has to be a value the schema
/// accepts.
///
/// A commented-out line parses whatever nonsense it contains, so the tests above
/// say nothing about the words in the hints beside it — and those words are what
/// an operator copies. The hint `# decimal | base32` cost nothing to write and
/// would cost a fleet a refused configuration on the first device that used it,
/// because the accepted spelling is `crockford-base32`.
///
/// The list is written out rather than derived from the enums on purpose: a
/// derivation would follow a rename automatically and leave the example behind,
/// which is the drift this test exists to catch.
/// The shipped example with one extra line inside its `[codes]` section.
///
/// The example itself is used rather than a hand-built fragment: a minimal
/// config would fail on whichever mandatory key was forgotten, and the test
/// would then be red for a reason that has nothing to do with the value under
/// test. What is being asked here is exactly the operator's question — "does
/// the file still load if I write the value the comment names".
fn example_with_codes_line(text: &str, line: &str) -> String {
    let anchor = "[codes]\n";
    let at = text
        .find(anchor)
        .expect("the example carries a [codes] section")
        + anchor.len();
    let (head, tail) = text.split_at(at);
    format!("{head}{line}\n{tail}")
}

#[test]
fn every_codes_value_the_example_names_is_accepted() {
    let path = dist_dir().join("config.toml.example");
    let text = std::fs::read_to_string(&path).expect("read config example");

    for alphabet in ["decimal", "crockford-base32"] {
        assert!(
            text.contains(alphabet),
            "the example must name the alphabet {alphabet} it accepts"
        );
        let raw: RawConfig = toml::from_str(&example_with_codes_line(
            &text,
            &format!("alphabet = \"{alphabet}\""),
        ))
        .unwrap_or_else(|e| panic!("the example names alphabet {alphabet}, rejected: {e}"));
        let _ = raw;
    }

    // The profile goes through the *validating* layer, not only the parser: a
    // value can be a legal spelling and still name a key agreement this device
    // cannot perform, which is refused at load precisely so that it is never
    // discovered by an engineer at the keyboard. What the example offers as
    // usable has to survive that check.
    // One usable profile today, and the loop is written as a loop because the
    // list is expected to grow: the device half of the other two profiles is
    // simply not written yet.
    let usable_profiles = ["p256"];
    for profile in usable_profiles {
        assert!(
            text.contains(profile),
            "the example must name the key agreement profile {profile} it accepts"
        );
        let with_profile = example_with_codes_line(&text, &format!("profile = \"{profile}\""));
        let raw: RawConfig = toml::from_str(&with_profile)
            .unwrap_or_else(|e| panic!("the example names profile {profile}, rejected: {e}"));
        let _ = raw;
        #[cfg(unix)]
        validate_example(&with_profile)
            .unwrap_or_else(|e| panic!("the example offers profile {profile}, refused: {e}"));
    }

    // And a profile the device cannot perform must not be offered as a value to
    // write. It may be *named* — the example explains why it is not available —
    // but a line an operator can uncomment has to work.
    for unusable in ["x25519", "gost-vko-34.10-2012"] {
        assert!(
            !text.contains(&format!("profile = \"{unusable}\"")),
            "the example offers profile {unusable}, which the loader refuses"
        );
    }

    // The journal section is documented in the same file and by the same rule:
    // every value its comments name has to be one the loader takes.
    let audit_anchor = "[audit]\n";
    let audit_at = text
        .find(audit_anchor)
        .expect("the example carries an [audit] section")
        + audit_anchor.len();
    for when_full in ["refuse", "rotate"] {
        assert!(
            text.contains(when_full),
            "the example must name the ceiling behaviour {when_full} it accepts"
        );
        let (head, tail) = text.split_at(audit_at);
        // The journal is switched on as well, so the value is exercised on a
        // section that is actually in force rather than on one the validator
        // returns early from.
        let with_value = format!("{head}enabled = true\nwhen_full = \"{when_full}\"\n{tail}");
        let raw: RawConfig = toml::from_str(&with_value)
            .unwrap_or_else(|e| panic!("the example names when_full {when_full}, rejected: {e}"));
        let _ = raw;
        #[cfg(unix)]
        validate_example(&with_value)
            .unwrap_or_else(|e| panic!("the example offers when_full {when_full}, refused: {e}"));
    }

    // And the spelling that used to be there must not come back.
    for wrong in ["\"base32\"", "\"gost\""] {
        assert!(
            !text.contains(wrong),
            "the example names {wrong}, which the schema does not accept"
        );
    }
}

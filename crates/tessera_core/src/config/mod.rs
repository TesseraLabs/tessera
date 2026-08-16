//! Configuration: raw and validated layers.

use std::fs;
use std::path::{Path, PathBuf};

pub mod raw;
pub mod validated;

pub use raw::RawConfig;
pub use validated::ValidatedConfig;

use crate::config::raw::{RawMode, RawPkcs12Source};
use crate::Error;

fn canonicalize_root_file(path: &mut PathBuf, field: &str) -> Result<(), Error> {
    use crate::privileged_path::{validate_file, ExecTrust};

    let validated =
        validate_file(path, ExecTrust::Root).map_err(|source| Error::PrivilegedPath {
            context: format!("{field} path {} is not root-controlled", path.display()),
            source,
        })?;
    *path = validated.canonical().to_path_buf();
    Ok(())
}

/// Whether this configuration ever hands `pkcs11_module` to `dlopen`.
///
/// `mode` alone does not answer that. A signing token (`mode = "pkcs11"`)
/// loads the provider, and so does a token that only carries the envelope
/// (`mode = "pkcs12"` with `pkcs12_source = "token_object"`): the login reads
/// the `CKO_DATA` object through the very same provider, and the daemon polls
/// that provider for carrier presence. Both must therefore clear the
/// root-control walk before the path reaches a privileged process.
///
/// A USB carrier is deliberately left out even when the file still names a
/// module. Nothing loads it there, and installations that upgraded from a
/// PKCS#11 setup routinely keep a stale — sometimes non-existent — path in the
/// file; failing them would refuse logins over a value that is never read.
///
/// The pairing `mode = "pkcs11"` plus `pkcs12_source = "token_object"` is
/// refused by validation, so the union here is never wider than what the two
/// accepted shapes need.
fn loads_pkcs11_module(raw: &RawConfig) -> bool {
    raw.mode == RawMode::Pkcs11 || raw.pkcs12_source == RawPkcs12Source::TokenObject
}

/// Load, parse, and validate a config file.
pub fn load_validated_config(path: &Path) -> Result<ValidatedConfig, Error> {
    let text = fs::read_to_string(path).map_err(|source| Error::Io {
        context: format!("read config {}", path.display()),
        source,
    })?;
    let raw: RawConfig = toml::from_str(&text).map_err(|source| Error::ConfigParse {
        path: path.to_path_buf(),
        source,
    })?;
    ValidatedConfig::try_from(&raw)
}

/// Load, parse, and validate a config for a root authentication path.
///
/// Unlike [`load_validated_config`], this entry point treats the config file,
/// every trust/CRL file, and every explicitly configured native module as
/// privileged inputs. Each leaf and all of its ancestors must be root-owned
/// and non-writable by group/other, and symlink components are rejected. Paths
/// are replaced with their canonical validated targets before ordinary
/// validation and later runtime use.
///
/// # Errors
///
/// Returns [`Error::PrivilegedPath`] for an unsafe config, trust file, CRL, or
/// native module path, plus the parse and semantic validation errors documented
/// by [`load_validated_config`].
pub fn load_privileged_validated_config(path: &Path) -> Result<ValidatedConfig, Error> {
    use crate::privileged_path::{read_to_string, ExecTrust};

    let text = read_to_string(path, ExecTrust::Root).map_err(|source| Error::PrivilegedPath {
        context: format!("config path {} is not root-controlled", path.display()),
        source,
    })?;
    let mut raw: RawConfig = toml::from_str(&text).map_err(|source| Error::ConfigParse {
        path: path.to_path_buf(),
        source,
    })?;

    for path in &mut raw.trust.anchors {
        canonicalize_root_file(path, "trust anchor")?;
    }
    for path in &mut raw.trust.intermediates {
        canonicalize_root_file(path, "trust intermediate")?;
    }
    if let Some(revocation) = raw.trust.revocation.as_mut() {
        for path in &mut revocation.crl_paths {
            canonicalize_root_file(path, "trust CRL")?;
        }
    }
    for trust_override in &mut raw.trust_override {
        for path in &mut trust_override.anchors {
            canonicalize_root_file(path, "trust_override anchor")?;
        }
        for path in &mut trust_override.intermediates {
            canonicalize_root_file(path, "trust_override intermediate")?;
        }
    }
    if loads_pkcs11_module(&raw) {
        if let Some(path) = raw.pkcs11_module.as_mut() {
            canonicalize_root_file(path, "pkcs11_module")?;
        }
    }
    if let Some(path) = raw.gost_engine_path.as_mut() {
        canonicalize_root_file(path, "gost_engine_path")?;
    }

    ValidatedConfig::try_from(&raw)
}

/// Read the trusted `gost_engine_path` out of a config, without requiring the
/// rest of the config to be usable yet.
///
/// [`load_privileged_validated_config`] cannot serve a caller that needs the
/// engine path *before* the other artefacts exist. The first managed
/// enrollment runs against a config that already names
/// `/var/lib/tessera/device.crl` — a file the enrollment itself creates — so
/// the full load fails until the import is done, which is long after the
/// process has made its first call into libcrypto and settled which
/// gost-engine it gets.
///
/// The engine path carries the same root-control policy as the full load: the
/// config file and the engine module must be root-owned, not writable by
/// group or other, with no symlink components, and the value returned is the
/// canonical validated target rather than the string from the TOML. Nothing
/// else in the config is inspected or validated.
///
/// `Ok(None)` means no engine is loaded for this config: either
/// `gost_engine_path` is absent, or the crypto backend is not OpenSSL — a
/// pairing [`ValidatedConfig::try_from`] rejects outright, and one no engine
/// is ever loaded for.
///
/// # Errors
///
/// Returns [`Error::PrivilegedPath`] when the config file or the engine module
/// is not root-controlled, [`Error::ConfigParse`] when the file is not valid
/// config TOML.
pub fn load_privileged_gost_engine_path(path: &Path) -> Result<Option<PathBuf>, Error> {
    use crate::config::raw::RawCryptoBackend;
    use crate::privileged_path::{read_to_string, ExecTrust};

    let text = read_to_string(path, ExecTrust::Root).map_err(|source| Error::PrivilegedPath {
        context: format!("config path {} is not root-controlled", path.display()),
        source,
    })?;
    let raw: RawConfig = toml::from_str(&text).map_err(|source| Error::ConfigParse {
        path: path.to_path_buf(),
        source,
    })?;

    if raw.crypto_backend != RawCryptoBackend::Openssl {
        return Ok(None);
    }
    let Some(mut engine_path) = raw.gost_engine_path else {
        return Ok(None);
    };
    canonicalize_root_file(&mut engine_path, "gost_engine_path")?;
    Ok(Some(engine_path))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod module_load_tests {
    use super::{loads_pkcs11_module, RawConfig};

    /// The smallest config that parses, carrying the two carrier keys under
    /// test. Semantic validation is deliberately not run: the question here is
    /// which shapes reach `dlopen`, and it is answered on the raw config —
    /// before the file's other artefacts are known to exist.
    fn raw(carrier_keys: &str) -> RawConfig {
        let body = format!(
            "crypto_backend = \"openssl\"\n\
             {carrier_keys}\n\
             [trust]\n\
             anchors = []\n\
             [host_identity]\n\
             sources = [\"hostname\"]\n\
             [logging]\n\
             level = \"info\"\n"
        );
        toml::from_str(&body).expect("fixture parses")
    }

    #[test]
    fn signing_token_loads_the_module() {
        assert!(loads_pkcs11_module(&raw("mode = \"pkcs11\"")));
    }

    #[test]
    fn envelope_carrying_token_loads_the_module() {
        assert!(loads_pkcs11_module(&raw("mode = \"pkcs12\"\n\
             pkcs12_source = \"token_object\"\n\
             pkcs12_token_object_label = \"tessera-credential\"")));
    }

    #[test]
    fn usb_carrier_does_not_load_the_module() {
        assert!(!loads_pkcs11_module(&raw("mode = \"pkcs12\"")));
        assert!(!loads_pkcs11_module(&raw(
            "mode = \"pkcs12\"\npkcs12_source = \"usb_partition\""
        )));
    }
}

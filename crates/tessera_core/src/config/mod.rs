//! Configuration: raw and validated layers.

use std::fs;
use std::path::{Path, PathBuf};

pub mod raw;
pub mod validated;

pub use raw::RawConfig;
pub use validated::ValidatedConfig;

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
    if let Some(path) = raw.pkcs11_module.as_mut() {
        canonicalize_root_file(path, "pkcs11_module")?;
    }
    if let Some(path) = raw.gost_engine_path.as_mut() {
        canonicalize_root_file(path, "gost_engine_path")?;
    }

    ValidatedConfig::try_from(&raw)
}

//! Configuration: raw and validated layers.

use std::fs;
use std::path::Path;

pub mod raw;
pub mod validated;

pub use raw::RawConfig;
pub use validated::ValidatedConfig;

use crate::Error;

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

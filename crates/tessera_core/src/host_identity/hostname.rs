//! Hostname source.

use std::path::Path;

use crate::error::HostIdentityError;
use crate::host_identity::{HostIdSource, HostIdSourceKind};

/// Reads `etc/hostname` under the configured root for hermetic Stage 1 tests.
pub struct HostnameSource;

impl HostIdSource for HostnameSource {
    fn kind(&self) -> HostIdSourceKind {
        HostIdSourceKind::Hostname
    }

    fn fetch(&self, fs_root: &Path) -> Result<String, HostIdentityError> {
        let path = fs_root.join("etc/hostname");
        let raw = std::fs::read_to_string(&path).map_err(|source| HostIdentityError::Read {
            path: path.clone(),
            source,
        })?;
        let value = raw.trim().to_string();
        if value.is_empty() {
            return Err(HostIdentityError::Empty {
                source_kind: self.kind(),
            });
        }
        Ok(value)
    }
}

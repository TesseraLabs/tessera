//! Machine-id source.

use std::path::Path;

use crate::error::HostIdentityError;
use crate::host_identity::{HostIdSource, HostIdSourceKind};

/// Reads `etc/machine-id` under the configured root.
pub struct MachineIdSource;

impl HostIdSource for MachineIdSource {
    fn kind(&self) -> HostIdSourceKind {
        HostIdSourceKind::MachineId
    }

    fn fetch(&self, fs_root: &Path) -> Result<String, HostIdentityError> {
        let path = fs_root.join("etc/machine-id");
        let raw = std::fs::read_to_string(&path).map_err(|source| HostIdentityError::Read {
            path: path.clone(),
            source,
        })?;
        Ok(raw.trim().to_string())
    }
}

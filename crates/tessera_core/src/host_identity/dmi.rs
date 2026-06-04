//! DMI host identity sources.

use std::path::Path;

use crate::error::HostIdentityError;
use crate::host_identity::{HostIdSource, HostIdSourceKind};

macro_rules! dmi_source {
    ($name:ident, $kind:expr, $file:literal) => {
        /// DMI source.
        pub struct $name;

        impl HostIdSource for $name {
            fn kind(&self) -> HostIdSourceKind {
                $kind
            }

            fn fetch(&self, fs_root: &Path) -> Result<String, HostIdentityError> {
                let path = fs_root.join("sys/class/dmi/id").join($file);
                let raw =
                    std::fs::read_to_string(&path).map_err(|source| HostIdentityError::Read {
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
    };
}

dmi_source!(
    DmiBoardSerialSource,
    HostIdSourceKind::DmiBoardSerial,
    "board_serial"
);
dmi_source!(
    DmiSystemUuidSource,
    HostIdSourceKind::DmiSystemUuid,
    "product_uuid"
);
dmi_source!(
    DmiSystemSerialSource,
    HostIdSourceKind::DmiSystemSerial,
    "product_serial"
);

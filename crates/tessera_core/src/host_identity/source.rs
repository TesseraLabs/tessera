//! Host identity source trait.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use crate::{error::HostIdentityError, Error};

/// Host identity source kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostIdSourceKind {
    /// `/etc/machine-id`.
    MachineId,
    /// DMI board serial.
    DmiBoardSerial,
    /// DMI system UUID.
    DmiSystemUuid,
    /// DMI system serial.
    DmiSystemSerial,
    /// Hostname.
    Hostname,
    /// Custom command.
    CustomCommand,
    /// Override.
    Override,
}

impl fmt::Display for HostIdSourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MachineId => "machine_id",
            Self::DmiBoardSerial => "dmi_board_serial",
            Self::DmiSystemUuid => "dmi_system_uuid",
            Self::DmiSystemSerial => "dmi_system_serial",
            Self::Hostname => "hostname",
            Self::CustomCommand => "custom_command",
            Self::Override => "override",
        })
    }
}

impl FromStr for HostIdSourceKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "machine_id" => Ok(Self::MachineId),
            "dmi_board_serial" | "board_serial" => Ok(Self::DmiBoardSerial),
            "dmi_system_uuid" | "system_uuid" => Ok(Self::DmiSystemUuid),
            "dmi_system_serial" | "system_serial" => Ok(Self::DmiSystemSerial),
            "hostname" => Ok(Self::Hostname),
            "custom_command" => Ok(Self::CustomCommand),
            "override" => Ok(Self::Override),
            _ => Err(Error::ConfigInvalid {
                reason: format!("invalid host identity source: {s}"),
            }),
        }
    }
}

/// Host id source.
pub trait HostIdSource: Send + Sync {
    /// Source kind.
    fn kind(&self) -> HostIdSourceKind;
    /// Fetch raw value.
    fn fetch(&self, fs_root: &Path) -> Result<String, HostIdentityError>;
}

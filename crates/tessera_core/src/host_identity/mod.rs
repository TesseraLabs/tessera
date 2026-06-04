//! Host identity resolution.

pub mod chain;
pub mod custom_command;
pub mod dmi;
pub mod hostname;
pub mod machine_id;
pub mod source;

pub use chain::{normalize_host_id, HostIdentityResolver, ProbeResult, ResolvedHostId};
pub use custom_command::CustomCommandSource;
pub use dmi::{DmiBoardSerialSource, DmiSystemSerialSource, DmiSystemUuidSource};
pub use hostname::HostnameSource;
pub use machine_id::MachineIdSource;
pub use source::{HostIdSource, HostIdSourceKind};

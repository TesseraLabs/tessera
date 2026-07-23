//! Runtime plugin ABI and loader.
//!
//! The open host owns this stable C boundary. Commercial enforcement
//! adapters are separate signed shared libraries and therefore never enter
//! the open Cargo dependency graph.

mod audit;
mod header;
mod loader;
mod verify;

pub use header::{
    EnforcementBackendVTable, PluginIntegrityLabel, TesseraPluginHeader,
    TESSERA_ENFORCEMENT_BACKEND_KIND, TESSERA_PLUGIN_ABI_VERSION,
};
pub use loader::{
    load_enforcement_backend, load_enforcement_backend_from_dir, PluginBackend, PluginLoadError,
    DEFAULT_PLUGIN_DIR,
};
pub use verify::{verify_detached_signature, SignatureError};

/// Stable numeric status codes returned by enforcement-plugin callbacks.
pub mod header_codes {
    pub use super::header::{
        PLUGIN_CAP_MISSING as CAP_MISSING, PLUGIN_INVALID_INPUT as INVALID_INPUT, PLUGIN_OK as OK,
        PLUGIN_PANIC as PANIC, PLUGIN_UNAVAILABLE as UNAVAILABLE,
        PLUGIN_USER_UNKNOWN as USER_UNKNOWN,
    };
}

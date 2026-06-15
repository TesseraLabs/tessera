//! Library surface for `tessera`.
//!
//! The binary in `src/main.rs` wires every component together; integration
//! tests pull only the pieces they need.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::ignored_unit_patterns,
    clippy::doc_markdown,
    clippy::implicit_hasher,
    clippy::unused_async,
    clippy::single_match_else,
    clippy::match_wildcard_for_single_variants,
    clippy::manual_let_else,
    clippy::single_match,
    clippy::io_other_error,
    clippy::module_name_repetitions
)]

pub mod actions;
pub mod check;
pub mod daemon;
pub mod dump_host_id;
pub mod fly_dm_wallpaper_writer;
pub mod logging;
pub mod logind;
pub mod notify;
pub mod peercred;
pub mod registry;
pub mod role;
pub mod server;
pub mod shutdown;
pub mod startup_check;
pub mod state;
pub mod tags;
pub mod testing;
pub mod udev_monitor;
pub mod udev_query;

pub use registry::{ActiveSession, RegistryStore, SessionRegistry};
pub use state::{ActionRequest, Event, IpcRequest, OnUsbRemoved, StateConfig, SuspendState};

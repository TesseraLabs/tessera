//! Stand-in for the `getent` name resolver on platforms that have no NSS.
//!
//! The resolver in [`super::getent`] is an additive second opinion on top of
//! the local account database: it forks `getent passwd` and reads the records
//! a directory serves. Neither the program nor the name service exists outside
//! Unix, so this build answers the way a Unix host with no usable `getent`
//! answers — silently, leaving the verdict entirely to the local database.
//!
//! This is not a relaxation: [`NameResolution::silent`] adds no names and
//! removes none, so an account the local database refuses stays refused.

use std::time::Duration;

use super::system_account::NameResolution;

/// Answer without consulting a name service, because this platform has none.
///
/// Same contract as the Unix [`super::getent::resolve`]: the returned
/// resolution contributes no opinion, and the local account database decides
/// on its own.
pub(super) fn resolve(accounts: &[&str], timeout: Duration) -> NameResolution {
    let _ = (accounts, timeout);
    tracing::warn!(
        target: "tessera.role",
        "no name service on this platform; \
         the local account database decides on its own"
    );
    NameResolution::silent()
}

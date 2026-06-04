//! Panic guard for PAM entry points.

use std::panic::{catch_unwind, UnwindSafe};

/// PAM success.
pub const PAM_SUCCESS: i32 = 0;
/// PAM generic auth error.
pub const PAM_AUTH_ERR: i32 = 7;
/// PAM auth info unavailable.
pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;

/// Run a PAM body with unwind protection.
pub fn run_pam<F>(f: F) -> i32
where
    F: FnOnce() -> i32 + UnwindSafe,
{
    if let Ok(code) = catch_unwind(f) {
        code
    } else {
        tracing::error!(target: "tessera.panic", "panic crossed PAM boundary");
        PAM_AUTHINFO_UNAVAIL
    }
}

//! CRL parsing and chain revocation check.
//!
//! Stage 2 introduces a minimal CRL store and a stateless
//! [`check_revocation`] function that walks a verified chain and rejects
//! certificates whose serial appears in any matching CRL.
//!
//! Time handling is deliberately injected: callers pass `now` so tests can
//! pin a known instant.  In production this should be `SystemTime::now()`.

mod store;

pub use store::{check_revocation, crl_status_for, Crl, CrlCoverage, CrlStore, RevocationConfig};

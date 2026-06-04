#![allow(missing_docs)]
#![cfg(target_os = "linux")]
//! Ignored pamtester smoke scaffolding.

#[test]
#[ignore = "requires root, libpam, and pamtester"]
fn pam_authenticate_returns_authinfo_unavail() {
    eprintln!("runbook: sudo cargo test -p pam_tessera --test pam_smoke -- --ignored");
}

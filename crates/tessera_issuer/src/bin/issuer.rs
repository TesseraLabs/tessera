//! `issuer` — the Tessera certificate-issuance command-line tool.
//!
//! The command surface lives in [`tessera_issuer::cli`] (so it can be
//! unit-tested without spawning a process); this binary is only its entry point.

fn main() -> std::process::ExitCode {
    tessera_issuer::cli::main()
}

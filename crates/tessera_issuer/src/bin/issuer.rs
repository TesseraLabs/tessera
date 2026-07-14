//! `issuer` — the Tessera certificate-issuance command-line tool.
//!
//! The certificate/CRL/journal subcommands are still scaffolds (they report
//! that they are unimplemented). The `serve` subcommand is wired up when the
//! crate is built with the `serve` and `pkcs11` features: it runs the
//! browser-bridging local signing agent backed by a PKCS#11 token.

use clap::{Parser, Subcommand};

/// Tessera certificate issuance.
#[derive(Debug, Parser)]
#[command(name = "issuer", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The issuance subcommands the CLI will expose.
#[derive(Debug, Subcommand)]
enum Command {
    /// Issue an organisation CA under a parent certificate.
    IssueCa,
    /// Issue an engineer shift-leaf under a parent CA.
    IssueLeaf,
    /// Issue a CRL for a CA.
    IssueCrl,
    /// Verify an issuance journal's hash chain.
    VerifyJournal,
    /// Run the browser-bridging local signing agent.
    Serve(ServeArgs),
}

/// Flags for `issuer serve`.
#[derive(Debug, clap::Args)]
struct ServeArgs {
    /// TCP port to bind on 127.0.0.1; 0 picks an ephemeral port.
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Allowed cabinet `Origin` (repeat for several).
    #[arg(long = "allow-origin")]
    allow_origins: Vec<String>,
    /// Path to the PKCS#11 module the CA key lives in.
    #[arg(long)]
    module: Option<std::path::PathBuf>,
    /// Token label to select (defaults to the first present token).
    #[arg(long)]
    token_label: Option<String>,
    /// CA key label — also the key id the cabinet references.
    #[arg(long)]
    key: Option<String>,
    /// Signing algorithm: `ecdsa-p256`, `ecdsa-p384`, or `rsa-sha256`.
    #[arg(long, default_value = "ecdsa-p256")]
    algorithm: String,
    /// Write the pairing token to a private per-user runtime file instead of
    /// printing it (background/daemon use).
    #[arg(long)]
    daemon_token_file: bool,
    /// Path to a pinentry program for the operator-confirmation dialog
    /// (autodiscovered on PATH when unset; falls back to a terminal prompt).
    #[arg(long)]
    pinentry: Option<std::path::PathBuf>,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => run_serve(args),
        Command::IssueCa => unimplemented_stub("issue-ca"),
        Command::IssueLeaf => unimplemented_stub("issue-leaf"),
        Command::IssueCrl => unimplemented_stub("issue-crl"),
        Command::VerifyJournal => unimplemented_stub("verify-journal"),
    }
}

/// Report a not-yet-wired subcommand.
fn unimplemented_stub(name: &str) -> std::process::ExitCode {
    eprintln!("issuer: `{name}` is not implemented yet");
    std::process::ExitCode::FAILURE
}

/// Run the local signing agent when the required features are compiled in.
#[cfg(all(feature = "serve", feature = "pkcs11"))]
fn run_serve(args: ServeArgs) -> std::process::ExitCode {
    use std::process::ExitCode;

    use secrecy::SecretString;
    use tessera_issuer::confirm::DefaultConfirmer;
    use tessera_issuer::pkcs11::{Pkcs11Config, Pkcs11SignError, Pkcs11Signer};
    use tessera_issuer::serve::{serve, AgentConfig, TokenDelivery};
    use tessera_issuer::sign::{KeyId, SignatureAlgorithm};

    let Some(module_path) = args.module else {
        eprintln!("issuer serve: --module is required");
        return ExitCode::FAILURE;
    };
    let Some(key) = args.key else {
        eprintln!("issuer serve: --key is required");
        return ExitCode::FAILURE;
    };
    if args.allow_origins.is_empty() {
        eprintln!("issuer serve: at least one --allow-origin is required");
        return ExitCode::FAILURE;
    }
    let algorithm = match args.algorithm.as_str() {
        "ecdsa-p256" => SignatureAlgorithm::EcdsaWithSha256,
        "ecdsa-p384" => SignatureAlgorithm::EcdsaWithSha384,
        "rsa-sha256" => SignatureAlgorithm::RsaPkcs1Sha256,
        other => {
            eprintln!("issuer serve: unknown --algorithm `{other}`");
            return ExitCode::FAILURE;
        }
    };

    let config = Pkcs11Config {
        module_path,
        token_label: args.token_label,
        key_id: KeyId::new(key),
        algorithm,
    };
    // Agent-side PIN source: the token PIN is read from the environment, never
    // from an HTTP request and never from a command-line argument. A pinentry
    // prompt is the intended production upgrade.
    let pin_source = || {
        std::env::var("TESSERA_ISSUER_PIN")
            .ok()
            .filter(|p| !p.is_empty())
            .map(SecretString::from)
            .ok_or_else(|| Pkcs11SignError::PinUnavailable("set TESSERA_ISSUER_PIN".to_owned()))
    };
    let signer = match Pkcs11Signer::open(config, pin_source) {
        Ok(signer) => signer,
        Err(e) => {
            eprintln!("issuer serve: {e}");
            return ExitCode::FAILURE;
        }
    };
    let agent_config = AgentConfig {
        bind_port: args.port,
        allowed_origins: args.allow_origins,
        advertised_algorithms: vec![algorithm],
        token_delivery: if args.daemon_token_file {
            TokenDelivery::RuntimeFile
        } else {
            TokenDelivery::Stdout
        },
    };
    // Operator confirmation: pinentry when available, terminal prompt otherwise.
    let confirmer = DefaultConfirmer::new(args.pinentry);
    match serve(signer, confirmer, agent_config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("issuer serve: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Fallback when the agent's features are not compiled in.
#[cfg(not(all(feature = "serve", feature = "pkcs11")))]
fn run_serve(_args: ServeArgs) -> std::process::ExitCode {
    eprintln!("issuer: `serve` requires the `serve` and `pkcs11` features");
    std::process::ExitCode::FAILURE
}

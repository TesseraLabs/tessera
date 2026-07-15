//! The `issuer` command-line surface.
//!
//! Every issuing subcommand drives the same issuance core the browser cabinet
//! uses, with the same pre-signing checks — the CLI is a thin wrapper that reads
//! inputs, selects a signing backend, calls the core, and writes the artifact.
//! No check is re-implemented here (the parity requirement), so a request the
//! core refuses is refused identically from the command line.
//!
//! The subcommands are:
//!
//! - `issue-ca` / `issue-leaf` — mint a CA or an engineer shift-leaf under a
//!   parent certificate. A leaf's public key comes from either an explicit
//!   `--spki` or a `--csr` (PKCS#10); with a CSR the subject and key are taken
//!   from the request and its self-signature is checked before issuing.
//! - `issue-crl` — sign a CRL for a CA.
//! - `verify-journal` — check an issuance journal's hash chain.
//! - `csr` — build a certificate request signed by the engineer's own token key.
//! - `serve` — run the browser-bridging local signing agent (feature `serve`).
//!
//! Help text and subcommand names are English (the usual CLI convention); the
//! *result* messages an operator reads are localized through [`crate::l10n`].
//! The token PIN is never a command-line argument: the PKCS#11 backend prompts
//! for it (pinentry, falling back to `TESSERA_ISSUER_PIN`) only for the duration
//! of a signing operation.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use clap::{Args, Parser, Subcommand, ValueEnum};

use tessera_ext::delegation::DelegationConstraints;
use tessera_ext::der::{encode_tlv, TAG_INTEGER, TAG_SEQUENCE};

use crate::crl::{CrlReason, CrlRequest, RevokedEntry};
use crate::csr::{Csr, LeafRequestFromCsr, LeafScope};
use crate::error::IssueError;
use crate::journal::{FileStorage, Journal, JournalStatus, JournalStorage};
use crate::l10n::{Locale, Msg};
use crate::profile::{CaRequest, IntegrityCeiling, LeafRequest, RootRequest, Validity};
use crate::serial::Serial;
use crate::sign::{KeyId, SignatureAlgorithm, SignatureBackend};
use crate::{
    issue_ca, issue_crl, issue_leaf, issue_leaf_from_csr, issue_root, verify_lines, IssuedCert,
};

/// The top-level `issuer` command line.
#[derive(Debug, Parser)]
#[command(name = "issuer", version, about = "Tessera certificate issuance", long_about = None)]
struct Cli {
    /// Operator-message language (`ru` or `en`); overrides `TESSERA_ISSUER_LANG`
    /// and `LANG`.
    #[arg(long, global = true)]
    lang: Option<String>,
    #[command(subcommand)]
    command: Command,
}

/// The issuing subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Issue a self-signed fleet root (issuer == subject).
    IssueRoot(IssueRootArgs),
    /// Issue an organisation CA under a parent certificate.
    IssueCa(IssueCaArgs),
    /// Issue an engineer shift-leaf under a parent CA.
    IssueLeaf(IssueLeafArgs),
    /// Issue a CRL for a CA.
    IssueCrl(IssueCrlArgs),
    /// Verify an issuance journal's hash chain.
    VerifyJournal(VerifyJournalArgs),
    /// Build a certificate request signed by the engineer's token key.
    Csr(CsrArgs),
    /// Run the browser-bridging local signing agent.
    #[cfg(feature = "serve")]
    Serve(ServeArgs),
}

/// The signing backend a subcommand uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendKind {
    /// A PKCS#11 token or HSM (the default).
    Pkcs11,
    /// A Vault / `OpenBao` Transit key.
    Vault,
    /// A deterministic in-crate signer for tests (no real cryptography).
    #[value(hide = true)]
    Mock,
}

/// Backend selection and its per-backend connection flags, shared by every
/// issuing subcommand.
#[derive(Debug, Args)]
struct BackendArgs {
    /// Signing backend.
    #[arg(long, value_enum, default_value_t = BackendKind::Pkcs11)]
    backend: BackendKind,
    /// CA key identifier: the PKCS#11 `CKA_LABEL`, or the Vault key id.
    #[arg(long)]
    key: String,
    /// Signing algorithm: `ecdsa-p256`, `ecdsa-p384`, or `rsa-sha256`.
    #[arg(long, default_value = "ecdsa-p256")]
    algorithm: String,
    /// PKCS#11 module path (pkcs11 backend).
    #[arg(long)]
    module: Option<PathBuf>,
    /// PKCS#11 token label to select (pkcs11 backend).
    #[arg(long)]
    token_label: Option<String>,
    /// pinentry program for the PIN prompt (pkcs11 backend).
    #[arg(long)]
    pinentry: Option<PathBuf>,
    /// Vault base address, e.g. `https://vault.example:8200` (vault backend).
    #[arg(long)]
    vault_addr: Option<String>,
    /// Vault Transit mount path (vault backend).
    #[arg(long, default_value = "transit")]
    mount: String,
    /// Vault Transit key name; defaults to `--key` (vault backend).
    #[arg(long)]
    vault_key: Option<String>,
    /// PEM CA bundle to trust instead of the platform store (vault backend).
    #[arg(long)]
    ca_bundle: Option<PathBuf>,
    /// Send a locally computed digest with `prehashed=true` (vault backend).
    #[arg(long)]
    prehashed: bool,
}

/// Flags for `issuer issue-root`.
///
/// Like `issue-ca` but without a parent (the root is self-signed). The root
/// key's public key is supplied with `--spki` (exported from the token whose key
/// `--key` signs with); on-token public-key extraction is not implemented, for
/// the same signing-only reason as `csr`.
#[derive(Debug, Args)]
struct IssueRootArgs {
    #[command(flatten)]
    backend: BackendArgs,
    /// The root's `SubjectPublicKeyInfo` (PEM or DER).
    #[arg(long)]
    spki: PathBuf,
    /// The root's subject distinguished name (RFC 4514).
    #[arg(long)]
    subject: String,
    /// `notBefore`, Unix seconds.
    #[arg(long)]
    not_before: u64,
    /// `notAfter`, Unix seconds.
    #[arg(long)]
    not_after: u64,
    /// A role the root envelope allows (repeat for several).
    #[arg(long = "allow-role")]
    allow_roles: Vec<String>,
    /// The root envelope's integrity-level ceiling.
    #[arg(long, default_value_t = 0)]
    max_level: i8,
    /// The root envelope's TTL ceiling, seconds.
    #[arg(long, default_value_t = 0)]
    max_ttl: u64,
    /// A required tag `key=value` the envelope demands (repeat for several).
    #[arg(long = "require-tag")]
    require_tags: Vec<String>,
    /// Certificate-format version.
    #[arg(long, default_value_t = 1)]
    profile_version: u32,
    /// NDJSON issuance journal file.
    #[arg(long)]
    journal: PathBuf,
    /// Output path for the issued root certificate.
    #[arg(long)]
    out: PathBuf,
    /// Write DER instead of PEM.
    #[arg(long)]
    der: bool,
}

/// Flags for `issuer issue-ca`.
#[derive(Debug, Args)]
struct IssueCaArgs {
    #[command(flatten)]
    backend: BackendArgs,
    /// Parent certificate (PEM or DER) to issue under.
    #[arg(long)]
    parent: PathBuf,
    /// The new CA's `SubjectPublicKeyInfo` (PEM or DER).
    #[arg(long)]
    spki: PathBuf,
    /// The new CA's subject distinguished name (RFC 4514).
    #[arg(long)]
    subject: String,
    /// `notBefore`, Unix seconds.
    #[arg(long)]
    not_before: u64,
    /// `notAfter`, Unix seconds.
    #[arg(long)]
    not_after: u64,
    /// A role the CA's envelope allows (repeat for several).
    #[arg(long = "allow-role")]
    allow_roles: Vec<String>,
    /// The envelope's integrity-level ceiling.
    #[arg(long, default_value_t = 0)]
    max_level: i8,
    /// The envelope's TTL ceiling, seconds.
    #[arg(long, default_value_t = 0)]
    max_ttl: u64,
    /// A required tag `key=value` the envelope demands (repeat for several).
    #[arg(long = "require-tag")]
    require_tags: Vec<String>,
    /// Certificate-format version.
    #[arg(long, default_value_t = 1)]
    profile_version: u32,
    /// NDJSON issuance journal file.
    #[arg(long)]
    journal: PathBuf,
    /// Output path for the issued certificate.
    #[arg(long)]
    out: PathBuf,
    /// Write DER instead of PEM.
    #[arg(long)]
    der: bool,
}

/// Flags for `issuer issue-leaf`.
#[derive(Debug, Args)]
struct IssueLeafArgs {
    #[command(flatten)]
    backend: BackendArgs,
    /// Parent CA certificate (PEM or DER).
    #[arg(long)]
    parent: PathBuf,
    /// Leaf `SubjectPublicKeyInfo` (PEM or DER). Mutually exclusive with `--csr`.
    #[arg(long)]
    spki: Option<PathBuf>,
    /// Leaf key source: a PKCS#10 CSR (PEM or DER). Its subject and key are used.
    #[arg(long)]
    csr: Option<PathBuf>,
    /// Subject distinguished name (RFC 4514); required with `--spki`.
    #[arg(long)]
    subject: Option<String>,
    /// A host descriptor the leaf binds (repeat for several).
    #[arg(long = "host")]
    host_binding: Vec<String>,
    /// A user descriptor the leaf binds (repeat for several).
    #[arg(long = "user")]
    user_binding: Vec<String>,
    /// A role the leaf may activate (repeat for several).
    #[arg(long = "role")]
    allowed_roles: Vec<String>,
    /// `notBefore`, Unix seconds.
    #[arg(long)]
    not_before: u64,
    /// `notAfter`, Unix seconds.
    #[arg(long)]
    not_after: u64,
    /// Integrity-ceiling level; omit for no ceiling.
    #[arg(long)]
    max_integrity_level: Option<i8>,
    /// Integrity-ceiling category bitmask (used only with a level).
    #[arg(long, default_value_t = 0)]
    max_integrity_categories: u64,
    /// Certificate-format version.
    #[arg(long, default_value_t = 1)]
    profile_version: u32,
    /// NDJSON issuance journal file.
    #[arg(long)]
    journal: PathBuf,
    /// Output path for the issued certificate.
    #[arg(long)]
    out: PathBuf,
    /// Write DER instead of PEM.
    #[arg(long)]
    der: bool,
}

/// Flags for `issuer issue-crl`.
#[derive(Debug, Args)]
struct IssueCrlArgs {
    #[command(flatten)]
    backend: BackendArgs,
    /// Issuing CA certificate (PEM or DER).
    #[arg(long)]
    issuer: PathBuf,
    /// `thisUpdate`, Unix seconds.
    #[arg(long)]
    this_update: u64,
    /// `nextUpdate`, Unix seconds (optional).
    #[arg(long)]
    next_update: Option<u64>,
    /// The `crlNumber` for this issuance (must exceed `--last-crl-number`).
    #[arg(long)]
    crl_number: u64,
    /// The highest `crlNumber` previously issued by this CA's state.
    #[arg(long, default_value_t = 0)]
    last_crl_number: u64,
    /// A revoked entry `serial_hex:unix_date[:reason_code]` (repeat for several).
    #[arg(long = "revoke")]
    revoked: Vec<String>,
    /// NDJSON issuance journal file.
    #[arg(long)]
    journal: PathBuf,
    /// Output path for the issued CRL.
    #[arg(long)]
    out: PathBuf,
    /// Write DER instead of PEM.
    #[arg(long)]
    der: bool,
}

/// Flags for `issuer verify-journal`.
#[derive(Debug, Args)]
struct VerifyJournalArgs {
    /// NDJSON issuance journal file to verify.
    #[arg(long)]
    journal: PathBuf,
}

/// Flags for `issuer csr`.
#[derive(Debug, Args)]
struct CsrArgs {
    #[command(flatten)]
    backend: BackendArgs,
    /// Subject distinguished name (RFC 4514) for the request.
    #[arg(long)]
    subject: String,
    /// The engineer's `SubjectPublicKeyInfo` (PEM or DER), exported from the
    /// token whose key `--key` signs with.
    #[arg(long)]
    spki: PathBuf,
    /// Output path for the CSR.
    #[arg(long)]
    out: PathBuf,
    /// Write DER instead of PEM.
    #[arg(long)]
    der: bool,
}

/// Flags for `issuer serve`.
#[cfg(feature = "serve")]
#[derive(Debug, Args)]
struct ServeArgs {
    /// TCP port to bind on 127.0.0.1; 0 picks an ephemeral port.
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Allowed cabinet `Origin` (repeat for several).
    #[arg(long = "allow-origin")]
    allow_origins: Vec<String>,
    /// Path to the PKCS#11 module the CA key lives in.
    #[arg(long)]
    module: Option<PathBuf>,
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
    /// Path to a pinentry program for the operator-confirmation dialog.
    #[arg(long)]
    pinentry: Option<PathBuf>,
}

/// Parse arguments, resolve the operator locale, run the selected command, and
/// map the outcome to a process exit code (failures print a localized message to
/// stderr and exit non-zero).
///
/// This is the `issuer` binary's entry point.
#[must_use]
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let locale = Locale::resolve(cli.lang.as_deref());
    match run(cli.command, locale) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{}", err.render(locale));
            ExitCode::FAILURE
        }
    }
}

/// Dispatch one parsed command.
fn run(command: Command, locale: Locale) -> Result<(), CliError> {
    match command {
        Command::IssueRoot(args) => {
            dispatch_with_backend(&args.backend, locale, IssueRootJob { args: &args })
        }
        Command::IssueCa(args) => {
            dispatch_with_backend(&args.backend, locale, IssueCaJob { args: &args })
        }
        Command::IssueLeaf(args) => {
            dispatch_with_backend(&args.backend, locale, IssueLeafJob { args: &args })
        }
        Command::IssueCrl(args) => {
            dispatch_with_backend(&args.backend, locale, IssueCrlJob { args: &args })
        }
        Command::Csr(args) => dispatch_with_backend(&args.backend, locale, CsrJob { args: &args }),
        Command::VerifyJournal(args) => verify_journal(&args, locale),
        #[cfg(feature = "serve")]
        Command::Serve(args) => run_serve(args, locale),
    }
}

/// An error surfaced by the CLI, carrying enough to print a localized message
/// and to let a test compare against the core's own error.
#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    /// The issuance core refused the request (the same error the cabinet gets).
    Issue(IssueError),
    /// A filesystem or encoding failure reading an input or writing an output.
    Io(String),
    /// The request was malformed on the command line (missing/conflicting flags).
    Usage(String),
    /// The signing backend could not be built or reached.
    Backend(String),
}

impl CliError {
    /// The localized one-line message for this error.
    #[must_use]
    pub fn render(&self, locale: Locale) -> String {
        match self {
            // The core's error text stays English (it is an API-level message);
            // the operator-facing prefix is localized.
            CliError::Issue(e) => format!("{} {e}", Msg::CliIssuanceRefused.text(locale)),
            CliError::Io(detail) => format!("{} {detail}", Msg::CliIoError.text(locale)),
            CliError::Usage(detail) => format!("{} {detail}", Msg::CliUsage.text(locale)),
            CliError::Backend(detail) => format!("{} {detail}", Msg::CliBackendError.text(locale)),
        }
    }
}

impl From<IssueError> for CliError {
    fn from(err: IssueError) -> Self {
        CliError::Issue(err)
    }
}

/// The public-key source for a leaf: an explicit `SubjectPublicKeyInfo` or a CSR.
#[derive(Debug, Clone)]
pub enum KeySource {
    /// A `SubjectPublicKeyInfo` (DER); the subject is supplied separately.
    Spki(Vec<u8>),
    /// A PKCS#10 CSR (PEM or DER); its subject and key are used.
    Csr(Vec<u8>),
}

// --- Backend dispatch -------------------------------------------------------

/// A unit of work parameterized over the concrete signing backend.
///
/// The backend type is only known after `--backend` is read, so each subcommand
/// is a job whose generic `run` is called with the built signer. This keeps the
/// backend concrete (no `dyn`) while letting the dispatch pick it at runtime.
trait BackendJob {
    /// Execute the job against `backend`, emitting localized output.
    fn run<B: SignatureBackend>(self, backend: &B, locale: Locale) -> Result<(), CliError>;
}

/// Build the selected backend and run `job` against it.
fn dispatch_with_backend(
    args: &BackendArgs,
    locale: Locale,
    job: impl BackendJob,
) -> Result<(), CliError> {
    match args.backend {
        BackendKind::Mock => run_mock(args, locale, job),
        BackendKind::Pkcs11 => run_pkcs11(args, locale, job),
        BackendKind::Vault => run_vault(args, locale, job),
    }
}

#[cfg(any(test, feature = "test-support"))]
fn run_mock(args: &BackendArgs, locale: Locale, job: impl BackendJob) -> Result<(), CliError> {
    let signer =
        crate::sign::MockSigner::new(KeyId::new(&args.key), parse_algorithm(&args.algorithm)?);
    job.run(&signer, locale)
}

#[cfg(not(any(test, feature = "test-support")))]
fn run_mock(_args: &BackendArgs, _locale: Locale, _job: impl BackendJob) -> Result<(), CliError> {
    Err(CliError::Usage(
        "the mock backend is a test aid and needs the `test-support` feature".to_owned(),
    ))
}

#[cfg(feature = "pkcs11")]
fn run_pkcs11(args: &BackendArgs, locale: Locale, job: impl BackendJob) -> Result<(), CliError> {
    use crate::pkcs11::{Pkcs11Config, Pkcs11Signer};

    let module_path = args
        .module
        .clone()
        .ok_or_else(|| CliError::Usage("--module is required for the pkcs11 backend".to_owned()))?;
    let config = Pkcs11Config {
        module_path,
        token_label: args.token_label.clone(),
        key_id: KeyId::new(&args.key),
        algorithm: parse_algorithm(&args.algorithm)?,
    };
    let signer = Pkcs11Signer::open(config, pin::CliPinSource::new(args.pinentry.clone()))
        .map_err(|e| CliError::Backend(e.to_string()))?;
    job.run(&signer, locale)
}

#[cfg(not(feature = "pkcs11"))]
fn run_pkcs11(_args: &BackendArgs, _locale: Locale, _job: impl BackendJob) -> Result<(), CliError> {
    Err(CliError::Usage(
        "this build has no pkcs11 backend (rebuild with the `pkcs11` feature)".to_owned(),
    ))
}

#[cfg(feature = "vault")]
fn run_vault(args: &BackendArgs, locale: Locale, job: impl BackendJob) -> Result<(), CliError> {
    use crate::vault::{VaultConfig, VaultSigner};

    let address = args.vault_addr.clone().ok_or_else(|| {
        CliError::Usage("--vault-addr is required for the vault backend".to_owned())
    })?;
    // The Vault token rides in a request header, so the endpoint must be TLS;
    // reject a plaintext address here for a clear flag-level error rather than
    // letting it surface as a generic backend failure. Transit signing has no
    // plaintext mode, so there is no localhost exception.
    crate::vault::require_https(&address).map_err(|e| CliError::Usage(e.to_string()))?;
    let config = VaultConfig {
        address,
        mount: args.mount.clone(),
        key_name: args.vault_key.clone().unwrap_or_else(|| args.key.clone()),
        key_id: KeyId::new(&args.key),
        algorithm: parse_algorithm(&args.algorithm)?,
        prehashed: args.prehashed,
        ca_bundle_path: args.ca_bundle.clone(),
    };
    let signer = VaultSigner::from_env(config).map_err(|e| CliError::Backend(e.to_string()))?;
    job.run(&signer, locale)
}

#[cfg(not(feature = "vault"))]
fn run_vault(_args: &BackendArgs, _locale: Locale, _job: impl BackendJob) -> Result<(), CliError> {
    Err(CliError::Usage(
        "this build has no vault backend (rebuild with the `vault` feature)".to_owned(),
    ))
}

// --- Jobs -------------------------------------------------------------------

/// `issue-root`.
struct IssueRootJob<'a> {
    args: &'a IssueRootArgs,
}

impl BackendJob for IssueRootJob<'_> {
    fn run<B: SignatureBackend>(self, backend: &B, locale: Locale) -> Result<(), CliError> {
        let a = self.args;
        let key = KeyId::new(&a.backend.key);
        let spki = decode_pem_or_der(&read_file(&a.spki)?)?;
        let req = RootRequest {
            subject: a.subject.clone(),
            subject_spki_der: spki,
            validity: Validity {
                not_before: a.not_before,
                not_after: a.not_after,
            },
            constraints: DelegationConstraints {
                require_tags: parse_require_tags(&a.require_tags)?,
                allow_roles: a.allow_roles.clone(),
                max_level: a.max_level,
                max_ttl: a.max_ttl,
            },
            profile_version: a.profile_version,
        };
        let mut journal = open_journal(&a.journal)?;
        let serial = Serial::generate();
        let issued = issue_root(backend, &key, &req, &serial, &mut journal, now_unix()?)?;
        write_artifact(&a.out, &issued.der, "CERTIFICATE", a.der)?;
        println!("{} {}", Msg::CliCertWritten.text(locale), a.out.display());
        Ok(())
    }
}

/// `issue-ca`.
struct IssueCaJob<'a> {
    args: &'a IssueCaArgs,
}

impl BackendJob for IssueCaJob<'_> {
    fn run<B: SignatureBackend>(self, backend: &B, locale: Locale) -> Result<(), CliError> {
        let a = self.args;
        let key = KeyId::new(&a.backend.key);
        let parent = decode_pem_or_der(&read_file(&a.parent)?)?;
        let spki = decode_pem_or_der(&read_file(&a.spki)?)?;
        let req = CaRequest {
            subject: a.subject.clone(),
            subject_spki_der: spki,
            validity: Validity {
                not_before: a.not_before,
                not_after: a.not_after,
            },
            constraints: DelegationConstraints {
                require_tags: parse_require_tags(&a.require_tags)?,
                allow_roles: a.allow_roles.clone(),
                max_level: a.max_level,
                max_ttl: a.max_ttl,
            },
            profile_version: a.profile_version,
        };
        let mut journal = open_journal(&a.journal)?;
        let serial = Serial::generate();
        let issued = issue_ca(
            backend,
            &key,
            &parent,
            &req,
            &serial,
            &mut journal,
            now_unix()?,
        )?;
        write_artifact(&a.out, &issued.der, "CERTIFICATE", a.der)?;
        println!("{} {}", Msg::CliCertWritten.text(locale), a.out.display());
        Ok(())
    }
}

/// `issue-leaf`.
struct IssueLeafJob<'a> {
    args: &'a IssueLeafArgs,
}

impl BackendJob for IssueLeafJob<'_> {
    fn run<B: SignatureBackend>(self, backend: &B, locale: Locale) -> Result<(), CliError> {
        let a = self.args;
        let key = KeyId::new(&a.backend.key);
        let parent = decode_pem_or_der(&read_file(&a.parent)?)?;
        let source = build_key_source(a.spki.as_deref(), a.csr.as_deref())?;
        let scope = leaf_scope(a);

        // With a CSR, surface the request's subject and self-signature status
        // before issuing (the core re-checks proof of possession authoritatively).
        if let KeySource::Csr(csr) = &source {
            let (subject, self_signed) = describe_csr(csr)?;
            println!("{} {subject}", Msg::CliCsrSubject.text(locale));
            let status = if self_signed {
                Msg::CliCsrSelfSigValid
            } else {
                Msg::CliCsrSelfSigInvalid
            };
            println!("{}", status.text(locale));
        }

        let mut journal = open_journal(&a.journal)?;
        let serial = Serial::generate();
        let issued = issue_leaf_cmd(
            backend,
            &key,
            &parent,
            a.subject.as_deref(),
            &source,
            &scope,
            &serial,
            &mut journal,
            now_unix()?,
        )?;
        write_artifact(&a.out, &issued.der, "CERTIFICATE", a.der)?;
        println!("{} {}", Msg::CliCertWritten.text(locale), a.out.display());
        Ok(())
    }
}

/// `issue-crl`.
struct IssueCrlJob<'a> {
    args: &'a IssueCrlArgs,
}

impl BackendJob for IssueCrlJob<'_> {
    fn run<B: SignatureBackend>(self, backend: &B, locale: Locale) -> Result<(), CliError> {
        let a = self.args;
        let key = KeyId::new(&a.backend.key);
        let issuer = decode_pem_or_der(&read_file(&a.issuer)?)?;
        let mut revoked = Vec::with_capacity(a.revoked.len());
        for spec in &a.revoked {
            revoked.push(parse_revoked(spec)?);
        }
        let req = CrlRequest {
            this_update: a.this_update,
            next_update: a.next_update,
            crl_number: a.crl_number,
            revoked,
        };
        let mut journal = open_journal(&a.journal)?;
        let signed_crl = issue_crl(
            backend,
            &key,
            &issuer,
            &req,
            a.last_crl_number,
            &mut journal,
            now_unix()?,
        )?;
        write_artifact(&a.out, &signed_crl.der, "X509 CRL", a.der)?;
        println!("{} {}", Msg::CliCrlWritten.text(locale), a.out.display());
        Ok(())
    }
}

/// `csr`.
struct CsrJob<'a> {
    args: &'a CsrArgs,
}

impl BackendJob for CsrJob<'_> {
    fn run<B: SignatureBackend>(self, backend: &B, locale: Locale) -> Result<(), CliError> {
        let a = self.args;
        let key = KeyId::new(&a.backend.key);
        let spki = decode_pem_or_der(&read_file(&a.spki)?)?;
        let der = build_csr_der(backend, &key, &a.subject, &spki)?;
        write_artifact(&a.out, &der, "CERTIFICATE REQUEST", a.der)?;
        println!("{} {}", Msg::CliCsrWritten.text(locale), a.out.display());
        Ok(())
    }
}

// --- Testable command handlers ---------------------------------------------

/// Issue a shift-leaf from either an explicit SPKI (with `subject`) or a CSR.
///
/// This is the seam the CLI and the parity test share: it forwards to the same
/// core (`issue_leaf` or `issue_leaf_from_csr`) with no added checks, so a
/// widened scope is refused here exactly as it is in the core.
///
/// # Errors
///
/// [`CliError::Usage`] when `--subject` is missing for an SPKI source, otherwise
/// [`CliError::Issue`] wrapping whatever the core returns.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the core issuance signature: signer, key, parent, subject, \
              key source, scope, serial, journal and clock are each required"
)]
pub fn issue_leaf_cmd<B: SignatureBackend, S: JournalStorage>(
    backend: &B,
    key: &KeyId,
    parent_der: &[u8],
    subject: Option<&str>,
    source: &KeySource,
    scope: &LeafScope,
    serial: &Serial,
    journal: &mut Journal<S>,
    now_unix: u64,
) -> Result<IssuedCert, CliError> {
    match source {
        KeySource::Spki(spki) => {
            let subject = subject.ok_or_else(|| {
                CliError::Usage("--subject is required with an SPKI key source".to_owned())
            })?;
            let req = LeafRequest {
                subject: subject.to_owned(),
                subject_spki_der: spki.clone(),
                validity: scope.validity,
                host_binding: scope.host_binding.clone(),
                user_binding: scope.user_binding.clone(),
                allowed_roles: scope.allowed_roles.clone(),
                max_integrity: scope.max_integrity,
                profile_version: scope.profile_version,
            };
            Ok(issue_leaf(
                backend, key, parent_der, &req, serial, journal, now_unix,
            )?)
        }
        KeySource::Csr(csr) => {
            let req = LeafRequestFromCsr {
                csr: csr.clone(),
                scope: scope.clone(),
            };
            Ok(issue_leaf_from_csr(
                backend, key, parent_der, &req, serial, journal, now_unix,
            )?)
        }
    }
}

/// Build a PKCS#10 CSR: assemble the `CertificationRequestInfo`, self-sign it
/// through `backend`, and frame the `CertificationRequest`.
///
/// The tool is signing-only: the engineer's public key (`spki_der`) is supplied,
/// and the request is signed by the token key `key` addresses. Proof of
/// possession therefore holds only when that token key matches `spki_der` — the
/// engineer's responsibility, since the tool does not generate keys.
///
/// # Errors
///
/// [`CliError::Issue`] if the subject or SPKI cannot be encoded, or
/// [`CliError::Backend`] if signing fails or returns a different algorithm.
pub fn build_csr_der<B: SignatureBackend>(
    backend: &B,
    key: &KeyId,
    subject: &str,
    spki_der: &[u8],
) -> Result<Vec<u8>, CliError> {
    let algorithm = backend
        .algorithm(key)
        .map_err(|e| CliError::Backend(e.to_string()))?;
    let algid_der = crate::tbs::algorithm_identifier_der(algorithm)?;
    let subject_der = crate::tbs::subject_name_der(subject)?;
    let spki_der = crate::tbs::validated_spki_der(spki_der)?;

    // CertificationRequestInfo ::= SEQUENCE { version INTEGER(0), subject,
    // subjectPKInfo, attributes [0] IMPLICIT SET OF Attribute (empty) }.
    let mut info = Vec::new();
    info.extend_from_slice(&encode_tlv(TAG_INTEGER, &[0x00]));
    info.extend_from_slice(&subject_der);
    info.extend_from_slice(&spki_der);
    info.extend_from_slice(&encode_tlv(0xA0, &[]));
    let info_der = encode_tlv(TAG_SEQUENCE, &info);

    let signature = backend
        .sign(&info_der, key)
        .map_err(|e| CliError::Backend(e.to_string()))?;
    if signature.algorithm != algorithm {
        return Err(CliError::Backend(
            "backend signed the CSR with a different algorithm than it declared".to_owned(),
        ));
    }
    // CertificationRequest ::= SEQUENCE { info, signatureAlgorithm, signature
    // BIT STRING } — the same SEQUENCE { body, algid, BIT STRING } framing a
    // certificate uses, so the certificate assembler builds it.
    Ok(crate::tbs::assemble_certificate(
        &info_der,
        &algid_der,
        &signature.bytes,
    ))
}

/// Parse a CSR and report its subject and whether its self-signature verifies.
///
/// # Errors
///
/// [`CliError::Issue`] if the bytes are not a parseable PKCS#10 request.
pub fn describe_csr(csr: &[u8]) -> Result<(String, bool), CliError> {
    let parsed = Csr::parse(csr)?;
    let self_signed = parsed.verify_proof_of_possession().is_ok();
    Ok((parsed.subject().to_owned(), self_signed))
}

/// Verify an issuance journal file and print a localized status line.
fn verify_journal(args: &VerifyJournalArgs, locale: Locale) -> Result<(), CliError> {
    let storage = FileStorage::new(&args.journal);
    let lines = storage
        .read_lines()
        .map_err(|e| CliError::Io(e.to_string()))?;
    let report = verify_lines(&lines);
    match report.status {
        JournalStatus::Intact => println!("{}", Msg::CliJournalIntact.text(locale)),
        JournalStatus::IntactUnsignedTail { unsigned_from_seq } => println!(
            "{} {unsigned_from_seq}",
            Msg::CliJournalUnsignedTail.text(locale)
        ),
        JournalStatus::Broken { position } => {
            // A broken chain is a verification failure: report it and exit non-zero.
            return Err(CliError::Io(format!(
                "{} {position}",
                Msg::CliJournalBroken.text(locale)
            )));
        }
    }
    Ok(())
}

// --- Helpers ----------------------------------------------------------------

/// Map an algorithm flag to a [`SignatureAlgorithm`].
fn parse_algorithm(value: &str) -> Result<SignatureAlgorithm, CliError> {
    match value {
        "ecdsa-p256" => Ok(SignatureAlgorithm::EcdsaWithSha256),
        "ecdsa-p384" => Ok(SignatureAlgorithm::EcdsaWithSha384),
        "rsa-sha256" => Ok(SignatureAlgorithm::RsaPkcs1Sha256),
        other => Err(CliError::Usage(format!("unknown algorithm `{other}`"))),
    }
}

/// Resolve the leaf key source from the mutually exclusive `--spki`/`--csr`.
fn build_key_source(spki: Option<&Path>, csr: Option<&Path>) -> Result<KeySource, CliError> {
    match (spki, csr) {
        (Some(_), Some(_)) => Err(CliError::Usage(
            "--spki and --csr are mutually exclusive".to_owned(),
        )),
        (Some(path), None) => Ok(KeySource::Spki(decode_pem_or_der(&read_file(path)?)?)),
        (None, Some(path)) => Ok(KeySource::Csr(read_file(path)?)),
        (None, None) => Err(CliError::Usage(
            "one of --spki or --csr is required".to_owned(),
        )),
    }
}

/// Assemble the operator-set leaf scope from the parsed flags.
fn leaf_scope(args: &IssueLeafArgs) -> LeafScope {
    LeafScope {
        validity: Validity {
            not_before: args.not_before,
            not_after: args.not_after,
        },
        host_binding: args.host_binding.clone(),
        user_binding: args.user_binding.clone(),
        allowed_roles: args.allowed_roles.clone(),
        max_integrity: args.max_integrity_level.map(|level| IntegrityCeiling {
            level,
            categories: args.max_integrity_categories,
        }),
        profile_version: args.profile_version,
    }
}

/// Parse `key=value` required-tag flags.
fn parse_require_tags(specs: &[String]) -> Result<Vec<(String, String)>, CliError> {
    let mut tags = Vec::with_capacity(specs.len());
    for spec in specs {
        let (key, value) = spec
            .split_once('=')
            .ok_or_else(|| CliError::Usage(format!("require-tag must be key=value: `{spec}`")))?;
        tags.push((key.to_owned(), value.to_owned()));
    }
    Ok(tags)
}

/// Parse one `serial_hex:unix_date[:reason_code]` revoked-entry flag.
fn parse_revoked(spec: &str) -> Result<RevokedEntry, CliError> {
    let mut parts = spec.split(':');
    let serial_hex = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CliError::Usage(format!("revoke needs a serial: `{spec}`")))?;
    let serial =
        hex::decode(serial_hex).map_err(|e| CliError::Usage(format!("revoke serial hex: {e}")))?;
    let date = parts
        .next()
        .ok_or_else(|| CliError::Usage(format!("revoke needs a date: `{spec}`")))?
        .parse::<u64>()
        .map_err(|e| CliError::Usage(format!("revoke date: {e}")))?;
    let reason = match parts.next() {
        Some(code) => Some(parse_reason(code)?),
        None => None,
    };
    Ok(RevokedEntry {
        serial,
        revocation_date: date,
        reason,
    })
}

/// Map an RFC 5280 reason code (0–6) to a [`CrlReason`].
fn parse_reason(code: &str) -> Result<CrlReason, CliError> {
    match code {
        "0" => Ok(CrlReason::Unspecified),
        "1" => Ok(CrlReason::KeyCompromise),
        "2" => Ok(CrlReason::CaCompromise),
        "3" => Ok(CrlReason::AffiliationChanged),
        "4" => Ok(CrlReason::Superseded),
        "5" => Ok(CrlReason::CessationOfOperation),
        "6" => Ok(CrlReason::CertificateHold),
        other => Err(CliError::Usage(format!("unknown revoke reason `{other}`"))),
    }
}

/// Open the issuance journal at `path` (creating an empty chain if absent).
fn open_journal(path: &Path) -> Result<Journal<FileStorage>, CliError> {
    Journal::load(FileStorage::new(path)).map_err(|e| CliError::Io(e.to_string()))
}

/// The current Unix time, seconds.
fn now_unix() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| CliError::Io(format!("system clock before the Unix epoch: {e}")))
}

/// Read a whole file into memory.
fn read_file(path: &Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|e| CliError::Io(format!("{}: {e}", path.display())))
}

/// Write an artifact as PEM (default) or DER, and report a localized line.
fn write_artifact(path: &Path, der: &[u8], pem_label: &str, as_der: bool) -> Result<(), CliError> {
    let bytes = if as_der {
        der.to_vec()
    } else {
        encode_pem(pem_label, der).into_bytes()
    };
    std::fs::write(path, bytes).map_err(|e| CliError::Io(format!("{}: {e}", path.display())))
}

/// Decode PEM (any label) if the input begins with `-`, else pass the DER
/// through unchanged. Keying on the first non-whitespace byte avoids misreading
/// DER that merely contains a dash as PEM.
fn decode_pem_or_der(bytes: &[u8]) -> Result<Vec<u8>, CliError> {
    let looks_pem = bytes
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|&b| b == b'-');
    if !looks_pem {
        return Ok(bytes.to_vec());
    }
    let text =
        core::str::from_utf8(bytes).map_err(|_| CliError::Io("PEM is not UTF-8".to_owned()))?;
    let mut body = String::new();
    let mut in_body = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_body = true;
        } else if trimmed.starts_with("-----END") {
            break;
        } else if in_body {
            body.push_str(trimmed);
        }
    }
    if body.is_empty() {
        return Err(CliError::Io("no PEM body found".to_owned()));
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| CliError::Io(format!("PEM base64: {e}")))
}

/// PEM-encode DER under `label`, wrapping the base64 body at 64 columns.
fn encode_pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // The base64 alphabet is ASCII, so every chunk is valid UTF-8.
        out.push_str(core::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

// --- PKCS#11 PIN source -----------------------------------------------------

/// The PIN provider for the CLI's PKCS#11 backend: an interactive pinentry
/// prompt, falling back to the `TESSERA_ISSUER_PIN` environment variable.
#[cfg(feature = "pkcs11")]
mod pin {
    use std::io::{BufRead, BufReader, Write};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use secrecy::SecretString;

    use crate::pkcs11::{PinSource, Pkcs11SignError};

    /// pinentry program names probed on `PATH`, in preference order.
    const PINENTRY_NAMES: &[&str] = &[
        "pinentry",
        "pinentry-mac",
        "pinentry-gtk-2",
        "pinentry-qt",
        "pinentry-curses",
    ];

    /// A [`PinSource`] that prompts via pinentry, then falls back to the
    /// `TESSERA_ISSUER_PIN` environment variable for non-interactive use.
    pub(super) struct CliPinSource {
        explicit_pinentry: Option<PathBuf>,
    }

    impl CliPinSource {
        /// A PIN source preferring `explicit_pinentry`, then a discovered one.
        pub(super) fn new(explicit_pinentry: Option<PathBuf>) -> Self {
            Self { explicit_pinentry }
        }
    }

    impl PinSource for CliPinSource {
        fn pin(&self) -> Result<SecretString, Pkcs11SignError> {
            if let Some(program) = discover(self.explicit_pinentry.clone()) {
                if let Some(secret) = pinentry_get_pin(&program) {
                    return Ok(secret);
                }
            }
            std::env::var("TESSERA_ISSUER_PIN")
                .ok()
                .filter(|p| !p.is_empty())
                .map(SecretString::from)
                .ok_or_else(|| {
                    Pkcs11SignError::PinUnavailable(
                        "no pinentry available; set TESSERA_ISSUER_PIN".to_owned(),
                    )
                })
        }
    }

    /// Locate a pinentry program: an explicit path if present, else the first
    /// known name on `PATH`.
    fn discover(explicit: Option<PathBuf>) -> Option<PathBuf> {
        if let Some(path) = explicit {
            if path.exists() {
                return Some(path);
            }
        }
        let paths = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&paths) {
            for name in PINENTRY_NAMES {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// Run one Assuan `GETPIN` exchange, returning the entered PIN.
    ///
    /// Returns `None` on any channel or protocol failure so the caller can fall
    /// back; a cancelled prompt is also `None`.
    fn pinentry_get_pin(program: &PathBuf) -> Option<SecretString> {
        let mut child = Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut stdin = child.stdin.take()?;
        let stdout = child.stdout.take()?;
        let mut reader = BufReader::new(stdout);

        let secret = (|| {
            read_until_ok(&mut reader)?; // greeting
            send(&mut stdin, "SETPROMPT Tessera token PIN")?;
            read_until_ok(&mut reader)?;
            send(&mut stdin, "GETPIN")?;
            read_pin(&mut reader)
        })();

        if send(&mut stdin, "BYE").is_none() {
            // Best-effort teardown; the exchange already produced `secret`.
        }
        drop(stdin);
        if child.wait().is_err() {
            // Reaping best-effort.
        }
        secret
    }

    /// Send one Assuan command line.
    fn send(stdin: &mut impl Write, command: &str) -> Option<()> {
        stdin.write_all(command.as_bytes()).ok()?;
        stdin.write_all(b"\n").ok()?;
        stdin.flush().ok()
    }

    /// Read lines until a final `OK`; `None` on `ERR` or EOF.
    fn read_until_ok(reader: &mut impl BufRead) -> Option<()> {
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).ok()? == 0 {
                return None;
            }
            let trimmed = line.trim_end();
            if trimmed == "OK" || trimmed.starts_with("OK ") {
                return Some(());
            }
            if trimmed.starts_with("ERR") {
                return None;
            }
        }
    }

    /// Read the `D <pin>` data line of a `GETPIN` reply, then its `OK`.
    fn read_pin(reader: &mut impl BufRead) -> Option<SecretString> {
        let mut pin: Option<SecretString> = None;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).ok()? == 0 {
                return None;
            }
            let trimmed = line.trim_end();
            if let Some(value) = trimmed.strip_prefix("D ") {
                pin = Some(SecretString::from(value.to_owned()));
            } else if trimmed == "OK" || trimmed.starts_with("OK ") {
                return pin;
            } else if trimmed.starts_with("ERR") {
                return None;
            }
        }
    }
}

// --- serve ------------------------------------------------------------------

/// Run the local signing agent when the required features are compiled in.
#[cfg(all(feature = "serve", feature = "pkcs11"))]
fn run_serve(args: ServeArgs, locale: Locale) -> Result<(), CliError> {
    use secrecy::SecretString;

    use crate::confirm::DefaultConfirmer;
    use crate::pkcs11::{Pkcs11Config, Pkcs11SignError, Pkcs11Signer};
    use crate::serve::{serve, AgentConfig, TokenDelivery};

    let module_path = args
        .module
        .ok_or_else(|| CliError::Usage("issuer serve: --module is required".to_owned()))?;
    let key = args
        .key
        .ok_or_else(|| CliError::Usage("issuer serve: --key is required".to_owned()))?;
    if args.allow_origins.is_empty() {
        return Err(CliError::Usage(
            "issuer serve: at least one --allow-origin is required".to_owned(),
        ));
    }
    let algorithm = parse_algorithm(&args.algorithm)?;
    let config = Pkcs11Config {
        module_path,
        token_label: args.token_label,
        key_id: KeyId::new(key),
        algorithm,
    };
    // Agent-side PIN source: read from the environment for the duration of a
    // login, never from an HTTP request or a command-line argument.
    let pin_source = || {
        std::env::var("TESSERA_ISSUER_PIN")
            .ok()
            .filter(|p| !p.is_empty())
            .map(SecretString::from)
            .ok_or_else(|| Pkcs11SignError::PinUnavailable("set TESSERA_ISSUER_PIN".to_owned()))
    };
    let signer =
        Pkcs11Signer::open(config, pin_source).map_err(|e| CliError::Backend(e.to_string()))?;
    let agent_config = AgentConfig {
        bind_port: args.port,
        allowed_origins: args.allow_origins,
        advertised_algorithms: vec![algorithm],
        token_delivery: if args.daemon_token_file {
            TokenDelivery::RuntimeFile
        } else {
            TokenDelivery::Stdout
        },
        locale,
    };
    let confirmer = DefaultConfirmer::new(args.pinentry, locale);
    serve(signer, confirmer, agent_config).map_err(|e| CliError::Backend(e.to_string()))
}

/// Fallback when `serve` is enabled without the `pkcs11` backend.
#[cfg(all(feature = "serve", not(feature = "pkcs11")))]
fn run_serve(_args: ServeArgs, _locale: Locale) -> Result<(), CliError> {
    Err(CliError::Usage(
        "issuer serve requires the `pkcs11` feature".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::sign::MockSigner;
    use crate::test_support::{self_signed_ca, spki_fixture, MemoryStorage};
    use crate::{Journal, Serial};
    use tessera_ext::delegation::{DelegationConstraints, ScopeDimension};

    const TS: u64 = 1_600_000_000;

    fn key() -> KeyId {
        KeyId::new("ca-key")
    }

    fn fresh_journal() -> Journal<MemoryStorage> {
        Journal::load(MemoryStorage::new()).unwrap()
    }

    /// A root CA whose envelope allows `oper` up to level 5, TTL one day.
    fn root_der(signer: &MockSigner) -> Vec<u8> {
        let req = CaRequest {
            subject: "CN=Tessera Root".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: Validity {
                not_before: 1_600_000_000,
                not_after: 1_900_000_000,
            },
            constraints: DelegationConstraints {
                require_tags: vec![],
                allow_roles: vec!["oper".to_owned()],
                max_level: 5,
                max_ttl: 86_400,
            },
            profile_version: 1,
        };
        self_signed_ca(
            signer,
            &key(),
            &req,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .unwrap()
        .der
    }

    /// A leaf scope that widens the parent: a role the parent never allowed.
    fn widening_scope() -> LeafScope {
        LeafScope {
            validity: Validity {
                not_before: 1_600_000_000,
                not_after: 1_600_003_600,
            },
            host_binding: vec!["*".to_owned()],
            user_binding: vec!["ivanov".to_owned()],
            allowed_roles: vec!["root".to_owned()],
            max_integrity: None,
            profile_version: 1,
        }
    }

    /// The CLI wrapper and the core refuse the same widened request identically.
    #[test]
    fn cli_and_core_refuse_a_widened_scope_identically() {
        let signer = MockSigner::ecdsa_sha256(key());
        let parent = root_der(&signer);
        let scope = widening_scope();
        let spki = spki_fixture();
        let serial = Serial::generate();

        // Through the core directly.
        let core_req = LeafRequest {
            subject: "CN=ivanov".to_owned(),
            subject_spki_der: spki.clone(),
            validity: scope.validity,
            host_binding: scope.host_binding.clone(),
            user_binding: scope.user_binding.clone(),
            allowed_roles: scope.allowed_roles.clone(),
            max_integrity: scope.max_integrity,
            profile_version: scope.profile_version,
        };
        let core_err = issue_leaf(
            &signer,
            &key(),
            &parent,
            &core_req,
            &serial,
            &mut fresh_journal(),
            TS,
        )
        .unwrap_err();

        // Through the CLI wrapper.
        let cli_err = issue_leaf_cmd(
            &signer,
            &key(),
            &parent,
            Some("CN=ivanov"),
            &KeySource::Spki(spki),
            &scope,
            &serial,
            &mut fresh_journal(),
            TS,
        )
        .unwrap_err();

        match cli_err {
            CliError::Issue(inner) => {
                assert_eq!(inner, core_err);
                assert!(matches!(
                    inner,
                    IssueError::ScopeWidened(ScopeDimension::AllowRoles)
                ));
            }
            other => panic!("expected a wrapped issuance error, got {other:?}"),
        }
    }

    /// A missing subject on the SPKI path is a usage error, not an issuance one.
    #[test]
    fn spki_source_without_subject_is_a_usage_error() {
        let signer = MockSigner::ecdsa_sha256(key());
        let parent = root_der(&signer);
        let err = issue_leaf_cmd(
            &signer,
            &key(),
            &parent,
            None,
            &KeySource::Spki(spki_fixture()),
            &widening_scope(),
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .unwrap_err();
        assert!(matches!(err, CliError::Usage(_)), "{err:?}");
    }

    /// Build a real, self-signed P-256 CSR (valid proof of possession).
    fn valid_p256_csr(subject: &str, seed: [u8; 32]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        use p256::pkcs8::EncodePublicKey as _;

        let signing_key = p256::ecdsa::SigningKey::from_slice(&seed).unwrap();
        let spki_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let subject_der = crate::tbs::subject_name_der(subject).unwrap();
        let spki_der = crate::tbs::validated_spki_der(&spki_der).unwrap();

        let mut info = Vec::new();
        info.extend_from_slice(&encode_tlv(TAG_INTEGER, &[0x00]));
        info.extend_from_slice(&subject_der);
        info.extend_from_slice(&spki_der);
        info.extend_from_slice(&encode_tlv(0xA0, &[]));
        let info_der = encode_tlv(TAG_SEQUENCE, &info);

        let signature: p256::ecdsa::Signature = signing_key.sign(&info_der);
        let algid =
            crate::tbs::algorithm_identifier_der(SignatureAlgorithm::EcdsaWithSha256).unwrap();
        crate::tbs::assemble_certificate(&info_der, &algid, signature.to_der().as_bytes())
    }

    /// `issue-leaf --csr` uses the CSR's subject and key and reports a valid
    /// self-signature.
    #[test]
    fn csr_source_issues_and_describe_reports_valid() {
        let signer = MockSigner::ecdsa_sha256(key());
        let parent = root_der(&signer);
        let csr = valid_p256_csr("CN=ivanov,O=Org", [0x22; 32]);

        let (subject, valid) = describe_csr(&csr).unwrap();
        assert_eq!(subject, "CN=ivanov,O=Org");
        assert!(valid, "a freshly self-signed CSR must verify");

        let scope = LeafScope {
            validity: Validity {
                not_before: 1_600_000_000,
                not_after: 1_600_003_600,
            },
            host_binding: vec!["*".to_owned()],
            user_binding: vec!["ivanov".to_owned()],
            allowed_roles: vec!["oper".to_owned()],
            max_integrity: None,
            profile_version: 1,
        };
        let issued = issue_leaf_cmd(
            &signer,
            &key(),
            &parent,
            None,
            &KeySource::Csr(csr),
            &scope,
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .unwrap();
        assert!(!issued.der.is_empty());
    }

    /// A malformed CSR is refused before any signing, with a wrapped issuance
    /// error (non-zero exit at the binary boundary).
    #[test]
    fn broken_csr_is_refused() {
        assert!(describe_csr(b"not a CSR at all").is_err());

        let signer = MockSigner::ecdsa_sha256(key());
        let parent = root_der(&signer);
        let err = issue_leaf_cmd(
            &signer,
            &key(),
            &parent,
            None,
            &KeySource::Csr(b"not a CSR".to_vec()),
            &widening_scope(),
            &Serial::generate(),
            &mut fresh_journal(),
            TS,
        )
        .unwrap_err();
        assert!(
            matches!(err, CliError::Issue(IssueError::CsrParse(_))),
            "{err:?}"
        );
    }

    /// `csr` builds a well-formed PKCS#10 request carrying the given subject.
    #[test]
    fn build_csr_produces_a_parseable_request() {
        let signer = MockSigner::ecdsa_sha256(key());
        let der = build_csr_der(&signer, &key(), "CN=engineer,O=Org", &spki_fixture()).unwrap();
        let parsed = Csr::parse(&der).unwrap();
        assert_eq!(parsed.subject(), "CN=engineer,O=Org");
        // Round-trips through PEM as well.
        let pem = encode_pem("CERTIFICATE REQUEST", &der);
        let reparsed = Csr::parse(pem.as_bytes()).unwrap();
        assert_eq!(reparsed.subject(), "CN=engineer,O=Org");
    }

    /// PEM and DER cert inputs decode to the same bytes.
    #[test]
    fn pem_and_der_inputs_decode_equally() {
        let der = vec![0x30u8, 0x03, 0x02, 0x01, 0x2a];
        let pem = encode_pem("CERTIFICATE", &der);
        assert_eq!(decode_pem_or_der(&der).unwrap(), der);
        assert_eq!(decode_pem_or_der(pem.as_bytes()).unwrap(), der);
    }
}

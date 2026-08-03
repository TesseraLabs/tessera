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
//!
//! Help text and subcommand names are English (the usual CLI convention); the
//! *result* messages an operator reads are localized through [`crate::l10n`].
//! The token PIN is never a command-line argument: no flag takes a secret by
//! value. It is obtained for the duration of a signing operation through the
//! ladder in [`secret`] — a source named by a flag, else a pinentry program on
//! `PATH`, else a console prompt with the echo off, else `TESSERA_ISSUER_PIN`
//! with a warning — and the file backend's key passphrase the same way.

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

/// Default TTL ceiling of a fleet root's delegation envelope, seconds (one
/// year). The dimension bounds the lifetime of the organisation CA issued
/// directly under the root, so it is measured in the units an organisation CA
/// is rotated in, not the units a shift lasts.
const ROOT_MAX_TTL_SECS: u64 = 31_536_000;

/// Default TTL ceiling of an organisation CA's delegation envelope, seconds
/// (four hours). This dimension bounds the shift leaf, so it matches the shift
/// length used throughout the issuance documentation.
const ORG_CA_MAX_TTL_SECS: u64 = 14_400;

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
    /// Lay an issued credential out on a carrier.
    PrepareCarrier(PrepareCarrierArgs),
    /// Verify an issuance journal's hash chain.
    VerifyJournal(VerifyJournalArgs),
    /// Build a certificate request signed by the engineer's token key.
    Csr(CsrArgs),
}

/// The signing backend a subcommand uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendKind {
    /// A PKCS#11 token or HSM (the default).
    Pkcs11,
    /// A Vault / `OpenBao` Transit key.
    Vault,
    /// An on-disk PKCS#8 CA key file.
    File,
    /// A deterministic in-crate signer for tests (no real cryptography).
    #[value(hide = true)]
    Mock,
}

impl BackendKind {
    /// The value `--backend` takes for this backend, for error messages.
    fn flag_value(self) -> &'static str {
        match self {
            BackendKind::Pkcs11 => "pkcs11",
            BackendKind::Vault => "vault",
            BackendKind::File => "file",
            BackendKind::Mock => "mock",
        }
    }
}

/// Backend selection and its per-backend connection flags, shared by every
/// issuing subcommand.
#[derive(Debug, Args)]
struct BackendArgs {
    /// Signing backend.
    #[arg(long, value_enum, default_value_t = BackendKind::Pkcs11)]
    backend: BackendKind,
    /// CA key identifier: the PKCS#11 `CKA_LABEL`, or the Vault key id. Required
    /// for pkcs11/vault; optional for the file backend, where it defaults to the
    /// key file's basename without extension.
    #[arg(long)]
    key: Option<String>,
    /// Signing algorithm: `ecdsa-p256`, `ecdsa-p384`, or `rsa-sha256`. Defaults
    /// to `ecdsa-p256` for pkcs11/vault; for the file backend the algorithm is
    /// derived from the key and this flag is only a cross-check.
    #[arg(long)]
    algorithm: Option<String>,
    /// PKCS#11 module path (pkcs11 backend).
    #[arg(long)]
    module: Option<PathBuf>,
    /// PKCS#11 token label to select (pkcs11 backend).
    #[arg(long)]
    token_label: Option<String>,
    /// PKCS#8 CA key file, PEM or DER (file backend).
    #[arg(long)]
    key_file: Option<PathBuf>,
    /// pinentry program for the PIN prompt (pkcs11 backend) or the key
    /// passphrase prompt (file backend). Naming one pins the secret source: no
    /// other source is consulted.
    #[arg(long, conflicts_with_all = ["pin_stdin", "pin_file", "key_passphrase_stdin", "key_passphrase_file"])]
    pinentry: Option<PathBuf>,
    /// Read the token PIN as one line from standard input (pkcs11 backend).
    #[arg(long, conflicts_with_all = ["pin_file", "key_passphrase_stdin"])]
    pin_stdin: bool,
    /// Read the token PIN as one line from a file readable only by its owner
    /// (pkcs11 backend). The flag takes the file's path, never the PIN itself.
    #[arg(long)]
    pin_file: Option<PathBuf>,
    /// Read the CA key passphrase as one line from standard input (file
    /// backend).
    #[arg(long, conflicts_with_all = ["key_passphrase_file"])]
    key_passphrase_stdin: bool,
    /// Read the CA key passphrase as one line from a file readable only by its
    /// owner (file backend). The flag takes the file's path, never the
    /// passphrase itself.
    #[arg(long)]
    key_passphrase_file: Option<PathBuf>,
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

#[cfg(any(feature = "pkcs11", feature = "file"))]
impl BackendArgs {
    /// The PIN source the operator named, if any.
    ///
    /// Only one can be present: the flags are mutually exclusive at parsing, so
    /// the order the arms are tried here never decides anything.
    #[cfg(feature = "pkcs11")]
    fn pin_source(&self) -> Option<secret::FlagSource> {
        if let Some(program) = self.pinentry.clone() {
            return Some(secret::FlagSource::Pinentry(program));
        }
        if self.pin_stdin {
            return Some(secret::FlagSource::Stdin);
        }
        self.pin_file.clone().map(secret::FlagSource::File)
    }

    /// The key-passphrase source the operator named, if any.
    #[cfg(feature = "file")]
    fn key_passphrase_source(&self) -> Option<secret::FlagSource> {
        if let Some(program) = self.pinentry.clone() {
            return Some(secret::FlagSource::Pinentry(program));
        }
        if self.key_passphrase_stdin {
            return Some(secret::FlagSource::Stdin);
        }
        self.key_passphrase_file
            .clone()
            .map(secret::FlagSource::File)
    }
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
    /// A role the root envelope allows (repeat for several). Required: the
    /// envelope's role list is a closed whitelist, so a root issued without one
    /// allows no role at all and no login under it can ever succeed. There is no
    /// default because role names belong to the deployment — any guess would
    /// either repeat that dead end or silently widen the envelope beyond what
    /// the operator named.
    #[arg(long = "allow-role", required = true)]
    allow_roles: Vec<String>,
    /// The root envelope's integrity-level ceiling.
    #[arg(long, default_value_t = 0)]
    max_level: i8,
    /// The root envelope's TTL ceiling, seconds. Here it bounds the lifetime of
    /// an organisation CA issued under the root, hence the year-scale default;
    /// `0` is rejected because it would demand a zero-lifetime child.
    #[arg(
        long,
        default_value_t = ROOT_MAX_TTL_SECS,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    max_ttl: u64,
    /// A required tag `key=value` the envelope demands (repeat for several).
    #[arg(long = "require-tag")]
    require_tags: Vec<String>,
    /// Certificate-format version. `0` is the current format and the only one
    /// an Engine accepts out of the box — raise it only for a fleet whose
    /// configuration already admits the newer version.
    #[arg(long, default_value_t = 0)]
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
    /// A role the CA's envelope allows (repeat for several). Required for the
    /// same reason as on `issue-root`: an empty list is a closed whitelist with
    /// no entries, so nothing issued under this CA can authenticate.
    #[arg(long = "allow-role", required = true)]
    allow_roles: Vec<String>,
    /// The envelope's integrity-level ceiling.
    #[arg(long, default_value_t = 0)]
    max_level: i8,
    /// The envelope's TTL ceiling, seconds. Here it bounds the lifetime of a
    /// shift leaf issued under this CA, hence the shift-scale default; `0` is
    /// rejected because it would demand a zero-lifetime leaf.
    #[arg(
        long,
        default_value_t = ORG_CA_MAX_TTL_SECS,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    max_ttl: u64,
    /// A required tag `key=value` the envelope demands (repeat for several).
    #[arg(long = "require-tag")]
    require_tags: Vec<String>,
    /// Certificate-format version. `0` is the current format and the only one
    /// an Engine accepts out of the box — raise it only for a fleet whose
    /// configuration already admits the newer version.
    #[arg(long, default_value_t = 0)]
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "the struct is the command line: each flag is one boolean and \
              folding them into enums would change the operator-facing syntax"
)]
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
    /// Generate the leaf key pair here instead of taking one in. The private key
    /// exists only in memory and in the container written to `--out-p12`.
    #[arg(long, conflicts_with_all = ["spki", "csr"])]
    generate_key: bool,
    /// Type of key to generate: `ecdsa-p256` (the default), `ecdsa-p384`,
    /// `rsa-2048`, `rsa-3072` or `rsa-4096`. Only with `--generate-key`.
    #[arg(long)]
    key_type: Option<String>,
    /// Output path for the PKCS#12 container. Required with, and only valid
    /// with, `--generate-key`.
    #[arg(long)]
    out_p12: Option<PathBuf>,
    /// Chain certificates to package beside the leaf (PEM, may hold several);
    /// defaults to the parent certificate alone. Only with `--generate-key`.
    #[arg(long)]
    chain: Option<PathBuf>,
    /// Read the container password as one line from standard input. Without any
    /// `--p12-passphrase-*` flag the tool generates one and shows it once.
    #[arg(long, conflicts_with_all = ["p12_passphrase_file", "p12_passphrase_prompt"])]
    p12_passphrase_stdin: bool,
    /// Read the container password as one line from a file readable only by its
    /// owner. The flag takes the file's path, never the password itself.
    #[arg(long, conflicts_with = "p12_passphrase_prompt")]
    p12_passphrase_file: Option<PathBuf>,
    /// Ask for the container password interactively (a pinentry dialog, else a
    /// console prompt with the echo off).
    #[arg(long)]
    p12_passphrase_prompt: bool,
    /// Subject distinguished name (RFC 4514); required with `--spki` and with
    /// `--generate-key`.
    #[arg(long)]
    subject: Option<String>,
    /// A host descriptor the leaf binds (repeat for several).
    #[arg(long = "host")]
    host_binding: Vec<String>,
    /// A role the leaf may activate — and, since the account name is the role,
    /// the account it admits its holder into (repeat for several).
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
    /// Certificate-format version. `0` is the current format and the only one
    /// an Engine accepts out of the box — raise it only for a fleet whose
    /// configuration already admits the newer version.
    #[arg(long, default_value_t = 0)]
    profile_version: u32,
    /// NDJSON issuance journal file.
    #[arg(long)]
    journal: PathBuf,
    /// Output path for the issued certificate. Optional with `--generate-key`,
    /// where the certificate also travels inside the container.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Write DER instead of PEM.
    #[arg(long)]
    der: bool,
}

/// Flags for `issuer prepare-carrier`.
///
/// The command has no signing backend: it moves already-issued artifacts onto a
/// carrier and signs nothing.
#[derive(Debug, Args)]
struct PrepareCarrierArgs {
    /// The PKCS#12 container to place.
    #[arg(long)]
    p12: PathBuf,
    /// The trust chain to place beside it (PEM).
    #[arg(long)]
    chain: Option<PathBuf>,
    /// The mounted carrier to lay the artifacts out on.
    #[arg(long)]
    media: Option<PathBuf>,
    /// Container path relative to the carrier, for a fleet whose devices
    /// configure `pkcs12_path_pattern` away from the default.
    #[arg(long)]
    container_path: Option<String>,
    /// PKCS#11 module of a passive token to write the container to.
    #[arg(long)]
    module: Option<PathBuf>,
    /// Label of the token data object holding the container.
    #[arg(long)]
    object_label: Option<String>,
    /// Token label to select. Worth naming whenever more than one token is
    /// plugged in: without it the first slot with a token wins, which is as
    /// likely to be the CA token as the carrier.
    #[arg(long)]
    token_label: Option<String>,
    /// pinentry program for the token PIN prompt. Naming one pins the secret
    /// source: no other source is consulted.
    #[arg(long, conflicts_with_all = ["pin_stdin", "pin_file"])]
    pinentry: Option<PathBuf>,
    /// Read the token PIN as one line from standard input.
    #[arg(long, conflicts_with_all = ["pin_file"])]
    pin_stdin: bool,
    /// Read the token PIN as one line from a file readable only by its owner.
    /// The flag takes the file's path, never the PIN itself.
    #[arg(long)]
    pin_file: Option<PathBuf>,
    /// Replace an existing container without asking.
    #[arg(long)]
    force: bool,
}

#[cfg(feature = "pkcs11")]
impl PrepareCarrierArgs {
    /// The PIN source the operator named, if any.
    fn pin_source(&self) -> Option<secret::FlagSource> {
        if let Some(program) = self.pinentry.clone() {
            return Some(secret::FlagSource::Pinentry(program));
        }
        if self.pin_stdin {
            return Some(secret::FlagSource::Stdin);
        }
        self.pin_file.clone().map(secret::FlagSource::File)
    }
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
        Command::PrepareCarrier(args) => prepare_carrier(&args, locale),
        Command::VerifyJournal(args) => verify_journal(&args, locale),
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
    reject_foreign_secret_flags(args, locale)?;
    match args.backend {
        BackendKind::Mock => run_mock(args, locale, job),
        BackendKind::Pkcs11 => run_pkcs11(args, locale, job),
        BackendKind::Vault => run_vault(args, locale, job),
        BackendKind::File => run_file(args, locale, job),
    }
}

/// Refuse a secret-source flag that belongs to a backend other than the one
/// selected.
///
/// The sources are per-backend: `--pin-*` feeds the PKCS#11 token PIN,
/// `--key-passphrase-*` the file backend's key, and neither Vault nor the mock
/// signer asks for a secret at all. A flag for another backend is read by
/// nobody, so accepting it would silently run the operation from a source the
/// operator did not name — a dialog, or the environment variable — while their
/// command line says otherwise.
fn reject_foreign_secret_flags(args: &BackendArgs, locale: Locale) -> Result<(), CliError> {
    let asks_for_a_pin = args.backend == BackendKind::Pkcs11;
    let asks_for_a_passphrase = args.backend == BackendKind::File;
    let foreign = [
        (
            "--pinentry",
            args.pinentry.is_some(),
            asks_for_a_pin || asks_for_a_passphrase,
        ),
        ("--pin-stdin", args.pin_stdin, asks_for_a_pin),
        ("--pin-file", args.pin_file.is_some(), asks_for_a_pin),
        (
            "--key-passphrase-stdin",
            args.key_passphrase_stdin,
            asks_for_a_passphrase,
        ),
        (
            "--key-passphrase-file",
            args.key_passphrase_file.is_some(),
            asks_for_a_passphrase,
        ),
    ]
    .into_iter()
    .find_map(|(flag, given, applies)| (given && !applies).then_some(flag));

    match foreign {
        None => Ok(()),
        Some(flag) => Err(CliError::Usage(format!(
            "{} {flag} (--backend {})",
            Msg::CliSecretFlagForeignBackend.text(locale),
            args.backend.flag_value(),
        ))),
    }
}

/// Resolve the key identifier the backend and the job both use.
///
/// `--key` names it directly. It is required for every backend except the file
/// backend, which defaults it to the key file's basename (there is no key
/// namespace in a file). Keeping this in one place guarantees the signer and the
/// issuance job agree on the id passed through [`SignatureBackend`].
fn effective_key_id(args: &BackendArgs) -> Result<KeyId, CliError> {
    if let Some(key) = args.key.as_deref().filter(|k| !k.is_empty()) {
        return Ok(KeyId::new(key));
    }
    if args.backend == BackendKind::File {
        if let Some(id) = args.key_file.as_deref().and_then(key_id_from_path) {
            return Ok(KeyId::new(id));
        }
    }
    Err(CliError::Usage("--key is required".to_owned()))
}

/// The key file's basename without extension, used as the default file-backend
/// key id.
fn key_id_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .filter(|stem| !stem.is_empty())
}

/// Resolve the signing algorithm for backends that take it as configuration
/// (pkcs11/vault/mock), defaulting to `ecdsa-p256`. The file backend derives its
/// algorithm from the key instead, so it does not use this.
#[cfg(any(test, feature = "test-support", feature = "pkcs11", feature = "vault"))]
fn resolved_algorithm(args: &BackendArgs) -> Result<SignatureAlgorithm, CliError> {
    parse_algorithm(args.algorithm.as_deref().unwrap_or("ecdsa-p256"))
}

#[cfg(any(test, feature = "test-support"))]
fn run_mock(args: &BackendArgs, locale: Locale, job: impl BackendJob) -> Result<(), CliError> {
    let signer = crate::sign::MockSigner::new(effective_key_id(args)?, resolved_algorithm(args)?);
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
        key_id: effective_key_id(args)?,
        algorithm: resolved_algorithm(args)?,
        // The CLI issuing path signs only with the issuance key; a dedicated
        // registry key is configured by external signing frontends, not here.
        registry_key: None,
    };
    let signer = Pkcs11Signer::open(config, pin::CliPinSource::new(args.pin_source(), locale))
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
    let key_id = effective_key_id(args)?;
    let config = VaultConfig {
        address,
        mount: args.mount.clone(),
        key_name: args
            .vault_key
            .clone()
            .unwrap_or_else(|| key_id.as_str().to_owned()),
        key_id,
        algorithm: resolved_algorithm(args)?,
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

#[cfg(feature = "file")]
fn run_file(args: &BackendArgs, locale: Locale, job: impl BackendJob) -> Result<(), CliError> {
    use crate::file::{FileConfig, FileSigner};

    let path = args
        .key_file
        .clone()
        .ok_or_else(|| CliError::Usage("--key-file is required for the file backend".to_owned()))?;
    // The file backend derives the algorithm from the key; an explicit
    // `--algorithm` is only a cross-check, so pass it through as-is (None means
    // "no cross-check") rather than substituting a default.
    let requested_algorithm = args.algorithm.as_deref().map(parse_algorithm).transpose()?;
    let key_id = effective_key_id(args)?;
    let passphrase = keypass::FilePassphraseSource::new(args.key_passphrase_source(), locale);
    let signer = FileSigner::open(
        FileConfig {
            path: path.clone(),
            key_id,
            requested_algorithm,
        },
        &passphrase,
    )
    .map_err(|e| CliError::Backend(e.to_string()))?;
    // The CA key passes the same owner-only gate as a secret file. Where the
    // platform has no such check, say so: silence would read as a permission
    // check that ran and found nothing wrong. It is said only once the key is
    // actually open — a warning about a file the run never got to read would
    // point the operator at the wrong thing.
    if let Some(notice) =
        secret::unchecked_gate_notice(crate::secret_file::GATE_ENFORCED, locale, &path)
    {
        secret::warn(&mut std::io::stderr(), &notice);
    }
    // A plaintext CA key is accepted but flagged on every start.
    if !signer.key_is_encrypted() {
        eprintln!("{}", Msg::FilePlaintextKeyWarning.text(locale));
    }
    job.run(&signer, locale)
}

#[cfg(not(feature = "file"))]
fn run_file(_args: &BackendArgs, _locale: Locale, _job: impl BackendJob) -> Result<(), CliError> {
    Err(CliError::Usage(
        "this build has no file backend (rebuild with the `file` feature)".to_owned(),
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
        let key = effective_key_id(&a.backend)?;
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
        let key = effective_key_id(&a.backend)?;
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
        // Before anything is read from disk: a flag that will be ignored is a
        // usage error, and saying so costs nothing here.
        if !a.generate_key {
            reject_generation_flags(a)?;
        }
        let key = effective_key_id(&a.backend)?;
        let parent = decode_pem_or_der(&read_file(&a.parent)?)?;
        let scope = leaf_scope(a);

        if a.generate_key {
            return self.run_generating(backend, &key, &parent, &scope, locale);
        }

        let source = build_key_source(a.spki.as_deref(), a.csr.as_deref())?;

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
        let out = a.out.as_deref().ok_or_else(|| {
            CliError::Usage("--out is required without --generate-key".to_owned())
        })?;
        write_artifact(out, &issued.der, "CERTIFICATE", a.der)?;
        println!("{} {}", Msg::CliCertWritten.text(locale), out.display());
        Ok(())
    }
}

impl IssueLeafJob<'_> {
    /// The `--generate-key` path: mint the key, issue, package, write.
    ///
    /// Everything the operator gets out of this is written here, in one place,
    /// because the private key exists only for the length of the call — there is
    /// no later step that could pick it up.
    fn run_generating<B: SignatureBackend>(
        self,
        backend: &B,
        key: &KeyId,
        parent: &[u8],
        scope: &LeafScope,
        locale: Locale,
    ) -> Result<(), CliError> {
        let a = self.args;
        let subject = a.subject.as_deref().ok_or_else(|| {
            CliError::Usage("--subject is required with --generate-key".to_owned())
        })?;
        let out_p12 = a.out_p12.as_deref().ok_or_else(|| {
            CliError::Usage("--out-p12 is required with --generate-key".to_owned())
        })?;
        let key_type = crate::keygen::LeafKeyType::parse(
            a.key_type.as_deref().unwrap_or(DEFAULT_LEAF_KEY_TYPE),
        )?;

        // Without a chain file the parent CA is the chain: it is the one
        // certificate the leaf provably needs, and it is already in hand.
        let chain = match a.chain.as_deref() {
            Some(path) => decode_pem_chain(&read_file(path)?)?,
            None => vec![parent.to_vec()],
        };

        let passphrase = p12pass::resolve(a, locale)?;
        let mut entropy = crate::keygen::OsEntropy;
        let mut journal = open_journal(&a.journal)?;
        let serial = Serial::generate();
        let generated = crate::issue_leaf_generating_key(
            backend,
            key,
            parent,
            &crate::GeneratedLeafRequest {
                subject: subject.to_owned(),
                key_type,
                scope: scope.clone(),
                chain_der: &chain,
            },
            passphrase.expose(),
            &serial,
            &mut journal,
            &mut entropy,
            now_unix()?,
        )?;

        write_container(out_p12, &generated.container)?;
        println!(
            "{} {}",
            Msg::CliContainerWritten.text(locale),
            out_p12.display()
        );
        if let Some(out) = a.out.as_deref() {
            write_artifact(out, &generated.cert.der, "CERTIFICATE", a.der)?;
            println!("{} {}", Msg::CliCertWritten.text(locale), out.display());
        }
        // The generated password is shown last so it is the final thing on the
        // operator's screen, and only when the tool made it up: one the operator
        // supplied is already theirs to keep.
        if let Some(shown) = passphrase.shown_once() {
            show_generated_passphrase(shown, locale)?;
        }
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
        let key = effective_key_id(&a.backend)?;
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
        let key = effective_key_id(&a.backend)?;
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

/// The key type generated when the operator names none.
///
/// P-256 rather than RSA: every supported device verifies it, and it is the one
/// choice whose generation does not make the operator wait.
const DEFAULT_LEAF_KEY_TYPE: &str = "ecdsa-p256";

/// Refuse a `--generate-key` flag on a run that is not generating a key.
///
/// `clap` cannot express this: a flag with a default value counts as present, so
/// `requires` never fires. Left unchecked, an operator who forgot
/// `--generate-key` would get a normal issuance and no container, with their
/// `--out-p12` silently ignored — the shape of mistake that is only noticed when
/// the engineer has nothing to log in with.
fn reject_generation_flags(args: &IssueLeafArgs) -> Result<(), CliError> {
    let stray = [
        ("--key-type", args.key_type.is_some()),
        ("--out-p12", args.out_p12.is_some()),
        ("--chain", args.chain.is_some()),
        ("--p12-passphrase-stdin", args.p12_passphrase_stdin),
        ("--p12-passphrase-file", args.p12_passphrase_file.is_some()),
        ("--p12-passphrase-prompt", args.p12_passphrase_prompt),
    ]
    .into_iter()
    .find_map(|(flag, given)| given.then_some(flag));

    match stray {
        None => Ok(()),
        Some(flag) => Err(CliError::Usage(format!(
            "{flag} applies only to --generate-key"
        ))),
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

/// Write a PKCS#12 container, readable by its owner alone.
///
/// The certificates the tool writes are public; this file is not — it carries a
/// private key, and the password protecting that key travels separately and may
/// not have reached the engineer yet.
///
/// The bytes go into a fresh file beside the target and are renamed over it.
/// `create_new` is what makes the mode hold: setting a mode on `open` affects
/// only a file being created, so writing straight to the target would inherit
/// whatever mode it already had — and would follow a symlink sitting there,
/// putting the key wherever it points. The rename also means a reader never
/// sees a half-written container.
///
/// Windows has no equivalent one-call restriction here; the file inherits the
/// directory's ACL, which is the platform's own answer to the same question.
fn write_container(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write as _;

    let io = |p: &Path, e: std::io::Error| CliError::Io(format!("{}: {e}", p.display()));

    let mut staged_name = std::ffi::OsString::from(".tessera-staging-");
    staged_name.push(path.file_name().unwrap_or_else(|| "container".as_ref()));
    let staged = path.with_file_name(staged_name);
    drop(std::fs::remove_file(&staged));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&staged).map_err(|e| io(&staged, e))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| io(&staged, e));
    drop(file);
    if let Err(e) = written {
        drop(std::fs::remove_file(&staged));
        return Err(e);
    }
    std::fs::rename(&staged, path).map_err(|e| io(path, e))
}

/// Decode every PEM block of a chain file into DER, in file order.
///
/// A chain file holds one certificate or several; the single-block decoder
/// would silently take only the first, which is exactly the kind of quiet loss
/// that surfaces later as an unverifiable chain on a device.
fn decode_pem_chain(bytes: &[u8]) -> Result<Vec<Vec<u8>>, CliError> {
    let chain = decode_pem_blocks(bytes)?;
    // Decoding base64 says nothing about what was inside it. The container's
    // certificate safe is unencrypted by design, so a file that is not a
    // certificate — the CA key file sits under an adjacent flag — would be
    // published in the clear. Each block is reported as the chain element it
    // is: an operator told "the leaf certificate" would go and check the wrong
    // file.
    for (index, der) in chain.iter().enumerate() {
        crate::pkcs12::check_certificate(der, &format!("chain element {index}"))
            .map_err(|e| CliError::Usage(format!("--chain: {e}")))?;
    }
    Ok(chain)
}

/// Split a PEM file into the DER of each block, in file order.
fn decode_pem_blocks(bytes: &[u8]) -> Result<Vec<Vec<u8>>, CliError> {
    let looks_pem = bytes
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|&b| b == b'-');
    if !looks_pem {
        return Ok(vec![bytes.to_vec()]);
    }
    let text =
        core::str::from_utf8(bytes).map_err(|_| CliError::Io("PEM is not UTF-8".to_owned()))?;
    let mut out = Vec::new();
    let mut body = String::new();
    let mut in_body = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_body = true;
            body.clear();
        } else if trimmed.starts_with("-----END") {
            in_body = false;
            let der = base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .map_err(|e| CliError::Io(format!("PEM base64: {e}")))?;
            out.push(der);
        } else if in_body {
            body.push_str(trimmed);
        }
    }
    if out.is_empty() {
        return Err(CliError::Io("no PEM certificate found".to_owned()));
    }
    Ok(out)
}

/// Refuse to generate a password there is nobody to show.
///
/// A generated password is shown once and nowhere else, so a run that cannot
/// show it produces a container no one can ever open. Writing it into a
/// captured stream instead — a CI log, a `tee` file — would mean treating it as
/// compromised from the moment it is issued.
///
/// This runs before the key is generated and before anything is journaled, so
/// the refusal costs nothing and leaves nothing behind.
fn require_terminal_for_generated_passphrase(locale: Locale) -> Result<(), CliError> {
    use std::io::IsTerminal as _;

    if std::io::stderr().is_terminal() {
        return Ok(());
    }
    Err(CliError::Usage(
        Msg::CliContainerPassphraseNoTerminal
            .text(locale)
            .to_owned(),
    ))
}

/// Show a generated container password, once, to a person.
///
/// Standard error, not standard output: the password is not part of the
/// artifact stream an operator pipes into a file or a log, and the same crate
/// already sends its environment-variable warning there. That the stream is a
/// terminal was settled before the issuance ran.
fn show_generated_passphrase(passphrase: &str, locale: Locale) -> Result<(), CliError> {
    use std::io::Write as _;

    let mut stderr = std::io::stderr();
    writeln!(
        stderr,
        "{}",
        Msg::CliContainerPassphraseHeading.text(locale)
    )
    .and_then(|()| writeln!(stderr, "{passphrase}"))
    .map_err(|e| CliError::Io(format!("stderr: {e}")))
}

/// Check that a chain about to be laid out belongs to the container beside it.
///
/// The container's certificate safe is unencrypted, so the leaf is readable
/// here without the password — and when it is, the chain can be checked against
/// it rather than taken on trust. A container this tool did not build may hide
/// its leaf; then there is nothing to check against and the chain's own
/// well-formedness, already established, is all that can be said.
fn check_chain_against_container(container: &[u8], chain: &[Vec<u8>]) -> Result<(), CliError> {
    let Ok(certs) = crate::pkcs12::certificates_without_passphrase(container) else {
        return Ok(());
    };
    let Some(leaf) = certs.first() else {
        return Ok(());
    };
    crate::pkcs12::check_chain(leaf, chain)
        .map_err(|e| CliError::Usage(format!("--chain does not match --p12: {e}")))
}

/// `prepare-carrier`: lay an already-issued credential out where the device's
/// check looks for it.
///
/// Nothing is signed and no secret is read: the command moves files. The one
/// judgement it makes is about replacing a container that is already there,
/// which it never does without a yes.
fn prepare_carrier(args: &PrepareCarrierArgs, locale: Locale) -> Result<(), CliError> {
    if args.module.is_some() || args.object_label.is_some() {
        return prepare_token_carrier(args, locale);
    }
    let media = args
        .media
        .as_deref()
        .ok_or_else(|| CliError::Usage("--media is required".to_owned()))?;

    // A mounted carrier reads no PIN and selects no token, so the flags that
    // supply those are refused rather than dropped. Every other incompatible
    // combination this command can be given is refused out loud; a `--pin-file`
    // accepted and ignored would let an operator believe a PIN was involved in
    // protecting what was just written to a plain directory.
    if let Some(flag) = token_only_flag(args) {
        return Err(CliError::Usage(format!(
            "{flag} describes a token carrier; a run with --media takes neither a PIN nor a \
             token label"
        )));
    }

    if let Some(relative) = args.container_path.as_deref() {
        crate::carrier::check_container_path(relative)
            .map_err(|e| CliError::Usage(e.to_string()))?;
    }

    let container = read_file(&args.p12)?;
    // The chain is validated before it is copied: `certs/chain.pem` is read by
    // the device, and a file that is not a chain fails there, not here.
    let chain = match args.chain.as_deref() {
        Some(path) => {
            let bytes = read_file(path)?;
            let certs = decode_pem_chain(&bytes)?;
            check_chain_against_container(&container, &certs)?;
            Some(bytes)
        }
        None => None,
    };

    let overwrite = resolve_overwrite(media, args, locale)?;
    let written = crate::carrier::lay_out_media(
        media,
        &crate::carrier::CarrierPayload {
            container: &container,
            chain_pem: chain.as_deref(),
        },
        args.container_path.as_deref(),
        overwrite,
    )
    .map_err(|e| CliError::Io(e.to_string()))?;

    println!("{}", Msg::CliCarrierWritten.text(locale));
    println!("  {}", written.container.display());
    if let Some(path) = written.chain {
        println!("  {}", path.display());
    }
    Ok(())
}

/// The first flag given that only a token carrier can act on, if any.
///
/// Named separately from the check that uses it so the list is one place: these
/// are declared unconditionally on the command (a build without the `pkcs11`
/// feature has them too, and can act on none of them).
fn token_only_flag(args: &PrepareCarrierArgs) -> Option<&'static str> {
    [
        ("--pinentry", args.pinentry.is_some()),
        ("--pin-stdin", args.pin_stdin),
        ("--pin-file", args.pin_file.is_some()),
        ("--token-label", args.token_label.is_some()),
    ]
    .into_iter()
    .find_map(|(flag, given)| given.then_some(flag))
}

/// `prepare-carrier` against a passive token: write the container into a
/// private data object.
///
/// Only the container travels this way. The trust chain stays on the device
/// side, and a run that asks for both is refused rather than half-served: an
/// operator told the carrier was prepared would not go looking for the chain.
#[cfg(feature = "pkcs11")]
fn prepare_token_carrier(args: &PrepareCarrierArgs, locale: Locale) -> Result<(), CliError> {
    use crate::carrier::{Overwrite, TokenTarget};
    use crate::pkcs11::PinSource as _;

    let module = args
        .module
        .as_deref()
        .ok_or_else(|| CliError::Usage("--object-label needs --module".to_owned()))?;
    let object_label = args
        .object_label
        .as_deref()
        .ok_or_else(|| CliError::Usage("--module needs --object-label".to_owned()))?;
    if args.media.is_some() || args.container_path.is_some() {
        return Err(CliError::Usage(
            "--media and --container-path describe a mounted carrier; a token takes \
             --module and --object-label"
                .to_owned(),
        ));
    }
    if args.chain.is_some() {
        return Err(CliError::Usage(
            "a token carries the container only; place the chain on the device or on a \
             mounted carrier"
                .to_owned(),
        ));
    }
    crate::carrier::check_object_label(object_label).map_err(|e| CliError::Usage(e.to_string()))?;

    // The size is judged from the directory entry first, so a file far too big
    // to be a container is refused without a copy of it in memory. It is not
    // the check that decides — a length read separately from the bytes can be
    // stale — only the one that keeps the obvious case cheap.
    if let Ok(metadata) = std::fs::metadata(&args.p12) {
        let claimed = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        crate::carrier::check_container_fits(claimed)
            .map_err(|e| CliError::Usage(e.to_string()))?;
    }
    let container = read_file(&args.p12)?;
    // Before the PIN is asked for: a container that cannot be written is not
    // worth interrupting the operator over.
    crate::carrier::check_container_fits(container.len())
        .map_err(|e| CliError::Usage(e.to_string()))?;

    let pin =
        pin::CliPinSource::for_carrier(args.pin_source(), args.token_label.as_deref(), locale)
            .pin()
            .map_err(|e| CliError::Usage(e.to_string()))?;
    let overwrite = if args.force {
        Overwrite::Allow
    } else {
        Overwrite::Refuse
    };

    let written = crate::carrier::lay_out_token(
        &TokenTarget {
            module_path: module,
            token_label: args.token_label.as_deref(),
            object_label,
        },
        &container,
        &pin,
        overwrite,
    )
    .map_err(|e| match e {
        // The replacement is a second decision, and it is taken with the token
        // in hand rather than in an answer typed after a PIN prompt.
        crate::carrier::CarrierError::TokenObjectExists(_) => {
            CliError::Usage(format!("{e}; re-run with --force"))
        }
        other => CliError::Io(other.to_string()),
    })?;

    println!("{}", Msg::CliCarrierWritten.text(locale));
    println!(
        "  {} ({} bytes) -> {} {}",
        written.object_label, written.bytes, written.token_label, written.token_serial
    );
    Ok(())
}

/// The refusal a build without the PKCS#11 feature gives for a token carrier.
#[cfg(not(feature = "pkcs11"))]
fn prepare_token_carrier(_args: &PrepareCarrierArgs, _locale: Locale) -> Result<(), CliError> {
    Err(CliError::Usage(
        crate::carrier::lay_out_token()
            .err()
            .map_or_else(String::new, |e| e.to_string()),
    ))
}

/// Decide whether an existing container may be replaced.
///
/// `--force` is the operator's yes given up front. Otherwise they are asked, and
/// a run with nobody to ask stops rather than guessing: the container in place
/// may be another engineer's working credential.
fn resolve_overwrite(
    media: &Path,
    args: &PrepareCarrierArgs,
    locale: Locale,
) -> Result<crate::carrier::Overwrite, CliError> {
    use crate::carrier::Overwrite;

    if args.force {
        return Ok(Overwrite::Allow);
    }
    let at_risk = crate::carrier::artifact_at_risk(
        media,
        args.container_path.as_deref(),
        args.chain.is_some(),
    )
    .map_err(|e| CliError::Usage(e.to_string()))?;
    let Some(target) = at_risk else {
        return Ok(Overwrite::Refuse);
    };
    match ask_yes_no(&format!(
        "{} {}",
        Msg::CliCarrierOverwriteAsk.text(locale),
        target.display()
    )) {
        Some(true) => Ok(Overwrite::Allow),
        Some(false) => Err(CliError::Usage(
            Msg::CliCarrierOverwriteDeclined.text(locale).to_owned(),
        )),
        None => Err(CliError::Usage(format!(
            "{} {}",
            Msg::CliCarrierOverwriteNeedsConfirmation.text(locale),
            target.display()
        ))),
    }
}

/// Ask a yes/no question on the terminal.
///
/// `None` means there was no terminal to ask on — distinct from a "no", because
/// the caller treats an unanswerable question and a refusal differently.
fn ask_yes_no(question: &str) -> Option<bool> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};

    if !std::io::stdin().is_terminal() {
        return None;
    }
    // Asked on standard error, where the answer is read from: printing to
    // standard output would leave an operator whose output is redirected
    // staring at a blank screen while the tool waits for an answer to a
    // question they never saw.
    let mut stderr = std::io::stderr();
    write!(stderr, "{question} ").ok()?;
    stderr.flush().ok()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer).ok()?;
    let answer = answer.trim().to_ascii_lowercase();
    Some(answer == "y" || answer == "yes")
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

// --- Secret prompting (pinentry) --------------------------------------------

/// Shared pinentry prompting for the interactive secrets: the PKCS#11 token
/// PIN, the file-backend key passphrase, and an operator-chosen container
/// password. The Assuan exchange is the same; only the prompt caption differs,
/// so the exchange lives here and the [`secret`] ladder wraps it as one of its
/// sources.
mod prompt {
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use secrecy::SecretString;

    /// pinentry program names probed on `PATH`, in preference order.
    const PINENTRY_NAMES: &[&str] = &[
        "pinentry",
        "pinentry-mac",
        "pinentry-gtk-2",
        "pinentry-qt",
        "pinentry-curses",
    ];

    /// Prompt for a secret with `program`, or `None` if the dialog produced
    /// none (it is missing, it failed, or the operator cancelled).
    ///
    /// `prompt` is the caption shown in the dialog (e.g. the token PIN or the
    /// key passphrase).
    pub(super) fn ask(program: &Path, prompt: &str) -> Option<SecretString> {
        pinentry_get_secret(program, prompt)
    }

    /// The first known pinentry program on `PATH`, if any.
    pub(super) fn discover_on_path() -> Option<PathBuf> {
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

    /// Run one Assuan `GETPIN` exchange under `prompt`, returning the entry.
    ///
    /// Returns `None` on any channel or protocol failure so the caller can fall
    /// back; a cancelled prompt is also `None`.
    fn pinentry_get_secret(program: &Path, prompt: &str) -> Option<SecretString> {
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
            send(&mut stdin, &format!("SETPROMPT {prompt}"))?;
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

    /// Read the `D <secret>` data line(s) of a `GETPIN` reply, then its `OK`.
    ///
    /// Assuan may split the secret across several `D` lines and percent-encodes
    /// `%`, CR and LF (and any other escaped octet); the payloads are
    /// concatenated and decoded as one. Only the line terminator is stripped — a
    /// secret's own trailing spaces are significant. A malformed escape, a
    /// non-UTF-8 result, or an `OK` with no preceding data yields `None` (the
    /// caller falls back to the environment) rather than a silently corrupted
    /// secret.
    fn read_pin(reader: &mut impl BufRead) -> Option<SecretString> {
        let mut payload = String::new();
        let mut seen_data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).ok()? == 0 {
                return None;
            }
            let line = strip_line_terminator(&line);
            if let Some(value) = line.strip_prefix("D ") {
                payload.push_str(value);
                seen_data = true;
            } else if line == "OK" || line.starts_with("OK ") {
                if !seen_data {
                    return None;
                }
                let bytes = percent_decode(&payload)?;
                let text = String::from_utf8(bytes).ok()?;
                return Some(SecretString::from(text));
            } else if line.starts_with("ERR") {
                return None;
            }
        }
    }

    /// Strip a single line terminator (`\n`, optionally preceded by `\r`) and
    /// nothing else: a secret's own trailing spaces must survive.
    fn strip_line_terminator(line: &str) -> &str {
        line.strip_suffix('\n')
            .map_or(line, |rest| rest.strip_suffix('\r').unwrap_or(rest))
    }

    /// Percent-decode an Assuan data payload (`%XX` for `%`, CR, LF and any other
    /// escaped octet) to its raw bytes.
    ///
    /// Returns `None` on a malformed escape — a `%` not followed by two hex
    /// digits — so a truncated or corrupted reply is refused rather than turned
    /// into a wrong secret.
    fn percent_decode(payload: &str) -> Option<Vec<u8>> {
        let bytes = payload.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while let Some(&byte) = bytes.get(i) {
            if byte == b'%' {
                let hi = hex_value(*bytes.get(i + 1)?)?;
                let lo = hex_value(*bytes.get(i + 2)?)?;
                out.push((hi << 4) | lo);
                i += 3;
            } else {
                out.push(byte);
                i += 1;
            }
        }
        Some(out)
    }

    /// A single hex digit's value (`0..=15`), or `None` if it is not a hex digit.
    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

        use secrecy::ExposeSecret as _;

        use super::{hex_value, percent_decode, read_pin, strip_line_terminator};

        /// Run `read_pin` over a canned pinentry reply and expose the result.
        fn pin(reply: &[u8]) -> Option<String> {
            read_pin(&mut &reply[..]).map(|s| s.expose_secret().to_owned())
        }

        #[test]
        fn decodes_percent_escape_in_the_pin() {
            // A PIN containing '%' arrives percent-encoded as %25.
            assert_eq!(pin(b"D 12%2534\nOK\n").as_deref(), Some("12%34"));
        }

        #[test]
        fn decodes_escaped_newline_without_treating_it_as_a_line_break() {
            // %0A is an embedded newline in the secret, not a protocol line end.
            assert_eq!(pin(b"D a%0Ab\nOK\n").as_deref(), Some("a\nb"));
        }

        #[test]
        fn concatenates_multiple_data_lines() {
            assert_eq!(pin(b"D abc\nD def\nOK\n").as_deref(), Some("abcdef"));
        }

        #[test]
        fn preserves_significant_trailing_space() {
            // A trailing space is real PIN content, not line noise to trim.
            assert_eq!(pin(b"D pw \nOK\n").as_deref(), Some("pw "));
        }

        #[test]
        fn handles_crlf_line_endings() {
            assert_eq!(pin(b"D secret\r\nOK\r\n").as_deref(), Some("secret"));
        }

        #[test]
        fn malformed_escape_is_refused() {
            // A truncated escape and a non-hex escape both refuse (fall back),
            // never a silently mangled secret.
            assert!(pin(b"D bad%2\nOK\n").is_none());
            assert!(pin(b"D bad%zz\nOK\n").is_none());
        }

        #[test]
        fn non_utf8_result_is_refused() {
            // %FF alone is not valid UTF-8 — refuse rather than corrupt.
            assert!(pin(b"D x%FFy\nOK\n").is_none());
        }

        #[test]
        fn err_and_bare_ok_yield_none() {
            assert!(pin(b"ERR 83886179 Operation cancelled\n").is_none());
            assert!(pin(b"OK\n").is_none());
        }

        #[test]
        fn strip_line_terminator_keeps_inner_and_trailing_spaces() {
            assert_eq!(strip_line_terminator("D x \r\n"), "D x ");
            assert_eq!(strip_line_terminator("D x \n"), "D x ");
            assert_eq!(strip_line_terminator("no-eol"), "no-eol");
        }

        #[test]
        fn percent_decode_edge_cases() {
            assert_eq!(percent_decode("A%42C").as_deref(), Some(&b"ABC"[..]));
            assert_eq!(percent_decode("").as_deref(), Some(&b""[..]));
            assert!(percent_decode("A%4").is_none());
            assert!(percent_decode("%g0").is_none());
        }

        #[test]
        fn hex_value_maps_both_cases() {
            assert_eq!(hex_value(b'0'), Some(0));
            assert_eq!(hex_value(b'9'), Some(9));
            assert_eq!(hex_value(b'a'), Some(10));
            assert_eq!(hex_value(b'F'), Some(15));
            assert_eq!(hex_value(b'g'), None);
        }
    }
}

/// The ladder of secret sources shared by the backends that need one: the
/// PKCS#11 token PIN and the file backend's CA key passphrase.
///
/// The order is fixed — a source named by a flag, else a pinentry program found
/// on `PATH`, else a console prompt with the echo off, else an environment
/// variable — and it exists to keep the environment variable last. A pinentry
/// program ships with `GnuPG`, which is not present on a stock macOS or Windows
/// workstation; without the console step those two platforms would have the
/// variable as their only source, and a token PIN in the environment is visible
/// to every child process and lands in memory dumps.
///
/// A source named by a flag is used *alone*: an unattended run that named one
/// must fail rather than block on a dialog nobody is there to answer.
///
/// Whatever the source, the secret is held in a [`SecretString`] (zeroized when
/// dropped), never logged, never journaled, and never accepted as a flag value —
/// the file and stdin sources take a path or a stream, so no secret can appear
/// in `argv`.
mod secret {
    use std::io::IsTerminal as _;
    use std::path::{Path, PathBuf};

    use secrecy::SecretString;
    use zeroize::Zeroizing;

    use crate::l10n::{Locale, Msg};

    /// A secret source named on the command line.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum FlagSource {
        /// An operator-supplied Assuan-compatible dialog (`--pinentry`).
        Pinentry(PathBuf),
        /// One line on standard input (`--pin-stdin` / `--key-passphrase-stdin`).
        Stdin,
        /// One line of an owner-only file (`--pin-file` / `--key-passphrase-file`).
        File(PathBuf),
    }

    /// One rung of the ladder: a source to try, in the order [`rungs`] returns.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Rung {
        /// Ask an Assuan-compatible dialog at this path.
        Pinentry(PathBuf),
        /// Read one line from standard input.
        Stdin,
        /// Read one line from this file.
        File(PathBuf),
        /// Prompt on the attached terminal with the echo off.
        Console,
        /// Take the value of the environment variable.
        Env,
    }

    /// The process facts the ladder's non-flag rungs depend on.
    ///
    /// Kept as data so the precedence can be tested without a terminal, a
    /// pinentry program, or a mutated environment.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    struct Facts {
        /// A pinentry program found on `PATH`, if any.
        discovered_pinentry: Option<PathBuf>,
        /// Whether a terminal is attached for a console prompt.
        console: bool,
        /// Whether the environment variable holds a non-empty value.
        env_present: bool,
    }

    impl Facts {
        /// Probe the running process for the non-flag rungs, given whether the
        /// environment variable was found to hold a value.
        fn probe(env_present: bool) -> Self {
            Self {
                discovered_pinentry: super::prompt::discover_on_path(),
                console: console_attached(),
                env_present,
            }
        }
    }

    /// The outside world the ladder reaches for: the environment variable's
    /// value and the stream warnings go to.
    ///
    /// Both are passed in rather than read and written where they are needed, so
    /// the rungs can be exercised without mutating the process environment
    /// (which `edition 2024` makes `unsafe`) and without capturing a process-wide
    /// stderr shared with every other test.
    ///
    /// The environment value is read once, into a buffer that is wiped when it
    /// is dropped: probing the variable with a throwaway `String` would leave a
    /// copy of the secret in freed memory even on the runs that never use it.
    struct Ports<'a> {
        /// The environment variable's value, an empty one treated as unset.
        env: Option<Zeroizing<String>>,
        /// Where operator warnings are written.
        warn: &'a mut dyn std::io::Write,
    }

    /// One backend secret: what to call it, and where its non-flag sources are.
    pub(super) struct Request<'a> {
        /// The source named on the command line, if the operator named one.
        pub(super) explicit: Option<&'a FlagSource>,
        /// The prompt caption shown to the operator.
        pub(super) caption: Msg,
        /// Which device the caption is about, when the tool can be more
        /// specific than the caption alone — the token label of a carrier, say.
        /// An operator with two tokens plugged in has to be able to tell from
        /// the prompt which one the PIN is going to.
        pub(super) subject: Option<&'a str>,
        /// The environment variable of last resort.
        pub(super) env_var: &'static str,
        /// The flags that can name a source, for the message shown when none of
        /// the sources produced a secret.
        pub(super) flags: &'static str,
        /// The operator-message locale.
        pub(super) locale: Locale,
    }

    /// A localized failure of the secret ladder.
    ///
    /// Carries a message already rendered in the operator's locale and nothing
    /// else — in particular never a secret, and never a partially read buffer.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct SecretError {
        /// The localized text shown to the operator.
        message: String,
    }

    impl core::fmt::Display for SecretError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl std::error::Error for SecretError {}

    /// Obtain the secret described by `request`, walking the ladder.
    ///
    /// # Errors
    ///
    /// [`SecretError`] when a source was reached and failed (an unreadable or
    /// over-permissive file, a broken console), or when no source produced a
    /// secret at all — the latter message names every source that could.
    pub(super) fn resolve(request: &Request<'_>) -> Result<SecretString, SecretError> {
        // A named source short-circuits the probe: with one given, the ladder
        // must not touch `PATH`, the terminal, or the environment at all.
        let mut stderr = std::io::stderr();
        let mut ports = Ports {
            env: if request.explicit.is_some() {
                None
            } else {
                env_value(request.env_var)
            },
            warn: &mut stderr,
        };
        resolve_with(request, &mut ports)
    }

    /// Walk the ladder over the given ports — the body of [`resolve`], with the
    /// process services it supplies made explicit.
    fn resolve_with(
        request: &Request<'_>,
        ports: &mut Ports<'_>,
    ) -> Result<SecretString, SecretError> {
        let facts = if request.explicit.is_some() {
            Facts::default()
        } else {
            Facts::probe(ports.env.is_some())
        };
        for rung in rungs(request.explicit, &facts) {
            if let Some(secret) = climb(&rung, request, ports)? {
                return Ok(secret);
            }
        }
        Err(unavailable(request))
    }

    /// The sources to try, most preferred first.
    ///
    /// A named source is the whole ladder. Otherwise the rungs are those the
    /// process actually has, in the fixed order the module documents.
    fn rungs(explicit: Option<&FlagSource>, facts: &Facts) -> Vec<Rung> {
        if let Some(source) = explicit {
            return vec![match source {
                FlagSource::Pinentry(program) => Rung::Pinentry(program.clone()),
                FlagSource::Stdin => Rung::Stdin,
                FlagSource::File(path) => Rung::File(path.clone()),
            }];
        }
        let mut ladder = Vec::new();
        if let Some(program) = &facts.discovered_pinentry {
            ladder.push(Rung::Pinentry(program.clone()));
        }
        if facts.console {
            ladder.push(Rung::Console);
        }
        if facts.env_present {
            ladder.push(Rung::Env);
        }
        ladder
    }

    /// Try one rung: `Ok(Some)` on a secret, `Ok(None)` when the rung produced
    /// none and the next may be tried, `Err` when the rung failed outright.
    ///
    /// A rung the operator *named* never falls through: the pinning must not be
    /// undone by continuing to a source they did not ask for, so a named file,
    /// stream or dialog that yields nothing is an error. A rung the ladder chose
    /// on its own is different — it was chosen from a guess about the process,
    /// and a guess that proves wrong (no dialog answers, the terminal cannot be
    /// opened) is exactly what the rungs below it are for.
    fn climb(
        rung: &Rung,
        request: &Request<'_>,
        ports: &mut Ports<'_>,
    ) -> Result<Option<SecretString>, SecretError> {
        let caption = prompt_caption(request);
        let caption = caption.as_str();
        match rung {
            Rung::Pinentry(program) => match super::prompt::ask(program, caption) {
                Some(secret) => Ok(Some(secret)),
                None if request.explicit.is_some() => Err(error(
                    request,
                    Msg::SecretPinentryFailed,
                    &program.display().to_string(),
                )),
                None => Ok(None),
            },
            Rung::Stdin => {
                let line = read_stdin_line()
                    .map_err(|e| line_error(request, &e, Msg::SecretStdinUnreadable, "stdin"))?;
                let text = as_text(&line)
                    .map_err(|e| error(request, Msg::SecretStdinUnreadable, &e.to_string()))?;
                accept(request, text, "stdin")
            }
            Rung::File(path) => read_secret_file(path, request, ports),
            Rung::Console => match rpassword::prompt_password(format!("{caption}: ")) {
                Ok(entered) => accept(request, &Zeroizing::new(entered), "console"),
                // The console rung is chosen by looking at standard input and
                // standard error, while the prompt reads the terminal device
                // itself (`/dev/tty`, `CONIN$`). When the two disagree the rung
                // simply cannot start, and the ladder continues; an entry the
                // operator ended — interrupted, or closed with no input — is an
                // answer, and stops it.
                Err(e) if console_failure_is_fatal(e.kind()) => {
                    Err(error(request, Msg::SecretConsoleFailed, &e.to_string()))
                }
                Err(_) => Ok(None),
            },
            Rung::Env => {
                let value = ports.env.as_ref().ok_or_else(|| unavailable(request))?;
                let warning = env_warning(request.locale, request.env_var);
                warn(&mut *ports.warn, &warning);
                accept(request, value, request.env_var)
            }
        }
    }

    /// The caption a prompt carries: the request's own, with the device it is
    /// about appended when there is one.
    ///
    /// The subject is what stops a PIN going to the wrong device. Two tokens on
    /// one workstation is the ordinary case for an operator preparing a
    /// credential, and each has its own attempt counter — a PIN presented to
    /// the other one is not a typo to retry, it is one attempt spent.
    fn prompt_caption(request: &Request<'_>) -> String {
        let caption = request.caption.text(request.locale);
        match request.subject {
            Some(subject) => format!("{caption} ({subject})"),
            None => caption.to_owned(),
        }
    }

    /// Write one warning line to the warning stream.
    ///
    /// A warning that cannot be written is dropped: the secret is in hand and
    /// the operation is sound, so failing it over an unwritable stderr would
    /// trade a real issuance for a note about one.
    pub(super) fn warn(sink: &mut dyn std::io::Write, line: &str) {
        let written = writeln!(sink, "{line}");
        drop(written);
    }

    /// Whether a failed console prompt ends the ladder.
    ///
    /// Two failures mean the operator was at the prompt and declined: an
    /// interrupt (`Ctrl-C`) and an end of input with nothing entered (`Ctrl-D`,
    /// `Ctrl-Z` on Windows), which `rpassword` reports as an unexpected
    /// end-of-file. Reaching past either for the environment variable would
    /// answer a question they refused to answer, and the variable is the last
    /// resort for a process with no terminal — not for one whose operator said
    /// no. Every other failure says the prompt never got to ask, and the ladder
    /// goes on.
    fn console_failure_is_fatal(kind: std::io::ErrorKind) -> bool {
        matches!(
            kind,
            std::io::ErrorKind::Interrupted | std::io::ErrorKind::UnexpectedEof
        )
    }

    /// Read a secret file: the owner-only gate first, its first line second.
    ///
    /// The gate runs on the open handle before any byte is read, so a file
    /// reachable beyond its owner never puts its content in memory and the file
    /// read is the file checked. It is the same gate the file backend applies to
    /// the CA key. On a platform without that check the operator is told so —
    /// silence here would read as "the permissions were checked and are fine".
    fn read_secret_file(
        path: &Path,
        request: &Request<'_>,
        ports: &mut Ports<'_>,
    ) -> Result<Option<SecretString>, SecretError> {
        let unreadable = |e: &dyn core::fmt::Display| {
            error(
                request,
                Msg::SecretFileUnreadable,
                &format!("{}: {e}", path.display()),
            )
        };
        let opened = crate::secret_file::open(path).map_err(|e| match e {
            crate::secret_file::OpenError::Io(e) => unreadable(&e),
            crate::secret_file::OpenError::BeyondOwner(refusal) => error(
                request,
                Msg::SecretFileBeyondOwner,
                &format!("{} (mode {:04o})", path.display(), refusal.mode),
            ),
        })?;
        let origin = path.display().to_string();
        if let Some(notice) =
            unchecked_gate_notice(crate::secret_file::GATE_ENFORCED, request.locale, path)
        {
            warn(&mut *ports.warn, &notice);
        }
        let line = opened
            .read_first_line()
            .map_err(|e| line_error(request, &e, Msg::SecretFileUnreadable, &origin))?;
        let text = as_text(&line).map_err(|e| unreadable(&e))?;
        accept(request, text, &origin)
    }

    /// Read one line of the secret from standard input.
    ///
    /// On Unix the descriptor is reopened through `/dev/stdin` and read
    /// directly: [`std::io::Stdin`] reads through a buffer that lives in a
    /// process-wide static for the life of the process and is never wiped, so a
    /// secret read through it stays in memory long after the
    /// [`secrecy::SecretString`] built from it is gone. Where that reopening is
    /// not available — any non-Unix target, or a Unix one without `/dev` — the
    /// read falls back to that buffer and the residue is real; the file and
    /// dialog sources have no such caveat.
    ///
    /// What `/dev/stdin` *is* differs between Unixes, and so does the reopened
    /// handle's file offset. On Linux it resolves through `/proc/self/fd/0`, and
    /// reopening a regular file there yields a fresh file description starting
    /// at offset zero; on macOS it is a devfs node that duplicates descriptor 0
    /// and shares its offset. So a run that redirects standard input from a file
    /// *already partly consumed* — `exec 0<secrets.txt`, a line read away, then
    /// `issuer --pin-stdin` — takes the file's first line on Linux and the next
    /// unread one on macOS. This source is meant for a pipe or a terminal, where
    /// the two agree; a partly consumed file redirection is not a supported way
    /// to name a secret, and `--pin-file` is the source that reads a file
    /// predictably.
    fn read_stdin_line() -> Result<Zeroizing<Vec<u8>>, crate::secret_file::ReadLineError> {
        #[cfg(unix)]
        if let Ok(mut reopened) = std::fs::File::open("/dev/stdin") {
            return crate::secret_file::read_line(&mut reopened);
        }
        crate::secret_file::read_line(&mut std::io::stdin())
    }

    /// Borrow a read buffer as text, without copying it out of its wiped
    /// allocation.
    fn as_text(raw: &[u8]) -> std::io::Result<&str> {
        core::str::from_utf8(raw).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("not UTF-8: {e}"))
        })
    }

    /// Wrap a read value as the secret, refusing an empty one.
    ///
    /// An empty secret is never what the operator meant — an empty file, an
    /// empty line, a variable set to nothing — and passing it on would surface
    /// as a failed login or, on a token, as a consumed PIN attempt.
    fn accept(
        request: &Request<'_>,
        value: &str,
        origin: &str,
    ) -> Result<Option<SecretString>, SecretError> {
        if value.is_empty() {
            return Err(error(request, Msg::SecretEmpty, origin));
        }
        Ok(Some(SecretString::from(value.to_owned())))
    }

    /// Whether a terminal is attached for an interactive console prompt.
    ///
    /// Either end counts. A run whose standard input is a pipe but whose
    /// standard error is the terminal still has an operator in front of it (the
    /// shape `ssh` and `sudo` prompt in), and the console prompt reads from the
    /// terminal device rather than from standard input.
    ///
    /// That makes this an estimate: the answer is read off standard input and
    /// standard error, while the prompt opens the terminal device itself. The
    /// rung is written to survive the estimate being wrong — a prompt that
    /// cannot start hands the ladder to the next source instead of ending it.
    fn console_attached() -> bool {
        std::io::stdin().is_terminal() || std::io::stderr().is_terminal()
    }

    /// The environment variable's value, treating an empty one as unset.
    ///
    /// The value lands straight in a buffer that is wiped when it is dropped —
    /// including on the runs that only wanted to know whether the variable is
    /// set at all.
    fn env_value(name: &str) -> Option<Zeroizing<String>> {
        let value = Zeroizing::new(std::env::var(name).ok()?);
        (!value.is_empty()).then_some(value)
    }

    /// The stderr warning printed whenever the environment variable is used.
    pub(super) fn env_warning(locale: Locale, env_var: &str) -> String {
        format!("{} {env_var}", Msg::SecretEnvWarning.text(locale))
    }

    /// The warning owed to the operator when a secret-bearing file was accepted
    /// without the owner-only gate, or `None` where the gate ran.
    ///
    /// The gate's reach is a parameter rather than read here so both callers —
    /// this ladder and the file backend's key — say the same thing, and so both
    /// answers can be seen on either platform.
    pub(super) fn unchecked_gate_notice(
        gate_enforced: bool,
        locale: Locale,
        path: &Path,
    ) -> Option<String> {
        (!gate_enforced).then(|| {
            format!(
                "{} {}",
                Msg::SecretFileUncheckedPlatform.text(locale),
                path.display()
            )
        })
    }

    /// A localized error for a line that could not be read from `origin`.
    ///
    /// A secret longer than the bound is called out as its own case: read as a
    /// generic I/O failure it would send the operator looking at permissions,
    /// when what happened is that the source held no line terminator.
    fn line_error(
        request: &Request<'_>,
        failure: &crate::secret_file::ReadLineError,
        unreadable: Msg,
        origin: &str,
    ) -> SecretError {
        match failure {
            crate::secret_file::ReadLineError::TooLong => error(
                request,
                Msg::SecretTooLong,
                &format!("{origin} ({} bytes)", crate::secret_file::MAX_SECRET_LEN),
            ),
            crate::secret_file::ReadLineError::Io(e) => {
                error(request, unreadable, &format!("{origin}: {e}"))
            }
        }
    }

    /// The error shown when no source produced a secret, naming every source
    /// that could have.
    fn unavailable(request: &Request<'_>) -> SecretError {
        SecretError {
            message: format!(
                "{} {}; {} {}",
                Msg::SecretUnavailableFlags.text(request.locale),
                request.flags,
                Msg::SecretUnavailableFallbacks.text(request.locale),
                request.env_var,
            ),
        }
    }

    /// A localized ladder error: a caption from the table, then the technical
    /// detail (a path, a variable name, an OS error) that is not translated.
    fn error(request: &Request<'_>, caption: Msg, detail: &str) -> SecretError {
        SecretError {
            message: format!("{} {detail}", caption.text(request.locale)),
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

        use super::{
            accept, climb, console_failure_is_fatal, env_warning, error, line_error,
            prompt_caption, read_secret_file, resolve_with, rungs, unchecked_gate_notice, Facts,
            FlagSource, Msg, PathBuf, Ports, Request, Rung, SecretError,
        };
        use crate::l10n::Locale;
        use secrecy::ExposeSecret as _;
        use zeroize::Zeroizing;

        /// The flag list the PIN request advertises, mirrored from `pin`.
        const FLAGS: &str = "--pinentry <path>, --pin-file <path>, --pin-stdin";

        /// A warning sink and an environment holding `value`.
        fn ports<'a>(value: Option<&str>, warn: &'a mut Vec<u8>) -> Ports<'a> {
            Ports {
                env: value.map(|v| Zeroizing::new(v.to_owned())),
                warn,
            }
        }

        /// A PIN-shaped request over `explicit`.
        fn request(explicit: Option<&FlagSource>) -> Request<'_> {
            Request {
                explicit,
                caption: Msg::SecretPromptTokenPin,
                subject: None,
                env_var: "TESSERA_ISSUER_PIN",
                flags: FLAGS,
                locale: Locale::En,
            }
        }

        /// The prompt has to name the device when the request knows it: an
        /// operator with the CA token plugged in beside the carrier decides
        /// which PIN to type from this line alone.
        #[test]
        fn a_prompt_names_the_device_it_is_asking_about() {
            let named = Request {
                caption: Msg::SecretPromptCarrierPin,
                subject: Some("Rutoken Lite 483d4e1a"),
                ..request(None)
            };
            let shown = prompt_caption(&named);
            assert!(shown.contains("Rutoken Lite 483d4e1a"), "{shown}");
            assert!(shown.contains("carrier"), "{shown}");
            // With nothing to name, the caption stands alone rather than
            // growing an empty pair of brackets.
            assert_eq!(
                prompt_caption(&request(None)),
                Msg::SecretPromptTokenPin.text(Locale::En)
            );
        }

        /// A process that has every non-flag source available.
        fn everything() -> Facts {
            Facts {
                discovered_pinentry: Some(PathBuf::from("/usr/bin/pinentry")),
                console: true,
                env_present: true,
            }
        }

        /// A named dialog is the whole ladder: with `--pinentry` given, no other
        /// source is consulted even though every one of them is available.
        #[test]
        fn a_named_pinentry_is_the_only_rung() {
            let explicit = FlagSource::Pinentry(PathBuf::from("/opt/corp/pinentry"));
            assert_eq!(
                rungs(Some(&explicit), &everything()),
                vec![Rung::Pinentry(PathBuf::from("/opt/corp/pinentry"))]
            );
        }

        /// A named file wins over a pinentry on `PATH`: an unattended run must
        /// not be diverted into a dialog nobody can answer.
        #[test]
        fn a_named_file_outranks_a_discovered_pinentry() {
            let explicit = FlagSource::File(PathBuf::from("/run/secrets/pin"));
            assert_eq!(
                rungs(Some(&explicit), &everything()),
                vec![Rung::File(PathBuf::from("/run/secrets/pin"))]
            );
            let explicit = FlagSource::Stdin;
            assert_eq!(rungs(Some(&explicit), &everything()), vec![Rung::Stdin]);
        }

        /// With no flag, a pinentry on `PATH` leads and the rest follow it.
        #[test]
        fn a_discovered_pinentry_leads_the_unnamed_ladder() {
            assert_eq!(
                rungs(None, &everything()),
                vec![
                    Rung::Pinentry(PathBuf::from("/usr/bin/pinentry")),
                    Rung::Console,
                    Rung::Env,
                ]
            );
        }

        /// No pinentry but a terminal: the console prompt is used, and the
        /// environment variable is not needed to reach a secret.
        #[test]
        fn without_a_pinentry_a_terminal_makes_the_console_the_source() {
            let facts = Facts {
                discovered_pinentry: None,
                console: true,
                env_present: true,
            };
            let ladder = rungs(None, &facts);
            assert_eq!(ladder.first(), Some(&Rung::Console));

            // And with no variable set at all the console still answers.
            let facts = Facts {
                console: true,
                ..Facts::default()
            };
            assert_eq!(rungs(None, &facts), vec![Rung::Console]);
        }

        /// No pinentry and no terminal: the environment variable is the last
        /// resort, and it is announced.
        #[test]
        fn without_a_terminal_the_environment_is_the_last_resort() {
            let facts = Facts {
                discovered_pinentry: None,
                console: false,
                env_present: true,
            };
            assert_eq!(rungs(None, &facts), vec![Rung::Env]);

            let warning = env_warning(Locale::En, "TESSERA_ISSUER_PIN");
            assert!(warning.contains("TESSERA_ISSUER_PIN"));
            assert!(warning.contains("child processes"));
            assert!(env_warning(Locale::Ru, "TESSERA_ISSUER_PIN").contains("дочерним процессам"));
        }

        /// With nothing available the ladder is empty and the error names every
        /// source the operator could have offered.
        #[test]
        fn an_empty_ladder_reports_every_source() {
            assert!(rungs(None, &Facts::default()).is_empty());
            let message = super::unavailable(&request(None)).to_string();
            for source in [
                "--pinentry",
                "--pin-file",
                "--pin-stdin",
                "pinentry program on PATH",
                "interactive terminal",
                "TESSERA_ISSUER_PIN",
            ] {
                assert!(message.contains(source), "{message:?} must name {source}");
            }
        }

        /// A file reachable by group or others is refused on its metadata — the
        /// error names the mode and the content is never read.
        #[cfg(unix)]
        #[test]
        fn a_group_readable_file_is_refused_before_its_content_is_read() {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pin");
            std::fs::write(&path, "s3cret\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

            let mut warnings = Vec::new();
            let err = read_secret_file(&path, &request(None), &mut ports(None, &mut warnings))
                .unwrap_err();
            let message = err.to_string();
            assert!(message.contains("0640"), "{message:?} must name the mode");
            assert!(
                !message.contains("s3cret"),
                "the error must not carry content"
            );

            // Tightened to owner-only, the same file is read.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let secret = read_secret_file(&path, &request(None), &mut ports(None, &mut warnings))
                .unwrap()
                .unwrap();
            assert_eq!(secret.expose_secret(), "s3cret");
            // Where the gate runs, nothing is said about it.
            assert!(warnings.is_empty(), "unexpected warning: {warnings:?}");
        }

        /// A missing file is an error, not a fall-through to another source.
        #[test]
        fn a_missing_secret_file_is_an_error() {
            let dir = tempfile::tempdir().unwrap();
            let mut warnings = Vec::new();
            let err = read_secret_file(
                &dir.path().join("absent"),
                &request(None),
                &mut ports(None, &mut warnings),
            )
            .unwrap_err();
            assert!(err.to_string().contains("absent"));
        }

        /// A secret file is read to its first line and no further: the rest of
        /// the file is neither consumed nor required to arrive.
        #[test]
        fn a_secret_file_is_read_to_its_first_line_only() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pin");
            std::fs::write(&path, "s3cret\nnot-the-secret\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }

            let mut warnings = Vec::new();
            let secret = read_secret_file(&path, &request(None), &mut ports(None, &mut warnings))
                .unwrap()
                .unwrap();
            assert_eq!(secret.expose_secret(), "s3cret");
        }

        /// A source with no line break within the bound is refused by name, not
        /// as a generic read failure — and the bound is in the message.
        #[test]
        fn a_source_without_a_line_break_is_refused_by_name() {
            let failure = crate::secret_file::ReadLineError::TooLong;
            let message = line_error(
                &request(None),
                &failure,
                Msg::SecretFileUnreadable,
                "/run/secrets/pin",
            )
            .to_string();
            assert!(message.contains("no line break"), "{message:?}");
            assert!(message.contains("/run/secrets/pin"), "{message:?}");
            assert!(
                message.contains(&crate::secret_file::MAX_SECRET_LEN.to_string()),
                "{message:?} must name the bound"
            );

            let ru = Request {
                locale: Locale::Ru,
                ..request(None)
            };
            let ru_message =
                line_error(&ru, &failure, Msg::SecretFileUnreadable, "pin").to_string();
            assert!(ru_message.contains("перевода строки"), "{ru_message:?}");
        }

        /// The environment rung answers from the injected environment and says
        /// so on the warning stream, naming the variable.
        #[test]
        fn the_environment_rung_warns_and_names_the_variable() {
            let mut warnings = Vec::new();
            let secret = climb(
                &Rung::Env,
                &request(None),
                &mut ports(Some("s3cret"), &mut warnings),
            )
            .unwrap()
            .unwrap();
            assert_eq!(secret.expose_secret(), "s3cret");

            let printed = String::from_utf8(warnings).unwrap();
            assert!(
                printed.contains("TESSERA_ISSUER_PIN"),
                "{printed:?} must name the variable"
            );
            assert!(
                printed.contains("child processes"),
                "{printed:?} must say why the variable is a last resort"
            );
            assert!(
                !printed.contains("s3cret"),
                "the warning must not carry the secret"
            );
        }

        /// With the variable unset the rung reports the ladder exhausted rather
        /// than reaching for the process environment behind the ports.
        #[test]
        fn the_environment_rung_without_a_value_reports_the_ladder_exhausted() {
            let mut warnings = Vec::new();
            let err =
                climb(&Rung::Env, &request(None), &mut ports(None, &mut warnings)).unwrap_err();
            assert!(err.to_string().contains("TESSERA_ISSUER_PIN"));
            assert!(warnings.is_empty(), "nothing was used, so nothing to warn");
        }

        /// A named file is read by the whole ladder, and neither the terminal
        /// nor the environment is consulted on the way.
        #[test]
        fn a_named_file_is_served_by_the_ladder_without_the_environment() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pin");
            std::fs::write(&path, "s3cret\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }

            let explicit = FlagSource::File(path);
            let mut warnings = Vec::new();
            let secret = resolve_with(
                &request(Some(&explicit)),
                &mut ports(Some("from-the-environment"), &mut warnings),
            )
            .unwrap();
            assert_eq!(secret.expose_secret(), "s3cret");
            assert!(warnings.is_empty(), "unexpected warning: {warnings:?}");
        }

        /// A console prompt that could not start hands the ladder on; one the
        /// operator ended stops it.
        ///
        /// Both ways of ending it count. `rpassword` reports `Ctrl-C` as an
        /// interrupt and `Ctrl-D` (`Ctrl-Z` on Windows) with nothing typed as an
        /// unexpected end of input; treating the latter as "the rung could not
        /// start" would walk past a refusal straight into the environment
        /// variable.
        #[test]
        fn an_interrupted_or_ended_console_entry_stops_the_ladder() {
            assert!(console_failure_is_fatal(std::io::ErrorKind::Interrupted));
            assert!(console_failure_is_fatal(std::io::ErrorKind::UnexpectedEof));
            for kind in [
                std::io::ErrorKind::NotFound,
                std::io::ErrorKind::PermissionDenied,
                std::io::ErrorKind::BrokenPipe,
                std::io::ErrorKind::Unsupported,
            ] {
                assert!(
                    !console_failure_is_fatal(kind),
                    "{kind:?} must not be fatal"
                );
            }
        }

        /// A platform without the permission gate says so, in the operator's
        /// locale, naming the file it did not check; a platform with one says
        /// nothing.
        #[test]
        fn an_unchecked_platform_is_announced() {
            let path = PathBuf::from("/run/secrets/pin");
            let en = unchecked_gate_notice(false, Locale::En, &path).unwrap();
            assert!(en.contains("/run/secrets/pin"));
            assert!(en.contains("does not check file permissions"));
            assert!(unchecked_gate_notice(false, Locale::Ru, &path)
                .unwrap()
                .contains("права файла"));
            assert!(
                unchecked_gate_notice(true, Locale::En, &path).is_none(),
                "a gate that ran has nothing to announce"
            );
        }

        /// An empty value is refused rather than passed on as a secret.
        #[test]
        fn an_empty_value_is_refused() {
            let err = accept(&request(None), "", "stdin").unwrap_err();
            assert!(err.to_string().contains("stdin"));
        }

        /// Errors are localized and carry only the technical detail beside the
        /// caption.
        #[test]
        fn errors_are_localized() {
            let explicit = FlagSource::Stdin;
            let ru = Request {
                locale: Locale::Ru,
                ..request(Some(&explicit))
            };
            let err: SecretError = error(&ru, Msg::SecretFileUnreadable, "/run/secrets/pin");
            assert!(err.to_string().starts_with("не удалось"));
            assert!(err.to_string().ends_with("/run/secrets/pin"));
        }
    }
}

/// The PIN providers for the CLI's PKCS#11 paths: the shared secret ladder,
/// captioned and sourced per device.
///
/// The ladder is the same for both. What must not be shared is its last rung.
/// The signing backend's PIN belongs to the CA token, and a scripted issuance
/// keeps it in [`CA_PIN_ENV`] for the whole run; adding a `prepare-carrier`
/// step to that script would, with no flag and no terminal, walk the same
/// ladder down to the same variable and present the CA token's PIN to the
/// engineer's carrier. That is not a prompt to retry — it is one attempt spent
/// on a counter that locks the carrier after a few, and the token then reports
/// a login failure rather than "that PIN belongs to the other device". So the
/// carrier reads its own variable, and its prompt names the token it is for.
#[cfg(feature = "pkcs11")]
mod pin {
    use secrecy::SecretString;

    use crate::l10n::{Locale, Msg};
    use crate::pkcs11::{PinSource, Pkcs11SignError};

    use super::secret::{self, FlagSource, Request};

    /// The flags that name a PIN source, for the message shown when none did.
    const PIN_FLAGS: &str = "--pinentry <path>, --pin-file <path>, --pin-stdin";
    /// The environment variable of last resort for the signing backend's token.
    const CA_PIN_ENV: &str = "TESSERA_ISSUER_PIN";
    /// The environment variable of last resort for a carrier token.
    const CARRIER_PIN_ENV: &str = "TESSERA_CARRIER_PIN";

    /// A [`PinSource`] backed by the ladder in [`super::secret`].
    pub(super) struct CliPinSource {
        /// The source the operator named, if any.
        explicit: Option<FlagSource>,
        /// The prompt caption: which device the PIN is for.
        caption: Msg,
        /// The token the PIN is going to, when one was named.
        subject: Option<String>,
        /// The environment variable of last resort.
        env_var: &'static str,
        /// The operator-message locale.
        locale: Locale,
    }

    impl CliPinSource {
        /// A PIN source for the signing backend's token.
        pub(super) fn new(explicit: Option<FlagSource>, locale: Locale) -> Self {
            Self {
                explicit,
                caption: Msg::SecretPromptTokenPin,
                subject: None,
                env_var: CA_PIN_ENV,
                locale,
            }
        }

        /// A PIN source for the token a credential is being written to.
        ///
        /// `token_label` is the label the operator selected the carrier by, and
        /// it goes into the prompt: with the CA token plugged in beside the
        /// carrier, "token PIN" alone does not say which one is being asked
        /// about.
        pub(super) fn for_carrier(
            explicit: Option<FlagSource>,
            token_label: Option<&str>,
            locale: Locale,
        ) -> Self {
            Self {
                explicit,
                caption: Msg::SecretPromptCarrierPin,
                subject: token_label.map(str::to_owned),
                env_var: CARRIER_PIN_ENV,
                locale,
            }
        }
    }

    impl PinSource for CliPinSource {
        fn pin(&self) -> Result<SecretString, Pkcs11SignError> {
            secret::resolve(&Request {
                explicit: self.explicit.as_ref(),
                caption: self.caption,
                subject: self.subject.as_deref(),
                env_var: self.env_var,
                flags: PIN_FLAGS,
                locale: self.locale,
            })
            .map_err(|e| Pkcs11SignError::PinUnavailable(e.to_string()))
        }
    }
}

/// The container password: generated by default, taken from the shared secret
/// ladder when the operator names a source.
///
/// The default is *generation*, not a prompt, and that asymmetry with the
/// backend secrets is deliberate. A backend secret already exists and the tool
/// can only ask for it; a container password is being created here, and one a
/// person invents under the pressure of routine is the weakest part of an
/// artifact that carries an extractable private key. So the tool makes it up
/// unless told otherwise — and when told, it still refuses one that is too
/// short.
///
/// No flag takes the password by value: `argv` is readable by every process on
/// the machine.
mod p12pass {
    use zeroize::Zeroizing;

    use crate::l10n::{Locale, Msg};
    use crate::pkcs12;

    use super::secret::{self, FlagSource, Request};
    use super::{CliError, IssueLeafArgs};

    /// The flags that name a password source, for the message shown when none
    /// did.
    const P12_FLAGS: &str =
        "--p12-passphrase-file <path>, --p12-passphrase-stdin, --p12-passphrase-prompt";
    /// The environment variable of last resort, reachable only through
    /// `--p12-passphrase-prompt` (the ladder's non-flag rungs).
    const P12_ENV: &str = "TESSERA_ISSUER_P12_PASSPHRASE";

    /// A container password, and whether the tool made it up.
    pub(super) struct ContainerPassphrase {
        /// The password itself, wiped when dropped.
        value: Zeroizing<String>,
        /// Whether the tool generated it, and so owes the operator a one-time
        /// display.
        generated: bool,
    }

    impl ContainerPassphrase {
        /// The password, for the length of the packaging call.
        pub(super) fn expose(&self) -> &str {
            &self.value
        }

        /// The password to show once, or `None` when the operator supplied it
        /// and already has it.
        pub(super) fn shown_once(&self) -> Option<&str> {
            self.generated.then(|| self.value.as_str())
        }
    }

    /// Resolves the container password for one `issue-leaf --generate-key` run.
    ///
    /// # Errors
    ///
    /// [`CliError::Usage`] when a named source fails or yields nothing, and
    /// [`CliError::Issue`] when an operator-supplied password is below the
    /// length floor.
    pub(super) fn resolve(
        args: &IssueLeafArgs,
        locale: Locale,
    ) -> Result<ContainerPassphrase, CliError> {
        let explicit = if args.p12_passphrase_stdin {
            Some(FlagSource::Stdin)
        } else {
            args.p12_passphrase_file.clone().map(FlagSource::File)
        };

        if explicit.is_none() && !args.p12_passphrase_prompt {
            // Asked before anything is issued: a password that cannot be shown
            // is a container nobody can open, and finding that out after the
            // certificate is signed and journaled leaves an artifact whose only
            // possible fate is to be thrown away.
            super::require_terminal_for_generated_passphrase(locale)?;
            return Ok(ContainerPassphrase {
                value: pkcs12::generate_passphrase(&mut crate::keygen::OsEntropy),
                generated: true,
            });
        }

        let secret = secret::resolve(&Request {
            explicit: explicit.as_ref(),
            caption: Msg::SecretPromptContainerPassphrase,
            subject: None,
            env_var: P12_ENV,
            flags: P12_FLAGS,
            locale,
        })
        .map_err(|e| CliError::Usage(e.to_string()))?;
        let value = {
            use secrecy::ExposeSecret as _;
            Zeroizing::new(secret.expose_secret().to_owned())
        };
        pkcs12::check_passphrase(&value)?;
        Ok(ContainerPassphrase {
            value,
            generated: false,
        })
    }
}

/// The passphrase provider for the CLI's file backend: the shared secret ladder,
/// captioned as the CA key passphrase.
#[cfg(feature = "file")]
mod keypass {
    use secrecy::SecretString;

    use crate::file::{FileSignError, PassphraseSource};
    use crate::l10n::{Locale, Msg};

    use super::secret::{self, FlagSource, Request};

    /// The flags that name a passphrase source, for the message shown when none
    /// did.
    const KEY_FLAGS: &str =
        "--pinentry <path>, --key-passphrase-file <path>, --key-passphrase-stdin";
    /// The environment variable of last resort.
    const KEY_ENV: &str = "TESSERA_ISSUER_KEY_PASSPHRASE";

    /// A [`PassphraseSource`] backed by the ladder in [`super::secret`].
    pub(super) struct FilePassphraseSource {
        /// The source the operator named, if any.
        explicit: Option<FlagSource>,
        /// The operator-message locale.
        locale: Locale,
    }

    impl FilePassphraseSource {
        /// A passphrase source over the source `explicit` names, else the full
        /// ladder.
        pub(super) fn new(explicit: Option<FlagSource>, locale: Locale) -> Self {
            Self { explicit, locale }
        }
    }

    impl PassphraseSource for FilePassphraseSource {
        fn passphrase(&self) -> Result<SecretString, FileSignError> {
            secret::resolve(&Request {
                explicit: self.explicit.as_ref(),
                caption: Msg::SecretPromptKeyPassphrase,
                subject: None,
                env_var: KEY_ENV,
                flags: KEY_FLAGS,
                locale: self.locale,
            })
            .map_err(|e| FileSignError::PassphraseUnavailable(e.to_string()))
        }
    }
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

    /// Issuance and verification must agree on which certificate format is the
    /// current one: an Engine left at its compiled-in ceiling accepts only the
    /// baseline format, so a certificate minted without an explicit
    /// `--profile-version` has to carry exactly that baseline. Any drift here
    /// is invisible at issuance time and only surfaces as a rejected
    /// authentication on the device.
    #[test]
    fn omitted_profile_version_defaults_to_the_baseline_format() {
        /// The format version the Engine accepts with no `[trust]` override.
        const BASELINE: u32 = 0;

        let root = Cli::parse_from([
            "issuer",
            "issue-root",
            "--spki",
            "spki.pem",
            "--subject",
            "CN=Tessera Root",
            "--not-before",
            "1600000000",
            "--not-after",
            "1900000000",
            "--allow-role",
            "oper",
            "--journal",
            "journal.ndjson",
            "--out",
            "root.pem",
        ]);
        let Command::IssueRoot(root) = root.command else {
            panic!("expected issue-root");
        };
        assert_eq!(root.profile_version, BASELINE);

        let ca = Cli::parse_from([
            "issuer",
            "issue-ca",
            "--parent",
            "root.pem",
            "--spki",
            "spki.pem",
            "--subject",
            "CN=Org CA",
            "--not-before",
            "1600000000",
            "--not-after",
            "1900000000",
            "--allow-role",
            "oper",
            "--journal",
            "journal.ndjson",
            "--out",
            "ca.pem",
        ]);
        let Command::IssueCa(ca) = ca.command else {
            panic!("expected issue-ca");
        };
        assert_eq!(ca.profile_version, BASELINE);

        let leaf = Cli::parse_from([
            "issuer",
            "issue-leaf",
            "--parent",
            "ca.pem",
            "--spki",
            "spki.pem",
            "--subject",
            "CN=ivanov",
            "--not-before",
            "1600000000",
            "--not-after",
            "1600003600",
            "--journal",
            "journal.ndjson",
            "--out",
            "leaf.pem",
        ]);
        let Command::IssueLeaf(leaf) = leaf.command else {
            panic!("expected issue-leaf");
        };
        assert_eq!(leaf.profile_version, BASELINE);
    }

    /// The `issue-root` argv without envelope flags, ready to be extended.
    fn root_argv() -> Vec<&'static str> {
        vec![
            "issuer",
            "issue-root",
            "--spki",
            "spki.pem",
            "--subject",
            "CN=Tessera Root",
            "--not-before",
            "1600000000",
            "--not-after",
            "1900000000",
            "--journal",
            "journal.ndjson",
            "--out",
            "root.pem",
        ]
    }

    /// The `issue-ca` argv without envelope flags, ready to be extended.
    fn ca_argv() -> Vec<&'static str> {
        vec![
            "issuer",
            "issue-ca",
            "--parent",
            "root.pem",
            "--spki",
            "spki.pem",
            "--subject",
            "CN=Org CA",
            "--not-before",
            "1600000000",
            "--not-after",
            "1900000000",
            "--journal",
            "journal.ndjson",
            "--out",
            "ca.pem",
        ]
    }

    /// The envelope's role list is a closed whitelist: an empty one allows no
    /// role, so a CA issued that way passes issuance and then fails every
    /// login. Refusing at argument parsing keeps the operator from learning
    /// this on the device, where the diagnosis points at the trust chain rather
    /// than at the issuing command.
    #[test]
    fn issuing_a_ca_without_an_allowed_role_is_refused() {
        assert!(
            Cli::try_parse_from(root_argv()).is_err(),
            "issue-root must not mint a root whose envelope allows no role"
        );
        assert!(
            Cli::try_parse_from(ca_argv()).is_err(),
            "issue-ca must not mint a CA whose envelope allows no role"
        );
    }

    /// The TTL ceiling bounds the *child* link, so a zero ceiling demands a
    /// zero-lifetime child — no issuable certificate satisfies it.
    #[test]
    fn an_explicitly_zero_ttl_ceiling_is_refused() {
        let mut root = root_argv();
        root.extend(["--allow-role", "oper", "--max-ttl", "0"]);
        assert!(
            Cli::try_parse_from(root).is_err(),
            "issue-root must not accept a zero TTL ceiling"
        );

        let mut ca = ca_argv();
        ca.extend(["--allow-role", "oper", "--max-ttl", "0"]);
        assert!(
            Cli::try_parse_from(ca).is_err(),
            "issue-ca must not accept a zero TTL ceiling"
        );
    }

    /// The two defaults differ because the dimension bounds different things:
    /// under a root it caps the organisation CA, under an organisation CA it
    /// caps the shift leaf. A single shared value would be wrong for one of
    /// them, and any zero would be wrong for both.
    #[test]
    fn omitted_ttl_ceilings_default_to_what_each_envelope_bounds() {
        let mut root_args = root_argv();
        root_args.extend(["--allow-role", "oper"]);
        let Command::IssueRoot(root) = Cli::parse_from(root_args).command else {
            panic!("expected issue-root");
        };
        assert_eq!(root.max_ttl, ROOT_MAX_TTL_SECS);
        assert_eq!(root.allow_roles, vec!["oper".to_owned()]);

        let mut ca_args = ca_argv();
        ca_args.extend(["--allow-role", "oper"]);
        let Command::IssueCa(ca) = Cli::parse_from(ca_args).command else {
            panic!("expected issue-ca");
        };
        assert_eq!(ca.max_ttl, ORG_CA_MAX_TTL_SECS);
        assert_eq!(ca.allow_roles, vec!["oper".to_owned()]);

        assert_ne!(
            root.max_ttl, ca.max_ttl,
            "the two ceilings bound different links and cannot share a value"
        );
    }

    /// An `issue-root` argv that parses, ready to be extended with the secret
    /// flags under test.
    fn root_argv_with_role() -> Vec<&'static str> {
        let mut argv = root_argv();
        argv.extend(["--allow-role", "oper"]);
        argv
    }

    /// Two named secret sources are a contradiction, not a precedence question:
    /// a run that names both has no single answer to "where does the PIN come
    /// from", so it is refused before anything is opened.
    #[test]
    fn two_named_secret_sources_are_refused_at_parsing() {
        for extra in [
            vec!["--pinentry", "/usr/bin/pinentry", "--pin-file", "pin.txt"],
            vec!["--pinentry", "/usr/bin/pinentry", "--pin-stdin"],
            vec![
                "--pinentry",
                "/usr/bin/pinentry",
                "--key-passphrase-file",
                "pass.txt",
            ],
            vec!["--pin-file", "pin.txt", "--pin-stdin"],
            vec![
                "--key-passphrase-file",
                "pass.txt",
                "--key-passphrase-stdin",
            ],
            // Both streams would consume the same standard input.
            vec!["--pin-stdin", "--key-passphrase-stdin"],
        ] {
            let mut argv = root_argv_with_role();
            argv.extend(extra.iter().copied());
            let err = Cli::try_parse_from(&argv)
                .err()
                .unwrap_or_else(|| panic!("{extra:?} must not parse"));
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{extra:?} must be refused as a conflict"
            );
        }
    }

    /// Each secret flag on its own parses, so the conflict above is about the
    /// combination and not about a flag being rejected outright.
    #[test]
    fn a_single_named_secret_source_parses() {
        for extra in [
            vec!["--pinentry", "/usr/bin/pinentry"],
            vec!["--pin-file", "pin.txt"],
            vec!["--pin-stdin"],
            vec!["--key-passphrase-file", "pass.txt"],
            vec!["--key-passphrase-stdin"],
        ] {
            let mut argv = root_argv_with_role();
            argv.extend(extra.iter().copied());
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "{extra:?} must parse on its own"
            );
        }
    }

    /// No flag accepts a secret by value. The sources that take an argument take
    /// a *path*, the stream sources take none, and there is no `--pin` at all —
    /// so a PIN or passphrase can never appear in the process's `argv`, which
    /// every other user of the host can read.
    #[test]
    fn no_flag_accepts_a_secret_by_value() {
        use clap::CommandFactory as _;

        /// The secret-related flags that take an argument; every one of them
        /// takes a filesystem path.
        const PATH_VALUED: &[&str] = &["pinentry", "pin_file", "key_passphrase_file"];
        /// The secret-related flags that take no argument at all.
        const VALUELESS: &[&str] = &["pin_stdin", "key_passphrase_stdin"];

        let command = Cli::command();
        let subcommand = command
            .get_subcommands()
            .find(|s| s.get_name() == "issue-root")
            .expect("issue-root");
        let mut seen: Vec<String> = Vec::new();
        for arg in subcommand.get_arguments() {
            let id = arg.get_id().as_str();
            if !(id.contains("pin") || id.contains("passphrase")) {
                continue;
            }
            seen.push(id.to_owned());
            let takes_value = matches!(
                arg.get_action(),
                clap::ArgAction::Set | clap::ArgAction::Append
            );
            assert_eq!(
                takes_value,
                PATH_VALUED.contains(&id),
                "{id} takes a value it should not, or lost the one it needs"
            );
        }
        seen.sort();
        let mut expected: Vec<String> = PATH_VALUED
            .iter()
            .chain(VALUELESS)
            .map(|s| (*s).to_owned())
            .collect();
        expected.sort();
        assert_eq!(
            seen, expected,
            "a secret-related flag appeared that this test has not vetted"
        );

        // And the flag that would take a secret directly does not exist.
        for named in [
            vec!["--pin", "1234"],
            vec!["--key-passphrase", "hunter2"],
            vec!["--passphrase", "hunter2"],
        ] {
            let mut argv = root_argv_with_role();
            argv.extend(named.iter().copied());
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{named:?} must not be a flag"
            );
        }
    }

    /// The parsed flags map onto the ladder's named source, one flag each.
    #[cfg(all(feature = "pkcs11", feature = "file"))]
    #[test]
    fn named_flags_map_onto_the_ladder_source() {
        let backend_of = |extra: Vec<&str>| {
            let mut argv = root_argv_with_role();
            argv.extend(extra);
            let Command::IssueRoot(root) = Cli::parse_from(argv).command else {
                panic!("expected issue-root");
            };
            root.backend
        };

        assert_eq!(backend_of(vec![]).pin_source(), None);
        assert_eq!(
            backend_of(vec!["--pin-file", "pin.txt"]).pin_source(),
            Some(secret::FlagSource::File(PathBuf::from("pin.txt")))
        );
        assert_eq!(
            backend_of(vec!["--pin-stdin"]).pin_source(),
            Some(secret::FlagSource::Stdin)
        );
        assert_eq!(
            backend_of(vec!["--pinentry", "/opt/corp/pinentry"]).pin_source(),
            Some(secret::FlagSource::Pinentry(PathBuf::from(
                "/opt/corp/pinentry"
            )))
        );
        // The same dialog flag serves the file backend's passphrase.
        assert_eq!(
            backend_of(vec!["--pinentry", "/opt/corp/pinentry"]).key_passphrase_source(),
            Some(secret::FlagSource::Pinentry(PathBuf::from(
                "/opt/corp/pinentry"
            )))
        );
        assert_eq!(
            backend_of(vec!["--key-passphrase-file", "pass.txt"]).key_passphrase_source(),
            Some(secret::FlagSource::File(PathBuf::from("pass.txt")))
        );
        assert_eq!(
            backend_of(vec!["--key-passphrase-stdin"]).key_passphrase_source(),
            Some(secret::FlagSource::Stdin)
        );
    }

    /// A secret-source flag naming another backend's source is refused, so the
    /// operation never runs from a source the operator did not name.
    #[test]
    fn a_secret_flag_of_another_backend_is_refused() {
        let backend_of = |extra: Vec<&str>| {
            let mut argv = root_argv_with_role();
            argv.extend(extra);
            let Command::IssueRoot(root) = Cli::parse_from(argv).command else {
                panic!("expected issue-root");
            };
            root.backend
        };
        let refusal = |extra: Vec<&str>| {
            let args = backend_of(extra);
            super::reject_foreign_secret_flags(&args, Locale::En)
        };

        // Each backend accepts only its own source flags.
        assert!(refusal(vec!["--backend", "pkcs11", "--pin-stdin"]).is_ok());
        assert!(refusal(vec!["--backend", "pkcs11", "--pin-file", "pin.txt"]).is_ok());
        assert!(refusal(vec!["--backend", "pkcs11", "--pinentry", "/bin/pe"]).is_ok());
        assert!(refusal(vec!["--backend", "file", "--key-passphrase-stdin"]).is_ok());
        assert!(refusal(vec!["--backend", "file", "--pinentry", "/bin/pe"]).is_ok());
        assert!(refusal(vec![]).is_ok());

        for (extra, flag) in [
            (
                vec!["--backend", "file", "--pin-file", "pin.txt"],
                "--pin-file",
            ),
            (vec!["--backend", "file", "--pin-stdin"], "--pin-stdin"),
            (
                vec!["--backend", "pkcs11", "--key-passphrase-file", "pass.txt"],
                "--key-passphrase-file",
            ),
            (
                vec!["--backend", "pkcs11", "--key-passphrase-stdin"],
                "--key-passphrase-stdin",
            ),
            (vec!["--backend", "vault", "--pin-stdin"], "--pin-stdin"),
            (
                vec!["--backend", "vault", "--pinentry", "/bin/pe"],
                "--pinentry",
            ),
        ] {
            let err = refusal(extra.clone()).unwrap_err();
            assert!(matches!(err, CliError::Usage(_)), "{extra:?}: {err:?}");
            let message = err.render(Locale::En);
            assert!(message.contains(flag), "{message:?} must name {flag}");
        }

        // A pair of flags that clap lets through, one from each backend's set,
        // is unreachable once the backend is known: whichever backend is
        // selected, one of the two belongs to the other one.
        for backend in ["pkcs11", "file", "vault"] {
            assert!(
                refusal(vec![
                    "--backend",
                    backend,
                    "--pin-file",
                    "pin.txt",
                    "--key-passphrase-stdin",
                ])
                .is_err(),
                "a cross-backend pair must not survive --backend {backend}"
            );
        }

        // And the refusal is localized.
        let ru = super::reject_foreign_secret_flags(
            &backend_of(vec!["--backend", "file", "--pin-stdin"]),
            Locale::Ru,
        )
        .unwrap_err()
        .render(Locale::Ru);
        assert!(ru.contains("другого бэкенда"), "{ru:?}");
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

/// The `--generate-key` surface: the flags, the container it produces, and what
/// it must never leave behind.
#[cfg(test)]
mod generate_key_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::sign::MockSigner;
    use crate::test_support::{self_signed_ca, spki_fixture, MemoryStorage};
    use crate::{CaRequest, Journal};
    use tessera_ext::delegation::DelegationConstraints;

    const TS: u64 = 1_600_000_000;

    fn key() -> KeyId {
        KeyId::new("ca-key")
    }

    /// An org CA the generated leaf can be issued under.
    fn parent(signer: &MockSigner) -> Vec<u8> {
        parent_named(signer, "Org CA")
    }

    /// As [`parent`], with a common name of the caller's choosing — a second CA
    /// needs its own subject, since that is what the chain check compares.
    pub(super) fn parent_named(signer: &MockSigner, common_name: &str) -> Vec<u8> {
        let req = CaRequest {
            subject: format!("CN={common_name}"),
            subject_spki_der: spki_fixture(),
            validity: Validity {
                not_before: TS,
                not_after: TS + 9_000_000,
            },
            constraints: DelegationConstraints {
                require_tags: vec![],
                allow_roles: vec!["oper".to_owned()],
                max_level: 5,
                max_ttl: 86_400,
            },
            profile_version: 0,
        };
        let mut journal = Journal::load(MemoryStorage::new()).unwrap();
        self_signed_ca(signer, &key(), &req, &Serial::generate(), &mut journal, TS)
            .unwrap()
            .der
    }

    /// The argv of a `--generate-key` issuance into `dir`.
    fn argv(dir: &Path, extra: &[&str]) -> Vec<String> {
        let mut out: Vec<String> = [
            "issuer",
            "issue-leaf",
            "--backend",
            "mock",
            "--key",
            "ca-key",
            "--parent",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        out.push(dir.join("parent.der").display().to_string());
        for arg in [
            "--generate-key",
            "--subject",
            "CN=ivanov",
            "--host",
            "*",
            "--role",
            "oper",
            "--not-before",
            "1600000000",
            "--not-after",
            "1600003600",
        ] {
            out.push(arg.to_owned());
        }
        out.push("--journal".to_owned());
        out.push(dir.join("journal.ndjson").display().to_string());
        out.push("--out-p12".to_owned());
        out.push(dir.join("ivanov.p12").display().to_string());
        out.extend(extra.iter().map(|s| (*s).to_owned()));
        out
    }

    /// Lay down the parent certificate and run the parsed command.
    ///
    /// A password source is supplied by default: a test process has no terminal
    /// to show a generated password on, and the tool refuses to print one into
    /// output that is being captured.
    fn run_in(dir: &Path, extra: &[&str]) -> Result<(), CliError> {
        let secret = dir.join("p12-password.txt");
        write_owner_only(&secret, "delivered-out-of-band\n");
        let mut with_source: Vec<&str> = extra.to_vec();
        let path = secret.display().to_string();
        with_source.extend(["--p12-passphrase-file", &path]);
        run_in_raw(dir, &with_source)
    }

    /// As [`run_in`], naming no password source — the tool then generates one.
    fn run_in_raw(dir: &Path, extra: &[&str]) -> Result<(), CliError> {
        let signer = MockSigner::ecdsa_sha256(key());
        std::fs::write(dir.join("parent.der"), parent(&signer)).unwrap();
        run(Cli::parse_from(argv(dir, extra)).command, Locale::En)
    }

    /// Write a secret file the owner-only gate accepts.
    fn write_owner_only(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn writes_a_container_and_leaves_no_key_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        run_in(dir.path(), &[]).expect("the issuance succeeds");

        let container = std::fs::read(dir.path().join("ivanov.p12")).unwrap();
        let certs = crate::pkcs12::certificates_without_passphrase(&container)
            .expect("the container's certificates are readable without the password");
        assert!(!certs.is_empty());

        // Nothing but the artifacts the operator asked for: in particular no
        // key file, no temporary, and no password beside the container.
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "ivanov.p12".to_owned(),
                "journal.ndjson".to_owned(),
                // The password source the test supplied, not something the run
                // produced.
                "p12-password.txt".to_owned(),
                "parent.der".to_owned(),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_container_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        run_in(dir.path(), &[]).expect("the issuance succeeds");
        let mode = std::fs::metadata(dir.path().join("ivanov.p12"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "a file carrying a private key must not be readable beyond its owner"
        );
    }

    #[test]
    fn refuses_a_generated_password_it_cannot_show_to_a_person() {
        // A test process has no terminal on standard error. Printing the
        // password anyway would put it in whatever captured the run, after
        // which it would have to be treated as compromised.
        let dir = tempfile::tempdir().unwrap();
        let err = run_in_raw(dir.path(), &[]).expect_err("there is nobody to show the password to");
        let CliError::Usage(message) = err else {
            panic!("expected a usage refusal, got {err:?}");
        };
        assert!(
            message.contains("--p12-passphrase-file"),
            "the refusal must name the sources that would work: {message}"
        );
        // And it happens before any work: a container written but unopenable,
        // or a journal line for a credential nobody received, would both be
        // worse than the refusal.
        assert!(!dir.path().join("ivanov.p12").exists());
        assert!(!dir.path().join("journal.ndjson").exists());
    }

    #[test]
    fn refuses_a_chain_file_that_is_not_a_certificate() {
        // The slip: `--chain ca.pk8.pem` where `--key-file ca.pk8.pem` was
        // meant. The certificate safe is unencrypted, so the CA key would ride
        // out in the clear.
        let dir = tempfile::tempdir().unwrap();
        let key_pem = crate::keygen::generate_key_pair(
            crate::keygen::LeafKeyType::EcdsaP256,
            &mut crate::keygen::OsEntropy,
        )
        .unwrap();
        let chain = dir.path().join("ca.pk8.pem");
        std::fs::write(
            &chain,
            encode_pem("PRIVATE KEY", &key_pem.private_key_pkcs8_der),
        )
        .unwrap();

        let err = run_in(dir.path(), &["--chain", &chain.display().to_string()])
            .expect_err("a private key must never be packaged as a chain");
        let CliError::Usage(message) = err else {
            panic!("expected a usage refusal, got {err:?}");
        };
        assert!(
            message.contains("chain element 0 is not an X.509 certificate"),
            "the message must name the element that was checked: {message}"
        );
        assert!(
            !message.contains("leaf"),
            "a chain element must not be reported as the leaf: {message}"
        );
        assert!(
            !message.contains("pkcs12 container"),
            "the container module must not leak into a chain diagnostic: {message}"
        );
        assert!(
            message.contains("expected tag"),
            "the underlying cause is worth keeping: {message}"
        );
        assert!(
            !dir.path().join("ivanov.p12").exists(),
            "nothing may be written when the chain is refused"
        );
    }

    #[test]
    fn refuses_a_chain_from_a_different_issuer() {
        let dir = tempfile::tempdir().unwrap();
        // A well-formed CA that did not issue this leaf.
        let signer = MockSigner::ecdsa_sha256(key());
        let foreign = dir.path().join("foreign-chain.pem");
        std::fs::write(
            &foreign,
            encode_pem("CERTIFICATE", &parent_named(&signer, "Some Other CA")),
        )
        .unwrap();

        // The mismatch is caught by the core when the container is assembled,
        // so it surfaces as the issuance refusal, not as a usage error.
        let err = run_in(dir.path(), &["--chain", &foreign.display().to_string()])
            .expect_err("a chain that did not issue the leaf must be refused");
        let CliError::Issue(IssueError::Container(message)) = err else {
            panic!("expected a container refusal, got {err:?}");
        };
        assert!(
            message.contains("does not lead to the leaf"),
            "got {message}"
        );
        assert!(
            !dir.path().join("ivanov.p12").exists(),
            "nothing may be written when the chain is refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacing_a_wider_container_file_does_not_inherit_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ivanov.p12");
        std::fs::write(&target, b"stale").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();

        run_in(dir.path(), &[]).expect("the issuance succeeds");

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a file carrying a private key must not keep a mode it had before"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_container_path_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere.txt");
        std::fs::write(&elsewhere, b"untouched").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join("ivanov.p12")).unwrap();

        run_in(dir.path(), &[]).expect("the issuance succeeds");

        assert_eq!(
            std::fs::read(&elsewhere).unwrap(),
            b"untouched",
            "the private key must not travel down a planted symlink"
        );
        assert!(!dir.path().join("ivanov.p12").is_symlink());
    }

    #[test]
    fn refuses_a_key_type_the_device_cannot_verify() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_in(dir.path(), &["--key-type", "gost-2012-256"])
            .expect_err("an unverifiable key type must be refused");
        let CliError::Issue(IssueError::UnsupportedKeyType { supported, .. }) = err else {
            panic!("expected UnsupportedKeyType, got {err:?}");
        };
        assert!(supported.contains("ecdsa-p384"), "got {supported}");
        assert!(
            !dir.path().join("ivanov.p12").exists(),
            "a refused request must not leave an artifact"
        );
        assert!(
            !dir.path().join("journal.ndjson").exists(),
            "a request refused before generation must not reach the journal"
        );
    }

    #[test]
    fn refuses_a_short_operator_password() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret.txt");
        write_owner_only(&secret, "short\n");

        let err = run_in_raw(
            dir.path(),
            &["--p12-passphrase-file", &secret.display().to_string()],
        )
        .expect_err("a short password must be refused");
        assert!(
            matches!(err, CliError::Issue(IssueError::PassphraseTooShort { .. })),
            "got {err:?}"
        );
    }

    #[test]
    fn no_flag_takes_the_password_by_value() {
        // `argv` is world-readable, so a flag that accepted the password
        // directly would publish it to every process on the machine.
        for flag in [
            "--p12-passphrase",
            "--p12-password",
            "--passphrase",
            "--password",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut with_value = argv(dir.path(), &[]);
            with_value.push(flag.to_owned());
            with_value.push("hunter2hunter2".to_owned());
            assert!(
                Cli::try_parse_from(&with_value).is_err(),
                "{flag} must not exist"
            );
        }
    }

    #[test]
    fn generation_is_mutually_exclusive_with_the_other_key_sources() {
        let dir = tempfile::tempdir().unwrap();
        for conflicting in [["--spki", "spki.pem"], ["--csr", "req.pem"]] {
            let mut argv = argv(dir.path(), &[]);
            argv.extend(conflicting.iter().map(|s| (*s).to_owned()));
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "--generate-key must conflict with {}",
                conflicting[0]
            );
        }
    }

    #[test]
    fn the_generation_flags_are_refused_without_the_generation_flag() {
        // Silently ignoring them would issue a plain certificate and no
        // container, which is only discovered when the engineer has nothing to
        // log in with.
        let base = [
            "issuer",
            "issue-leaf",
            "--backend",
            "mock",
            "--key",
            "ca-key",
            "--parent",
            "ca.pem",
            "--spki",
            "spki.pem",
            "--subject",
            "CN=ivanov",
            "--not-before",
            "1600000000",
            "--not-after",
            "1600003600",
            "--journal",
            "journal.ndjson",
            "--out",
            "leaf.pem",
        ];
        for stray in [
            vec!["--p12-passphrase-stdin"],
            vec!["--p12-passphrase-prompt"],
            vec!["--out-p12", "ivanov.p12"],
            vec!["--key-type", "ecdsa-p384"],
            vec!["--chain", "chain.pem"],
        ] {
            let mut argv: Vec<&str> = base.to_vec();
            argv.extend(&stray);
            let err = run(Cli::parse_from(&argv).command, Locale::En)
                .expect_err("a stray generation flag must be refused");
            let CliError::Usage(message) = err else {
                panic!("expected a usage refusal for {stray:?}, got {err:?}");
            };
            let flag = stray.first().copied().unwrap_or_default();
            assert!(message.contains(flag), "got {message}");
        }
    }
}

/// `prepare-carrier`: where the artifacts land and what it refuses to do.
#[cfg(test)]
mod prepare_carrier_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// Parse and run a `prepare-carrier` argv.
    fn run_argv(flags: &[String]) -> Result<(), CliError> {
        let mut argv = vec!["issuer".to_owned(), "prepare-carrier".to_owned()];
        argv.extend_from_slice(flags);
        run(Cli::parse_from(argv).command, Locale::En)
    }

    fn arg(flag: &str, value: &Path) -> Vec<String> {
        vec![flag.to_owned(), value.display().to_string()]
    }

    /// A CA certificate in PEM, for the chain files these tests hand around.
    fn ca_pem() -> String {
        use crate::sign::MockSigner;
        let signer = MockSigner::ecdsa_sha256(KeyId::new("ca-key"));
        encode_pem(
            "CERTIFICATE",
            &super::generate_key_tests::parent_named(&signer, "Carrier Test CA"),
        )
    }

    #[test]
    fn lays_artifacts_where_the_device_looks() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        let chain = dir.path().join("chain.pem");
        let media = dir.path().join("media");
        // Minted once: every call produces a fresh serial, so the file and the
        // expectation have to come from the same certificate.
        let pem = ca_pem();
        std::fs::write(&p12, b"container").unwrap();
        std::fs::write(&chain, &pem).unwrap();

        let mut argv = arg("--p12", &p12);
        argv.extend(arg("--chain", &chain));
        argv.extend(arg("--media", &media));
        run_argv(&argv).expect("the layout succeeds");

        assert_eq!(
            std::fs::read(media.join("certs/user.p12")).unwrap(),
            b"container"
        );
        assert_eq!(
            std::fs::read_to_string(media.join("certs/chain.pem")).unwrap(),
            pem
        );
    }

    #[test]
    fn refuses_to_replace_a_container_without_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        let media = dir.path().join("media");
        std::fs::write(&p12, b"mine").unwrap();
        std::fs::create_dir_all(media.join("certs")).unwrap();
        std::fs::write(media.join("certs/user.p12"), b"someone-else").unwrap();

        let mut argv = arg("--p12", &p12);
        argv.extend(arg("--media", &media));
        // The test process has no terminal, so the question cannot be asked and
        // the operation must stop rather than guess.
        let err = run_argv(&argv).expect_err("an unconfirmed overwrite must be refused");
        assert!(matches!(err, CliError::Usage(_)), "got {err:?}");
        assert_eq!(
            std::fs::read(media.join("certs/user.p12")).unwrap(),
            b"someone-else"
        );

        argv.push("--force".to_owned());
        run_argv(&argv).expect("--force is the confirmation");
        assert_eq!(
            std::fs::read(media.join("certs/user.p12")).unwrap(),
            b"mine"
        );
    }

    /// A PIN flag on a mounted-carrier run is refused, not dropped. The command
    /// refuses every other incompatible combination out loud, and an operator
    /// who passed `--pin-file` and saw a success would have every reason to
    /// think a PIN was protecting what landed in a plain directory. Holds in a
    /// build without the token backend too: the flags are declared there as
    /// well, and mean even less.
    #[test]
    fn a_mounted_carrier_refuses_the_flags_that_belong_to_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        let pin_file = dir.path().join("pin.txt");
        std::fs::write(&p12, b"container").unwrap();
        std::fs::write(&pin_file, b"12345678\n").unwrap();

        for extra in [
            arg("--pin-file", &pin_file),
            vec!["--pin-stdin".to_owned()],
            vec!["--token-label".to_owned(), "Rutoken Lite".to_owned()],
            arg("--pinentry", Path::new("/usr/bin/pinentry")),
        ] {
            let media = dir.path().join(extra.join("-").replace(['/', '-'], "_"));
            let mut argv = arg("--p12", &p12);
            argv.extend(arg("--media", &media));
            argv.extend(extra.clone());
            match run_argv(&argv) {
                Err(CliError::Usage(message)) => assert!(
                    message.contains(extra.first().map_or("", String::as_str)),
                    "the refusal must name the flag: {message}"
                ),
                other => panic!("{extra:?} must be refused, got {other:?}"),
            }
            assert!(
                !media.exists(),
                "{extra:?}: a refused run must lay nothing out"
            );
        }
    }

    /// A build that cannot reach a token says so instead of writing nothing
    /// and reporting success.
    #[cfg(not(feature = "pkcs11"))]
    #[test]
    fn a_build_without_the_token_backend_refuses_rather_than_pretending() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        std::fs::write(&p12, b"container").unwrap();

        let mut argv = arg("--p12", &p12);
        argv.extend([
            "--module".to_owned(),
            "/usr/lib/librtpkcs11ecp.so".to_owned(),
        ]);
        argv.extend(["--object-label".to_owned(), "tessera-credential".to_owned()]);

        let err = run_argv(&argv).expect_err("this build cannot reach a token");
        let CliError::Usage(message) = err else {
            panic!("expected a usage refusal, got {err:?}");
        };
        assert!(
            message.contains("pkcs11"),
            "the refusal must name what is missing: {message}"
        );
    }

    /// The two carriers are not mixed in one run. Half-serving the request
    /// would leave an operator told the carrier was prepared and no chain
    /// anywhere.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn a_token_run_refuses_the_flags_that_belong_to_a_mounted_carrier() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        let chain = dir.path().join("chain.pem");
        std::fs::write(&p12, b"container").unwrap();
        std::fs::write(&chain, b"chain").unwrap();

        let token = |extra: Vec<String>| {
            let mut argv = arg("--p12", &p12);
            argv.extend([
                "--module".to_owned(),
                "/nonexistent/__tessera_no_module__.so".to_owned(),
            ]);
            argv.extend(["--object-label".to_owned(), "tessera-credential".to_owned()]);
            argv.extend(extra);
            run_argv(&argv)
        };

        for extra in [
            arg("--media", dir.path()),
            arg("--chain", &chain),
            vec!["--container-path".to_owned(), "certs/x.p12".to_owned()],
        ] {
            let err = token(extra.clone()).expect_err("mixed carriers must be refused");
            assert!(matches!(err, CliError::Usage(_)), "{extra:?}: got {err:?}");
        }
    }

    /// Half a token target is a typo, not a request: `--module` without a label
    /// would write where nothing looks for it.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn a_token_run_needs_both_the_module_and_the_object_label() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        std::fs::write(&p12, b"container").unwrap();

        let mut argv = arg("--p12", &p12);
        argv.extend([
            "--module".to_owned(),
            "/nonexistent/__tessera_no_module__.so".to_owned(),
        ]);
        let err = run_argv(&argv).expect_err("--module alone is not a target");
        assert!(matches!(err, CliError::Usage(_)), "got {err:?}");

        let mut argv = arg("--p12", &p12);
        argv.extend(["--object-label".to_owned(), "tessera-credential".to_owned()]);
        let err = run_argv(&argv).expect_err("--object-label alone is not a target");
        assert!(matches!(err, CliError::Usage(_)), "got {err:?}");
    }

    /// The size is judged before the PIN is asked for. The test process has no
    /// PIN source at all, so a check made in the wrong order would fail on the
    /// missing PIN — and on a real token it would not fail at all, it would
    /// truncate.
    #[cfg(feature = "pkcs11")]
    #[test]
    fn an_oversized_container_is_refused_before_the_operator_is_asked_for_a_pin() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        std::fs::write(&p12, vec![0xAB; 48 * 1024]).unwrap();

        let mut argv = arg("--p12", &p12);
        argv.extend([
            "--module".to_owned(),
            "/nonexistent/__tessera_no_module__.so".to_owned(),
        ]);
        argv.extend(["--object-label".to_owned(), "tessera-credential".to_owned()]);

        let err = run_argv(&argv).expect_err("48 KiB must be refused");
        let CliError::Usage(message) = err else {
            panic!("expected a usage refusal, got {err:?}");
        };
        assert!(
            message.contains("49152") && message.contains("32768"),
            "the refusal must name both sizes: {message}"
        );
    }

    #[test]
    fn refuses_a_container_path_that_leaves_the_carrier() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        let media = dir.path().join("media");
        let victim = dir.path().join("keep.txt");
        std::fs::write(&p12, b"container").unwrap();
        std::fs::write(&victim, b"not yours").unwrap();

        for escape in [
            "../escaped.p12".to_owned(),
            victim.display().to_string(),
            "certs/../../escaped.p12".to_owned(),
        ] {
            let mut argv = arg("--p12", &p12);
            argv.extend(arg("--media", &media));
            argv.extend(["--container-path".to_owned(), escape.clone()]);
            argv.push("--force".to_owned());

            let err = run_argv(&argv).expect_err("'{escape}' must be refused");
            assert!(matches!(err, CliError::Usage(_)), "{escape}: got {err:?}");
        }
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"not yours",
            "a refused path must not have written anything"
        );
    }

    #[test]
    fn refuses_a_chain_file_that_is_not_a_chain() {
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        let chain = dir.path().join("not-a-chain.pem");
        let media = dir.path().join("media");
        std::fs::write(&p12, b"container").unwrap();
        std::fs::write(
            &chain,
            "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let mut argv = arg("--p12", &p12);
        argv.extend(arg("--chain", &chain));
        argv.extend(arg("--media", &media));
        let err = run_argv(&argv).expect_err("a chain file must hold certificates");
        let CliError::Usage(message) = err else {
            panic!("expected a usage refusal, got {err:?}");
        };
        // Preparing a carrier assembles no container, so nothing here may speak
        // of one; and the element checked is a chain element, not a leaf.
        assert!(
            message.contains("chain element 0 is not an X.509 certificate"),
            "got {message}"
        );
        assert!(!message.contains("leaf"), "got {message}");
        assert!(!message.contains("pkcs12 container"), "got {message}");
        assert!(
            !media.join("certs/chain.pem").exists(),
            "nothing may reach the carrier when the chain is refused"
        );
    }

    #[test]
    fn takes_no_password_at_all() {
        // Container and password travel by separate channels; a flag here would
        // invite writing the password onto the carrier beside the container.
        let dir = tempfile::tempdir().unwrap();
        let p12 = dir.path().join("ivanov.p12");
        std::fs::write(&p12, b"container").unwrap();
        for flag in ["--p12-passphrase-file", "--passphrase-file", "--password"] {
            let mut argv = arg("--p12", &p12);
            argv.extend(arg("--media", dir.path()));
            argv.extend([flag.to_owned(), "whatever".to_owned()]);
            let mut full = vec!["issuer".to_owned(), "prepare-carrier".to_owned()];
            full.extend(argv);
            assert!(Cli::try_parse_from(&full).is_err(), "{flag} must not exist");
        }
    }
}

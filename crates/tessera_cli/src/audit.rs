//! `tessera audit` subcommand: `verify`, `status` and `attest` over the
//! device's hash-chained journal.
//!
//! `verify` is the operation the whole journal exists for, so its output is
//! written for the moment an auditor runs it and something is wrong: it says
//! which of three states the chain is in, and where the first break is. The exit
//! code carries the same three states, because that is what a script reads:
//!
//! | Exit | Meaning |
//! |---|---|
//! | 0 | intact — either fully attested, or with a tail not yet attested |
//! | 1 | broken — a line was altered, removed or reordered |
//! | 2 | the journal could not be read at all |
//!
//! `audit annotate` is how a writer outside the device — a reconciliation, a
//! review — puts its own data under the same chain. Its exit codes are 0 for a
//! recorded annotation, 3 for a journal that has reached its ceiling and is
//! configured to refuse, and 2 for anything else that stopped it.
//!
//! An unattested tail is *not* a failure. It is the ordinary state of a device
//! between attestations, and an exit code that treated it as a problem would
//! train whoever runs this to ignore exit codes.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use tessera_core::audit::{
    verify_attestations, AttestationStatus, AuditError, AuditJournal, AuditPolicy, KeyFileSigner,
    KeyFileVerifier, WhenFull, AUDIT_FILENAME,
};
use tessera_hashchain::ChainStatus;

/// Default location of the device journal.
const DEFAULT_AUDIT_DIR: &str = "/var/lib/tessera";

/// Default location of the device configuration.
const DEFAULT_CONFIG: &str = "/etc/tessera/config.toml";

/// Exit code for a chain that does not verify.
const EXIT_BROKEN: u8 = 1;

/// Exit code for a journal that could not be read or written at all.
const EXIT_UNREADABLE: u8 = 2;

/// Exit code for a journal that has reached its ceiling and refuses records.
const EXIT_FULL: u8 = 3;

/// CLI arguments for `tessera audit`.
#[derive(Debug, Args)]
pub struct AuditArgs {
    /// The audit operation to run.
    #[command(subcommand)]
    pub cmd: AuditCmd,
}

/// `tessera audit` operations.
#[derive(Debug, Subcommand)]
pub enum AuditCmd {
    /// Recompute the chain from genesis and report the position of the first
    /// break. Exits 1 on a broken chain, 0 on an intact one (attested tail or
    /// not), 2 when the journal cannot be read.
    Verify(AuditVerifyArgs),
    /// Print what the journal holds: how many records, how much of the ceiling
    /// is used, when the head was last attested.
    Status(AuditStatusArgs),
    /// Sign the current chain head with the device's attestation key and record
    /// the signature as its own line.
    Attest(AuditAttestArgs),
    /// Record a writer-defined annotation on the chain. Exits 3 when the
    /// journal has reached its ceiling and is configured to refuse.
    Annotate(AuditAnnotateArgs),
}

/// Arguments shared by every `audit` operation.
#[derive(Debug, Args)]
pub struct AuditPathArgs {
    /// The journal file. Defaults to the production layout.
    #[arg(long)]
    pub file: Option<PathBuf>,
}

impl AuditPathArgs {
    /// The journal path this invocation works on.
    fn path(&self) -> PathBuf {
        self.file
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_AUDIT_DIR).join(AUDIT_FILENAME))
    }
}

/// Arguments for `audit verify`.
#[derive(Debug, Args)]
pub struct AuditVerifyArgs {
    /// Where the journal lives.
    #[command(flatten)]
    pub path: AuditPathArgs,

    /// PEM file with the device's PUBLIC attestation key. Without it the head
    /// signatures are not checked, and the output says so.
    #[arg(long)]
    pub attestation_key: Option<PathBuf>,
}

/// Arguments for `audit status`.
#[derive(Debug, Args)]
pub struct AuditStatusArgs {
    /// Where the journal lives.
    #[command(flatten)]
    pub path: AuditPathArgs,

    /// Device configuration to read `[audit]` from, to report whether this
    /// device keeps a journal at all.
    #[arg(long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,

    /// The ceiling the journal is configured with, in bytes. Only affects what
    /// this command reports.
    #[arg(long)]
    pub ceiling_bytes: Option<u64>,
}

/// Arguments for `audit attest`.
#[derive(Debug, Args)]
pub struct AuditAttestArgs {
    /// Where the journal lives.
    #[command(flatten)]
    pub path: AuditPathArgs,

    /// PEM file holding the device's attestation private key.
    #[arg(long)]
    pub key: PathBuf,
}

/// Arguments for `audit annotate`.
#[derive(Debug, Args)]
pub struct AuditAnnotateArgs {
    /// Where the journal lives.
    #[command(flatten)]
    pub path: AuditPathArgs,

    /// The writer's namespace tag, e.g. `acme.review`. Must not be empty.
    #[arg(long)]
    pub kind: String,

    /// The annotation body, a JSON object.
    #[arg(long)]
    pub data: String,

    /// The ceiling to hold the journal to, in bytes.
    #[arg(long)]
    pub ceiling_bytes: Option<u64>,

    /// What to do once the ceiling is reached.
    #[arg(long, value_enum, default_value_t = FullBehaviour::Refuse)]
    pub when_full: FullBehaviour,
}

/// What the journal does once it is full, as the CLI spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FullBehaviour {
    /// Refuse new records.
    Refuse,
    /// Rotate, leaving a record of the break.
    Rotate,
}

impl From<FullBehaviour> for WhenFull {
    fn from(value: FullBehaviour) -> Self {
        match value {
            FullBehaviour::Refuse => WhenFull::Refuse,
            FullBehaviour::Rotate => WhenFull::Rotate,
        }
    }
}

/// Run `tessera audit`.
#[must_use]
pub fn run(args: AuditArgs) -> ExitCode {
    match args.cmd {
        AuditCmd::Verify(args) => run_verify(&args),
        AuditCmd::Status(args) => run_status(&args),
        AuditCmd::Attest(args) => run_attest(&args),
        AuditCmd::Annotate(args) => run_annotate(&args),
    }
}

/// Opens the journal, or prints why it could not be opened.
fn open(path: PathBuf, ceiling_bytes: Option<u64>) -> Result<AuditJournal, ExitCode> {
    open_with(path, ceiling_bytes, WhenFull::Refuse)
}

/// Opens the journal with an explicit behaviour for a full one.
fn open_with(
    path: PathBuf,
    ceiling_bytes: Option<u64>,
    when_full: WhenFull,
) -> Result<AuditJournal, ExitCode> {
    let mut policy = AuditPolicy::new(path);
    policy.when_full = when_full;
    if let Some(ceiling) = ceiling_bytes {
        policy.ceiling_bytes = ceiling;
    }
    AuditJournal::open(policy).map_err(|error| {
        eprintln!("audit: {error}");
        ExitCode::from(EXIT_UNREADABLE)
    })
}

fn run_verify(args: &AuditVerifyArgs) -> ExitCode {
    let path = args.path.path();
    let journal = match open(path.clone(), None) {
        Ok(journal) => journal,
        Err(code) => return code,
    };
    let report = match journal.verify() {
        Ok(report) => report,
        Err(error) => {
            eprintln!("audit: {error}");
            return ExitCode::from(EXIT_UNREADABLE);
        }
    };
    let lines: Vec<String> = match std::fs::read_to_string(&path) {
        Ok(text) => text.lines().map(str::to_owned).collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            eprintln!("audit: {error}");
            return ExitCode::from(EXIT_UNREADABLE);
        }
    };

    println!("journal: {}", path.display());
    println!("records: {}", report.entry_count);
    match report.status {
        ChainStatus::Intact if report.entry_count == 0 => {
            // An empty chain verifies, and saying "everything is attested"
            // about nothing would read as a stronger statement than it is.
            println!("status: intact");
            println!("attested: the journal is empty");
            report_attestations(&lines, args.attestation_key.as_deref())
        }
        ChainStatus::Intact => {
            println!("status: intact");
            println!("attested: every record is covered by a head signature");
            report_attestations(&lines, args.attestation_key.as_deref())
        }
        ChainStatus::IntactUnsignedTail { unsigned_from_seq } => {
            println!("status: intact");
            println!("attested: records from seq {unsigned_from_seq} are not yet attested");
            report_attestations(&lines, args.attestation_key.as_deref())
        }
        ChainStatus::Broken { position } => {
            println!("status: broken");
            println!("first invalid record: {position}");
            eprintln!(
                "audit: the journal is broken at record {position}: a record was altered, \
                 removed or reordered, and a history that has been edited is not a history"
            );
            ExitCode::from(EXIT_BROKEN)
        }
        // A status this build does not know is not something to summarise
        // optimistically: it is reported as unreadable, and a reader is told
        // which build to bring.
        other => {
            eprintln!("audit: this build cannot interpret the chain status {other:?}");
            ExitCode::from(EXIT_UNREADABLE)
        }
    }
}

fn run_status(args: &AuditStatusArgs) -> ExitCode {
    let path = args.path.path();
    let journal = match open(path.clone(), args.ceiling_bytes) {
        Ok(journal) => journal,
        Err(code) => return code,
    };
    let report = match journal.verify() {
        Ok(report) => report,
        Err(error) => {
            eprintln!("audit: {error}");
            return ExitCode::from(EXIT_UNREADABLE);
        }
    };
    let used = std::fs::metadata(&path).map_or(0, |meta| meta.len());
    let ceiling = journal.policy().ceiling_bytes;

    println!("journal: {}", path.display());
    // Whether this device is CONFIGURED to keep a chain is the first thing an
    // operator needs here, and it is not the same question as whether this file
    // happens to exist. Without a configured chain there is no record of logins
    // and no refusal when a record cannot be written — and everything printed
    // below would describe a file nothing is using.
    println!("configured: {}", configured_state(&args.config));
    println!("records: {}", report.entry_count);
    println!("used_bytes: {used}");
    println!("ceiling_bytes: {ceiling}");
    println!("full: {}", if used >= ceiling { "yes" } else { "no" });
    println!(
        "when_full: {}",
        match journal.policy().when_full {
            WhenFull::Refuse => "refuse",
            WhenFull::Rotate => "rotate",
            _ => "unknown",
        }
    );
    match journal.last_attested_ts() {
        Some(ts) => println!("last_attested_ts: {ts}"),
        None => println!("last_attested_ts: never"),
    }
    ExitCode::SUCCESS
}

fn run_attest(args: &AuditAttestArgs) -> ExitCode {
    let path = args.path.path();
    let mut journal = match open(path.clone(), None) {
        Ok(journal) => journal,
        Err(code) => return code,
    };
    let signer = match KeyFileSigner::load(&args.key) {
        Ok(signer) => signer,
        Err(error) => {
            eprintln!("audit: {error}");
            return ExitCode::from(EXIT_UNREADABLE);
        }
    };
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    match journal.attest(&signer, now) {
        Ok(()) => {
            println!("journal: {}", path.display());
            println!("attested_ts: {now}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("audit: {error}");
            ExitCode::from(EXIT_UNREADABLE)
        }
    }
}

fn run_annotate(args: &AuditAnnotateArgs) -> ExitCode {
    let path = args.path.path();
    let data: serde_json::Value = match serde_json::from_str(&args.data) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("audit: the annotation body is not JSON: {error}");
            return ExitCode::from(EXIT_UNREADABLE);
        }
    };
    let mut journal = match open_with(path.clone(), args.ceiling_bytes, args.when_full.into()) {
        Ok(journal) => journal,
        Err(code) => return code,
    };
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);

    match journal.annotate(&args.kind, data, now) {
        Ok(()) => {
            println!("journal: {}", path.display());
            println!("status: recorded");
            ExitCode::SUCCESS
        }
        Err(error @ AuditError::Full { .. }) => {
            println!("journal: {}", path.display());
            println!("status: full");
            eprintln!("audit: {error}");
            ExitCode::from(EXIT_FULL)
        }
        Err(error) => {
            eprintln!("audit: {error}");
            ExitCode::from(EXIT_UNREADABLE)
        }
    }
}

/// Checks the head signatures, or says plainly that nothing checked them.
///
/// The distinction this prints is the one the whole journal rests on. A hash
/// chain is not keyed: whoever can write the file can write a different history
/// and recompute every link, so "the chain verifies" is a statement a forgery
/// satisfies too. Only a signature over the head, made with a key the forger
/// does not hold, separates the two — and it is only separated if somebody
/// checks it.
///
/// So without `--attestation-key` this reports `attestation: not checked` and
/// exits non-zero-free but unmistakable, rather than letting the earlier
/// "every record is covered by a head signature" line be read as evidence. That
/// line means a signature is *present*; this one says whether it is *real*.
fn report_attestations(lines: &[String], key: Option<&std::path::Path>) -> ExitCode {
    let Some(key) = key else {
        println!("attestation: not checked (no --attestation-key given)");
        return ExitCode::SUCCESS;
    };
    let verifier = match KeyFileVerifier::load(key) {
        Ok(verifier) => verifier,
        Err(error) => {
            eprintln!("audit: {error}");
            return ExitCode::from(EXIT_UNREADABLE);
        }
    };
    match verify_attestations(lines, &verifier).status {
        AttestationStatus::None => {
            println!("attestation: none present");
            ExitCode::SUCCESS
        }
        AttestationStatus::AllVerified { count } => {
            println!("attestation: verified ({count})");
            ExitCode::SUCCESS
        }
        AttestationStatus::Failed {
            position,
            verified_before,
        } => {
            println!("attestation: failed at record {position}");
            eprintln!(
                "audit: the head signature at record {position} was not made by this key \
                 ({verified_before} verified before it): the journal is not the history the \
                 device vouched for"
            );
            ExitCode::from(EXIT_BROKEN)
        }
        AttestationStatus::Malformed { position } => {
            println!("attestation: unreadable at record {position}");
            eprintln!("audit: the head signature at record {position} cannot be read");
            ExitCode::from(EXIT_BROKEN)
        }
        other => {
            eprintln!("audit: this build cannot interpret the attestation status {other:?}");
            ExitCode::from(EXIT_UNREADABLE)
        }
    }
}

/// Whether the device's configuration says it keeps a journal.
///
/// A configuration that cannot be read gives `unknown` rather than `no`: the
/// two are different facts, and reporting the second for the first would tell an
/// operator that the guarantee is off when nothing here knows that.
fn configured_state(config: &std::path::Path) -> &'static str {
    match tessera_core::config::load_validated_config(config) {
        Ok(validated) if validated.audit.policy.is_some() => "yes",
        Ok(_) => "no",
        Err(_) => "unknown (configuration not readable)",
    }
}

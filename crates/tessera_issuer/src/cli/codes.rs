//! The `issuer codes` command surface: the operator side of the phone channel.
//!
//! Four commands, and none of them decides anything. Every check lives in
//! [`crate::codes`], which the browser cabinet calls too; what happens here is
//! reading files, choosing where the operator key is, printing the result and
//! writing the receipt. A refusal an operator meets on this command line is the
//! same refusal, from the same function, that they would meet in the cabinet.
//!
//! - `codes issue` — answer a challenge read out over the telephone;
//! - `codes receipt verify` — read a receipt back and check it holds together;
//! - `codes ticket show` — show the bounds, the term and the provenance of a
//!   ticket;
//! - `codes reconcile` — put the receipts of an operator beside the journals of
//!   the devices.
//!
//! # Exit codes
//!
//! The number the tool exits with is part of the interface. Three kinds of news,
//! never mixed:
//!
//! | code | what happened |
//! |------|---------------|
//! | `0`  | the code was issued |
//! | `10` | the request fell outside the operator's ticket — device, epoch, operator, region, tags, role, level |
//! | `11` | the nonce counter does not fit the receipts — ahead, behind, or no history at all |
//! | `12` | a signature or an anchor did not hold — organisation signature, proof of possession, unanchored signer, ticket term, wrong operator key |
//! | `13` | the issuance carried no grounds |
//! | `14` | any other refusal of the issuance |
//! | `1`  | **the check never happened**: a missing file, a document that does not parse, a key that cannot be reached, a token that would not answer |
//!
//! `1` is not a verdict. It says the tool never got as far as an answer, and a
//! caller that reads it as "the request was turned away" goes green having
//! checked nothing. The numbers keep that from happening by accident too: `0`,
//! `1` and `2` carry no verdict, `64` and `70` are left to the e2e runner for
//! its own stand failures, and everything from `126` up belongs to the shell.
//!
//! Beside the code, standard error carries one machine-readable line naming the
//! exact check — finer than the code, and stable:
//!
//! ```text
//! codes-refusal: ticket_scope_level
//! ```
//!
//! The class comes from [`crate::codes::Refusal::class`] (or, for a file that is
//! not the document it claims to be, from the `CLASS_*` constants here). It
//! exists because the sentence next to it is prose: it is translated and it will
//! be reworded, and an expectation built on prose breaks at the first
//! improvement to the wording.
//!
//! `reconcile` is the deliberate exception: it exits `0` with a report full of
//! findings, because the report is the answer. Its exit code says the command
//! ran, never that the fleet is in order.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use zeroize::Zeroizing;

use tessera_codes_contract::challenge::SignedChallenge;
use tessera_codes_contract::code::Alphabet;
use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::params::{
    FleetParams, FleetParamsInput, DEFAULT_ATTEMPTS_PER_NONCE, DEFAULT_ATTEMPT_TTL_SECS,
    DEFAULT_CODE_LEN, DEFAULT_NONCE_WIDTH,
};
use tessera_codes_contract::profile::{AlgorithmProfile, UnconfirmedProfileRisk};
use tessera_codes_contract::registry::DeviceRecord;
use tessera_codes_contract::ticket::SignedTicket;
use tessera_codes_contract::time::ClaimedTime;

use crate::codes::agreement::{OperatorKey, SoftwareOperatorKey};
use crate::codes::annex::SiteScope;
use crate::codes::issue::{issue, IssuanceRequest};
use crate::codes::reconcile::{read_journal, reconcile, JournalError, LoginEntry, Provenance};
use crate::codes::scope::DeviceScope;
use crate::codes::store;
use crate::codes::trust::{AnchorKey, Anchors};
use crate::codes::RefusalGroup;
use crate::l10n::{Locale, Msg};

use super::{decode_pem_or_der, now_unix, read_file, CliError};

/// Separator between an organisation identifier and its anchor file, and
/// between a device number and its journal.
const PAIR_SEPARATOR: char = '=';

// Refusal classes of the documents this surface reads. A refused *issuance*
// carries its own class from [`crate::codes::Refusal::class`]; these cover the
// step before it, where a file does not hold the document it claims to. They are
// part of the interface for the same reason: a caller acts on the class, never
// on the sentence.

/// A challenge that is not a well-formed challenge — the check character of the
/// device number among the reasons.
const CLASS_CHALLENGE_MALFORMED: &str = "challenge_malformed";
/// A device record file that does not parse.
const CLASS_DEVICE_RECORD_MALFORMED: &str = "device_record_malformed";
/// A ticket file that does not parse.
const CLASS_TICKET_MALFORMED: &str = "ticket_malformed";
/// A ticket whose signature or term the anchors rejected.
const CLASS_TICKET_REJECTED: &str = "ticket_rejected";
/// A receipt file that does not parse, or a receipt directory that cannot be
/// read as one.
const CLASS_RECEIPT_MALFORMED: &str = "receipt_malformed";
/// A receipt that does not belong to the ticket it was checked against.
const CLASS_RECEIPT_TICKET_MISMATCH: &str = "receipt_ticket_mismatch";
/// A device journal line that does not hold what the reconciliation pairs on,
/// or a chain that does not verify.
const CLASS_JOURNAL_MALFORMED: &str = "journal_malformed";
/// A device journal that carries no code login at all.
///
/// A class of its own rather than a shade of the one above: "this journal has
/// been edited" and "this is not the journal you meant to hand over" send a
/// reader to different places, and a caller that has to act on the difference
/// cannot get it out of a shared token.
const CLASS_JOURNAL_WITHOUT_LOGINS: &str = "journal_without_logins";

/// Flags for `issuer codes`.
#[derive(Debug, Args)]
pub(super) struct CodesArgs {
    #[command(subcommand)]
    command: CodesCommand,
}

/// The commands of the phone channel.
#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "the variants are parsed command lines, one of them long; clap's derive takes the \
              arguments struct itself, not a box around it, and the value is built once per run"
)]
enum CodesCommand {
    /// Answer a challenge read out over the telephone.
    #[command(long_about = "\
Answer a challenge read out over the telephone.

The code is computed from the challenge, the signed device record and the \
operator ticket; the receipt of the issuance is written into --receipts.

Exit codes:
  0   the code was issued
  10  the request fell outside the operator ticket (device, epoch, operator,
      region, tags, role, level)
  11  the nonce counter does not fit the receipts (ahead, behind, no history)
  12  a signature or an anchor did not hold (organisation signature, proof of
      possession, unanchored signer, ticket term, wrong operator key)
  13  the issuance carried no grounds
  14  any other refusal of the issuance
  1   the check never happened: a missing file, a document that does not parse,
      a key that cannot be reached, a token that would not answer

A refusal also prints one machine-readable line to standard error naming the
exact check, for example:

  codes-refusal: ticket_scope_level")]
    Issue(IssueArgs),
    /// Work with the receipts of the channel.
    #[command(subcommand)]
    Receipt(ReceiptCommand),
    /// Work with operator tickets.
    #[command(subcommand)]
    Ticket(TicketCommand),
    /// Reconcile receipts against device journals.
    Reconcile(ReconcileArgs),
}

/// The receipt commands.
#[derive(Debug, Subcommand)]
enum ReceiptCommand {
    /// Read a receipt back and check it holds together.
    Verify(ReceiptVerifyArgs),
}

/// The ticket commands.
#[derive(Debug, Subcommand)]
enum TicketCommand {
    /// Show the bounds, the term and the provenance of a ticket.
    Show(TicketShowArgs),
}

/// Alphabet of the fleet, as a flag value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AlphabetArg {
    /// Decimal digits.
    Decimal,
    /// Crockford base32.
    CrockfordBase32,
}

/// Key agreement profile of the fleet, as a flag value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProfileArg {
    /// NIST P-256 ECDH.
    P256,
    /// X25519.
    X25519,
    /// ГОСТ Р 34.10-2012 VKO.
    Gost,
}

/// The fleet parameters, which fix the shape of a nonce and of a code.
///
/// They are flags rather than a file because the two sides of a call have to
/// agree on them and a fleet that changes them changes its whole channel: a
/// value read from a file somebody edited is exactly the drift that shows up as
/// "the code does not fit". Everything is checked by
/// [`FleetParams::parse`] — the same check the device applies.
#[derive(Debug, Clone, Args)]
struct FleetArgs {
    /// Number of characters in the code.
    #[arg(long, default_value_t = DEFAULT_CODE_LEN)]
    code_len: u8,
    /// Verification attempts allowed for one nonce.
    #[arg(long, default_value_t = DEFAULT_ATTEMPTS_PER_NONCE)]
    attempts_per_nonce: u8,
    /// Alphabet of the code and of the nonce.
    #[arg(long, value_enum, default_value_t = AlphabetArg::CrockfordBase32)]
    alphabet: AlphabetArg,
    /// Width of the nonce, in characters.
    #[arg(long, default_value_t = DEFAULT_NONCE_WIDTH)]
    nonce_width: u8,
    /// How long an attempt may stay open, in seconds.
    #[arg(long, default_value_t = DEFAULT_ATTEMPT_TTL_SECS)]
    attempt_ttl_secs: u64,
    /// Key agreement profile of the device pairs.
    #[arg(long, value_enum, default_value_t = ProfileArg::P256)]
    profile: ProfileArg,
    /// Accept a profile whose vendor gate is still open.
    #[arg(long)]
    accept_unconfirmed_profile: bool,
}

impl FleetArgs {
    /// Checks the parameters the way the device does.
    fn params(&self) -> Result<FleetParams, CliError> {
        FleetParams::parse(FleetParamsInput {
            code_len: self.code_len,
            attempts_per_nonce: self.attempts_per_nonce,
            alphabet: match self.alphabet {
                AlphabetArg::Decimal => Alphabet::Decimal,
                AlphabetArg::CrockfordBase32 => Alphabet::CrockfordBase32,
            },
            nonce_width: self.nonce_width,
            attempt_ttl_secs: self.attempt_ttl_secs,
            profile: self.profile(),
            unconfirmed_profile_risk: if self.accept_unconfirmed_profile {
                UnconfirmedProfileRisk::AcceptedByFleetOwner
            } else {
                UnconfirmedProfileRisk::NotAccepted
            },
        })
        .map_err(|error| CliError::Usage(error.to_string()))
    }

    /// The profile the flags name.
    fn profile(&self) -> AlgorithmProfile {
        match self.profile {
            ProfileArg::P256 => AlgorithmProfile::P256,
            ProfileArg::X25519 => AlgorithmProfile::X25519,
            ProfileArg::Gost => AlgorithmProfile::GostVko34102012,
        }
    }
}

/// Where the operator's private key is, and how to reach it.
#[derive(Debug, Clone, Args)]
struct OperatorKeyArgs {
    /// `CKA_ID` of the operator key pair on the token, in hexadecimal.
    #[arg(long, conflicts_with = "soft_key")]
    operator_key_id: Option<String>,
    /// PKCS#11 module path.
    #[arg(long)]
    module: Option<PathBuf>,
    /// PKCS#11 token label to select.
    #[arg(long)]
    token_label: Option<String>,
    /// pinentry program for the PIN prompt. Naming one pins the secret source:
    /// no other source is consulted.
    #[arg(long, conflicts_with_all = ["pin_stdin", "pin_file"])]
    pinentry: Option<PathBuf>,
    /// Read the token PIN as one line from standard input.
    #[arg(long, conflicts_with = "pin_file")]
    pin_stdin: bool,
    /// Read the token PIN as one line from a file readable only by its owner.
    /// The flag takes the file's path, never the PIN itself.
    #[arg(long)]
    pin_file: Option<PathBuf>,
    /// The explicitly enabled software mode: a PKCS#8 operator key file, PEM or
    /// DER. The receipt records that the key was held this way.
    #[arg(long)]
    soft_key: Option<PathBuf>,
    /// Passphrase of an encrypted operator key file, read as one line from a
    /// file readable only by its owner.
    #[arg(long, requires = "soft_key")]
    soft_key_passphrase_file: Option<PathBuf>,
}

/// Flags for `issuer codes issue`.
///
/// The exit codes are in the long help because an operator scripting this
/// command has to know them, and a table that lives only in the source is a
/// table nobody reading `--help` will find.
#[derive(Debug, Args)]
struct IssueArgs {
    #[command(flatten)]
    fleet: FleetArgs,
    #[command(flatten)]
    key: OperatorKeyArgs,
    /// The challenge as it was read out, in its wire form.
    #[arg(long, conflicts_with = "challenge_file")]
    challenge: Option<String>,
    /// A file holding the challenge in its wire form.
    #[arg(long)]
    challenge_file: Option<PathBuf>,
    /// The signed device record of the device the challenge names.
    #[arg(long)]
    device_record: PathBuf,
    /// The operator ticket to work under.
    #[arg(long)]
    ticket: PathBuf,
    /// `SubjectPublicKeyInfo` of the authority that issues operator tickets
    /// (PEM or DER).
    #[arg(long)]
    anchor_ticket_authority: PathBuf,
    /// An organisation anchor as `id=path` (repeat for several).
    #[arg(long = "anchor-organisation")]
    anchor_organisations: Vec<String>,
    /// Grounds for the issuance: a work order, a request, a ticket of the
    /// fleet's own tracker. Required, and not satisfied by whitespace.
    #[arg(long)]
    reason: String,
    /// Directory the receipts of this operator live in.
    #[arg(long)]
    receipts: PathBuf,
    /// Region the device stands in, from the fleet inventory.
    #[arg(long, requires = "device_tags")]
    device_region: Option<String>,
    /// A site tag of the device (repeat for several).
    #[arg(long = "device-tag", requires = "device_region")]
    device_tags: Vec<String>,
    /// The moment to work at, Unix seconds.
    ///
    /// Only test builds carry it. In a shipped build the term of the ticket and
    /// the moment written into the receipt both come from the system clock and
    /// from nothing else: a flag that moved them would let an operator keep
    /// issuing under an expired ticket and file receipts whose timestamps say
    /// whatever suits, and the difference between the moment of a receipt and
    /// the moment of a login is one of the few signals a reconciliation has.
    #[cfg(test)]
    #[arg(long)]
    now: Option<u64>,
    /// Print the code alone, without captions — for a caller that reads it.
    #[arg(long)]
    code_only: bool,
}

/// Flags for `issuer codes receipt verify`.
#[derive(Debug, Args)]
struct ReceiptVerifyArgs {
    #[command(flatten)]
    fleet: FleetArgs,
    /// The receipt file to read.
    #[arg(long)]
    receipt: PathBuf,
    /// The ticket the receipt claims to have been issued under. Supplying it
    /// checks the binding the receipt's file name carries.
    #[arg(long)]
    ticket: Option<PathBuf>,
}

/// Flags for `issuer codes ticket show`.
#[derive(Debug, Args)]
struct TicketShowArgs {
    /// The ticket file to read.
    #[arg(long)]
    ticket: PathBuf,
    /// `SubjectPublicKeyInfo` of the ticket authority (PEM or DER). Without it
    /// the fields are shown as claims, not as anything anybody signed for.
    #[arg(long)]
    anchor_ticket_authority: Option<PathBuf>,
    /// The moment to judge the term at, Unix seconds. Defaults to the system
    /// clock.
    #[arg(long)]
    now: Option<u64>,
}

/// Flags for `issuer codes reconcile`.
#[derive(Debug, Args)]
struct ReconcileArgs {
    #[command(flatten)]
    fleet: FleetArgs,
    /// Directory holding the receipts to reconcile.
    #[arg(long)]
    receipts: PathBuf,
    /// A device journal as `device-number=path` (repeat for several). Without
    /// any, the report is marked incomplete.
    #[arg(long = "device-journal")]
    device_journals: Vec<String>,
}

/// Runs one `codes` command.
pub(super) fn run(args: CodesArgs, locale: Locale) -> Result<(), CliError> {
    match args.command {
        CodesCommand::Issue(args) => run_issue(&args, locale),
        CodesCommand::Receipt(ReceiptCommand::Verify(args)) => run_receipt_verify(&args, locale),
        CodesCommand::Ticket(TicketCommand::Show(args)) => run_ticket_show(&args, locale),
        CodesCommand::Reconcile(args) => run_reconcile(&args, locale),
    }
}

/// `issuer codes issue`.
fn run_issue(args: &IssueArgs, locale: Locale) -> Result<(), CliError> {
    let params = args.fleet.params()?;
    let challenge = read_challenge(args, params)?;
    let record = read_record(&args.device_record)?;
    let ticket = read_ticket(&args.ticket)?;
    let anchors = read_anchors(
        &args.anchor_ticket_authority,
        &args.anchor_organisations,
        record.organisation_id(),
        record.owner_id(),
    )?;
    let now = ClaimedTime::new(claimed_now(args)?);

    let device_scope = match (args.device_region.as_deref(), args.device_tags.as_slice()) {
        (Some(region), tags) if !tags.is_empty() => Some(DeviceScope {
            tags: tags.to_vec(),
            region: region.to_owned(),
        }),
        _ => None,
    };

    let request = IssuanceRequest {
        challenge: &challenge,
        record: &record,
        ticket: &ticket,
        params: &params,
        device_scope: device_scope.as_ref(),
        reason: &args.reason,
        now,
    };

    let issuance = with_operator_key(&args.key, args.fleet.profile(), locale, |key| {
        issue(&request, &anchors, key).map_err(|refusal| CliError::Codes {
            class: refusal.class(),
            group: refusal.group(),
            detail: refusal.to_string(),
        })
    })?;

    create_private_dir(&args.receipts)?;

    let path = store::write(&args.receipts, &issuance, ticket.ticket())
        .map_err(|error| CliError::Io(error.to_string()))?;

    if args.code_only {
        println!("{}", issuance.code);
        return Ok(());
    }

    println!(
        "{} {}",
        Msg::CodesCodeHeading.text(locale),
        issuance.spoken_code()
    );
    println!(
        "{} {}",
        Msg::CodesReceiptWritten.text(locale),
        path.display()
    );
    println!(
        "{} {}",
        Msg::CodesKeyStorage.text(locale),
        issuance.annex.key_storage().as_str()
    );
    if issuance.annex.site_scope() == SiteScope::Undeclared {
        eprintln!("{}", Msg::CodesSiteUndeclared.text(locale));
    }
    Ok(())
}

/// `issuer codes receipt verify`.
fn run_receipt_verify(args: &ReceiptVerifyArgs, locale: Locale) -> Result<(), CliError> {
    let params = args.fleet.params()?;
    let stored = store::read_file(&args.receipt, &params).map_err(|error| CliError::Codes {
        class: CLASS_RECEIPT_MALFORMED,
        group: RefusalGroup::Environment,
        detail: error.to_string(),
    })?;

    if let Some(path) = args.ticket.as_deref() {
        let ticket = read_ticket(path)?;
        let expected =
            stored
                .receipt
                .file_name(ticket.ticket())
                .map_err(|error| CliError::Codes {
                    class: CLASS_RECEIPT_MALFORMED,
                    group: RefusalGroup::Environment,
                    detail: error.to_string(),
                })?;
        let actual = args
            .receipt
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        if expected != actual {
            return Err(CliError::Codes {
                class: CLASS_RECEIPT_TICKET_MISMATCH,
                group: RefusalGroup::Other,
                detail: format!(
                    "{} the file name does not match the receipt under this ticket (expected \
                     {expected})",
                    Msg::CodesReceiptInvalid.text(locale)
                ),
            });
        }
        if stored.annex.ticket_number() != ticket.ticket().number() {
            return Err(CliError::Codes {
                class: CLASS_RECEIPT_TICKET_MISMATCH,
                group: RefusalGroup::Other,
                detail: format!(
                    "{} the annex names ticket {} and the supplied ticket is {}",
                    Msg::CodesReceiptInvalid.text(locale),
                    stored.annex.ticket_number(),
                    ticket.ticket().number()
                ),
            });
        }
        println!("{}", Msg::CodesReceiptValid.text(locale));
    }

    println!("{}", stored.receipt.to_wire());
    println!("{}", stored.annex.to_wire());
    Ok(())
}

/// `issuer codes ticket show`.
fn run_ticket_show(args: &TicketShowArgs, locale: Locale) -> Result<(), CliError> {
    let ticket = read_ticket(&args.ticket)?;
    let now = ClaimedTime::new(match args.now {
        Some(now) => now,
        None => now_unix()?,
    });

    match args.anchor_ticket_authority.as_deref() {
        Some(path) => {
            let anchors = Anchors::new(read_anchor_key(path)?);
            ticket
                .verify(&anchors, now)
                .map_err(|error| CliError::Codes {
                    class: CLASS_TICKET_REJECTED,
                    group: RefusalGroup::Trust,
                    detail: error.to_string(),
                })?;
            println!("{}", Msg::CodesTicketVerified.text(locale));
        }
        None => eprintln!("{}", Msg::CodesTicketUnverified.text(locale)),
    }

    let scope = ticket.ticket().scope();
    println!("number: {}", ticket.ticket().number());
    println!("operator: {}", ticket.ticket().server_id());
    println!("region: {}", scope.region());
    println!("tags: {}", scope.tags().join(","));
    println!("roles: {}", scope.roles().join(","));
    println!("max_level: {}", scope.max_level().get());
    println!("not_after: {}", ticket.ticket().not_after());
    println!(
        "operator_key: {}",
        hex::encode(ticket.ticket().public_key().as_bytes())
    );
    println!("signature: {}", hex::encode(ticket.signature().as_bytes()));
    // The hash bound into every key this ticket derives: two operators holding
    // "the same" ticket whose hashes differ hold two different documents.
    let context = ticket.context_hash().map_err(|error| CliError::Codes {
        class: CLASS_TICKET_MALFORMED,
        group: RefusalGroup::Environment,
        detail: error.to_string(),
    })?;
    println!("context_hash: {}", hex::encode(context.as_bytes()));
    Ok(())
}

/// `issuer codes reconcile`.
fn run_reconcile(args: &ReconcileArgs, locale: Locale) -> Result<(), CliError> {
    let params = args.fleet.params()?;
    let receipts =
        store::read_directory(&args.receipts, &params).map_err(|error| CliError::Codes {
            class: CLASS_RECEIPT_MALFORMED,
            group: RefusalGroup::Environment,
            detail: error.to_string(),
        })?;
    let entries = store::entries(&receipts);

    let mut provenance = Provenance {
        chain_verified: true,
        unsigned_from_seq: None,
        refusals_without_nonce: 0,
        unaccounted_without_nonce: std::collections::BTreeSet::new(),
    };
    let logins = if args.device_journals.is_empty() {
        None
    } else {
        let mut logins: Vec<LoginEntry> = Vec::new();
        for pair in &args.device_journals {
            let (device_number, path) = split_pair(pair, "--device-journal")?;
            // The number arrives typed by a person, from a label or a printout,
            // and the receipts hold its significant form. Comparing the two as
            // strings makes every pairing fail — and a reconciliation where
            // nothing pairs is not an empty report, it is a page of alarms in
            // the two classes the whole command exists for.
            let device_number = CheckedDeviceNumber::parse(device_number).map_err(|error| {
                CliError::Usage(format!(
                    "--device-journal names the device `{device_number}`, which is not a device \
                     number: {error}"
                ))
            })?;
            let text = String::from_utf8(read_file(&PathBuf::from(path))?)
                .map_err(|_| CliError::Io(format!("{path} is not UTF-8")))?;
            let journal =
                read_journal(device_number.significant(), &text, &params).map_err(|error| {
                    CliError::Codes {
                        class: match error {
                            // "Nothing to reconcile against" and "this history
                            // has been edited" send a reader to different
                            // places; one token for both would hide which.
                            JournalError::NoLoginLines => CLASS_JOURNAL_WITHOUT_LOGINS,
                            _ => CLASS_JOURNAL_MALFORMED,
                        },
                        group: RefusalGroup::Environment,
                        detail: format!("{path}: {error}"),
                    }
                })?;
            provenance.chain_verified &= journal.chain_verified;
            provenance.refusals_without_nonce = provenance
                .refusals_without_nonce
                .saturating_add(journal.refusals_without_nonce);
            provenance
                .unaccounted_without_nonce
                .extend(journal.unaccounted_without_nonce);
            // The earliest unsigned tail across the journals: the weakest of
            // them is what the report may claim for all of them.
            provenance.unsigned_from_seq =
                match (provenance.unsigned_from_seq, journal.unsigned_from_seq) {
                    (Some(left), Some(right)) => Some(left.min(right)),
                    (some, None) | (None, some) => some,
                };
            logins.extend(journal.entries);
        }
        Some(logins)
    };

    let report = reconcile(
        &entries,
        logins.as_deref(),
        &if logins.is_some() {
            provenance
        } else {
            Provenance::absent()
        },
    );
    if !report.is_complete() {
        eprintln!("{}", Msg::CodesReconcileIncomplete.text(locale));
    }
    // The report first, the verdict after it. The report opens with what could
    // not be established — an absent device side, a journal with no chain, a
    // tail no signature covers — and a reader who met "the two sides agree"
    // first would carry that sentence over the caveat that qualifies it.
    print!("{report}");
    // And the verdict only over a report that was able to look. "No
    // disagreements" printed under a journal whose lines this build could not
    // account for is the sentence the incompleteness exists to prevent, and a
    // consumer reading exit code and last line — which is what a script does —
    // would take the fleet for clean.
    if !report.has_findings() && report.is_complete() {
        println!("{}", Msg::CodesReconcileClean.text(locale));
    }
    Ok(())
}

/// Reads the signed challenge from the flag or the file that carries it.
fn read_challenge(args: &IssueArgs, params: FleetParams) -> Result<SignedChallenge, CliError> {
    let text = match (args.challenge.as_deref(), args.challenge_file.as_deref()) {
        (Some(text), _) => text.to_owned(),
        (None, Some(path)) => String::from_utf8(read_file(path)?)
            .map_err(|_| CliError::Io(format!("{} is not UTF-8", path.display())))?,
        (None, None) => {
            return Err(CliError::Usage(
                "one of --challenge or --challenge-file is required".to_owned(),
            ))
        }
    };
    // The check character of the device number is checked here, before anything
    // is derived or computed: a number typed wrong is a typo the operator hears
    // about, not a code that will not fit.
    SignedChallenge::parse(text.trim(), &params).map_err(|error| CliError::Codes {
        class: CLASS_CHALLENGE_MALFORMED,
        group: RefusalGroup::Other,
        detail: error.to_string(),
    })
}

/// Reads a signed device record.
fn read_record(path: &std::path::Path) -> Result<DeviceRecord, CliError> {
    let text = String::from_utf8(read_file(path)?)
        .map_err(|_| CliError::Io(format!("{} is not UTF-8", path.display())))?;
    DeviceRecord::parse(text.trim()).map_err(|error| CliError::Codes {
        class: CLASS_DEVICE_RECORD_MALFORMED,
        group: RefusalGroup::Environment,
        detail: error.to_string(),
    })
}

/// Reads a signed operator ticket.
fn read_ticket(path: &std::path::Path) -> Result<SignedTicket, CliError> {
    let text = String::from_utf8(read_file(path)?)
        .map_err(|_| CliError::Io(format!("{} is not UTF-8", path.display())))?;
    SignedTicket::parse(text.trim()).map_err(|error| CliError::Codes {
        class: CLASS_TICKET_MALFORMED,
        group: RefusalGroup::Environment,
        detail: error.to_string(),
    })
}

/// Reads one anchor from a `SubjectPublicKeyInfo` file.
fn read_anchor_key(path: &std::path::Path) -> Result<AnchorKey, CliError> {
    let der = decode_pem_or_der(&read_file(path)?)?;
    AnchorKey::from_spki_der(&der)
        .map_err(|error| CliError::Usage(format!("{}: {error}", path.display())))
}

/// Reads the anchors, refusing before anything is computed when the
/// organisation that signed the record is not among them.
///
/// The refusal is early on purpose: "unknown signer" arriving out of a
/// verification reads like a bad signature, and an operator on a call would go
/// looking at the record rather than at their own anchor set.
fn read_anchors(
    authority: &std::path::Path,
    organisations: &[String],
    organisation_of_record: &str,
    owner_of_record: &str,
) -> Result<Anchors, CliError> {
    let mut anchors = Anchors::new(read_anchor_key(authority)?);
    for pair in organisations {
        let (id, path) = split_pair(pair, "--anchor-organisation")?;
        anchors = anchors.with_organisation(id, read_anchor_key(&PathBuf::from(path))?);
    }
    if !anchors.knows_organisation(owner_of_record) {
        return Err(CliError::Usage(format!(
            "the record was countersigned by the owner `{owner_of_record}`, which no \
             --anchor-organisation names"
        )));
    }
    if !anchors.knows_organisation(organisation_of_record) {
        return Err(CliError::Usage(format!(
            "the record was signed by the organisation `{organisation_of_record}`, which no \
             --anchor-organisation names"
        )));
    }
    Ok(anchors)
}

/// Splits an `id=path` flag value.
fn split_pair<'a>(value: &'a str, flag: &str) -> Result<(&'a str, &'a str), CliError> {
    value
        .split_once(PAIR_SEPARATOR)
        .filter(|(left, right)| !left.is_empty() && !right.is_empty())
        .ok_or_else(|| CliError::Usage(format!("{flag} takes `name{PAIR_SEPARATOR}path`")))
}

/// The moment the operator's side claims.
///
/// A shipped build has one source for it — the system clock. See the `now`
/// field of [`IssueArgs`] for why there is no flag.
fn claimed_now(args: &IssueArgs) -> Result<u64, CliError> {
    #[cfg(test)]
    if let Some(now) = args.now {
        return Ok(now);
    }
    #[cfg(not(test))]
    let _ = args;
    now_unix()
}

/// Creates a directory only its owner can enter.
///
/// Receipts are audit records of who was let into what; a directory the whole
/// machine can read is not where they belong.
fn create_private_dir(path: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(path)
        .map_err(|error| CliError::Io(format!("{}: {error}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| CliError::Io(format!("{}: {error}", path.display())))?;
    }
    Ok(())
}

/// Builds the operator key the flags name and hands it to `job`.
///
/// The two modes are exclusive and neither is a fallback: a token that cannot be
/// reached is a refusal, never a quiet slide into reading a key file.
fn with_operator_key<T>(
    args: &OperatorKeyArgs,
    profile: AlgorithmProfile,
    locale: Locale,
    job: impl FnOnce(&dyn OperatorKey) -> Result<T, CliError>,
) -> Result<T, CliError> {
    match (args.operator_key_id.as_deref(), args.soft_key.as_deref()) {
        (Some(key_id), None) => with_token_key(args, key_id, profile, locale, job),
        (None, Some(path)) => {
            let key = read_software_key(args, path, profile)?;
            job(&key)
        }
        (None, None) => Err(CliError::Usage(
            "one of --operator-key-id (a token) or --soft-key (the explicit software mode) is \
             required"
                .to_owned(),
        )),
        (Some(_), Some(_)) => Err(CliError::Usage(
            "--operator-key-id and --soft-key name two different keys".to_owned(),
        )),
    }
}

#[cfg(feature = "pkcs11")]
fn with_token_key<T>(
    args: &OperatorKeyArgs,
    key_id: &str,
    profile: AlgorithmProfile,
    locale: Locale,
    job: impl FnOnce(&dyn OperatorKey) -> Result<T, CliError>,
) -> Result<T, CliError> {
    use crate::codes::token::{TokenKeyConfig, TokenOperatorKey};

    let module_path = args
        .module
        .clone()
        .ok_or_else(|| CliError::Usage("--module is required with --operator-key-id".to_owned()))?;
    let key_id = hex::decode(key_id).map_err(|_| {
        CliError::Usage("--operator-key-id takes the CKA_ID in hexadecimal".to_owned())
    })?;
    let pin_source = super::pin::CliPinSource::new(pin_source(args), locale);
    let key = TokenOperatorKey::open(
        TokenKeyConfig {
            module_path,
            token_label: args.token_label.clone(),
            key_id,
        },
        pin_source,
        profile,
    )
    .map_err(|error| CliError::Backend(error.to_string()))?;
    job(&key)
}

#[cfg(not(feature = "pkcs11"))]
fn with_token_key<T>(
    _args: &OperatorKeyArgs,
    _key_id: &str,
    _profile: AlgorithmProfile,
    _locale: Locale,
    _job: impl FnOnce(&dyn OperatorKey) -> Result<T, CliError>,
) -> Result<T, CliError> {
    Err(CliError::Usage(
        "this build has no pkcs11 backend (rebuild with the `pkcs11` feature)".to_owned(),
    ))
}

/// The PIN source the operator named, if any.
#[cfg(feature = "pkcs11")]
fn pin_source(args: &OperatorKeyArgs) -> Option<super::secret::FlagSource> {
    use super::secret::FlagSource;

    if let Some(program) = args.pinentry.clone() {
        return Some(FlagSource::Pinentry(program));
    }
    if args.pin_stdin {
        return Some(FlagSource::Stdin);
    }
    args.pin_file.clone().map(FlagSource::File)
}

/// Reads the operator key file of the explicitly enabled software mode.
///
/// The file goes through the same owner-only gate as every other secret this
/// tool reads: it holds a private key, and a key file the whole machine can read
/// is the software mode at its worst rather than at its stated cost.
fn read_software_key(
    args: &OperatorKeyArgs,
    path: &std::path::Path,
    profile: AlgorithmProfile,
) -> Result<SoftwareOperatorKey, CliError> {
    let der = read_pkcs8_key(path, args.soft_key_passphrase_file.as_deref())?;
    SoftwareOperatorKey::from_pkcs8_der(&der, profile)
        .map_err(|error| CliError::Usage(format!("{}: {error}", path.display())))
}

/// Reads a PKCS#8 key file, decrypting it when it is encrypted.
///
/// Plaintext and encrypted files are told apart by what parses, not by the file
/// name or the flag: a caller who names a passphrase file for a plaintext key
/// has one of the two wrong, and reading the key anyway would hide which.
fn read_pkcs8_key(
    path: &std::path::Path,
    passphrase_file: Option<&std::path::Path>,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let raw = crate::secret_file::open(path)
        .map_err(|error| match error {
            crate::secret_file::OpenError::Io(error) => {
                CliError::Io(format!("{}: {error}", path.display()))
            }
            crate::secret_file::OpenError::BeyondOwner(refusal) => CliError::Usage(format!(
                "{} is readable beyond its owner (mode {:o}); restrict it (chmod 600)",
                path.display(),
                refusal.mode
            )),
        })?
        .read_all()
        .map_err(|error| CliError::Io(format!("{}: {error}", path.display())))?;
    let der = Zeroizing::new(decode_pem_or_der(&raw)?);

    if PrivateKeyInfo::try_from(der.as_slice()).is_ok() {
        if passphrase_file.is_some() {
            return Err(CliError::Usage(format!(
                "{} is not encrypted, and --soft-key-passphrase-file names a passphrase for it",
                path.display()
            )));
        }
        return Ok(der);
    }

    let encrypted = EncryptedPrivateKeyInfo::try_from(der.as_slice()).map_err(|_| {
        CliError::Usage(format!(
            "{} is not a PKCS#8 private key (PEM or DER)",
            path.display()
        ))
    })?;
    let passphrase_file = passphrase_file.ok_or_else(|| {
        CliError::Usage(format!(
            "{} is encrypted; name its passphrase with --soft-key-passphrase-file <path>",
            path.display()
        ))
    })?;
    let passphrase = read_passphrase(passphrase_file)?;
    let plain = encrypted.decrypt(passphrase.as_slice()).map_err(|_| {
        CliError::Usage("the operator key passphrase does not open the key".to_owned())
    })?;
    Ok(Zeroizing::new(plain.as_bytes().to_vec()))
}

/// Reads a passphrase as the first line of an owner-only file.
fn read_passphrase(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    crate::secret_file::open(path)
        .map_err(|error| match error {
            crate::secret_file::OpenError::Io(error) => {
                CliError::Io(format!("{}: {error}", path.display()))
            }
            crate::secret_file::OpenError::BeyondOwner(refusal) => CliError::Usage(format!(
                "{} is readable beyond its owner (mode {:o}); restrict it (chmod 600)",
                path.display(),
                refusal.mode
            )),
        })?
        .read_first_line()
        .map_err(|error| match error {
            crate::secret_file::ReadLineError::TooLong => CliError::Usage(format!(
                "{} gives no line break within the accepted length of a passphrase",
                path.display()
            )),
            crate::secret_file::ReadLineError::Io(error) => {
                CliError::Io(format!("{}: {error}", path.display()))
            }
        })
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{split_pair, AlphabetArg, FleetArgs, ProfileArg};
    use tessera_codes_contract::params::{
        DEFAULT_ATTEMPTS_PER_NONCE, DEFAULT_ATTEMPT_TTL_SECS, DEFAULT_CODE_LEN, DEFAULT_NONCE_WIDTH,
    };

    fn defaults() -> FleetArgs {
        FleetArgs {
            code_len: DEFAULT_CODE_LEN,
            attempts_per_nonce: DEFAULT_ATTEMPTS_PER_NONCE,
            alphabet: AlphabetArg::CrockfordBase32,
            nonce_width: DEFAULT_NONCE_WIDTH,
            attempt_ttl_secs: DEFAULT_ATTEMPT_TTL_SECS,
            profile: ProfileArg::P256,
            accept_unconfirmed_profile: false,
        }
    }

    #[test]
    fn the_flag_defaults_are_the_contract_defaults() {
        assert_eq!(
            defaults().params().unwrap(),
            tessera_codes_contract::params::FleetParams::defaults()
        );
    }

    #[test]
    fn parameters_weaker_than_the_contract_do_not_parse() {
        // Two characters are below the floor in every alphabet the contract
        // holds; four are below it only in decimal, and a test that used four
        // would be about the alphabet rather than the floor.
        let mut args = defaults();
        args.code_len = 2;
        assert!(args.params().is_err());

        // And the ceiling on the attempt lifetime is the contract's, not a
        // suggestion the flags may exceed.
        let mut args = defaults();
        args.attempt_ttl_secs = tessera_codes_contract::params::MAX_ATTEMPT_TTL_SECS + 1;
        assert!(args.params().is_err());
    }

    #[test]
    fn an_unconfirmed_profile_needs_the_risk_accepted_in_a_flag_of_its_own() {
        let mut args = defaults();
        args.profile = ProfileArg::Gost;
        assert!(args.params().is_err());
        args.accept_unconfirmed_profile = true;
        assert!(args.params().is_ok());
    }

    #[test]
    fn a_pair_flag_takes_a_name_and_a_path() {
        assert_eq!(
            split_pair("acme=/tmp/acme.spki", "--anchor-organisation").unwrap(),
            ("acme", "/tmp/acme.spki")
        );
        for malformed in ["acme", "=/tmp/acme.spki", "acme="] {
            assert!(split_pair(malformed, "--anchor-organisation").is_err());
        }
    }

    /// The command line exercised end to end, against files on disk.
    ///
    /// The handlers are called directly rather than through a spawned process:
    /// what is under test is the wiring — which file is read, which key is
    /// built, what is written — and a subprocess would only add a way for the
    /// test to pass while the wiring is wrong.
    mod on_disk {
        use std::fs;
        use std::path::{Path, PathBuf};

        use super::super::{
            run_issue, run_receipt_verify, run_reconcile, run_ticket_show, IssueArgs,
            OperatorKeyArgs, ReceiptVerifyArgs, ReconcileArgs, TicketShowArgs,
        };
        use super::defaults;
        use crate::cli::CliError;
        use crate::codes::store;
        use crate::codes::tests::fixtures;
        use crate::l10n::Locale;
        use tessera_codes_contract::params::FleetParams;

        /// A fleet laid out in a temporary directory.
        struct Files {
            root: tempfile::TempDir,
            world: fixtures::World,
        }

        impl Files {
            /// Writes every document of the fixture world to disk.
            fn new() -> Self {
                let root = tempfile::tempdir().unwrap();
                let world = fixtures::world();
                write(&root.path().join("challenge"), &world.challenge.to_wire());
                write(&root.path().join("record"), &world.record.to_wire());
                write(&root.path().join("ticket"), &world.ticket.to_wire());
                fs::write(
                    root.path().join("authority.spki"),
                    fixtures::spki_of(fixtures::AUTHORITY_SEED),
                )
                .unwrap();
                fs::write(
                    root.path().join("acme.spki"),
                    fixtures::spki_of(fixtures::ORGANISATION_SEED),
                )
                .unwrap();
                std::fs::write(
                    root.path().join("owner.spki"),
                    fixtures::spki_of(fixtures::OWNER_SEED),
                )
                .unwrap();
                write_owner_only(
                    &root.path().join("operator.key"),
                    &fixtures::pkcs8_of(fixtures::OPERATOR_SEED),
                );
                Self { root, world }
            }

            fn path(&self, name: &str) -> PathBuf {
                self.root.path().join(name)
            }

            /// The arguments of an ordinary, covered issuance.
            fn issue_args(&self) -> IssueArgs {
                IssueArgs {
                    fleet: defaults(),
                    key: OperatorKeyArgs {
                        operator_key_id: None,
                        module: None,
                        token_label: None,
                        pinentry: None,
                        pin_stdin: false,
                        pin_file: None,
                        soft_key: Some(self.path("operator.key")),
                        soft_key_passphrase_file: None,
                    },
                    challenge: None,
                    challenge_file: Some(self.path("challenge")),
                    device_record: self.path("record"),
                    ticket: self.path("ticket"),
                    anchor_ticket_authority: self.path("authority.spki"),
                    anchor_organisations: vec![
                        format!("acme={}", self.path("acme.spki").display()),
                        format!(
                            "{}={}",
                            fixtures::OWNER_ID,
                            self.path("owner.spki").display()
                        ),
                    ],
                    reason: "work order 42".to_owned(),
                    receipts: self.path("receipts"),
                    device_region: Some("ru-central".to_owned()),
                    device_tags: vec!["dc-1".to_owned()],
                    now: Some(fixtures::NOW.get()),
                    code_only: true,
                }
            }
        }

        /// Одна строка настоящей цепочки устройства для того же challenge.
        fn device_chain_line(challenge: &tessera_codes_contract::challenge::Challenge) -> String {
            use crate::codes::reconcile::DeviceLine;
            use tessera_hashchain::storage::MemoryStorage;
            use tessera_hashchain::Chain;

            let mut chain: Chain<MemoryStorage, DeviceLine> =
                Chain::load(MemoryStorage::new()).unwrap();
            let record: DeviceLine = serde_json::from_value(serde_json::json!({
                "op": "code_login",
                "nonce_ref": challenge.nonce().as_str(),
                "role_id": challenge.role_id(),
                "level": challenge.level().get(),
                "epoch": challenge.epoch().get(),
                "ticket_no": "tk-e2e-1",
                "outcome": "success",
            }))
            .unwrap();
            chain.append(&record, 1_800_000_000).unwrap();
            format!("{}\n", chain.storage().lines().join("\n"))
        }

        fn write(path: &Path, text: &str) {
            fs::write(path, format!("{text}\n")).unwrap();
        }

        /// Writes a key file the owner-only gate accepts.
        fn write_owner_only(path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        /// A request outside the ticket is distinguishable, by class and by
        /// exit code, from every other way an issuance can fail.
        ///
        /// This is what lets a harness assert "the operator could not step
        /// outside their ticket" without asserting on prose: matching a
        /// translated sentence would pass on a stand where nothing works, which
        /// is the failure mode the assertion exists to catch.
        #[test]
        fn a_request_outside_the_ticket_is_told_apart_from_a_broken_stand() {
            let files = Files::new();
            let outside = fixtures::signed_challenge_with(|input| input.level = 9);
            write(&files.path("challenge-level-9"), &outside.to_wire());

            let mut args = files.issue_args();
            args.challenge_file = Some(files.path("challenge-level-9"));
            let refusal = run_issue(&args, Locale::En).unwrap_err();
            assert_eq!(refusal.refusal_class(), Some("ticket_scope_level"));
            assert_eq!(refusal.exit_code(), crate::cli::EXIT_REFUSED_TICKET_SCOPE);

            // A stand that is merely broken must not produce that class: the
            // record here is a file that is not a record at all.
            write(&files.path("record"), "not a device record");
            let broken = run_issue(&files.issue_args(), Locale::En).unwrap_err();
            assert_eq!(broken.refusal_class(), Some("device_record_malformed"));

            // Nor must a request the ticket does cover: it is not a refusal.
            let files = Files::new();
            assert!(run_issue(&files.issue_args(), Locale::En).is_ok());
        }

        /// The classes of the axes stay apart from each other, so a harness
        /// asserting one axis does not go green on another.
        #[test]
        fn each_axis_of_the_ticket_reports_its_own_class() {
            let files = Files::new();
            let role =
                fixtures::signed_challenge_with(|input| input.role_id = "ops.dc.root".to_owned());
            write(&files.path("challenge-role"), &role.to_wire());
            let mut args = files.issue_args();
            args.challenge_file = Some(files.path("challenge-role"));
            assert_eq!(
                run_issue(&args, Locale::En).unwrap_err().refusal_class(),
                Some("ticket_scope_role")
            );

            let mut args = files.issue_args();
            args.device_region = Some("ru-north".to_owned());
            assert_eq!(
                run_issue(&args, Locale::En).unwrap_err().refusal_class(),
                Some("ticket_scope_region")
            );
        }

        /// Каждый класс отказа уходит своим кодом возврата, и сбой стенда не
        /// путается ни с одним вердиктом.
        ///
        /// Проверяется через настоящие вызовы команды, а не таблицей констант:
        /// таблица подтвердила бы только саму себя, а разойтись может именно
        /// сопоставление отказа с группой.
        #[test]
        fn every_class_of_refusal_leaves_its_own_exit_code() {
            use crate::cli::{
                EXIT_REFUSED_GROUNDS, EXIT_REFUSED_TICKET_SCOPE, EXIT_REFUSED_TRUST,
                EXIT_TOOL_FAILURE,
            };

            let files = Files::new();

            // Вне рамок билета.
            let outside = fixtures::signed_challenge_with(|input| input.level = 9);
            write(&files.path("challenge-level-9"), &outside.to_wire());
            let mut args = files.issue_args();
            args.challenge_file = Some(files.path("challenge-level-9"));
            assert_eq!(
                run_issue(&args, Locale::En).unwrap_err().exit_code(),
                EXIT_REFUSED_TICKET_SCOPE
            );

            // Нет основания.
            let mut args = files.issue_args();
            args.reason = "  ".to_owned();
            assert_eq!(
                run_issue(&args, Locale::En).unwrap_err().exit_code(),
                EXIT_REFUSED_GROUNDS
            );

            // Доверие: ключ оператора не тот, что в билете.
            let mut args = files.issue_args();
            write_owner_only(
                &files.path("foreign.key"),
                &fixtures::pkcs8_of(fixtures::DEVICE_SEED),
            );
            args.key.soft_key = Some(files.path("foreign.key"));
            assert_eq!(
                run_issue(&args, Locale::En).unwrap_err().exit_code(),
                EXIT_REFUSED_TRUST
            );

            // Сбой стенда: запись устройства — не запись устройства. Ни один
            // вердикт этот код не занимает.
            write(&files.path("record"), "not a device record");
            let broken = run_issue(&files.issue_args(), Locale::En).unwrap_err();
            assert_eq!(broken.exit_code(), EXIT_TOOL_FAILURE);
            assert_eq!(
                broken.refusal_group(),
                Some(crate::codes::RefusalGroup::Environment)
            );
        }

        #[test]
        fn an_issuance_writes_a_receipt_that_reads_back() {
            let files = Files::new();
            run_issue(&files.issue_args(), Locale::En).unwrap();

            let receipts =
                store::read_directory(&files.path("receipts"), &FleetParams::defaults()).unwrap();
            let stored = receipts.first().unwrap();
            assert_eq!(stored.receipt.reason(), "work order 42");
            assert_eq!(stored.annex.server_id(), "op-42");
        }

        #[test]
        fn grounds_of_whitespace_alone_issue_nothing() {
            let files = Files::new();
            let mut args = files.issue_args();
            args.reason = "   ".to_owned();

            assert!(matches!(
                run_issue(&args, Locale::En),
                Err(CliError::Codes { .. })
            ));
            assert!(!files.path("receipts").exists());
        }

        #[test]
        fn an_organisation_no_anchor_names_is_refused_before_anything_is_read() {
            let files = Files::new();
            let mut args = files.issue_args();
            args.anchor_organisations = Vec::new();

            assert!(matches!(
                run_issue(&args, Locale::En),
                Err(CliError::Usage(_))
            ));
        }

        #[test]
        fn a_receipt_verifies_against_the_ticket_it_was_issued_under() {
            let files = Files::new();
            run_issue(&files.issue_args(), Locale::En).unwrap();
            let receipts =
                store::read_directory(&files.path("receipts"), &FleetParams::defaults()).unwrap();
            let path = receipts.first().unwrap().path.clone();

            let args = ReceiptVerifyArgs {
                fleet: defaults(),
                receipt: path.clone(),
                ticket: Some(files.path("ticket")),
            };
            run_receipt_verify(&args, Locale::En).unwrap();

            // A receipt whose file was renamed no longer binds to the ticket.
            let renamed = files.path("receipts").join("renamed.receipt");
            fs::rename(&path, &renamed).unwrap();
            let args = ReceiptVerifyArgs {
                fleet: defaults(),
                receipt: renamed,
                ticket: Some(files.path("ticket")),
            };
            assert!(matches!(
                run_receipt_verify(&args, Locale::En),
                Err(CliError::Codes { .. })
            ));
        }

        #[test]
        fn a_ticket_is_shown_verified_and_unverified() {
            let files = Files::new();
            let verified = TicketShowArgs {
                ticket: files.path("ticket"),
                anchor_ticket_authority: Some(files.path("authority.spki")),
                now: Some(fixtures::NOW.get()),
            };
            run_ticket_show(&verified, Locale::En).unwrap();

            let unverified = TicketShowArgs {
                ticket: files.path("ticket"),
                anchor_ticket_authority: None,
                now: Some(fixtures::NOW.get()),
            };
            run_ticket_show(&unverified, Locale::En).unwrap();

            // The term is judged against the anchor, so an expired ticket is a
            // refusal rather than a printed document.
            let expired = TicketShowArgs {
                ticket: files.path("ticket"),
                anchor_ticket_authority: Some(files.path("authority.spki")),
                now: Some(fixtures::TICKET_NOT_AFTER + 1),
            };
            assert!(matches!(
                run_ticket_show(&expired, Locale::En),
                Err(CliError::Codes { .. })
            ));
        }

        #[test]
        fn a_reconciliation_without_journals_runs_and_is_marked_incomplete() {
            let files = Files::new();
            run_issue(&files.issue_args(), Locale::En).unwrap();

            let args = ReconcileArgs {
                fleet: defaults(),
                receipts: files.path("receipts"),
                device_journals: Vec::new(),
            };
            run_reconcile(&args, Locale::En).unwrap();

            // With the device side present, the receipt of that issuance pairs.
            // The journal is a real chain, in the form the device writes: a
            // fixture in the tracing form would keep this test green even if
            // the reader could not read a device journal at all.
            let device = files
                .world
                .challenge
                .challenge()
                .device_number()
                .significant()
                .to_owned();
            fs::write(
                files.path("device.ndjson"),
                device_chain_line(files.world.challenge.challenge()),
            )
            .unwrap();
            let args = ReconcileArgs {
                fleet: defaults(),
                receipts: files.path("receipts"),
                device_journals: vec![format!(
                    "{device}={}",
                    files.path("device.ndjson").display()
                )],
            };
            run_reconcile(&args, Locale::En).unwrap();
        }
    }
}

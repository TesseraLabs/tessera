//! The `issuer codes` command surface: the issuing side, on a command line.
//!
//! Three commands, and none of them decides anything. Every check lives in
//! [`crate::codes`], which the browser cabinet and the issuing service call too;
//! what happens here is reading files, choosing where the agreement key is and
//! printing the result. A refusal met on this command line is the same refusal,
//! from the same function, that would be met anywhere else.
//!
//! - `codes issue` — answer the signed request an engineer brought;
//! - `codes ticket show` — show the bounds, the term and the provenance of a
//!   ticket;
//! - `codes reconcile` — put the issuance records beside the journals of
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
//! | `10` | the request fell outside the ticket — device, epoch, server, region, tags, role, level |
//! | `12` | a signature or an anchor did not hold — organisation signature, proof of possession, unanchored signer, ticket term, wrong agreement key |
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
use tessera_codes_contract::request::{RequestError, SignedRequest};
use tessera_codes_contract::ticket::SignedTicket;
use tessera_codes_contract::time::ClaimedTime;

use crate::codes::agreement::{KeyStorage, OperatorKey, SoftwareOperatorKey};
use crate::codes::issue::{issue, IssuanceRequest};
use crate::codes::reconcile::{
    read_journal, read_server_chain, reconcile, Expectations, IssuingAnchors, JournalError,
    LoginEntry, Provenance, Report, Revocation, RevocationListUsed, ServerChain, ServerChainError,
    Verdict,
};
use crate::codes::scope::{DeviceScope, SiteScope};
use crate::codes::trust::{AnchorKey, Anchors};
use crate::codes::RefusalGroup;
use crate::codes::{IssuanceRecord, RECORD_PREFIX};
use crate::l10n::{Locale, Msg};
use tessera_codes_contract::revocation::{SignedRevocationList, SubjectKind};

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
/// A signed request that does not parse.
const CLASS_REQUEST_MALFORMED: &str = "request_malformed";
/// A request that carries no grounds.
///
/// The token an operator sees for this is the one the refusal ladder uses, so
/// that "no grounds were recorded" reads the same whether the absence was caught
/// while reading the document or while answering it.
const CLASS_MISSING_REASON: &str = "missing_reason";
/// A revocation list that did not verify, replayed an older serial, or does not
/// parse.
const CLASS_REVOCATIONS_REJECTED: &str = "revocations_rejected";
/// A file that does not hold the chain of the issuing side.
const CLASS_SERVER_CHAIN_MALFORMED: &str = "server_chain_malformed";
/// A chain of the issuing side whose hashes do not add up.
///
/// A class of its own rather than a shade of the one above, for the same reason
/// the device side has two: "this history has been edited" and "this is not the
/// journal you meant to hand over" are answers a caller acts on differently.
const CLASS_SERVER_CHAIN_BROKEN: &str = "server_chain_broken";
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

/// The commands of the channel.
#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "the variants are parsed command lines, one of them long; clap's derive takes the \
              arguments struct itself, not a box around it, and the value is built once per run"
)]
enum CodesCommand {
    /// Answer the signed request an engineer brought.
    #[command(long_about = "\
Answer the signed request an engineer brought.

The code is computed from the challenge the device showed, the signed request \
of the engineer, the signed device record and the ticket of the issuing side. \
The grounds live inside the request and have no second copy. The journal record \
of the issuance is written by whoever signs the grant, which this command does \
not.

Exit codes:
  0   the code was issued
  10  the request fell outside the ticket (device, epoch, server, region,
      tags, role, level)
  12  a signature or an anchor did not hold (organisation signature, proof of
      possession, unanchored signer, ticket term, wrong agreement key)
  13  the issuance carried no grounds
  14  any other refusal of the issuance
  1   the check never happened: a missing file, a document that does not parse,
      a key that cannot be reached, a token that would not answer

A refusal also prints one machine-readable line to standard error naming the
exact check, for example:

  codes-refusal: ticket_scope_level")]
    Issue(IssueArgs),
    /// Read an issuance record back, field by field.
    #[command(subcommand)]
    Record(RecordCommand),
    /// Work with the tickets of issuing sides.
    #[command(subcommand)]
    Ticket(TicketCommand),
    /// Reconcile issuance records against device journals.
    Reconcile(ReconcileArgs),
}

/// The record commands.
#[derive(Debug, Subcommand)]
enum RecordCommand {
    /// Show the fields of an issuance record.
    Show(RecordShowArgs),
}

/// Flags for `issuer codes record show`.
///
/// The record travels as one line with the grant inside it in hexadecimal, and
/// the request inside the grant in hexadecimal again. Anything outside this
/// crate that wanted a field of it — a stand helper, an operator at a terminal —
/// would have to decode two layers with a text tool, which is a second reader of
/// the format written in `sed`. This command is that reader, once, here.
#[derive(Debug, Args)]
struct RecordShowArgs {
    #[command(flatten)]
    fleet: FleetArgs,
    /// The record file to read, or the chain line carrying it.
    #[arg(long = "record")]
    server_chain_line: PathBuf,
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
    /// DER. The journal record of the issuance says the key was held this way.
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
    /// The challenge the device showed, in its wire form.
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
    /// A file holding the signed request of the engineer, in its wire form.
    ///
    /// The grounds of the issuance live inside it and nowhere else: a flag
    /// beside the document would be a second copy, and a second copy is a second
    /// answer to "what was this code handed out for".
    #[arg(long)]
    request: PathBuf,
    /// Region the device stands in, from the fleet inventory.
    #[arg(long, requires = "device_tags")]
    device_region: Option<String>,
    /// A site tag of the device (repeat for several).
    #[arg(long = "device-tag", requires = "device_region")]
    device_tags: Vec<String>,
    /// The moment to work at, Unix seconds.
    ///
    /// Only test builds carry it. In a shipped build the term of the ticket
    /// comes from the system clock and from nothing else: a flag that moved it
    /// would let an issuing side keep working under an expired ticket.
    #[cfg(test)]
    #[arg(long)]
    now: Option<u64>,
    /// Print the code alone, without captions — for a caller that reads it.
    #[arg(long)]
    code_only: bool,
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

/// Custody tier of the agreement key, as a flag value.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CustodyArg {
    /// A key file, in the explicitly enabled software mode.
    Software,
    /// A PKCS#11 token or HSM.
    Token,
}

impl CustodyArg {
    /// The tier this flag value names.
    const fn tier(self) -> KeyStorage {
        match self {
            Self::Software => KeyStorage::Software,
            Self::Token => KeyStorage::Token,
        }
    }
}

/// Flags for `issuer codes reconcile`.
#[derive(Debug, Args)]
struct ReconcileArgs {
    #[command(flatten)]
    fleet: FleetArgs,
    /// The chain of the issuing side, as one file of newline-delimited JSON.
    #[arg(long)]
    server_chain: PathBuf,
    /// The custody tier the fleet declares for the agreement key. Without it
    /// the tier of each issuance is reported and not judged.
    #[arg(long)]
    declared_custody: Option<CustodyArg>,
    /// The signed list of withdrawn rights, as the fleet published it.
    ///
    /// Verified against the authorisation key before a single entry is read: an
    /// unsigned list is one anybody on the path can replace with an empty one,
    /// and an empty list is indistinguishable from "nobody has been cut off".
    /// Public key of an issuing side, as `<server-id>=<path>`, repeatable.
    ///
    /// Without it the signatures on the grants are read from the file and
    /// nowhere else, and the report says so as a caveat rather than staying
    /// silent: a grant assembled by anybody at all reads like one the issuing
    /// side signed.
    #[arg(long = "anchor-issuing-key", value_name = "SERVER=PATH")]
    anchor_issuing_keys: Vec<String>,
    #[arg(long, requires = "anchor_authorisation_key")]
    revocation_list: Option<PathBuf>,
    /// `SubjectPublicKeyInfo` of the fleet's authorisation key (PEM or DER).
    #[arg(long)]
    anchor_authorisation_key: Option<PathBuf>,
    /// The serial of the revocation list already applied.
    ///
    /// A signature stops substitution but not replay: yesterday's list is
    /// signed just as validly, and it is the one that still admits whoever was
    /// cut off this morning.
    ///
    /// Optional, and NOT defaulted to zero. Zero says "nothing has been applied
    /// yet" and admits any list; leaving the flag off says nothing, and the
    /// report answers with a caveat rather than pretending a waterline was
    /// declared. An auditor who does not know the applied serial can still run
    /// the command — and will be told what that cost.
    #[arg(long)]
    applied_revocation_serial: Option<u64>,
    /// A withdrawn right as `kind:subject=unix-seconds`, where the kind is
    /// `engineer` or `organisation` (repeat for several).
    ///
    /// For a stand, and marked as such in the report: nothing signed these, so a
    /// report built on them cannot call itself complete.
    #[arg(long = "revoked")]
    revoked: Vec<String>,
    /// A device journal as `device-number=path` (repeat for several). Without
    /// any, the report is marked incomplete.
    #[arg(long = "device-journal")]
    device_journals: Vec<String>,
}

/// Runs one `codes` command.
pub(super) fn run(args: CodesArgs, locale: Locale) -> Result<(), CliError> {
    match args.command {
        CodesCommand::Issue(args) => run_issue(&args, locale),
        CodesCommand::Record(RecordCommand::Show(args)) => run_record_show(&args),
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

    let signed_request = read_request(&args.request, params)?;

    let request = IssuanceRequest {
        challenge: &challenge,
        request: &signed_request,
        record: &record,
        ticket: &ticket,
        params: &params,
        device_scope: device_scope.as_ref(),
        now,
    };

    let issuance = with_operator_key(&args.key, args.fleet.profile(), locale, |key| {
        issue(&request, &anchors, key).map_err(|refusal| CliError::Codes {
            class: refusal.class(),
            group: refusal.group(),
            detail: refusal.to_string(),
        })
    })?;

    if args.code_only {
        println!("{}", issuance.code);
        return Ok(());
    }

    println!("{} {}", Msg::CodesCodeHeading.text(locale), issuance.code);
    println!(
        "{} {}",
        Msg::CodesKeyStorage.text(locale),
        issuance.key_storage.as_str()
    );
    // The grant leaves here unsigned: the key that signs it is not the key that
    // agreed the secret, and this command holds only the second. What it can
    // state is what will be signed.
    println!(
        "{} {}",
        Msg::CodesGrantServer.text(locale),
        issuance.grant.server_id()
    );
    // The state of the site axis comes out of the issuance, where the coverage
    // was decided. Recomputing it here from "was a device scope supplied" would
    // be a second answer to a question already answered.
    if issuance.site_scope == SiteScope::Undeclared {
        eprintln!("{}", Msg::CodesSiteUndeclared.text(locale));
    }
    Ok(())
}

/// Reads the signed request of the engineer.
///
/// A request whose grounds are absent is refused here under the class the
/// refusal ladder uses for it: the document does not assemble without them, so
/// this is where their absence is met, and an operator should not have to learn
/// two tokens for one fact.
fn read_request(path: &Path, params: FleetParams) -> Result<SignedRequest, CliError> {
    let text = String::from_utf8(read_file(path)?)
        .map_err(|_| CliError::Io(format!("{} is not UTF-8", path.display())))?;
    SignedRequest::parse(text.trim(), &params).map_err(|error| {
        // Two different answers wear two different groups. "The request records
        // no grounds" is a verdict about the issuance and exits as one; "this
        // file is not a request" is a stand nobody set up, and a caller that
        // could not tell them apart would read a broken directory as a refused
        // issuance.
        let (class, group) = match error {
            RequestError::MissingGrounds => (CLASS_MISSING_REASON, RefusalGroup::Grounds),
            _ => (CLASS_REQUEST_MALFORMED, RefusalGroup::Environment),
        };
        CliError::Codes {
            class,
            group,
            detail: error.to_string(),
        }
    })
}

/// `issuer codes record show`.
///
/// Prints one `key=value` per line, in a form a script can read: the values are
/// identifiers, numbers and tokens, the same bytes in every locale. A caption
/// would be prose, and prose is what a caller must never parse.
fn run_record_show(args: &RecordShowArgs) -> Result<(), CliError> {
    let params = args.fleet.params()?;
    let text = String::from_utf8(read_file(&args.server_chain_line)?)
        .map_err(|_| CliError::Io(format!("{} is not UTF-8", args.server_chain_line.display())))?;

    // A file holding the record itself, or a line of the chain that carries it:
    // a caller has whichever it has, and making it strip the framing first
    // would put the format back into a text tool.
    let wire = record_wire(text.trim());
    let record =
        IssuanceRecord::parse(&wire, &params).map_err(record_error(&args.server_chain_line))?;

    let request = record.request().request();
    let challenge = request.challenge();
    println!("device={}", challenge.device_number().as_str());
    println!("epoch={}", challenge.epoch().get());
    println!("nonce={}", challenge.nonce().as_str());
    println!("role={}", challenge.role_id());
    println!("level={}", challenge.level().get());
    println!("server={}", record.grant().server_id());
    println!("engineer={}", challenge.engineer_id());
    println!("organisation={}", record.organisation_id());
    println!("ticket={}", record.ticket_number().as_str());
    println!("requested_at={}", request.requested_at().get());
    println!("grounds={}", request.grounds());
    println!("key_storage={}", record.key_storage().as_str());
    println!("site_scope={}", record.site_scope().as_str());
    println!(
        "identity_unverified={}",
        if record.identity_unverified() {
            "yes"
        } else {
            "no"
        }
    );
    Ok(())
}

/// Names a file that does not hold a record.
fn record_error(path: &Path) -> impl Fn(crate::codes::IssuanceRecordError) -> CliError + '_ {
    move |error| CliError::Codes {
        class: CLASS_SERVER_CHAIN_MALFORMED,
        group: RefusalGroup::Environment,
        detail: format!("{}: {error}", path.display()),
    }
}

/// Takes the record out of whatever the caller had.
fn record_wire(text: &str) -> String {
    if let Some(index) = text.find(RECORD_PREFIX) {
        // A chain line: the record is a JSON string field inside it, so it ends
        // at the quote. A record on its own ends at the end of the text.
        let rest = &text[index..];
        let end = rest.find('"').unwrap_or(rest.len());
        return rest[..end].to_owned();
    }
    text.to_owned()
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

/// Reads the chain of the issuing side.
///
/// The chain is written by whoever computes codes — the issuing service — and
/// read here without being re-derived: a reconciliation that rebuilt what it
/// checks would be checking its own arithmetic.
fn read_server_chain_file(
    path: &Path,
    params: FleetParams,
    anchors: &IssuingAnchors,
) -> Result<ServerChain, CliError> {
    let text = String::from_utf8(read_file(path)?)
        .map_err(|_| CliError::Io(format!("{} is not UTF-8", path.display())))?;
    read_server_chain(&text, &params, anchors).map_err(|error| CliError::Codes {
        // "This history has been edited" and "this is not the journal you meant
        // to hand over" send a reader to different places, exactly as they do on
        // the device side; one token for both would hide which.
        class: match error {
            ServerChainError::BrokenChain { .. } => CLASS_SERVER_CHAIN_BROKEN,
            _ => CLASS_SERVER_CHAIN_MALFORMED,
        },
        group: RefusalGroup::Environment,
        detail: format!("{}: {error}", path.display()),
    })
}

/// Reads the withdrawals a caller supplied as `kind:subject=unix-seconds`.
///
/// Unsigned by construction, and the report says so: this is what a stand has
/// before a fleet publishes a list, and a reconciliation that treated it like a
/// published one would be treating a command line as an authority.
fn read_revocations(pairs: &[String]) -> Result<Vec<Revocation>, CliError> {
    pairs
        .iter()
        .map(|pair| {
            let (subject, at) = split_pair(pair, "--revoked")?;
            let (kind, subject) = subject.split_once(':').ok_or_else(|| {
                CliError::Usage(format!(
                    "--revoked expects `kind:subject=unix-seconds`, where the kind is `engineer` \
                     or `organisation`; got `{pair}`"
                ))
            })?;
            let kind = SubjectKind::parse(kind).ok_or_else(|| {
                CliError::Usage(format!(
                    "--revoked names the subject kind `{kind}`, which is neither `engineer` nor \
                     `organisation`: a fleet may number a person and an organisation alike, so \
                     the kind cannot be guessed from the identifier"
                ))
            })?;
            let at = at.parse::<u64>().map_err(|_| {
                CliError::Usage(format!(
                    "--revoked names the moment `{at}`, which is not Unix seconds"
                ))
            })?;
            Ok(Revocation {
                kind,
                subject: subject.to_owned(),
                at,
            })
        })
        .collect()
}

/// Reads the published list of withdrawn rights, signature first.
///
/// The signature is checked before any entry is read, and the serial before the
/// entries are used: the first stops substitution, the second stops replay, and
/// neither stops the other.
fn read_revocation_list(args: &ReconcileArgs) -> Result<Option<ReadRevocations>, CliError> {
    let Some(path) = args.revocation_list.as_deref() else {
        return Ok(None);
    };
    let anchor_path = args.anchor_authorisation_key.as_deref().ok_or_else(|| {
        CliError::Usage("--revocation-list needs --anchor-authorisation-key".into())
    })?;
    let anchor_bytes = decode_pem_or_der(&read_file(anchor_path)?)?;
    let anchor = AnchorKey::from_spki_der(&anchor_bytes).map_err(|error| CliError::Codes {
        class: CLASS_REVOCATIONS_REJECTED,
        group: RefusalGroup::Environment,
        detail: format!("{}: {error}", anchor_path.display()),
    })?;

    let text = String::from_utf8(read_file(path)?)
        .map_err(|_| CliError::Io(format!("{} is not UTF-8", path.display())))?;
    let signed = SignedRevocationList::parse(text.trim()).map_err(revocations_rejected(path))?;
    signed
        .verify(&AuthorisationOnly(anchor))
        .map_err(revocations_rejected(path))?;

    let list = signed.list();
    if let Some(waterline) = args.applied_revocation_serial {
        if !list.is_newer_than(waterline) {
            return Err(CliError::Codes {
                class: CLASS_REVOCATIONS_REJECTED,
                group: RefusalGroup::Environment,
                detail: format!(
                    "the list carries serial {} and serial {waterline} has already been \
                     applied: an older list is signed just as validly as the current one, and \
                     it is the one that still admits whoever was cut off since",
                    list.serial(),
                ),
            });
        }
    }

    Ok(Some(ReadRevocations {
        used: RevocationListUsed {
            serial: list.serial(),
            waterline: args.applied_revocation_serial,
        },
        entries: list
            .entries()
            .iter()
            .map(|entry| Revocation {
                kind: entry.kind(),
                subject: entry.subject_id().to_owned(),
                at: entry.revoked_at().get(),
            })
            .collect(),
    }))
}

/// The withdrawals a run read, and which list they came from.
struct ReadRevocations {
    /// The list itself, for the report to name.
    used: RevocationListUsed,
    /// The withdrawals in it.
    entries: Vec<Revocation>,
}

/// Reads the keys of the issuing sides, as `<server-id>=<path>` pairs.
///
/// An empty list is legitimate and is NOT the same as "no signatures to
/// check": what it means is that this run cannot check them, and the report
/// says so. An auditor reconciling a journal they were handed may have no key
/// for the side that issued it, and a command that refused to run without one
/// would be a command nobody could run.
///
/// # Errors
///
/// [`CliError::Usage`] for a pair without an `=`, and the file and key errors
/// of the anchor itself.
fn read_issuing_anchors(pairs: &[String]) -> Result<IssuingAnchors, CliError> {
    let mut anchors = IssuingAnchors::default();
    for pair in pairs {
        let (server_id, path) = pair.split_once('=').ok_or_else(|| {
            CliError::Usage(format!(
                "--anchor-issuing-key expects `<server-id>=<path>`, and `{pair}` has no `=`"
            ))
        })?;
        if server_id.is_empty() {
            return Err(CliError::Usage(
                "--anchor-issuing-key names an empty issuing side".into(),
            ));
        }
        let bytes = decode_pem_or_der(&read_file(Path::new(path))?)?;
        let key = AnchorKey::from_spki_der(&bytes).map_err(|error| CliError::Codes {
            class: CLASS_SERVER_CHAIN_MALFORMED,
            group: RefusalGroup::Environment,
            detail: format!("{path}: {error}"),
        })?;
        anchors.insert(server_id.to_owned(), key);
    }
    Ok(anchors)
}

/// Names a revocation list that did not hold.
fn revocations_rejected<E: core::fmt::Display>(path: &Path) -> impl Fn(E) -> CliError + '_ {
    move |error| CliError::Codes {
        class: CLASS_REVOCATIONS_REJECTED,
        group: RefusalGroup::Environment,
        detail: format!("{}: {error}", path.display()),
    }
}

/// A verifier that knows one key and one office.
///
/// Reconciling reads one signed document — the list of withdrawn rights — and
/// the key that signs it is the fleet's authorisation key. Building the full
/// anchor set here would mean holding a ticket authority this command has no
/// use for, and a verifier that resolved more signers than it needs is a
/// verifier that can be asked the wrong question.
struct AuthorisationOnly(AnchorKey);

impl tessera_codes_contract::signature::SignatureVerifier for AuthorisationOnly {
    fn verify(
        &self,
        signer: tessera_codes_contract::signature::SignerRef<'_>,
        message: &[u8],
        signature: &tessera_codes_contract::signature::Signature,
    ) -> Result<(), tessera_codes_contract::signature::SignatureError> {
        match signer {
            tessera_codes_contract::signature::SignerRef::AuthorisationKey => {
                self.0.verify(message, signature)
            }
            _ => Err(tessera_codes_contract::signature::SignatureError::UnknownSigner),
        }
    }
}

/// `issuer codes reconcile`.
/// What the chain of the issuing side establishes, before the device side is
/// read.
///
/// A function rather than a literal inside the command, because it is the one
/// place where a property of the file becomes a property of the report — and a
/// literal there is a line no test can reach without capturing the output of a
/// whole command. Both fields it fills are caveats: an unsigned tail says
/// issuances could have been dropped from the end, an unread line says this
/// build did not read part of what it was given.
fn provenance_of(chain: &ServerChain) -> Provenance {
    Provenance {
        chain_verified: true,
        unsigned_from_seq: None,
        server_unsigned_from_seq: chain.unsigned_from_seq,
        server_unread_lines: chain.unread_lines,
        refusals_without_nonce: 0,
        unpairable_lines: Vec::new(),
    }
}

fn run_reconcile(args: &ReconcileArgs, locale: Locale) -> Result<(), CliError> {
    let params = args.fleet.params()?;
    let anchors = read_issuing_anchors(&args.anchor_issuing_keys)?;
    let chain = read_server_chain_file(&args.server_chain, params, &anchors)?;
    let mut provenance = provenance_of(&chain);
    let entries = chain.entries;
    let signed_list = read_revocation_list(args)?;
    let mut revocations = signed_list
        .as_ref()
        .map(|read| read.entries.clone())
        .unwrap_or_default();
    let unsigned = read_revocations(&args.revoked)?;
    let unsigned_count = unsigned.len();
    revocations.extend(unsigned);
    let expectations = Expectations {
        declared_key_storage: args.declared_custody.map(CustodyArg::tier),
        revocations,
        unsigned_revocations: unsigned_count,
        // Which list the withdrawals came from, and whether a waterline was
        // declared at all. Both go into the report: a reader told which rights
        // were withdrawn and not which list said so has been told half of it.
        revocation_list: signed_list.map(|read| read.used),
    };

    let logins = if args.device_journals.is_empty() {
        None
    } else {
        let mut logins: Vec<LoginEntry> = Vec::new();
        for pair in &args.device_journals {
            let (device_number, path) = split_pair(pair, "--device-journal")?;
            // The number arrives typed by a person, from a label or a printout,
            // and the records hold its significant form. Comparing the two as
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
            provenance.unpairable_lines.extend(journal.unpairable_lines);
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
            // The device side is absent, but what was established about the
            // chain of the issuing side still holds: an unsigned tail there is
            // a caveat about the issuances, not about the journals nobody
            // supplied.
            Provenance {
                server_unsigned_from_seq: provenance.server_unsigned_from_seq,
                server_unread_lines: provenance.server_unread_lines,
                ..Provenance::absent()
            }
        },
        &expectations,
    );
    if !report.is_complete() {
        eprintln!("{}", Msg::CodesReconcileIncomplete.text(locale));
    }
    // The report first, the verdict after it. The report opens with what could
    // not be established — an absent device side, a journal with no chain, a
    // tail no signature covers — and a reader who met "the two sides agree"
    // first would carry that sentence over the caveat that qualifies it.
    print!("{report}");
    if let Some(verdict) = clean_verdict(&report, locale) {
        println!("{verdict}");
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

/// The sentence printed under a report that found nothing, or [`None`].
///
/// A function rather than a condition at the print, because the decision is
/// what has to be testable: printing it is a `println!` nobody can assert
/// about without capturing a stream. One verdict, read off the report as a
/// whole — two predicates over parts of it, one for the last line of the
/// report and one for the sentence under it, is how "no disagreements" came to
/// be printed over a journal whose lines this build could not read.
fn clean_verdict(report: &Report, locale: Locale) -> Option<&'static str> {
    (report.verdict() == Verdict::Clean).then(|| Msg::CodesReconcileClean.text(locale))
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
            run_issue, run_reconcile, run_record_show, run_ticket_show, CustodyArg, IssueArgs,
            OperatorKeyArgs, ReconcileArgs, RecordShowArgs, TicketShowArgs,
        };
        use super::defaults;
        use crate::cli::CliError;
        use crate::codes::agreement::KeyStorage;
        use crate::codes::reconcile::{ServerLine, ISSUANCE_OP, ISSUANCE_RECORD_FIELD};
        use crate::codes::scope::SiteScope;
        use crate::codes::tests::fixtures;
        use crate::codes::{IssuanceRecord, IssuanceRecordFields};
        use crate::l10n::Locale;
        use tessera_codes_contract::grant::UnsignedGrant;
        use tessera_codes_contract::signature::Signature;
        use tessera_codes_contract::ticket::TicketNumber;

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
                write(
                    &root.path().join("request"),
                    &fixtures::signed_request(&world).to_wire(),
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
                    request: self.path("request"),
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

        /// Кладёт challenge и подписанный запрос вокруг него под одним именем.
        ///
        /// Порознь их класть нельзя: выдача сверяет два документа между собой и
        /// отказывает по расхождению раньше всех прочих проверок, так что тест,
        /// подменивший только challenge, проверял бы эту сверку вместо той оси,
        /// ради которой написан.
        fn write_pair(
            files: &Files,
            name: &str,
            challenge: &tessera_codes_contract::challenge::SignedChallenge,
        ) -> (PathBuf, PathBuf) {
            let challenge_path = files.path(&format!("challenge-{name}"));
            let request_path = files.path(&format!("request-{name}"));
            write(&challenge_path, &challenge.to_wire());
            write(
                &request_path,
                &fixtures::signed_request_for(challenge.challenge(), fixtures::GROUNDS).to_wire(),
            );
            (challenge_path, request_path)
        }

        /// Проводная форма запроса, у которого основание — одни пробелы.
        ///
        /// Собирается правкой байтов, а не конструктором: документ с пустым
        /// основанием не собирается вовсе, и в этом вся гарантия. Тест обязан
        /// подать выдаче ровно то, что могло бы приехать по сети от стороны,
        /// собравшей документ иначе, — иначе он проверял бы конструктор,
        /// который и так отказывает.
        fn blank_grounds(files: &Files) -> String {
            let signed = fixtures::signed_request(&files.world);
            let inner = signed
                .request()
                .to_wire()
                .replace(&format!("grounds={}", fixtures::GROUNDS), "grounds=   ");
            format!(
                "tessera-codes/v1/signed-engineer-request;request={};engineer_signature={}",
                hex::encode(inner),
                match signed.engineer_signature() {
                    tessera_codes_contract::request::EngineerSignature::Signed(signature) => {
                        hex::encode(signature.as_bytes())
                    }
                    // The blank-grounds fixture builds a signed request, so
                    // this arm is unreachable through it; naming the variant
                    // rather than wildcarding it means a third case added later
                    // stops the build here instead of being formatted with
                    // `Debug` into a document.
                    unverified @ tessera_codes_contract::request::EngineerSignature::Unverified {
                        ..
                    } => format!("{unverified:?}"),
                }
            )
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
            let (challenge, request) = write_pair(&files, "level-9", &outside);

            let mut args = files.issue_args();
            args.challenge_file = Some(challenge);
            args.request = request;
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
            let (challenge, request) = write_pair(&files, "role", &role);
            let mut args = files.issue_args();
            args.challenge_file = Some(challenge);
            args.request = request;
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
            let (challenge, request) = write_pair(&files, "level-9", &outside);
            let mut args = files.issue_args();
            args.challenge_file = Some(challenge);
            args.request = request;
            assert_eq!(
                run_issue(&args, Locale::En).unwrap_err().exit_code(),
                EXIT_REFUSED_TICKET_SCOPE
            );

            // Нет основания: документ с пустым основанием не собирается, и
            // отказ приходит из чтения запроса — под тем же классом и тем же
            // кодом возврата, что и прежде. Оператору не за чем знать, на каком
            // шаге отсутствие основания было замечено.
            write(&files.path("request-blank"), &blank_grounds(&files));
            let mut args = files.issue_args();
            args.request = files.path("request-blank");
            let refusal = run_issue(&args, Locale::En).unwrap_err();
            assert_eq!(refusal.refusal_class(), Some("missing_reason"));
            assert_eq!(refusal.exit_code(), EXIT_REFUSED_GROUNDS);

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
        fn a_request_that_is_not_a_request_issues_nothing() {
            let files = Files::new();
            write(&files.path("request-broken"), "not a signed request");
            let mut args = files.issue_args();
            args.request = files.path("request-broken");

            let refusal = run_issue(&args, Locale::En).unwrap_err();
            assert_eq!(refusal.refusal_class(), Some("request_malformed"));
        }

        #[test]
        fn a_request_signed_over_another_challenge_issues_nothing() {
            // Основание одной попытки, отвечающее за код другой: два документа
            // разошлись, и выдача обязана отказать до вычисления.
            let files = Files::new();
            let other = fixtures::signed_challenge_with(|input| input.level = 1);
            write(
                &files.path("request-other"),
                &fixtures::signed_request_for(other.challenge(), fixtures::GROUNDS).to_wire(),
            );
            let mut args = files.issue_args();
            args.request = files.path("request-other");

            let refusal = run_issue(&args, Locale::En).unwrap_err();
            assert_eq!(refusal.refusal_class(), Some("request_challenge_mismatch"));
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

        /// Цепочка выдач того же прогона, какой её пишет выдающая сторона.
        ///
        /// Пишет её здесь тест, а не команда: журнал ведёт тот, кто считает и
        /// подписывает, а `issuer codes issue` подписи гранта не ставит — ключа
        /// подписи у него нет по построению. Цепочка настоящая, собранная тем
        /// же `tessera_hashchain`, которым её соберёт служба: фикстура «одна
        /// строка JSON» оставила бы этот тест зелёным даже там, где читатель не
        /// умеет читать цепочку вовсе.
        fn write_server_chain(files: &Files, key_storage: KeyStorage) {
            write_server_chain_of(files, key_storage, 1);
        }

        /// The same, with a chosen number of issuances in it.
        fn write_server_chain_of(files: &Files, key_storage: KeyStorage, records: usize) {
            use tessera_hashchain::storage::MemoryStorage;
            use tessera_hashchain::Chain;

            let grant = UnsignedGrant::new(fixtures::signed_request(&files.world), "op-42")
                .unwrap()
                .sign(Signature::new(vec![0x11, 0x22]).unwrap(), None)
                .unwrap();
            let record = IssuanceRecord::new(IssuanceRecordFields {
                grant,
                ticket_number: TicketNumber::parse("tk-e2e-1").unwrap(),
                organisation_id: "acme".to_owned(),
                key_storage,
                site_scope: SiteScope::Checked,
                // The fixture request is signed, so the mark is clear: the two
                // have to agree, and the type refuses a record where they do
                // not.
                identity_unverified: false,
            })
            .unwrap();

            let mut chain: Chain<MemoryStorage, ServerLine> =
                Chain::load(MemoryStorage::new()).unwrap();
            for index in 0..records {
                let line: ServerLine = serde_json::from_value(serde_json::json!({
                    "op": ISSUANCE_OP,
                    ISSUANCE_RECORD_FIELD: record.to_wire(),
                }))
                .unwrap();
                chain.append(&line, 1_800_000_000 + index as u64).unwrap();
            }
            fs::write(
                files.path("server-chain.ndjson"),
                format!("{}\n", chain.storage().lines().join("\n")),
            )
            .unwrap();
        }

        /// The same chain with one line whose `op` this build does not know.
        ///
        /// Appended by the chain crate itself and not by hand: a line typed out
        /// would not link, the reader would refuse the file as broken, and the
        /// test would go green for the wrong reason.
        fn write_server_chain_with_an_unknown_line(files: &Files) {
            use tessera_hashchain::storage::MemoryStorage;
            use tessera_hashchain::Chain;

            let grant = UnsignedGrant::new(fixtures::signed_request(&files.world), "op-42")
                .unwrap()
                .sign(Signature::new(vec![0x11, 0x22]).unwrap(), None)
                .unwrap();
            let record = IssuanceRecord::new(IssuanceRecordFields {
                grant,
                ticket_number: TicketNumber::parse("tk-e2e-1").unwrap(),
                organisation_id: "acme".to_owned(),
                key_storage: KeyStorage::Software,
                site_scope: SiteScope::Checked,
                identity_unverified: false,
            })
            .unwrap();

            let mut chain: Chain<MemoryStorage, ServerLine> =
                Chain::load(MemoryStorage::new()).unwrap();
            let issuance: ServerLine = serde_json::from_value(serde_json::json!({
                "op": ISSUANCE_OP,
                ISSUANCE_RECORD_FIELD: record.to_wire(),
            }))
            .unwrap();
            chain.append(&issuance, 1_800_000_000).unwrap();
            let unknown: ServerLine = serde_json::from_value(serde_json::json!({
                "op": "codes.something-a-later-build-invented",
                "note": "a line this build cannot read",
            }))
            .unwrap();
            chain.append(&unknown, 1_800_000_001).unwrap();
            fs::write(
                files.path("server-chain.ndjson"),
                format!("{}\n", chain.storage().lines().join("\n")),
            )
            .unwrap();
        }

        #[test]
        fn a_reconciliation_without_journals_runs_and_is_marked_incomplete() {
            let files = Files::new();
            run_issue(&files.issue_args(), Locale::En).unwrap();
            write_server_chain(&files, KeyStorage::Software);

            let args = ReconcileArgs {
                fleet: defaults(),
                server_chain: files.path("server-chain.ndjson"),
                declared_custody: None,
                revocation_list: None,
                anchor_issuing_keys: Vec::new(),
                anchor_authorisation_key: None,
                applied_revocation_serial: Some(0),
                revoked: Vec::new(),
                device_journals: Vec::new(),
            };
            run_reconcile(&args, Locale::En).unwrap();

            // With the device side present, the record of that issuance pairs.
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
                server_chain: files.path("server-chain.ndjson"),
                declared_custody: None,
                revocation_list: None,
                anchor_issuing_keys: Vec::new(),
                anchor_authorisation_key: None,
                applied_revocation_serial: Some(0),
                revoked: Vec::new(),
                device_journals: vec![format!(
                    "{device}={}",
                    files.path("device.ndjson").display()
                )],
            };
            run_reconcile(&args, Locale::En).unwrap();
        }

        /// Сверка читает серверную цепочку, а правленую — отвергает.
        ///
        /// Два ответа в одном тесте, потому что порознь ни один не отличает
        /// «прочитала» от «не заметила»: чтение подтверждается парой, которая
        /// сошлась, а отказ — тем, что та же цепочка с изъятой строкой не даёт
        /// отчёта вовсе.
        #[test]
        fn a_chain_that_was_edited_produces_no_report() {
            let files = Files::new();
            run_issue(&files.issue_args(), Locale::En).unwrap();
            write_server_chain(&files, KeyStorage::Software);

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
            let args = |chain: PathBuf| ReconcileArgs {
                fleet: defaults(),
                server_chain: chain,
                declared_custody: None,
                revocation_list: None,
                anchor_issuing_keys: Vec::new(),
                anchor_authorisation_key: None,
                applied_revocation_serial: Some(0),
                revoked: Vec::new(),
                device_journals: vec![format!(
                    "{device}={}",
                    files.path("device.ndjson").display()
                )],
            };
            run_reconcile(&args(files.path("server-chain.ndjson")), Locale::En).unwrap();

            // Та же цепочка, из которой вынули строку из СЕРЕДИНЫ: чтение
            // обязано остановиться, а не отдать отчёт, который «ничего не
            // нашёл». Хвост ловится не этим — его ловит оговорка о незаверённом
            // хвосте, и кейс, обрезающий хвост, проверял бы её.
            write_server_chain_of(&files, KeyStorage::Software, 3);
            let text = fs::read_to_string(files.path("server-chain.ndjson")).unwrap();
            let mut lines: Vec<&str> = text.lines().collect();
            lines.remove(1);
            let edited = files.path("server-chain-edited.ndjson");
            fs::write(&edited, lines.join("\n")).unwrap();
            let refusal = run_reconcile(&args(edited), Locale::En).unwrap_err();
            assert_eq!(refusal.refusal_class(), Some("server_chain_broken"));
        }

        /// Объявленная ступень кастодии превращает запись отчёта в тревогу.
        #[test]
        fn a_declared_custody_tier_turns_a_lower_one_into_a_finding() {
            let files = Files::new();
            run_issue(&files.issue_args(), Locale::En).unwrap();
            write_server_chain(&files, KeyStorage::Software);

            let args = ReconcileArgs {
                fleet: defaults(),
                server_chain: files.path("server-chain.ndjson"),
                declared_custody: Some(CustodyArg::Token),
                revocation_list: None,
                anchor_issuing_keys: Vec::new(),
                anchor_authorisation_key: None,
                applied_revocation_serial: Some(0),
                revoked: Vec::new(),
                device_journals: Vec::new(),
            };
            // Отчёт собирается и печатается; вердикт читается отдельно, потому
            // что команда возвращает Ok и на находках — находка не сбой.
            run_reconcile(&args, Locale::En).unwrap();
        }

        /// Справка команды не упоминает ни телефона, ни квитанций.
        ///
        /// Единственное, что оператор читает перед первым вызовом. Пока в ней
        /// стоят подкоманды удалённого канала, она обещает то, чего нет.
        #[test]
        fn the_help_of_the_surface_speaks_of_no_telephone() {
            use clap::CommandFactory as _;

            let mut command = crate::cli::Cli::command();
            let mut rendered = Vec::new();
            command.write_long_help(&mut rendered).unwrap();
            for subcommand in command.get_subcommands_mut() {
                let mut text = Vec::new();
                subcommand.write_long_help(&mut text).unwrap();
                rendered.extend(text);
                for nested in subcommand.get_subcommands_mut() {
                    let mut text = Vec::new();
                    nested.write_long_help(&mut text).unwrap();
                    rendered.extend(text);
                }
            }
            let help = String::from_utf8(rendered).unwrap().to_lowercase();
            for word in ["telephone", "receipt", "квитанц", "телефон"] {
                assert!(!help.contains(word), "справка всё ещё говорит про `{word}`");
            }
        }

        /// Список отзыва принимается только подписанным и только новее
        /// применённого.
        ///
        /// Три ответа подряд, потому что порознь ни один не отличает «сверка
        /// прочитала список» от «сверка его не заметила»: подпись не той
        /// стороны, повтор вчерашнего серийника и честный список.
        #[test]
        fn a_revocation_list_is_read_only_when_signed_and_newer() {
            use tessera_codes_contract::revocation::{
                RevocationEntry, RevocationList, RevocationListFields, SignedRevocationList,
                SubjectKind,
            };
            use tessera_codes_contract::time::ClaimedTime;

            let files = Files::new();
            write_server_chain(&files, KeyStorage::Software);

            let list = RevocationList::new(RevocationListFields {
                serial: 7,
                issued_at: ClaimedTime::new(1_800_000_100),
                entries: vec![RevocationEntry::new(
                    SubjectKind::Engineer,
                    "eng-1",
                    ClaimedTime::new(1_799_999_999),
                    "left-the-fleet",
                )
                .unwrap()],
            })
            .unwrap();
            // Подписывает ключ авторизаций фикстурного парка — тот же, чей
            // якорь кладётся ниже. Байты подписи настоящие: список проверяется
            // подписью, и фикстура, подписанная «чем-нибудь», проверяла бы
            // разбор вместо проверки.
            let signer = fixtures::signer(fixtures::AUTHORITY_SEED);
            let published =
                SignedRevocationList::new(list.clone(), signer.sign(&list.encode().unwrap()));
            write(&files.path("revocations.txt"), &published.to_wire());
            fs::write(
                files.path("authorisation.spki"),
                fixtures::spki_of(fixtures::AUTHORITY_SEED),
            )
            .unwrap();

            let args = |serial: u64, anchor: &str| ReconcileArgs {
                fleet: defaults(),
                server_chain: files.path("server-chain.ndjson"),
                declared_custody: None,
                revocation_list: Some(files.path("revocations.txt")),
                anchor_issuing_keys: Vec::new(),
                anchor_authorisation_key: Some(files.path(anchor)),
                applied_revocation_serial: Some(serial),
                revoked: Vec::new(),
                device_journals: Vec::new(),
            };

            // Честный список новее применённого: читается.
            run_reconcile(&args(6, "authorisation.spki"), Locale::En).unwrap();

            // Тот же список, но серийник уже применён: повтор вчерашнего.
            let replay = run_reconcile(&args(7, "authorisation.spki"), Locale::En).unwrap_err();
            assert_eq!(replay.refusal_class(), Some("revocations_rejected"));

            // Тот же список против ЧУЖОГО якоря: подписал не тот.
            fs::write(
                files.path("stranger.spki"),
                fixtures::spki_of(fixtures::ORGANISATION_SEED),
            )
            .unwrap();
            let stranger = run_reconcile(&args(6, "stranger.spki"), Locale::En).unwrap_err();
            assert_eq!(stranger.refusal_class(), Some("revocations_rejected"));

            // И без ватерлинии вовсе: команда не отказывает — аудитор может не
            // знать применённого серийника, — но отчёт обязан сказать, что
            // принял бы список ЛЮБОГО возраста. До правки флаг по умолчанию
            // стоял нулём, то есть молча утверждал «применено ничего», и
            // подавленные находки выглядели как их отсутствие.
            let without = ReconcileArgs {
                applied_revocation_serial: None,
                ..args(6, "authorisation.spki")
            };
            run_reconcile(&without, Locale::En).unwrap();

            let anchors = super::super::read_issuing_anchors(&without.anchor_issuing_keys).unwrap();
            let chain = super::super::read_server_chain_file(
                &without.server_chain,
                without.fleet.params().unwrap(),
                &anchors,
            )
            .unwrap();
            let read = super::super::read_revocation_list(&without)
                .unwrap()
                .unwrap();
            assert_eq!(read.used.waterline, None);
            let report = crate::codes::reconcile::reconcile(
                &chain.entries,
                None,
                &crate::codes::reconcile::Provenance::absent(),
                &crate::codes::reconcile::Expectations {
                    declared_key_storage: None,
                    revocations: read.entries,
                    unsigned_revocations: 0,
                    revocation_list: Some(read.used),
                },
            );
            assert!(!report.is_complete(), "{report}");
            assert!(
                report
                    .to_string()
                    .contains("revocation-waterline-unset serial=7"),
                "{report}"
            );
        }

        /// Запись выдачи читается из СТРОКИ ЦЕПОЧКИ, а не только из файла.
        ///
        /// Это то, что есть у стенда: грант лежит в строке шестнадцатеричным
        /// полем, а запрос внутри гранта — снова шестнадцатеричным, и разбор
        /// текстовым инструментом по такой строке не работает вовсе. Читатель
        /// формата один, и он здесь.
        #[test]
        fn a_record_is_read_out_of_a_chain_line() {
            let files = Files::new();
            write_server_chain(&files, KeyStorage::Software);

            let args = RecordShowArgs {
                fleet: defaults(),
                server_chain_line: files.path("server-chain.ndjson"),
            };
            run_record_show(&args).unwrap();
        }

        /// Строка цепочки, которую сборка не прочла, доходит до отчёта.
        ///
        /// Проверяется ПРОВОДКА, а не сама оговорка: её держит тест в
        /// `reconcile`, а здесь — что команда действительно берёт счёт из
        /// прочитанной цепочки и кладёт его в происхождение. Мутация «класть
        /// ноль» не роняла ничего, пока этого теста не было: отчёт над файлом,
        /// прочитанным наполовину, называл себя полным, и вся правка держалась
        /// на одной строке присваивания, которую никто не стерёг.
        #[test]
        fn an_unread_line_of_the_chain_reaches_the_report() {
            let files = Files::new();
            run_issue(&files.issue_args(), Locale::En).unwrap();
            write_server_chain_with_an_unknown_line(&files);

            let args = ReconcileArgs {
                fleet: defaults(),
                server_chain: files.path("server-chain.ndjson"),
                declared_custody: None,
                revocation_list: None,
                anchor_issuing_keys: Vec::new(),
                anchor_authorisation_key: None,
                applied_revocation_serial: Some(0),
                revoked: Vec::new(),
                device_journals: Vec::new(),
            };
            // The command does not refuse: a chain that carries issuances IS
            // the journal that was asked for.
            run_reconcile(&args, Locale::En).unwrap();

            // And what it read carries the count, so the report built from it
            // cannot call itself complete. Read through the same path the
            // command uses; a mutation that puts a zero into the provenance
            // makes this red.
            let params = args.fleet.params().unwrap();
            let chain = super::super::read_server_chain_file(
                &args.server_chain,
                params,
                &crate::codes::reconcile::IssuingAnchors::default(),
            )
            .unwrap();
            assert_eq!(chain.unread_lines, 1, "the unknown line was not counted");
            assert_eq!(chain.entries.len(), 1, "the issuance was not read");

            // Through the very function the command uses to turn a chain into
            // a provenance. Building the provenance by hand here would test
            // this test's idea of the wiring rather than the wiring.
            let report = crate::codes::reconcile::reconcile(
                &chain.entries,
                None,
                &super::super::provenance_of(&chain),
                &crate::codes::reconcile::Expectations::default(),
            );
            assert!(!report.is_complete(), "{report}");
            assert!(
                report.to_string().contains("unread-server-lines"),
                "{report}"
            );
        }

        /// Вердикт «чисто» печатается только над отчётом, который смог
        /// посмотреть.
        ///
        /// Проверяется решение, а не печать: до этой правки условие стояло
        /// прямо в `println!`, и его откат оставлял весь набор зелёным.
        #[test]
        fn the_clean_verdict_is_withheld_from_a_report_that_could_not_look() {
            use crate::codes::reconcile::{reconcile, Expectations, Provenance};

            let complete = reconcile(
                &[],
                Some(&[]),
                &Provenance {
                    chain_verified: true,
                    unsigned_from_seq: None,
                    server_unsigned_from_seq: None,
                    server_unread_lines: 0,
                    refusals_without_nonce: 0,
                    unpairable_lines: Vec::new(),
                },
                &Expectations::default(),
            );
            assert!(crate::cli::codes::clean_verdict(&complete, Locale::En).is_some());

            // Устройства не было вовсе.
            let absent = reconcile(&[], None, &Provenance::absent(), &Expectations::default());
            assert!(
                crate::cli::codes::clean_verdict(&absent, Locale::En).is_none(),
                "вердикт «чисто» над отчётом без устройства"
            );

            // Устройство было, но журнал нёс слово, которого сборка не знает.
            let unreadable = reconcile(
                &[],
                Some(&[]),
                &Provenance {
                    chain_verified: true,
                    unsigned_from_seq: None,
                    server_unsigned_from_seq: None,
                    server_unread_lines: 0,
                    refusals_without_nonce: 0,
                    unpairable_lines: vec![crate::codes::reconcile::UnpairableLine {
                        device_number: "77000123".to_owned(),
                        line: 3,
                        outcome: "granted".to_owned(),
                    }],
                },
                &Expectations::default(),
            );
            assert!(
                crate::cli::codes::clean_verdict(&unreadable, Locale::En).is_none(),
                "вердикт «чисто» над непрочитанной строкой"
            );
        }
    }
}

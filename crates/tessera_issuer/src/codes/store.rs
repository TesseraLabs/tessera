//! Receipts on disk.
//!
//! One issuance, one file, named by the contract
//! ([`IssuanceReceipt::file_name`]): the device, the epoch, the counter, the
//! ticket, the operator and a digest of the receipt. Two receipts of one channel
//! therefore sort next to each other, and none of them can overwrite another —
//! which is why the file is created exclusively and never truncated. A receipt
//! that replaced an earlier one would erase exactly the record an audit is
//! looking for.
//!
//! A file carries two lines: the receipt in the format of the contract, and the
//! annex beside it ([`crate::codes::annex`]). Both are required. A receipt
//! without its annex would not say how the operator key was held or whether the
//! counter refusal was overridden, and a reader cannot tell "the file predates
//! the annex" from "somebody removed it".
//!
//! This is the only module of the operator side that touches a filesystem. What
//! it hands back are values the pure modules work on: the last known counter of
//! a device, and the receipt side of a reconciliation.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use tessera_codes_contract::device_number::CheckedDeviceNumber;
use tessera_codes_contract::params::FleetParams;
use tessera_codes_contract::receipt::{IssuanceReceipt, ReceiptError};
use tessera_codes_contract::ticket::OperatorTicket;

use crate::codes::annex::{AnnexError, ReceiptAnnex};
use crate::codes::counter::KnownCounter;
use crate::codes::issue::Issuance;
use crate::codes::reconcile::ReceiptEntry;

/// Extension every receipt file carries.
pub const RECEIPT_EXTENSION: &str = "receipt";

/// Largest receipt file read, in bytes.
///
/// A receipt is two lines of a few hundred bytes. The cap is here so that a
/// directory holding something else entirely does not turn a reconciliation into
/// an unbounded read.
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

/// A receipt as it was read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceipt {
    /// The receipt itself.
    pub receipt: IssuanceReceipt,
    /// What the receipt records beyond the contract's own fields.
    pub annex: ReceiptAnnex,
    /// Where it was read from.
    pub path: PathBuf,
}

/// Writes the receipt of one issuance into `directory`.
///
/// Returns the path the receipt was written to.
///
/// # Errors
///
/// [`StoreError::Io`] when the directory cannot be written to,
/// [`StoreError::AlreadyWritten`] when a receipt of that name is already there,
/// and [`StoreError::Receipt`] when the receipt cannot be encoded.
pub fn write(
    directory: &Path,
    issuance: &Issuance,
    ticket: &OperatorTicket,
) -> Result<PathBuf, StoreError> {
    let name = issuance
        .receipt
        .file_name(ticket)
        .map_err(|error| StoreError::Receipt(ReceiptError::Canon(error)))?;
    let path = directory.join(format!("{name}.{RECEIPT_EXTENSION}"));
    let body = format!(
        "{}\n{}\n",
        issuance.receipt.to_wire(),
        issuance.annex.to_wire()
    );

    // The body lands in a file of its own, is flushed, and only then takes the
    // name a reader looks at. Writing into the final name directly would leave
    // an empty receipt behind a crash — and an empty receipt is not a lost
    // record, it is a file that refuses to parse and stops every reader of the
    // directory afterwards.
    let staging = directory.join(format!(".{name}.{RECEIPT_EXTENSION}.tmp"));
    write_staging(&staging, body.as_bytes())?;

    // A hard link publishes the name atomically *and* refuses to take a name
    // that exists, which is the property a receipt needs: one issuance, one
    // file, never overwritten.
    let published = fs::hard_link(&staging, &path).map_err(|error| match error.kind() {
        std::io::ErrorKind::AlreadyExists => StoreError::AlreadyWritten(path.clone()),
        _ => StoreError::Io(format!("{}: {error}", path.display())),
    });
    // The staging copy goes whether the name was taken or not: it is not a
    // record, only the way the record got there. A failure to remove it leaves
    // a dot-file the readers skip, so it is not worth failing the issuance over.
    drop(fs::remove_file(&staging));
    published?;

    Ok(path)
}

/// Writes the body into a staging file, flushed to disk before it is published.
fn write_staging(path: &Path, body: &[u8]) -> Result<(), StoreError> {
    // A leftover staging file from a run that was killed is not a record and is
    // not read by anything; it is replaced rather than treated as a collision.
    drop(fs::remove_file(path));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| StoreError::Io(format!("{}: {error}", path.display())))?;
    file.write_all(body)
        .and_then(|()| file.sync_all())
        .map_err(|error| StoreError::Io(format!("{}: {error}", path.display())))
}

/// Reads one receipt file.
///
/// # Errors
///
/// [`StoreError::Io`] when the file cannot be read or is larger than the cap,
/// [`StoreError::Shape`] when it does not carry a receipt and an annex,
/// [`StoreError::Receipt`] and [`StoreError::Annex`] when either line does not
/// parse.
pub fn read_file(path: &Path, params: &FleetParams) -> Result<StoredReceipt, StoreError> {
    let size = fs::metadata(path)
        .map_err(|error| StoreError::Io(format!("{}: {error}", path.display())))?
        .len();
    if size > MAX_RECEIPT_BYTES {
        return Err(StoreError::Io(format!(
            "{} is larger than the {MAX_RECEIPT_BYTES}-byte cap of a receipt",
            path.display()
        )));
    }
    let text = fs::read_to_string(path)
        .map_err(|error| StoreError::Io(format!("{}: {error}", path.display())))?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());

    let receipt = lines.next().ok_or_else(|| StoreError::Shape {
        path: path.to_path_buf(),
    })?;
    let annex = lines.next().ok_or_else(|| StoreError::Shape {
        path: path.to_path_buf(),
    })?;
    if lines.next().is_some() {
        return Err(StoreError::Shape {
            path: path.to_path_buf(),
        });
    }

    Ok(StoredReceipt {
        receipt: IssuanceReceipt::parse(receipt, params)?,
        annex: ReceiptAnnex::parse(annex)?,
        path: path.to_path_buf(),
    })
}

/// Reads every receipt of a directory, in the order of their names.
///
/// A directory that does not exist yet is an empty set of receipts: an operator
/// who has never issued a code has no directory, and that is the ordinary state
/// of a first call rather than a failure. Files that do not carry the receipt
/// extension are skipped; a file that does and does not parse is an error, not a
/// receipt quietly left out of a reconciliation.
///
/// # Errors
///
/// The [`StoreError`] of the first file that could not be read.
pub fn read_directory(
    directory: &Path,
    params: &FleetParams,
) -> Result<Vec<StoredReceipt>, StoreError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(StoreError::Io(format!("{}: {error}", directory.display()))),
    };

    let mut paths = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| StoreError::Io(format!("{}: {error}", directory.display())))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some(RECEIPT_EXTENSION) {
            paths.push(path);
        }
    }
    paths.sort();

    paths
        .iter()
        .map(|path| read_file(path, params))
        .collect::<Result<Vec<_>, _>>()
}

/// Returns where the receipts say a device was left.
///
/// The latest receipt is the one of the highest epoch, and within it the one of
/// the highest counter — not the newest file and not the latest claimed moment:
/// both of those are written by the side whose work the receipt records.
///
/// This is the second of the two stores the counter control reads. The first is
/// the hash-chained ledger ([`crate::codes::ledger`]); rolling a counter back
/// means editing both, and the module documents what that buys.
#[must_use]
pub fn last_known_counter(
    receipts: &[StoredReceipt],
    device_number: &CheckedDeviceNumber,
) -> Option<KnownCounter> {
    receipts
        .iter()
        .filter(|stored| {
            stored.receipt.device_number().significant() == device_number.significant()
        })
        .map(|stored| KnownCounter {
            epoch: stored.receipt.epoch(),
            counter: stored.receipt.nonce().counter(),
            nonce: stored.receipt.nonce().as_str().to_owned(),
        })
        .max_by_key(|known| (known.epoch, known.counter))
}

/// Turns stored receipts into the receipt side of a reconciliation.
#[must_use]
pub fn entries(receipts: &[StoredReceipt]) -> Vec<ReceiptEntry> {
    receipts
        .iter()
        .map(|stored| ReceiptEntry {
            device_number: stored.receipt.device_number().significant().to_owned(),
            epoch: stored.receipt.epoch().get(),
            nonce: stored.receipt.nonce().clone(),
            role_id: stored.receipt.role_id().to_owned(),
            level: stored.receipt.level().get(),
            ticket_number: stored.annex.ticket_number().as_str().to_owned(),
            source: stored.path.display().to_string(),
        })
        .collect()
}

/// Failure of reading or writing a receipt.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The filesystem refused the operation.
    #[error("a receipt could not be read or written: {0}")]
    Io(String),
    /// A receipt of that name is already on disk.
    #[error("{0} already exists; a receipt is never overwritten")]
    AlreadyWritten(PathBuf),
    /// The file does not carry a receipt and an annex.
    #[error("{path} does not carry a receipt line and an annex line")]
    Shape {
        /// The offending file.
        path: PathBuf,
    },
    /// The receipt line does not parse.
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    /// The annex line does not parse.
    #[error(transparent)]
    Annex(#[from] AnnexError),
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{entries, last_known_counter, read_directory, read_file, write, StoreError};
    use crate::codes::issue::{issue, IssuanceRequest};
    use crate::codes::tests::fixtures;
    use tessera_codes_contract::params::FleetParams;

    /// Writes one receipt into a fresh directory and returns both.
    fn written(world: &fixtures::World) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let issuance = issue(
            &IssuanceRequest {
                challenge: &world.challenge,
                record: &world.record,
                ticket: &world.ticket,
                params: &world.params,
                device_scope: Some(&world.device_scope),
                reason: "work order 42",
                now: fixtures::NOW,
                known_counter: None,
                history_depth: 0,
                override_decision: None,
            },
            &world.anchors,
            &world.operator_key,
        )
        .unwrap();
        let path = write(directory.path(), &issuance, world.ticket.ticket()).unwrap();
        (directory, path)
    }

    #[test]
    fn a_written_receipt_reads_back_whole() {
        let world = fixtures::world();
        let (_directory, path) = written(&world);
        let stored = read_file(&path, &FleetParams::defaults()).unwrap();

        assert_eq!(stored.receipt.reason(), "work order 42");
        assert_eq!(stored.annex.operator_id(), "op-42");
        assert_eq!(stored.annex.ticket_number().as_str(), "tk-17");
    }

    #[test]
    fn a_receipt_is_never_overwritten() {
        let world = fixtures::world();
        let (directory, _path) = written(&world);
        let issuance = issue(
            &IssuanceRequest {
                challenge: &world.challenge,
                record: &world.record,
                ticket: &world.ticket,
                params: &world.params,
                device_scope: Some(&world.device_scope),
                reason: "work order 42",
                now: fixtures::NOW,
                known_counter: None,
                history_depth: 0,
                override_decision: None,
            },
            &world.anchors,
            &world.operator_key,
        )
        .unwrap();
        assert!(matches!(
            write(directory.path(), &issuance, world.ticket.ticket()),
            Err(StoreError::AlreadyWritten(_))
        ));
    }

    #[test]
    fn a_directory_that_does_not_exist_holds_no_receipts() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("never-written");
        assert_eq!(
            read_directory(&absent, &FleetParams::defaults())
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn the_last_known_counter_comes_from_the_highest_epoch_and_counter() {
        let world = fixtures::world();
        let (directory, _path) = written(&world);
        let receipts = read_directory(directory.path(), &FleetParams::defaults()).unwrap();

        let known = last_known_counter(&receipts, world.challenge.device_number()).unwrap();
        assert_eq!(known.epoch.get(), fixtures::EPOCH);
        assert_eq!(known.counter, 1);

        let other = fixtures::other_device_number();
        assert_eq!(last_known_counter(&receipts, &other), None);
    }

    #[test]
    fn a_file_without_an_annex_is_refused() {
        let world = fixtures::world();
        let (directory, path) = written(&world);
        let text = std::fs::read_to_string(&path).unwrap();
        let stripped = text.lines().next().unwrap().to_owned();
        std::fs::write(&path, stripped).unwrap();

        assert!(matches!(
            read_file(&path, &FleetParams::defaults()),
            Err(StoreError::Shape { .. })
        ));
        assert!(matches!(
            read_directory(directory.path(), &FleetParams::defaults()),
            Err(StoreError::Shape { .. })
        ));
    }

    #[test]
    fn the_receipt_side_of_a_reconciliation_comes_out_of_the_files() {
        let world = fixtures::world();
        let (directory, _path) = written(&world);
        let receipts = read_directory(directory.path(), &FleetParams::defaults()).unwrap();
        let entries = entries(&receipts);

        let entry = entries.first().unwrap();
        assert_eq!(entry.role_id, "ops.dc.senior");
        assert_eq!(entry.ticket_number, "tk-17");
        assert_eq!(entry.epoch, fixtures::EPOCH);
    }
}

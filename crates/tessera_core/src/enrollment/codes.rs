//! The optional Codes part of an enrollment package.
//!
//! A package carries the device half of the code login method — the container
//! holding the device private key, the operator tickets, their revocation list
//! and the anchor those tickets are verified against — in a section that may
//! simply not be there. A fleet running Access alone ships a package without
//! it, and such a package imports exactly as it did before this section
//! existed: the absence is the normal case, not a degraded one.
//!
//! # What this module does and does not do
//!
//! It reads the section, verifies each named file against the hash the package
//! pins it at, and hands the bytes over. It applies nothing: the epochs, the
//! anti-rollback, the nonce store and the permissions of the store belong to
//! [`crate::codes::artefacts`], which is also what a courier payload goes
//! through. And it parses no ticket of its own — the documents are checked with
//! [`crate::codes::tickets`], which in turn calls [`tessera_codes_contract`]. A
//! second parser here would be a second opinion about what a ticket is, and the
//! device would then hold artefacts that pass the import and fail the login.
//!
//! # Where the section comes from in each trust mode
//!
//! Managed packages carry it inside the signed `manifest.toml`, so it rides the
//! same signature and the same `bundle_version` as the roles, the tags and the
//! CRL. Standalone packages carry it in a `codes.toml` beside the tags file and
//! are trusted the way everything else in a standalone package is trusted — by
//! the ownership and mode of the medium. The shape is the same in both, which
//! is why it is described once, in [`crate::role::ManifestCodes`].
//!
//! # Why the pin is not optional in a managed package
//!
//! Everything else in a managed package is authenticated: the role slices by
//! their per-slice hashes, the CRL and the `.p12` by their pins, all under one
//! signature and one `bundle_version`. A Codes file named without a hash would
//! be the one byte stream in the package nothing vouched for — and it is the
//! stream that decides which operators may hand this device a code. So a
//! managed section that names a file without pinning it is refused rather than
//! trusted. A standalone package pins nothing and is trusted by the permissions
//! of the medium, the same way its tags and role slices are; a pin there is
//! honoured when it is present.
//!
//! # The PIN of the delivery container
//!
//! It is supplied by the operator running the import and never travels in the
//! package: a container whose password rides beside it is not a protected
//! container. Where the key goes afterwards, and why it does not stay in that
//! container, is [`crate::codes::artefacts`].

use std::path::Path;

use secrecy::SecretString;
use sha2::{Digest as _, Sha256};

use tessera_codes_contract::key::Epoch;

use crate::codes::artefacts::{CodesDelivery, DeliveredKey};
use crate::codes::tickets::{TicketAnchor, MAX_ARTEFACT_BYTES};
use crate::role::{ManifestCodes, ManifestCodesFile};

use super::import::{ImportError, ImportMode};

/// File name of the Codes section of a standalone package.
pub const STANDALONE_CODES_FILENAME: &str = "codes.toml";

/// Sanity cap on the delivery key container (256 KiB): one key and one chain.
///
/// The store's own cap, not a second one: what the import accepts here is what
/// the login path has to be able to read back.
pub const MAX_KEY_CONTAINER_BYTES: usize = crate::codes::store::MAX_KEY_CONTAINER_BYTES;

/// Sanity cap on the standalone Codes section.
///
/// The same cap the manifest is read under, because in a managed package the
/// section *is* part of the manifest: one document in two places must not have
/// two limits.
pub const MAX_SECTION_BYTES: usize = crate::role::manifest::MAX_MANIFEST_BYTES;

/// Reads the Codes section of a standalone package, when it has one.
///
/// `Ok(None)` means the package carries no Codes part — the Access-only case,
/// and the one that must keep importing as it always did.
///
/// # Errors
///
/// [`ImportError::CodesSection`] when the file is present but does not parse,
/// and [`ImportError::Io`] when it cannot be read.
pub fn read_standalone_section(root: &Path) -> Result<Option<ManifestCodes>, ImportError> {
    let path = root.join(STANDALONE_CODES_FILENAME);
    // The section is read under the same cap as the manifest it stands in for:
    // it is the same document in the same place, and the medium it sits on is
    // no more trusted here than there.
    let bytes = match crate::fs_mode::read_capped_regular(&path, MAX_SECTION_BYTES) {
        Ok(crate::fs_mode::CappedRead::Whole(bytes)) => bytes,
        Ok(crate::fs_mode::CappedRead::TooLarge) => {
            return Err(ImportError::Oversize {
                artefact: "codes section",
                read: MAX_SECTION_BYTES.saturating_add(1),
                max: MAX_SECTION_BYTES,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ImportError::Io {
                path: path.display().to_string(),
                reason: error.to_string(),
            })
        }
    };
    let text = std::str::from_utf8(&bytes).map_err(|error| ImportError::CodesSection {
        reason: format!("{STANDALONE_CODES_FILENAME} is not valid UTF-8: {error}"),
    })?;
    let section = toml::from_str(text).map_err(|error| ImportError::CodesSection {
        reason: format!("{STANDALONE_CODES_FILENAME} is invalid: {error}"),
    })?;
    Ok(Some(section))
}

/// Reads and verifies every file the section names.
///
/// Nothing is written and nothing on the device is consulted: the result is a
/// consignment [`crate::codes::artefacts::apply`] decides on. The failures that
/// belong here are the ones about the *package* — a file that is missing,
/// oversized, unpinned in a managed package, hashed differently than the
/// manifest says, or holding a document the device could not read.
///
/// # Errors
///
/// [`ImportError::CodesUnpinned`] for a managed file named without a hash,
/// [`ImportError::CodesHashMismatch`] when the bytes do not match the pin,
/// [`ImportError::CodesMissing`] for a named file that is not in the package,
/// [`ImportError::UnsafeName`] for a name that is not bare,
/// [`ImportError::Oversize`] past a size cap, [`ImportError::CodesSection`] for
/// a document the device would refuse to read, and [`ImportError::Io`] for a
/// read that failed.
pub fn read_delivery(
    section: &ManifestCodes,
    root: &Path,
    mode: ImportMode,
    pin: &SecretString,
) -> Result<CodesDelivery, ImportError> {
    let key = match &section.key_container {
        Some(named) => Some(DeliveredKey {
            epoch: Epoch::new(section.epoch),
            container: read_named(
                root,
                mode,
                named,
                "codes key container",
                MAX_KEY_CONTAINER_BYTES,
            )?,
            pin: pin.clone(),
        }),
        None => None,
    };
    let tickets = read_optional(root, mode, section.tickets.as_ref(), "codes ticket set")?;
    let revocations = read_optional(
        root,
        mode,
        section.ticket_revocations.as_ref(),
        "codes ticket revocation list",
    )?;
    let ticket_authority = read_optional(
        root,
        mode,
        section.ticket_authority.as_ref(),
        "codes ticket authority anchor",
    )?;

    // The anchor decides which operator tickets are real, so an anchor that is
    // not a public key has to stop the import rather than sit in the store
    // until the first login discovers it.
    if let Some(bytes) = &ticket_authority {
        TicketAnchor::parse(bytes).map_err(|error| ImportError::CodesSection {
            reason: error.to_string(),
        })?;
    }

    Ok(CodesDelivery {
        key,
        tickets,
        revocations,
        ticket_authority,
    })
}

/// Reads one optional artefact under the shared document cap.
fn read_optional(
    root: &Path,
    mode: ImportMode,
    named: Option<&ManifestCodesFile>,
    artefact: &'static str,
) -> Result<Option<Vec<u8>>, ImportError> {
    match named {
        None => Ok(None),
        Some(named) => read_named(root, mode, named, artefact, MAX_ARTEFACT_BYTES).map(Some),
    }
}

/// Reads one named file EXACTLY ONCE and verifies its pin on those bytes.
///
/// Reading once and returning the same buffer closes the check-then-use window
/// the CRL pin closes for the same reason: the medium a package sits on is
/// removable and may change under a second read.
///
/// The name is checked to be a bare file name, and that is not the whole of the
/// question: a bare name still resolves through whatever the medium put at it.
/// So the read refuses a symlink, decides the file type on the descriptor it
/// already holds rather than on the path, and stops one byte past the cap —
/// a package can otherwise name a symlink to a character device and hand the
/// import an endless read, or a FIFO and hang it.
fn read_named(
    root: &Path,
    mode: ImportMode,
    named: &ManifestCodesFile,
    artefact: &'static str,
    max: usize,
) -> Result<Vec<u8>, ImportError> {
    if named.file.is_empty()
        || named.file == "."
        || named.file == ".."
        || named.file.contains('/')
        || named.file.contains('\\')
    {
        return Err(ImportError::UnsafeName {
            name: named.file.clone(),
        });
    }
    let pin = match (mode, named.sha256.as_deref()) {
        (ImportMode::Managed, None) => {
            return Err(ImportError::CodesUnpinned {
                file: named.file.clone(),
            })
        }
        (_, pin) => pin,
    };

    let path = root.join(&named.file);
    let bytes = match crate::fs_mode::read_capped_regular(&path, max) {
        Ok(crate::fs_mode::CappedRead::Whole(bytes)) => bytes,
        Ok(crate::fs_mode::CappedRead::TooLarge) => {
            return Err(ImportError::Oversize {
                artefact,
                read: max.saturating_add(1),
                max,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ImportError::CodesMissing {
                file: named.file.clone(),
            })
        }
        Err(error) => {
            return Err(ImportError::Io {
                path: path.display().to_string(),
                reason: error.to_string(),
            })
        }
    };
    if let Some(pin) = pin {
        let actual = hex::encode(Sha256::digest(&bytes));
        if !actual.eq_ignore_ascii_case(pin.trim()) {
            return Err(ImportError::CodesHashMismatch {
                file: named.file.clone(),
            });
        }
    }
    Ok(bytes)
}

// The import writes the artefacts under pinned POSIX modes, so the whole path
// — and everything that asserts on it — is Unix-only.
#[cfg(all(test, unix))]
#[path = "codes_tests.rs"]
mod tests;

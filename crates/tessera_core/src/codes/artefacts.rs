//! Putting delivered Codes artefacts onto the device, and taking them off.
//!
//! Two directions, one module, because they are the two halves of the same
//! invariant: what an import writes is exactly what a wipe has to remove, and a
//! list of artefacts that lives in two places grows a difference.
//!
//! # The key container is a delivery form, not a storage form
//!
//! The device private key travels inside a PIN-protected PKCS#12 because that
//! is how key material moves — through an operator's hands, over a medium
//! nobody trusts. It does not stay that way. A device has to come back from a
//! power cut on its own: the code is checked at the moment an engineer stands at
//! the keyboard, and that engineer must not know the PIN of the device, so there
//! is nobody to type it at boot. The import therefore opens the container once,
//! with the PIN the operator supplied, and re-writes the key into the store
//! under root-only permissions, openable by the verifying process without a
//! person in the room.
//!
//! What protects the key afterwards is the ownership and mode of the store and
//! the integrity of the environment — trusted boot and a closed software
//! environment — and not a PIN. That is the same boundary "root on the device"
//! already sits behind in the threat model, and it is stated here rather than
//! implied. The delivered container is never copied into the store beside it:
//! two encodings of one key double the number of files a wipe has to find.
//!
//! # Epochs
//!
//! The key epoch is the anti-rollback of this path, and it works exactly like
//! `bundle_version`: greater replaces, smaller is refused, and equal moves
//! nothing forward — the artefacts of an equal epoch are written back as
//! delivered, which is what makes presenting a medium twice a repair rather
//! than a no-op that leaves a half-applied store as it was.
//!
//! Nothing about an attempt is reset here, because nothing about an attempt is
//! stored: an attempt lives in the memory of the process holding it and dies
//! with it. What the state directory does hold — the throttle — is deliberately
//! left alone by an import: a lockout that a delivered medium could clear would
//! be a lockout anyone who can reach the device could clear.
//!
//! # The revocation list only grows
//!
//! A withdrawn ticket stays withdrawn. A delivery whose revocation list has lost
//! a number the device already applies is an older list, whatever its file date,
//! and it is refused rather than merged: merging would hide the fact that
//! somebody replayed a medium from before the withdrawal.
//!
//! # The transaction
//!
//! The whole application runs under the same cross-process lock the login path
//! takes ([`super::lock::StateLock`]), so an import cannot interleave with a
//! login reading the state it is replacing. The order inside it is fail-closed:
//! everything is parsed and verified — including the trustworthiness of the
//! store itself — before any device file is touched, and only then are the
//! artefacts published with `tmp → rename`.
//!
//! The epoch is persisted last, after the key it belongs to. A crash between
//! the two leaves the new key under the previous epoch, and codes derived
//! against that pair are refused; what makes it recoverable is that the next
//! run of the same medium writes the key again rather than skipping it because
//! a file is already there. The repeat is the repair, and it is a repair only
//! if it repeats every step.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use openssl::pkcs12::Pkcs12;
use secrecy::SecretString;
use zeroize::Zeroizing;

use tessera_codes_contract::key::Epoch;

use super::store::{CodesPaths, DeviceKeyError};
use super::tickets::{TicketStore, TicketStoreError};
use super::{
    audit, epoch,
    lock::{StateLock, LOCK_FILENAME},
    state::STATE_FILENAME,
};

/// Permissions of the directories the artefacts live in: root alone.
const DIR_MODE: u32 = 0o700;

/// Permissions of the stored device key: root alone.
const KEY_MODE: u32 = 0o600;

/// Permissions of the artefacts that are trust inputs but not secrets.
///
/// They sit inside a `0700` directory, so the group and other bits reach
/// nobody; the mode is pinned all the same, because a store that is later moved
/// or a directory whose mode is repaired by hand must not silently publish the
/// ticket set.
const ARTEFACT_MODE: u32 = 0o644;

/// The device key as it was delivered, before it is opened.
pub struct DeliveredKey {
    /// Epoch the delivered key belongs to.
    pub epoch: Epoch,
    /// Raw PKCS#12 bytes of the delivery container.
    pub container: Vec<u8>,
    /// PIN the delivery container was closed with.
    ///
    /// It opens the container once, here, and is never written anywhere: the
    /// stored key is not protected by it. See the module documentation.
    pub pin: SecretString,
}

impl std::fmt::Debug for DeliveredKey {
    /// Prints the epoch and the container length, and neither the PIN nor a
    /// byte of the container.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveredKey")
            .field("epoch", &self.epoch.get())
            .field("container_len", &self.container.len())
            .field("pin", &"<redacted>")
            .finish()
    }
}

/// One consignment of Codes artefacts, from an enrolment package or from a
/// courier payload.
///
/// Every part is optional and the combinations are meaningful rather than
/// accidental: an Access-only fleet delivers nothing at all, enabling the method
/// on a running device delivers the key together with the tickets and the
/// anchor, and a rotation delivers the ticket set and its revocation list
/// alone.
#[derive(Debug, Default)]
pub struct CodesDelivery {
    /// The device key and its epoch.
    pub key: Option<DeliveredKey>,
    /// The operator ticket set, in the wire form of the contract crate.
    pub tickets: Option<Vec<u8>>,
    /// The revocation list of those tickets.
    pub revocations: Option<Vec<u8>>,
    /// The anchor every ticket is verified against.
    pub ticket_authority: Option<Vec<u8>>,
}

impl CodesDelivery {
    /// Reports whether the consignment carries nothing at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.key.is_none()
            && self.tickets.is_none()
            && self.revocations.is_none()
            && self.ticket_authority.is_none()
    }
}

/// What an application of a consignment changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Epoch the device is on afterwards, if it carries a key at all.
    pub epoch: Option<Epoch>,
    /// Whether the stored key was replaced.
    pub key_replaced: bool,
    /// Whether a ticket set was published.
    pub tickets_applied: bool,
    /// Whether a revocation list was published.
    pub revocations_applied: bool,
}

/// What a wipe found and removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wiped {
    /// The last epoch the device was on, for the audit record of the command
    /// that is retiring it. `None` when the device never held a Codes key.
    pub last_epoch: Option<Epoch>,
    /// Artefacts that were present and are now gone, by their file names.
    pub removed: Vec<String>,
}

impl Wiped {
    /// Reports whether the device carried any Codes artefact at all.
    ///
    /// A device of an Access-only fleet carries none, and that is not a failure
    /// of the command that retires it.
    #[must_use]
    pub fn found_anything(&self) -> bool {
        !self.removed.is_empty() || self.last_epoch.is_some()
    }
}

/// Whether an import re-checks the finished store the way a login does.
///
/// The same split [`super::CodeMethod::open`] and
/// [`super::CodeMethod::open_privileged`] already draw, expressed as a value
/// because it travels through a caller's options rather than through a choice
/// of function. A device enforces; a test whose store lives under a temporary
/// directory cannot, because no ownership policy accepts such a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreCheck {
    /// Walk the finished store with [`CodesPaths::check_trusted`].
    Enforced,
    /// Skip the walk.
    Skipped,
}

/// Failure of applying or removing the Codes artefacts.
#[derive(Debug, thiserror::Error)]
pub enum ArtefactError {
    /// The consignment names an epoch below the one the device has accepted.
    #[error("key epoch rollback: the delivery names {delivered} and the device is on {persisted}")]
    EpochRollback {
        /// Epoch of the consignment.
        delivered: u32,
        /// Epoch the device has accepted.
        persisted: u32,
    },
    /// The delivery names an epoch below the one the configuration runs on.
    ///
    /// Distinct from [`ArtefactError::EpochRollback`], which compares against
    /// the epoch the device has already accepted: this one is about a device
    /// that has no epoch file yet, where the configuration is the only floor
    /// there is. Writing the older epoch down would leave the device refusing
    /// every login afterwards.
    #[error("key epoch behind the configuration: the delivery names {delivered} and the configuration runs on {configured}")]
    EpochBehindConfigured {
        /// Epoch of the consignment.
        delivered: u32,
        /// Epoch named by the configuration of the device.
        configured: u32,
    },
    /// The delivered revocation list has lost a number the device applies.
    #[error("the delivered ticket revocation list is older than the applied one")]
    RevocationRollback,
    /// The delivery container did not open, or held no key.
    #[error(transparent)]
    Container(#[from] DeviceKeyError),
    /// A delivered artefact does not hold what its format describes.
    #[error(transparent)]
    Tickets(#[from] TicketStoreError),
    /// The key could not be re-written into the store.
    #[error("the device key could not be stored: {reason}")]
    KeyStore {
        /// What failed.
        reason: String,
    },
    /// The store is not trustworthy, so nothing was applied to it.
    #[error("the code artefact store is not trustworthy, nothing was applied: {0}")]
    Untrusted(String),
    /// This platform does not carry the code login method at all.
    ///
    /// Not a broken device and not a broken package: the method rests on POSIX
    /// permissions, and where there are none it cannot be carried. Kept as its
    /// own variant because the operator's next step differs — nothing here is
    /// repairable by fixing the store or re-cutting the medium.
    #[error("the code artefacts were not applied: {0}")]
    UnsupportedPlatform(#[source] super::CodeLoginError),
    /// An artefact could not be read or written.
    #[error("code artefact I/O error at {path}: {reason}")]
    Io {
        /// Path being touched.
        path: String,
        /// Underlying failure.
        reason: String,
    },
}

/// Applies a consignment of Codes artefacts to the store at `paths`.
///
/// An empty consignment is a no-op that reports one: a fleet that ships no
/// Codes part is not a fleet that failed to ship one.
///
/// `check` decides whether the finished store is walked with the ownership
/// policy of the login path; a device passes [`StoreCheck::Enforced`].
///
/// # Errors
///
/// [`ArtefactError::EpochRollback`] for a key epoch below the accepted one,
/// [`ArtefactError::EpochBehindConfigured`] for a key epoch below the one the
/// configuration runs on when the device has no epoch file yet,
/// [`ArtefactError::RevocationRollback`] for a revocation list that lost a
/// number, [`ArtefactError::Container`] when the delivery container does not
/// open with the PIN, [`ArtefactError::Tickets`] for an artefact that does not
/// parse, [`ArtefactError::Untrusted`] when the store does not pass the check
/// the login path makes, [`ArtefactError::UnsupportedPlatform`] where the
/// method cannot be carried at all, and [`ArtefactError::Io`] for a failed read
/// or write. Nothing is published — and nothing is created — unless every check
/// above has passed.
pub fn apply(
    paths: &CodesPaths,
    delivery: &CodesDelivery,
    gost_engine_path: Option<&Path>,
    check: StoreCheck,
    configured_epoch: Option<Epoch>,
) -> Result<Applied, ArtefactError> {
    if delivery.is_empty() {
        return Ok(Applied {
            epoch: read_epoch(paths)?,
            key_replaced: false,
            tickets_applied: false,
            revocations_applied: false,
        });
    }

    // Asked before a single directory is made, and asked of the same predicate
    // the login path asks so the two cannot drift apart. An import that reached
    // `ensure_store_dirs` here would create the store and only then fail on
    // pinning its mode — leaving the litter of an operation that could never
    // have finished, and reporting it as an I/O fault rather than as what it
    // is. The device is not broken; the platform does not carry the method.
    super::platform_offers_the_method().map_err(ArtefactError::UnsupportedPlatform)?;

    ensure_store_dirs(paths)?;
    let _lock = StateLock::acquire(&paths.state_dir).map_err(|error| ArtefactError::Io {
        path: paths.state_dir.display().to_string(),
        reason: error.to_string(),
    })?;

    // Everything that can be refused is refused here, before a single device
    // file is touched: the artefacts are parsed with the same parser the login
    // path uses, the epoch is checked against the persisted floor, and the
    // container is opened with the PIN.
    let persisted = epoch::read(&paths.state_dir).map_err(|error| ArtefactError::Io {
        path: paths.state_dir.display().to_string(),
        reason: error.to_string(),
    })?;
    let plan = plan_key(
        delivery.key.as_ref(),
        persisted,
        has_spoken(paths),
        configured_epoch,
    )?;
    check_delivered_artefacts(paths, delivery)?;
    let stored_key = match (&delivery.key, plan.write_key) {
        (Some(key), true) => Some(restore_key(key, gost_engine_path)?),
        _ => None,
    };

    // The store is checked with the same self-check the login path runs — not a
    // second, weaker one — and it is checked BEFORE anything is published. A
    // check afterwards states the same fact too late: the artefacts would be on
    // a store somebody else can write, the epoch would have moved, and the
    // repeat of the import that the engineer would then run finds the epoch
    // already there and changes nothing.
    //
    // What can be checked at this point is the directories, which
    // `ensure_store_dirs` has just created or repaired, and whichever artefacts
    // the device already carries. The files published below inherit their trust
    // from the directory they are written into and the modes they are written
    // with.
    if check == StoreCheck::Enforced {
        paths
            .check_trusted_before_publishing()
            .map_err(ArtefactError::Untrusted)?;
    }

    // Publication. The order is the recovery order: the artefacts a login reads
    // first, then the key, then the state, and the epoch floor last of all.
    if let Some(bytes) = &delivery.ticket_authority {
        write_atomic(&paths.ticket_authority, bytes, ARTEFACT_MODE)?;
    }
    if let Some(bytes) = &delivery.tickets {
        write_atomic(&paths.tickets, bytes, ARTEFACT_MODE)?;
    }
    if let Some(bytes) = &delivery.revocations {
        write_atomic(&paths.ticket_revocations, bytes, ARTEFACT_MODE)?;
    }
    if let Some(bytes) = &stored_key {
        write_atomic(&paths.device_key_container, bytes, KEY_MODE)?;
    }
    if let Some(new_epoch) = plan.persist_epoch {
        epoch::write(&paths.state_dir, new_epoch).map_err(|error| ArtefactError::Io {
            path: paths.state_dir.display().to_string(),
            reason: error.to_string(),
        })?;
    }

    let applied = Applied {
        epoch: plan.persist_epoch.or(persisted),
        key_replaced: stored_key.is_some(),
        tickets_applied: delivery.tickets.is_some(),
        revocations_applied: delivery.revocations.is_some(),
    };
    audit::emit_artefacts_applied(&applied);
    Ok(applied)
}

/// Removes every Codes artefact from the store at `paths`.
///
/// The last epoch is read before anything is removed and handed back, because
/// the owner of the fleet needs it to withdraw the registry record of the
/// device and cannot recover it afterwards.
///
/// A device that carries no Codes artefact is wiped successfully and reports an
/// empty [`Wiped`]: a fleet that never enabled the method has nothing to lose
/// here, and a command that failed on it would fail on every Access-only device
/// being retired.
///
/// # Errors
///
/// [`ArtefactError::Io`] for a removal that failed for a reason other than the
/// file being absent.
pub fn wipe(paths: &CodesPaths) -> Result<Wiped, ArtefactError> {
    // The lock is taken when there is a state directory to take it on; a device
    // that never held artefacts has none, and creating one in order to wipe it
    // would be the only trace the command left.
    let _lock = if paths.state_dir.is_dir() {
        Some(
            StateLock::acquire(&paths.state_dir).map_err(|error| ArtefactError::Io {
                path: paths.state_dir.display().to_string(),
                reason: error.to_string(),
            })?,
        )
    } else {
        None
    };

    let last_epoch = read_epoch(paths)?;
    let mut removed = Vec::new();

    // The key first: it is the artefact whose survival matters, and a wipe
    // interrupted halfway must not leave it behind.
    if shred(&paths.device_key_container)? {
        push_removed(&mut removed, &paths.device_key_container);
    }
    for path in [
        &paths.tickets,
        &paths.ticket_revocations,
        &paths.ticket_authority,
        &paths.state_dir.join(STATE_FILENAME),
        &paths.state_dir.join(epoch::EPOCH_FILENAME),
    ] {
        if remove_if_present(path)? {
            push_removed(&mut removed, path);
        }
    }

    // The cross-process lock file last of all. It is not delivered — this
    // module creates it — but the promise here is that a wipe removes what an
    // import writes, and a state directory left holding one file is a device
    // that still looks provisioned to whoever looks at it next.
    //
    // Last, and not earlier, because the hold is still taken: unlinking the
    // path releases nothing, but a process arriving afterwards creates a fresh
    // file and takes the lock on a different inode. That is harmless only once
    // there is nothing left for the two of them to disagree about, which is
    // true here and would not be true a few lines above.
    let lock_file = paths.state_dir.join(LOCK_FILENAME);
    if remove_if_present(&lock_file)? {
        push_removed(&mut removed, &lock_file);
    }

    let wiped = Wiped {
        last_epoch,
        removed,
    };
    audit::emit_artefacts_wiped(&wiped);
    Ok(wiped)
}

/// What the key part of a consignment implies for the store.
#[derive(Debug, Clone, Copy)]
struct KeyPlan {
    /// Whether the stored key is to be written.
    write_key: bool,
    /// The epoch to persist, when it moves.
    persist_epoch: Option<Epoch>,
}

/// Decides what the delivered key does to the store, or refuses it.
///
/// `has_spoken` says whether this device has already been through a
/// conversation — its state directory holds a throttle record. It is asked
/// separately from the epoch because the two can disagree: a fleet whose
/// artefacts were placed by hand runs against the epoch in `config.toml` and
/// has no epoch file at all, which [`super::epoch::effective`] supports on
/// purpose. Such a device is not a fresh one, and the delivery is not moving it
/// anywhere: what it gets is the epoch written down explicitly.
fn plan_key(
    key: Option<&DeliveredKey>,
    persisted: Option<Epoch>,
    has_spoken: bool,
    configured: Option<Epoch>,
) -> Result<KeyPlan, ArtefactError> {
    let Some(key) = key else {
        return Ok(KeyPlan {
            write_key: false,
            persist_epoch: None,
        });
    };

    // Asked of every device with no epoch file, whether or not it has spoken.
    // With no file there is nothing to compare the delivery against except the
    // configuration, and the delivery is about to create the file: an older
    // epoch is written down happily, and every login afterwards refuses —
    // `epoch::effective` finds the configuration ahead of the store and says
    // so. That is a device taken out of service by a careful administrator
    // applying a stale package, with no attack anywhere in the story, and the
    // way back is editing files on the machine.
    //
    // It used to be asked only of a device that had spoken, which left the
    // case this floor matters most in — first provisioning, no state file at
    // all — with no floor whatsoever.
    if persisted.is_none() {
        if let Some(configured) = configured {
            if key.epoch < configured {
                return Err(ArtefactError::EpochBehindConfigured {
                    delivered: key.epoch.get(),
                    configured: configured.get(),
                });
            }
        }
    }

    if persisted.is_none() && has_spoken {
        // A device provisioned by hand is not a fresh one, and the delivery is
        // not moving it anywhere: what it gets is the epoch written down
        // explicitly.
        return Ok(KeyPlan {
            write_key: true,
            persist_epoch: Some(key.epoch),
        });
    }

    match persisted {
        Some(current) if key.epoch < current => Err(ArtefactError::EpochRollback {
            delivered: key.epoch.get(),
            persisted: current.get(),
        }),
        // The same epoch again: the key is written back whenever the medium
        // carries one.
        //
        // Writing the key back unconditionally is what makes a repeat of the
        // medium a real repair. Writing it only when the store has lost the
        // file leaves a device stuck the moment the store holds *a* key that is
        // not the one this epoch belongs to — a container re-cut after a
        // delivery that half-landed, a store rebuilt from a backup taken before
        // the last rotation. The file is there, the epoch is equal, so no
        // repeat of the medium would ever replace it, and every code the fleet
        // computes is refused with nothing on the device to explain it.
        Some(current) if key.epoch == current => Ok(KeyPlan {
            write_key: true,
            persist_epoch: None,
        }),
        _ => Ok(KeyPlan {
            write_key: true,
            persist_epoch: Some(key.epoch),
        }),
    }
}

/// Reports whether this device has already been through a conversation.
///
/// The question is asked of the file rather than of its contents: it being
/// there means the throttle of this device has something to remember, which
/// only happens after a challenge has left it.
fn has_spoken(paths: &CodesPaths) -> bool {
    paths.state_dir.join(STATE_FILENAME).exists()
}

/// Parses the delivered ticket artefacts and checks the revocation list against
/// the one the device already applies.
fn check_delivered_artefacts(
    paths: &CodesPaths,
    delivery: &CodesDelivery,
) -> Result<(), ArtefactError> {
    let tickets = as_text(delivery.tickets.as_deref(), &paths.tickets)?;
    let revocations = as_text(delivery.revocations.as_deref(), &paths.ticket_revocations)?;
    let delivered = TicketStore::parse(tickets.as_deref(), revocations.as_deref())?;

    if delivery.revocations.is_some() {
        let applied_text = read_optional(&paths.ticket_revocations)?;
        let applied = TicketStore::parse(None, applied_text.as_deref())?;
        // Monotonicity as a superset test rather than a version field: the list
        // carries no counter, and "older" is precisely "has forgotten a number
        // we already act on".
        if !applied
            .revoked()
            .iter()
            .all(|number| delivered.revoked().contains(number))
        {
            return Err(ArtefactError::RevocationRollback);
        }
    }
    Ok(())
}

/// Reads an artefact the device may or may not carry.
///
/// Under the cap of the format and with the file type decided on the
/// descriptor, the same way the login path reads the same files. The store is
/// root-only, so this is not where an attacker is expected; it is where the
/// artefacts of a store that was restored, moved or repaired by hand arrive,
/// and an import that dies reading one of them is an import that cannot fix it.
fn read_optional(path: &Path) -> Result<Option<String>, ArtefactError> {
    match crate::fs_mode::read_capped_regular(path, super::tickets::MAX_ARTEFACT_BYTES) {
        Ok(crate::fs_mode::CappedRead::Whole(bytes)) => as_text(Some(&bytes), path),
        Ok(crate::fs_mode::CappedRead::TooLarge) => {
            Err(ArtefactError::Tickets(TicketStoreError::Malformed {
                reason: format!(
                    "the artefact at {} is larger than the {}-byte cap",
                    path.display(),
                    super::tickets::MAX_ARTEFACT_BYTES
                ),
            }))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ArtefactError::Io {
            path: path.display().to_string(),
            reason: error.to_string(),
        }),
    }
}

/// Decodes a delivered artefact as the UTF-8 text its format is.
fn as_text(bytes: Option<&[u8]>, path: &Path) -> Result<Option<String>, ArtefactError> {
    match bytes {
        None => Ok(None),
        Some(bytes) if bytes.len() > super::tickets::MAX_ARTEFACT_BYTES => {
            Err(ArtefactError::Tickets(TicketStoreError::Malformed {
                reason: format!(
                    "the delivered artefact for {} is larger than the {}-byte cap",
                    path.display(),
                    super::tickets::MAX_ARTEFACT_BYTES
                ),
            }))
        }
        Some(bytes) => String::from_utf8(bytes.to_vec()).map(Some).map_err(|_| {
            ArtefactError::Tickets(TicketStoreError::Malformed {
                reason: format!(
                    "the delivered artefact for {} is not valid UTF-8",
                    path.display()
                ),
            })
        }),
    }
}

/// Opens the delivery container and re-wraps the key for storage.
///
/// The stored container carries no password. That is the point of the whole
/// step: the verifying process opens it with nobody in the room, and what
/// protects it is the mode of the file and the integrity of the device, stated
/// in the module documentation. The end-entity certificate travels with the key
/// because a PKCS#12 without one does not open at all.
fn restore_key(
    key: &DeliveredKey,
    gost_engine_path: Option<&Path>,
) -> Result<Zeroizing<Vec<u8>>, ArtefactError> {
    let material =
        crate::pkcs12::LoadedKeyMaterial::from_p12(&key.container, &key.pin, gost_engine_path)
            .map_err(|error| ArtefactError::Container(DeviceKeyError::Container(error)))?;
    let private = material
        .private_key()
        .map_err(|error| ArtefactError::Container(DeviceKeyError::Container(error)))?;

    let stored = Pkcs12::builder()
        .name("tessera-codes-device")
        .pkey(&private)
        .cert(material.end_entity.x509())
        .build2("")
        .and_then(|container| container.to_der())
        .map_err(|error| ArtefactError::KeyStore {
            reason: error.to_string(),
        })?;
    Ok(Zeroizing::new(stored))
}

/// Reads the persisted epoch, mapping the failure to this module's error.
fn read_epoch(paths: &CodesPaths) -> Result<Option<Epoch>, ArtefactError> {
    epoch::read(&paths.state_dir).map_err(|error| ArtefactError::Io {
        path: paths.state_dir.display().to_string(),
        reason: error.to_string(),
    })
}

/// Creates the store and state directories with the mode the artefacts need.
fn ensure_store_dirs(paths: &CodesPaths) -> Result<(), ArtefactError> {
    for dir in [paths.device_key_container.parent(), Some(&paths.state_dir)]
        .into_iter()
        .flatten()
    {
        if !dir.is_dir() {
            fs::create_dir_all(dir).map_err(|error| ArtefactError::Io {
                path: dir.display().to_string(),
                reason: error.to_string(),
            })?;
        }
        crate::fs_mode::pin_mode(dir, DIR_MODE).map_err(|error| ArtefactError::Io {
            path: dir.display().to_string(),
            reason: error.to_string(),
        })?;
    }
    Ok(())
}

/// Publishes one artefact through a temporary file and a rename.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ArtefactError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artefact");
    let tmp = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| -> io::Result<()> {
        let mut file = crate::fs_mode::create_with_mode(&tmp, mode)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        crate::fs_mode::pin_mode(&tmp, mode)?;
        fs::rename(&tmp, path)?;
        crate::fs_mode::sync_dir(parent)
    })();
    if result.is_err() {
        if let Err(cleanup) = fs::remove_file(&tmp) {
            if cleanup.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    target: "codes.audit",
                    path = %tmp.display(),
                    error = %cleanup,
                    "failed to clean up a code artefact temporary file"
                );
            }
        }
    }
    result.map_err(|error| ArtefactError::Io {
        path: path.display().to_string(),
        reason: error.to_string(),
    })
}

/// Removes a delivered copy of key material, overwriting it first.
///
/// The delivery container is the key of the device on somebody's medium, and it
/// has no business outliving the import that consumed it. What can be promised
/// is what [`shred`] promises and no more: the obvious copy is gone, the blocks
/// underneath are the filesystem's business, and a medium leaving the fleet is
/// still destroyed rather than trusted to this.
///
/// Reports whether there was a file to remove.
///
/// # Errors
///
/// [`ArtefactError::Io`] when the file is there and cannot be removed — on a
/// read-only medium, for instance, where the caller has to decide whether that
/// is fatal.
pub fn shred_delivered_key(path: &Path) -> Result<bool, ArtefactError> {
    shred(path)
}

/// Removes a file, reporting whether there was one.
fn remove_if_present(path: &Path) -> Result<bool, ArtefactError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ArtefactError::Io {
            path: path.display().to_string(),
            reason: error.to_string(),
        }),
    }
}

/// Overwrites a file with zeroes before removing it, and reports whether there
/// was one.
///
/// The overwrite is what can be done from user space and no more than that: a
/// journalling or copy-on-write filesystem may keep the previous blocks, and a
/// device leaving the fleet for good deserves the medium destroyed rather than
/// this. It still removes the obvious copy — the one a `dd` of the partition
/// finds — and it costs one write of a few kilobytes.
///
/// # Only ever a regular file, and only the one that was opened
///
/// The path is resolved once, without following a link, and the zeroes go to
/// that descriptor. One of the two callers hands in a path on the medium the
/// package arrived on, and the whole of an import runs between the moment that
/// file was read and the moment it is retired — long enough for the name to
/// become a link to a file of the system. This runs as root, so following such
/// a link would mean the import zeroing `/etc/shadow` on request.
///
/// A path that is not a regular file is therefore left unwritten and only
/// unlinked: removing a planted link takes the plant away without touching
/// whatever it aimed at, and leaving it behind would be leaving the attacker's
/// artefact on the medium.
fn shred(path: &Path) -> Result<bool, ArtefactError> {
    let (mut file, length) = match crate::fs_mode::open_regular_for_overwrite(path) {
        Ok(opened) => opened,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            // Not a regular file, or a link: nothing here may be written
            // through, and the entry itself still goes.
            tracing::warn!(
                target: "codes.audit",
                path = %path.display(),
                error = %error,
                "the delivered key container was not overwritten: it is not a regular file"
            );
            return remove_if_present(path);
        }
    };
    let overwritten = (|| -> io::Result<()> {
        let zeroes = vec![0_u8; 4096];
        let mut left = length;
        while left > 0 {
            let chunk = usize::try_from(left)
                .unwrap_or(usize::MAX)
                .min(zeroes.len());
            let Some(slice) = zeroes.get(..chunk) else {
                break;
            };
            file.write_all(slice)?;
            left = left.saturating_sub(u64::try_from(chunk).unwrap_or(left));
        }
        file.sync_all()
    })();
    if let Err(error) = overwritten {
        // The removal below is what the caller asked for; failing to overwrite
        // first is worth a line in the journal and not a refusal to wipe.
        tracing::warn!(
            target: "codes.audit",
            path = %path.display(),
            error = %error,
            "failed to overwrite the device key before removing it"
        );
    }
    remove_if_present(path)
}

/// Records a removed artefact under its file name.
fn push_removed(removed: &mut Vec<String>, path: &Path) {
    let name = path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    removed.push(name);
}

#[cfg(all(test, unix))]
#[path = "artefacts_tests.rs"]
mod tests;

// The tests above assert on POSIX modes and so are Unix-only. These are not:
// they are about what happens on a platform that does not carry the method at
// all, and one of them has to run *there* to mean anything.
#[cfg(test)]
mod platform_tests {
    #![expect(
        clippy::unwrap_used,
        reason = "a failed setup step in a test should fail the test on the spot"
    )]

    use std::path::PathBuf;

    use super::{apply, CodesDelivery, CodesPaths, StoreCheck};

    /// A store rooted at a directory that does not exist yet.
    ///
    /// The nesting is the whole point. `CodesPaths::under(dir.path())` would put
    /// the store root *at* the temporary directory, which the harness has just
    /// created — and then "the import created no store" could never be asserted,
    /// because the directory is there either way. The root returned here is
    /// created by nothing but `ensure_store_dirs`.
    fn store_under_a_fresh_root() -> (tempfile::TempDir, PathBuf, CodesPaths) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("codes");
        let paths = CodesPaths::under(&root);
        assert!(
            !root.exists(),
            "the fixture is wrong if the store root exists before the import"
        );
        (dir, root, paths)
    }

    /// A package with no Codes part, applied on any platform whatsoever.
    ///
    /// This is the Access-only import, and it has nothing to do with the code
    /// method: it must keep working where the method cannot be carried, and it
    /// must leave no store behind on its way through.
    #[test]
    fn an_empty_delivery_changes_nothing_on_any_platform() {
        let (_dir, root, paths) = store_under_a_fresh_root();

        let applied = apply(
            &paths,
            &CodesDelivery::default(),
            None,
            StoreCheck::Enforced,
            None,
        )
        .unwrap();

        assert_eq!(applied.epoch, None);
        assert!(!applied.key_replaced);
        assert!(
            !root.exists(),
            "an import that carries no Codes part leaves no trace of the method"
        );
    }

    /// A consignment that arrives where the method cannot run.
    ///
    /// The refusal has to come before the store is made. The import that created
    /// its directories and then failed on their permissions left litter from an
    /// operation that could never have finished, and told the operator about an
    /// I/O fault rather than about the platform.
    #[test]
    #[cfg(not(unix))]
    fn a_consignment_is_refused_before_the_store_is_created() {
        let (_dir, root, paths) = store_under_a_fresh_root();
        let delivery = CodesDelivery {
            tickets: Some(b"anything at all".to_vec()),
            ..CodesDelivery::default()
        };

        let error = apply(&paths, &delivery, None, StoreCheck::Enforced, None).unwrap_err();

        assert!(
            matches!(error, super::ArtefactError::UnsupportedPlatform(_)),
            "the platform is the reason, and it is not an I/O fault: {error:?}"
        );
        assert!(
            !root.exists(),
            "a refused import creates no store directory"
        );
        assert!(
            !paths.state_dir.exists(),
            "a refused import creates no state directory"
        );
    }
}

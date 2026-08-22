//! The chain itself: storage trait, the append point, and the fail-closed rule
//! that in-memory state advances only after a durable write.

use std::marker::PhantomData;

use crate::payload::{genesis_hash, sha256, ChainPayload, Entry};
use crate::storage::{ChainLock, NoLock};
use crate::verify::{verify_lines, ChainReport};

/// Failure of a chain append, read, or encoding.
///
/// Every one of these is a refusal, never a shrug: the caller decides whether
/// the action behind the record may still proceed, and a journal whose record is
/// load-bearing answers "no".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// The backing storage could not append or read (permissions, disk, a
    /// browser-side failure).
    #[error("journal storage unavailable: {0}")]
    Storage(String),
    /// A record could not be serialized to NDJSON.
    #[error("journal record encoding failed: {0}")]
    Encoding(String),
    /// An annotation was appended with an empty `kind`. The `kind` is the
    /// writer's namespace tag and MUST identify who wrote the annotation, so an
    /// empty one is rejected before it reaches the chain.
    #[error("annotation kind must not be empty")]
    EmptyAnnotationKind,
    /// An annotation's `data` was not a JSON object. The format promises an
    /// object (a null, array, or scalar would let writers smuggle a bare value
    /// past the contract), so a non-object is rejected before it reaches the
    /// chain.
    #[error("annotation data must be a JSON object")]
    AnnotationDataNotObject,
}

/// Append-only storage backing a [`Chain`].
///
/// The chain works only with record lines and owns no framing: a native caller
/// backs this with a file, the browser cabinet with its own persistence.
/// Implementations MUST persist an appended line before returning `Ok`, and MUST
/// return the lines from [`read_lines`](ChainStorage::read_lines) in append
/// order.
pub trait ChainStorage {
    /// Appends one record line. The line carries no trailing newline; the
    /// storage owns line framing.
    ///
    /// # Errors
    ///
    /// [`ChainError::Storage`] if the line could not be durably appended.
    fn append(&mut self, line: &str) -> Result<(), ChainError>;

    /// Reads every record line, in append order.
    ///
    /// # Errors
    ///
    /// [`ChainError::Storage`] if the records could not be read.
    fn read_lines(&self) -> Result<Vec<String>, ChainError>;

    /// Reads the last record line, or [`None`] for an empty chain.
    ///
    /// The append path wants the tail and nothing else, and it runs on every
    /// login. The default reads everything and takes the last, which is correct
    /// for a store that is already in memory; a file backend overrides it and
    /// seeks from the end instead.
    ///
    /// # Errors
    ///
    /// [`ChainError::Storage`] if the records could not be read.
    fn tail(&self) -> Result<Option<String>, ChainError> {
        Ok(self.read_lines()?.pop())
    }

    /// Takes an exclusive hold for the length of one append transaction.
    ///
    /// The hold must cover reading the tail **and** the write that follows it.
    /// Locking the write alone fixes nothing: two processes that read the same
    /// tail write two lines claiming the same position, and neither write is
    /// torn — the chain is simply broken from there on, silently and for good.
    ///
    /// A store that cannot be reached by a second process needs none, which is
    /// what the default returns.
    ///
    /// # Errors
    ///
    /// [`ChainError::Storage`] when the hold could not be taken, including when
    /// another process held it past the backend's patience. That is a refusal,
    /// and a caller whose record is load-bearing refuses with it.
    fn lock(&self) -> Result<Box<dyn ChainLock>, ChainError> {
        Ok(Box::new(NoLock))
    }
}

/// An append-only, hash-chained journal of payload `P` over a [`ChainStorage`].
///
/// [`Chain::load`] resumes an existing chain (or starts an empty one) and
/// [`Chain::append`] extends it. In-memory state (`next_seq`, `head`) advances
/// only after a durable append, so a storage failure leaves the chain exactly as
/// it was and a caller that refuses the action on error leaves neither the
/// action nor a record of it.
#[derive(Debug)]
pub struct Chain<S: ChainStorage, P: ChainPayload> {
    storage: S,
    next_seq: u64,
    head: [u8; 32],
    payload: PhantomData<fn() -> P>,
}

impl<S: ChainStorage, P: ChainPayload> Chain<S, P> {
    /// Opens the chain over `storage`, resuming from its current tail.
    ///
    /// New lines chain from the physical last line. A stored line that was
    /// tampered with is reported by [`Chain::verify`], not here: `load` only
    /// positions the append point, and refusing to open a broken journal would
    /// mean a tampered file also stops it recording what happens next.
    ///
    /// # Errors
    ///
    /// [`ChainError::Storage`] if the existing records cannot be read.
    pub fn load(storage: S) -> Result<Self, ChainError> {
        let (next_seq, head) = position_from_tail::<P>(storage.tail()?)?;
        Ok(Self {
            storage,
            next_seq,
            head,
            payload: PhantomData,
        })
    }

    /// The current head: SHA-256 of the last appended line, or the genesis
    /// anchor for an empty chain. This is the value a head signature covers.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// The `seq` the next appended line will carry.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Borrows the backing storage (to read lines out for verification).
    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Borrows the backing storage mutably.
    ///
    /// Needed by storages that carry state of their own — a size counter for a
    /// journal with a ceiling, for one — and never by the chain itself.
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    /// Encodes and appends one line, advancing chain state only on success.
    ///
    /// # Errors
    ///
    /// [`ChainError::Encoding`] if the payload cannot be serialized, or
    /// [`ChainError::Storage`] if the line cannot be durably appended. On either
    /// the chain is left exactly as it was.
    pub fn append(&mut self, payload: &P, now_unix: u64) -> Result<(), ChainError> {
        // The hold covers the tail read below and the write after it. Anything
        // narrower — a lock around the write alone, or trusting the position
        // this chain cached when it was opened — lets two processes append at
        // the same position, which breaks the chain from there on and says
        // nothing about it.
        let _hold = self.storage.lock()?;

        // Re-read rather than trust `self`: between opening this chain and now
        // another process may have appended, and on a device where `sshd` forks
        // per connection that is the ordinary case, not the exotic one.
        let (next_seq, head) = position_from_tail::<P>(self.storage.tail()?)?;
        self.next_seq = next_seq;
        self.head = head;

        let entry = Entry {
            seq: self.next_seq,
            prev_hash: hex::encode(self.head),
            ts: now_unix,
            payload: payload.clone(),
        };
        let line =
            serde_json::to_string(&entry).map_err(|e| ChainError::Encoding(e.to_string()))?;
        // Fail-closed: on an append error `head` and `next_seq` are left
        // untouched, so a caller that refuses the action leaves no half-record.
        self.storage.append(&line)?;
        self.head = sha256(line.as_bytes());
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(())
    }

    /// Verifies the chain from its own storage.
    ///
    /// # Errors
    ///
    /// [`ChainError::Storage`] if the records cannot be read.
    pub fn verify(&self) -> Result<ChainReport, ChainError> {
        Ok(verify_lines::<P>(&self.storage.read_lines()?))
    }
}

/// Where the next line goes, worked out from the last one that is there.
///
/// The position comes from the tail's own `seq` rather than from a count of
/// lines: counting means reading the whole journal, and this runs on the
/// authentication path.
///
/// A tail that cannot be parsed is a refusal, not a fresh chain. The two must
/// never lead to the same place — "somebody edited this" and "this device has
/// recorded nothing yet" are different facts, and appending onto a tail nobody
/// can read would build the new history on top of the damage.
fn position_from_tail<P: ChainPayload>(
    tail: Option<String>,
) -> Result<(u64, [u8; 32]), ChainError> {
    let Some(line) = tail else {
        return Ok((0, genesis_hash::<P>()));
    };
    let entry: Entry<P> = serde_json::from_str(&line).map_err(|error| {
        ChainError::Storage(format!(
            "the last record of this journal cannot be read, so nothing may be appended after it: {error}"
        ))
    })?;
    Ok((entry.seq.saturating_add(1), sha256(line.as_bytes())))
}

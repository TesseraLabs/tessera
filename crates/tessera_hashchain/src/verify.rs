//! Verification: recompute the chain from genesis and say where it first
//! stopped adding up.

use crate::payload::{decode_hash, genesis_hash, sha256, ChainPayload, Entry, EntryKind};

/// The outcome of verifying a chain.
///
/// The three states are deliberately not two. "Intact, but the tail is not yet
/// covered by a signature" is the ordinary state of a live journal, and folding
/// it into "broken" would teach an operator to ignore the word.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainStatus {
    /// The chain is intact and every line is covered by a later head signature.
    Intact,
    /// The chain is intact, but the lines after the last head signature — or all
    /// of them, if none is signed — are not covered by one yet.
    IntactUnsignedTail {
        /// The `seq` of the first line in the unsigned tail.
        unsigned_from_seq: u64,
    },
    /// The chain is broken: the line at `position` (its index, which is also the
    /// `seq` it was obliged to carry) is missing, reordered, or altered.
    Broken {
        /// Zero-based position of the first invalid line.
        position: u64,
    },
}

/// A verification result: the [`ChainStatus`] plus summary counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// The chain status.
    pub status: ChainStatus,
    /// How many lines were examined.
    pub entry_count: u64,
    /// The `seq` of the last head-signature line, if any.
    pub last_signed_seq: Option<u64>,
}

/// Verifies `lines` (in append order) against the chain rules of payload `P`.
///
/// Recomputes the hash chain from `P`'s genesis anchor, checks that `seq` is
/// dense and monotonic from 0, and classifies the tail as signed or not. On the
/// first altered, reordered, missing, or malformed line it returns
/// [`ChainStatus::Broken`] with that position — which is what "where did this
/// stop being a history" means in practice: the position is both the index in
/// the file and the `seq` the line should have carried.
///
/// The *cryptographic* validity of a head signature is not checked here: it
/// needs a public key this crate has no way to obtain. A signed tail therefore
/// means only that a head-signature line structurally covers it.
///
/// A line whose payload parses but that the journal's own
/// [`ChainPayload::is_structurally_valid`] rejects is [`ChainStatus::Broken`] at
/// its position: parsing says the types admit it, that method says the format
/// does.
#[must_use]
pub fn verify_lines<P: ChainPayload>(lines: &[String]) -> ChainReport {
    let mut expected_prev = genesis_hash::<P>();
    let mut last_signed_seq: Option<u64> = None;
    let mut unsigned_from: Option<u64> = None;

    for (index, line) in lines.iter().enumerate() {
        let position = index as u64;
        let broken = |last_signed_seq| ChainReport {
            status: ChainStatus::Broken { position },
            entry_count: lines.len() as u64,
            last_signed_seq,
        };

        let Ok(entry) = serde_json::from_str::<Entry<P>>(line) else {
            return broken(last_signed_seq);
        };
        if entry.seq != position {
            return broken(last_signed_seq);
        }
        let Some(prev) = decode_hash(&entry.prev_hash) else {
            return broken(last_signed_seq);
        };
        if prev != expected_prev {
            return broken(last_signed_seq);
        }
        if !entry.payload.is_structurally_valid() {
            return broken(last_signed_seq);
        }

        match entry.payload.kind() {
            EntryKind::HeadSignature => {
                last_signed_seq = Some(entry.seq);
                unsigned_from = None;
            }
            EntryKind::Record => {
                if unsigned_from.is_none() {
                    unsigned_from = Some(entry.seq);
                }
            }
        }
        expected_prev = sha256(line.as_bytes());
    }

    let status = match unsigned_from {
        Some(seq) => ChainStatus::IntactUnsignedTail {
            unsigned_from_seq: seq,
        },
        None => ChainStatus::Intact,
    };
    ChainReport {
        status,
        entry_count: lines.len() as u64,
        last_signed_seq,
    }
}

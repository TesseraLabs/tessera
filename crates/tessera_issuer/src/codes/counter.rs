//! Control of the nonce counter: which challenge an operator may answer at all.
//!
//! A device counts its challenges. The receipts an operator wrote for that
//! device therefore say where the device was the last time somebody answered
//! it, and a challenge that does not sit next to that place is not a challenge
//! from the device as it was left:
//!
//! - **ahead** — the device produced challenges nobody answered, and the
//!   operator is being handed one of them to turn into a code that will still
//!   fit later: a code stockpiled for the future;
//! - **behind, same epoch** — either the call is a recording being played back,
//!   or the device was rolled back from a snapshot without the epoch change a
//!   rollback owes, and then the code issued now replays deterministically;
//! - **equal to the last answered** — the previous call dropped before the code
//!   was read out, and the engineer is reading the same challenge again. Allowed,
//!   and marked, because a repetition that is normal once is a pattern when it
//!   is not.
//!
//! The only silent case is the counter one step past the last receipt: that is
//! a device that advanced once, as it does for every challenge.
//!
//! Nothing here reads a file or a clock. What the receipts of a device say is
//! [`KnownCounter`], and the caller supplies it.

use tessera_codes_contract::key::Epoch;

/// The first counter a device issues in a key epoch.
///
/// A freshly enrolled device, and a device whose epoch has just been rotated,
/// answers its first challenge with this counter; the device side starts at one
/// rather than zero (`tessera_core::codes::state`). It matters here because a
/// device with no receipts at all may only be met at exactly this value — a
/// larger one means challenges nobody wrote a receipt for.
pub const EPOCH_INITIAL_COUNTER: u64 = 1;

/// Where the history of one device says it was left.
///
/// The nonce travels beside the counter because the counter alone cannot tell a
/// dropped call from a second challenge: a device that was restarted draws a new
/// nonce on the same counter, and answering both would put two codes on one
/// counter — the thing the counter exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownCounter {
    /// Key epoch of the last issuance.
    pub epoch: Epoch,
    /// Nonce counter of the last issuance.
    pub counter: u64,
    /// Nonce of the last issuance, exactly as it was answered.
    pub nonce: String,
}

/// What the counter of an accepted challenge says about the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CounterNote {
    /// No receipt exists for this device yet, and the challenge is the first of
    /// the epoch.
    FirstOfEpoch,
    /// The epoch has moved on since the last receipt, and the challenge is the
    /// first of the new one.
    NewEpoch,
    /// The device advanced by one since the last receipt — the ordinary call.
    Advanced,
    /// The challenge repeats the one the last receipt was written for: a call
    /// that dropped before the code was read out.
    RepeatedCall,
    /// The refusal was overridden by a second operator.
    Overridden,
}

impl CounterNote {
    /// The token this note is written under in a receipt annex and a journal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstOfEpoch => "first_of_epoch",
            Self::NewEpoch => "new_epoch",
            Self::Advanced => "advanced",
            Self::RepeatedCall => "repeated_call",
            Self::Overridden => "overridden",
        }
    }

    /// Parses a note written by [`CounterNote::as_str`].
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        [
            Self::FirstOfEpoch,
            Self::NewEpoch,
            Self::Advanced,
            Self::RepeatedCall,
            Self::Overridden,
        ]
        .into_iter()
        .find(|note| note.as_str() == token)
    }
}

/// Why a challenge was refused on its counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CounterRefusal {
    /// The counter runs ahead of the last receipt by more than one step.
    #[error("the challenge counter {got} runs ahead of the last receipted {known}: a code issued now fits a challenge that has not been made yet")]
    Ahead {
        /// Counter of the last receipt.
        known: u64,
        /// Counter the challenge carries.
        got: u64,
    },
    /// The counter is behind the last receipt within the same epoch.
    #[error("the challenge counter {got} is behind the last receipted {known} in the same epoch: a recorded call, or a device rolled back without an epoch change")]
    Behind {
        /// Counter of the last receipt.
        known: u64,
        /// Counter the challenge carries.
        got: u64,
    },
    /// The epoch of the challenge is older than the epoch of the last receipt.
    #[error("the challenge is for key epoch {got}, older than the receipted epoch {known}")]
    EpochBehind {
        /// Epoch of the last receipt.
        known: u32,
        /// Epoch the challenge carries.
        got: u32,
    },
    /// The counter repeats the last one with a different nonce.
    #[error("the challenge repeats counter {counter} with a nonce other than the one already answered: a dropped call reads the same challenge back, a new one advances the counter")]
    ReusedCounter {
        /// Counter both challenges carry.
        counter: u64,
    },
    /// A new epoch, or a device with no receipts, met at a counter other than
    /// the first of the epoch.
    #[error("the first challenge of a key epoch carries counter {EPOCH_INITIAL_COUNTER}, this one carries {got}: challenges of this epoch were answered without a receipt")]
    NotEpochStart {
        /// Counter the challenge carries.
        got: u64,
    },
}

impl CounterRefusal {
    /// The stable class token of this refusal, as
    /// [`Refusal::class`](crate::codes::Refusal::class) reports it.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Ahead { .. } => "counter_ahead",
            Self::ReusedCounter { .. } => "counter_reused",
            Self::Behind { .. } => "counter_behind",
            Self::EpochBehind { .. } => "counter_epoch_behind",
            Self::NotEpochStart { .. } => "counter_not_epoch_start",
        }
    }
}

/// Decides whether a challenge may be answered, from the receipts of its
/// device.
///
/// `known` is [`None`] when no receipt exists for the device.
///
/// # Errors
///
/// The [`CounterRefusal`] describing how the challenge parts from the receipts.
/// A refusal is not overridden here: the override is a decision of two people
/// and is applied by [`override_refusal`], which records who made it.
pub fn assess(
    epoch: Epoch,
    counter: u64,
    nonce: &str,
    known: Option<&KnownCounter>,
) -> Result<CounterNote, CounterRefusal> {
    let Some(known) = known else {
        return first_of_epoch(counter, CounterNote::FirstOfEpoch);
    };

    if epoch < known.epoch {
        return Err(CounterRefusal::EpochBehind {
            known: known.epoch.get(),
            got: epoch.get(),
        });
    }
    if epoch > known.epoch {
        return first_of_epoch(counter, CounterNote::NewEpoch);
    }

    if counter == known.counter {
        // A dropped call reads the *same* challenge back. A different nonce on
        // the same counter is a second challenge, and answering it would put two
        // codes on one counter.
        if nonce == known.nonce {
            return Ok(CounterNote::RepeatedCall);
        }
        return Err(CounterRefusal::ReusedCounter { counter });
    }
    if counter == known.counter.saturating_add(1) {
        return Ok(CounterNote::Advanced);
    }
    if counter > known.counter {
        return Err(CounterRefusal::Ahead {
            known: known.counter,
            got: counter,
        });
    }
    Err(CounterRefusal::Behind {
        known: known.counter,
        got: counter,
    })
}

/// The decision of a second operator to answer a challenge the counter refused.
///
/// The value carries who made it. There is no way to spell an override without
/// naming somebody: an override nobody signed for is exactly the quiet bypass
/// the counter control exists to prevent, and a flag on its own would be one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterOverride {
    approver: String,
}

impl CounterOverride {
    /// Records the second operator who approved the override.
    ///
    /// # Errors
    ///
    /// Returns [`OverrideError::NoApprover`] when the identifier is empty or
    /// only whitespace, and [`OverrideError::ApproverIsSelf`] when it names the
    /// operator handling the call — an approval by the same person is not a
    /// second pair of eyes.
    pub fn by(approver: &str, operator_id: &str) -> Result<Self, OverrideError> {
        let approver = approver.trim();
        if approver.is_empty() {
            return Err(OverrideError::NoApprover);
        }
        if approver == operator_id.trim() {
            return Err(OverrideError::ApproverIsSelf);
        }
        Ok(Self {
            approver: approver.to_owned(),
        })
    }

    /// Returns the identifier of the approving operator.
    #[must_use]
    pub fn approver(&self) -> &str {
        &self.approver
    }
}

/// Why an override was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OverrideError {
    /// No second operator was named.
    #[error("an override names the second operator who approved it")]
    NoApprover,
    /// The approver is the operator handling the call.
    #[error("the approving operator is the one handling the call; four eyes are two people")]
    ApproverIsSelf,
}

/// Applies an override to a refused counter, or reports the refusal unchanged.
///
/// The note that comes back is [`CounterNote::Overridden`], and it travels into
/// the receipt and the journal — an overridden issuance is legible as one
/// afterwards, which is the whole point of allowing it at all.
///
/// # Errors
///
/// The original [`CounterRefusal`] when no override was supplied.
pub fn override_refusal(
    refusal: CounterRefusal,
    decision: Option<&CounterOverride>,
) -> Result<CounterNote, CounterRefusal> {
    match decision {
        Some(_) => Ok(CounterNote::Overridden),
        None => Err(refusal),
    }
}

/// The rule for a device whose epoch has no receipts: the first counter of the
/// epoch and nothing else.
fn first_of_epoch(counter: u64, note: CounterNote) -> Result<CounterNote, CounterRefusal> {
    if counter == EPOCH_INITIAL_COUNTER {
        Ok(note)
    } else {
        Err(CounterRefusal::NotEpochStart { got: counter })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assess, override_refusal, CounterNote, CounterOverride, CounterRefusal, KnownCounter,
        OverrideError, EPOCH_INITIAL_COUNTER,
    };
    use tessera_codes_contract::key::Epoch;

    /// Нонс истории: счётчик, дополненный до ширины по умолчанию, и хвост.
    fn nonce_of(counter: u64) -> String {
        format!("{counter:0>6}4711")
    }

    fn known(epoch: u32, counter: u64) -> KnownCounter {
        KnownCounter {
            epoch: Epoch::new(epoch),
            counter,
            nonce: nonce_of(counter),
        }
    }

    #[test]
    fn a_device_without_receipts_is_met_only_at_the_first_counter() {
        assert_eq!(
            assess(
                Epoch::new(3),
                EPOCH_INITIAL_COUNTER,
                &nonce_of(EPOCH_INITIAL_COUNTER),
                None
            ),
            Ok(CounterNote::FirstOfEpoch)
        );
        assert_eq!(
            assess(Epoch::new(3), 42, &nonce_of(42), None),
            Err(CounterRefusal::NotEpochStart { got: 42 })
        );
    }

    #[test]
    fn the_ordinary_call_advances_by_one() {
        assert_eq!(
            assess(Epoch::new(3), 8, &nonce_of(8), Some(&known(3, 7))),
            Ok(CounterNote::Advanced)
        );
    }

    #[test]
    fn a_repeated_challenge_is_allowed_and_marked() {
        assert_eq!(
            assess(Epoch::new(3), 7, &nonce_of(7), Some(&known(3, 7))),
            Ok(CounterNote::RepeatedCall)
        );
    }

    #[test]
    fn a_counter_running_ahead_is_refused() {
        assert_eq!(
            assess(Epoch::new(3), 12, &nonce_of(12), Some(&known(3, 7))),
            Err(CounterRefusal::Ahead { known: 7, got: 12 })
        );
    }

    #[test]
    fn a_counter_falling_behind_is_refused() {
        assert_eq!(
            assess(Epoch::new(3), 5, &nonce_of(5), Some(&known(3, 7))),
            Err(CounterRefusal::Behind { known: 7, got: 5 })
        );
    }

    #[test]
    fn a_new_epoch_starts_at_the_first_counter_and_nowhere_else() {
        assert_eq!(
            assess(
                Epoch::new(4),
                EPOCH_INITIAL_COUNTER,
                &nonce_of(EPOCH_INITIAL_COUNTER),
                Some(&known(3, 7))
            ),
            Ok(CounterNote::NewEpoch)
        );
        assert_eq!(
            assess(Epoch::new(4), 2, &nonce_of(2), Some(&known(3, 7))),
            Err(CounterRefusal::NotEpochStart { got: 2 })
        );
    }

    #[test]
    fn an_older_epoch_is_refused() {
        assert_eq!(
            assess(
                Epoch::new(2),
                EPOCH_INITIAL_COUNTER,
                &nonce_of(EPOCH_INITIAL_COUNTER),
                Some(&known(3, 7))
            ),
            Err(CounterRefusal::EpochBehind { known: 3, got: 2 })
        );
    }

    #[test]
    fn an_override_needs_a_second_person() {
        assert_eq!(
            CounterOverride::by("  ", "op-42"),
            Err(OverrideError::NoApprover)
        );
        assert_eq!(
            CounterOverride::by("op-42", "op-42"),
            Err(OverrideError::ApproverIsSelf)
        );
        assert_eq!(
            CounterOverride::by(" op-7 ", "op-42").map(|d| d.approver().to_owned()),
            Ok("op-7".to_owned())
        );
    }

    #[test]
    fn without_an_override_the_refusal_stands() {
        let refusal = CounterRefusal::Ahead { known: 7, got: 12 };
        assert_eq!(override_refusal(refusal, None), Err(refusal));
    }

    #[test]
    fn an_override_is_always_marked() {
        let refusal = CounterRefusal::Ahead { known: 7, got: 12 };
        let decision = CounterOverride::by("op-7", "op-42").ok();
        assert_eq!(
            override_refusal(refusal, decision.as_ref()),
            Ok(CounterNote::Overridden)
        );
    }

    #[test]
    fn every_note_survives_a_round_trip_through_its_token() {
        for note in [
            CounterNote::FirstOfEpoch,
            CounterNote::NewEpoch,
            CounterNote::Advanced,
            CounterNote::RepeatedCall,
            CounterNote::Overridden,
        ] {
            assert_eq!(CounterNote::parse(note.as_str()), Some(note));
        }
        assert_eq!(CounterNote::parse("whatever"), None);
    }
}

//! What a device says it did with an attempt.
//!
//! Three words, and both sides of the channel have to mean the same thing by
//! them: the device writes one into every journal record of a code login, and
//! the reconciliation of an audit reads it to tell an admission from a refusal.
//!
//! They live here, in the crate both sides already depend on, rather than in
//! the device and again in the reader. A value copied into two places is the
//! shape of defect this project has already paid for once — a constant spelled
//! wrong in five agreeing places, where every copy confirmed the others and no
//! internal check could see it. One definition cannot disagree with itself.

/// The attempt was answered and the session was opened.
pub const OUTCOME_SUCCESS: &str = "success";

/// The attempt was refused: a wrong code, a request no ticket covers, a state
/// no login proceeds from.
///
/// A refusal is not an admission and must not be read as one. A refused attempt
/// costs the engineer one of the tries the nonce allows, so several of them
/// against one nonce is ordinary — an engineer mistyping a code — and not a
/// device answering one challenge twice.
pub const OUTCOME_DENIED: &str = "denied";

/// The attempt is over because the tries the nonce allowed ran out.
///
/// Also a refusal, and the last one this nonce can carry.
pub const OUTCOME_ATTEMPTS_EXHAUSTED: &str = "attempts_exhausted";

/// What a reader of this vocabulary can say about one word.
///
/// Three cases and not two. A yes-or-no question about admission has a silent
/// default — everything that is not a success becomes a refusal — and that
/// default is where a reader stops being able to say "I do not know". A journal
/// written by a build whose vocabulary is wider than this one, or a fourth word
/// added here and not taught to a reader, would then turn admissions into
/// refusals without a single edit: the sessions really opened, and the reader
/// reports none of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The attempt was answered and a session was opened.
    Admission,
    /// The attempt was refused, in one of the ways this vocabulary knows.
    Refusal,
    /// A word this vocabulary does not carry.
    ///
    /// Not a refusal. A reader that meets one cannot say what happened, and
    /// what it does about that is its own business — but it may not decide
    /// silently, because the answer it would default to is the one that hides
    /// findings rather than the one that raises them.
    Unknown,
}

/// Classifies one outcome word.
///
/// The one place a fourth word gets classified: readers ask this instead of
/// comparing against [`OUTCOME_SUCCESS`] themselves, so teaching the vocabulary
/// a new word is an edit here and nowhere else.
#[must_use]
pub fn classify(outcome: &str) -> Outcome {
    match outcome {
        OUTCOME_SUCCESS => Outcome::Admission,
        OUTCOME_DENIED | OUTCOME_ATTEMPTS_EXHAUSTED => Outcome::Refusal,
        _ => Outcome::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, Outcome, OUTCOME_ATTEMPTS_EXHAUSTED, OUTCOME_DENIED, OUTCOME_SUCCESS};

    #[test]
    fn each_word_of_the_vocabulary_lands_where_it_belongs() {
        assert_eq!(classify(OUTCOME_SUCCESS), Outcome::Admission);
        assert_eq!(classify(OUTCOME_DENIED), Outcome::Refusal);
        assert_eq!(classify(OUTCOME_ATTEMPTS_EXHAUSTED), Outcome::Refusal);
    }

    #[test]
    fn a_word_the_vocabulary_does_not_carry_is_neither() {
        // Neither, and that is the whole point: as a refusal it would hide a
        // session that was opened, and as an admission it would invent one.
        for word in ["granted", "success_after_retry", "", "SUCCESS"] {
            assert_eq!(classify(word), Outcome::Unknown, "word: {word:?}");
        }
    }
}

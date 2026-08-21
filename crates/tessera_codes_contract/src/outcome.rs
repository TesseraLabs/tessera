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

/// Reports whether an outcome says a session was opened.
///
/// Written as a question about admission rather than a comparison against
/// [`OUTCOME_SUCCESS`], so that a fourth word added to this vocabulary has one
/// place to be classified in instead of every reader deciding for itself.
#[must_use]
pub fn is_admission(outcome: &str) -> bool {
    outcome == OUTCOME_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{is_admission, OUTCOME_ATTEMPTS_EXHAUSTED, OUTCOME_DENIED, OUTCOME_SUCCESS};

    #[test]
    fn only_a_success_is_an_admission() {
        assert!(is_admission(OUTCOME_SUCCESS));
        assert!(!is_admission(OUTCOME_DENIED));
        assert!(!is_admission(OUTCOME_ATTEMPTS_EXHAUSTED));
        // An outcome this vocabulary does not know is not an admission: a
        // reader that guessed would turn an unknown word into an open session.
        assert!(!is_admission("granted"));
        assert!(!is_admission(""));
    }
}

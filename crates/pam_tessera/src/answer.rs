//! What a person typed, held so that dropping it is enough.
//!
//! Every visible prompt of a login returns one of these. The type exists
//! because of where the values come from and where they end up: the greeter of
//! the target fleet answers the second prompt of a conversation with the
//! contents of its password field, whatever that prompt asked for, so any
//! answer may turn out to be a password — including the ones this module
//! refuses and drops.
//!
//! # Why a type and not a habit
//!
//! The buffer PAM allocates is wiped where PAM allocated it
//! ([`crate::pam_conv`]), and that half was never in doubt. What was is the
//! copy handed back: an ordinary `String` returns its allocation to the
//! allocator with the bytes still in it, and every caller then had to remember
//! to overwrite it — on the path that accepted the value, on the path that
//! refused it, and on the path that threw it away to ask again. One of those
//! three was always going to be forgotten, and the forgotten one leaves a
//! password in the heap of `sshd`, `login` or a display manager for whatever
//! reads that memory next.
//!
//! [`Answer`] removes the choice: the wiping is in the drop, so a caller cannot
//! skip it and cannot be asked to remember it. Callers that keep a value —
//! the account name, the identifier of an issuing side — take an owned copy
//! deliberately and become responsible for that copy, which is the one place
//! the decision belongs.

use std::fmt;
use std::ops::Deref;

use zeroize::Zeroizing;

/// One answer to one visible prompt, overwritten when it goes out of scope.
///
/// Borrowed as a `&str` for every ordinary use (bounds, comparisons, parsing).
/// There is deliberately no way to move the `String` out: a value that left
/// this type would be one nothing wipes, which is the state this type exists to
/// end.
pub struct Answer(Zeroizing<String>);

impl Answer {
    /// Take ownership of what a conversation returned.
    ///
    /// The only constructor, and it is `pub(crate)` on purpose: production
    /// builds these in [`crate::pam_conv`] from the PAM response, and the
    /// scripted conversations of the tests build them from string literals.
    /// Nothing outside this crate has an answer to hold.
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The answer as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// An owned copy of the answer, for a caller that keeps it.
    ///
    /// Named so that keeping a value reads as a decision at the call site. What
    /// happens to the copy is the caller's, and a caller that keeps one has
    /// said why in a comment beside this call.
    #[must_use]
    pub fn to_kept_string(&self) -> String {
        self.0.to_string()
    }
}

impl Deref for Answer {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

/// Prints as a bound and not as a value.
///
/// A `Debug` that showed the text would put an answer into every log line that
/// ever formats a structure containing one — which is exactly the accident this
/// module exists to prevent.
impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer")
            .field("len", &self.0.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bytes_are_overwritten_and_not_merely_released() {
        // Read back THROUGH THE BUFFER, not from the value: a test that asked
        // the `String` what it now holds would pass for a buffer that was only
        // cleared — the length would be zero and the bytes would still be
        // there, one pointer away, which is the whole difference this type is
        // about.
        //
        // Sound because the allocation is still owned: `zeroize` on a `String`
        // overwrites in place and keeps the capacity.
        use zeroize::Zeroize as _;
        let mut held = String::from("a-password-nobody-should-keep");
        let length = held.len();
        let start = held.as_ptr();

        held.zeroize();

        // SAFETY: `held` still owns the allocation `start` points into, and
        // `length` bytes of it were initialised before the overwrite.
        let bytes = unsafe { std::slice::from_raw_parts(start, length) };
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "the buffer kept its bytes: {bytes:?}"
        );
    }

    #[test]
    fn an_answer_reads_as_text_and_prints_as_a_length() {
        let answer = Answer::new("op-42".to_owned());
        assert_eq!(answer.as_str(), "op-42");
        assert_eq!(answer.trim(), "op-42");
        assert_eq!(answer.to_kept_string(), "op-42");
        // The one thing a log line must never get out of this type.
        let printed = format!("{answer:?}");
        assert!(
            !printed.contains("op-42"),
            "Debug printed the answer: {printed}"
        );
        assert!(
            printed.contains('5'),
            "Debug said nothing about it: {printed}"
        );
    }
}

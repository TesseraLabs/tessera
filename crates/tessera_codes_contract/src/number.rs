//! The check character both numbers of the channel are built on.
//!
//! Two kinds of number travel on this channel and both are copied by hand: the
//! number of a device, read off a label, and the personal number of an
//! engineer, typed at a prompt. They share one arithmetic, and they share it
//! from here rather than by one of them borrowing the other's module — a
//! function that computes the engineer's check character out of a file called
//! `device_number` is a pun, and a reader takes a pun for a mistake.
//!
//! # Algorithm
//!
//! The ISO 7064 MOD 37,36 character over the significant characters of the
//! number: digits `0`–`9` and Latin letters `A`–`Z`, taken in order, with
//! lowercase folded to uppercase. Everything else — dashes, spaces, dots, any
//! non-ASCII character — is ignored.
//!
//! That ignoring is a deliberate limit, not an oversight: a number is printed
//! with separators that vary between labels and are retyped freely, so a
//! separator cannot carry meaning. The consequence has to be stated plainly —
//! **an error confined to an ignored character is not caught**, because to this
//! algorithm the two spellings are the same number. A test pins that limit so
//! nobody later reads the guarantee as broader than it is.
//!
//! # What the check character catches, measured
//!
//! EVERY single wrong character changes the result. Every swap of neighbouring
//! characters does too, except one pair — exactly one — for each value the
//! running product can hold. The two characters of that pair are always
//! adjacent in value, counted around the alphabet, so `0` and `Z` are a pair
//! like `I` and `J`. With nothing in front of them it is `I` and `J`; a prefix
//! moves the exception to another pair rather than removing it. One
//! transposition in six hundred and thirty is therefore accepted.
//!
//! The gap is in the shape of the scheme, not in this code. Every multiplier
//! from two to thirty-six was tried in place of the doubling below: not one of
//! them detects every transposition, and this one is already among the best —
//! most are several times worse. What removes the gap is a check character
//! drawn from thirty-seven symbols instead of the body's thirty-six, and that
//! changes the shape of every number a fleet prints. The decision was taken
//! deliberately in September 2026: the format stays, the gap stays, and it is
//! written down here and pinned by name in the tests rather than described as
//! something the scheme does not do.

/// Number of characters the algorithm counts with: `0`–`9` and `A`–`Z`.
const RADIX: u32 = 36;

/// Modulus of the hybrid system, one above the radix.
const MODULUS: u32 = RADIX + 1;

/// A number with nothing for a check character to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the number carries no character a check character could be computed over")]
pub struct EmptyBody;

/// Returns the characters the algorithm counts, folded to uppercase.
///
/// Public because every party to the channel needs it and none of them should
/// write it again: a second folding that disagreed about, say, a non-ASCII
/// digit would put two different numbers into one canonical encoding, and the
/// codes would stop meeting for a reason nobody could see.
#[must_use]
pub fn significant_characters(text: &str) -> String {
    text.chars()
        .map(|symbol| symbol.to_ascii_uppercase())
        .filter(|symbol| symbol.is_ascii_digit() || symbol.is_ascii_uppercase())
        .collect()
}

/// Returns the ISO 7064 MOD 37,36 check character of a number written without
/// one.
///
/// # Errors
///
/// [`EmptyBody`] when the input carries no significant character.
pub fn check_character(body: &str) -> Result<char, EmptyBody> {
    let significant = significant_characters(body);
    if significant.is_empty() {
        return Err(EmptyBody);
    }

    // The hybrid system of ISO 7064: the running product is carried modulo 37
    // while the characters are valued modulo 36, and a sum that lands on zero is
    // lifted to 36. What that does and does not catch is measured in the module
    // documentation above, not asserted here.
    let mut product = RADIX;
    for symbol in significant.chars() {
        let value = symbol.to_digit(RADIX).unwrap_or(0);
        let mut sum = (product + value) % RADIX;
        if sum == 0 {
            sum = RADIX;
        }
        product = (sum * 2) % MODULUS;
    }
    let check = (MODULUS - product) % RADIX;
    // `check` is a remainder modulo the radix, so the character always exists;
    // the fallible form avoids a panic path for a branch that cannot be taken.
    char::from_digit(check, RADIX)
        .map(|symbol| symbol.to_ascii_uppercase())
        .ok_or(EmptyBody)
}

/// Splits significant characters into the body and the check character.
///
/// [`None`] when there are fewer than two: one character alone is a check
/// character over nothing.
#[must_use]
pub fn split_check(significant: &str) -> Option<(&str, char)> {
    let split = significant.len().checked_sub(1).filter(|body| *body > 0)?;
    let (body, tail) = significant.split_at(split);
    Some((body, tail.chars().next()?))
}

#[cfg(test)]
mod tests {
    use super::{check_character, significant_characters, split_check, EmptyBody};

    #[test]
    fn separators_and_case_do_not_change_the_number() {
        assert_eq!(significant_characters("ru-77 / dc-01.42"), "RU77DC0142");
        assert_eq!(significant_characters("ru77dc0142"), "RU77DC0142");
        assert_eq!(check_character("ru-77"), check_character("RU77"));
    }

    #[test]
    fn a_number_of_nothing_has_no_check_character() {
        assert_eq!(check_character("---"), Err(EmptyBody));
        assert_eq!(check_character(""), Err(EmptyBody));
    }

    #[test]
    fn a_lone_character_is_a_check_character_over_nothing() {
        assert_eq!(split_check("A"), None);
        assert_eq!(split_check(""), None);
        assert_eq!(split_check("AB"), Some(("A", 'B')));
    }

    #[test]
    fn the_arithmetic_is_the_one_both_numbers_are_built_on() {
        // Not a round trip through a type: the value itself, so that moving
        // this function between modules cannot change what it computes.
        assert_eq!(check_character("77-000123"), Ok('S'));
        assert_eq!(check_character("ORG1-000001"), Ok('4'));
    }
}

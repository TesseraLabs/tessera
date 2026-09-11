//! The device number and its check character.
//!
//! A device number travels on a label and on a screen: an engineer reads it, an
//! operator types it in. The check character catches the two mistakes that
//! channel produces — one wrong character, and two neighbouring characters
//! swapped — before the wrong device is ever looked up.
//!
//! # Algorithm
//!
//! In [`crate::number`], which the personal number of an engineer is built on
//! too. What it catches and what it does not is measured there.
//!
//! # Where this lives
//!
//! The same validator belongs to the device number identity of the platform.
//! It is implemented here because this crate sits below that one in the
//! dependency order and needs the check character for the phone-channel
//! challenge; the identity work reuses this module rather than writing a second
//! copy.

use crate::number::{self, split_check};

/// A device number carrying its check character.
///
/// The value keeps the number exactly as it was written, separators and all;
/// [`CheckedDeviceNumber::significant`] gives the folded form the algorithm —
/// and any canonical encoding — works on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CheckedDeviceNumber {
    text: String,
    significant: String,
}

impl CheckedDeviceNumber {
    /// Parses a number that already carries its check character as the last
    /// significant character.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceNumberError::TooShort`] when the number holds fewer than
    /// two significant characters — there is nothing for a check character to
    /// protect — and [`DeviceNumberError::CheckCharacterMismatch`] when the
    /// character does not match the rest of the number.
    pub fn parse(text: &str) -> Result<Self, DeviceNumberError> {
        let significant = number::significant_characters(text);
        let (body, got) = split_check(&significant).ok_or(DeviceNumberError::TooShort)?;
        let expected = check_character(body)?;
        if got != expected {
            return Err(DeviceNumberError::CheckCharacterMismatch { expected, got });
        }

        Ok(Self {
            text: text.to_owned(),
            significant,
        })
    }

    /// Builds a number by appending the check character to a number written
    /// without one.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceNumberError::TooShort`] when the number holds no
    /// significant character at all.
    pub fn from_body(body: &str) -> Result<Self, DeviceNumberError> {
        let check = check_character(body)?;
        let mut text = body.to_owned();
        text.push(check);
        let significant = number::significant_characters(&text);
        Ok(Self { text, significant })
    }

    /// Returns the number as it was written, separators included.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the significant characters of the number, folded to uppercase
    /// and with the check character last.
    ///
    /// This is the form that enters a canonical encoding: two labels that print
    /// the same number with different separators must not produce two different
    /// challenges.
    #[must_use]
    pub fn significant(&self) -> &str {
        &self.significant
    }

    /// Returns the check character.
    #[must_use]
    pub fn check_character(&self) -> char {
        // The constructors reject a number without significant characters, so
        // the last one is always there.
        self.significant.chars().next_back().unwrap_or('0')
    }
}

impl core::fmt::Display for CheckedDeviceNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Rejection of a device number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceNumberError {
    /// The number carries too few significant characters to be checked.
    #[error("the device number carries too few characters to carry a check character")]
    TooShort,
    /// The check character does not match the rest of the number.
    #[error("device number check character `{got}` does not match the expected `{expected}`")]
    CheckCharacterMismatch {
        /// Character the algorithm computes over the number.
        expected: char,
        /// Character the number actually carries.
        got: char,
    },
}

/// Returns the ISO 7064 MOD 37,36 check character of a number written without
/// one.
///
/// A device-flavoured name for [`crate::number::check_character`], kept so that
/// a caller working with device numbers gets device-flavoured errors. The
/// arithmetic is not written twice.
///
/// # Errors
///
/// Returns [`DeviceNumberError::TooShort`] when the input carries no
/// significant character.
pub fn check_character(body: &str) -> Result<char, DeviceNumberError> {
    number::check_character(body).map_err(|_| DeviceNumberError::TooShort)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{check_character, CheckedDeviceNumber, DeviceNumberError};

    fn checked(body: &str) -> CheckedDeviceNumber {
        CheckedDeviceNumber::from_body(body).unwrap()
    }

    #[test]
    fn a_computed_check_character_parses_back() {
        let number = checked("77-000123");
        assert_eq!(number.as_str().len(), "77-000123".len() + 1);
        assert_eq!(
            CheckedDeviceNumber::parse(number.as_str())
                .map(|parsed| parsed.significant().to_owned()),
            Ok(number.significant().to_owned())
        );
    }

    #[test]
    fn a_single_substitution_is_caught() {
        let number = checked("77-000123");
        let significant = number.significant().to_owned();
        // Walk every position of the body and every replacement of it.
        let body_len = significant.len() - 1;
        for position in 0..body_len {
            for replacement in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars() {
                let mut damaged: Vec<char> = significant.chars().collect();
                if damaged.get(position).copied() == Some(replacement) {
                    continue;
                }
                if let Some(slot) = damaged.get_mut(position) {
                    *slot = replacement;
                }
                let text: String = damaged.into_iter().collect();
                assert!(
                    matches!(
                        CheckedDeviceNumber::parse(&text),
                        Err(DeviceNumberError::CheckCharacterMismatch { .. })
                    ),
                    "substitution at {position} to `{replacement}` slipped through: {text}"
                );
            }
        }
    }

    const ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /// Does the check character survive swapping the two characters of `body`
    /// at `position`?
    fn transposition_survives(body: &str, position: usize) -> bool {
        let mut swapped: Vec<char> = body.chars().collect();
        swapped.swap(position, position + 1);
        let swapped: String = swapped.into_iter().collect();
        check_character(body) == check_character(&swapped)
    }

    #[test]
    fn a_transposition_of_neighbours_is_caught_except_for_one_pair_per_state() {
        // Exhaustive, and it states the exception rather than avoiding it. The
        // test this replaced swapped neighbours in one number that happened to
        // be lucky, and it would have gone on passing while the channel refused
        // one transposition in six hundred and thirty.
        //
        // The shape of the exception, measured over every pair and every
        // running state: exactly ONE unordered pair survives each state of the
        // running product, and its two characters are always adjacent in value.
        // With nothing in front, the state is the starting one and the pair is
        // `I` and `J`.
        let mut survivors = Vec::new();
        for left in ALPHABET.chars() {
            for right in ALPHABET.chars() {
                if left >= right {
                    continue;
                }
                let body: String = [left, right].into_iter().collect();
                if transposition_survives(&body, 0) {
                    survivors.push((left, right));
                }
            }
        }
        assert_eq!(
            survivors,
            vec![('I', 'J')],
            "the pair that survives an empty prefix is not the one this build was measured to have"
        );
    }

    #[test]
    fn one_pair_survives_after_every_leading_character_and_it_is_a_consecutive_one() {
        // The exception is not a property of the first position, which is where
        // it is easiest to look for and where it was first found. Every state
        // of the running product has one pair of its own, so a prefix moves the
        // exception rather than removing it.
        let values: Vec<char> = ALPHABET.chars().collect();
        for prefix in ALPHABET.chars() {
            let mut survivors = Vec::new();
            for (left_index, left) in values.iter().enumerate() {
                for right in values.iter().skip(left_index + 1) {
                    let body: String = [prefix, *left, *right].into_iter().collect();
                    if transposition_survives(&body, 1) {
                        survivors.push((*left, *right));
                    }
                }
            }
            assert_eq!(
                survivors.len(),
                1,
                "after `{prefix}` the surviving pairs are {survivors:?}, and there should be one"
            );
            let Some((left, right)) = survivors.first() else {
                unreachable!("the assertion above established there is one")
            };
            // Adjacent around the alphabet, not only along it: one state
            // admits `0` and `Z`, which are neighbours the way the arithmetic
            // counts and not the way a reader would.
            let distance = ALPHABET
                .find(*right)
                .zip(ALPHABET.find(*left))
                .map(|(right, left)| (right + ALPHABET.len() - left) % ALPHABET.len());
            assert!(
                distance == Some(1) || distance == Some(ALPHABET.len() - 1),
                "after `{prefix}` the surviving pair `{left}{right}` is not adjacent in value"
            );
        }
    }

    #[test]
    fn the_pair_that_survives_is_named_here_so_that_closing_it_is_noticed() {
        // A regression pinned by name. If the channel ever moves to a check
        // character drawn from a wider alphabet, this test goes red, and
        // somebody removes it deliberately instead of discovering the change by
        // accident six months later.
        assert!(transposition_survives("IJ", 0));
        assert_eq!(check_character("IJ"), check_character("JI"));
        // And a pair that is adjacent in value but not the one this state
        // admits is caught, so the test above is not passing on the width of
        // the alphabet.
        assert!(!transposition_survives("HI", 0));
    }

    #[test]
    fn letters_and_separators_are_handled() {
        let number = checked("ru-77 / dc-01.42");
        assert!(CheckedDeviceNumber::parse(number.as_str()).is_ok());
        assert!(number
            .significant()
            .chars()
            .all(|symbol| symbol.is_ascii_digit() || symbol.is_ascii_uppercase()));
        // Case is folded, so the same number typed in lowercase still parses.
        assert!(CheckedDeviceNumber::parse(&number.as_str().to_lowercase()).is_ok());
    }

    #[test]
    fn an_error_in_an_ignored_character_is_not_caught() {
        // The limit of the algorithm, pinned on purpose: separators carry no
        // weight, so replacing, adding or dropping one changes nothing the
        // check character can see.
        let number = checked("77-000123");
        let respaced = number.as_str().replace('-', " ");
        let unseparated = number.as_str().replace('-', "");
        assert!(CheckedDeviceNumber::parse(&respaced).is_ok());
        assert!(CheckedDeviceNumber::parse(&unseparated).is_ok());
        assert_eq!(
            CheckedDeviceNumber::parse(&respaced)
                .map(|parsed| parsed.significant().to_owned())
                .unwrap_or_default(),
            number.significant()
        );
    }

    #[test]
    fn a_number_without_significant_characters_is_rejected() {
        assert_eq!(check_character("---"), Err(DeviceNumberError::TooShort));
        assert_eq!(
            CheckedDeviceNumber::parse("-4-"),
            Err(DeviceNumberError::TooShort)
        );
    }

    #[test]
    fn the_check_character_is_the_last_significant_one() {
        let number = checked("77-000123");
        assert_eq!(
            Some(number.check_character()),
            number.significant().chars().next_back()
        );
    }
}

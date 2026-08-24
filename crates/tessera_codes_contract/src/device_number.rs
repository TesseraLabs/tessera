//! The device number and its check character.
//!
//! A device number travels over a telephone: an engineer reads it aloud, an
//! operator types it in. The check character catches the two mistakes that
//! channel produces — one wrong character, and two neighbouring characters
//! swapped — before the wrong device is ever looked up.
//!
//! # Algorithm
//!
//! The check character is the ISO 7064 MOD 37,36 character over the significant
//! characters of the number: digits `0`–`9` and Latin letters `A`–`Z`, taken in
//! order, with lowercase folded to uppercase. Everything else — dashes, spaces,
//! dots, any non-ASCII character — is ignored.
//!
//! That ignoring is a deliberate limit, not an oversight: the number is printed
//! with separators that vary between labels and are retyped freely, so a
//! separator cannot carry meaning. The consequence has to be stated plainly —
//! **an error confined to an ignored character is not caught**, because to this
//! algorithm the two spellings are the same number. A test pins that limit so
//! nobody later reads the guarantee as broader than it is.
//!
//! # Where this lives
//!
//! The same validator belongs to the device number identity of the platform.
//! It is implemented here because this crate sits below that one in the
//! dependency order and needs the check character for the phone-channel
//! challenge; the identity work reuses this module rather than writing a second
//! copy.

/// Number of characters the algorithm counts with: `0`–`9` and `A`–`Z`.
const RADIX: u32 = 36;

/// Modulus of the hybrid system, one above the radix.
const MODULUS: u32 = RADIX + 1;

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
        let significant = significant_characters(text);
        let split = significant
            .len()
            .checked_sub(1)
            .filter(|body_len| *body_len > 0)
            .ok_or(DeviceNumberError::TooShort)?;

        let (body, tail) = significant.split_at(split);
        let expected = check_character(body)?;
        let got = tail.chars().next().ok_or(DeviceNumberError::TooShort)?;
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
        let significant = significant_characters(&text);
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
/// # Errors
///
/// Returns [`DeviceNumberError::TooShort`] when the input carries no
/// significant character.
pub fn check_character(body: &str) -> Result<char, DeviceNumberError> {
    let significant = significant_characters(body);
    if significant.is_empty() {
        return Err(DeviceNumberError::TooShort);
    }

    // The hybrid system of ISO 7064: the running product is carried modulo 37
    // while the characters are valued modulo 36, and a sum that lands on zero is
    // lifted to 36. That pairing is what buys the two guarantees the channel
    // needs — every single wrong character and every swap of neighbours changes
    // the result.
    let mut product = RADIX;
    for symbol in significant.chars() {
        let value = char_value(symbol).unwrap_or(0);
        let mut sum = (product + value) % RADIX;
        if sum == 0 {
            sum = RADIX;
        }
        product = (sum * 2) % MODULUS;
    }
    let check = (MODULUS - product) % RADIX;
    // `check` is a remainder modulo the radix, so the character always exists;
    // the fallible form avoids a panic path for a branch that cannot be taken.
    value_char(check).ok_or(DeviceNumberError::TooShort)
}

/// Returns the characters the algorithm counts, folded to uppercase.
fn significant_characters(text: &str) -> String {
    text.chars()
        .map(|symbol| symbol.to_ascii_uppercase())
        .filter(|symbol| symbol.is_ascii_digit() || symbol.is_ascii_uppercase())
        .collect()
}

/// Returns the numeric value of a significant character.
fn char_value(symbol: char) -> Option<u32> {
    symbol.to_digit(RADIX)
}

/// Returns the character for a value below the radix.
fn value_char(value: u32) -> Option<char> {
    char::from_digit(value, RADIX).map(|symbol| symbol.to_ascii_uppercase())
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

    #[test]
    fn a_transposition_of_neighbours_is_caught() {
        let number = checked("A1B2C3D4");
        let significant: Vec<char> = number.significant().chars().collect();
        for position in 0..significant.len() - 2 {
            let mut damaged = significant.clone();
            damaged.swap(position, position + 1);
            if damaged == significant {
                continue;
            }
            let text: String = damaged.into_iter().collect();
            assert!(
                matches!(
                    CheckedDeviceNumber::parse(&text),
                    Err(DeviceNumberError::CheckCharacterMismatch { .. })
                ),
                "transposition at {position} slipped through: {text}"
            );
        }
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

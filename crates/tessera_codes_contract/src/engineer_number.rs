//! The personal number of an engineer, and its check character.
//!
//! The number an engineer types at the device prompt and the server looks up in
//! its registry. It is not a secret and not a factor: it says who stood at the
//! keyboard, and it binds the issued code to that person by entering the MAC
//! input. What it is not evidence of is listed in the decision record of the
//! channel.
//!
//! # Shape
//!
//! An organisation segment, a serial part and a check character:
//!
//! ```text
//! ORG 1000001 4
//! ^^^ ^^^^^^^ ^
//! |   |       check character over everything before it
//! |   serial part, assigned by the owner of the fleet
//! organisation segment
//! ```
//!
//! The boundary is where the letters stop, and that is the whole rule: the
//! segment is the leading run of letters, the serial part is digits. A format
//! whose boundary had to be guessed is a format two implementations guess
//! differently, and this channel has implementations in two languages.
//!
//! The consequence is worth stating because it surprises: the number printed
//! `ORG1-000001` in the fixtures of the stand reads as segment `ORG` and serial
//! `1000001`. The `1` of `ORG1` is written for a person and counted as a
//! serial digit.
//!
//! The segment is what keeps two contractors from assigning one number: the
//! device has no registry of engineers and cannot tell them apart by anything
//! else, so a fleet where the same number named two people would have a journal
//! that attributes a login to nobody in particular.
//!
//! # The segment is a readable prefix, not a key of the organisation
//!
//! Uniqueness belongs to the WHOLE number. Which organisation a person belongs
//! to comes from the signed registry record and the signed authorisation, and
//! from nowhere else; a mapping from segment to organisation is forbidden on
//! the server.
//!
//! Not a matter of taste. Under the rule above, `ORG1-000001` and
//! `ORG2-000001` carry the same segment `ORG` and differ in their serial parts.
//! A reader who took the segment for an organisation key — which is
//! tempting and looks natural — would fold two different contractors into one,
//! and would do it silently, in the place where a journal says who came in.
//!
//! The separator is written for a person and ignored by the arithmetic, like
//! every separator on this channel — `ORG1-0000014` and `org1 000001 4` are the
//! same number. What is *not* free is the shape: a number without a segment, or
//! with a serial part shorter than the format allows, is refused rather than
//! folded into something acceptable.
//!
//! # Why a type of its own
//!
//! The arithmetic is shared with the device number and lives in
//! [`crate::number`], but the two are not the same thing and must not be one
//! type. A device number identifies a machine on a label; this identifies a
//! person in a registry, and a value that could be used as either would let a
//! caller put a device where an engineer belongs and be told nothing.

use crate::number::{self, split_check};

/// Fewest characters an organisation segment may carry.
///
/// Two rather than one: a single character gives thirty-six organisations
/// before a fleet has to change the format of every number it has printed.
const MIN_SEGMENT: usize = 2;

/// Most characters an organisation segment may carry.
const MAX_SEGMENT: usize = 8;

/// Fewest digits a serial part may carry.
///
/// Four, so that a number is legible as a number: a serial of one digit next to
/// a segment of letters reads as a typo, and a person retyping it from a note
/// has nothing to check the length against.
const MIN_SERIAL: usize = 4;

/// Most digits a serial part may carry.
const MAX_SERIAL: usize = 12;

/// The personal number of an engineer, carrying its check character.
///
/// The value keeps the number as it was written, separator and all;
/// [`EngineerNumber::significant`] gives the folded form the arithmetic and any
/// canonical encoding work on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EngineerNumber {
    text: String,
    significant: String,
    segment_len: usize,
}

impl EngineerNumber {
    /// Parses a number that already carries its check character.
    ///
    /// # Errors
    ///
    /// Every way the number can fail to be one — see [`EngineerNumberError`].
    /// The shape is checked before the check character: a string that is not a
    /// personal number at all should be told so, rather than told that its
    /// check character does not match a body it does not have.
    pub fn parse(text: &str) -> Result<Self, EngineerNumberError> {
        let significant = number::significant_characters(text);
        let (body, got) = split_check(&significant).ok_or(EngineerNumberError::TooShort)?;
        let segment_len = check_shape(body)?;
        let expected = number::check_character(body).map_err(|_| EngineerNumberError::TooShort)?;
        if got != expected {
            return Err(EngineerNumberError::CheckCharacterMismatch { expected, got });
        }
        Ok(Self {
            text: text.to_owned(),
            significant,
            segment_len,
        })
    }

    /// Builds a number by appending the check character to a body written
    /// without one.
    ///
    /// # Errors
    ///
    /// As [`EngineerNumber::parse`], short of the mismatch it cannot produce.
    pub fn from_body(body: &str) -> Result<Self, EngineerNumberError> {
        let folded = number::significant_characters(body);
        let segment_len = check_shape(&folded)?;
        let check = number::check_character(&folded).map_err(|_| EngineerNumberError::TooShort)?;
        let mut text = body.to_owned();
        text.push(check);
        let significant = number::significant_characters(&text);
        Ok(Self {
            text,
            significant,
            segment_len,
        })
    }

    /// Returns the number as it was written, separator included.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the significant characters, folded to uppercase, check character
    /// last.
    ///
    /// This is the form that enters a canonical encoding: two spellings of one
    /// number must not produce two different codes.
    #[must_use]
    pub fn significant(&self) -> &str {
        &self.significant
    }

    /// Returns the organisation segment, folded to uppercase.
    #[must_use]
    pub fn organisation_segment(&self) -> &str {
        self.significant.get(..self.segment_len).unwrap_or_default()
    }

    /// Returns the serial part, without the check character.
    #[must_use]
    pub fn serial(&self) -> &str {
        let end = self.significant.len().saturating_sub(1);
        self.significant
            .get(self.segment_len..end)
            .unwrap_or_default()
    }

    /// Returns the check character.
    #[must_use]
    pub fn check_character(&self) -> char {
        // The constructors reject a number without significant characters, so
        // the last one is always there.
        self.significant.chars().next_back().unwrap_or('0')
    }
}

impl core::fmt::Display for EngineerNumber {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Rejection of a personal number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EngineerNumberError {
    /// The number carries too few significant characters to be checked.
    #[error("the personal number carries too few characters to carry a check character")]
    TooShort,

    /// The organisation segment is missing, too short or too long.
    #[error(
        "the organisation segment of a personal number is {got} characters, and it must be \
         between {MIN_SEGMENT} and {MAX_SEGMENT}"
    )]
    Segment {
        /// Characters the segment actually carries.
        got: usize,
    },

    /// The serial part is missing, too short or too long.
    #[error(
        "the serial part of a personal number is {got} digits, and it must be between \
         {MIN_SERIAL} and {MAX_SERIAL}"
    )]
    Serial {
        /// Digits the serial part actually carries.
        got: usize,
    },

    /// The segment does not begin with a letter.
    ///
    /// A number that opened with a digit would be a number whose segment and
    /// serial part cannot be told apart by looking: the boundary is where the
    /// letters stop.
    #[error("the organisation segment of a personal number must begin with a letter")]
    SegmentNotLetterLed,

    /// The check character does not match the rest of the number.
    #[error("personal number check character `{got}` does not match the expected `{expected}`")]
    CheckCharacterMismatch {
        /// Character the algorithm computes over the number.
        expected: char,
        /// Character the number actually carries.
        got: char,
    },
}

/// Checks the shape of a body without its check character, returning the length
/// of the organisation segment.
///
/// The boundary between the segment and the serial part is where the letters
/// stop. That is the whole rule, and it is why the segment must begin with a
/// letter and the serial part must be digits: a format where the boundary had
/// to be guessed would be a format two implementations guess differently.
fn check_shape(body: &str) -> Result<usize, EngineerNumberError> {
    let segment_len = body.chars().take_while(char::is_ascii_uppercase).count();
    if segment_len == 0 {
        return Err(EngineerNumberError::SegmentNotLetterLed);
    }
    if !(MIN_SEGMENT..=MAX_SEGMENT).contains(&segment_len) {
        return Err(EngineerNumberError::Segment { got: segment_len });
    }

    let serial = body.get(segment_len..).unwrap_or_default();
    if !serial.chars().all(|symbol| symbol.is_ascii_digit()) {
        // Letters after the serial part started: the boundary is not where the
        // letters stop after all, so the number has no shape this format names.
        return Err(EngineerNumberError::Serial { got: serial.len() });
    }
    if !(MIN_SERIAL..=MAX_SERIAL).contains(&serial.len()) {
        return Err(EngineerNumberError::Serial { got: serial.len() });
    }
    Ok(segment_len)
}

#[cfg(test)]
mod tests;

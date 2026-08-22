//! The nonce of an attempt: one long random value.
//!
//! A nonce is a run of characters of the fleet alphabet, of the width the fleet
//! parameters fix, drawn from a cryptographic generator. The crate draws none of
//! it: there is no source of randomness inside a WebAssembly module without an
//! environment, and a contract that reaches for one starts depending on it. The
//! value arrives from the caller and is checked here for width and alphabet.
//!
//! # Why there is no counter in it
//!
//! There was one: a monotonic counter, persisted on the device, rendered in
//! front of a random tail. It existed so that a person reading a nonce aloud
//! read a short number, and it paid for that with a persisted value — which
//! brought a hard refusal when the counter ran ahead, a detection of stockpiled
//! challenges, and a rollback check on the device. Dictation is gone, and with
//! it the reason. What is left is what the counter was standing in for: a value
//! wide enough that it does not repeat, and an attempt that exists only in the
//! memory of the device holding it open. A nonce nobody is holding an attempt
//! for is refused because there is no attempt, not because a file remembers the
//! number.
//!
//! The width is what carries that now, so it is bounded by the contract rather
//! than by a fleet: [`MIN_NONCE_ENTROPY_BITS`] states how much randomness a
//! nonce has to carry, and a configuration that asks for less does not parse.

use crate::params::FleetParams;

/// Smallest amount of randomness a nonce must carry, in bits.
///
/// The nonce is the whole of what keeps one attempt from being another: there
/// is no counter beside it any more, and the device holds no record of the
/// values it has used. A hundred and twenty-eight bits is the width at which
/// repetition stops being something a fleet has to reason about, and nothing on
/// this channel pays for it — the value travels in a QR code or a paste buffer,
/// not in somebody's voice.
///
/// The floor is stated in bits rather than in characters because the alphabet is
/// a fleet parameter: the same width buys 3.3 bits per character in decimal and
/// 5 in Crockford base32, so a width that is enough for one is short for the
/// other.
pub const MIN_NONCE_ENTROPY_BITS: u32 = 128;

/// Widest nonce the contract allows, in characters.
///
/// Not a security bound — a longer nonce is no weaker — but a bound on what the
/// documents of the channel have to carry and what a parser has to accept.
pub const MAX_NONCE_WIDTH: u8 = 64;

/// A parsed nonce.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce {
    value: String,
}

impl Nonce {
    /// Checks a drawn value against the fleet parameters.
    ///
    /// The caller draws the value; this is where it becomes a nonce. Both sides
    /// go through here, so a value one side would accept and the other would
    /// not cannot exist.
    ///
    /// # Errors
    ///
    /// Returns [`NonceError::WidthMismatch`] when the value is not exactly as
    /// wide as the parameters say, and [`NonceError::Alphabet`] when it carries
    /// a symbol outside the fleet alphabet. A value of the right width in the
    /// wrong alphabet is refused rather than transliterated: two spellings of
    /// one nonce would be two codes.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, NonceError> {
        let width = usize::from(params.nonce_width());
        let symbols = text.chars().count();
        if symbols != width {
            return Err(NonceError::WidthMismatch {
                expected: params.nonce_width(),
                got: symbols,
            });
        }
        if !text.is_ascii() {
            return Err(NonceError::Alphabet);
        }
        let allowed = params.alphabet().symbols();
        if !text.bytes().all(|symbol| allowed.contains(&symbol)) {
            return Err(NonceError::Alphabet);
        }
        Ok(Self {
            value: text.to_owned(),
        })
    }

    /// Returns the nonce as it travels over the channel.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl core::fmt::Display for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.value)
    }
}

/// Rejection of a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    /// The value is not of the width the parameters fix.
    #[error("nonce width {got} does not match the configured {expected}")]
    WidthMismatch {
        /// Width the parameters describe, in characters.
        expected: u8,
        /// Width that was offered.
        got: usize,
    },
    /// The value carries a symbol outside the fleet alphabet.
    #[error("the nonce carries a symbol outside the configured alphabet")]
    Alphabet,
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{Nonce, NonceError};
    use crate::code::Alphabet;
    use crate::params::{FleetParams, FleetParamsInput};

    fn params() -> FleetParams {
        FleetParams::defaults()
    }

    fn fixture_nonce() -> String {
        "7".repeat(usize::from(params().nonce_width()))
    }

    #[test]
    fn a_value_of_the_configured_width_parses_and_round_trips() {
        let text = fixture_nonce();
        let nonce = Nonce::parse(&text, &params()).unwrap();
        assert_eq!(nonce.as_str(), text);
        assert_eq!(nonce.to_string(), text);
    }

    #[test]
    fn a_shorter_or_longer_value_is_refused() {
        let short = "7".repeat(usize::from(params().nonce_width()) - 1);
        assert!(matches!(
            Nonce::parse(&short, &params()),
            Err(NonceError::WidthMismatch { .. })
        ));
        let long = "7".repeat(usize::from(params().nonce_width()) + 1);
        assert!(matches!(
            Nonce::parse(&long, &params()),
            Err(NonceError::WidthMismatch { .. })
        ));
    }

    #[test]
    fn a_symbol_outside_the_alphabet_is_refused() {
        // A letter under the default base32 fleet is ordinary; `U`, which
        // Crockford leaves out, is not.
        let base32 = params();
        let mut with_letter = "7".repeat(usize::from(base32.nonce_width()) - 1);
        with_letter.push('A');
        assert!(Nonce::parse(&with_letter, &base32).is_ok());

        let mut with_u = "7".repeat(usize::from(base32.nonce_width()) - 1);
        with_u.push('U');
        assert_eq!(Nonce::parse(&with_u, &base32), Err(NonceError::Alphabet));

        // The same letter under a decimal fleet is not a nonce at all.
        let decimal = FleetParams::parse(FleetParamsInput {
            alphabet: Alphabet::Decimal,
            code_len: 8,
            nonce_width: 39,
            ..FleetParamsInput::defaults()
        })
        .unwrap();
        let mut over_decimal = "7".repeat(usize::from(decimal.nonce_width()) - 1);
        over_decimal.push('A');
        assert_eq!(
            Nonce::parse(&over_decimal, &decimal),
            Err(NonceError::Alphabet)
        );
    }

    #[test]
    fn a_non_ascii_value_of_the_right_width_is_refused() {
        // One character each, so the width check passes and the alphabet check
        // is what has to refuse.
        let text = "з".repeat(usize::from(params().nonce_width()));
        assert_eq!(Nonce::parse(&text, &params()), Err(NonceError::Alphabet));
    }
}

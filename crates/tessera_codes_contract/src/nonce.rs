//! The hybrid nonce of the phone channel.
//!
//! A nonce is a monotonic decimal counter of the width the fleet parameters fix,
//! followed by a random tail of the width they fix. The crate does not draw the
//! tail: there is no source of randomness inside a WebAssembly module without an
//! environment, and a contract that reaches for one starts depending on it. The
//! tail arrives from the caller and is checked for width and alphabet.
//!
//! Counter overflow is a distinct error and never a wrap: a device that has run
//! out of counter space owes an epoch rotation, and that has to be visible in
//! the type of the result rather than hidden in a reused nonce.

use crate::params::FleetParams;

/// A parsed hybrid nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    counter: u64,
    counter_width: u8,
    tail: String,
    rendered: String,
}

impl Nonce {
    /// Builds a nonce from a counter value and an externally drawn tail.
    ///
    /// # Errors
    ///
    /// Returns [`NonceError::CounterOverflow`] when the counter does not fit
    /// the configured width, and the tail errors when the tail is of the wrong
    /// width or contains a symbol outside the configured alphabet.
    pub fn new(counter: u64, tail: &str, params: &FleetParams) -> Result<Self, NonceError> {
        let width = params.counter_width();
        if counter >= counter_capacity(width) {
            return Err(NonceError::CounterOverflow {
                width,
                counter_value: counter,
            });
        }
        check_tail(tail, *params)?;

        let rendered = format!(
            "{counter:0width$}{tail}",
            counter = counter,
            width = usize::from(width),
            tail = tail
        );
        Ok(Self {
            counter,
            counter_width: width,
            tail: tail.to_owned(),
            rendered,
        })
    }

    /// Parses a rendered nonce against the fleet parameters.
    ///
    /// # Errors
    ///
    /// Returns the [`NonceError`] describing the first violation: a wrong total
    /// length, a non-decimal counter, or a tail symbol outside the alphabet.
    pub fn parse(text: &str, params: &FleetParams) -> Result<Self, NonceError> {
        let counter_width = usize::from(params.counter_width());
        let expected_len = counter_width + usize::from(params.tail_width());
        if !text.is_ascii() || text.len() != expected_len {
            return Err(NonceError::LengthMismatch {
                expected: expected_len,
                got: text.chars().count(),
            });
        }

        let counter_text = text
            .get(..counter_width)
            .ok_or(NonceError::LengthMismatch {
                expected: expected_len,
                got: text.len(),
            })?;
        let tail = text
            .get(counter_width..)
            .ok_or(NonceError::LengthMismatch {
                expected: expected_len,
                got: text.len(),
            })?;

        if !counter_text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(NonceError::CounterNotDecimal);
        }
        let counter = counter_text
            .parse::<u64>()
            .map_err(|_| NonceError::CounterNotDecimal)?;

        Self::new(counter, tail, params)
    }

    /// Returns the next nonce: the counter advanced by one, with a freshly
    /// drawn tail supplied by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`NonceError::CounterOverflow`] when the counter has reached the
    /// end of its width. The counter is never carried around the modulus: the
    /// consumer is expected to rotate the key epoch instead.
    pub fn next_with_tail(&self, tail: &str, params: &FleetParams) -> Result<Self, NonceError> {
        let next = self
            .counter
            .checked_add(1)
            .ok_or(NonceError::CounterOverflow {
                width: self.counter_width,
                counter_value: self.counter,
            })?;
        Self::new(next, tail, params)
    }

    /// Returns the nonce as it travels over the channel.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.rendered
    }

    /// Returns the counter part.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Returns the random tail.
    #[must_use]
    pub fn tail(&self) -> &str {
        &self.tail
    }
}

impl core::fmt::Display for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.rendered)
    }
}

/// Rejection of a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    /// The counter no longer fits the width of the profile.
    #[error("nonce counter {counter_value} no longer fits a width of {width} digits")]
    CounterOverflow {
        /// Counter width of the profile, in digits.
        width: u8,
        /// Counter value that did not fit.
        counter_value: u64,
    },
    /// The counter part is not decimal.
    #[error("the nonce counter is not decimal")]
    CounterNotDecimal,
    /// The rendered nonce is of the wrong length.
    #[error("nonce length {got} does not match the configured {expected}")]
    LengthMismatch {
        /// Length the parameters describe.
        expected: usize,
        /// Length that was offered.
        got: usize,
    },
    /// The random tail is of the wrong width.
    #[error("nonce tail width {got} does not match the configured {expected}")]
    TailWidthMismatch {
        /// Width the parameters describe.
        expected: u8,
        /// Width that was offered.
        got: usize,
    },
    /// The random tail carries a symbol outside the configured alphabet.
    #[error("the nonce tail carries a symbol outside the configured alphabet")]
    TailAlphabet,
}

/// Returns the first counter value that no longer fits `width` digits.
fn counter_capacity(width: u8) -> u64 {
    // `FleetParams::parse` caps the width at 18 digits, so the power fits.
    10u64.checked_pow(u32::from(width)).unwrap_or(u64::MAX)
}

/// Checks the tail against the configured width and alphabet.
fn check_tail(tail: &str, params: FleetParams) -> Result<(), NonceError> {
    let symbols = tail.chars().count();
    if symbols != usize::from(params.tail_width()) {
        return Err(NonceError::TailWidthMismatch {
            expected: params.tail_width(),
            got: symbols,
        });
    }
    let allowed = params.alphabet().symbols();
    for symbol in tail.bytes() {
        if !allowed.contains(&symbol) {
            return Err(NonceError::TailAlphabet);
        }
    }
    if !tail.is_ascii() {
        return Err(NonceError::TailAlphabet);
    }
    Ok(())
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

    fn narrow_params() -> FleetParams {
        FleetParams::parse(FleetParamsInput {
            counter_width: 2,
            tail_width: 2,
            ..FleetParamsInput::defaults()
        })
        .unwrap()
    }

    #[test]
    fn a_nonce_renders_counter_then_tail() {
        let nonce = Nonce::new(420, "0713", &params()).unwrap();
        assert_eq!(nonce.as_str(), "0004200713");
        assert_eq!(nonce.counter(), 420);
        assert_eq!(nonce.tail(), "0713");
    }

    #[test]
    fn parsing_round_trips() {
        let nonce = Nonce::parse("0004200713", &params()).unwrap();
        assert_eq!(nonce, Nonce::new(420, "0713", &params()).unwrap());
    }

    #[test]
    fn a_wrong_length_does_not_parse() {
        assert!(matches!(
            Nonce::parse("00042007", &params()),
            Err(NonceError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn a_non_decimal_counter_does_not_parse() {
        assert_eq!(
            Nonce::parse("00042A0713", &params()),
            Err(NonceError::CounterNotDecimal)
        );
    }

    #[test]
    fn a_tail_of_the_wrong_width_is_rejected() {
        assert!(matches!(
            Nonce::new(1, "071", &params()),
            Err(NonceError::TailWidthMismatch { .. })
        ));
    }

    #[test]
    fn a_tail_outside_the_alphabet_is_rejected() {
        assert_eq!(
            Nonce::new(1, "07A3", &params()),
            Err(NonceError::TailAlphabet)
        );
        let base32 = FleetParams::parse(FleetParamsInput {
            alphabet: Alphabet::CrockfordBase32,
            ..FleetParamsInput::defaults()
        })
        .unwrap();
        assert!(Nonce::new(1, "07AZ", &base32).is_ok());
        // `U` is not part of Crockford base32, even though other letters are.
        assert_eq!(
            Nonce::new(1, "07AU", &base32),
            Err(NonceError::TailAlphabet)
        );
    }

    #[test]
    fn the_counter_does_not_wrap_at_the_width() {
        let params = narrow_params();
        let last = Nonce::new(99, "07", &params).unwrap();
        assert_eq!(last.as_str(), "9907");
        assert_eq!(
            last.next_with_tail("13", &params),
            Err(NonceError::CounterOverflow {
                width: 2,
                counter_value: 100
            })
        );
        assert_eq!(
            Nonce::new(100, "13", &params),
            Err(NonceError::CounterOverflow {
                width: 2,
                counter_value: 100
            })
        );
    }

    #[test]
    fn the_counter_advances_by_one() {
        let params = narrow_params();
        let first = Nonce::new(7, "07", &params).unwrap();
        let second = first.next_with_tail("13", &params).unwrap();
        assert_eq!(second.as_str(), "0813");
        assert_eq!(second.counter(), 8);
    }
}

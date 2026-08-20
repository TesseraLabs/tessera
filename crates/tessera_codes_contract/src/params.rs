//! Fleet parameters of the phone channel.
//!
//! The parameters are checked where they are parsed, not where they are used:
//! otherwise "only stricter" gets verified in the cabinet and forgotten on the
//! device. A configuration weaker than the contract minimum fails to parse; it
//! is never quietly replaced by a default.

use crate::code::Alphabet;
use crate::profile::{AlgorithmProfile, UnconfirmedProfileRisk};

/// Shortest code the contract allows.
pub const MIN_CODE_LEN: u8 = 6;

/// Largest number of attempts per nonce the contract allows.
pub const MAX_ATTEMPTS_PER_NONCE: u8 = 10;

/// Default code length.
pub const DEFAULT_CODE_LEN: u8 = 8;

/// Default number of attempts per nonce.
pub const DEFAULT_ATTEMPTS_PER_NONCE: u8 = 5;

/// Default width of the nonce counter, in decimal digits.
pub const DEFAULT_COUNTER_WIDTH: u8 = 6;

/// Default width of the random nonce tail, in characters.
pub const DEFAULT_TAIL_WIDTH: u8 = 4;

/// Default key agreement profile.
pub const DEFAULT_PROFILE: AlgorithmProfile = AlgorithmProfile::P256;

/// Widest nonce counter the contract allows: `10^19` no longer fits a `u64`,
/// and the counter is compared and incremented as one.
pub const MAX_COUNTER_WIDTH: u8 = 18;

/// Widest random tail the contract allows. A tail beyond this is not stronger
/// in any way that matters, and it is read aloud over a telephone.
pub const MAX_TAIL_WIDTH: u8 = 16;

/// Narrowest nonce counter and tail the contract allows.
pub const MIN_NONCE_PART_WIDTH: u8 = 1;

/// Raw parameters, as they arrive from a fleet configuration.
///
/// This type carries no guarantees; it exists so that
/// [`FleetParams::parse`] has a single input to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetParamsInput {
    /// Number of characters in the code.
    pub code_len: u8,
    /// Number of verification attempts allowed for one nonce.
    pub attempts_per_nonce: u8,
    /// Alphabet the code and the nonce tail are written in.
    pub alphabet: Alphabet,
    /// Width of the decimal nonce counter.
    pub counter_width: u8,
    /// Width of the random nonce tail.
    pub tail_width: u8,
    /// Key agreement profile of the device pairs.
    pub profile: AlgorithmProfile,
    /// Whether the configuration accepts a profile whose vendor gate is open.
    ///
    /// Kept apart from [`FleetParamsInput::profile`] on purpose: the choice of
    /// an algorithm and the acceptance of an unverified one are two different
    /// decisions, made by different people.
    pub unconfirmed_profile_risk: UnconfirmedProfileRisk,
}

impl FleetParamsInput {
    /// Returns the contract defaults in raw form.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            code_len: DEFAULT_CODE_LEN,
            attempts_per_nonce: DEFAULT_ATTEMPTS_PER_NONCE,
            alphabet: Alphabet::Decimal,
            counter_width: DEFAULT_COUNTER_WIDTH,
            tail_width: DEFAULT_TAIL_WIDTH,
            profile: DEFAULT_PROFILE,
            unconfirmed_profile_risk: UnconfirmedProfileRisk::NotAccepted,
        }
    }
}

/// Checked fleet parameters.
///
/// Constructed only through [`FleetParams::parse`] or
/// [`FleetParams::defaults`], so every value that reaches the code computation
/// has already passed the contract minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetParams {
    code_len: u8,
    attempts_per_nonce: u8,
    alphabet: Alphabet,
    counter_width: u8,
    tail_width: u8,
    profile: AlgorithmProfile,
}

impl FleetParams {
    /// Returns the contract defaults: an eight-digit decimal code, five
    /// attempts per nonce and the P-256 profile.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            code_len: DEFAULT_CODE_LEN,
            attempts_per_nonce: DEFAULT_ATTEMPTS_PER_NONCE,
            alphabet: Alphabet::Decimal,
            counter_width: DEFAULT_COUNTER_WIDTH,
            tail_width: DEFAULT_TAIL_WIDTH,
            profile: DEFAULT_PROFILE,
        }
    }

    /// Checks a raw configuration and builds the parameters.
    ///
    /// # Errors
    ///
    /// Returns the [`ParamsError`] describing the first coordinate that is
    /// weaker than the contract allows, or outside the range the
    /// implementation can compute in.
    pub fn parse(input: FleetParamsInput) -> Result<Self, ParamsError> {
        if input.code_len < MIN_CODE_LEN {
            return Err(ParamsError::CodeTooShort {
                minimum: MIN_CODE_LEN,
                got: input.code_len,
            });
        }
        let max_code_len = input.alphabet.max_code_len();
        if input.code_len > max_code_len {
            return Err(ParamsError::CodeTooLong {
                maximum: max_code_len,
                got: input.code_len,
            });
        }
        if input.attempts_per_nonce == 0 {
            return Err(ParamsError::NoAttempts);
        }
        if input.attempts_per_nonce > MAX_ATTEMPTS_PER_NONCE {
            return Err(ParamsError::TooManyAttempts {
                maximum: MAX_ATTEMPTS_PER_NONCE,
                got: input.attempts_per_nonce,
            });
        }
        if input.counter_width < MIN_NONCE_PART_WIDTH || input.counter_width > MAX_COUNTER_WIDTH {
            return Err(ParamsError::CounterWidthOutOfRange {
                minimum: MIN_NONCE_PART_WIDTH,
                maximum: MAX_COUNTER_WIDTH,
                got: input.counter_width,
            });
        }
        if input.tail_width < MIN_NONCE_PART_WIDTH || input.tail_width > MAX_TAIL_WIDTH {
            return Err(ParamsError::TailWidthOutOfRange {
                minimum: MIN_NONCE_PART_WIDTH,
                maximum: MAX_TAIL_WIDTH,
                got: input.tail_width,
            });
        }
        if let Some(gate) = input.profile.open_gate() {
            if input.unconfirmed_profile_risk != UnconfirmedProfileRisk::AcceptedByFleetOwner {
                return Err(ParamsError::UnconfirmedProfile {
                    profile: input.profile.as_str(),
                    gate,
                });
            }
        }

        Ok(Self {
            code_len: input.code_len,
            attempts_per_nonce: input.attempts_per_nonce,
            alphabet: input.alphabet,
            counter_width: input.counter_width,
            tail_width: input.tail_width,
            profile: input.profile,
        })
    }

    /// Number of characters in the code.
    #[must_use]
    pub const fn code_len(&self) -> u8 {
        self.code_len
    }

    /// Number of verification attempts allowed for one nonce.
    #[must_use]
    pub const fn attempts_per_nonce(&self) -> u8 {
        self.attempts_per_nonce
    }

    /// Alphabet of the code and of the nonce tail.
    #[must_use]
    pub const fn alphabet(&self) -> Alphabet {
        self.alphabet
    }

    /// Width of the decimal nonce counter.
    #[must_use]
    pub const fn counter_width(&self) -> u8 {
        self.counter_width
    }

    /// Width of the random nonce tail.
    #[must_use]
    pub const fn tail_width(&self) -> u8 {
        self.tail_width
    }

    /// Key agreement profile of the device pairs.
    ///
    /// The profile takes no part in [`Self::strictness_cmp`]: two profiles are
    /// different algorithms, not two strengths of the same one, and a partial
    /// order over them would invent a ranking the contract cannot back.
    #[must_use]
    pub const fn profile(&self) -> AlgorithmProfile {
        self.profile
    }

    /// Returns the strength coordinates compared by [`Self::strictness_cmp`].
    ///
    /// The first coordinate is the entropy of the code in thousandths of a bit,
    /// so that a shorter code over a larger alphabet is weighed against a
    /// longer decimal one instead of being compared by bare length. The counter
    /// width is deliberately absent: a wider counter postpones an epoch
    /// rotation, it does not make a code harder to guess.
    fn strength(self) -> (u64, i64, u64) {
        let entropy = u64::from(self.code_len) * self.alphabet.entropy_millibits();
        // Fewer attempts is stricter, so the coordinate is negated to keep the
        // comparison uniformly "greater is stricter".
        let attempts = -i64::from(self.attempts_per_nonce);
        (entropy, attempts, u64::from(self.tail_width))
    }

    /// Reports whether `self` is at least as strict as `other` in every
    /// coordinate.
    #[must_use]
    pub fn is_at_least_as_strict_as(&self, other: &Self) -> bool {
        let (le, la, lt) = self.strength();
        let (re, ra, rt) = other.strength();
        le >= re && la >= ra && lt >= rt
    }

    /// Compares two parameter sets by strictness.
    ///
    /// The result is a partial order, not a number: a configuration that
    /// lengthens the code while also allowing more attempts trades one
    /// coordinate for another, and is [`None`] — neither set is a tightening of
    /// the other.
    ///
    /// The comparison is offered as a method rather than a [`PartialOrd`] impl
    /// on purpose: two parameter sets can be equally strict while differing in
    /// a coordinate that carries no strength (the counter width), and
    /// [`PartialOrd`] would then be required to call them equal.
    #[must_use]
    pub fn strictness_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match (
            self.is_at_least_as_strict_as(other),
            other.is_at_least_as_strict_as(self),
        ) {
            (true, true) => Some(core::cmp::Ordering::Equal),
            (true, false) => Some(core::cmp::Ordering::Greater),
            (false, true) => Some(core::cmp::Ordering::Less),
            (false, false) => None,
        }
    }
}

/// Rejection of a fleet configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParamsError {
    /// The code is shorter than the contract minimum.
    #[error("code length {got} is below the contract minimum of {minimum}")]
    CodeTooShort {
        /// Shortest length the contract allows.
        minimum: u8,
        /// Length the configuration asked for.
        got: u8,
    },
    /// The code is longer than the implementation can compute without bias.
    #[error("code length {got} exceeds the maximum of {maximum} for this alphabet")]
    CodeTooLong {
        /// Longest length this alphabet allows.
        maximum: u8,
        /// Length the configuration asked for.
        got: u8,
    },
    /// The configuration allows no verification attempt at all.
    #[error("at least one attempt per nonce is required")]
    NoAttempts,
    /// The configuration allows more attempts than the contract maximum.
    #[error("{got} attempts per nonce exceed the contract maximum of {maximum}")]
    TooManyAttempts {
        /// Largest number of attempts the contract allows.
        maximum: u8,
        /// Number the configuration asked for.
        got: u8,
    },
    /// The nonce counter width is outside the supported range.
    #[error("counter width {got} is outside the range {minimum}..={maximum}")]
    CounterWidthOutOfRange {
        /// Narrowest counter the contract allows.
        minimum: u8,
        /// Widest counter the contract allows.
        maximum: u8,
        /// Width the configuration asked for.
        got: u8,
    },
    /// The configuration selects a profile whose vendor gate is still open,
    /// without recording that the risk was accepted.
    #[error("profile `{profile}` is not confirmed: {gate}; running a fleet on it requires the configuration to accept the risk explicitly")]
    UnconfirmedProfile {
        /// Identifier of the profile the configuration asked for.
        profile: &'static str,
        /// The gate that is still open.
        gate: &'static str,
    },
    /// The nonce tail width is outside the supported range.
    #[error("tail width {got} is outside the range {minimum}..={maximum}")]
    TailWidthOutOfRange {
        /// Narrowest tail the contract allows.
        minimum: u8,
        /// Widest tail the contract allows.
        maximum: u8,
        /// Width the configuration asked for.
        got: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::{FleetParams, FleetParamsInput, ParamsError, MAX_ATTEMPTS_PER_NONCE, MIN_CODE_LEN};
    use crate::code::Alphabet;
    use crate::profile::{AlgorithmProfile, UnconfirmedProfileRisk};
    use core::cmp::Ordering;

    #[test]
    fn defaults_are_eight_digits_and_five_attempts() {
        let params = FleetParams::defaults();
        assert_eq!(params.code_len(), 8);
        assert_eq!(params.attempts_per_nonce(), 5);
        assert_eq!(params.alphabet(), Alphabet::Decimal);
        assert_eq!(FleetParams::parse(FleetParamsInput::defaults()), Ok(params));
    }

    #[test]
    fn a_four_digit_code_does_not_parse() {
        let input = FleetParamsInput {
            code_len: 4,
            ..FleetParamsInput::defaults()
        };
        assert_eq!(
            FleetParams::parse(input),
            Err(ParamsError::CodeTooShort {
                minimum: MIN_CODE_LEN,
                got: 4
            })
        );
    }

    #[test]
    fn eleven_attempts_do_not_parse() {
        let input = FleetParamsInput {
            attempts_per_nonce: 11,
            ..FleetParamsInput::defaults()
        };
        assert_eq!(
            FleetParams::parse(input),
            Err(ParamsError::TooManyAttempts {
                maximum: MAX_ATTEMPTS_PER_NONCE,
                got: 11
            })
        );
    }

    #[test]
    fn zero_attempts_do_not_parse() {
        let input = FleetParamsInput {
            attempts_per_nonce: 0,
            ..FleetParamsInput::defaults()
        };
        assert_eq!(FleetParams::parse(input), Err(ParamsError::NoAttempts));
    }

    #[test]
    fn a_code_longer_than_the_alphabet_supports_does_not_parse() {
        let input = FleetParamsInput {
            code_len: 20,
            ..FleetParamsInput::defaults()
        };
        assert!(matches!(
            FleetParams::parse(input),
            Err(ParamsError::CodeTooLong { .. })
        ));
    }

    fn parsed(input: FleetParamsInput) -> FleetParams {
        FleetParams::parse(input).unwrap_or_else(|_| FleetParams::defaults())
    }

    #[test]
    fn a_longer_code_alone_is_a_tightening() {
        let base = FleetParams::defaults();
        let stricter = parsed(FleetParamsInput {
            code_len: 10,
            ..FleetParamsInput::defaults()
        });
        assert!(stricter.is_at_least_as_strict_as(&base));
        assert_eq!(stricter.strictness_cmp(&base), Some(Ordering::Greater));
        assert_eq!(base.strictness_cmp(&stricter), Some(Ordering::Less));
    }

    #[test]
    fn trading_strictness_is_not_a_tightening() {
        let base = FleetParams::defaults();
        let traded = parsed(FleetParamsInput {
            code_len: 10,
            attempts_per_nonce: 8,
            ..FleetParamsInput::defaults()
        });
        assert!(!traded.is_at_least_as_strict_as(&base));
        assert!(!base.is_at_least_as_strict_as(&traded));
        assert_eq!(traded.strictness_cmp(&base), None);
    }

    #[test]
    fn equal_parameters_compare_equal() {
        let base = FleetParams::defaults();
        assert_eq!(base.strictness_cmp(&base), Some(Ordering::Equal));
    }

    #[test]
    fn the_default_profile_is_p256_and_parses_without_a_risk_decision() {
        let params = parsed(FleetParamsInput::defaults());
        assert_eq!(params.profile(), AlgorithmProfile::P256);
        assert_eq!(FleetParams::defaults().profile(), AlgorithmProfile::P256);
    }

    #[test]
    fn x25519_parses_without_a_risk_decision() {
        let input = FleetParamsInput {
            profile: AlgorithmProfile::X25519,
            ..FleetParamsInput::defaults()
        };
        assert_eq!(
            FleetParams::parse(input).map(|params| params.profile()),
            Ok(AlgorithmProfile::X25519)
        );
    }

    #[test]
    fn gost_without_an_accepted_risk_does_not_parse_and_names_the_gate() {
        let input = FleetParamsInput {
            profile: AlgorithmProfile::GostVko34102012,
            ..FleetParamsInput::defaults()
        };
        let error = FleetParams::parse(input).err();
        assert!(matches!(
            error,
            Some(ParamsError::UnconfirmedProfile {
                profile: "gost-vko-34.10-2012",
                ..
            })
        ));
        let message = error.map(|error| error.to_string()).unwrap_or_default();
        assert!(
            message.contains("34.10-2012") && message.contains("PKCS#11"),
            "the refusal must point at the open gate: {message}"
        );
    }

    #[test]
    fn gost_parses_once_the_risk_is_accepted() {
        let input = FleetParamsInput {
            profile: AlgorithmProfile::GostVko34102012,
            unconfirmed_profile_risk: UnconfirmedProfileRisk::AcceptedByFleetOwner,
            ..FleetParamsInput::defaults()
        };
        assert_eq!(
            FleetParams::parse(input).map(|params| params.profile()),
            Ok(AlgorithmProfile::GostVko34102012)
        );
    }

    #[test]
    fn accepting_the_risk_does_not_excuse_a_weak_code() {
        let input = FleetParamsInput {
            code_len: 4,
            profile: AlgorithmProfile::GostVko34102012,
            unconfirmed_profile_risk: UnconfirmedProfileRisk::AcceptedByFleetOwner,
            ..FleetParamsInput::defaults()
        };
        assert!(matches!(
            FleetParams::parse(input),
            Err(ParamsError::CodeTooShort { .. })
        ));
    }

    #[test]
    fn a_larger_alphabet_at_equal_length_is_a_tightening() {
        let decimal = FleetParams::defaults();
        let base32 = parsed(FleetParamsInput {
            alphabet: Alphabet::CrockfordBase32,
            ..FleetParamsInput::defaults()
        });
        assert_eq!(base32.strictness_cmp(&decimal), Some(Ordering::Greater));
    }
}

//! Fleet parameters of the phone channel.
//!
//! The parameters are checked where they are parsed, not where they are used:
//! otherwise "only stricter" gets verified in the cabinet and forgotten on the
//! device. A configuration weaker than the contract minimum fails to parse; it
//! is never quietly replaced by a default.

use crate::code::Alphabet;
use crate::nonce::{MAX_NONCE_WIDTH, MIN_NONCE_ENTROPY_BITS};
use crate::profile::{AlgorithmProfile, UnconfirmedProfileRisk};

/// Smallest amount of guesswork a code must cost, in bits.
///
/// Derived from the only other bound the contract puts on guessing, and derived
/// rather than chosen: an attempt allows at most
/// [`MAX_ATTEMPTS_PER_NONCE`] tries, so a code drawn from at least `2^20`
/// values is hit with a probability below one in a hundred thousand even when
/// a fleet grants the whole budget. Fewer bits than that and the budget stops
/// being the thing that bounds an attacker.
///
/// The floor is in **bits and not in characters** because the alphabet is a
/// fleet parameter. Calibrating a length instead would mean that a fleet
/// switching from decimal to base32 kept its length and quietly changed its
/// strength — in one direction or the other, depending on which way it moved.
pub const MIN_CODE_ENTROPY_BITS: u32 = 20;

/// Largest number of attempts per nonce the contract allows.
pub const MAX_ATTEMPTS_PER_NONCE: u8 = 10;

/// Default code length, in characters of the default alphabet.
///
/// Six characters of Crockford base32 carry thirty bits — more than the eight
/// decimal digits this default replaced (twenty-six and a half) and two
/// characters shorter to type. That is the whole argument for the change of
/// alphabet: the same keyboard, a shorter code, more strength.
pub const DEFAULT_CODE_LEN: u8 = 6;

/// Default number of attempts per nonce.
///
/// Unchanged by the recalibration, and deliberately: the floor above is
/// computed against the *maximum* budget the contract allows, so a default
/// below that maximum is already covered by it.
pub const DEFAULT_ATTEMPTS_PER_NONCE: u8 = 5;

/// Longest an attempt may stay open, in seconds.
///
/// A normative ceiling, not a suggestion: without one, "only stricter" bounds
/// nothing upward, and the window a status-token stands for stretches to
/// whatever a fleet writes in its configuration. Ten minutes is longer than
/// anybody needs to read a code off a screen and type it, and every minute past
/// that is a minute the single attempt slot of the device is held and the
/// freshness of the status answer decays.
pub const MAX_ATTEMPT_TTL_SECS: u64 = 600;

/// Default lifetime of an attempt, in seconds.
pub const DEFAULT_ATTEMPT_TTL_SECS: u64 = 300;

/// Default width of the nonce, in characters.
///
/// Chosen for the default alphabet the same way the code length is: twenty-six
/// characters of Crockford base32 carry a hundred and thirty bits, just over
/// the floor of [`MIN_NONCE_ENTROPY_BITS`]. A decimal fleet needs thirty-nine
/// characters for the same randomness and has to say so in its configuration —
/// which is the point of calibrating in bits rather than in characters.
pub const DEFAULT_NONCE_WIDTH: u8 = 26;

/// Default key agreement profile.
pub const DEFAULT_PROFILE: AlgorithmProfile = AlgorithmProfile::P256;

/// Default alphabet of the code and the nonce.
///
/// Crockford base32: the code is read off a screen and typed on an ordinary
/// keyboard, and base32 buys the same strength in fewer characters. The decimal
/// profile stays available and is an explicit choice of a fleet whose devices
/// have a keypad and nothing else.
pub const DEFAULT_ALPHABET: Alphabet = Alphabet::CrockfordBase32;

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
    /// Alphabet the code and the nonce are written in.
    pub alphabet: Alphabet,
    /// Width of the nonce, in characters.
    pub nonce_width: u8,
    /// How long an attempt may stay open, in seconds.
    pub attempt_ttl_secs: u64,
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
            alphabet: DEFAULT_ALPHABET,
            nonce_width: DEFAULT_NONCE_WIDTH,
            attempt_ttl_secs: DEFAULT_ATTEMPT_TTL_SECS,
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
    nonce_width: u8,
    attempt_ttl_secs: u64,
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
            alphabet: DEFAULT_ALPHABET,
            nonce_width: DEFAULT_NONCE_WIDTH,
            attempt_ttl_secs: DEFAULT_ATTEMPT_TTL_SECS,
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
        // Strength, not length. The same number of characters is a different
        // code in a different alphabet, and a fleet that changed one without
        // the other would move its floor without meaning to.
        let code_entropy_millibits = u64::from(input.code_len) * input.alphabet.entropy_millibits();
        if code_entropy_millibits < u64::from(MIN_CODE_ENTROPY_BITS) * 1000 {
            return Err(ParamsError::CodeTooWeak {
                minimum_bits: MIN_CODE_ENTROPY_BITS,
                got_bits: u32::try_from(code_entropy_millibits / 1000).unwrap_or(u32::MAX),
                got_len: input.code_len,
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
        if input.nonce_width > MAX_NONCE_WIDTH {
            return Err(ParamsError::NonceTooWide {
                maximum: MAX_NONCE_WIDTH,
                got: input.nonce_width,
            });
        }
        // The floor is on randomness, not on characters: the alphabet decides
        // how much of it one character buys, so a width that clears the floor in
        // base32 falls short of it in decimal.
        let entropy_millibits = u64::from(input.nonce_width) * input.alphabet.entropy_millibits();
        if entropy_millibits < u64::from(MIN_NONCE_ENTROPY_BITS) * 1000 {
            return Err(ParamsError::NonceTooNarrow {
                minimum_bits: MIN_NONCE_ENTROPY_BITS,
                got_bits: u32::try_from(entropy_millibits / 1000).unwrap_or(u32::MAX),
                got_width: input.nonce_width,
            });
        }
        // Both ends of the lifetime. Zero is not "no limit", and the ceiling is
        // normative: without it a fleet's "only stricter" bounds nothing
        // upward, and the window a status answer stands for stretches with the
        // attempt.
        if input.attempt_ttl_secs == 0 || input.attempt_ttl_secs > MAX_ATTEMPT_TTL_SECS {
            return Err(ParamsError::AttemptTtlOutOfRange {
                maximum: MAX_ATTEMPT_TTL_SECS,
                got: input.attempt_ttl_secs,
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
            nonce_width: input.nonce_width,
            attempt_ttl_secs: input.attempt_ttl_secs,
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

    /// Width of the nonce, in characters.
    #[must_use]
    pub const fn nonce_width(&self) -> u8 {
        self.nonce_width
    }

    /// How long an attempt may stay open, in seconds.
    #[must_use]
    pub const fn attempt_ttl_secs(&self) -> u64 {
        self.attempt_ttl_secs
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
    /// longer decimal one instead of being compared by bare length. The third
    /// is the entropy of the nonce, measured the same way and for the same
    /// reason — comparing bare widths across two alphabets would call a base32
    /// nonce weaker than a decimal one of equal randomness. The fourth is the
    /// lifetime of an attempt.
    fn strength(self) -> (u64, i64, u64, i64) {
        let entropy = u64::from(self.code_len) * self.alphabet.entropy_millibits();
        // Fewer attempts is stricter, so the coordinate is negated to keep the
        // comparison uniformly "greater is stricter".
        let attempts = -i64::from(self.attempts_per_nonce);
        let nonce_entropy = u64::from(self.nonce_width) * self.alphabet.entropy_millibits();
        // Shorter is stricter here too: an attempt held open longer is a longer
        // window for whoever is guessing, and a staler status answer.
        let ttl = -i64::try_from(self.attempt_ttl_secs).unwrap_or(i64::MIN);
        (entropy, attempts, nonce_entropy, ttl)
    }

    /// Reports whether `self` is at least as strict as `other` in every
    /// coordinate.
    #[must_use]
    pub fn is_at_least_as_strict_as(&self, other: &Self) -> bool {
        let (le, la, ln, lt) = self.strength();
        let (re, ra, rn, rt) = other.strength();
        le >= re && la >= ra && ln >= rn && lt >= rt
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
    /// The code carries less guesswork than the contract requires.
    #[error("a code of {got_len} characters in this alphabet costs about {got_bits} bits of guesswork, and the contract requires {minimum_bits}")]
    CodeTooWeak {
        /// Guesswork the contract requires, in bits.
        minimum_bits: u32,
        /// Guesswork the configuration would have cost, in bits.
        got_bits: u32,
        /// Length the configuration asked for, in characters.
        got_len: u8,
    },
    /// The lifetime of an attempt is zero or past the normative ceiling.
    #[error("an attempt lifetime of {got} seconds is outside 1..={maximum}")]
    AttemptTtlOutOfRange {
        /// Longest lifetime the contract allows.
        maximum: u64,
        /// Lifetime the configuration asked for.
        got: u64,
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
    /// The configuration selects a profile whose vendor gate is still open,
    /// without recording that the risk was accepted.
    #[error("profile `{profile}` is not confirmed: {gate}; running a fleet on it requires the configuration to accept the risk explicitly")]
    UnconfirmedProfile {
        /// Identifier of the profile the configuration asked for.
        profile: &'static str,
        /// The gate that is still open.
        gate: &'static str,
    },
    /// The nonce is narrower than the randomness floor of the contract.
    #[error("a nonce of {got_width} characters in this alphabet carries about {got_bits} bits, and the contract requires {minimum_bits}")]
    NonceTooNarrow {
        /// Randomness the contract requires, in bits.
        minimum_bits: u32,
        /// Randomness the configuration would have carried, in bits.
        got_bits: u32,
        /// Width the configuration asked for, in characters.
        got_width: u8,
    },
    /// The nonce is wider than the documents of the channel accept.
    #[error("nonce width {got} is past the maximum of {maximum}")]
    NonceTooWide {
        /// Widest nonce the contract allows.
        maximum: u8,
        /// Width the configuration asked for.
        got: u8,
    },
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{
        FleetParams, FleetParamsInput, ParamsError, MAX_ATTEMPTS_PER_NONCE, MAX_ATTEMPT_TTL_SECS,
        MIN_CODE_ENTROPY_BITS,
    };
    use crate::code::Alphabet;
    use crate::nonce::{MAX_NONCE_WIDTH, MIN_NONCE_ENTROPY_BITS};
    use crate::profile::{AlgorithmProfile, UnconfirmedProfileRisk};
    use core::cmp::Ordering;

    #[test]
    fn defaults_are_six_base32_characters_and_five_attempts() {
        // Six characters of base32 is thirty bits — stronger than the eight
        // decimal digits this default replaced, and two characters shorter to
        // type. The recalibration is the point of the change, not a side
        // effect of it.
        let params = FleetParams::defaults();
        assert_eq!(params.code_len(), 6);
        assert_eq!(params.attempts_per_nonce(), 5);
        assert_eq!(params.alphabet(), Alphabet::CrockfordBase32);
        assert_eq!(params.attempt_ttl_secs(), 300);
        assert_eq!(FleetParams::parse(FleetParamsInput::defaults()), Ok(params));

        let bits = u64::from(params.code_len()) * params.alphabet().entropy_millibits() / 1000;
        assert!(bits >= u64::from(MIN_CODE_ENTROPY_BITS), "{bits} bits");
        let replaced = u64::from(8_u8) * Alphabet::Decimal.entropy_millibits() / 1000;
        assert!(bits > replaced, "{bits} bits against {replaced}");
    }

    #[test]
    fn a_nonce_below_the_randomness_floor_does_not_parse() {
        // The floor is on bits, so the same width passes in one alphabet and
        // fails in another: twenty-six decimal digits carry about 86 bits,
        // twenty-six base32 characters carry 130.
        let narrow = FleetParamsInput {
            nonce_width: 26,
            alphabet: Alphabet::Decimal,
            // Long enough that the code clears its own floor: this test is
            // about the nonce, and a code that failed first would hide it.
            code_len: 8,
            ..FleetParamsInput::defaults()
        };
        assert!(matches!(
            FleetParams::parse(narrow),
            Err(ParamsError::NonceTooNarrow {
                minimum_bits: MIN_NONCE_ENTROPY_BITS,
                ..
            })
        ));

        let same_width_over_base32 = FleetParamsInput {
            nonce_width: 26,
            ..FleetParamsInput::defaults()
        };
        assert!(FleetParams::parse(same_width_over_base32).is_ok());
    }

    #[test]
    fn a_nonce_past_the_maximum_width_does_not_parse() {
        let wide = FleetParamsInput {
            nonce_width: MAX_NONCE_WIDTH + 1,
            ..FleetParamsInput::defaults()
        };
        assert_eq!(
            FleetParams::parse(wide),
            Err(ParamsError::NonceTooWide {
                maximum: MAX_NONCE_WIDTH,
                got: MAX_NONCE_WIDTH + 1
            })
        );
    }

    #[test]
    fn a_wider_nonce_is_a_tightening_and_a_narrower_one_is_not() {
        let base = FleetParams::defaults();
        let wider = FleetParams::parse(FleetParamsInput {
            nonce_width: base.nonce_width() + 1,
            ..FleetParamsInput::defaults()
        })
        .unwrap();
        assert_eq!(wider.strictness_cmp(&base), Some(Ordering::Greater));
        assert_eq!(base.strictness_cmp(&wider), Some(Ordering::Less));
    }

    #[test]
    fn a_code_below_the_guesswork_floor_does_not_parse() {
        // The floor is in bits, so the same length passes in one alphabet and
        // fails in another. Four base32 characters are twenty bits and pass;
        // four decimal digits are thirteen and do not.
        let four_base32 = FleetParamsInput {
            code_len: 4,
            ..FleetParamsInput::defaults()
        };
        assert!(FleetParams::parse(four_base32).is_ok());

        let four_decimal = FleetParamsInput {
            code_len: 4,
            alphabet: Alphabet::Decimal,
            ..FleetParamsInput::defaults()
        };
        assert!(matches!(
            FleetParams::parse(four_decimal),
            Err(ParamsError::CodeTooWeak {
                minimum_bits: MIN_CODE_ENTROPY_BITS,
                got_len: 4,
                ..
            })
        ));
    }

    #[test]
    fn an_attempt_lifetime_outside_the_ceiling_does_not_parse() {
        // Both ends. Zero is not "no limit" and the ceiling is not advisory:
        // without an upper bound "only stricter" bounds nothing upward, and the
        // window a status answer stands for stretches with it.
        for got in [0, MAX_ATTEMPT_TTL_SECS + 1] {
            assert_eq!(
                FleetParams::parse(FleetParamsInput {
                    attempt_ttl_secs: got,
                    ..FleetParamsInput::defaults()
                }),
                Err(ParamsError::AttemptTtlOutOfRange {
                    maximum: MAX_ATTEMPT_TTL_SECS,
                    got
                })
            );
        }
        assert!(FleetParams::parse(FleetParamsInput {
            attempt_ttl_secs: MAX_ATTEMPT_TTL_SECS,
            ..FleetParamsInput::defaults()
        })
        .is_ok());
    }

    #[test]
    fn a_shorter_attempt_lifetime_is_a_tightening() {
        let base = FleetParams::defaults();
        let shorter = FleetParams::parse(FleetParamsInput {
            attempt_ttl_secs: base.attempt_ttl_secs() - 1,
            ..FleetParamsInput::defaults()
        })
        .unwrap();
        assert_eq!(shorter.strictness_cmp(&base), Some(Ordering::Greater));
        assert_eq!(base.strictness_cmp(&shorter), Some(Ordering::Less));
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

    /// Parses a configuration a test means to be valid.
    ///
    /// Panics on a refusal rather than falling back to the defaults: a helper
    /// that substituted them would turn every comparison against an input the
    /// contract rejects into a comparison of the defaults with themselves —
    /// green, and about nothing.
    fn parsed(input: FleetParamsInput) -> FleetParams {
        FleetParams::parse(input).unwrap()
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
            code_len: 2,
            profile: AlgorithmProfile::GostVko34102012,
            unconfirmed_profile_risk: UnconfirmedProfileRisk::AcceptedByFleetOwner,
            ..FleetParamsInput::defaults()
        };
        assert!(matches!(
            FleetParams::parse(input),
            Err(ParamsError::CodeTooWeak { .. })
        ));
    }

    #[test]
    fn a_larger_alphabet_at_equal_length_is_a_tightening() {
        // The same lengths in two alphabets: base32 buys more of both the code
        // and the nonce, so it is strictly the tighter configuration.
        let base32 = FleetParams::defaults();
        let decimal = parsed(FleetParamsInput {
            alphabet: Alphabet::Decimal,
            // The shortest decimal code and nonce that clear the floors: even
            // at their weakest-allowed the base32 defaults are stricter.
            code_len: 8,
            nonce_width: 39,
            ..FleetParamsInput::defaults()
        });
        assert_eq!(decimal.strictness_cmp(&base32), Some(Ordering::Less));
        assert_eq!(base32.strictness_cmp(&decimal), Some(Ordering::Greater));
    }
}

//! Computation and verification of the code itself.
//!
//! The code is `truncate_N(HMAC(K, canon(...)))`. The truncation is uniform:
//! reducing a MAC modulo an alphabet range that does not divide the range of
//! the sample skews the low codes upwards, and a skew is exactly what an
//! attacker guessing codes over the telephone is looking for. Values in the
//! incomplete tail of the sample range are therefore rejected rather than
//! folded.

use subtle::ConstantTimeEq;

use crate::canon::{canon, CanonError, CodeInput};
use crate::key::DerivedKey;
use crate::mac::hmac_sha256;
use crate::params::FleetParams;

/// Number of extra MAC rounds attempted before the truncation gives up.
///
/// Each round offers four independent 64-bit samples, and a sample is rejected
/// with probability below `2^-4` for every alphabet and length the parameters
/// allow. Exhausting this many rounds is not reachable in practice; it is here
/// so the loop is bounded by construction.
const MAX_TRUNCATION_ROUNDS: u32 = 64;

/// Separator of the retry rounds, kept out of the space of canonical inputs.
const RETRY_LABEL: &[u8] = b"/tessera-codes-contract/v1/truncate-retry/";

/// Alphabet a code is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alphabet {
    /// Decimal digits — the default, and the only one that survives being read
    /// aloud in any language.
    Decimal,
    /// Crockford base32: digits and letters without `I`, `L`, `O` and `U`.
    CrockfordBase32,
}

impl Alphabet {
    /// Returns the symbols of the alphabet, in value order.
    #[must_use]
    pub const fn symbols(self) -> &'static [u8] {
        match self {
            Self::Decimal => b"0123456789",
            Self::CrockfordBase32 => b"0123456789ABCDEFGHJKMNPQRSTVWXYZ",
        }
    }

    /// Returns the number of symbols in the alphabet.
    #[must_use]
    pub const fn radix(self) -> u64 {
        match self {
            Self::Decimal => 10,
            Self::CrockfordBase32 => 32,
        }
    }

    /// Returns the entropy of one symbol, in thousandths of a bit.
    #[must_use]
    pub const fn entropy_millibits(self) -> u64 {
        match self {
            // log2(10) = 3.321928…, rounded down so that no comparison of
            // parameter sets overstates the strength of a decimal code.
            Self::Decimal => 3321,
            Self::CrockfordBase32 => 5000,
        }
    }

    /// Returns the longest code whose value range still fits a `u64`, which is
    /// what the unbiased truncation samples from.
    #[must_use]
    pub const fn max_code_len(self) -> u8 {
        match self {
            Self::Decimal => 19,
            Self::CrockfordBase32 => 12,
        }
    }

    /// Returns the symbol for one digit value.
    #[must_use]
    fn symbol(self, digit: u64) -> u8 {
        let symbols = self.symbols();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the value is reduced modulo the alphabet size, which is far below usize::MAX"
        )]
        let index = (digit % self.radix()) as usize;
        #[expect(
            clippy::indexing_slicing,
            reason = "the index is reduced modulo the length of the very table it indexes"
        )]
        symbols[index]
    }

    /// Folds a character typed by a human into the alphabet.
    ///
    /// Crockford base32 leaves out `I`, `L`, `O` and `U` precisely so the
    /// first three can be read back as `1`, `1` and `0`; `U` stays excluded
    /// and does not map to anything. Returns [`None`] for anything the
    /// alphabet does not contain.
    fn fold(self, symbol: char) -> Option<u8> {
        let upper = symbol.to_ascii_uppercase();
        let folded = match self {
            Self::Decimal => upper,
            Self::CrockfordBase32 => match upper {
                'I' | 'L' => '1',
                'O' => '0',
                other => other,
            },
        };
        let byte = u8::try_from(folded).ok()?;
        self.symbols().iter().copied().find(|s| *s == byte)
    }
}

/// A computed code, in the alphabet of the fleet parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code(String);

impl Code {
    /// Returns the code as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Failure of the code computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    /// The MAC input could not be encoded canonically.
    #[error(transparent)]
    Canon(#[from] CanonError),
    /// The unbiased truncation found no acceptable sample within its bound.
    #[error("unbiased truncation exhausted its rounds")]
    TruncationExhausted,
}

/// Failure of a code verification.
///
/// The single variant is the point: the caller learns that the code did not
/// meet, never which step of the computation it parted ways with. A caller that
/// needs to know why logs it on its own side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("code verification failed")]
pub struct CodeMismatch;

/// Computes the code for the given input.
///
/// # Errors
///
/// Returns [`CodeError::Canon`] when the input cannot be encoded canonically,
/// and [`CodeError::TruncationExhausted`] when the unbiased truncation runs out
/// of samples — a case that is not reachable with the parameters this contract
/// accepts.
pub fn compute_code(
    key: &DerivedKey,
    input: &CodeInput<'_>,
    params: &FleetParams,
) -> Result<Code, CodeError> {
    let canonical = canon(input)?;
    let alphabet = params.alphabet();
    let range = code_range(*params);

    for round in 0..=MAX_TRUNCATION_ROUNDS {
        let mac = if round == 0 {
            hmac_sha256(key.expose(), &canonical)
        } else {
            let mut message = Vec::with_capacity(canonical.len() + RETRY_LABEL.len() + 4);
            message.extend_from_slice(&canonical);
            message.extend_from_slice(RETRY_LABEL);
            message.extend_from_slice(&round.to_be_bytes());
            hmac_sha256(key.expose(), &message)
        };

        for window in mac.chunks_exact(8) {
            let mut sample = [0u8; 8];
            for (slot, byte) in sample.iter_mut().zip(window.iter()) {
                *slot = *byte;
            }
            if let Some(value) = accept_sample(u64::from_be_bytes(sample), range) {
                return Ok(Code(render(value, alphabet, params.code_len())));
            }
        }
    }

    Err(CodeError::TruncationExhausted)
}

/// Verifies a code presented by a human against the expected one.
///
/// The comparison is constant time in the code characters. The alphabet folding
/// applied to the presented text is not secret — it depends only on what was
/// typed — and the length of the presented text is not secret either.
///
/// # Errors
///
/// Returns [`CodeMismatch`] whenever the presented code is not the expected
/// one, whatever the reason: a wrong role, a wrong nonce, a wrong key, an
/// unusable character or a wrong length.
pub fn verify_code(
    key: &DerivedKey,
    input: &CodeInput<'_>,
    params: &FleetParams,
    presented: &str,
) -> Result<(), CodeMismatch> {
    let expected = compute_code(key, input, params).map_err(|_| CodeMismatch)?;
    let alphabet = params.alphabet();

    let mut folded = Vec::with_capacity(presented.len());
    for symbol in presented.chars() {
        folded.push(alphabet.fold(symbol).ok_or(CodeMismatch)?);
    }

    if folded.len() != expected.as_str().len() {
        return Err(CodeMismatch);
    }
    if folded.ct_eq(expected.as_str().as_bytes()).into() {
        Ok(())
    } else {
        Err(CodeMismatch)
    }
}

/// Returns the number of distinct codes the parameters describe.
fn code_range(params: FleetParams) -> u64 {
    params
        .alphabet()
        .radix()
        .checked_pow(u32::from(params.code_len()))
        // `FleetParams::parse` rejects a length whose range overflows, so this
        // saturation is unreachable; it keeps the function total.
        .unwrap_or(u64::MAX)
}

/// Accepts a 64-bit sample only from the largest multiple of `range` that fits
/// the sample space, so that every code value is equally likely.
fn accept_sample(sample: u64, range: u64) -> Option<u64> {
    if range == 0 {
        return None;
    }
    let space = 1u128 << 64;
    let limit = space - (space % u128::from(range));
    if u128::from(sample) < limit {
        Some(sample % range)
    } else {
        None
    }
}

/// Renders a value as a fixed-width string in the alphabet, most significant
/// symbol first.
fn render(value: u64, alphabet: Alphabet, width: u8) -> String {
    let radix = alphabet.radix();
    let mut symbols = Vec::with_capacity(usize::from(width));
    let mut rest = value;
    for _ in 0..width {
        symbols.push(alphabet.symbol(rest % radix));
        rest /= radix;
    }
    symbols.reverse();
    String::from_utf8(symbols).unwrap_or_default()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use std::sync::LazyLock;

    use super::{accept_sample, compute_code, render, verify_code, Alphabet, CodeMismatch};
    use crate::canon::{CodeInput, Level};
    use crate::device_number::CheckedDeviceNumber;
    use crate::key::{derive_key, DerivedKey, Epoch, KeyContext, SharedSecret, TicketHash};
    use crate::params::{FleetParams, FleetParamsInput};

    /// The device the tests of this module issue codes for.
    static DEVICE: LazyLock<CheckedDeviceNumber> =
        LazyLock::new(|| CheckedDeviceNumber::from_body("77-000123").unwrap());

    fn key() -> DerivedKey {
        let secret = SharedSecret::new(vec![0x11; 32]).unwrap();
        let context = KeyContext::new(
            &DEVICE,
            Epoch::new(7),
            TicketHash::of_canonical_signed_ticket(b"signed ticket"),
        );
        derive_key(&secret, &context).unwrap()
    }

    fn input() -> CodeInput<'static> {
        CodeInput {
            device_number: &DEVICE,
            nonce: "0004200713",
            role_id: "ops.dc.senior",
            level: Level::new(2),
        }
    }

    #[test]
    fn a_code_has_the_configured_length_and_alphabet() {
        let params = FleetParams::defaults();
        let code = compute_code(&key(), &input(), &params).unwrap();
        assert_eq!(code.as_str().len(), usize::from(params.code_len()));
        assert!(code.as_str().bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn the_code_is_deterministic() {
        let params = FleetParams::defaults();
        assert_eq!(
            compute_code(&key(), &input(), &params).unwrap(),
            compute_code(&key(), &input(), &params).unwrap()
        );
    }

    #[test]
    fn a_different_role_gives_a_different_code() {
        let params = FleetParams::defaults();
        let other = CodeInput {
            role_id: "ops.dc.junior",
            ..input()
        };
        assert_ne!(
            compute_code(&key(), &input(), &params).unwrap(),
            compute_code(&key(), &other, &params).unwrap()
        );
    }

    #[test]
    fn verification_accepts_the_computed_code() {
        let params = FleetParams::defaults();
        let code = compute_code(&key(), &input(), &params).unwrap();
        assert_eq!(
            verify_code(&key(), &input(), &params, code.as_str()),
            Ok(())
        );
    }

    #[test]
    fn every_mismatch_reports_the_same_error() {
        let params = FleetParams::defaults();
        let code = compute_code(&key(), &input(), &params).unwrap();

        let wrong_role = CodeInput {
            role_id: "ops.dc.junior",
            ..input()
        };
        let wrong_nonce = CodeInput {
            nonce: "0004200714",
            ..input()
        };
        let wrong_key = {
            let secret = SharedSecret::new(vec![0x99; 32]).unwrap();
            derive_key(
                &secret,
                &KeyContext::new(
                    &DEVICE,
                    Epoch::new(7),
                    TicketHash::of_canonical_signed_ticket(b"signed ticket"),
                ),
            )
            .unwrap()
        };

        assert_eq!(
            verify_code(&key(), &wrong_role, &params, code.as_str()),
            Err(CodeMismatch)
        );
        assert_eq!(
            verify_code(&key(), &wrong_nonce, &params, code.as_str()),
            Err(CodeMismatch)
        );
        assert_eq!(
            verify_code(&wrong_key, &input(), &params, code.as_str()),
            Err(CodeMismatch)
        );
        assert_eq!(
            verify_code(&key(), &input(), &params, "1"),
            Err(CodeMismatch)
        );
        assert_eq!(
            verify_code(&key(), &input(), &params, "abcdefgh"),
            Err(CodeMismatch)
        );
    }

    fn base32_params() -> FleetParams {
        FleetParams::parse(FleetParamsInput {
            alphabet: Alphabet::CrockfordBase32,
            code_len: 10,
            ..FleetParamsInput::defaults()
        })
        .unwrap()
    }

    #[test]
    fn base32_codes_avoid_the_excluded_letters() {
        let params = base32_params();
        // One code is a weak sample of the alphabet, so walk a range of nonces.
        for counter in 0..200u32 {
            let nonce = format!("{counter:06}0713");
            let input = CodeInput {
                nonce: &nonce,
                ..input()
            };
            let code = compute_code(&key(), &input, &params).unwrap();
            assert!(
                !code.as_str().contains(['I', 'L', 'O', 'U']),
                "excluded letter in {code}"
            );
            assert_eq!(code.as_str().len(), 10);
        }
    }

    #[test]
    fn base32_verification_folds_the_look_alikes() {
        let params = base32_params();
        let code = compute_code(&key(), &input(), &params).unwrap();
        let typed: String = code
            .as_str()
            .chars()
            .map(|c| match c {
                '1' => 'l',
                '0' => 'O',
                other => other.to_ascii_lowercase(),
            })
            .collect();
        assert_eq!(verify_code(&key(), &input(), &params, &typed), Ok(()));
    }

    #[test]
    fn u_is_not_a_base32_symbol() {
        assert_eq!(Alphabet::CrockfordBase32.fold('U'), None);
        assert_eq!(Alphabet::CrockfordBase32.fold('u'), None);
        assert_eq!(Alphabet::CrockfordBase32.fold('I'), Some(b'1'));
        assert_eq!(Alphabet::CrockfordBase32.fold('l'), Some(b'1'));
        assert_eq!(Alphabet::CrockfordBase32.fold('o'), Some(b'0'));
        assert_eq!(Alphabet::Decimal.fold('A'), None);
    }

    #[test]
    fn truncation_rejects_the_incomplete_tail() {
        // 2^64 mod 10 = 6, so the largest usable multiple of ten ends six
        // below the top of the sample space.
        let limit = u64::MAX - 5;
        assert_eq!(accept_sample(limit - 1, 10), Some((limit - 1) % 10));
        assert_eq!(accept_sample(limit, 10), None);
        assert_eq!(accept_sample(u64::MAX, 10), None);
    }

    #[test]
    fn truncation_keeps_every_sample_of_a_dividing_range() {
        // A power of two divides the sample space exactly: nothing is rejected.
        assert_eq!(accept_sample(u64::MAX, 1 << 32), Some(u64::from(u32::MAX)));
        assert_eq!(accept_sample(0, 1 << 32), Some(0));
    }

    #[test]
    fn truncation_is_unbiased_across_the_sample_space() {
        // Every residue class of the accepted region has the same size.
        let range = 10u64;
        let accepted = (0..range)
            .map(|residue| {
                (0..1000u64)
                    .filter(|step| {
                        accept_sample(step.wrapping_mul(range).wrapping_add(residue), range)
                            .is_some()
                    })
                    .count()
            })
            .collect::<Vec<_>>();
        assert!(accepted.iter().all(|count| *count == 1000));
    }

    #[test]
    fn rendering_pads_to_the_configured_width() {
        assert_eq!(render(7, Alphabet::Decimal, 6), "000007");
        assert_eq!(render(31, Alphabet::CrockfordBase32, 4), "000Z");
        assert_eq!(render(32, Alphabet::CrockfordBase32, 4), "0010");
    }
}

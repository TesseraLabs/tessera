//! The random tail of the hybrid nonce.
//!
//! The contract crate draws no randomness — it has to compile into a browser
//! tab — so the tail is drawn here, from the system generator and from nothing
//! else. There is no fallback: a device whose generator is unavailable does not
//! issue a challenge, because a nonce tail that is not random makes the whole
//! hybrid nonce a counter, and a counter is predictable to whoever is guessing
//! codes.
//!
//! The symbols are drawn by rejection rather than by reducing a byte modulo the
//! alphabet size. Reducing skews the low symbols — with ten symbols, thirty-two
//! of the two hundred and fifty-six byte values map to `0`..`5` and thirty
//! to `6`..`9` — and a skewed nonce tail is a tail with less entropy than the
//! parameters of the fleet promise.

use rand::TryRng as _;
use zeroize::Zeroizing;

use tessera_codes_contract::params::FleetParams;

/// Bytes drawn per refill of the buffer.
const DRAW_CHUNK: usize = 64;

/// Refills attempted before the draw gives up.
///
/// Each refill offers sixty-four bytes and the rejection rate is below one in
/// eight for every alphabet the contract accepts, so exhausting this many is
/// not reachable; the bound is here so the loop is bounded by construction.
const MAX_REFILLS: usize = 64;

/// Failure of drawing a tail.
#[derive(Debug, thiserror::Error)]
pub enum TailError {
    /// The system generator refused.
    #[error("the system random generator is unavailable: {reason}")]
    Rng {
        /// What the generator reported.
        reason: String,
    },
    /// The rejection sampling ran out of draws.
    #[error("drawing an unbiased nonce tail exhausted its draws")]
    Exhausted,
}

/// Draws a nonce tail of the width and alphabet the parameters fix.
///
/// The value is returned in [`Zeroizing`]: it is half of a nonce, and a nonce
/// that outlives its attempt in freed memory is a nonce somebody else can find.
///
/// # Errors
///
/// [`TailError::Rng`] when the system generator refuses — the method fails
/// closed there, with no second source — and [`TailError::Exhausted`] when the
/// rejection sampling runs out of draws.
pub fn draw_tail(params: &FleetParams) -> Result<Zeroizing<String>, TailError> {
    let symbols = params.alphabet().symbols();
    let width = usize::from(params.tail_width());
    // The largest multiple of the alphabet size that fits a byte; values at or
    // above it are thrown away rather than folded.
    let limit = 256 - (256 % symbols.len());

    let mut tail = Zeroizing::new(String::with_capacity(width));
    let mut buffer = Zeroizing::new([0_u8; DRAW_CHUNK]);
    for _ in 0..MAX_REFILLS {
        rand::rngs::SysRng
            .try_fill_bytes(&mut buffer[..])
            .map_err(|error| TailError::Rng {
                reason: error.to_string(),
            })?;
        for byte in buffer.iter() {
            if usize::from(*byte) >= limit {
                continue;
            }
            let index = usize::from(*byte) % symbols.len();
            let Some(symbol) = symbols.get(index) else {
                continue;
            };
            tail.push(char::from(*symbol));
            if tail.len() == width {
                return Ok(tail);
            }
        }
    }
    Err(TailError::Exhausted)
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use tessera_codes_contract::code::Alphabet;
    use tessera_codes_contract::nonce::Nonce;
    use tessera_codes_contract::params::{FleetParams, FleetParamsInput};

    use super::draw_tail;

    #[test]
    fn a_drawn_tail_fits_the_parameters() {
        let params = FleetParams::defaults();
        for _ in 0..64 {
            let tail = draw_tail(&params).unwrap();
            assert_eq!(tail.len(), usize::from(params.tail_width()));
            // The contract is the judge of what a tail may hold.
            assert!(Nonce::new(1, &tail, &params).is_ok(), "{}", *tail);
        }
    }

    #[test]
    fn a_drawn_tail_fits_a_base32_fleet() {
        let params = FleetParams::parse(FleetParamsInput {
            alphabet: Alphabet::CrockfordBase32,
            tail_width: 8,
            ..FleetParamsInput::defaults()
        })
        .unwrap();
        for _ in 0..64 {
            let tail = draw_tail(&params).unwrap();
            assert_eq!(tail.len(), 8);
            assert!(Nonce::new(1, &tail, &params).is_ok(), "{}", *tail);
        }
    }

    #[test]
    fn the_draw_does_not_return_one_repeated_tail() {
        let params = FleetParams::defaults();
        let first = draw_tail(&params).unwrap();
        let repeated = (0..32).all(|_| *draw_tail(&params).unwrap() == *first);
        assert!(!repeated, "every draw returned {}", *first);
    }
}

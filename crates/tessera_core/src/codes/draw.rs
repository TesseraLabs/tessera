//! Drawing the nonce of an attempt.
//!
//! The contract crate draws no randomness — it has to compile into a browser
//! tab — so the nonce is drawn here, from the system generator and from nothing
//! else. There is no fallback: a device whose generator is unavailable does not
//! issue a challenge. The nonce is the whole of what separates one attempt from
//! every other one, because nothing else does any more: there is no counter
//! beside it and no record on disk of the values this device has used.
//!
//! The symbols are drawn by rejection rather than by reducing a byte modulo the
//! alphabet size. Reducing skews the low symbols — with ten symbols, thirty-two
//! of the two hundred and fifty-six byte values map to `0`..`5` and thirty
//! to `6`..`9` — and a skewed nonce carries less entropy than the parameters of
//! the fleet promise.

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

/// Failure of drawing a nonce.
#[derive(Debug, thiserror::Error)]
pub enum DrawError {
    /// The system generator refused.
    #[error("the system random generator is unavailable: {reason}")]
    Rng {
        /// What the generator reported.
        reason: String,
    },
    /// The rejection sampling ran out of draws.
    #[error("drawing an unbiased nonce exhausted its draws")]
    Exhausted,
}

/// Draws a nonce of the width and alphabet the parameters fix.
///
/// The value is returned in [`Zeroizing`]: a nonce that outlives its attempt in
/// freed memory is a nonce somebody else can find, and there is no persisted
/// record anywhere that would refuse it a second time.
///
/// # Errors
///
/// [`DrawError::Rng`] when the system generator refuses — the method fails
/// closed there, with no second source — and [`DrawError::Exhausted`] when the
/// rejection sampling runs out of draws.
pub fn draw_nonce(params: &FleetParams) -> Result<Zeroizing<String>, DrawError> {
    let symbols = params.alphabet().symbols();
    let width = usize::from(params.nonce_width());
    // The largest multiple of the alphabet size that fits a byte; values at or
    // above it are thrown away rather than folded.
    let limit = 256 - (256 % symbols.len());

    let mut drawn = Zeroizing::new(String::with_capacity(width));
    let mut buffer = Zeroizing::new([0_u8; DRAW_CHUNK]);
    for _ in 0..MAX_REFILLS {
        rand::rngs::SysRng
            .try_fill_bytes(&mut buffer[..])
            .map_err(|error| DrawError::Rng {
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
            drawn.push(char::from(*symbol));
            if drawn.len() == width {
                return Ok(drawn);
            }
        }
    }
    Err(DrawError::Exhausted)
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

    use super::draw_nonce;

    #[test]
    fn a_drawn_nonce_fits_the_parameters() {
        let params = FleetParams::defaults();
        for _ in 0..64 {
            let nonce = draw_nonce(&params).unwrap();
            assert_eq!(nonce.len(), usize::from(params.nonce_width()));
            // The contract is the judge of what a nonce may hold.
            assert!(Nonce::parse(&nonce, &params).is_ok(), "{}", *nonce);
        }
    }

    #[test]
    fn a_drawn_nonce_fits_a_base32_fleet() {
        let params = FleetParams::parse(FleetParamsInput {
            alphabet: Alphabet::CrockfordBase32,
            nonce_width: 32,
            ..FleetParamsInput::defaults()
        })
        .unwrap();
        for _ in 0..64 {
            let nonce = draw_nonce(&params).unwrap();
            assert_eq!(nonce.len(), 32);
            assert!(Nonce::parse(&nonce, &params).is_ok(), "{}", *nonce);
        }
    }

    #[test]
    fn the_draw_does_not_return_one_repeated_value() {
        let params = FleetParams::defaults();
        let first = draw_nonce(&params).unwrap();
        let repeated = (0..32).all(|_| *draw_nonce(&params).unwrap() == *first);
        assert!(!repeated, "every draw returned {}", *first);
    }
}

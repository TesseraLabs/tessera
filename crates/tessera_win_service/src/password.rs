//! Generation of the technical account's password.
//!
//! The password is never chosen by a person and never typed by one: it is
//! generated here, stored under DPAPI, and handed to the credential provider
//! over the pipe. Its only human-facing constraint is Windows' own complexity
//! policy, which a domain or local policy may enforce on
//! `NetUserAdd` — a password rejected for complexity would make `prepare` fail
//! for a reason that has nothing to do with us, so all four character classes
//! are guaranteed rather than left to chance.
//!
//! Quote, backslash and space are absent from the alphabet. Not because the
//! code cannot handle them — nothing here builds a command line — but because
//! the value is occasionally copied by an operator during a bench run, and a
//! password that survives being pasted into a shell is worth the two bits of
//! entropy it costs.

use zeroize::Zeroizing;

/// Password length in characters. With the alphabet below (72 symbols) this is
/// about 148 bits, which is far past anything that matters here: the value is
/// machine-generated, never reused, and never exposed to an online guess.
const PASSWORD_LEN: usize = 24;

/// Uppercase letters.
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Lowercase letters.
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
/// Digits.
const DIGIT: &[u8] = b"0123456789";
/// Punctuation that survives a copy-paste.
const SYMBOL: &[u8] = b"!#$%&*+-=?@";

/// How many draws may be rejected before the source is declared broken. A
/// uniform source rejects with probability under 1/9 per byte, so reaching this
/// means the source is not random, and looping forever on a broken source is
/// worse than failing.
const MAX_DRAWS: usize = 4096;

/// Why a password could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// The entropy source failed.
    #[error("entropy source failed: {0}")]
    Entropy(String),
    /// The entropy source produced values that never passed rejection
    /// sampling, which means it is not producing uniform bytes.
    #[error("entropy source did not yield usable bytes")]
    Unusable,
}

/// A source of uniform random bytes.
///
/// A trait rather than a direct call to the system generator so the properties
/// below can be asserted against a source whose output is known.
pub trait RandomBytes {
    /// Fills `buf` with random bytes.
    ///
    /// # Errors
    ///
    /// [`PasswordError::Entropy`] when the source fails.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), PasswordError>;
}

/// The operating system's generator.
pub struct SystemRandom;

impl RandomBytes for SystemRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), PasswordError> {
        use rand::TryRng as _;

        rand::rngs::SysRng
            .try_fill_bytes(buf)
            .map_err(|e| PasswordError::Entropy(e.to_string()))
    }
}

/// The full alphabet, in class order.
fn alphabet() -> Vec<u8> {
    let mut all = Vec::with_capacity(UPPER.len() + LOWER.len() + DIGIT.len() + SYMBOL.len());
    all.extend_from_slice(UPPER);
    all.extend_from_slice(LOWER);
    all.extend_from_slice(DIGIT);
    all.extend_from_slice(SYMBOL);
    all
}

/// Generates a password from the system generator.
///
/// # Errors
///
/// See [`generate_with`].
pub fn generate() -> Result<Zeroizing<String>, PasswordError> {
    generate_with(&mut SystemRandom)
}

/// Generates a password from `source`, guaranteeing one character of each
/// class.
///
/// The returned buffer wipes itself when dropped; the caller is expected to
/// keep it no longer than it takes to store it.
///
/// # Errors
///
/// [`PasswordError::Entropy`] when the source fails, [`PasswordError::Unusable`]
/// when it never yields bytes that pass rejection sampling.
pub fn generate_with<R: RandomBytes>(source: &mut R) -> Result<Zeroizing<String>, PasswordError> {
    let alphabet = alphabet();
    loop {
        let candidate = draw(source, &alphabet, PASSWORD_LEN)?;
        if has_every_class(&candidate) {
            // The bytes are drawn from an ASCII alphabet, so this cannot fail;
            // the fallible form is used anyway rather than an unchecked
            // conversion, because "cannot fail" is a claim about code far from
            // here.
            let text =
                String::from_utf8(candidate.to_vec()).map_err(|_| PasswordError::Unusable)?;
            return Ok(Zeroizing::new(text));
        }
        // Missing a class is overwhelmingly unlikely at this length; redrawing
        // keeps every position uniform, which patching one character in would
        // not.
    }
}

/// Draws `len` characters uniformly from `alphabet` by rejection sampling.
fn draw<R: RandomBytes>(
    source: &mut R,
    alphabet: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
    let modulus = u16::try_from(alphabet.len()).map_err(|_| PasswordError::Unusable)?;
    // The largest multiple of the alphabet size that fits in a byte. Values at
    // or above it are discarded, which is what keeps the draw uniform instead
    // of biased towards the first characters.
    let ceiling = (256_u16 / modulus) * modulus;
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(len));
    let mut scratch = Zeroizing::new([0_u8; 64]);
    let mut draws = 0_usize;
    while out.len() < len {
        source.fill(scratch.as_mut_slice())?;
        for byte in scratch.iter().copied() {
            draws = draws.saturating_add(1);
            if draws > MAX_DRAWS {
                return Err(PasswordError::Unusable);
            }
            if u16::from(byte) >= ceiling {
                continue;
            }
            let index = usize::from(byte) % alphabet.len();
            let Some(symbol) = alphabet.get(index) else {
                return Err(PasswordError::Unusable);
            };
            out.push(*symbol);
            if out.len() == len {
                break;
            }
        }
    }
    Ok(out)
}

/// Whether `candidate` carries at least one character of every class.
fn has_every_class(candidate: &[u8]) -> bool {
    [UPPER, LOWER, DIGIT, SYMBOL]
        .iter()
        .all(|class| candidate.iter().any(|c| class.contains(c)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// A source that walks the byte space, so every draw is different and the
    /// rejection path is exercised.
    struct Counter(u8);

    impl RandomBytes for Counter {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), PasswordError> {
            for slot in buf.iter_mut() {
                *slot = self.0;
                self.0 = self.0.wrapping_add(7);
            }
            Ok(())
        }
    }

    /// A source that only ever produces values past the rejection ceiling.
    struct AlwaysRejected;

    impl RandomBytes for AlwaysRejected {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), PasswordError> {
            buf.fill(255);
            Ok(())
        }
    }

    /// A source that fails.
    struct Broken;

    impl RandomBytes for Broken {
        fn fill(&mut self, _buf: &mut [u8]) -> Result<(), PasswordError> {
            Err(PasswordError::Entropy("no entropy".to_owned()))
        }
    }

    #[test]
    fn generated_passwords_have_the_right_shape() {
        let password = generate_with(&mut Counter(1)).unwrap();
        assert_eq!(password.chars().count(), PASSWORD_LEN);
        assert!(has_every_class(password.as_bytes()));
        let alphabet = alphabet();
        assert!(
            password.bytes().all(|b| alphabet.contains(&b)),
            "password left the alphabet: {}",
            password.as_str()
        );
    }

    /// The system source is the one that ships; a shape check on it guards
    /// against a wiring mistake that a fixture source would hide.
    #[test]
    fn the_system_source_produces_a_usable_password() {
        let password = generate().unwrap();
        assert_eq!(password.chars().count(), PASSWORD_LEN);
        assert!(has_every_class(password.as_bytes()));
    }

    /// Two draws must not coincide. This is a smoke test for a wiring mistake
    /// (a fixed seed, a reused buffer), not a statistical one.
    #[test]
    fn two_passwords_differ() {
        assert_ne!(*generate().unwrap(), *generate().unwrap());
    }

    #[test]
    fn a_broken_source_fails_rather_than_producing_a_weak_password() {
        assert!(matches!(
            generate_with(&mut Broken),
            Err(PasswordError::Entropy(_))
        ));
        assert!(matches!(
            generate_with(&mut AlwaysRejected),
            Err(PasswordError::Unusable)
        ));
    }
}

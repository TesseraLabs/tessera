//! Certificate serial numbers: random, positive, at most 20 octets.
//!
//! RFC 5280 requires a serial to be a positive integer of at most 20 octets.
//! Tessera issues 128-bit random serials so independent operators need no shared
//! counter — collisions are statistically excluded (design decision D6). The
//! core is entropy-agnostic: [`Serial::from_entropy`] canonicalises caller-
//! supplied bytes, and the OS-entropy [`Serial::generate`] is a native-only
//! convenience so the `wasm32` core does not pull an entropy backend.

/// A canonical, positive, ≤ 20-octet certificate serial number.
///
/// The stored bytes are the DER `INTEGER` *content* (big-endian, minimal), ready
/// to wrap in an `INTEGER` TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serial(Vec<u8>);

impl Serial {
    /// Builds a serial from raw entropy: the high bit of the first octet is
    /// cleared (guaranteeing a positive value with no added sign octet), leading
    /// zero octets are stripped to a minimal encoding, an all-zero input becomes
    /// `1` (RFC 5280 forbids a zero serial), and the result is capped at 20
    /// octets.
    ///
    /// Passing 16 bytes yields a ~127-bit serial — the intended 128-bit-class
    /// width after the sign bit is cleared.
    #[must_use]
    pub fn from_entropy(bytes: &[u8]) -> Self {
        let mut value: Vec<u8> = bytes.to_vec();
        // Produce a minimal, sign-clear encoding. Clearing the sign bit of the
        // first octet can expose a fresh leading zero, and stripping a leading
        // zero can expose a new octet whose high bit is set — so strip and clear
        // in a loop until the leading octet is both minimal and positive. (A
        // single clear-then-strip pass is not enough: e.g. `0x80 0x85` would
        // leave `0x85`, which is still negative.)
        loop {
            while value.len() > 1 && value.first() == Some(&0) {
                value.remove(0);
            }
            match value.first_mut() {
                // Clear the sign bit so the INTEGER is unambiguously positive and
                // no extra 0x00 sign octet is ever needed.
                Some(first) if *first & 0x80 != 0 => *first &= 0x7F,
                _ => break,
            }
        }
        // RFC 5280 forbids a zero serial; an all-zero (or empty) input becomes 1.
        if value.is_empty() || value.iter().all(|&b| b == 0) {
            value = vec![1];
        }
        value.truncate(20);
        Self(value)
    }

    /// The DER `INTEGER` content octets of the serial.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Generates a fresh 128-bit random serial from the operating-system CSPRNG.
    ///
    /// Native only: the browser/`wasm32` core receives its serial through
    /// [`Serial::from_entropy`] from a host-provided random source instead.
    #[cfg(feature = "native")]
    #[must_use]
    pub fn generate() -> Self {
        use rand::Rng;
        let mut buf = [0u8; 16];
        rand::rng().fill_bytes(&mut buf);
        Self::from_entropy(&buf)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn clears_sign_bit() {
        let serial = Serial::from_entropy(&[0xFF; 16]);
        assert_eq!(serial.as_bytes().first().copied().unwrap() & 0x80, 0);
    }

    #[test]
    fn caps_at_twenty_octets_and_stays_positive() {
        let serial = Serial::from_entropy(&[0xAB; 32]);
        assert!(serial.as_bytes().len() <= 20);
        assert_eq!(serial.as_bytes().first().copied().unwrap() & 0x80, 0);
    }

    #[test]
    fn all_zero_entropy_becomes_one() {
        let serial = Serial::from_entropy(&[0u8; 16]);
        assert_eq!(serial.as_bytes(), &[1]);
    }

    #[test]
    fn strips_leading_zero_to_minimal() {
        // High bit already clear, plus a leading zero octet → minimal form drops it.
        let serial = Serial::from_entropy(&[0x00, 0x00, 0x2A]);
        assert_eq!(serial.as_bytes(), &[0x2A]);
    }

    #[test]
    fn clearing_sign_bit_that_exposes_a_high_octet_stays_positive() {
        // Masking the first octet to 0x00 exposes the next octet; if that octet
        // also has its high bit set the result must still be positive and
        // minimal. Regression for a non-positive serial from a single pass.
        for input in [
            [0x80, 0x90].as_slice(),
            &[0x80, 0x85],
            &[0x00, 0xFF, 0x01],
            &[0x80, 0x80, 0x05],
        ] {
            let serial = Serial::from_entropy(input);
            let first = serial.as_bytes().first().copied().unwrap();
            assert_eq!(
                first & 0x80,
                0,
                "serial {serial:02x?} from {input:02x?} must be positive"
            );
            assert_ne!(serial.as_bytes(), &[0]);
            // Minimal: no redundant leading zero octet.
            assert!(
                serial.as_bytes().len() == 1 || first != 0,
                "serial {serial:02x?} has a non-minimal leading zero",
            );
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn generate_is_positive_and_bounded() {
        for _ in 0..64 {
            let serial = Serial::generate();
            assert!(!serial.as_bytes().is_empty());
            assert!(serial.as_bytes().len() <= 20);
            assert_eq!(serial.as_bytes().first().copied().unwrap() & 0x80, 0);
            assert_ne!(serial.as_bytes(), &[0]);
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn two_generated_serials_differ() {
        // A 127-bit random space makes an equal pair astronomically unlikely.
        assert_ne!(Serial::generate(), Serial::generate());
    }
}

//! The time a document claims.
//!
//! The crate reads no clock: on the device it would be the clock of a machine
//! an engineer can set, in the cabinet the clock of a browser, and in a test
//! neither. Every moment therefore arrives from the caller, and the type says
//! whose word it is.

/// A moment claimed by the side that wrote a document, in seconds since the
/// Unix epoch.
///
/// **The value is untrusted.** It is what the issuing side wrote down, not what
/// any clock this crate can see says, and nothing about it has been checked:
/// the expiry of a ticket compares two such claims, which catches an honest
/// mistake and a stale document, not a signer that lies about the time. A
/// consumer that needs a trustworthy moment gets it from its own clock and
/// passes it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimedTime(u64);

impl ClaimedTime {
    /// Wraps a claimed moment.
    #[must_use]
    pub const fn new(seconds_since_epoch: u64) -> Self {
        Self(seconds_since_epoch)
    }

    /// Returns the raw value, in seconds since the Unix epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for ClaimedTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::ClaimedTime;

    #[test]
    fn moments_order_by_value() {
        assert!(ClaimedTime::new(10) < ClaimedTime::new(11));
        assert_eq!(ClaimedTime::new(10).get(), 10);
        assert_eq!(ClaimedTime::new(10).to_string(), "10");
    }
}

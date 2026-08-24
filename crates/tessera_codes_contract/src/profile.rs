//! Algorithm profile of the device key pair.
//!
//! The profile says which key agreement the two sides perform outside this
//! crate; the contract itself only carries it, checks it and refuses to let a
//! fleet start on a profile that has not been confirmed on real hardware.
//!
//! The ГОСТ profile is such a case. The formula is specified, but the vendor
//! library that has to compute VKO 34.10-2012 on a Linux build has not been
//! exercised end to end, and until it has, a fleet configured for it is a fleet
//! whose codes may not meet. Rather than emit a warning nobody reads, the parse
//! fails unless the configuration says, in a field of its own, that the risk is
//! accepted.

/// Key agreement profile of the device pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmProfile {
    /// NIST P-256 ECDH — the default of the international profile.
    P256,
    /// ГОСТ Р 34.10-2012 VKO — the profile of the Russian deployment. Not
    /// confirmed on hardware yet; see [`AlgorithmProfile::open_gate`].
    GostVko34102012,
    /// X25519 — offered as an option for fleets with no certification
    /// obligation.
    X25519,
}

impl AlgorithmProfile {
    /// Returns the identifier of the profile as it is written in a
    /// configuration and in the documents of the channel.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P256 => "p256",
            Self::GostVko34102012 => "gost-vko-34.10-2012",
            Self::X25519 => "x25519",
        }
    }

    /// Returns the open gate that keeps the profile unconfirmed, or [`None`]
    /// when the profile is confirmed.
    ///
    /// The text is part of the error a rejected configuration receives: an
    /// operator who meets the refusal has to learn what is missing without
    /// leaving the message.
    #[must_use]
    pub const fn open_gate(self) -> Option<&'static str> {
        match self {
            Self::P256 | Self::X25519 => None,
            Self::GostVko34102012 => Some(
                "VKO 34.10-2012 has not been exercised on a Linux build of the vendor PKCS#11 \
                 library; the key agreement of a fleet on this profile is unverified",
            ),
        }
    }

    /// Reports whether the profile has been confirmed on real hardware.
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        self.open_gate().is_none()
    }
}

/// Whether the fleet configuration accepts running on a profile whose vendor
/// gate is still open.
///
/// The acknowledgement is a value of its own rather than a `bool` with a
/// convenient default: a boolean field is set to `true` by a copied
/// configuration file and by a builder that fills in what it does not know,
/// and neither of those is a decision anybody made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnconfirmedProfileRisk {
    /// No decision was recorded — an unconfirmed profile does not parse.
    NotAccepted,
    /// The fleet owner accepted that the profile is unverified.
    AcceptedByFleetOwner,
}

impl Default for UnconfirmedProfileRisk {
    /// Returns [`UnconfirmedProfileRisk::NotAccepted`]: silence is not consent.
    fn default() -> Self {
        Self::NotAccepted
    }
}

#[cfg(test)]
mod tests {
    use super::{AlgorithmProfile, UnconfirmedProfileRisk};

    #[test]
    fn only_the_gost_profile_carries_an_open_gate() {
        assert!(AlgorithmProfile::P256.is_confirmed());
        assert!(AlgorithmProfile::X25519.is_confirmed());
        assert!(!AlgorithmProfile::GostVko34102012.is_confirmed());
        assert!(AlgorithmProfile::GostVko34102012
            .open_gate()
            .is_some_and(|gate| gate.contains("34.10-2012")));
    }

    #[test]
    fn the_risk_is_not_accepted_by_default() {
        assert_eq!(
            UnconfirmedProfileRisk::default(),
            UnconfirmedProfileRisk::NotAccepted
        );
    }
}

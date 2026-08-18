//! Failure of a code login attempt.
//!
//! The enum is deliberately coarse where the engineer at the device can see it
//! and precise where only the journal can. Every refusal that a caller could
//! turn into a probe — an unknown operator, a ticket outside its term, a ticket
//! on the revocation list, a scope that does not reach this device, a nonce
//! nobody issued, a code that does not meet — collapses into
//! [`CodeLoginError::Denied`]. What separated them is written to the audit
//! target instead, where it reaches an operator of the fleet and not a caller.
//!
//! The variants that are *not* denials are the ones an engineer has to act on:
//! the method is not installed, the attempt budget is spent, the counter of the
//! epoch is used up, or the persisted state moved backwards. None of them says
//! anything about a secret.

/// Refusal of a code login.
#[derive(Debug, thiserror::Error)]
pub enum CodeLoginError {
    /// The device carries no artefacts for the code method.
    ///
    /// Not a configuration error of the module: a device that was never given
    /// a key container and a ticket set simply does not offer this method, and
    /// the PAM stack moves on to the next one.
    #[error("the code login method is not provisioned on this device")]
    Unavailable,

    /// The platform cannot provide what the method rests on.
    ///
    /// Not a fault of the device and not a state it can be repaired into: the
    /// key that computes the codes is stored **without a password**, because a
    /// device has to verify codes after a reboot with nobody standing next to
    /// it, so what protects that key is the permissions of the file it sits in
    /// and nothing else. Outside Unix there is no mode word to check — the
    /// equivalent is a DACL, and no DACL work exists here — which leaves two
    /// possibilities, of which only one is acceptable: the method does not run
    /// there, or the key that computes the access codes of a cash machine lies
    /// under permissions nobody verified.
    ///
    /// Kept apart from [`CodeLoginError::Unavailable`] because the facts differ
    /// — a provisioned device on the wrong platform against an unprovisioned
    /// one — even though a PAM stack answers both the same way: skip this
    /// method, try the next.
    #[error(
        "the code login method needs POSIX file permissions, which this platform does not have"
    )]
    UnsupportedPlatform,

    /// The attempt was refused. The reason is in the audit journal.
    #[error("the code login attempt was refused")]
    Denied,

    /// The attempt budget of this nonce is spent.
    ///
    /// The PAM branch reports this as `PAM_MAXTRIES`; it is not the same
    /// answer as [`CodeLoginError::Denied`] and must not be folded into it.
    #[error("the attempt budget of this code is exhausted")]
    AttemptsExhausted,

    /// The device refuses for now, and will stop refusing on its own.
    ///
    /// Two limits produce this: the budget of challenges the device issues in a
    /// window, which is what keeps a caller from spending the nonce counter to
    /// exhaustion, and the lock a run of failed attempts puts on one role. Both
    /// expire without anybody clearing them — see [`super::throttle`].
    #[error("the code method is refusing for another {} second(s)", retry_after.as_secs())]
    TemporarilyLocked {
        /// How long the caller has to wait.
        retry_after: std::time::Duration,
    },

    /// The nonce counter no longer fits the width of the fleet parameters.
    ///
    /// The counter is never carried around its modulus, because a repeated
    /// nonce inside one key epoch repeats a code. The device owes a key epoch
    /// rotation before it can issue another challenge.
    #[error("the nonce counter of this key epoch is exhausted; rotate the key epoch")]
    CounterExhausted,

    /// The persisted state of the method moved backwards.
    ///
    /// Restoring a device from a snapshot rolls its counter back with it, and
    /// a rolled-back counter re-issues nonces that have already been spoken
    /// aloud. The method refuses until the key epoch is rotated.
    #[error("the persisted code state moved backwards; rotate the key epoch")]
    StateRollback,

    /// The operating system random generator refused to fill the nonce tail.
    ///
    /// There is no fallback inside this method: a nonce tail drawn from
    /// anything other than the system generator is not a nonce tail.
    #[error("the system random generator is unavailable: {reason}")]
    Rng {
        /// What the generator reported.
        reason: String,
    },

    /// The persisted state could not be read or written.
    #[error("the persisted code state is unusable: {reason}")]
    State {
        /// What the underlying operation reported.
        reason: String,
    },

    /// The trusted-time markers of the device could not be read.
    ///
    /// Without them a pending attempt cannot be invalidated on a reboot, and
    /// an attempt that survives a reboot is an attempt whose one-time nonce is
    /// no longer one-time.
    #[error("the boot markers of the device are unreadable: {reason}")]
    BootMarkers {
        /// What the underlying read reported.
        reason: String,
    },
}

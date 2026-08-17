//! What it costs to ask this device for a challenge, and to guess a code.
//!
//! The attempt budget of a single nonce is not a rate limit. It bounds one
//! conversation and nothing else, and two things fall straight through it:
//!
//! - **guessing**: every new call to the PAM stack yields a fresh nonce with a
//!   fresh budget, so an attacker who is willing to start again is limited only
//!   by how fast they can open connections;
//! - **exhausting the counter**, which is worse: the challenge is printed
//!   *before* any code is presented, so anyone who reaches the PAM stack with
//!   the name of a role account spends one value of the nonce counter per
//!   attempt without knowing a ticket, an operator or a code. The counter is
//!   finite and never wraps — that is what keeps a nonce from repeating inside
//!   a key epoch — so a device driven to the end of it stops offering the
//!   method until somebody physically brings a new key epoch. For a machine
//!   nobody can reach any other way, that is the worst outcome there is.
//!
//! This module is the second limit: what a caller may ask for, rather than what
//! they may answer.
//!
//! # Two limits, deliberately different
//!
//! **Issuance is capped device-wide, by time.** At most
//! [`MAX_CHALLENGES_PER_WINDOW`] challenges leave the device per
//! [`CHALLENGE_WINDOW`], counted across every role, because the resource being
//! protected — the nonce counter — is device-wide. Beyond that the device
//! refuses to issue, and refusing to issue costs no counter value.
//!
//! **Failures lock one role, by count.** Consecutive failed attempts on a role
//! arm a lock on that role alone, with a delay that grows and then stops
//! growing at [`MAX_LOCKOUT`].
//!
//! # The cure is not the disease
//!
//! Every refusal here expires on its own. A lock that hangs a login until an
//! engineer drives to the site is not better than the attack it prevents; on a
//! cash machine it is the same outage with a different cause. So there is no
//! state in this module that a person has to clear, and the longest anything
//! lasts is [`MAX_LOCKOUT`].
//!
//! Two consequences were chosen rather than inherited, and both are worth
//! stating plainly:
//!
//! - **A flood does deny service, briefly.** Filling the issuance window keeps
//!   an honest engineer waiting for the rest of it. That is accepted: minutes
//!   of waiting against a counter that never comes back.
//! - **Only what follows a challenge counts as a failure.** A rejected ticket,
//!   an operator identifier nobody holds, a scope that does not reach this
//!   device — none of them arms the lock, because none of them costs the device
//!   anything. If they did, an attacker who knows no secret at all could keep a
//!   role locked out indefinitely by failing cheaply, forever.
//!
//! # What this does not fix
//!
//! Rate limiting turns "an afternoon" into "years", not into "never". The other
//! half of that arithmetic is the width of the nonce counter, which is a fleet
//! parameter: at the default six digits a device sustains roughly a hundred
//! days of uninterrupted attack before the counter is spent, and every extra
//! digit multiplies that by ten. A fleet that expects its devices to be
//! reachable by strangers should widen the counter, and this note is here so
//! that decision is made rather than defaulted into.
//!
//! # Time
//!
//! Every moment here is whole seconds since boot, from the same markers the
//! rest of the method uses: the wall clock of a device an engineer stands in
//! front of is theirs to set, and a lock measured against it would be a lock
//! they could end. See [`super::boot`].
//!
//! A reboot restarts the since-boot scale, so the timers are re-armed rather
//! than cleared: the *count* of consecutive failures survives, and the wait it
//! earns starts again from the new boot. Rebooting therefore buys an attacker
//! one wait, never a clean slate.

use std::collections::BTreeMap;
use std::time::Duration;

/// Span the issuance budget is counted over.
///
/// A phone call in which an engineer reads out a challenge and reads back a
/// code takes minutes, and a second challenge in the same call means the first
/// was misheard. Two minutes is therefore long enough that no honest
/// conversation notices this limit and short enough that a caller who does hit
/// it waits rather than gives up.
pub const CHALLENGE_WINDOW: Duration = Duration::from_mins(2);

/// Challenges the device will issue within one [`CHALLENGE_WINDOW`].
///
/// Eight is more than any honest conversation needs and is what bounds the
/// consumption of the nonce counter: it is the number that turns the counter
/// from something an attacker spends in an afternoon into something they spend
/// months on. See the module note on counter width.
pub const MAX_CHALLENGES_PER_WINDOW: u32 = 8;

/// Consecutive failed attempts on a role before it is locked.
///
/// An attempt is one nonce carried to the end of its own budget, not one wrong
/// code. The two limits would otherwise contradict each other: the fleet
/// parameters grant a nonce several tries, and a lock armed by the third wrong
/// code would take the rest of them away from the engineer they were granted
/// to. What this counts is conversations that ended in nothing.
pub const LOCKOUT_AFTER_FAILURES: u32 = 3;

/// First wait a locked role earns.
pub const LOCKOUT_BASE: Duration = Duration::from_secs(30);

/// Longest wait a locked role can earn.
///
/// The cap is the whole reason the backoff is safe to double: without it, a
/// role that failed twenty times would be locked for years, which is an outage
/// nobody ordered.
pub const MAX_LOCKOUT: Duration = Duration::from_mins(15);

/// Delay the caller applies before reporting a refusal.
///
/// The spec asks for delays as well as a lockout, and a delay is the part that
/// costs an attacker something on *every* attempt rather than only on the third.
/// It is returned rather than slept here: this crate does not block, and the
/// branch that owns the login is the one that can afford to wait.
pub const FAILURE_DELAY: Duration = Duration::from_secs(2);

/// Roles tracked at once.
///
/// A role only earns an entry once it has been given a challenge, so the set is
/// bounded by the role base of the device; the cap is a second bound in case
/// that base is large.
pub const MAX_TRACKED_ROLES: usize = 64;

/// What a caller may do right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The request may proceed.
    Allow,
    /// The request is refused until the wait has passed.
    Wait(Duration),
}

impl Verdict {
    /// Returns the wait, or [`None`] when the request may proceed.
    #[must_use]
    pub const fn wait(self) -> Option<Duration> {
        match self {
            Self::Allow => None,
            Self::Wait(wait) => Some(wait),
        }
    }
}

/// The failure ledger of one role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoleLedger {
    /// Attempts that failed in a row, without a success in between.
    pub consecutive_failures: u32,
    /// Moment, in seconds since boot, the lock ends at. Zero means unlocked.
    pub locked_until: u64,
}

/// The issuance window and the failure ledgers of one device.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Throttle {
    window_started: u64,
    issued_in_window: u32,
    roles: BTreeMap<String, RoleLedger>,
}

impl Throttle {
    /// Rebuilds the throttle from persisted values.
    #[must_use]
    pub fn restore(
        window_started: u64,
        issued_in_window: u32,
        roles: BTreeMap<String, RoleLedger>,
    ) -> Self {
        Self {
            window_started,
            issued_in_window,
            roles,
        }
    }

    /// Returns the start of the current window and how much of it is spent.
    #[must_use]
    pub const fn window(&self) -> (u64, u32) {
        (self.window_started, self.issued_in_window)
    }

    /// Returns the failure ledgers, for persistence.
    #[must_use]
    pub const fn ledgers(&self) -> &BTreeMap<String, RoleLedger> {
        &self.roles
    }

    /// Reports whether the device may issue a challenge for `role_id` now.
    #[must_use]
    pub fn check_issue(&self, role_id: &str, now: u64) -> Verdict {
        if let Verdict::Wait(wait) = self.check_verify(role_id, now) {
            return Verdict::Wait(wait);
        }
        if self.window_elapsed(now) {
            return Verdict::Allow;
        }
        if self.issued_in_window < MAX_CHALLENGES_PER_WINDOW {
            return Verdict::Allow;
        }
        Verdict::Wait(Duration::from_secs(
            CHALLENGE_WINDOW
                .as_secs()
                .saturating_sub(now.saturating_sub(self.window_started)),
        ))
    }

    /// Reports whether a code may be verified for `role_id` now.
    ///
    /// Only the lock applies: a conversation that already holds a challenge has
    /// spent its counter value, and refusing to read the code back would waste
    /// it without making anything safer.
    #[must_use]
    pub fn check_verify(&self, role_id: &str, now: u64) -> Verdict {
        match self.roles.get(role_id) {
            Some(ledger) if ledger.locked_until > now => {
                Verdict::Wait(Duration::from_secs(ledger.locked_until - now))
            }
            _ => Verdict::Allow,
        }
    }

    /// Records that a challenge was issued.
    ///
    /// Called after the challenge exists, not before: a request refused for any
    /// other reason spent no counter value and must not spend budget either.
    pub fn note_issued(&mut self, now: u64) {
        // An empty window is not an old window: a device that has issued
        // nothing has no window open, and anchoring one at boot would give the
        // first caller of the day whatever was left of a span nobody used.
        if self.issued_in_window == 0 || self.window_elapsed(now) {
            self.window_started = now;
            self.issued_in_window = 0;
        }
        self.issued_in_window = self.issued_in_window.saturating_add(1);
    }

    /// Records an attempt on `role_id` that ended without a login, arming the
    /// lock once the failures run past [`LOCKOUT_AFTER_FAILURES`].
    pub fn note_failure(&mut self, role_id: &str, now: u64) {
        self.make_room(role_id);
        let ledger = self.roles.entry(role_id.to_owned()).or_default();
        ledger.consecutive_failures = ledger.consecutive_failures.saturating_add(1);
        if ledger.consecutive_failures >= LOCKOUT_AFTER_FAILURES {
            let wait = backoff(ledger.consecutive_failures);
            ledger.locked_until = now.saturating_add(wait.as_secs());
        }
    }

    /// Records a login on `role_id`: the ledger of that role starts again.
    ///
    /// The issuance window is left alone. It protects the counter, not the
    /// password, and a successful login is no reason to let the next caller
    /// spend eight more values.
    pub fn note_success(&mut self, role_id: &str) {
        self.roles.remove(role_id);
    }

    /// Re-arms the timers against a since-boot scale that has restarted.
    ///
    /// The counts are kept and the waits are re-derived from them: a reboot
    /// costs an attacker the wait they were already serving, and nothing more.
    pub fn rebase_to_new_boot(&mut self) {
        self.window_started = 0;
        self.issued_in_window = 0;
        for ledger in self.roles.values_mut() {
            ledger.locked_until = if ledger.consecutive_failures >= LOCKOUT_AFTER_FAILURES {
                backoff(ledger.consecutive_failures).as_secs()
            } else {
                0
            };
        }
    }

    /// Reports whether the current window is over at `now`.
    ///
    /// A moment before the start of the window — which only a caller passing a
    /// clock that moved backwards can produce — counts as over, so the window
    /// restarts rather than staying shut for as long as the jump was.
    fn window_elapsed(&self, now: u64) -> bool {
        now < self.window_started
            || now.saturating_sub(self.window_started) >= CHALLENGE_WINDOW.as_secs()
    }

    /// Drops a ledger when the table is full.
    ///
    /// The one dropped is the one whose lock ends soonest, so that an attacker
    /// cannot push the role they are working on out of the table by touching
    /// other roles: the entry they armed is the last to go, not the first.
    fn make_room(&mut self, incoming: &str) {
        if self.roles.len() < MAX_TRACKED_ROLES || self.roles.contains_key(incoming) {
            return;
        }
        let evictable = self
            .roles
            .iter()
            .min_by_key(|(_, ledger)| (ledger.locked_until, ledger.consecutive_failures))
            .map(|(role, _)| role.clone());
        if let Some(role) = evictable {
            self.roles.remove(&role);
        }
    }
}

/// Returns the wait earned by `failures` consecutive failures.
///
/// Doubling from [`LOCKOUT_BASE`], capped at [`MAX_LOCKOUT`]. The shift is
/// bounded before it is taken: a saturating multiplication would be enough for
/// the value, but a shift past the width of the type is a defect regardless of
/// what the caller does with the result.
fn backoff(failures: u32) -> Duration {
    let steps = failures.saturating_sub(LOCKOUT_AFTER_FAILURES).min(16);
    let seconds = LOCKOUT_BASE
        .as_secs()
        .saturating_mul(1u64 << steps)
        .min(MAX_LOCKOUT.as_secs());
    Duration::from_secs(seconds)
}

#[cfg(test)]
#[expect(
    clippy::panic,
    reason = "an unmet precondition in a test should fail the test on the spot"
)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::{
        backoff, RoleLedger, Throttle, Verdict, CHALLENGE_WINDOW, LOCKOUT_AFTER_FAILURES,
        LOCKOUT_BASE, MAX_CHALLENGES_PER_WINDOW, MAX_LOCKOUT, MAX_TRACKED_ROLES,
    };

    const ROLE: &str = "oper";

    #[test]
    fn issuance_is_allowed_up_to_the_window_budget() {
        let mut throttle = Throttle::default();
        for issued in 0..MAX_CHALLENGES_PER_WINDOW {
            assert_eq!(
                throttle.check_issue(ROLE, 10),
                Verdict::Allow,
                "challenge {issued} should be inside the budget"
            );
            throttle.note_issued(10);
        }
        assert!(matches!(throttle.check_issue(ROLE, 10), Verdict::Wait(_)));
    }

    #[test]
    fn the_issuance_budget_returns_by_itself() {
        let mut throttle = Throttle::default();
        for _ in 0..MAX_CHALLENGES_PER_WINDOW {
            throttle.note_issued(10);
        }
        let Verdict::Wait(wait) = throttle.check_issue(ROLE, 10) else {
            panic!("the budget should be spent");
        };
        assert_eq!(wait, CHALLENGE_WINDOW);

        // One second before the window ends, and one second after it.
        let ends_at = 10 + CHALLENGE_WINDOW.as_secs();
        assert!(matches!(
            throttle.check_issue(ROLE, ends_at - 1),
            Verdict::Wait(_)
        ));
        assert_eq!(throttle.check_issue(ROLE, ends_at), Verdict::Allow);
    }

    #[test]
    fn the_budget_is_device_wide_and_not_per_role() {
        let mut throttle = Throttle::default();
        for _ in 0..MAX_CHALLENGES_PER_WINDOW {
            throttle.note_issued(10);
        }
        // The resource being protected is one counter, so another role does not
        // get another budget.
        assert!(matches!(
            throttle.check_issue("another", 10),
            Verdict::Wait(_)
        ));
    }

    #[test]
    fn failures_lock_the_role_only_after_the_threshold() {
        let mut throttle = Throttle::default();
        for _ in 1..LOCKOUT_AFTER_FAILURES {
            throttle.note_failure(ROLE, 100);
            assert_eq!(throttle.check_verify(ROLE, 100), Verdict::Allow);
        }
        throttle.note_failure(ROLE, 100);
        assert_eq!(
            throttle.check_verify(ROLE, 100),
            Verdict::Wait(LOCKOUT_BASE)
        );
    }

    #[test]
    fn a_lock_belongs_to_one_role() {
        let mut throttle = Throttle::default();
        for _ in 0..LOCKOUT_AFTER_FAILURES {
            throttle.note_failure(ROLE, 100);
        }
        assert!(matches!(throttle.check_verify(ROLE, 100), Verdict::Wait(_)));
        assert_eq!(throttle.check_verify("another", 100), Verdict::Allow);
    }

    #[test]
    fn a_lock_ends_on_its_own() {
        let mut throttle = Throttle::default();
        for _ in 0..LOCKOUT_AFTER_FAILURES {
            throttle.note_failure(ROLE, 100);
        }
        let ends_at = 100 + LOCKOUT_BASE.as_secs();
        assert!(matches!(
            throttle.check_verify(ROLE, ends_at - 1),
            Verdict::Wait(_)
        ));
        assert_eq!(throttle.check_verify(ROLE, ends_at), Verdict::Allow);
    }

    #[test]
    fn a_login_clears_the_ledger_of_that_role() {
        let mut throttle = Throttle::default();
        for _ in 0..LOCKOUT_AFTER_FAILURES {
            throttle.note_failure(ROLE, 100);
        }
        throttle.note_success(ROLE);
        assert_eq!(throttle.check_verify(ROLE, 100), Verdict::Allow);
    }

    #[test]
    fn the_wait_grows_and_then_stops_growing() {
        assert_eq!(backoff(LOCKOUT_AFTER_FAILURES), LOCKOUT_BASE);
        assert_eq!(backoff(LOCKOUT_AFTER_FAILURES + 1), LOCKOUT_BASE * 2);
        assert_eq!(backoff(LOCKOUT_AFTER_FAILURES + 2), LOCKOUT_BASE * 4);
        // However long the run of failures, the wait stops at the cap — a lock
        // measured in years is an outage, not a defence.
        assert_eq!(backoff(u32::MAX), MAX_LOCKOUT);
        for failures in 0..1000u32 {
            assert!(backoff(failures) <= MAX_LOCKOUT);
        }
    }

    #[test]
    fn a_reboot_restarts_the_wait_but_not_the_ledger() {
        let mut throttle = Throttle::default();
        for _ in 0..LOCKOUT_AFTER_FAILURES {
            throttle.note_failure(ROLE, 5_000);
        }
        throttle.rebase_to_new_boot();

        // Zero seconds since the new boot: the wait is being served again, from
        // the beginning, and the count that earned it is untouched.
        assert_eq!(throttle.check_verify(ROLE, 0), Verdict::Wait(LOCKOUT_BASE));
        assert_eq!(
            throttle.check_verify(ROLE, LOCKOUT_BASE.as_secs()),
            Verdict::Allow
        );
        throttle.note_failure(ROLE, LOCKOUT_BASE.as_secs());
        assert_eq!(
            throttle.check_verify(ROLE, LOCKOUT_BASE.as_secs()),
            Verdict::Wait(LOCKOUT_BASE * 2)
        );
    }

    #[test]
    fn a_reboot_does_not_leave_an_unlocked_role_locked() {
        let mut throttle = Throttle::default();
        throttle.note_failure(ROLE, 5_000);
        throttle.rebase_to_new_boot();
        assert_eq!(throttle.check_verify(ROLE, 0), Verdict::Allow);
    }

    #[test]
    fn a_clock_that_moved_backwards_does_not_shut_the_window_for_the_length_of_the_jump() {
        let mut throttle = Throttle::default();
        for _ in 0..MAX_CHALLENGES_PER_WINDOW {
            throttle.note_issued(10_000);
        }
        assert_eq!(throttle.check_issue(ROLE, 5), Verdict::Allow);
    }

    #[test]
    fn the_ledger_table_keeps_the_armed_entry_when_it_overflows() {
        let mut throttle = Throttle::default();
        // Fill the table with roles that failed once and are not locked.
        for index in 0..MAX_TRACKED_ROLES {
            throttle.note_failure(&format!("role-{index:03}"), 100);
        }
        // Arm one of them properly.
        for _ in 1..LOCKOUT_AFTER_FAILURES {
            throttle.note_failure("role-000", 100);
        }
        assert!(matches!(
            throttle.check_verify("role-000", 100),
            Verdict::Wait(_)
        ));

        // Touching further roles evicts the unlocked entries, never the armed one.
        for index in 0..MAX_TRACKED_ROLES {
            throttle.note_failure(&format!("newcomer-{index:03}"), 100);
        }
        assert!(throttle.ledgers().len() <= MAX_TRACKED_ROLES);
        assert!(matches!(
            throttle.check_verify("role-000", 100),
            Verdict::Wait(_)
        ));
    }

    #[test]
    fn the_throttle_round_trips_through_its_persisted_values() {
        let mut throttle = Throttle::default();
        throttle.note_issued(10);
        throttle.note_failure(ROLE, 10);
        let (started, issued) = throttle.window();
        let restored = Throttle::restore(started, issued, throttle.ledgers().clone());
        assert_eq!(restored, throttle);
    }

    #[test]
    fn a_restored_ledger_is_the_one_that_was_written() {
        let restored = Throttle::restore(
            7,
            3,
            BTreeMap::from([(
                ROLE.to_owned(),
                RoleLedger {
                    consecutive_failures: 4,
                    locked_until: 500,
                },
            )]),
        );
        assert_eq!(
            restored.check_verify(ROLE, 100),
            Verdict::Wait(Duration::from_secs(400))
        );
        assert_eq!(restored.window(), (7, 3));
    }
}

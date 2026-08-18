//! Persisted state of the code method: which nonces are alive, which are spent.
//!
//! Three things have to survive a power cut on a device nobody can reach:
//!
//! - **which nonces were already spent**, because a one-time nonce that forgets
//!   it was used is not one-time. This is the whole of the offline replay
//!   defence, and it is why the state is written to disk rather than kept in
//!   the process that printed the challenge;
//! - **how many wrong codes each pending nonce has taken**, because the budget
//!   is per nonce and a restart between two guesses must not refill it;
//! - **which boot the pending attempts belong to**, because an attempt cannot
//!   outlive the running system it was started on.
//!
//! The last point is what closes the loss of trusted time. A pending attempt
//! carries the boot identifier it was started under and the whole seconds since
//! that boot. A reboot changes the identifier and every pending attempt is
//! dropped; a monotonic clock dragged backwards leaves a pending attempt that
//! claims to have started later than the present moment, and every pending
//! attempt is dropped as well. Neither case is repaired: an attempt whose
//! lifetime cannot be measured is refused, not extended.
//!
//! The consumed set is *not* dropped on a reboot. That is the asymmetry the
//! design rests on: pending attempts are cheap to redo and dangerous to keep,
//! spent nonces are the opposite.
//!
//! # Rollback
//!
//! The counter file and this file are written together, counter first. A device
//! restored from a snapshot brings both back, and a counter that reads smaller
//! than the highest value this file has seen means nonces already spoken aloud
//! are about to be issued again. The load refuses, and the fleet owes the
//! device a key epoch rotation — which is what the recovery procedure of a
//! fleet has to include anyway.
//!
//! The reverse order is survivable and is allowed: a crash between the two
//! writes leaves a counter ahead of this file, which burns a nonce and repeats
//! none.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use super::boot::BootMarkers;
use super::counter::{self, IssuedCounter};
use super::throttle::{RoleLedger, Throttle, MAX_TRACKED_ROLES};

/// Name of the state file inside the state directory.
pub const STATE_FILENAME: &str = "nonce.state";

/// Permissions of the state file: root alone.
const STATE_MODE: u32 = 0o600;

/// Marker that opens the file and pins the version of its format.
const STATE_PREFIX: &str = "tessera-codes/state/v1";

/// Largest number of attempts kept alive at once — the grace window.
///
/// The window is a security parameter, not a comfort one: every nonce alive at
/// the same moment is another target a guesser may hit, so the bound is small
/// and the oldest attempt is spent rather than kept when a new one arrives.
pub const MAX_PENDING_ATTEMPTS: usize = 8;

/// Largest number of individually remembered spent nonces.
///
/// Beyond this the lowest values are folded into a floor: everything at or
/// below the floor counts as spent. Folding can only refuse more, never less.
pub const MAX_CONSUMED_NONCES: usize = 64;

/// Longest state file accepted, in bytes.
const MAX_STATE_BYTES: usize = 64 * 1024;

/// An attempt that has been issued and not yet finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingAttempt {
    /// Counter half of the nonce that was issued.
    pub counter: u64,
    /// Whole seconds since boot at the moment the challenge was printed.
    pub started_since_boot: u64,
    /// Wrong codes this nonce has already taken.
    pub attempts_used: u8,
}

/// Failure of the persisted state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// The state moved backwards against the counter file.
    #[error("the persisted nonce counter is behind the state file")]
    Rollback,
    /// The state file does not hold what the format describes.
    #[error("the persisted code state is malformed: {reason}")]
    Corrupt {
        /// What was wrong with the file.
        reason: String,
    },
    /// The state could not be read or written.
    #[error("the persisted code state could not be read or written: {0}")]
    Io(#[from] io::Error),
}

/// The state of the code method on one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeState {
    boot_id: String,
    issued: u64,
    consumed_floor: u64,
    consumed: BTreeSet<u64>,
    pending: Vec<PendingAttempt>,
    throttle: Throttle,
}

impl CodeState {
    /// Loads the state of `state_dir` and reconciles it with the markers of the
    /// running system.
    ///
    /// Reconciliation is part of loading rather than a step a caller may skip:
    /// a caller holding an unreconciled state would be holding pending attempts
    /// from before a reboot.
    ///
    /// # Errors
    ///
    /// [`StateError::Rollback`] when the counter file is behind this file,
    /// [`StateError::Corrupt`] for a file that does not parse, and
    /// [`StateError::Io`] for a read that failed.
    pub fn load(state_dir: &Path, markers: &BootMarkers) -> Result<Self, StateError> {
        let counter_issued = counter::read_issued(state_dir)?.map_or(0, IssuedCounter::get);
        let mut state = match fs::read_to_string(state_path(state_dir)) {
            Ok(text) => Self::parse(&text)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self {
                boot_id: markers.boot_id().to_owned(),
                issued: 0,
                consumed_floor: 0,
                consumed: BTreeSet::new(),
                pending: Vec::new(),
                throttle: Throttle::default(),
            },
            Err(error) => return Err(StateError::Io(error)),
        };

        if counter_issued < state.issued {
            return Err(StateError::Rollback);
        }
        state.issued = counter_issued.max(state.issued);

        let rebooted = state.boot_id != markers.boot_id();
        let clock_moved_back = state
            .pending
            .iter()
            .any(|attempt| attempt.started_since_boot > markers.since_boot_secs());
        if rebooted || clock_moved_back {
            // The nonces of the dropped attempts are spent, not merely
            // forgotten: a challenge that was printed was read aloud, and the
            // only safe assumption about a value spoken into a telephone is
            // that somebody wrote it down.
            let dropped: Vec<u64> = state
                .pending
                .iter()
                .map(|attempt| attempt.counter)
                .collect();
            state.pending.clear();
            for counter in dropped {
                state.mark_consumed(counter);
            }
            markers.boot_id().clone_into(&mut state.boot_id);
            // The since-boot scale the throttle measures against has restarted,
            // so its timers are re-armed rather than believed. Clearing them
            // instead would make a power cycle the way out of a lockout.
            state.throttle.rebase_to_new_boot();
        }

        Ok(state)
    }

    /// Returns the counter the next challenge should carry.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::Corrupt`] only when the counter has reached the
    /// end of `u64`; the narrower limit of the fleet parameters is enforced
    /// where the nonce itself is built.
    pub fn next_counter(&self) -> Result<u64, StateError> {
        self.issued.checked_add(1).ok_or(StateError::Corrupt {
            reason: "the nonce counter reached the end of its representation".to_owned(),
        })
    }

    /// Records that `counter` was issued at `since_boot`.
    ///
    /// When the grace window is full the oldest attempt is spent to make room:
    /// keeping it alive would widen the window a guesser works against, and
    /// silently dropping it without marking it spent would let its nonce be
    /// used later.
    pub fn record_issued(&mut self, counter: u64, since_boot: u64) {
        self.issued = self.issued.max(counter);
        if self.pending.len() >= MAX_PENDING_ATTEMPTS {
            if let Some(position) = self
                .pending
                .iter()
                .enumerate()
                .min_by_key(|(_, attempt)| attempt.counter)
                .map(|(position, _)| position)
            {
                let oldest = self.pending.remove(position);
                self.mark_consumed(oldest.counter);
            }
        }
        self.pending.push(PendingAttempt {
            counter,
            started_since_boot: since_boot,
            attempts_used: 0,
        });
    }

    /// Returns the pending attempt carrying `counter`, if it is still alive.
    #[must_use]
    pub fn pending(&self, counter: u64) -> Option<PendingAttempt> {
        self.pending
            .iter()
            .find(|attempt| attempt.counter == counter)
            .copied()
    }

    /// Reports whether `counter` has been spent.
    #[must_use]
    pub fn is_consumed(&self, counter: u64) -> bool {
        (self.consumed_floor > 0 && counter <= self.consumed_floor)
            || self.consumed.contains(&counter)
    }

    /// Takes one attempt from the budget of `counter` and returns how many it
    /// has now taken.
    ///
    /// Charged *before* the code is compared, not after: the comparison and the
    /// write that records it are two steps, and a process that ends between
    /// them would hand the next caller a budget that never moved. There is no
    /// lockout anywhere else in this method to catch that.
    ///
    /// Returns `None` when no attempt with that counter is pending.
    pub fn charge_attempt(&mut self, counter: u64) -> Option<u8> {
        let attempt = self
            .pending
            .iter_mut()
            .find(|attempt| attempt.counter == counter)?;
        attempt.attempts_used = attempt.attempts_used.saturating_add(1);
        Some(attempt.attempts_used)
    }

    /// Gives back an attempt charged for something that was not an answer.
    ///
    /// The device failing to assemble a key is not an engineer guessing wrong,
    /// and the budget exists to bound guessing. The charge still happens first
    /// — a refund that does not reach the disk costs one attempt, which is the
    /// direction this has to fail in.
    pub fn refund_attempt(&mut self, counter: u64) {
        if let Some(attempt) = self
            .pending
            .iter_mut()
            .find(|attempt| attempt.counter == counter)
        {
            attempt.attempts_used = attempt.attempts_used.saturating_sub(1);
        }
    }

    /// Returns the issuance budget and the failure ledgers of this device.
    #[must_use]
    pub const fn throttle(&self) -> &Throttle {
        &self.throttle
    }

    /// Returns the throttle for a caller about to record something in it.
    pub const fn throttle_mut(&mut self) -> &mut Throttle {
        &mut self.throttle
    }

    /// Spends `counter`: it leaves the grace window and is refused from now on.
    pub fn consume(&mut self, counter: u64) {
        self.pending.retain(|attempt| attempt.counter != counter);
        self.mark_consumed(counter);
    }

    /// Returns the highest counter this device has issued.
    #[must_use]
    pub const fn issued(&self) -> u64 {
        self.issued
    }

    /// Returns the attempts currently inside the grace window.
    #[must_use]
    pub fn pending_attempts(&self) -> &[PendingAttempt] {
        &self.pending
    }

    /// Writes the state to `state_dir`, atomically.
    ///
    /// # Errors
    ///
    /// The underlying I/O failure.
    pub fn save(&self, state_dir: &Path) -> Result<(), StateError> {
        let path = state_path(state_dir);
        let tmp = state_dir.join(format!(".{STATE_FILENAME}.{}.tmp", std::process::id()));
        let rendered = self.render();
        let result = (|| -> io::Result<()> {
            let mut file = crate::fs_mode::create_with_mode(&tmp, STATE_MODE)?;
            file.write_all(rendered.as_bytes())?;
            file.sync_all()?;
            crate::fs_mode::pin_mode(&tmp, STATE_MODE)?;
            fs::rename(&tmp, &path)?;
            // The rename has to be durable too, not only the bytes it names:
            // a spent nonce whose record was lost with the directory entry is
            // a nonce that forgets it was spoken aloud.
            crate::fs_mode::sync_dir(state_dir)
        })();
        if result.is_err() {
            if let Err(cleanup) = fs::remove_file(&tmp) {
                if cleanup.kind() != io::ErrorKind::NotFound {
                    tracing::warn!(
                        target: "codes.audit",
                        path = %tmp.display(),
                        error = %cleanup,
                        "failed to clean up the code state temporary file"
                    );
                }
            }
        }
        result.map_err(StateError::Io)
    }

    /// Adds `counter` to the spent set, folding the oldest values into the
    /// floor once the set outgrows its bound.
    fn mark_consumed(&mut self, counter: u64) {
        self.consumed.insert(counter);
        while self.consumed.len() > MAX_CONSUMED_NONCES {
            let Some(lowest) = self.consumed.iter().next().copied() else {
                break;
            };
            self.consumed_floor = self.consumed_floor.max(lowest);
            self.consumed.retain(|value| *value > self.consumed_floor);
        }
    }

    /// Renders the file.
    fn render(&self) -> String {
        let consumed = self
            .consumed
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut lines = vec![
            STATE_PREFIX.to_owned(),
            format!("boot={}", self.boot_id),
            format!("issued={}", self.issued),
            format!("floor={}", self.consumed_floor),
            format!("consumed={consumed}"),
        ];
        let (window_started, issued_in_window) = self.throttle.window();
        lines.push(format!("window={window_started},{issued_in_window}"));
        lines.extend(self.throttle.ledgers().iter().map(|(role, ledger)| {
            format!(
                "role={role},{},{}",
                ledger.consecutive_failures, ledger.locked_until
            )
        }));
        lines.extend(self.pending.iter().map(|attempt| {
            format!(
                "pending={},{},{}",
                attempt.counter, attempt.started_since_boot, attempt.attempts_used
            )
        }));
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }

    /// Parses the file.
    ///
    /// Nothing is repaired and nothing is skipped: a line the format does not
    /// describe means the file was written by something other than this code,
    /// and a state of unknown provenance is not a state to keep counting from.
    fn parse(text: &str) -> Result<Self, StateError> {
        if text.len() > MAX_STATE_BYTES {
            return Err(StateError::Corrupt {
                reason: "the state file is longer than the format allows".to_owned(),
            });
        }
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(STATE_PREFIX) {
            return Err(StateError::Corrupt {
                reason: "the state file does not open with the format marker".to_owned(),
            });
        }

        let mut boot_id = None;
        let mut issued = None;
        let mut floor = None;
        let mut consumed = BTreeSet::new();
        let mut seen_consumed = false;
        let mut pending = Vec::new();
        let mut window = None;
        let mut ledgers = BTreeMap::new();

        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| StateError::Corrupt {
                reason: "a line of the state file is not a key and a value".to_owned(),
            })?;
            match key {
                "boot" if boot_id.is_none() && !value.is_empty() => {
                    boot_id = Some(value.to_owned());
                }
                "issued" if issued.is_none() => issued = Some(parse_u64("issued", value)?),
                "floor" if floor.is_none() => floor = Some(parse_u64("floor", value)?),
                "consumed" if !seen_consumed => {
                    seen_consumed = true;
                    for item in value.split(',').filter(|item| !item.is_empty()) {
                        consumed.insert(parse_u64("consumed", item)?);
                    }
                }
                "window" if window.is_none() => window = Some(parse_window(value)?),
                "role" => {
                    if ledgers.len() == MAX_TRACKED_ROLES {
                        return Err(StateError::Corrupt {
                            reason: "the state file tracks more roles than the throttle holds"
                                .to_owned(),
                        });
                    }
                    let (role, ledger) = parse_ledger(value)?;
                    ledgers.insert(role, ledger);
                }
                "pending" => {
                    if pending.len() == MAX_PENDING_ATTEMPTS {
                        return Err(StateError::Corrupt {
                            reason: "the state file holds more pending attempts than the grace \
                                     window allows"
                                .to_owned(),
                        });
                    }
                    pending.push(parse_pending(value)?);
                }
                other => {
                    return Err(StateError::Corrupt {
                        reason: format!("the state file carries an unexpected field `{other}`"),
                    })
                }
            }
        }

        Ok(Self {
            boot_id: boot_id.ok_or_else(|| StateError::Corrupt {
                reason: "the state file names no boot".to_owned(),
            })?,
            issued: issued.ok_or_else(|| StateError::Corrupt {
                reason: "the state file names no issued counter".to_owned(),
            })?,
            consumed_floor: floor.ok_or_else(|| StateError::Corrupt {
                reason: "the state file names no consumed floor".to_owned(),
            })?,
            consumed,
            pending,
            throttle: {
                let (started, issued_in_window) = window.unwrap_or((0, 0));
                Throttle::restore(started, issued_in_window, ledgers)
            },
        })
    }
}

/// Returns the path of the state file inside `state_dir`.
fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILENAME)
}

/// Parses one decimal field.
fn parse_u64(field: &str, value: &str) -> Result<u64, StateError> {
    value.parse::<u64>().map_err(|_| StateError::Corrupt {
        reason: format!("the field `{field}` of the state file is not a decimal number"),
    })
}

/// Parses one `pending` record.
fn parse_pending(value: &str) -> Result<PendingAttempt, StateError> {
    let mut fields = value.split(',');
    let counter = parse_u64("pending.counter", fields.next().unwrap_or_default())?;
    let started_since_boot = parse_u64(
        "pending.started_since_boot",
        fields.next().unwrap_or_default(),
    )?;
    let attempts_used = fields
        .next()
        .unwrap_or_default()
        .parse::<u8>()
        .map_err(|_| StateError::Corrupt {
            reason: "the attempt count of a pending record is not a small number".to_owned(),
        })?;
    if fields.next().is_some() {
        return Err(StateError::Corrupt {
            reason: "a pending record of the state file carries too many fields".to_owned(),
        });
    }
    Ok(PendingAttempt {
        counter,
        started_since_boot,
        attempts_used,
    })
}

/// Parses a `window` record: the moment it opened and how much of it is spent.
fn parse_window(value: &str) -> Result<(u64, u32), StateError> {
    let mut fields = value.split(',');
    let started = parse_u64("window.started", fields.next().unwrap_or_default())?;
    let issued = fields
        .next()
        .unwrap_or_default()
        .parse::<u32>()
        .map_err(|_| StateError::Corrupt {
            reason: "the issued count of the window record is not a number".to_owned(),
        })?;
    if fields.next().is_some() {
        return Err(StateError::Corrupt {
            reason: "the window record of the state file carries too many fields".to_owned(),
        });
    }
    Ok((started, issued))
}

/// Parses a `role` record: the failure ledger of one role.
///
/// The role identifier cannot hold a comma — the schema of a role slice admits
/// lowercase letters, digits and a dash — so the fields need no escaping. An
/// identifier that does hold one is refused rather than split: it did not come
/// from a role base of this device.
fn parse_ledger(value: &str) -> Result<(String, RoleLedger), StateError> {
    let mut fields = value.split(',');
    let role = fields.next().unwrap_or_default();
    if role.is_empty() {
        return Err(StateError::Corrupt {
            reason: "a role record of the state file names no role".to_owned(),
        });
    }
    let consecutive_failures = fields
        .next()
        .unwrap_or_default()
        .parse::<u32>()
        .map_err(|_| StateError::Corrupt {
            reason: "the failure count of a role record is not a number".to_owned(),
        })?;
    let locked_until = parse_u64("role.locked_until", fields.next().unwrap_or_default())?;
    if fields.next().is_some() {
        return Err(StateError::Corrupt {
            reason: "a role record of the state file carries too many fields".to_owned(),
        });
    }
    Ok((
        role.to_owned(),
        RoleLedger {
            consecutive_failures,
            locked_until,
        },
    ))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use std::time::Duration;

    use super::{CodeState, MAX_PENDING_ATTEMPTS};
    use crate::codes::boot::BootMarkers;

    fn markers(boot: &str, since_boot: u64) -> BootMarkers {
        BootMarkers::new(boot, Duration::from_secs(since_boot))
    }

    #[test]
    fn a_fresh_device_starts_at_the_first_counter() {
        let dir = tempfile::tempdir().unwrap();
        let state = CodeState::load(dir.path(), &markers("boot-a", 10)).unwrap();
        assert_eq!(state.next_counter().unwrap(), 1);
        assert!(state.pending_attempts().is_empty());
    }

    #[test]
    fn the_grace_window_spends_the_oldest_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let boot = markers("boot-a", 10);
        let mut state = CodeState::load(dir.path(), &boot).unwrap();
        for counter in 1..=(MAX_PENDING_ATTEMPTS as u64 + 1) {
            state.record_issued(counter, 10);
        }
        assert_eq!(state.pending_attempts().len(), MAX_PENDING_ATTEMPTS);
        assert!(state.pending(1).is_none());
        assert!(state.is_consumed(1));
    }

    /// Tests that write the persisted state of the device.
    ///
    /// They need a platform whose file permissions can be checked, and that is a
    /// property of the method rather than of the harness: the device key is kept
    /// **without a password**, because codes have to be verified after a reboot
    /// with nobody there to type one, so what protects it is the mode of the
    /// files beside it. Outside Unix there is no mode word — the equivalent is a
    /// DACL, and none is written here — so the writes below refuse by design.
    /// See `codes::store`, `codes::lock` and the storage of `tessera_hashchain`,
    /// where the same boundary is stated, and `platform_offers_the_method`,
    /// which is where the product answers it.
    ///
    /// Reading the same state stays outside this group: a device that cannot
    /// write a counter can still parse one, and those tests keep running
    /// everywhere.
    #[cfg(unix)]
    mod persisted {
        use super::super::{StateError, MAX_CONSUMED_NONCES, STATE_FILENAME};
        use super::*;
        use crate::codes::counter;
        use tempfile::TempDir;

        /// Issues one nonce and persists both files, the way the method does.
        fn issue(dir: &TempDir, markers: &BootMarkers) -> u64 {
            let mut state = CodeState::load(dir.path(), markers).unwrap();
            let counter = state.next_counter().unwrap();
            counter::write_issued(dir.path(), counter).unwrap();
            state.record_issued(counter, markers.since_boot_secs());
            state.save(dir.path()).unwrap();
            counter
        }

        #[test]
        fn the_counter_only_moves_forward_across_restarts() {
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 10);
            assert_eq!(issue(&dir, &boot), 1);
            assert_eq!(issue(&dir, &boot), 2);
            // A new process on the same boot keeps counting where the last left off.
            let state = CodeState::load(dir.path(), &boot).unwrap();
            assert_eq!(state.next_counter().unwrap(), 3);
            assert_eq!(state.pending_attempts().len(), 2);
        }

        #[test]
        fn a_reboot_drops_pending_attempts_and_spends_their_nonces() {
            let dir = tempfile::tempdir().unwrap();
            let counter = issue(&dir, &markers("boot-a", 10));

            let state = CodeState::load(dir.path(), &markers("boot-b", 3)).unwrap();
            assert!(state.pending(counter).is_none());
            assert!(state.is_consumed(counter));
            // The counter itself survives: the nonce is spent, not re-issuable.
            assert_eq!(state.next_counter().unwrap(), counter + 1);
        }

        #[test]
        fn a_monotonic_clock_dragged_backwards_drops_pending_attempts() {
            let dir = tempfile::tempdir().unwrap();
            let counter = issue(&dir, &markers("boot-a", 500));

            let state = CodeState::load(dir.path(), &markers("boot-a", 499)).unwrap();
            assert!(state.pending(counter).is_none());
            assert!(state.is_consumed(counter));
        }

        #[test]
        fn a_spent_nonce_stays_spent_across_a_reboot() {
            let dir = tempfile::tempdir().unwrap();
            let counter = issue(&dir, &markers("boot-a", 10));
            let mut state = CodeState::load(dir.path(), &markers("boot-a", 20)).unwrap();
            state.consume(counter);
            state.save(dir.path()).unwrap();

            let reloaded = CodeState::load(dir.path(), &markers("boot-b", 5)).unwrap();
            assert!(reloaded.is_consumed(counter));
            assert!(reloaded.pending(counter).is_none());
        }

        #[test]
        fn wrong_codes_accumulate_across_restarts() {
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 10);
            let counter = issue(&dir, &boot);

            let mut state = CodeState::load(dir.path(), &boot).unwrap();
            assert_eq!(state.charge_attempt(counter), Some(1));
            state.save(dir.path()).unwrap();

            let mut reloaded = CodeState::load(dir.path(), &boot).unwrap();
            assert_eq!(reloaded.pending(counter).unwrap().attempts_used, 1);
            assert_eq!(reloaded.charge_attempt(counter), Some(2));
            assert_eq!(reloaded.charge_attempt(u64::MAX), None);
        }

        #[test]
        fn a_counter_file_behind_the_state_is_a_rollback() {
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 10);
            issue(&dir, &boot);
            issue(&dir, &boot);
            // The snapshot brought an older counter back while the state file kept
            // the value the device really reached.
            counter::write_issued(dir.path(), 1).unwrap();
            assert!(matches!(
                CodeState::load(dir.path(), &boot),
                Err(StateError::Rollback)
            ));
        }

        #[test]
        fn a_counter_file_ahead_of_the_state_is_survivable() {
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 10);
            issue(&dir, &boot);
            // A crash between the two writes: the counter advanced, the state file
            // did not. The nonce is burned and none is repeated.
            counter::write_issued(dir.path(), 9).unwrap();
            let state = CodeState::load(dir.path(), &boot).unwrap();
            assert_eq!(state.next_counter().unwrap(), 10);
        }

        #[test]
        fn the_spent_set_folds_into_a_floor_without_forgetting_anything() {
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 10);
            let mut state = CodeState::load(dir.path(), &boot).unwrap();
            let last = MAX_CONSUMED_NONCES as u64 + 20;
            for counter in 1..=last {
                state.consume(counter);
            }
            for counter in 1..=last {
                assert!(state.is_consumed(counter), "{counter} was forgotten");
            }
            assert!(!state.is_consumed(last + 1));

            state.save(dir.path()).unwrap();
            let reloaded = CodeState::load(dir.path(), &boot).unwrap();
            assert!(reloaded.is_consumed(1));
            assert!(!reloaded.is_consumed(last + 1));
        }

        #[test]
        fn a_state_file_of_unknown_shape_does_not_load() {
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 10);
            issue(&dir, &boot);
            let path = dir.path().join(STATE_FILENAME);

            let good = std::fs::read_to_string(&path).unwrap();
            for damaged in [
                good.replace("tessera-codes/state/v1", "tessera-codes/state/v2"),
                format!("{good}surprise=1\n"),
                good.replace("issued=", "issued=x"),
                good.replacen("boot=", "", 1),
            ] {
                std::fs::write(&path, damaged.as_bytes()).unwrap();
                assert!(matches!(
                    CodeState::load(dir.path(), &boot),
                    Err(StateError::Corrupt { .. })
                ));
            }
        }

        #[test]
        fn the_state_round_trips_through_the_file() {
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 10);
            let counter = issue(&dir, &boot);
            let mut state = CodeState::load(dir.path(), &boot).unwrap();
            state.charge_attempt(counter);
            state.consume(2);
            state.save(dir.path()).unwrap();
            assert_eq!(CodeState::load(dir.path(), &boot).unwrap(), state);
        }
    }
}

//! Persisted state of the code method: what a flood has already cost this
//! device.
//!
//! One thing survives a power cut here, and it is not the attempt. It is the
//! throttle — how much of the issuance window this device has spent, and which
//! roles are locked after a run of wrong codes. That has to outlive a process
//! because every login is a process of its own: a limit kept in memory would be
//! reset by the next call, which is exactly the call it exists to refuse.
//!
//! # What deliberately does not live here
//!
//! The attempt. Not its nonce, not its ephemeral private key, not the count of
//! wrong codes it has taken. All of it lives in the memory of the process
//! holding the attempt open, from the moment the challenge is printed to the
//! moment the code is accepted or refused, and it dies with that process.
//!
//! That is the whole replay defence, and it is stronger than the file it
//! replaces. A device restored from a snapshot without memory has no attempt at
//! all: a code cut for the nonce of the snapshot meets nothing, because nothing
//! is holding that nonce open. The file this module used to keep — spent
//! nonces, pending attempts, a monotonic counter — came back with the snapshot
//! together with the counter that was supposed to detect it, so the rollback
//! check compared two values that were rolled back as one. Removing the file
//! removes the thing that was being rolled back.
//!
//! What it does not cover is a snapshot taken *with* memory: that restores the
//! attempt itself. Nothing on a device without a hardware monotonic anchor
//! detects it, and the specification states that as a premise of the
//! environment rather than a property of the product.
//!
//! # Time
//!
//! Whole seconds since boot, from the markers the rest of the method uses. A
//! reboot restarts that scale, so the throttle is re-armed against the new boot
//! rather than believed — see [`Throttle::rebase_to_new_boot`]. Clearing it
//! instead would make a power cycle the way out of a lockout.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use super::boot::BootMarkers;
use super::throttle::{RoleLedger, Throttle, MAX_TRACKED_ROLES};

/// Name of the state file inside the state directory.
pub const STATE_FILENAME: &str = "nonce.state";

/// Permissions of the state file: root alone.
const STATE_MODE: u32 = 0o600;

/// Marker that opens the file and pins the version of its format.
const STATE_PREFIX: &str = "tessera-codes/state/v2";

/// Longest state file accepted, in bytes.
const MAX_STATE_BYTES: usize = 64 * 1024;

/// Failure of the persisted state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
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
    throttle: Throttle,
}

impl CodeState {
    /// Loads the state of `state_dir` and reconciles it with the markers of the
    /// running system.
    ///
    /// Reconciliation is part of loading rather than a step a caller may skip:
    /// a caller holding an unreconciled state would be measuring the throttle
    /// against a since-boot scale that no longer runs.
    ///
    /// # Errors
    ///
    /// [`StateError::Corrupt`] for a file that does not parse, and
    /// [`StateError::Io`] for a read that failed. A file that is not there is
    /// not a failure: a device that has never refused anything has nothing to
    /// remember.
    pub fn load(state_dir: &Path, markers: &BootMarkers) -> Result<Self, StateError> {
        let mut state = match fs::read_to_string(state_path(state_dir)) {
            Ok(text) => Self::parse(&text)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self {
                boot_id: markers.boot_id().to_owned(),
                throttle: Throttle::default(),
            },
            Err(error) => return Err(StateError::Io(error)),
        };

        if state.boot_id != markers.boot_id() {
            markers.boot_id().clone_into(&mut state.boot_id);
            state.throttle.rebase_to_new_boot();
        }

        Ok(state)
    }

    /// Returns the throttle.
    #[must_use]
    pub const fn throttle(&self) -> &Throttle {
        &self.throttle
    }

    /// Returns the throttle for modification.
    #[must_use]
    pub const fn throttle_mut(&mut self) -> &mut Throttle {
        &mut self.throttle
    }

    /// Writes the state durably.
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
            // The rename has to be durable too, not only the bytes it names: a
            // lockout whose record was lost with the directory entry is a
            // lockout the next power cycle lifts.
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

    /// Renders the file.
    fn render(&self) -> String {
        let mut lines = vec![STATE_PREFIX.to_owned(), format!("boot={}", self.boot_id)];
        let (window_started, issued_in_window) = self.throttle.window();
        lines.push(format!("window={window_started},{issued_in_window}"));
        lines.extend(self.throttle.ledgers().iter().map(|(role, ledger)| {
            format!(
                "role={role},{},{}",
                ledger.consecutive_failures, ledger.locked_until
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
    /// A file left by the format that persisted attempts carries fields this
    /// one does not know, so it is refused rather than half-read.
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
            throttle: {
                // Required like the boot line above it. The doctrine of this
                // parser is that nothing is repaired and nothing is skipped,
                // and a missing window quietly restored as "no issuances yet"
                // is a repair: the file would come back as an open issuance
                // budget, which is the one direction a missing field must not
                // be read in.
                let (started, issued_in_window) = window.ok_or_else(|| StateError::Corrupt {
                    reason: "the state file names no issuance window".to_owned(),
                })?;
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

    use super::{CodeState, STATE_FILENAME};
    use crate::codes::boot::BootMarkers;

    fn markers(boot: &str, since_boot: u64) -> BootMarkers {
        BootMarkers::new(boot, Duration::from_secs(since_boot))
    }

    #[test]
    fn a_device_with_no_file_starts_with_an_empty_throttle() {
        let dir = tempfile::tempdir().unwrap();
        let state = CodeState::load(dir.path(), &markers("boot-a", 10)).unwrap();
        assert_eq!(state.throttle().window(), (0, 0));
        assert!(state.throttle().ledgers().is_empty());
    }

    #[test]
    fn a_state_file_of_the_format_that_persisted_attempts_does_not_load() {
        // The old format carried `issued`, `consumed` and `pending` lines. A
        // device upgraded in place must refuse that file rather than read the
        // half of it this format still recognises: what those lines meant is
        // gone, and a state of unknown provenance is not a state to count from.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(STATE_FILENAME),
            "tessera-codes/state/v1\nboot=boot-a\nissued=7\nfloor=0\nconsumed=1,2\n",
        )
        .unwrap();
        assert!(CodeState::load(dir.path(), &markers("boot-a", 10)).is_err());
    }

    #[test]
    fn a_state_file_without_its_window_does_not_load() {
        // "Nothing is repaired and nothing is skipped" is the doctrine of this
        // parser, and the window used to be the one exception: a file missing
        // it came back as a budget nobody had spent, which is the direction a
        // missing field must never be read in.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(STATE_FILENAME),
            "tessera-codes/state/v2\nboot=boot-a\n",
        )
        .unwrap();
        assert!(CodeState::load(dir.path(), &markers("boot-a", 10)).is_err());
    }

    #[test]
    fn a_state_file_of_unknown_shape_does_not_load() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(STATE_FILENAME),
            "tessera-codes/state/v2\nboot=boot-a\nsomething=else\n",
        )
        .unwrap();
        assert!(CodeState::load(dir.path(), &markers("boot-a", 10)).is_err());
    }

    /// Tests that WRITE the persisted state.
    ///
    /// They need a platform whose file permissions can be pinned, and that is a
    /// property of the method rather than of the harness: the device key beside
    /// this file is kept **without a password** — codes are verified after a
    /// reboot with nobody there to type one — so what protects it is the mode of
    /// the files around it. Outside Unix there is no mode word, the equivalent
    /// is a DACL and none is written here, so `fs_mode` refuses and the write
    /// fails closed. The product answers the same question earlier, in
    /// `platform_offers_the_method`: a device that cannot carry the store is
    /// refused the method, so nothing outside these tests reaches this path.
    ///
    /// Reading and parsing stay outside this group and keep running everywhere:
    /// a platform that cannot write a state file can still be shown that a
    /// malformed one is refused. The same split is in `codes::epoch`.
    #[cfg(unix)]
    mod persisted {
        use super::*;

        #[test]
        fn the_throttle_survives_a_restart_of_the_process() {
            // The reason this file exists at all: every login is a new process, so
            // a budget that lived in memory would be refilled by the caller it is
            // meant to refuse.
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 100);
            let mut state = CodeState::load(dir.path(), &boot).unwrap();
            state.throttle_mut().note_issued(100);
            state.throttle_mut().note_failure("oper", 100);
            state.save(dir.path()).unwrap();

            let reloaded = CodeState::load(dir.path(), &boot).unwrap();
            assert_eq!(reloaded.throttle().window().1, 1);
            assert_eq!(
                reloaded
                    .throttle()
                    .ledgers()
                    .get("oper")
                    .map(|ledger| ledger.consecutive_failures),
                Some(1)
            );
        }

        #[test]
        fn a_reboot_rearms_the_throttle_rather_than_clearing_it() {
            let dir = tempfile::tempdir().unwrap();
            let mut state = CodeState::load(dir.path(), &markers("boot-a", 100)).unwrap();
            state.throttle_mut().note_failure("oper", 100);
            state.save(dir.path()).unwrap();

            let after_reboot = CodeState::load(dir.path(), &markers("boot-b", 1)).unwrap();
            assert_eq!(
                after_reboot
                    .throttle()
                    .ledgers()
                    .get("oper")
                    .map(|ledger| ledger.consecutive_failures),
                Some(1),
                "a power cycle must not be the way out of a lockout"
            );
        }

        #[test]
        fn the_state_round_trips_through_the_file() {
            let dir = tempfile::tempdir().unwrap();
            let boot = markers("boot-a", 50);
            let mut state = CodeState::load(dir.path(), &boot).unwrap();
            state.throttle_mut().note_issued(50);
            state.throttle_mut().note_failure("oper", 50);
            state.save(dir.path()).unwrap();
            assert_eq!(CodeState::load(dir.path(), &boot).unwrap(), state);
        }
    }
}

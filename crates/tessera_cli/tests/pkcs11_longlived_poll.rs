//! Long-lived-context poll measurement for the presence monitor.
//!
//! The monitor keeps one PKCS#11 context open for the life of the daemon and
//! polls it every interval, while a login process reaches the same provider
//! through its own context. The failures this provider is known for
//! (`rtpkcs11ecp` 2.14.1 aborting on a concurrent `C_Initialize`) all sit at
//! initialization, so a measurement made with `pkcs11-tool` — which
//! initializes and finalizes per invocation — says nothing about the shape the
//! monitor actually runs in.
//!
//! What this measures, per poll: `C_GetSlotList` plus one `C_GetTokenInfo` per
//! slot, timed individually. The interesting figure is the tail, not the mean:
//! a hang inside the vendor library is not cured by restarting the service, so
//! a single multi-second call matters more than a slow average.
//!
//! The second test answers a different question with the same held context:
//! whether a token that is unplugged and plugged back in is ever seen again.
//! PKCS#11 permits a provider to fix its slot list at `C_Initialize`, and this
//! codebase never finalizes — so a provider that behaves that way leaves the
//! monitor permanently blind while still looking like it works, which is worse
//! than having no monitor at all. It needs the carrier to actually move, by a
//! hand or by a bench that can detach it.
//!
//! Ignored by default — they need hardware and take minutes.
//!
//! ```text
//! # concurrency measurement, beside a login loop in another process
//! PKCS11_MODULE_PATH=… cargo test -p tessera_cli --test pkcs11_longlived_poll \
//!     a_long_lived_context_polls_without_stalling -- --ignored --nocapture
//!
//! # reconnect check — prompts for the token to be pulled and reinserted
//! PKCS11_MODULE_PATH=… cargo test -p tessera_cli --test pkcs11_longlived_poll \
//!     a_reconnected_token_is_seen_again -- --ignored --nocapture
//!
//! # same check on a bench that detaches the carrier itself, emitting marks
//! # a driving script subtracts its own timestamps from
//! PKCS11_MODULE_PATH=… TESSERA_RECONNECT_MODE=marks \
//!     cargo test -p tessera_cli --test pkcs11_longlived_poll \
//!     a_reconnected_token_is_seen_again -- --ignored --nocapture
//! ```
//!
//! Environment:
//!
//! - `PKCS11_MODULE_PATH` — the provider (unset: the tests skip).
//! - `TESSERA_POLL_SECONDS` — measurement duration, default 150.
//! - `TESSERA_POLL_INTERVAL_MS` — interval between polls, default 300.
//! - `TESSERA_CARRIER_TOKEN_SERIAL` — which token the reconnect check watches.
//!   Unset means the only one connected; with several connected it must name
//!   the one that will be pulled.
//! - `TESSERA_RECONNECT_TIMEOUT_SECONDS` — how long each half of the reconnect
//!   check waits, default 90.
//! - `TESSERA_RECONNECT_MODE` — `manual` (default; prompts an operator) or
//!   `marks` (no prompts, for a bench that detaches the carrier on its own).
//!
//! Both modes print machine-readable marks on stdout, all offsets measured
//! from one origin per run:
//!
//! ```text
//! TESSERA_POLL_MARK  unix_ms=… run_ms=… serials=483d4e1a,48b541ca
//! TESSERA_POLL_MARK  unix_ms=… run_ms=… error=…
//! TESSERA_EVENT_MARK unix_ms=… run_ms=… event=carrier_absent serial=483d4e1a
//! ```
//!
//! `run_ms` is for comparing marks within a run; `unix_ms` is the clock a
//! separate process can also read, which is what makes provider latency
//! measurable at all — see the note on the reconnect test about why the
//! manual-mode durations are not that measurement.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::{Duration, Instant};

use tessera_core::token::pkcs11::{read_token_serial, LockingMode, Pkcs11Backend};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Percentile of an already-sorted slice, by nearest rank.
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

#[test]
#[ignore = "needs a real token and runs for minutes"]
fn a_long_lived_context_polls_without_stalling() {
    let Some(module) = tessera_core::token::pkcs11::test_helpers::pkcs11_test_module_path() else {
        eprintln!("skipped: PKCS11_MODULE_PATH is not set to an existing module");
        return;
    };
    let duration = Duration::from_secs(env_u64("TESSERA_POLL_SECONDS", 150));
    let interval = Duration::from_millis(env_u64("TESSERA_POLL_INTERVAL_MS", 300));

    // One context, held for the whole run: this is the shape the monitor uses.
    let backend = Pkcs11Backend::load(&module, LockingMode::Mutex).expect("load the provider");

    let mut slot_list_times: Vec<Duration> = Vec::new();
    let mut token_info_times: Vec<Duration> = Vec::new();
    let mut polls = 0_u64;
    let mut slot_list_errors = 0_u64;
    let mut token_info_errors = 0_u64;
    let mut serial_sets: Vec<Vec<String>> = Vec::new();

    let started = Instant::now();
    while started.elapsed() < duration {
        polls += 1;
        let t0 = Instant::now();
        let slots = backend.list_slots_with_token();
        slot_list_times.push(t0.elapsed());
        match slots {
            Ok(slots) => {
                let mut serials = Vec::new();
                for slot in slots {
                    let t1 = Instant::now();
                    let serial = read_token_serial(&backend, slot);
                    token_info_times.push(t1.elapsed());
                    match serial {
                        Ok(s) => serials.push(s),
                        Err(e) => {
                            token_info_errors += 1;
                            eprintln!("poll {polls}: C_GetTokenInfo on {slot}: {e}");
                        }
                    }
                }
                serials.sort();
                if serial_sets.last() != Some(&serials) {
                    eprintln!(
                        "poll {polls} at {:?}: present serials = {serials:?}",
                        started.elapsed()
                    );
                    serial_sets.push(serials);
                }
            }
            Err(e) => {
                slot_list_errors += 1;
                eprintln!("poll {polls}: C_GetSlotList: {e}");
            }
        }
        std::thread::sleep(interval);
    }

    slot_list_times.sort();
    token_info_times.sort();
    for (name, times) in [
        ("C_GetSlotList", &slot_list_times),
        ("C_GetTokenInfo", &token_info_times),
    ] {
        if times.is_empty() {
            eprintln!("{name}: no samples");
            continue;
        }
        eprintln!(
            "{name}: n={} p50={:?} p95={:?} p99={:?} max={:?}",
            times.len(),
            percentile(times, 50.0),
            percentile(times, 95.0),
            percentile(times, 99.0),
            times[times.len() - 1],
        );
    }
    eprintln!(
        "polls={polls} slot_list_errors={slot_list_errors} token_info_errors={token_info_errors} \
         distinct_serial_sets={}",
        serial_sets.len()
    );
}

/// Every present token's serial, or the error the poll produced.
///
/// A serial that could not be read fails the whole poll rather than dropping
/// out of the list: a single `C_GetTokenInfo` failure looks exactly like a
/// carrier that is no longer there, and the transition a bench measures would
/// then be timed against a read error nothing in the output named.
fn present_serials(backend: &Pkcs11Backend) -> Result<Vec<String>, String> {
    let slots = backend
        .list_slots_with_token()
        .map_err(|e| format!("slot enumeration failed: {e}"))?;
    let mut serials: Vec<String> = Vec::with_capacity(slots.len());
    for slot in slots {
        serials.push(
            read_token_serial(backend, slot)
                .map_err(|e| format!("reading the serial of {slot} failed: {e}"))?,
        );
    }
    serials.sort();
    Ok(serials)
}

/// Milliseconds since the Unix epoch.
///
/// Emitted beside the run-relative offset because it is the only clock this
/// process and the script driving the carrier can both read. A wall clock can
/// step, which over a bench measurement lasting seconds is a smaller problem
/// than having no shared origin at all.
fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Poll until `want_present` matches whether `serial` is there, or give up.
///
/// Every poll prints a mark, and every offset is measured from `origin` — the
/// one instant the whole run shares. Per-phase stopwatches were what made the
/// first bench numbers unsubtractable: two durations with different zeros look
/// like they can be compared and cannot.
///
/// Poll errors are reported and retried: a reader mid-reset legitimately
/// errors for a moment, and the question is whether the provider ever
/// recovers, not whether it stumbles.
fn await_presence(
    backend: &Pkcs11Backend,
    origin: Instant,
    serial: &str,
    want_present: bool,
    timeout: Duration,
) -> Result<Duration, String> {
    let phase_started = Instant::now();
    let mut last_error: Option<String> = None;
    while phase_started.elapsed() < timeout {
        match present_serials(backend) {
            Ok(serials) => {
                println!(
                    "TESSERA_POLL_MARK unix_ms={} run_ms={} serials={}",
                    unix_ms(),
                    origin.elapsed().as_millis(),
                    serials.join(",")
                );
                if serials.iter().any(|s| s == serial) == want_present {
                    return Ok(origin.elapsed());
                }
            }
            Err(e) => {
                println!(
                    "TESSERA_POLL_MARK unix_ms={} run_ms={} error={e}",
                    unix_ms(),
                    origin.elapsed().as_millis(),
                );
                if last_error.as_ref() != Some(&e) {
                    eprintln!("  (poll error, retrying: {e})");
                    last_error = Some(e);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    Err(format!(
        "timed out after {:?} waiting for {serial} to be {}",
        timeout,
        if want_present { "present" } else { "absent" }
    ))
}

/// Print the transition mark a driving script subtracts its own timestamp from.
fn event_mark(origin: Instant, event: &str, serial: &str) {
    println!(
        "TESSERA_EVENT_MARK unix_ms={} run_ms={} event={event} serial={serial}",
        unix_ms(),
        origin.elapsed().as_millis(),
    );
}

/// A token pulled and put back must be seen again through the *same* context.
///
/// This is the assumption the whole monitor rests on. If the provider fixes
/// its slot list at `C_Initialize`, the daemon would notice the first removal,
/// apply the configured action, and then never see the carrier again — every
/// later poll reporting an absence that is not real, and every session on that
/// host ending on the next login. Nothing in an unattended run can distinguish
/// that from a healthy provider, which is why the carrier has to actually move.
///
/// # Two modes
///
/// `TESSERA_RECONNECT_MODE=manual` (the default) prompts an operator and is
/// the only way to run this where the carrier is physical hardware.
///
/// `TESSERA_RECONNECT_MODE=marks` prints nothing to act on and waits for the
/// same two transitions to happen by themselves — for a bench where the
/// carrier is attached through a hypervisor and a script detaches it at a time
/// it records.
///
/// # What the numbers do and do not mean
///
/// **In manual mode the durations are not a measurement of the provider.**
/// The clock starts when the prompt is printed, so the first figure contains
/// however long it took a person to read a line of terminal output and pull a
/// device out of a socket. Nothing here can separate that from the provider's
/// own latency, and a figure read as if it could would put an invented number
/// into the documented detection contract. This is not hypothetical: it is the
/// reading two people arrived at independently from the first bench run.
///
/// What the run does establish, in either mode, is the property it exists for:
/// one long-lived context saw both the disappearance and the return.
///
/// To measure provider latency, use `marks` mode and subtract outside: every
/// poll prints `TESSERA_POLL_MARK` and each transition prints
/// `TESSERA_EVENT_MARK`, both carrying `unix_ms` (shared with the driving
/// script) and `run_ms` (offset from one origin for the whole run, so any two
/// marks from a run are directly comparable). The measurement is then the
/// difference between the script's own timestamp for cutting the carrier and
/// the `TESSERA_EVENT_MARK` for `carrier_absent`.
#[test]
#[ignore = "needs a real token and either a hand or a bench that can detach it"]
fn a_reconnected_token_is_seen_again() {
    let Some(module) = tessera_core::token::pkcs11::test_helpers::pkcs11_test_module_path() else {
        eprintln!("skipped: PKCS11_MODULE_PATH is not set to an existing module");
        return;
    };
    let timeout = Duration::from_secs(env_u64("TESSERA_RECONNECT_TIMEOUT_SECONDS", 90));

    // One context for the whole check, never finalized — the daemon's shape.
    let backend = Pkcs11Backend::load(&module, LockingMode::Mutex).expect("load the provider");

    let initial = present_serials(&backend).expect("the first poll must answer");
    eprintln!("connected at start: {initial:?}");
    let watched = if let Ok(serial) = std::env::var("TESSERA_CARRIER_TOKEN_SERIAL") {
        assert!(
            initial.contains(&serial),
            "TESSERA_CARRIER_TOKEN_SERIAL={serial} is not among the connected tokens {initial:?}"
        );
        serial
    } else {
        assert_eq!(
            initial.len(),
            1,
            "with {} tokens connected, name the one to pull in TESSERA_CARRIER_TOKEN_SERIAL",
            initial.len()
        );
        initial[0].clone()
    };

    // One origin for every mark in the run, so any two of them subtract.
    let origin = Instant::now();
    let prompts = match std::env::var("TESSERA_RECONNECT_MODE").as_deref() {
        Ok("marks") => false,
        Ok("manual") | Err(_) => true,
        Ok(other) => {
            panic!("TESSERA_RECONNECT_MODE must be \"manual\" or \"marks\", got {other:?}")
        }
    };
    event_mark(origin, "run_started", &watched);

    if prompts {
        eprintln!("\n>>> UNPLUG token {watched} now (waiting up to {timeout:?})");
    } else {
        eprintln!("\nwaiting for token {watched} to go away (up to {timeout:?})");
    }
    let gone_at = await_presence(&backend, origin, &watched, false, timeout)
        .expect("the removal must be observed — without this there is no monitor at all");
    event_mark(origin, "carrier_absent", &watched);
    eprintln!("<<< absence observed {gone_at:?} into the run");

    if prompts {
        eprintln!("\n>>> PLUG token {watched} BACK IN (waiting up to {timeout:?})");
    } else {
        eprintln!("\nwaiting for token {watched} to come back (up to {timeout:?})");
    }
    let back_at = await_presence(&backend, origin, &watched, true, timeout).unwrap_or_else(|e| {
        panic!(
            "{e}\n\nThe token was never seen again through the context that was already open. \
             The provider does not refresh its slot list without a fresh C_Initialize, which \
             this codebase never issues — so the monitor goes blind after the first removal \
             while continuing to look healthy. The polling design cannot stand on this \
             provider as it is."
        )
    });
    event_mark(origin, "carrier_present", &watched);
    eprintln!("<<< return observed {back_at:?} into the run");

    eprintln!(
        "\nRESULT: one long-lived context saw both the disappearance and the return \
         (absent at {gone_at:?}, present again at {back_at:?}, both from the start of the run). \
         Reconnect does not blind the monitor."
    );
    if prompts {
        eprintln!(
            "NOTE: these figures include the time a person took to act on each prompt. They \
             say nothing about how quickly the provider reflects a change — for that, run with \
             TESSERA_RECONNECT_MODE=marks and subtract against the driving script's own \
             timestamps."
        );
    }
}

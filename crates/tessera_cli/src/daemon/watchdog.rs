//! systemd watchdog keepalive, conditioned on the presence poller being alive.
//!
//! ## Why the process and not the thread
//!
//! A blocking call into the PKCS#11 provider cannot be cancelled from inside
//! this process. A timeout around it detects the hang — that is what the poll
//! supervisor does, and it is what makes lost observation visible to the
//! configured fail mode — but the thread stays inside the vendor library for
//! as long as the library keeps it, and the provider it holds is not usable by
//! anyone else meanwhile. The only remedy that actually returns the daemon to
//! observing is a new process.
//!
//! Of the two ways to get one, `WatchdogSec` in the unit is chosen over a
//! killable one-shot helper process:
//!
//! - it reuses the restart path the design already leans on
//!   (`Restart=on-failure`, `RestartSec=5s`), and the first poll after a
//!   restart re-decides presence from scratch, so nothing about a removal
//!   during the gap is lost;
//! - a helper process would pay a `C_Initialize` per poll, and concurrent
//!   `C_Initialize` on `rtpkcs11ecp` 2.14.1 is the defect this codebase keeps
//!   one process-global context to avoid. Polling would become the one thing
//!   in the product that does it repeatedly, next to logins doing the same.
//!
//! The keepalive is therefore withheld — deliberately — while the poller is
//! silent, and systemd replaces the process.
//!
//! On a host whose carrier is a USB medium there is no poller and nothing to
//! condition on; the keepalive is then unconditional, so enabling
//! `WatchdogSec` cannot restart such a host on a schedule.

use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::token_presence::PollerLiveness;
use crate::notify::{notify_watchdog, NotifyHandle};

/// The interval systemd expects a keepalive within, as it tells us.
///
/// Absent when the unit sets no `WatchdogSec` (and when the daemon is run by
/// hand), in which case there is no watchdog to feed.
fn watchdog_interval() -> Option<Duration> {
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    (usec > 0).then(|| Duration::from_micros(usec))
}

/// Whether to send a keepalive now.
///
/// Silence longer than `threshold` means the poll thread is inside a call that
/// is not coming back; the daemon still runs, still answers IPC, and still
/// believes whatever the last poll told it — which is precisely the state that
/// must not be allowed to persist.
fn should_ping(liveness: Option<&PollerLiveness>, threshold: Duration) -> bool {
    liveness.is_none_or(|l| l.silent_for() < threshold)
}

/// Whether systemd will restart this process when the keepalive stops.
///
/// Read by the startup checks: promising continuous presence while holding no
/// way to recover from a stalled poll is a promise that outlives the first
/// stall. A unit from a package that predates `WatchdogSec`, an operator's
/// edited drop-in, and a daemon started by hand all land here.
#[must_use]
pub fn recovery_available() -> bool {
    watchdog_interval().is_some()
}

/// How long the poll may be silent before the keepalive is withheld.
///
/// Twice what one poll cycle is allowed to take: a single slow cycle is not a
/// stall, two in a row is. Deriving it from the configured cadence rather than
/// from `WatchdogSec` keeps a deliberately slow poll interval from turning
/// into a restart loop, and keeps the blind window from being padded by a
/// `WatchdogSec` an operator raised for unrelated reasons.
fn stall_threshold(poll_deadline: Duration) -> Duration {
    poll_deadline.saturating_mul(2)
}

/// Start the keepalive task, or `None` when no watchdog is configured.
///
/// `poll_deadline` is what the poll supervisor allows one cycle.
#[must_use]
pub fn spawn(
    liveness: Option<PollerLiveness>,
    poll_deadline: Duration,
    shutdown: CancellationToken,
) -> Option<JoinHandle<()>> {
    let interval = watchdog_interval()?;
    // Half the interval is the conventional margin: one lost or late ping
    // must not by itself be enough to trip the watchdog.
    let ping_every = interval / 2;
    let threshold = stall_threshold(poll_deadline);
    tracing::info!(
        target: "tessera.monitord",
        watchdog_secs = interval.as_secs(),
        poll_silence_threshold_secs = threshold.as_secs(),
        conditioned_on_poller = liveness.is_some(),
        "systemd watchdog keepalive started"
    );
    Some(tokio::spawn(async move {
        let handle = NotifyHandle::system_default();
        let mut reported_stall = false;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(ping_every) => {
                    if should_ping(liveness.as_ref(), threshold) {
                        reported_stall = false;
                        notify_watchdog(&handle);
                    } else if !reported_stall {
                        reported_stall = true;
                        tracing::error!(
                            target: "tessera.monitord",
                            audit_level = "CRITICAL",
                            threshold_secs = threshold.as_secs(),
                            "token presence poll has not returned; withholding the systemd \
                             watchdog keepalive so the daemon is restarted — a call blocked \
                             inside the provider cannot be cancelled from this process"
                        );
                    }
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{should_ping, Duration, PollerLiveness};

    /// A host with no poller must be fed unconditionally, or enabling the
    /// watchdog would restart every USB-carrier host on a timer.
    #[test]
    fn a_host_without_a_poller_is_always_fed() {
        assert!(should_ping(None, Duration::from_millis(1)));
    }

    /// A poller that reported recently keeps the daemon alive.
    #[test]
    fn a_live_poller_keeps_the_keepalive_going() {
        let liveness = PollerLiveness::aged(Duration::from_secs(1));
        assert!(should_ping(Some(&liveness), Duration::from_mins(1)));
    }

    /// A poller stuck inside the provider stops it, which is how the restart
    /// is requested. Withholding the ping is the mechanism, not an oversight.
    ///
    /// The liveness is aged past the threshold rather than compared against a
    /// zero one: a zero threshold would pass on the direction of a comparison
    /// alone, without any silence having actually elapsed.
    #[test]
    fn a_stuck_poller_withholds_the_keepalive() {
        let liveness = PollerLiveness::aged(Duration::from_mins(5));
        assert!(
            !should_ping(Some(&liveness), Duration::from_mins(1)),
            "silence past the threshold must withhold the keepalive"
        );
    }

    /// The threshold follows the configured cadence, not `WatchdogSec`, so a
    /// slow poll interval cannot become a restart loop and a raised
    /// `WatchdogSec` does not silently widen the blind window twice over.
    #[test]
    fn the_stall_threshold_is_twice_one_poll_cycle() {
        assert_eq!(
            super::stall_threshold(Duration::from_secs(7)),
            Duration::from_secs(14)
        );
    }
}

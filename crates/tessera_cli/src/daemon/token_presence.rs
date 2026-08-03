//! Presence poller for a PKCS#11 token carrier.
//!
//! A smart-card token is not a block device and raises no udev event, so the
//! only way to know it is still there is to ask the provider. This module
//! turns that question into a stream of [`TokenPoll`] outcomes feeding the
//! state manager, which owns what an absence costs.
//!
//! ## Why a poll and not `C_WaitForSlotEvent`
//!
//! The blocking form cannot be cancelled by anything short of `C_Finalize`,
//! which this codebase never calls — the context lives for the life of the
//! process (see `tessera_core::token::pkcs11`). Providers that do not
//! implement the call at all exist, SoftHSM2 among them, so a poll would be
//! needed as a fallback in any case.
//!
//! ## Why an OS thread, and what happens when a call hangs
//!
//! The cryptoki calls are blocking FFI into a vendor library with a history of
//! aborting the process, so they run on a dedicated thread rather than on a
//! tokio worker.
//!
//! A hang gets two separate answers, because detecting it and recovering from
//! it are different problems:
//!
//! - **Detection** is [`supervise`]: it stops waiting after
//!   [`POLL_CALL_TIMEOUT`] and reports [`TokenPoll::Failed`], so the
//!   configured fail mode decides what an unobservable carrier costs instead
//!   of the daemon quietly standing by its last observation.
//! - **Recovery** is [`super::watchdog`]: nothing in this process can cancel
//!   a call already inside the library, so the daemon withholds the systemd
//!   keepalive and is replaced. [`PollerLiveness`] is what the two share.
//!
//! No second poll is started while one is stuck. The stuck thread is the one
//! holding the provider, and issuing a concurrent call into a library that has
//! just stopped answering is the failure class this design avoids everywhere
//! else. The supervisor keeps reporting failures on the same cadence until the
//! thread reports again — or until the restart arrives.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use tessera_core::token::pkcs11::{read_token_serial, LockingMode, Pkcs11Backend};

use crate::state::{Event, TokenPoll};

/// How long one poll may take before it counts as a failed poll.
///
/// On the bench a full poll of two connected Rutokens — `C_GetSlotList` plus
/// one `C_GetTokenInfo` per slot — stayed under 250 ms across 471 consecutive
/// polls, worst single call 155 ms. Five seconds is far outside that spread,
/// so a healthy reader never trips it, while a strict host still reacts within
/// seconds of the provider going quiet.
pub const POLL_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// When the poll thread was last heard from.
///
/// A timeout inside this process cannot interrupt a blocking call into the
/// provider — the thread stays in the library, and no amount of bookkeeping
/// here brings it back. What this records is the evidence needed to ask
/// systemd for the one remedy that does work: replacing the process. See
/// [`crate::daemon::watchdog`].
#[derive(Clone, Debug)]
pub struct PollerLiveness(Arc<Mutex<Instant>>);

impl PollerLiveness {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    /// Record that the poll thread produced an outcome of its own.
    ///
    /// A failure the thread reported still counts: it came back from the
    /// provider, which is the property under watch. A failure the supervisor
    /// synthesised on a missed deadline deliberately does not.
    fn mark(&self) {
        *self.0.lock() = Instant::now();
    }

    /// A liveness whose last report is `age` in the past.
    #[cfg(test)]
    pub(super) fn aged(age: Duration) -> Self {
        Self(Arc::new(Mutex::new(
            Instant::now().checked_sub(age).unwrap_or_else(Instant::now),
        )))
    }

    /// How long the poll thread has been silent.
    #[must_use]
    pub fn silent_for(&self) -> Duration {
        self.0.lock().elapsed()
    }
}

/// Start the token-presence poller.
///
/// Returns the supervisor task's handle and the liveness the watchdog reads.
/// The poll thread itself is detached: it may be blocked inside the provider
/// at shutdown, and joining it would make the daemon's exit hostage to a
/// library that has stopped answering. It observes `shutdown` between polls
/// and ends on its own.
#[must_use]
pub fn spawn(
    module_path: PathBuf,
    locking_mode: LockingMode,
    interval: Duration,
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
) -> (JoinHandle<()>, PollerLiveness) {
    let (poll_tx, poll_rx) = mpsc::unbounded_channel();
    let thread_shutdown = shutdown.clone();
    if let Err(e) = std::thread::Builder::new()
        .name("tessera-token-poll".to_owned())
        .spawn(move || {
            poll_loop(
                &module_path,
                locking_mode,
                interval,
                &poll_tx,
                &thread_shutdown,
            );
        })
    {
        // The sender went with the closure that could not be spawned, so the
        // supervisor sees a closed channel and reports lost observation. A
        // poller that never started must not read as a token that is present.
        tracing::error!(
            target: "tessera.monitord",
            error = %e,
            "token presence poll thread could not be started"
        );
    }

    // A poll that started on time still has its own call time to spend, so
    // the deadline is the cadence plus what one call is allowed to take.
    let deadline = interval.saturating_add(POLL_CALL_TIMEOUT);
    let liveness = PollerLiveness::new();
    let handle = supervise(poll_rx, deadline, event_tx, shutdown, liveness.clone());
    (handle, liveness)
}

/// Forward poll outcomes to the state manager, substituting a failure whenever
/// the poll thread misses `deadline`.
fn supervise(
    mut poll_rx: mpsc::UnboundedReceiver<TokenPoll>,
    deadline: Duration,
    event_tx: mpsc::UnboundedSender<Event>,
    shutdown: CancellationToken,
    liveness: PollerLiveness,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Once the poll thread is gone the channel answers `None` instantly
        // and forever; pacing the reports keeps the cadence the state manager
        // counts in and stops this from becoming a spin.
        let mut poller_gone = false;
        loop {
            tokio::select! {
                // Shutdown is checked first on purpose. On a clean stop both
                // this and the closed poll channel are ready at once, and the
                // default random choice would decide by coin flip whether the
                // reboot logs a CRITICAL about a monitor that did not die.
                biased;
                () = shutdown.cancelled() => break,
                received = async {
                    if poller_gone {
                        tokio::time::sleep(deadline).await;
                        Ok(None)
                    } else {
                        tokio::time::timeout(deadline, poll_rx.recv()).await
                    }
                } => {
                    let outcome = match received {
                        Ok(Some(poll)) => {
                            // The thread came back from the provider — the
                            // one fact the watchdog is watching for.
                            liveness.mark();
                            poll
                        }
                        // The thread is gone: it panicked, or it never
                        // started. Nothing observes the token any more, which
                        // is not the same as the token being there — and one
                        // report of it would sit below the threshold that
                        // decides what lost observation costs, leaving the
                        // daemon silent about a monitor that no longer exists.
                        // So it keeps saying so, on the same cadence, until
                        // the daemon shuts down or is replaced.
                        Ok(None) => {
                            // The poll thread checks `shutdown` only between
                            // polls, so on a clean stop it closes the channel
                            // up to one sleep step after this task could have
                            // taken the cancellation branch. Reaching here in
                            // that window is an orderly exit, not a lost
                            // monitor — and logging it as CRITICAL would put
                            // an alarm in the journal on every reboot, which
                            // is how operators learn to skip the real one.
                            if shutdown.is_cancelled() {
                                break;
                            }
                            if !poller_gone {
                                poller_gone = true;
                                tracing::error!(
                                    target: "tessera.monitord",
                                    audit_level = "CRITICAL",
                                    "token presence poll thread is gone; reporting lost \
                                     observation every cycle until the daemon is replaced"
                                );
                            }
                            TokenPoll::Failed(
                                "token presence poller stopped".to_owned(),
                            )
                        }
                        Err(_elapsed) => {
                            tracing::error!(
                                target: "tessera.monitord",
                                timeout_secs = deadline.as_secs(),
                                "token presence poll did not return in time; treating as a failed \
                                 poll and not starting a second call into the provider"
                            );
                            TokenPoll::Failed(format!(
                                "poll did not return within {}s",
                                deadline.as_secs()
                            ))
                        }
                    };
                    if event_tx.send(Event::TokenPoll(outcome)).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Poll the provider until `shutdown`, reporting every outcome.
///
/// The first poll runs before the first sleep: after a daemon restart the
/// carrier may already be gone, and waiting an interval before looking would
/// widen the window in which that removal goes unnoticed.
fn poll_loop(
    module_path: &std::path::Path,
    locking_mode: LockingMode,
    interval: Duration,
    poll_tx: &mpsc::UnboundedSender<TokenPoll>,
    shutdown: &CancellationToken,
) {
    // The context is taken from the process-global registry, which loads and
    // initializes the library at most once per path. Acquiring it per poll
    // rather than once keeps a provider that was not ready at daemon start
    // from disabling presence observation for the life of the process.
    while !shutdown.is_cancelled() {
        let outcome = match Pkcs11Backend::load(module_path, locking_mode) {
            Ok(backend) => poll_once(&backend),
            Err(e) => TokenPoll::Failed(format!("pkcs11 provider unavailable: {e}")),
        };
        if poll_tx.send(outcome).is_err() {
            break;
        }
        // Sleeping in short steps keeps shutdown responsive without giving the
        // provider a faster cadence than the operator configured.
        let mut slept = Duration::ZERO;
        let step = Duration::from_millis(200).min(interval);
        while slept < interval && !shutdown.is_cancelled() {
            std::thread::sleep(step);
            slept = slept.saturating_add(step);
        }
    }
}

/// One poll: every serial the provider *confirmed* present, or the reason
/// there is no answer at all.
///
/// A serial is reported only when `C_GetTokenInfo` actually returned it. A
/// slot that could not be read is not evidence that the token in it is gone —
/// it is the absence of evidence either way — so it contributes nothing and
/// the caller's absence bookkeeping decides what a carrier missing from this
/// set means. When no slot could be read at all, the poll produced no
/// information and says so.
fn poll_once(backend: &Pkcs11Backend) -> TokenPoll {
    let slots = match backend.list_slots_with_token() {
        Ok(slots) => slots,
        Err(e) => return TokenPoll::Failed(format!("slot enumeration failed: {e}")),
    };
    let offered = slots.len();
    let mut serials = BTreeSet::new();
    let mut unreadable = 0_usize;
    for slot in slots {
        match read_token_serial(backend, slot) {
            Ok(serial) => {
                serials.insert(serial);
            }
            Err(e) => {
                unreadable += 1;
                tracing::warn!(
                    target: "tessera.monitord",
                    error = %e,
                    "token info unreadable for one slot; that slot contributes no evidence"
                );
            }
        }
    }
    classify(offered, unreadable, serials)
}

/// Turn the tally of one poll into its outcome.
///
/// Split out from [`poll_once`] because the judgement — which tallies amount
/// to an answer and which amount to none — is the part worth testing without
/// a provider attached.
fn classify(offered: usize, unreadable: usize, serials: BTreeSet<String>) -> TokenPoll {
    // Every slot the provider offered refused to identify itself. Reporting
    // an empty set here would be a claim that no carrier is present, which is
    // the one thing this poll did not establish.
    if offered > 0 && unreadable == offered {
        return TokenPoll::Failed(format!(
            "none of the {offered} slot(s) with a token could be identified"
        ));
    }
    TokenPoll::Observed(serials)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::{supervise, BTreeSet, Duration, Event, PollerLiveness, TokenPoll};
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    const DEADLINE: Duration = Duration::from_millis(150);

    /// Receive the next event the supervisor emitted, or `None`.
    async fn next(rx: &mut mpsc::UnboundedReceiver<Event>) -> Option<TokenPoll> {
        match tokio::time::timeout(DEADLINE * 8, rx.recv()).await {
            Ok(Some(Event::TokenPoll(poll))) => Some(poll),
            _ => None,
        }
    }

    /// A hung provider call is the case a service restart does not cure: the
    /// process is alive and the last thing it saw was the token present. The
    /// supervisor must stop waiting and say so, or the daemon goes on
    /// believing an observation it no longer has.
    #[tokio::test]
    async fn a_poll_that_never_returns_is_reported_as_a_failure() {
        let (poll_tx, poll_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let _h = supervise(
            poll_rx,
            DEADLINE,
            event_tx,
            shutdown.clone(),
            PollerLiveness::new(),
        );

        // The sender stays alive for the whole test: the poll thread has not
        // died, it is stuck inside the provider.
        match next(&mut event_rx).await {
            Some(TokenPoll::Failed(reason)) => assert!(
                reason.contains("did not return"),
                "the reason must name the hang: {reason}"
            ),
            other => panic!("expected a failed poll, got {other:?}"),
        }
        drop(poll_tx);
        shutdown.cancel();
    }

    /// The stuck call eventually comes back, and its answer is accepted: a
    /// timed-out poll is a missed observation, not a poller that is written
    /// off for the life of the daemon.
    #[tokio::test]
    async fn an_answer_after_a_missed_deadline_is_still_accepted() {
        let (poll_tx, poll_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let _h = supervise(
            poll_rx,
            DEADLINE,
            event_tx,
            shutdown.clone(),
            PollerLiveness::new(),
        );

        assert!(matches!(
            next(&mut event_rx).await,
            Some(TokenPoll::Failed(_))
        ));

        let mut serials = std::collections::BTreeSet::new();
        serials.insert("483d4e1a".to_owned());
        poll_tx
            .send(TokenPoll::Observed(serials.clone()))
            .expect("the supervisor is still listening");
        assert_eq!(
            next(&mut event_rx).await,
            Some(TokenPoll::Observed(serials)),
            "a late answer must reach the state manager"
        );
        shutdown.cancel();
    }

    /// A slot the provider offered but would not identify is not evidence
    /// that the token in it is gone. Dropping it from the reported set and
    /// calling the set an answer would turn one `CKR_DEVICE_ERROR` into a
    /// confirmed absence — and with the recommended zero removal grace, into
    /// an immediately locked screen.
    #[test]
    fn a_poll_whose_every_slot_is_unreadable_is_not_an_absence() {
        let outcome = super::classify(2, 2, BTreeSet::new());
        assert!(
            matches!(outcome, TokenPoll::Failed(_)),
            "got {outcome:?} — an unidentifiable slot must not read as an empty carrier set"
        );
    }

    /// A reader that answers alongside one that does not still produced an
    /// answer; the carrier missing from it is handled by the state manager's
    /// absence bookkeeping, not by discarding the whole poll.
    #[test]
    fn a_partially_readable_poll_is_still_an_answer() {
        let mut serials = BTreeSet::new();
        serials.insert("483d4e1a".to_owned());
        assert_eq!(
            super::classify(2, 1, serials.clone()),
            TokenPoll::Observed(serials)
        );
    }

    /// No slots at all is an answer: the provider was reached and reported
    /// nothing present.
    #[test]
    fn an_empty_provider_is_an_answer_not_a_failure() {
        assert_eq!(
            super::classify(0, 0, BTreeSet::new()),
            TokenPoll::Observed(BTreeSet::new())
        );
    }

    /// A synthesised timeout must not refresh the liveness. The whole
    /// watchdog rests on that: if a missed deadline counted as the poller
    /// being alive, a thread stuck forever inside the provider would keep the
    /// daemon fed and the restart would never come.
    #[tokio::test]
    async fn a_missed_deadline_does_not_count_as_the_poller_being_alive() {
        let (poll_tx, poll_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let liveness = PollerLiveness::new();
        let _h = supervise(
            poll_rx,
            DEADLINE,
            event_tx,
            shutdown.clone(),
            liveness.clone(),
        );

        assert!(matches!(
            next(&mut event_rx).await,
            Some(TokenPoll::Failed(_))
        ));
        assert!(
            liveness.silent_for() >= DEADLINE,
            "the supervisor's own timeout must leave the silence intact, not reset it"
        );

        // A real report does refresh it, so the assertion above is about the
        // synthesised failure rather than about `mark` never being called.
        poll_tx
            .send(TokenPoll::Observed(BTreeSet::new()))
            .expect("supervisor still listening");
        assert!(next(&mut event_rx).await.is_some());
        assert!(
            liveness.silent_for() < DEADLINE,
            "an answer from the thread must refresh the liveness"
        );
        shutdown.cancel();
    }

    /// A poller that has gone away leaves nothing observing the token, which
    /// is not the same as the token being present.
    #[tokio::test]
    async fn a_poller_that_stopped_reports_lost_observation() {
        let (poll_tx, poll_rx) = mpsc::unbounded_channel::<TokenPoll>();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let _h = supervise(
            poll_rx,
            DEADLINE * 20,
            event_tx,
            shutdown.clone(),
            PollerLiveness::new(),
        );

        drop(poll_tx);
        match next(&mut event_rx).await {
            Some(TokenPoll::Failed(reason)) => assert!(
                reason.contains("stopped"),
                "the reason must name the dead poller: {reason}"
            ),
            other => panic!("expected a failed poll, got {other:?}"),
        }
        shutdown.cancel();
    }

    /// A clean shutdown races the poll thread's own exit, and losing that
    /// race must not look like a monitor that died. Reporting lost
    /// observation here would put a CRITICAL in the journal on every ordinary
    /// reboot — the kind of entry operators learn to skip past, and then skip
    /// past when it is real.
    #[tokio::test]
    async fn a_clean_shutdown_reports_nothing() {
        let (poll_tx, poll_rx) = mpsc::unbounded_channel::<TokenPoll>();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let _h = supervise(
            poll_rx,
            DEADLINE,
            event_tx,
            shutdown.clone(),
            PollerLiveness::new(),
        );

        // The order a clean stop produces: the token is cancelled, and the
        // poll thread closes its channel a moment later.
        shutdown.cancel();
        drop(poll_tx);

        assert!(
            next(&mut event_rx).await.is_none(),
            "a shutdown must not be reported as lost observation"
        );
    }

    /// One report of a dead poller is not enough: the state manager only acts
    /// on a streak, so a supervisor that said it once and fell silent would
    /// leave `strict` never enforcing and `permissive` never even logging the
    /// loss. It must keep saying so until something replaces the daemon.
    #[tokio::test]
    async fn a_dead_poller_is_reported_until_the_threshold_is_passed() {
        let (poll_tx, poll_rx) = mpsc::unbounded_channel::<TokenPoll>();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let _h = supervise(
            poll_rx,
            DEADLINE,
            event_tx,
            shutdown.clone(),
            PollerLiveness::new(),
        );

        drop(poll_tx);
        // Four is past the state manager's threshold of three, so this proves
        // the stream continues rather than stopping exactly at it.
        for i in 0..4 {
            match next(&mut event_rx).await {
                Some(TokenPoll::Failed(_)) => {}
                other => panic!("report {i}: expected a failed poll, got {other:?}"),
            }
        }
        shutdown.cancel();
    }
}

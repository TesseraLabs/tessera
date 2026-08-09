#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::pedantic
)]
//! Drives the state manager with token-presence polls.
//!
//! The poll outcomes are injected rather than produced by a provider: what is
//! under test is what an absence costs a live session, which is decided here
//! and not in the reader.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tessera_cli::logind::LogindSignal;
use tessera_cli::registry::{ActiveSession, RegistryStore, SessionRegistry};
use tessera_cli::state::{
    spawn_state_manager, ActionRequest, CredentialMode, Event, IpcRequest, OnUsbRemoved,
    StateConfig, TokenPoll,
};
use tessera_cli::udev_query::AlwaysPresent;
use tessera_core::config::validated::MonitorFailMode;
use tessera_proto::SessionTarget;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const CARRIER: &str = "483d4e1a";
const GRACE: Duration = Duration::from_secs(1);
/// Consecutive polls that must agree before the state manager acts, mirroring
/// `POLLS_BEFORE_CONFIRMED`. A single poll is not evidence: the provider
/// reports an empty slot list both when a carrier is gone and when the
/// smart-card service is briefly blind.
const CONFIRMING: usize = 3;

fn session(serial: &str) -> ActiveSession {
    ActiveSession {
        session_id: Uuid::from_u128(1),
        pam_user: "u".into(),
        pam_service: "s".into(),
        target: SessionTarget::logind("c1"),
        usb_serial: Some(serial.into()),
        usb_vid_pid: None,
        usb_devnode: None,
        carrier: Some(tessera_proto::CarrierKind::Token),
        host_id_hash: "h".into(),
        opened_at: SystemTime::UNIX_EPOCH,
        cert_cn: "cn".into(),
        cert_serial: "01".into(),
        engineer_ski: String::new(),
        engineer_cert_sha256: String::new(),
        uid: 0,
        session_expiry: None,
    }
}

fn observed(serials: &[&str]) -> Event {
    Event::TokenPoll(TokenPoll::Observed(
        serials
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>(),
    ))
}

fn failed() -> Event {
    Event::TokenPoll(TokenPoll::Failed("provider unavailable".to_owned()))
}

struct Harness {
    event_tx: mpsc::UnboundedSender<Event>,
    action_rx: mpsc::UnboundedReceiver<ActionRequest>,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn send(&self, ev: Event) {
        self.event_tx.send(ev).expect("send event");
    }

    /// The action the daemon took, or `None` if it took none in `within`.
    async fn action(&mut self, within: Duration) -> Option<ActionRequest> {
        tokio::time::timeout(within, self.action_rx.recv())
            .await
            .ok()
            .flatten()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn harness(
    mode: CredentialMode,
    fail_mode: MonitorFailMode,
    sessions: Vec<ActiveSession>,
) -> Harness {
    let dir = tempfile::tempdir().expect("tmp");
    let store = RegistryStore::new(dir.path().join("s.json"));
    let registry = SessionRegistry::new();
    for s in sessions {
        registry.add(s);
    }
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let (action_tx, action_rx) = mpsc::unbounded_channel();
    let cfg = StateConfig {
        credential_mode: mode,
        grace_seconds: GRACE.as_secs(),
        suspend_grace_seconds: 3,
        on_usb_removed: OnUsbRemoved::Lock,
        registry_store: store,
        monitor_fail_mode: fail_mode,
    };
    let shutdown = CancellationToken::new();
    let _h = spawn_state_manager(
        cfg,
        registry,
        event_rx,
        action_tx,
        Arc::new(AlwaysPresent),
        shutdown.clone(),
    );
    Harness {
        event_tx,
        action_rx,
        shutdown,
        _dir: dir,
    }
}

fn token_harness(sessions: Vec<ActiveSession>) -> Harness {
    harness(
        CredentialMode::Pkcs11,
        MonitorFailMode::Permissive,
        sessions,
    )
}

/// The carrier of a live session stops being reported, and the configured
/// action follows once the grace window is over.
#[tokio::test]
async fn an_absent_token_applies_the_configured_action_after_the_grace() {
    let mut h = token_harness(vec![session(CARRIER)]);
    h.send(observed(&[CARRIER]));
    for _ in 0..CONFIRMING {
        h.send(observed(&[]));
    }

    let req = h.action(GRACE * 3).await.expect("the action must be taken");
    assert!(matches!(
        req,
        ActionRequest::HandleUsbRemoved {
            action: OnUsbRemoved::Lock,
            ..
        }
    ));
}

/// The engineer put the token back before the window closed.
#[tokio::test]
async fn a_token_that_returns_within_the_grace_cancels_the_action() {
    let mut h = token_harness(vec![session(CARRIER)]);
    h.send(observed(&[CARRIER]));
    for _ in 0..CONFIRMING {
        h.send(observed(&[]));
    }
    h.send(observed(&[CARRIER]));

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "the carrier came back inside the grace window; no session may be ended"
    );
}

/// A removal that happened while the daemon was down is not lost.
///
/// Polling re-decides presence from scratch, so the polls after a restart
/// need no earlier observation to be a change from — which is what an
/// event-driven design would have required, and what it would have missed.
/// The confirming series still applies: what a restart cannot do is make the
/// absence invisible.
#[tokio::test]
async fn a_removal_during_a_restart_is_not_lost() {
    let mut h = token_harness(vec![session(CARRIER)]);
    for _ in 0..CONFIRMING {
        h.send(observed(&[]));
    }

    let req = h
        .action(GRACE * 3)
        .await
        .expect("an absence that predates the daemon must still be acted on");
    assert!(matches!(req, ActionRequest::HandleUsbRemoved { .. }));
}

/// Some token being connected is not this token being connected. Matching on
/// "a token is present" rather than on the serial would leave a session alive
/// for whoever plugs in any smart card at all.
#[tokio::test]
async fn another_token_being_present_is_not_this_token_being_present() {
    let mut h = token_harness(vec![session(CARRIER)]);
    for _ in 0..CONFIRMING {
        h.send(observed(&["48b541ca"]));
    }

    let req = h
        .action(GRACE * 3)
        .await
        .expect("a foreign token must not stand in for the session's carrier");
    assert!(matches!(req, ActionRequest::HandleUsbRemoved { .. }));
}

/// A carrier that stays out is one removal, not one per poll: the action runs
/// once and repeated polls saying the same thing add nothing.
#[tokio::test]
async fn a_token_left_out_does_not_re_trigger_the_action_on_every_poll() {
    let mut h = token_harness(vec![session(CARRIER)]);
    for _ in 0..CONFIRMING {
        h.send(observed(&[]));
    }
    assert!(
        h.action(GRACE * 3).await.is_some(),
        "the confirmed absence acts"
    );

    // Only now, with the grace window already spent and the action already
    // dispatched, do the later polls arrive. Sending them earlier would prove
    // nothing: the grace timer alone suppresses those.
    for _ in 0..5 {
        h.send(observed(&[]));
    }
    assert!(
        h.action(GRACE * 3).await.is_none(),
        "the same absence must not be enforced again on every poll"
    );
}

/// One poll that does not confirm the carrier is not a removal.
///
/// The provider reports an empty slot list both when the carrier is gone and
/// when the smart-card service is briefly blind — a `pcscd` restart, a reader
/// reset, a neighbouring process mid-APDU. Acting on the first of those would
/// lock the screen of an engineer whose token never left the reader, and with
/// the recommended zero removal grace it would do it immediately.
#[tokio::test]
async fn a_single_unconfirmed_poll_does_not_end_a_session() {
    let mut h = token_harness(vec![session(CARRIER)]);
    h.send(observed(&[CARRIER]));
    h.send(observed(&[]));

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "a single poll without the carrier is not evidence enough to end a session"
    );

    // And the streak that follows does act, so the assertion above is not
    // passing because nothing on this path ever acts.
    for _ in 0..CONFIRMING {
        h.send(observed(&[]));
    }
    assert!(
        h.action(GRACE * 3).await.is_some(),
        "a carrier absent across consecutive polls must still be enforced"
    );
}

/// A poll that confirms the carrier clears the streak, so blindness that
/// resolves costs nothing however often it recurs.
#[tokio::test]
async fn a_confirmed_carrier_clears_the_absence_streak() {
    let mut h = token_harness(vec![session(CARRIER)]);
    // Three unconfirmed polls in total, never two in a row, ending on one so
    // that no trailing answer could cancel an action this test must prevent.
    h.send(observed(&[]));
    h.send(observed(&[CARRIER]));
    h.send(observed(&[]));
    h.send(observed(&[CARRIER]));
    h.send(observed(&[]));

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "isolated unconfirmed polls separated by confirmations are not a removal"
    );
}

/// A session opened under a different carrier is not judged in this
/// namespace. After an operator switches a host from a USB medium to a token
/// and restarts the daemon, the restored sessions still hold block-device
/// serials, which no provider will ever report — judging them here would end
/// every one of them on the first poll.
#[tokio::test]
async fn a_session_from_another_carrier_is_not_judged_by_the_token_poll() {
    let mut usb_session = session(CARRIER);
    usb_session.carrier = Some(tessera_proto::CarrierKind::UsbPartition);
    let mut h = harness(
        CredentialMode::Pkcs11,
        MonitorFailMode::Strict,
        vec![usb_session],
    );
    for _ in 0..CONFIRMING * 2 {
        h.send(observed(&[]));
    }

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "a block-device serial means nothing to a provider and must not be read as an absence"
    );
}

/// A record written before the carrier kind was transmitted says nothing
/// about which namespace its serial belongs to, and a guess would be wrong in
/// exactly the case that matters.
#[tokio::test]
async fn a_session_of_unknown_carrier_is_not_judged_by_the_token_poll() {
    let mut legacy = session(CARRIER);
    legacy.carrier = None;
    let mut h = harness(
        CredentialMode::Pkcs11,
        MonitorFailMode::Strict,
        vec![legacy],
    );
    for _ in 0..CONFIRMING * 2 {
        h.send(observed(&[]));
    }

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "an unlabelled record must keep the behaviour it was opened with"
    );
}

/// Strict monitoring promises continuous presence. Not observing the carrier
/// is not observing it present, so a persistent failure is a removal.
#[tokio::test]
async fn a_persistent_poll_failure_is_a_removal_under_strict_monitoring() {
    let mut h = harness(
        CredentialMode::Pkcs11,
        MonitorFailMode::Strict,
        vec![session(CARRIER)],
    );
    h.send(observed(&[CARRIER]));
    for _ in 0..3 {
        h.send(failed());
    }

    let req = h
        .action(GRACE * 3)
        .await
        .expect("strict monitoring cannot keep its promise without observation");
    assert!(matches!(req, ActionRequest::HandleUsbRemoved { .. }));
}

/// Permissive monitoring never promised presence, so the same failure costs
/// the session nothing.
#[tokio::test]
async fn a_persistent_poll_failure_leaves_the_session_alive_under_permissive_monitoring() {
    let mut h = token_harness(vec![session(CARRIER)]);
    h.send(observed(&[CARRIER]));
    for _ in 0..5 {
        h.send(failed());
    }

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "permissive monitoring degrades to a log entry, not to an ended session"
    );
}

/// One failed poll is a hiccup — a reader busy with another process, a
/// `pcscd` restart. Acting on it would end the sessions of engineers who did
/// nothing.
#[tokio::test]
async fn a_single_poll_failure_is_not_a_persistent_one() {
    let mut h = harness(
        CredentialMode::Pkcs11,
        MonitorFailMode::Strict,
        vec![session(CARRIER)],
    );
    h.send(observed(&[CARRIER]));
    h.send(failed());

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "a single failure must not end a session"
    );

    // And the streak that follows it does act, so the test above is not
    // passing because nothing in this path ever acts.
    h.send(failed());
    h.send(failed());
    h.send(failed());
    assert!(
        h.action(GRACE * 3).await.is_some(),
        "a sustained failure must still be treated as a removal"
    );
}

/// A poll that answers clears the streak: three failures spread across
/// successful polls are three hiccups, not a loss of observation.
#[tokio::test]
async fn successful_polls_between_failures_clear_the_streak() {
    let mut h = harness(
        CredentialMode::Pkcs11,
        MonitorFailMode::Strict,
        vec![session(CARRIER)],
    );
    // Three failures in total, but never two in a row, and the sequence ends
    // on a failure so that no later answer could cancel an action this test
    // was supposed to prevent.
    h.send(failed());
    h.send(observed(&[CARRIER]));
    h.send(failed());
    h.send(observed(&[CARRIER]));
    h.send(failed());

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "isolated failures separated by answers are not lost observation"
    );
}

/// A closed session takes its absence record with it.
///
/// Observable because the record is keyed by session id: if closing left it
/// behind, a session re-opened under the same id would inherit a part-spent
/// streak and be enforced sooner than its own polls justify. The same
/// bookkeeping is what stops the map growing for the daemon's whole uptime
/// while a provider is persistently failing.
#[tokio::test]
async fn closing_a_session_drops_what_earlier_polls_concluded_about_it() {
    let mut h = token_harness(vec![session(CARRIER)]);
    // One short of the threshold, so any inherited count would push the
    // re-opened session over it.
    for _ in 0..CONFIRMING - 1 {
        h.send(observed(&[]));
    }
    assert!(
        h.action(GRACE * 3).await.is_none(),
        "below the threshold nothing is enforced yet"
    );

    let (reply, closed) = tokio::sync::oneshot::channel();
    h.send(Event::Ipc(IpcRequest::SessionClose {
        session_id: session(CARRIER).session_id,
        closed_at: SystemTime::now(),
        reply,
    }));
    closed.await.expect("close acknowledged");

    let (reply, opened) = tokio::sync::oneshot::channel();
    h.send(Event::Ipc(IpcRequest::SessionOpen {
        session: Box::new(session(CARRIER)),
        reply,
    }));
    opened.await.expect("open acknowledged");

    for _ in 0..CONFIRMING - 1 {
        h.send(observed(&[]));
    }
    assert!(
        h.action(GRACE * 3).await.is_none(),
        "the re-opened session must start its own count, not inherit the closed one's"
    );
}

/// A suspend drops the pending grace timers, and it must drop what the polls
/// concluded along with them. Kept, the record would say "already actioned"
/// for a carrier that is genuinely gone after the resume, and nothing would
/// ever arm a grace for it again.
#[tokio::test]
async fn a_suspend_clears_what_earlier_polls_concluded() {
    let mut h = token_harness(vec![session(CARRIER)]);
    for _ in 0..CONFIRMING {
        h.send(observed(&[]));
    }
    assert!(
        h.action(GRACE * 3).await.is_some(),
        "the absence before the suspend is enforced"
    );

    h.send(Event::Logind(LogindSignal::PrepareForSleep(true)));
    h.send(Event::Logind(LogindSignal::PrepareForSleep(false)));
    // Past the suspend grace, so absences are no longer suppressed.
    tokio::time::sleep(Duration::from_secs(6)).await;

    for _ in 0..CONFIRMING {
        h.send(observed(&[]));
    }
    assert!(
        h.action(GRACE * 3).await.is_some(),
        "a carrier still gone after the resume must be enforced again, not written off as \
         already handled before the suspend"
    );
}

/// A USB-carrier host runs no poller. Should one ever be wired there, a token
/// serial must not be read in the block-device namespace: a collision would
/// end a session over an identifier that means something else.
#[tokio::test]
async fn a_usb_carrier_host_ignores_token_polls() {
    let mut h = harness(
        CredentialMode::Pkcs12,
        MonitorFailMode::Strict,
        vec![session(CARRIER)],
    );
    h.send(observed(&[]));
    for _ in 0..5 {
        h.send(failed());
    }

    assert!(
        h.action(GRACE * 3).await.is_none(),
        "the USB carrier's presence is udev's business, not the poller's"
    );
}

//! What the overlay does with what arrives on the socket.
//!
//! No display and no X server: the surface is a recorder, and what is asserted
//! is the sequence of things the overlay did to a screen, together with the
//! ending it reached and what it told the module. That is the part of the
//! overlay that can be wrong in a way nobody would see on a stand — a symbol
//! left on the screen after the attempt, a payload drawn for a stranger — and
//! it is the part a case on a machine is worst at catching.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test that cannot set itself up should fail on the spot"
)]

use std::io::{Cursor, Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use tessera_core::codes::overlay_ipc::{
    encode, AttemptId, Ending, Message, ATTEMPT_ID_LEN, HEADER_LEN, MAX_BODY_LEN,
};
use tessera_core::codes::qr::Symbol;

use super::{pump, Surface, SurfaceError, Waiting};

const PAYLOAD: &str = "https://codes.example/#tessera-codes/v1/signed-challenge;device=77-000123X";

fn attempt() -> AttemptId {
    AttemptId::from_bytes([0x42; ATTEMPT_ID_LEN])
}

fn other_attempt() -> AttemptId {
    AttemptId::from_bytes([0x99; ATTEMPT_ID_LEN])
}

/// What the overlay did to the screen, in order.
#[derive(Debug, PartialEq, Eq)]
enum Drawn {
    Shown(usize),
    Hidden,
}

/// A screen that records rather than draws.
#[derive(Default)]
struct Recorder {
    drawn: Vec<Drawn>,
    refuse_show: bool,
}

impl Surface for Recorder {
    fn show(&mut self, symbol: &Symbol) -> Result<(), SurfaceError> {
        if self.refuse_show {
            return Err(SurfaceError::new("no display in this test"));
        }
        self.drawn.push(Drawn::Shown(symbol.side()));
        Ok(())
    }

    fn hide(&mut self) -> Result<(), SurfaceError> {
        self.drawn.push(Drawn::Hidden);
        Ok(())
    }
}

/// Runs the overlay against a script of frames.
///
/// Nothing comes back: the wire runs one way, and the overlay is given no
/// writer at all. That is the shape of the guarantee — root does not read what
/// this process produced — expressed in a signature rather than in a comment.
fn run(frames: &[Vec<u8>]) -> (Ending, Recorder) {
    run_with(frames, Recorder::default())
}

fn run_with(frames: &[Vec<u8>], mut surface: Recorder) -> (Ending, Recorder) {
    let mut input = Cursor::new(frames.concat());
    let ending = pump(&mut input, None, &mut surface).unwrap();
    (ending, surface)
}

#[test]
fn a_challenge_is_drawn_and_a_cancel_takes_it_away() {
    let (ending, surface) = run(&[
        encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap(),
        encode(attempt(), &Message::Cancel).unwrap(),
    ]);
    assert_eq!(ending, Ending::Cancelled);
    assert!(matches!(
        surface.drawn.as_slice(),
        [Drawn::Shown(_), Drawn::Hidden]
    ));
}

#[test]
fn a_refresh_replaces_what_is_drawn() {
    let (ending, surface) = run(&[
        encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap(),
        encode(attempt(), &Message::Refresh("second payload".to_owned())).unwrap(),
        encode(attempt(), &Message::Cancel).unwrap(),
    ]);
    assert_eq!(ending, Ending::Cancelled);
    assert!(matches!(
        surface.drawn.as_slice(),
        [Drawn::Shown(_), Drawn::Shown(_), Drawn::Hidden]
    ));
}

#[test]
fn the_module_going_away_takes_the_symbol_off_the_screen() {
    // The failure this guards is the one a person would see: the login finished
    // or was abandoned, the module exited, and a QR stayed on the screen of a
    // cash machine for the next person to photograph.
    let (ending, surface) =
        run(&[encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap()]);
    assert_eq!(ending, Ending::Lost);
    assert_eq!(*surface.drawn.last().unwrap(), Drawn::Hidden);
}

#[test]
fn nothing_is_drawn_before_a_challenge_arrives() {
    // Anything that connects to the socket can send a frame. An overlay that
    // drew on a refresh it never got a challenge for would draw for whoever
    // asked first.
    for message in [Message::Refresh(PAYLOAD.to_owned()), Message::Cancel] {
        let (ending, surface) = run(&[encode(attempt(), &message).unwrap()]);
        assert!(
            matches!(ending, Ending::Violation(_)),
            "{message:?} ended as {ending:?}"
        );
        assert_eq!(surface.drawn, vec![Drawn::Hidden], "{message:?}");
    }
}

#[test]
fn a_frame_from_another_attempt_ends_the_conversation_without_drawing_it() {
    let (ending, surface) = run(&[
        encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap(),
        encode(other_attempt(), &Message::Refresh("elsewhere".to_owned())).unwrap(),
    ]);
    assert!(matches!(ending, Ending::Violation(_)), "{ending:?}");
    assert_eq!(
        surface.drawn,
        vec![Drawn::Shown(surface_side(&surface)), Drawn::Hidden],
        "the payload of another attempt reached the screen"
    );
}

/// The side of the first symbol the recorder was given.
fn surface_side(surface: &Recorder) -> usize {
    match surface.drawn.first() {
        Some(Drawn::Shown(side)) => *side,
        other => panic!("nothing was drawn: {other:?}"),
    }
}

#[test]
fn the_longest_payload_the_protocol_accepts_still_draws() {
    // The two bounds of this channel are set independently — the frame's body
    // limit and the capacity of a QR a camera can read — and this is what keeps
    // them agreeing. If they ever part, the overlay starts answering "I cannot
    // draw this" to a payload the module was entitled to send, and the failure
    // appears on a fleet rather than here.
    let payload = "x".repeat(MAX_BODY_LEN);
    let (ending, surface) = run(&[encode(attempt(), &Message::Challenge(payload)).unwrap()]);

    assert_eq!(ending, Ending::Lost, "the stream simply ran out");
    assert!(
        matches!(surface.drawn.as_slice(), [Drawn::Shown(_), Drawn::Hidden]),
        "the longest legal payload was not drawn: {:?}",
        surface.drawn
    );
}

#[test]
fn a_display_that_refuses_stops_the_overlay_and_takes_the_symbol_down() {
    // The reason does not travel: it goes to this process's standard error and
    // the module learns only that the socket closed. What is asserted here is
    // what remains observable — the attempt ends as a failure of the display,
    // and nothing is left on the screen.
    let mut surface = Recorder {
        drawn: Vec::new(),
        refuse_show: true,
    };
    let mut input =
        Cursor::new(encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap());
    let failure = pump(&mut input, None, &mut surface).unwrap_err();

    assert!(
        matches!(failure, super::PumpError::Surface(_)),
        "{failure:?}"
    );
    assert_eq!(surface.drawn, vec![Drawn::Hidden]);
}

#[test]
fn a_frame_that_stops_halfway_is_refused_rather_than_waited_on_forever() {
    let mut frame = encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap();
    frame.truncate(HEADER_LEN + 4);
    let (ending, surface) = run(&[frame]);
    assert!(matches!(ending, Ending::Violation(_)), "{ending:?}");
    assert_eq!(surface.drawn, vec![Drawn::Hidden]);
}

#[test]
fn a_header_declaring_more_than_the_protocol_allows_is_refused_on_the_header() {
    // Nothing is waited for and nothing is allocated for the body a hostile
    // peer promised: the overlay stops on the declaration.
    //
    // The ending alone does not say that. A build that took the declaration at
    // face value would ask for the body, be told the stream ended, and refuse
    // the same frame with the same ending — the difference is only in how much
    // of the stream it swallowed first. So the reader is left with a second
    // frame after the hostile one, and what is asserted is that the pump never
    // reached it.
    let mut frame = encode(attempt(), &Message::Cancel).unwrap();
    frame[6 + ATTEMPT_ID_LEN..HEADER_LEN].copy_from_slice(&u16::MAX.to_be_bytes());
    let after = encode(attempt(), &Message::Cancel).unwrap();
    let mut input = Cursor::new([frame, after].concat());

    let mut surface = Recorder::default();
    let ending = pump(&mut input, None, &mut surface).unwrap();

    assert!(matches!(ending, Ending::Violation(_)), "{ending:?}");
    assert_eq!(surface.drawn, vec![Drawn::Hidden]);
    assert_eq!(
        input.position(),
        u64::try_from(HEADER_LEN).unwrap(),
        "the header was refused, so nothing past it should have been read"
    );
}

#[test]
fn silence_ends_the_attempt_as_a_wait_that_ran_out() {
    // A socket with a read timeout answers `WouldBlock`. The overlay must treat
    // that as the attempt ending rather than as a stream to read again, or a
    // greeter is left with a symbol on it and a process spinning behind it.
    struct Silent;
    impl std::io::Read for Silent {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "waited",
            ))
        }
    }

    let mut surface = Recorder::default();
    let ending = pump(&mut Silent, None, &mut surface).unwrap();
    assert_eq!(ending, Ending::TimedOut);
    assert_eq!(surface.drawn, vec![Drawn::Hidden]);
}

/// A screen with a descriptor of its own, standing in for the display.
///
/// The real surface hears from an X server; here the other end of a socket
/// plays that part, which is enough to say whether the overlay listens to it at
/// all while the module is silent.
struct Talkative {
    events: UnixStream,
    serviced: usize,
    /// Whether serving the display fails, as it does once X has gone.
    refuses: bool,
}

impl Surface for Talkative {
    fn show(&mut self, _: &Symbol) -> Result<(), SurfaceError> {
        Ok(())
    }

    fn hide(&mut self) -> Result<(), SurfaceError> {
        Ok(())
    }

    fn events(&self) -> Option<BorrowedFd<'_>> {
        Some(self.events.as_fd())
    }

    fn service(&mut self) -> Result<(), SurfaceError> {
        if self.refuses {
            self.serviced += 1;
            return Err(SurfaceError::new("the display has gone"));
        }
        let mut said = [0_u8; 16];
        let read = self
            .events
            .read(&mut said)
            .map_err(|error| SurfaceError::new(error.to_string()))?;
        self.serviced += 1;
        if read == 0 {
            // The connection to the display ended. Reported as a refusal
            // because that is what it is to the caller: there is nothing left
            // to serve, and an X client whose socket closed cannot repaint.
            return Err(SurfaceError::new("the display went away"));
        }
        Ok(())
    }
}

#[test]
fn the_display_is_served_while_the_module_says_nothing() {
    // The failure this guards is invisible in every test that drives the pump
    // from a buffer: the overlay waits on the socket alone, the X connection is
    // never read, and the window stops being repainted the first time the
    // greeter puts a dialogue over it.
    let (mut module, overlay) = UnixStream::pair().unwrap();
    let (mut display, display_side) = UnixStream::pair().unwrap();
    display.write_all(b"expose").unwrap();

    let frames = [
        encode(attempt(), &Message::Challenge(PAYLOAD.to_owned())).unwrap(),
        encode(attempt(), &Message::Cancel).unwrap(),
    ]
    .concat();
    // The module speaks only after the display has: without the pause the
    // socket could be readable on the first wait and the display never looked
    // at, which would make this test pass for the wrong reason.
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        module.write_all(&frames).unwrap();
        drop(module);
    });

    let mut surface = Talkative {
        events: display_side,
        serviced: 0,
        refuses: false,
    };
    let mut input = overlay.try_clone().unwrap();
    let waiting = Waiting::new(overlay.as_fd(), Duration::from_secs(10));
    let ending = pump(&mut input, Some(waiting), &mut surface).unwrap();
    writer.join().unwrap();

    assert_eq!(ending, Ending::Cancelled);
    assert!(
        surface.serviced >= 1,
        "the display said something and was never served"
    );
}

#[test]
fn a_wait_that_runs_out_ends_the_attempt_and_lasted_the_budget() {
    // Both halves matter. The ending says the overlay stopped; the elapsed time
    // says it actually waited, and a budget that is not applied would show up
    // here as an attempt abandoned at once.
    let (module, overlay) = UnixStream::pair().unwrap();
    let (_display, display_side) = UnixStream::pair().unwrap();
    let silence = Duration::from_millis(200);

    let mut surface = Talkative {
        events: display_side,
        serviced: 0,
        refuses: false,
    };
    let mut input = overlay.try_clone().unwrap();
    let waiting = Waiting::new(overlay.as_fd(), silence);
    let started = Instant::now();
    let ending = pump(&mut input, Some(waiting), &mut surface).unwrap();
    let waited = started.elapsed();
    drop(module);

    assert_eq!(ending, Ending::TimedOut);
    assert!(waited >= silence, "waited only {waited:?}");
}

#[test]
fn a_display_that_will_not_be_served_is_dropped_from_the_wait() {
    // A display that has gone is READY, not quiet: its descriptor answers
    // `POLLHUP` at once and forever. A pump that kept serving it would spin a
    // core and write a line per turn into the greeter's journal for the rest of
    // the attempt — the visible half of this failure, and the half a person
    // reports.
    //
    // What is asserted is the count: served once, then never again. The ending
    // is asserted too, because dropping the display must not end the attempt —
    // the login belongs to the module.
    let (module, overlay) = UnixStream::pair().unwrap();
    let (display, display_side) = UnixStream::pair().unwrap();
    // The peer of the display is gone, which is what makes it permanently ready.
    drop(display);

    let mut surface = Talkative {
        events: display_side,
        serviced: 0,
        refuses: true,
    };
    let silence = Duration::from_millis(200);
    let mut input = overlay.try_clone().unwrap();
    let waiting = Waiting::new(overlay.as_fd(), silence);
    let ending = pump(&mut input, Some(waiting), &mut surface).unwrap();
    drop(module);

    assert_eq!(ending, Ending::TimedOut);
    assert_eq!(
        surface.serviced, 1,
        "the display was served {} times after refusing",
        surface.serviced
    );
}

#[test]
fn events_from_the_display_do_not_extend_the_budget_of_silence() {
    // The budget answers one question — how long a module may say nothing
    // before the symbol comes off the screen — and a greeter repainting its own
    // window is not the module speaking. Restarting the wait on every repaint
    // leaves the QR of an abandoned attempt on a screen for exactly as long as
    // somebody stands in front of it.
    let (module, overlay) = UnixStream::pair().unwrap();
    let (mut display, display_side) = UnixStream::pair().unwrap();

    // A display that keeps talking for longer than the budget lasts.
    let chatter = std::thread::spawn(move || {
        for _ in 0..40 {
            if display.write_all(b"expose").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });

    let mut surface = Talkative {
        events: display_side,
        serviced: 0,
        refuses: false,
    };
    let silence = Duration::from_millis(200);
    let mut input = overlay.try_clone().unwrap();
    let waiting = Waiting::new(overlay.as_fd(), silence);
    let started = Instant::now();
    let ending = pump(&mut input, Some(waiting), &mut surface).unwrap();
    let waited = started.elapsed();
    drop(module);
    chatter.join().unwrap();

    assert_eq!(ending, Ending::TimedOut);
    assert!(surface.serviced > 1, "the display was not served at all");
    // Generous against a slow machine and still far below the eight hundred
    // milliseconds of chatter: a budget that restarts would outlast it.
    assert!(
        waited < silence * 3,
        "the wait lasted {waited:?}, which is longer than the budget it was given"
    );
}

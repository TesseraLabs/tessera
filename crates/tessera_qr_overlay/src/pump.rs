//! The conversation, without a display.
//!
//! Everything the overlay does between reading bytes and putting ink on a
//! screen lives here, behind a reader, a writer and a [`Surface`]. That split is
//! the whole reason the overlay can be held to anything: the rules — one
//! challenge first, a payload that does not fit is reported rather than drawn,
//! a stranger's frame ends the attempt — are checked against a buffer in a test,
//! and only the drawing needs a machine with a greeter on it.

use std::io::Read;
use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, PollTimeout};

use tessera_core::codes::overlay_ipc::{
    declared_frame_len, Ending, OverlayAction, OverlayError, OverlaySession, HEADER_LEN,
    MAX_FRAME_LEN,
};
use tessera_core::codes::qr::{symbol, Symbol};

/// A surface the overlay can put a symbol on.
///
/// A trait rather than the X client directly, so that the conversation can be
/// driven without a display. It is deliberately two calls: an overlay that
/// could do more to a screen than show one symbol and take it away again would
/// be an unprivileged pre-auth process with more reach than it needs.
pub trait Surface {
    /// Puts the symbol on the screen, replacing whatever was there.
    ///
    /// # Errors
    ///
    /// [`SurfaceError`] when the display refused.
    fn show(&mut self, symbol: &Symbol) -> Result<(), SurfaceError>;

    /// Takes the symbol off the screen.
    ///
    /// # Errors
    ///
    /// [`SurfaceError`] when the display refused.
    fn hide(&mut self) -> Result<(), SurfaceError>;

    /// The descriptor the display speaks on, when the surface has one.
    ///
    /// [`None`] is a surface that says nothing back — the recorder a test
    /// drives — and the overlay then waits on the module alone.
    fn events(&self) -> Option<BorrowedFd<'_>> {
        None
    }

    /// Answers whatever the display has said.
    ///
    /// Called whenever the display's descriptor has something on it. A surface
    /// that never speaks does nothing here.
    ///
    /// # Errors
    ///
    /// [`SurfaceError`] when the display refused.
    fn service(&mut self) -> Result<(), SurfaceError> {
        Ok(())
    }
}

/// Where the module's frames arrive, and how long silence is tolerated.
///
/// Held apart from the reader because the conversation is checked against a
/// buffer that has no descriptor and no clock. [`None`] in place of this says
/// exactly that: read at once, wait on nothing.
#[derive(Clone, Copy, Debug)]
pub struct Waiting<'fd> {
    module: BorrowedFd<'fd>,
    silence: Duration,
}

impl<'fd> Waiting<'fd> {
    /// Waits on `module`, giving up after `silence` without a frame.
    #[must_use]
    pub const fn new(module: BorrowedFd<'fd>, silence: Duration) -> Self {
        Self { module, silence }
    }
}

/// What the wait ended on.
enum Woken {
    /// The module has bytes, or has gone away.
    Module,
    /// Nothing came within the silence budget.
    Silence,
}

/// The display refused something the overlay asked of it.
#[derive(Debug, thiserror::Error)]
#[error("the display refused: {detail}")]
pub struct SurfaceError {
    detail: String,
}

impl SurfaceError {
    /// Names what the display refused.
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// The overlay could not finish the conversation.
#[derive(Debug, thiserror::Error)]
pub enum PumpError {
    /// The socket failed.
    #[error("the connection to the module failed: {0}")]
    Io(#[from] std::io::Error),

    /// The display failed while the attempt was still running.
    ///
    /// Distinct from an attempt that ended: the module is told about this one
    /// over the wire, so that the device journal records a login that failed
    /// because nothing could be drawn rather than a login nobody explains.
    #[error("the display failed: {0}")]
    Surface(#[from] SurfaceError),
}

/// Drives one attempt to its end.
///
/// Reads frames from `input` and draws through `surface`. Nothing is written
/// back: the wire runs one way. Returns the [`Ending`] the attempt reached —
/// every path out,
/// including the ones that are not messages: the module went away, the payload
/// could not be drawn, a stranger sent a frame.
///
/// The wait is on two things at once when `waiting` names them: the module's
/// socket and the display. A display whose events are never read is a display
/// whose window stops being repainted — the symbol survives until something
/// passes over it and then it is gone, which on a greeter that puts its own
/// dialogues up is most of the time the symbol is needed. Without `waiting` the
/// reader is read straight, which is what a buffer in a test wants.
///
/// A socket with a read timeout on it produces an
/// [`std::io::ErrorKind::WouldBlock`], and this function turns that into the
/// same ending as the silence budget running out.
///
/// # Errors
///
/// [`PumpError::Surface`] when the screen could not be cleared on the way out —
/// the one failure a caller cannot be left to guess at, because it means the
/// symbol of a finished attempt is still on the screen.
pub fn pump(
    input: &mut impl Read,
    waiting: Option<Waiting<'_>>,
    surface: &mut impl Surface,
) -> Result<Ending, PumpError> {
    let mut session = OverlaySession::new();
    // Whether the display is still worth waiting on. It stops being worth it
    // the first time it refuses to be served — see `wait_for_frame`.
    let mut display_answers = true;
    loop {
        if let Some(waiting) = waiting {
            match wait_for_frame(waiting, surface, &mut display_answers)? {
                Woken::Module => {}
                Woken::Silence => return finish(surface, session.timed_out().clone()),
            }
        }
        let frame = match read_frame(input) {
            Ok(Some(frame)) => frame,
            // A clean end of the stream is the module going away. It is not an
            // error on this side: the module exits first on every path where
            // the login succeeded.
            Ok(None) => return finish(surface, session.peer_lost().clone()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return finish(surface, session.timed_out().clone())
            }
            Err(error) => return Err(error.into()),
        };

        // A refused frame gets no reply. The session refused it because whoever
        // sent it is not the module of this attempt — a stranger's frame, or one
        // out of turn — and answering would tell an unknown peer what this side
        // makes of what it sends. The module learns the same thing from the
        // socket closing under it.
        let Ok(action) = session.receive(&frame) else {
            let ending = session
                .ending()
                .cloned()
                .unwrap_or(Ending::Failed(OverlayError::Protocol));
            return finish(surface, ending);
        };

        match action {
            OverlayAction::Draw(payload) | OverlayAction::Redraw(payload) => {
                // Unreachable while the frame's body bound and the capacity of
                // a readable QR agree, which a test in this module keeps true.
                // Kept anyway: the alternative to reporting a payload that
                // cannot be drawn is drawing nothing and saying nothing, and
                // the engineer standing at the screen would have no idea why.
                let Ok(drawn) = symbol(&payload) else {
                    give_up(&mut session, OverlayError::Payload);
                    return finish(surface, Ending::Failed(OverlayError::Payload));
                };
                if let Err(error) = surface.show(&drawn) {
                    give_up(&mut session, OverlayError::Display);
                    finish(surface, Ending::Failed(OverlayError::Display))?;
                    return Err(error.into());
                }
            }
            OverlayAction::Finish(ending) => return finish(surface, ending),
        }
    }
}

/// Waits until the module has bytes, repainting for the display meanwhile.
///
/// The display is served first when both are ready: repainting costs nothing
/// against a frame that is already in the socket buffer, and the reverse order
/// leaves a window unpainted for the length of whatever the frame starts.
///
/// A failure of the display here is NOT a failure of the wait. The symbol may
/// already be unreadable, but the attempt belongs to the module, and an overlay
/// that abandoned it would take a login down over a repaint.
fn wait_for_frame(
    waiting: Waiting<'_>,
    surface: &mut impl Surface,
    display_answers: &mut bool,
) -> Result<Woken, std::io::Error> {
    // The budget is a deadline taken once, not a timeout handed to every call.
    // Recomputed inside the loop it would restart on every repaint the greeter
    // asked for, and an overlay abandoned by a module that died would then sit
    // on the screen for as long as the greeter keeps drawing — which is exactly
    // as long as somebody is standing in front of it.
    let deadline = Instant::now() + waiting.silence;
    loop {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(Woken::Silence);
        };
        let ready = {
            let display = if *display_answers {
                surface.events()
            } else {
                None
            };
            let mut watched = Vec::with_capacity(2);
            watched.push(PollFd::new(waiting.module, PollFlags::POLLIN));
            if let Some(display) = display {
                watched.push(PollFd::new(display, PollFlags::POLLIN));
            }
            // A budget that will not fit the argument becomes the smallest wait
            // there is, never an endless one: `PollTimeout::NONE` would turn a
            // number too large to express into "wait forever", which is the one
            // answer this budget exists to rule out.
            let timeout = PollTimeout::try_from(left).unwrap_or(PollTimeout::ZERO);
            match nix::poll::poll(&mut watched, timeout) {
                // `PollTimeout::try_from(Duration)` rounds to the kernel's
                // millisecond granularity. A zero result can therefore arrive
                // just before the absolute deadline. A signal is not silence
                // either: whoever sent it did not speak for the module. Only
                // the next loop may decide that the budget has expired.
                Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
                Ok(_) => {}
                Err(error) => return Err(std::io::Error::from(error)),
            }
            // Hang-up and error are readable ends too: the read that follows
            // reports them as an end of stream, which is what they are.
            let interesting = PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR;
            let ready_at = |index: usize| {
                watched
                    .get(index)
                    .and_then(PollFd::revents)
                    .is_some_and(|events| events.intersects(interesting))
            };
            (ready_at(0), display.is_some() && ready_at(1))
        };

        if ready.1 {
            if let Err(error) = surface.service() {
                // Said once and then never again, and the descriptor is dropped
                // from the wait with it. A display that has gone answers the
                // poll immediately and forever — `POLLHUP` is readiness — so a
                // pump that kept serving it would spin a core and fill the
                // greeter's journal for the rest of the attempt, which is the
                // part of this failure a person would actually notice.
                //
                // The attempt is NOT ended over it. The symbol may already be
                // unreadable, but the login belongs to the module, and this
                // process exists to draw for it rather than to judge it.
                eprintln!(
                    "tessera-qr-overlay: the display was not served and is no longer waited on: \
                     {error}"
                );
                *display_answers = false;
            }
        }
        if ready.0 {
            return Ok(Woken::Module);
        }
    }
}

/// Says why the overlay is giving up, where a person can read it.
///
/// Its own standard error, and nowhere else. The reason does NOT travel back to
/// the module: the module runs as root and the overlay does not, and a reverse
/// channel would be the one place where root parses what an unprivileged
/// process wrote. The module sees the socket close, which is all it needs to
/// carry on with the text path.
fn give_up(session: &mut OverlaySession, reason: OverlayError) {
    eprintln!("tessera-qr-overlay: giving up: {reason:?}");
    session.gave_up(reason);
}

/// Takes the symbol off the screen and hands back the ending.
fn finish(surface: &mut impl Surface, ending: Ending) -> Result<Ending, PumpError> {
    surface.hide()?;
    Ok(ending)
}

/// Reads one whole frame, or [`None`] at a clean end of the stream.
///
/// The length comes out of the header and is bounded before a single byte of
/// body is waited for: a peer that declares more than the protocol allows is
/// refused on the header, not after it has been given the memory it asked for.
fn read_frame(input: &mut impl Read) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut frame = vec![0_u8; HEADER_LEN];
    match input.read_exact(&mut frame) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }

    let total = match declared_frame_len(&frame) {
        // A header this build will refuse. Handing the bytes back unread lets
        // the session refuse it and say which way it was wrong, instead of this
        // function inventing an error of its own.
        Ok(Some(total)) if total <= MAX_FRAME_LEN => total,
        _ => return Ok(Some(frame)),
    };

    frame.resize(total, 0);
    let Some(body) = frame.get_mut(HEADER_LEN..) else {
        return Ok(Some(frame));
    };
    match input.read_exact(body) {
        Ok(()) => Ok(Some(frame)),
        // A truncated body is not a clean end: the peer promised bytes it did
        // not send. Handing back what arrived lets the session refuse it.
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            frame.truncate(HEADER_LEN);
            Ok(Some(frame))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;

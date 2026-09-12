//! Shows the QR of a login attempt over the greeter, and nothing else.
//!
//! Started by the PAM module of the attempt, with the path of the socket that
//! attempt is served on. Exits when the attempt ends, whichever way it ended.
//!
//! One byte travels back up the socket, and only one: `DRAWN`, written after
//! the FIRST symbol is on the screen. The module chooses between showing the
//! challenge as text in the prompt and leaving it to this process, and that
//! choice needs to know the symbol is actually visible — connecting to the
//! socket happens before the display is open and proves nothing. Everything
//! else the overlay has to say goes to its standard error, which lands wherever
//! the greeter's own does; the module runs as root and reads nothing else from
//! here. See `overlay_ipc` for what bounds that byte.
//!
//! # Usage
//!
//! ```text
//! tessera-qr-overlay --socket /run/tessera-overlay/attempt-<hex>
//! ```
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | the attempt ended and the screen was cleared |
//! | `1`  | the overlay could not do its job — no socket, no display |
//! | `2`  | the invocation was wrong |
//!
//! The code says whether the overlay worked, not whether the login succeeded:
//! the overlay is never told. A login that failed and a login that succeeded
//! both end the same way here, which is the point of a process that draws a
//! payload and holds no secret.

use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use tessera_core::codes::overlay_ipc;
use tessera_core::codes::qr::Symbol;
use tessera_qr_overlay::x11::X11Surface;
use tessera_qr_overlay::{pump, Surface, SurfaceError, Waiting};

/// How long the overlay waits for a frame before deciding the module is gone.
///
/// Longer than any step of an attempt a person is part of — reading a symbol
/// with a telephone, typing a code — and short enough that a process left
/// behind by a module that died does not sit on a greeter's screen until the
/// machine is rebooted.
const SILENCE: Duration = Duration::from_mins(10);

fn main() -> std::process::ExitCode {
    let socket = match socket_from_arguments(std::env::args().skip(1)) {
        Ok(path) => path,
        Err(complaint) => {
            let _ignored = writeln!(std::io::stderr(), "tessera-qr-overlay: {complaint}");
            return std::process::ExitCode::from(2);
        }
    };

    match show(&socket) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(failure) => {
            // The reason goes to the standard error of a process the module
            // started, which is where the module points its own journal. It
            // carries nothing about the attempt: the overlay does not know
            // anything about the attempt worth carrying.
            let _ignored = writeln!(std::io::stderr(), "tessera-qr-overlay: {failure}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Connects, draws, and returns when the attempt is over.
fn show(socket: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket)?;
    // The wait is set here rather than inside the conversation: a clock in the
    // part that is tested would be a clock every test has to wait on.
    stream.set_read_timeout(Some(SILENCE))?;
    // The write half stays open for exactly one byte, sent after the first
    // symbol is drawn (see `AckOnFirstDraw`). It used to go down here, when
    // nothing travelled upwards at all.
    let ack = stream.try_clone()?;
    let mut surface = AckOnFirstDraw {
        inner: X11Surface::open()?,
        ack: Some(ack),
    };

    // The ending is not turned into an exit code. What the overlay reports is
    // whether it did its job; what the attempt came to is the module's to
    // record, and it already knows.
    // The wait is handed in rather than left to the socket alone: the display
    // has to be served while the module says nothing, or the window stops being
    // repainted.
    // A second descriptor for the same socket: waiting borrows it while reading
    // needs it mutably, and one description under two handles costs nothing.
    let watched = stream.try_clone()?;
    let waiting = Waiting::new(watched.as_fd(), SILENCE);
    pump(&mut stream, Some(waiting), &mut surface)?;
    Ok(())
}

/// A surface that tells the module, once, that a symbol reached the screen.
///
/// A decorator rather than a line inside [`pump`]: the acknowledgement belongs
/// to the moment a draw SUCCEEDED, and that moment is already a return value
/// here. Putting it in the conversation would mean every test of the
/// conversation carrying a socket it has no use for.
///
/// The byte goes out at most once — `ack` is taken on the first success — and a
/// write that fails is ignored: the module is the one waiting for it, and a
/// module that has gone away needs nothing from this process.
struct AckOnFirstDraw<S: Surface> {
    inner: S,
    ack: Option<UnixStream>,
}

impl<S: Surface> Surface for AckOnFirstDraw<S> {
    fn show(&mut self, symbol: &Symbol) -> Result<(), SurfaceError> {
        self.inner.show(symbol)?;
        if let Some(stream) = self.ack.take() {
            let _ignored = (&stream).write_all(&[overlay_ipc::DRAWN]);
            // The half goes down as soon as the byte is out: one byte is the
            // whole of what this direction carries.
            let _ignored = stream.shutdown(std::net::Shutdown::Write);
        }
        Ok(())
    }

    fn hide(&mut self) -> Result<(), SurfaceError> {
        self.inner.hide()
    }

    fn events(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.inner.events()
    }

    fn service(&mut self) -> Result<(), SurfaceError> {
        self.inner.service()
    }
}

/// The socket path out of the arguments.
fn socket_from_arguments(
    mut arguments: impl Iterator<Item = String>,
) -> Result<PathBuf, &'static str> {
    let mut socket = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => {
                socket = Some(PathBuf::from(
                    arguments.next().ok_or("--socket needs a path")?,
                ));
            }
            _ => return Err("usage: tessera-qr-overlay --socket <path>"),
        }
    }
    socket.ok_or("usage: tessera-qr-overlay --socket <path>")
}

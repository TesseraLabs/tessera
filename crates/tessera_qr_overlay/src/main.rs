//! Shows the QR of a login attempt over the greeter, and nothing else.
//!
//! Started by the PAM module of the attempt, with the path of the socket that
//! attempt is served on. Exits when the attempt ends, whichever way it ended.
//!
//! Nothing travels back up the socket. When the overlay cannot draw, it says so
//! on its standard error — which lands wherever the greeter's own does — and
//! stops; the module runs as root and does not read what an unprivileged
//! process wrote.
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

use tessera_qr_overlay::x11::X11Surface;
use tessera_qr_overlay::{pump, Waiting};

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
    // Nothing is ever written back — the wire runs one way — so the write half
    // goes down at once. It costs nothing and it makes the direction a fact of
    // the socket rather than a promise of the code above it.
    let _ignored = stream.shutdown(std::net::Shutdown::Write);
    let mut surface = X11Surface::open()?;

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

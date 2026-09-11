//! The surface, against a real X display.
//!
//! An override-redirect window: the window manager of the greeter is told not
//! to manage it, so it keeps the position and the stacking this process gives
//! it and no theme draws a frame around a symbol a camera has to read.
//!
//! # It does not take the keyboard
//!
//! Deliberately, and it is the single most important line in this file even
//! though it is not a line of code. The design of 2026-07-03 has two modes: one
//! where the engineer types the code into the greeter's own field, and one
//! where the overlay has a field of its own and calls `XSetInputFocus` to get
//! the keystrokes. This is the first mode. Nothing here asks for focus, grabs
//! the keyboard or selects a key event, so an unprivileged pre-auth process on
//! a machine anybody can walk up to never has the keyboard of that machine.
//!
//! # Where the symbol is put
//!
//! In the top right corner, at a third of the shorter side of the screen. That
//! is a first choice and it is not verified: what it has to avoid is covering
//! the field the engineer types into, and which part of the screen that is
//! belongs to the greeter's theme. The stand case on a virtual machine is what
//! settles it; until then the number is here, in one place, with this comment
//! next to it rather than a claim that it was measured.

use std::os::fd::{AsFd, BorrowedFd};

use tessera_core::codes::qr::Symbol;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    ConnectionExt, CreateGCAux, CreateWindowAux, EventMask, Gcontext, Rectangle, StackMode, Window,
    WindowClass,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::COPY_DEPTH_FROM_PARENT;

use crate::pump::{Surface, SurfaceError};

/// Fraction of the shorter screen side the symbol occupies.
const SCREEN_FRACTION: u16 = 3;

/// Margin from the screen edge, as a fraction of the symbol's side.
const MARGIN_FRACTION: u16 = 10;

/// A window on the greeter's display that shows one symbol.
pub struct X11Surface {
    connection: RustConnection,
    window: Window,
    ink: Gcontext,
    paper: Gcontext,
    side: u16,
    mapped: bool,
    /// What is on the window right now.
    ///
    /// Kept because the X server does not keep it: a window that was covered
    /// comes back empty and is repainted by whoever owns it. Without this the
    /// symbol survives exactly until the greeter puts a dialogue over it.
    shown: Option<Symbol>,
}

impl X11Surface {
    /// Opens the display and creates the window, without showing it.
    ///
    /// The display and the credentials for it come from the environment the
    /// caller was started in — the module hands the overlay the greeter's, and
    /// that hand-off is the part that fails first on a new fleet.
    ///
    /// # Errors
    ///
    /// [`SurfaceError`] when the display refuses the connection or the window.
    pub fn open() -> Result<Self, SurfaceError> {
        let (connection, screen_index) = x11rb::connect(None)
            .map_err(|error| SurfaceError::new(format!("no display: {error}")))?;
        let screen = connection
            .setup()
            .roots
            .get(screen_index)
            .ok_or_else(|| SurfaceError::new("the display named a screen it does not have"))?;
        let root = screen.root;
        let side = screen.width_in_pixels.min(screen.height_in_pixels) / SCREEN_FRACTION;
        let margin = side / MARGIN_FRACTION;
        let x = i16::try_from(screen.width_in_pixels.saturating_sub(side + margin)).unwrap_or(0);
        let y = i16::try_from(margin).unwrap_or(0);

        let window = connection
            .generate_id()
            .map_err(|error| SurfaceError::new(format!("no window identifier: {error}")))?;
        connection
            .create_window(
                COPY_DEPTH_FROM_PARENT,
                window,
                root,
                x,
                y,
                side,
                side,
                0,
                WindowClass::INPUT_OUTPUT,
                screen.root_visual,
                &CreateWindowAux::new()
                    .background_pixel(screen.white_pixel)
                    // The window manager of the greeter does not get to place,
                    // resize or decorate this window.
                    .override_redirect(1)
                    // Exposure only. No key events are selected, so this window
                    // could not receive a keystroke even if it had focus.
                    .event_mask(EventMask::EXPOSURE),
            )
            .map_err(|error| SurfaceError::new(format!("no window: {error}")))?
            .check()
            .map_err(|error| {
                SurfaceError::new(format!("the display refused the window: {error}"))
            })?;

        let ink = new_gc(&connection, window, screen.black_pixel)?;
        let paper = new_gc(&connection, window, screen.white_pixel)?;

        Ok(Self {
            connection,
            window,
            ink,
            paper,
            side,
            mapped: false,
            shown: None,
        })
    }

    /// Draws the symbol into the window.
    ///
    /// Dark modules as ink on paper, which is the polarity print uses and the
    /// one every reader handles without thinking about it. The symbol is drawn
    /// at a whole number of pixels per module: a module of two and a half
    /// pixels is a module whose edges land differently across the symbol, and a
    /// camera reads that as noise.
    fn draw(&self, symbol: &Symbol) -> Result<(), SurfaceError> {
        let modules = u16::try_from(symbol.side()).unwrap_or(u16::MAX);
        if modules == 0 {
            return Err(SurfaceError::new("the symbol has no modules"));
        }
        let scale = (self.side / modules).max(1);
        let drawn = scale * modules;
        let offset = (self.side.saturating_sub(drawn)) / 2;

        self.connection
            .poly_fill_rectangle(
                self.window,
                self.paper,
                &[Rectangle {
                    x: 0,
                    y: 0,
                    width: self.side,
                    height: self.side,
                }],
            )
            .map_err(|error| SurfaceError::new(format!("the paper was refused: {error}")))?;

        let mut dark = Vec::new();
        for y in 0..symbol.side() {
            for x in 0..symbol.side() {
                if !symbol.is_dark(x, y) {
                    continue;
                }
                let (Ok(column), Ok(row)) = (u16::try_from(x), u16::try_from(y)) else {
                    continue;
                };
                dark.push(Rectangle {
                    x: i16::try_from(offset + column * scale).unwrap_or(i16::MAX),
                    y: i16::try_from(offset + row * scale).unwrap_or(i16::MAX),
                    width: scale,
                    height: scale,
                });
            }
        }
        // One request per row of the symbol at most: a single request carrying
        // every dark module of a version-20 symbol would be larger than the
        // maximum request length of many servers.
        for chunk in dark.chunks(1024) {
            self.connection
                .poly_fill_rectangle(self.window, self.ink, chunk)
                .map_err(|error| SurfaceError::new(format!("the ink was refused: {error}")))?;
        }
        self.connection
            .flush()
            .map_err(|error| SurfaceError::new(format!("the display did not take it: {error}")))?;
        Ok(())
    }
}

fn new_gc(
    connection: &RustConnection,
    window: Window,
    colour: u32,
) -> Result<Gcontext, SurfaceError> {
    let context = connection
        .generate_id()
        .map_err(|error| SurfaceError::new(format!("no graphics context: {error}")))?;
    connection
        .create_gc(
            context,
            window,
            &CreateGCAux::new().foreground(colour).background(colour),
        )
        .map_err(|error| SurfaceError::new(format!("no graphics context: {error}")))?
        .check()
        .map_err(|error| SurfaceError::new(format!("the display refused a context: {error}")))?;
    Ok(context)
}

impl Surface for X11Surface {
    fn show(&mut self, symbol: &Symbol) -> Result<(), SurfaceError> {
        if !self.mapped {
            self.connection
                .map_window(self.window)
                .map_err(|error| SurfaceError::new(format!("the window did not appear: {error}")))?
                .check()
                .map_err(|error| {
                    SurfaceError::new(format!("the display refused to show it: {error}"))
                })?;
            self.mapped = true;
        }
        // Raised on every symbol, not only on the first: the greeter puts its
        // own dialogues up while an attempt is running, and a symbol behind one
        // of them is a symbol nobody can photograph.
        self.connection
            .configure_window(
                self.window,
                &x11rb::protocol::xproto::ConfigureWindowAux::new().stack_mode(StackMode::ABOVE),
            )
            .map_err(|error| SurfaceError::new(format!("the window did not raise: {error}")))?;
        self.draw(symbol)?;
        self.shown = Some(symbol.clone());
        Ok(())
    }

    fn hide(&mut self) -> Result<(), SurfaceError> {
        self.shown = None;
        if !self.mapped {
            return Ok(());
        }
        self.connection
            .unmap_window(self.window)
            .map_err(|error| SurfaceError::new(format!("the window did not go away: {error}")))?;
        self.connection
            .flush()
            .map_err(|error| SurfaceError::new(format!("the display did not take it: {error}")))?;
        self.mapped = false;
        Ok(())
    }

    fn events(&self) -> Option<BorrowedFd<'_>> {
        Some(self.connection.stream().as_fd())
    }

    fn service(&mut self) -> Result<(), SurfaceError> {
        let mut repaint = false;
        loop {
            match self.connection.poll_for_event() {
                Ok(Some(Event::Expose(_))) => repaint = true,
                // Every other event is read and dropped on purpose. They are
                // read because an event queue nobody drains grows without
                // bound, and dropped because this window has no business
                // reacting to anything but being asked to paint itself.
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => {
                    return Err(SurfaceError::new(format!(
                        "the display stopped talking: {error}"
                    )))
                }
            }
        }
        if !repaint {
            return Ok(());
        }
        // Nothing to repaint is not a failure: an Expose between the symbol
        // going away and the process exiting is ordinary.
        let Some(symbol) = self.shown.take() else {
            return Ok(());
        };
        let outcome = self.draw(&symbol);
        self.shown = Some(symbol);
        outcome
    }
}

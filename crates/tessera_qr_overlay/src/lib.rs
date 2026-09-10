//! Draws the QR of a login attempt over the greeter of a graphical login.
//!
//! On a text console the device draws the symbol itself. On a graphical login
//! the greeter owns the screen, so the symbol is put on top of it by this
//! process: a separate, unprivileged X client that connects to a socket the PAM
//! module opened, draws what arrives, and goes away when told.
//!
//! # What this process is not allowed to be
//!
//! It does not take the keyboard. The engineer types the code into the
//! greeter's own field, which is the mode the design of 2026-07-03 calls 2a,
//! and an overlay that took focus would be an unprivileged pre-auth process
//! with a text field on a machine anybody can walk up to. There is no field
//! here, no input handling and no message on the wire that could carry a code.
//!
//! It also decides nothing. It holds no key, computes no code, verifies no
//! signature and never sees a nonce it could reuse: it is handed a payload that
//! is about to be photographed off a screen by a stranger's telephone, which is
//! the least secret thing in the whole method.
//!
//! # Shape of the crate
//!
//! [`pump()`] is the part that can be tested: it drives the conversation over any
//! reader and writer and draws through the [`Surface`] trait. [`x11`] is the
//! implementation of that trait against a real display, and it is the part that
//! needs a greeter, an X server and a machine to be tested on — which is what
//! the stand case is for.

pub mod pump;
pub mod x11;

pub use self::pump::{pump, PumpError, Surface, SurfaceError, Waiting};

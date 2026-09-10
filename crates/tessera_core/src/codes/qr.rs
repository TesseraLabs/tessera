//! The QR of a challenge, drawn for a console and for an ssh session.
//!
//! A device shows the challenge and a telephone reads it. On a graphical login
//! that is the overlay's job; everywhere else — a text console, a serial line,
//! an ssh session — the only surface the device has is a stream of characters,
//! and this module is what turns the payload into one a camera can read off it.
//!
//! # Half blocks, and why the drawing is not a picture
//!
//! A terminal cell is about twice as tall as it is wide, so a symbol drawn one
//! cell per module comes out stretched and a camera reads it badly or not at
//! all. Two module rows per character row — the half-block glyphs `▀`, `▄`, `█`
//! — put the aspect ratio back and halve the height, which matters on a console
//! that is twenty-four rows tall.
//!
//! # Polarity
//!
//! A dark module is drawn as ink: a filled glyph. On a terminal with a dark
//! background that yields a symbol whose polarity is inverted against print,
//! and readers of the ISO standard accept both — the specification defines the
//! reflectance relationship, not which of the two is on the screen. This is
//! stated rather than assumed: the guarantee that a telephone actually reads
//! what this function draws belongs to a case on a stand with a decoder in it,
//! not to a comment here.
//!
//! # It does not fit an eighty-column console, and that is stated rather than fixed
//!
//! At the version this channel bounds — twenty, ninety-seven modules — the
//! drawing is a hundred and five characters wide and fifty-three rows tall,
//! quiet zone included. A console of eighty by twenty-four cuts it off, and a
//! cut-off symbol does not read.
//!
//! Nothing is done about it here, deliberately. The width could only come down
//! by shrinking the quiet zone below the four modules the standard asks for, or
//! by refusing payloads the channel legitimately carries — the first trades a
//! symbol that reads for one that sometimes does, the second closes a login.
//! What the channel is built for is the overlay of a graphical login, which has
//! a screen rather than a character grid, and the wide terminal of an ssh
//! session.
//!
//! The login is not lost on a narrow console: the payload is printed as text
//! under the symbol, and typing it into a telephone is the same document by
//! another road. So this is a loss of convenience, and it is written down where
//! somebody sizing a serial console will see it.
//!
//! # The quiet zone is part of the symbol
//!
//! Four modules of margin on every side. Without them a reader has no way to
//! find the edge of the symbol against whatever the terminal drew before it,
//! and the symbol that scans on a clean screen stops scanning under a prompt.

use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};

/// Highest QR version the channel will produce.
///
/// Version 20 is 97 modules across. Above it the modules get small enough that
/// a telephone held at arm's length in front of a console — or in front of an
/// overlay on a screen behind glass — stops resolving them, and the failure is
/// the worst kind: the symbol is drawn, it looks right to a person, and it does
/// not read. The payload budget of the channel is set so that an attempt fits
/// inside this version; a payload that does not fit is refused rather than
/// drawn smaller.
const MAX_VERSION: u8 = 20;

/// Lowest QR version worth drawing.
///
/// Not a constraint on the payload — anything fits above it — but a floor that
/// keeps a short payload from producing a symbol so small that the terminal's
/// own character grid becomes the limiting factor.
const MIN_VERSION: u8 = 2;

/// Error correction level of the symbol.
///
/// Medium recovers about fifteen percent of the symbol. On a screen there is no
/// dirt and no wear, but there is a cursor, a scrolled line and a person's hand
/// in the frame, and the level below this one leaves nothing for any of them.
const CORRECTION: QrCodeEcc = QrCodeEcc::Medium;

/// Modules of quiet zone on each side.
const QUIET_ZONE: i32 = 4;

/// Renders the payload as a QR symbol in half-block characters.
///
/// The result ends with a newline and carries no escape sequences: it travels
/// inside a PAM prompt, and a prompt that carried terminal control would be a
/// prompt that rewrites the screen of whoever displays it.
///
/// # Errors
///
/// [`QrError::PayloadTooLong`] when the payload does not fit a symbol a camera
/// can read at this correction level — see `MAX_VERSION`. The refusal names
/// the length so that whoever configured the fleet can see what to shorten.
pub fn unicode_blocks(payload: &str) -> Result<String, QrError> {
    let code = encode(payload)?;
    Ok(draw(&code))
}

/// Renders the payload as a matrix of modules, quiet zone included.
///
/// For a caller that draws pixels rather than characters — the overlay of a
/// graphical login. The quiet zone is part of what is returned rather than left
/// to the caller: a symbol drawn flush against the edge of a window is a symbol
/// a reader cannot find, and that is not a decision worth taking twice.
///
/// # Errors
///
/// As [`unicode_blocks`].
pub fn symbol(payload: &str) -> Result<Symbol, QrError> {
    let code = encode(payload)?;
    let side = usize::try_from(code.size() + QUIET_ZONE * 2).unwrap_or(usize::MAX);
    let mut dark = Vec::with_capacity(side * side);
    for y in -QUIET_ZONE..code.size() + QUIET_ZONE {
        for x in -QUIET_ZONE..code.size() + QUIET_ZONE {
            // Coordinates outside the symbol answer light, which is the quiet
            // zone; the loop needs no second bounds rule.
            dark.push(code.get_module(x, y));
        }
    }
    Ok(Symbol { side, dark })
}

/// A drawn QR symbol as modules, quiet zone included.
///
/// Rows top to bottom, columns left to right, one boolean per module. Deliberately
/// not a bitmap, a byte buffer or an image: the caller decides how many pixels a
/// module is worth, and a type that had already decided would force every caller
/// to a resolution chosen for one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    side: usize,
    dark: Vec<bool>,
}

impl Symbol {
    /// Modules along one side, quiet zone included.
    #[must_use]
    pub const fn side(&self) -> usize {
        self.side
    }

    /// Whether the module at these coordinates is dark.
    ///
    /// Coordinates outside the symbol are light, so a caller that walks a
    /// slightly larger area does not have to bound its own loops.
    #[must_use]
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        if x >= self.side || y >= self.side {
            return false;
        }
        self.dark.get(y * self.side + x).copied().unwrap_or(false)
    }
}

/// Encodes the payload, bounded to a version a camera can read.
///
/// The segments are built from the text rather than handed to the high-level
/// call, because that call picks any version up to 40 and this channel refuses
/// above twenty: the bound is the whole point, and a symbol that encoded fine
/// and read badly is the failure being prevented.
fn encode(payload: &str) -> Result<QrCode, QrError> {
    let segments = QrSegment::make_segments(payload);
    QrCode::encode_segments_advanced(
        &segments,
        CORRECTION,
        Version::new(MIN_VERSION),
        Version::new(MAX_VERSION),
        None,
        // The correction level is not raised even when the payload leaves room
        // for it: two devices of one fleet drawing the same payload at
        // different levels produce two different symbols, and an operator
        // comparing screens would be comparing the encoder's spare capacity.
        false,
    )
    .map_err(|_| QrError::PayloadTooLong {
        length: payload.len(),
        max_version: MAX_VERSION,
    })
}

/// Draws the symbol, two module rows per character row.
fn draw(code: &QrCode) -> String {
    let from = -QUIET_ZONE;
    let to = code.size() + QUIET_ZONE;
    let mut text = String::new();
    let mut y = from;
    while y < to {
        for x in from..to {
            // Coordinates outside the symbol are light, and that is the quiet
            // zone: `get_module` answers for them, so the loop needs no second
            // bounds rule.
            let upper = code.get_module(x, y);
            let lower = code.get_module(x, y + 1);
            text.push(match (upper, lower) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        text.push('\n');
        y += 2;
    }
    text
}

/// Why a payload could not be drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QrError {
    /// The payload does not fit a symbol a camera can read.
    #[error(
        "the payload is {length} bytes, which does not fit a QR of version {max_version} at \
         medium correction; a longer one draws modules too small for a telephone to resolve"
    )]
    PayloadTooLong {
        /// Length of the payload, in bytes.
        length: usize,
        /// Highest version the channel draws.
        max_version: u8,
    },
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{symbol, unicode_blocks, QrError, MAX_VERSION, QUIET_ZONE};

    /// A payload of the shape the channel actually carries.
    ///
    /// The padding is deliberately not digits. A run of digits encodes in
    /// numeric mode, roughly three bytes to ten bits, and a budget test padded
    /// that way measures a payload the channel never sends: what the tail of a
    /// challenge actually carries is a base64 signature, mixed case and
    /// punctuation, which leaves the encoder no mode but byte. Padded with
    /// digits, 640 bytes fit a symbol far below the version this channel
    /// bounds, and the test would pass while the real budget did not.
    fn payload(len: usize) -> String {
        const TAIL: &[u8] = b"aB3+/xY9ZqK7wMnP2sTvE8hJ6uR4dG0lF5cX1bN";
        let mut text = String::from("https://codes.fleet.example/e#tessera-codes/v1/signed-challenge;device=77-000123S;epoch=7;nonce=");
        let mut index = 0;
        while text.len() < len {
            // Indexing is bounded by the modulus, and the bytes are ASCII.
            text.push(char::from(TAIL[index % TAIL.len()]));
            index += 1;
        }
        text.truncate(len);
        text
    }

    #[test]
    fn the_symbol_carries_a_quiet_zone_on_every_side() {
        // Without it a reader cannot find the edge of the symbol against the
        // prompt printed above it: the QR that scans on a clean screen stops
        // scanning in the place it is actually used.
        let drawn = unicode_blocks(&payload(400)).unwrap();
        let rows: Vec<&str> = drawn.lines().collect();
        let quiet_rows = usize::try_from(QUIET_ZONE).unwrap() / 2;

        for row in rows
            .iter()
            .take(quiet_rows)
            .chain(rows.iter().rev().take(quiet_rows))
        {
            assert!(
                row.chars().all(|glyph| glyph == ' '),
                "a row of the quiet zone carries ink: {row:?}"
            );
        }
        for row in &rows {
            let quiet = usize::try_from(QUIET_ZONE).unwrap();
            let leading = row.chars().take(quiet).all(|glyph| glyph == ' ');
            let trailing = row.chars().rev().take(quiet).all(|glyph| glyph == ' ');
            assert!(
                leading && trailing,
                "a side of the quiet zone carries ink: {row:?}"
            );
        }
    }

    #[test]
    fn the_matrix_and_the_drawing_are_the_same_symbol() {
        // Two ways of drawing one payload — half blocks for a console, modules
        // for the overlay — that disagreed would put two different QR codes in
        // front of one engineer, and only one of them would scan.
        let text = payload(400);
        let matrix = symbol(&text).unwrap();
        let rows: Vec<Vec<char>> = unicode_blocks(&text)
            .unwrap()
            .lines()
            .map(|row| row.chars().collect())
            .collect();

        assert_eq!(rows.first().unwrap().len(), matrix.side());
        for y in 0..matrix.side() {
            let row = rows.get(y / 2).unwrap();
            for (x, glyph) in row.iter().enumerate() {
                let drawn = if y % 2 == 0 {
                    *glyph == '█' || *glyph == '▀'
                } else {
                    *glyph == '█' || *glyph == '▄'
                };
                assert_eq!(drawn, matrix.is_dark(x, y), "module ({x}, {y})");
            }
        }
    }

    #[test]
    fn the_matrix_answers_light_outside_its_own_edge() {
        // So that a caller centring the symbol in a window can walk a slightly
        // larger area without bounding its loops a second time.
        let matrix = symbol(&payload(200)).unwrap();
        let side = matrix.side();
        assert!(!matrix.is_dark(side, 0));
        assert!(!matrix.is_dark(0, side));
        assert!(!matrix.is_dark(usize::MAX, usize::MAX));
    }

    #[test]
    fn the_matrix_carries_the_quiet_zone_it_promises() {
        let matrix = symbol(&payload(400)).unwrap();
        let quiet = usize::try_from(QUIET_ZONE).unwrap();
        for y in 0..matrix.side() {
            for x in 0..matrix.side() {
                let inside = x >= quiet
                    && y >= quiet
                    && x < matrix.side() - quiet
                    && y < matrix.side() - quiet;
                assert!(inside || !matrix.is_dark(x, y), "ink at ({x}, {y})");
            }
        }
    }

    #[test]
    fn a_payload_that_does_not_fit_is_refused_by_both_drawings() {
        let too_long = payload(4000);
        assert!(matches!(
            symbol(&too_long),
            Err(QrError::PayloadTooLong { .. })
        ));
        assert!(matches!(
            unicode_blocks(&too_long),
            Err(QrError::PayloadTooLong { .. })
        ));
    }

    #[test]
    fn the_symbol_is_square_in_modules_and_half_as_tall_in_rows() {
        // The whole reason for half blocks: one cell per module comes out
        // stretched and a camera reads it badly.
        let drawn = unicode_blocks(&payload(400)).unwrap();
        let rows: Vec<&str> = drawn.lines().collect();
        let width = rows.first().unwrap().chars().count();
        assert!(
            rows.iter().all(|row| row.chars().count() == width),
            "the rows are of different widths, so the grid is torn"
        );
        // Two module rows per character row, rounded up.
        assert_eq!(rows.len(), width.div_ceil(2));
    }

    #[test]
    fn the_drawing_carries_no_terminal_control() {
        // It travels inside a PAM prompt. A prompt carrying escape sequences is
        // a prompt that rewrites the screen of whoever displays it — including
        // a greeter that never expected to be drawn on.
        let drawn = unicode_blocks(&payload(400)).unwrap();
        assert!(
            drawn
                .chars()
                .all(|glyph| glyph == '\n' || !glyph.is_control()),
            "the drawing carries a control character"
        );
        assert!(!drawn.contains('\u{1b}'));
    }

    #[test]
    fn a_payload_the_camera_could_not_read_is_refused_rather_than_drawn() {
        // Refused, not drawn smaller. A symbol above version 20 is drawn, looks
        // right to a person, and does not read — which costs an engineer a trip
        // rather than a message.
        let refused = unicode_blocks(&payload(4000)).unwrap_err();
        assert_eq!(
            refused,
            QrError::PayloadTooLong {
                length: 4000,
                max_version: MAX_VERSION
            }
        );
    }

    #[test]
    fn a_payload_of_the_channel_budget_still_draws() {
        // 640 bytes is the budget of the payload contract, and the reason the
        // budget has that number is this call: the widest payload the channel
        // can produce has to fit a version a telephone reads.
        assert!(unicode_blocks(&payload(640)).is_ok());
    }
}

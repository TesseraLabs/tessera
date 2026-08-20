//! The МКЦ integrity level of the process the module runs in.
//!
//! The code login method grants a level, so it has to know which level is
//! being asked for. The greeter has already picked one by the time PAM runs,
//! and the kernel states the result as the label of the running process at
//! `/proc/self/attr/current` — the same channel a Parsec device exposes to
//! anything that cares, with no library, no FFI and no vendor UI in between.
//!
//! # The source is the adapter, not the file
//!
//! Which of those two sentences applies is decided by [`LevelSource`], and it
//! is decided by the OS adapter this device runs under rather than by what the
//! label file happens to contain. A device with a mandatory mechanism reads the
//! label and refuses everything it cannot make sense of; a device without one
//! has one level, zero, by construction — there is no mechanism that could
//! state another, and no file to read for it.
//!
//! The distinction has to come from the adapter because the file itself cannot
//! carry it: `/proc/self/attr/current` exists on every Linux and only a Parsec
//! kernel fills it in, so an empty read means "no mandatory mechanism here" on
//! one device and "the label of this process is missing" on the other. Guessing
//! between them by the content either hands a plain Linux device a level nobody
//! granted, or refuses the method on the whole non-Astra fleet.
//!
//! # The label
//!
//! Five colon-separated decimal fields, `конф:целостность:лин:кат:роли`; the
//! **second** one is the integrity level. A base level reads `0:0:0:0:0`,
//! which is a valid answer and not an absent one.
//!
//! # Why the whitelist is narrow
//!
//! Nothing here guesses. On an adapter that declares a mandatory mechanism, a
//! label that is missing, empty, cut short, or written in a shape this module
//! was not taught fails the login rather than resolving to a level — a level
//! guessed from an unrecognised label is a level nobody authorised.
//!
//! The level is not trusted on its own either. It states what the greeter
//! asked for, and the greeter is pre-authentication; what makes it safe is that
//! an operator ticket has to admit it — the ticket is the ceiling of the level
//! in this path, the way `MAX_INTEGRITY` is in the certificate path, and no
//! role slice states one. This module only has to be honest about what was
//! asked, and to keep
//! saying the same thing — see [`crate::codes_flow`] for the re-read that
//! closes the window between the challenge and the verdict.

use std::io::Read as _;

use tessera_codes_contract::canon::Level;

/// Where the kernel publishes the label of the running process.
pub const PROCESS_LABEL_PATH: &str = "/proc/self/attr/current";

/// Number of fields a label the module accepts is written in.
const LABEL_FIELDS: usize = 5;

/// Index of the integrity level among them.
const INTEGRITY_FIELD: usize = 1;

/// Longest label read from the label file.
///
/// A label is five small numbers. The bound is here because the path is a
/// filesystem name and a device with an unexpected mount layout could put
/// something else behind it.
const MAX_LABEL_LEN: u64 = 256;

/// Longest single field accepted, in characters — enough for any level a
/// kernel can express and short enough that a parse cannot be handed a
/// thousand digits.
const MAX_FIELD_LEN: usize = 20;

/// Highest integrity level the module will resolve.
///
/// The linear level of an Astra label is a signed byte
/// ([`IntegrityLabel::MAX_LEVEL`](tessera_core::mac::IntegrityLabel::MAX_LEVEL)),
/// so a level past it cannot be expressed as the label of a session at all and
/// would only ever be refused one stage later, with a less specific reason.
pub const MAX_INTEGRITY_LEVEL: u32 = 127;

/// The base level: the one level a device without a mandatory mechanism has.
const BASE_LEVEL: Level = Level::new(0);

/// Where the integrity level of a session comes from on this device.
///
/// Chosen from the OS adapter the module was configured for, once, before any
/// reading is attempted. It is what keeps "this device has no mandatory
/// mechanism" and "the label of this process could not be read" apart; the
/// second is fail-closed and the first is not a failure at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelSource {
    /// The adapter declares a mandatory mechanism (Astra Parsec): the level is
    /// the one the kernel published for this process, and nothing else is
    /// accepted in its place.
    ProcessLabel,

    /// The adapter declares no mandatory mechanism: every session runs at the
    /// base level, and no label is read or expected.
    NoMandatoryMechanism,
}

impl LevelSource {
    /// Reads the integrity level this session is being opened at.
    ///
    /// # Errors
    ///
    /// The failures of [`read_process_level`] under
    /// [`LevelSource::ProcessLabel`]. [`LevelSource::NoMandatoryMechanism`]
    /// cannot fail: it reads nothing.
    pub fn read(self) -> Result<Level, LevelError> {
        match self {
            Self::ProcessLabel => read_process_level(),
            Self::NoMandatoryMechanism => Ok(BASE_LEVEL),
        }
    }
}

/// Why the integrity level of the process could not be established.
///
/// Every variant is a refusal. None of them carries the text of the label:
/// what a device did answer with belongs in the diagnostics of the caller, not
/// in an error that travels.
#[derive(Debug, thiserror::Error)]
pub enum LevelError {
    /// The label file could not be read.
    #[error("the process label at {path} could not be read: {reason}")]
    Unreadable {
        /// Path that was read.
        path: &'static str,
        /// What the read reported.
        reason: String,
    },

    /// The label file is there but says nothing.
    ///
    /// A process whose label was cleared reads this way, and so does one on a
    /// kernel that labels nothing. On an adapter that declares a mandatory
    /// mechanism neither is level zero: a device that was supposed to be
    /// labelled and is not has a level nobody can state.
    #[error("the process label is empty; the level of this session is not stated")]
    Empty,

    /// The label is not written in the shape this module accepts.
    #[error("the process label is written in {fields} fields, not {LABEL_FIELDS}")]
    Malformed {
        /// How many fields it did carry.
        fields: usize,
    },

    /// A field of the label is not a decimal number of a plausible width.
    #[error("field {field} of the process label is not a decimal number")]
    NonNumericField {
        /// Which field, counted from zero.
        field: usize,
    },

    /// The level is beyond what the label of a session can hold.
    #[error(
        "the integrity level {level} is beyond {MAX_INTEGRITY_LEVEL}, which no session label holds"
    )]
    OutOfRange {
        /// The level the label stated.
        level: u64,
    },
}

/// Reads the integrity level of the running process.
///
/// # Errors
///
/// [`LevelError::Unreadable`] when the label file does not answer, and the
/// parse failures of [`parse_process_label`] otherwise.
pub fn read_process_level() -> Result<Level, LevelError> {
    let text = read_label(PROCESS_LABEL_PATH)?;
    parse_process_label(&text)
}

/// Reads at most [`MAX_LABEL_LEN`] bytes of `path`.
fn read_label(path: &'static str) -> Result<String, LevelError> {
    let unreadable = |error: std::io::Error| LevelError::Unreadable {
        path,
        reason: error.to_string(),
    };
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut text = String::new();
    // `/proc` reports a size of zero, so the bound has to come from the reader
    // rather than from the metadata of the file.
    file.take(MAX_LABEL_LEN)
        .read_to_string(&mut text)
        .map_err(unreadable)?;
    Ok(text)
}

/// Parses a process label and returns the integrity level it states.
///
/// The kernel terminates the value with a NUL and, depending on the reader, a
/// newline; both are trimmed before anything is looked at.
///
/// # Errors
///
/// [`LevelError::Empty`] for a label that says nothing,
/// [`LevelError::Malformed`] for one that is not five fields,
/// [`LevelError::NonNumericField`] for a field that is not a decimal number,
/// and [`LevelError::OutOfRange`] for a level no session label could hold.
pub fn parse_process_label(text: &str) -> Result<Level, LevelError> {
    let trimmed = text.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if trimmed.is_empty() {
        return Err(LevelError::Empty);
    }

    let fields: Vec<&str> = trimmed.split(':').collect();
    if fields.len() != LABEL_FIELDS {
        return Err(LevelError::Malformed {
            fields: fields.len(),
        });
    }

    // Every field is checked, not only the one that is used: a label whose
    // other coordinates are written in a shape this module does not know is a
    // label from a system it was not taught about, and the level in it means
    // whatever that system decided it means.
    for (index, field) in fields.iter().enumerate() {
        if field.is_empty()
            || field.len() > MAX_FIELD_LEN
            || !field.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(LevelError::NonNumericField { field: index });
        }
    }

    let integrity = fields
        .get(INTEGRITY_FIELD)
        .ok_or(LevelError::Malformed {
            fields: fields.len(),
        })?
        .parse::<u64>()
        .map_err(|_| LevelError::NonNumericField {
            field: INTEGRITY_FIELD,
        })?;
    let level = u32::try_from(integrity)
        .ok()
        .filter(|level| *level <= MAX_INTEGRITY_LEVEL)
        .ok_or(LevelError::OutOfRange { level: integrity })?;
    Ok(Level::new(level))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed setup step in a test should fail the test on the spot"
)]
mod tests {
    use super::{parse_process_label, LevelError, LevelSource, MAX_INTEGRITY_LEVEL};

    #[test]
    fn the_bound_is_what_a_session_label_can_express() {
        // The bound is the linear level of an Astra label, which is a signed
        // byte. Written out as a number here, and checked against the type it
        // came from so the two cannot drift apart.
        assert_eq!(
            MAX_INTEGRITY_LEVEL,
            u32::from(tessera_core::mac::IntegrityLabel::MAX_LEVEL.cast_unsigned())
        );
    }

    #[test]
    fn an_adapter_without_a_mandatory_mechanism_is_level_zero_by_construction() {
        // No file is read: on a plain Linux device the label file exists and is
        // empty, and reading it would refuse the method on the whole fleet.
        assert_eq!(
            LevelSource::NoMandatoryMechanism.read().unwrap().get(),
            0,
            "a device with no mandatory mechanism has one level, and it is zero",
        );
    }

    #[test]
    fn a_base_label_is_level_zero() {
        // A TTY or SSH login on a device with МКЦ enabled but nothing raised.
        assert_eq!(parse_process_label("0:0:0:0:0").unwrap().get(), 0);
    }

    #[test]
    fn the_second_field_is_the_level() {
        for level in 0..=3 {
            let label = format!("0:{level}:0:0:0");
            assert_eq!(parse_process_label(&label).unwrap().get(), level);
        }
        // The first field is confidentiality and must not be mistaken for it.
        assert_eq!(parse_process_label("2:0:0:0:0").unwrap().get(), 0);
    }

    #[test]
    fn the_kernel_terminators_are_trimmed() {
        assert_eq!(parse_process_label("0:3:0:0:0\0").unwrap().get(), 3);
        assert_eq!(parse_process_label("0:3:0:0:0\n").unwrap().get(), 3);
        assert_eq!(parse_process_label(" 0:3:0:0:0\0\n").unwrap().get(), 3);
    }

    #[test]
    fn an_empty_label_is_not_level_zero() {
        // What an unlabelled process answers. On an adapter that declares a
        // mandatory mechanism, reading it as the base level would hand the
        // device a level the МКЦ contour never granted; a device without the
        // mechanism never gets here at all (`NoMandatoryMechanism`).
        assert!(matches!(parse_process_label(""), Err(LevelError::Empty)));
        assert!(matches!(parse_process_label("\0"), Err(LevelError::Empty)));
        assert!(matches!(
            parse_process_label("   \n"),
            Err(LevelError::Empty)
        ));
    }

    #[test]
    fn a_partial_label_is_refused() {
        for label in ["0:3", "0:3:0:0", "0:3:0:0:0:0"] {
            assert!(
                matches!(
                    parse_process_label(label),
                    Err(LevelError::Malformed { .. })
                ),
                "accepted a partial label: {label}"
            );
        }
    }

    #[test]
    fn a_label_from_another_system_is_refused() {
        for label in [
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
            "0:x:0:0:0",
            "0::0:0:0",
            "0:0x3:0:0:0",
            "0:-1:0:0:0",
        ] {
            assert!(
                matches!(
                    parse_process_label(label),
                    Err(LevelError::NonNumericField { .. } | LevelError::Malformed { .. })
                ),
                "accepted a foreign label: {label}"
            );
        }
    }

    #[test]
    fn a_level_no_session_label_could_express_is_refused() {
        let label = format!("0:{}:0:0:0", MAX_INTEGRITY_LEVEL + 1);
        assert!(matches!(
            parse_process_label(&label),
            Err(LevelError::OutOfRange { .. })
        ));
        // One below the bound still resolves, so the refusal is the bound and
        // not an off-by-one that quietly narrowed the range.
        let last = format!("0:{MAX_INTEGRITY_LEVEL}:0:0:0");
        assert_eq!(
            parse_process_label(&last).unwrap().get(),
            MAX_INTEGRITY_LEVEL
        );
    }

    #[test]
    fn a_field_of_a_thousand_digits_is_refused() {
        let label = format!("0:{}:0:0:0", "9".repeat(1000));
        assert!(matches!(
            parse_process_label(&label),
            Err(LevelError::NonNumericField { .. })
        ));
    }
}

//! Operator confirmation for a certificate-issuance signing frontend.
//!
//! Before a key signs a TBS, an operator surface parses it with the shared
//! [`tessera_ext`] code (the same definitions the Engine enforces), renders a
//! human summary of the operation, and asks the operator to approve it: the
//! confirmation authorizes the *operation*, distinct from whatever authenticates
//! the caller. A TBS that the shared code cannot parse is refused before the
//! operator is ever prompted — what cannot be shown cannot be signed.
//!
//! Parsing a TBS into the shown [`OperationSummary`] lives in [`crate::summary`]
//! (pure, `wasm32`-compatible); this module owns only the interactive channel.
//! Two backends ship here: a pinentry dialog (the gpg-agent precedent, spoken
//! over the Assuan protocol) and a terminal prompt fallback. Both are injectable,
//! so a caller can drive a controllable one. This is the library's generic
//! confirmation channel for signing frontends; the fixed strings it renders are
//! localized through the passed [`Locale`].

use std::io::{BufRead, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::l10n::Locale;
use crate::summary::OperationSummary;

/// Errors from a confirmation channel that is present but failed to operate.
///
/// A decline is *not* an error — it is `Ok(false)`. These variants signal a
/// broken channel, on which the [`DefaultConfirmer`] falls back to the terminal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfirmError {
    /// The pinentry program could not be started.
    #[error("could not start confirmation program: {0}")]
    Spawn(String),
    /// An I/O error talking to the confirmation channel.
    #[error("confirmation channel I/O error: {0}")]
    Io(String),
    /// The Assuan exchange returned an unexpected response.
    #[error("confirmation protocol error: {0}")]
    Protocol(String),
}

/// Shows an operation to the operator and reports whether they approve it.
///
/// A blanket impl covers any `Fn(&OperationSummary) -> Result<bool,
/// ConfirmError>`, so a closure is an injectable confirmer for tests.
pub trait Confirmer {
    /// Present `summary` and return `true` if the operator approves.
    ///
    /// # Errors
    ///
    /// [`ConfirmError`] when the channel itself fails (not when the operator
    /// declines — a decline is `Ok(false)`).
    fn confirm(&self, summary: &OperationSummary) -> Result<bool, ConfirmError>;
}

impl<F> Confirmer for F
where
    F: Fn(&OperationSummary) -> Result<bool, ConfirmError>,
{
    fn confirm(&self, summary: &OperationSummary) -> Result<bool, ConfirmError> {
        self(summary)
    }
}

/// The terminal confirmation header, localized.
fn confirm_header(locale: Locale) -> &'static str {
    match locale {
        Locale::En => "=== Confirm issuance operation ===",
        Locale::Ru => "=== Подтверждение операции выпуска ===",
    }
}

/// The terminal confirmation prompt, localized.
fn confirm_prompt(locale: Locale) -> &'static str {
    match locale {
        Locale::En => "Sign this operation? [y/N]:",
        Locale::Ru => "Подписать эту операцию? [y/N]:",
    }
}

/// The notice printed when the pinentry channel fails and the terminal is used.
fn pinentry_fell_back(locale: Locale) -> &'static str {
    match locale {
        Locale::En => "pinentry unavailable, using terminal prompt:",
        Locale::Ru => "pinentry недоступен, используется терминал:",
    }
}

/// pinentry program names to probe on `PATH`, in preference order.
const PINENTRY_NAMES: &[&str] = &[
    "pinentry",
    "pinentry-mac",
    "pinentry-gtk-2",
    "pinentry-qt",
    "pinentry-curses",
];

/// A confirmer backed by a pinentry dialog (Assuan `CONFIRM`).
#[derive(Debug, Clone)]
pub struct PinentryConfirmer {
    program: PathBuf,
    locale: Locale,
}

impl PinentryConfirmer {
    /// Wrap a specific pinentry program, rendering summaries in `locale`.
    #[must_use]
    pub fn new(program: PathBuf, locale: Locale) -> Self {
        Self { program, locale }
    }

    /// Locate a pinentry program: an explicit path (from config/env) if it
    /// exists, otherwise the first known name found on `PATH`. Summaries render
    /// in `locale`.
    #[must_use]
    pub fn discover(explicit: Option<PathBuf>, locale: Locale) -> Option<Self> {
        if let Some(path) = explicit {
            if path.exists() {
                return Some(Self::new(path, locale));
            }
        }
        find_in_path(PINENTRY_NAMES).map(|program| Self::new(program, locale))
    }

    /// Run one Assuan `SETDESC`/`CONFIRM` exchange.
    fn run_confirm(&self, summary: &OperationSummary) -> Result<bool, ConfirmError> {
        let mut child = Command::new(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ConfirmError::Spawn(e.to_string()))?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ConfirmError::Io("pinentry stdin unavailable".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ConfirmError::Io("pinentry stdout unavailable".to_owned()))?;
        let mut reader = BufReader::new(stdout);

        let result = (|| {
            read_ok(&mut reader)?; // greeting
            send(
                &mut stdin,
                &format!("SETDESC {}", assuan_escape(&summary.render(self.locale))),
            )?;
            read_ok(&mut reader)?;
            send(&mut stdin, "SETPROMPT Tessera")?;
            read_ok(&mut reader)?;
            send(&mut stdin, "CONFIRM")?;
            confirm_response(&mut reader)
        })();

        // Politely close; ignore errors on teardown (the exchange already
        // produced `result`).
        if send(&mut stdin, "BYE").is_err() {
            // Teardown best-effort.
        }
        drop(stdin);
        if child.wait().is_err() {
            // Reaping best-effort.
        }
        result
    }
}

impl Confirmer for PinentryConfirmer {
    fn confirm(&self, summary: &OperationSummary) -> Result<bool, ConfirmError> {
        self.run_confirm(summary)
    }
}

/// A confirmer that prompts on the controlling terminal.
///
/// The summary and prompt go to stderr (stdout is left for machine output); the
/// answer is read from stdin. The summary, header, and prompt render in the
/// configured [`Locale`].
#[derive(Debug, Clone, Copy)]
pub struct TerminalConfirmer {
    locale: Locale,
}

impl TerminalConfirmer {
    /// A terminal confirmer that renders in `locale`.
    #[must_use]
    pub fn new(locale: Locale) -> Self {
        Self { locale }
    }
}

impl Confirmer for TerminalConfirmer {
    fn confirm(&self, summary: &OperationSummary) -> Result<bool, ConfirmError> {
        eprintln!("\n{}", confirm_header(self.locale));
        eprintln!("{}", summary.render(self.locale));
        eprint!("{} ", confirm_prompt(self.locale));
        std::io::stderr()
            .flush()
            .map_err(|e| ConfirmError::Io(e.to_string()))?;
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| ConfirmError::Io(e.to_string()))?;
        Ok(is_affirmative(&line))
    }
}

/// Whether a typed answer approves the operation. The English `y`/`yes` and the
/// Russian `д`/`да` are all accepted regardless of locale, so an operator is
/// never trapped by a locale mismatch.
fn is_affirmative(line: &str) -> bool {
    let answer = line.trim().to_lowercase();
    matches!(answer.as_str(), "y" | "yes" | "д" | "да")
}

/// The production confirmer: pinentry if one is available, else the terminal.
///
/// A pinentry *channel* failure (cannot spawn / protocol error) falls back to
/// the terminal; a pinentry *decline* is honoured as a decline.
#[derive(Debug, Clone)]
pub struct DefaultConfirmer {
    pinentry: Option<PinentryConfirmer>,
    locale: Locale,
}

impl DefaultConfirmer {
    /// Build the default confirmer, preferring `explicit_pinentry` then a
    /// pinentry program discovered on `PATH`; all surfaces render in `locale`.
    #[must_use]
    pub fn new(explicit_pinentry: Option<PathBuf>, locale: Locale) -> Self {
        Self {
            pinentry: PinentryConfirmer::discover(explicit_pinentry, locale),
            locale,
        }
    }
}

impl Confirmer for DefaultConfirmer {
    fn confirm(&self, summary: &OperationSummary) -> Result<bool, ConfirmError> {
        if let Some(pinentry) = &self.pinentry {
            match pinentry.confirm(summary) {
                Ok(decision) => return Ok(decision),
                Err(e) => {
                    eprintln!("{} {e}", pinentry_fell_back(self.locale));
                }
            }
        }
        TerminalConfirmer::new(self.locale).confirm(summary)
    }
}

/// Find the first of `names` present on `PATH` (probing a `.exe` suffix too on
/// Windows).
fn find_in_path(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
            #[cfg(windows)]
            {
                let exe = dir.join(format!("{name}.exe"));
                if exe.is_file() {
                    return Some(exe);
                }
            }
        }
    }
    None
}

/// Percent-escape a string for an Assuan command line.
///
/// Only what the protocol reads as structure is escaped: `%` itself, the C0
/// controls (a bare LF would end the line and turn the rest of the text into a
/// forged command), and `DEL`. Everything else — including non-ASCII — travels
/// as raw UTF-8, which is what the receiving side displays after it
/// percent-decodes the line.
///
/// Two constraints meet here. Escaping too little lets a value break the line;
/// escaping every non-ASCII byte costs six characters per Cyrillic letter and
/// pushes the command past the 1000-byte Assuan line limit, on which pinentry
/// drops the connection and the dialog disappears altogether. Escaping has to
/// walk characters, not bytes: a byte of a multi-byte character copied out
/// through `char::from` becomes a `U+00XX` codepoint that is re-encoded as UTF-8
/// on the way out, which is what turned Cyrillic summaries into mojibake.
///
/// This protects the transport, not the display: the escaping is reversible by
/// design, and pinentry decodes `%XX` back into the raw byte before rendering
/// it. What must not reach the operator's eyes in an active form is neutralized
/// where the summary is rendered, in [`crate::summary`].
fn assuan_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '%' | '\u{00}'..='\u{1F}' | '\u{7F}' => {
                let code = u32::from(c);
                out.push('%');
                out.push(hex_nibble((code >> 4) & 0xF));
                out.push(hex_nibble(code & 0xF));
            }
            _ => out.push(c),
        }
    }
    out
}

/// A single uppercase hex digit for a nibble (`0..=15`).
///
/// The argument is masked to four bits, so the fallback digit below is
/// unreachable. It is kept rather than replaced by a panic because this runs on
/// the path to a signature; what it must never do is fire silently, since a
/// quiet `'0'` would turn the escape into `%00`, injecting the one byte that
/// truncates the dialog text at the receiving end.
fn hex_nibble(nibble: u32) -> char {
    debug_assert!(nibble < 16, "callers must pass a four-bit nibble");
    char::from_digit(nibble & 0xF, 16).map_or('0', |c| c.to_ascii_uppercase())
}

/// Send one Assuan command line.
fn send(stdin: &mut impl std::io::Write, command: &str) -> Result<(), ConfirmError> {
    stdin
        .write_all(command.as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .and_then(|()| stdin.flush())
        .map_err(|e| ConfirmError::Io(e.to_string()))
}

/// Read Assuan responses until a final `OK`, erroring on `ERR`.
fn read_ok(reader: &mut impl BufRead) -> Result<(), ConfirmError> {
    loop {
        match read_line(reader)? {
            AssuanLine::Ok => return Ok(()),
            AssuanLine::Err(code) => return Err(ConfirmError::Protocol(code)),
            AssuanLine::Other => {}
        }
    }
}

/// Read the response to `CONFIRM`: `OK` is approval, `ERR` is a decline.
fn confirm_response(reader: &mut impl BufRead) -> Result<bool, ConfirmError> {
    loop {
        match read_line(reader)? {
            AssuanLine::Ok => return Ok(true),
            // pinentry returns an `ERR` with a cancel code when the operator
            // declines — a decline, not a channel failure.
            AssuanLine::Err(_) => return Ok(false),
            AssuanLine::Other => {}
        }
    }
}

/// One classified Assuan response line.
enum AssuanLine {
    Ok,
    Err(String),
    Other,
}

/// Read and classify one Assuan line.
fn read_line(reader: &mut impl BufRead) -> Result<AssuanLine, ConfirmError> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|e| ConfirmError::Io(e.to_string()))?;
    if read == 0 {
        return Err(ConfirmError::Protocol(
            "pinentry closed the connection".to_owned(),
        ));
    }
    let trimmed = line.trim_end();
    if trimmed == "OK" || trimmed.starts_with("OK ") {
        Ok(AssuanLine::Ok)
    } else if let Some(code) = trimmed.strip_prefix("ERR ") {
        Ok(AssuanLine::Err(code.to_owned()))
    } else if trimmed == "ERR" {
        Ok(AssuanLine::Err(String::new()))
    } else {
        // Data (`D`), status (`S`), comment (`#`), inquiry — informational here.
        Ok(AssuanLine::Other)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::unnecessary_wraps)]

    use super::*;
    use crate::l10n::Caption;
    use crate::summary::{OperationKind, SummaryLine};

    #[test]
    fn assuan_escape_encodes_controls_and_percent() {
        assert_eq!(assuan_escape("a b"), "a b");
        assert_eq!(assuan_escape("line1\nline2"), "line1%0Aline2");
        assert_eq!(assuan_escape("50%"), "50%25");
    }

    #[test]
    fn assuan_escape_keeps_non_ascii_intact() {
        // Non-ASCII carries no protocol meaning and is left as it is: the
        // receiving side reads the line as UTF-8. Escaping it byte by byte both
        // triples the length and, done through `char::from`, corrupts the text.
        assert_eq!(assuan_escape("да"), "да");
        assert_eq!(assuan_escape("\u{1F512}"), "\u{1F512}");
        assert_eq!(
            assuan_escape("CN=Иванов И. И., O=Ромашка"),
            "CN=Иванов И. И., O=Ромашка"
        );
    }

    #[test]
    fn assuan_escape_covers_the_boundary_bytes() {
        assert_eq!(assuan_escape(""), "");
        // The last C0 control is escaped, the first printable byte is not.
        assert_eq!(assuan_escape("\u{1F}"), "%1F");
        assert_eq!(assuan_escape(" "), " ");
        // DEL is the one control above the printable range.
        assert_eq!(assuan_escape("~\u{7F}"), "~%7F");
    }

    #[test]
    fn escaped_summary_fits_the_assuan_line_limit() {
        // Assuan caps a client request at 1000 bytes including the command and
        // the line terminator; over that, libassuan answers
        // `GPG_ERR_ASS_LINE_TOO_LONG` and pinentry drops the connection, so the
        // dialog disappears instead of being shown. The worst realistic summary
        // has to fit with room to spare — a Russian rendering of a fully
        // populated shift-leaf.
        const ASSUAN_MAX_LINE: usize = 1000;

        let summary = OperationSummary {
            kind: OperationKind::ShiftLeaf,
            subject: "CN=Иванов Иван Иванович, OU=Служба эксплуатации, \
                      O=Акционерное общество «Ромашка», C=RU"
                .to_owned(),
            not_before: "2026-08-10T07:00:00Z".to_owned(),
            not_after: "2026-08-10T19:00:00Z".to_owned(),
            lines: vec![
                SummaryLine {
                    caption: Caption::Roles,
                    value: "oper, serv, admin".to_owned(),
                },
                SummaryLine {
                    caption: Caption::Hosts,
                    value: "atm-0431.branch-77.romashka.example, \
                            atm-0432.branch-77.romashka.example"
                        .to_owned(),
                },
                SummaryLine {
                    caption: Caption::RequiredTags,
                    value: "смена, инкассация, обслуживание".to_owned(),
                },
                SummaryLine {
                    caption: Caption::MaxLevel,
                    value: "2".to_owned(),
                },
                SummaryLine {
                    caption: Caption::MaxTtl,
                    value: "43200".to_owned(),
                },
                SummaryLine {
                    caption: Caption::Integrity,
                    value: "2".to_owned(),
                },
                SummaryLine {
                    caption: Caption::Profile,
                    value: "1".to_owned(),
                },
            ],
        };

        let command = format!("SETDESC {}", assuan_escape(&summary.render(Locale::Ru)));
        // `send` appends one byte of line terminator to the command.
        let line = command.len() + 1;
        assert!(
            line < ASSUAN_MAX_LINE,
            "SETDESC line is {line} bytes, over the {ASSUAN_MAX_LINE}-byte Assuan limit"
        );
    }

    #[test]
    fn assuan_escape_round_trips_to_source_bytes() {
        // The property under test: pinentry percent-decodes the line it
        // receives and must end up with exactly the source UTF-8 bytes. A
        // mismatch here is the double encoding that filled the dialog with
        // mojibake.
        for source in [
            "операция: сертификат УЦ организации",
            "50% ключей\nна складе",
            "Ünïcødé — dash",
            "ascii only",
        ] {
            assert_eq!(
                percent_decode(&assuan_escape(source)),
                source.as_bytes(),
                "round-trip mismatch for {source:?}"
            );
        }
    }

    /// Decode percent sequences back into bytes, as the receiving Assuan side
    /// does.
    fn percent_decode(text: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(text.len());
        let mut bytes = text.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let hi = char::from(bytes.next().expect("truncated escape"));
                let lo = char::from(bytes.next().expect("truncated escape"));
                let hi = hi.to_digit(16).expect("not a hex digit");
                let lo = lo.to_digit(16).expect("not a hex digit");
                out.push(u8::try_from(hi * 16 + lo).expect("byte out of range"));
            } else {
                out.push(byte);
            }
        }
        out
    }

    #[test]
    fn closure_is_a_confirmer() {
        fn yes(_: &OperationSummary) -> Result<bool, ConfirmError> {
            Ok(true)
        }
        fn no(_: &OperationSummary) -> Result<bool, ConfirmError> {
            Ok(false)
        }
        let summary = OperationSummary {
            kind: OperationKind::Crl,
            subject: "CN=x".to_owned(),
            not_before: "a".to_owned(),
            not_after: "b".to_owned(),
            lines: vec![],
        };
        assert!(yes.confirm(&summary).unwrap());
        assert!(!no.confirm(&summary).unwrap());
    }
}

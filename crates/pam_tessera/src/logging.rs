//! One-shot tracing subscriber bridging into syslog (auth facility).
//!
//! PAM modules execute inside the calling process (sshd, login, sudo). Without
//! a global subscriber `tracing::error!` / `tracing::warn!` calls in the rest
//! of this crate are dropped silently, which makes production diagnosis blind.
//! `init_once` installs a process-global subscriber the FIRST time any PAM
//! entry is invoked; subsequent calls are no-ops.
//!
//! Output goes to syslog via the `syslog` crate (auth facility, ident
//! `pam_tessera`). On systems running journald the entries land in the
//! journal automatically; on classic syslog stacks they appear in
//! /var/log/auth.log.
#![allow(clippy::module_name_repetitions)]

use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};

use syslog::{Facility, Formatter3164, Logger, LoggerBackend};
use tracing_subscriber::fmt::MakeWriter;

static INIT: OnceLock<()> = OnceLock::new();

/// Install the syslog-backed tracing subscriber once per process. Safe to
/// call from every PAM entry — repeat calls short-circuit.
pub fn init_once() {
    INIT.get_or_init(|| {
        if let Err(err) = install_subscriber() {
            // We cannot log this failure (no subscriber yet); fall back to
            // stderr so something surfaces under `pamtester -v`.
            eprintln!("pam_tessera: failed to install tracing subscriber: {err}");
        }
    });
}

fn install_subscriber() -> Result<(), Box<dyn std::error::Error>> {
    let logger = syslog::unix(Formatter3164 {
        facility: Facility::LOG_AUTH,
        hostname: None,
        process: "pam_tessera".into(),
        pid: 0,
    })?;
    let writer = SyslogWriter {
        inner: Mutex::new(logger),
    };
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .without_time()
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

struct SyslogWriter {
    inner: Mutex<Logger<LoggerBackend, Formatter3164>>,
}

impl Write for &SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let line = String::from_utf8_lossy(buf);
        for piece in line.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(mut g) = self.inner.lock() {
                let _ = g.info(piece.to_string());
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SyslogWriter {
    type Writer = &'a SyslogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

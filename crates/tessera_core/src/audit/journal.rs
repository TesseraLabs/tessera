//! The device's audit journal: the chain, the ceiling, the attestation and the
//! verification.

use std::path::{Path, PathBuf};

use tessera_hashchain::storage::FileStorage;
use tessera_hashchain::{Chain, ChainError, ChainReport, ChainStorage as _};

use super::record::{AuditRecord, WhenFull};
use super::secrets::find_secret_field;

/// Default name of the journal inside the device's state directory.
pub const AUDIT_FILENAME: &str = "audit.ndjson";

/// Suffix given to a chain that was rotated away.
pub const ROTATED_SUFFIX: &str = "1";

/// Default ceiling: 64 MiB.
///
/// This is an event journal, not telemetry — one line per login, per enrolment,
/// per attestation, of the order of 200 bytes. At the busiest device the fleet
/// has any reason to expect, 64 MiB is years of history, so the ceiling is what
/// stops a runaway writer rather than something a device meets in the ordinary
/// course of its work. A fleet that exports on a schedule sets it lower; the
/// number is a parameter for exactly that reason.
pub const DEFAULT_CEILING_BYTES: u64 = 64 * 1024 * 1024;

/// Default attestation interval: 24 hours.
pub const DEFAULT_ATTEST_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// How the journal behaves: where it lives, how large it may grow, what it does
/// when it is full, and how often its head is attested.
#[derive(Debug, Clone)]
pub struct AuditPolicy {
    /// Where the chain file lives.
    pub path: PathBuf,
    /// The ceiling on the chain file, in bytes.
    pub ceiling_bytes: u64,
    /// What happens once the ceiling is reached.
    pub when_full: WhenFull,
    /// How often the head is attested on the schedule, in seconds.
    pub attest_interval_secs: u64,
}

impl AuditPolicy {
    /// The default policy for a journal at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ceiling_bytes: DEFAULT_CEILING_BYTES,
            when_full: WhenFull::Refuse,
            attest_interval_secs: DEFAULT_ATTEST_INTERVAL_SECS,
        }
    }
}

impl From<&crate::config::validated::AuditPolicySection> for AuditPolicy {
    fn from(section: &crate::config::validated::AuditPolicySection) -> Self {
        Self {
            path: section.file.clone(),
            ceiling_bytes: section.ceiling_bytes,
            when_full: section.when_full,
            attest_interval_secs: section.attest_interval.as_secs(),
        }
    }
}

/// Signs the 32-byte head of the chain with the device's attestation key.
///
/// The trait is here and the key is not: what holds the device key differs by
/// platform (a PKCS#11 token, a file under root) and none of that belongs in the
/// journal. `algorithm` is the stable label recorded beside the signature.
pub trait HeadSigner {
    /// The stable label for how this signer signs, e.g. `"ecdsa-sha256"`.
    fn algorithm(&self) -> &str;

    /// Signs the chain head.
    ///
    /// # Errors
    ///
    /// Whatever the key store reports, as a message. The journal treats any
    /// failure the same way: the head stays unattested and says so.
    fn sign(&self, head: &[u8; 32]) -> Result<Vec<u8>, String>;
}

/// Failure of the device audit journal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// The chain could not be read or appended to.
    #[error("the device audit journal could not be written: {0}")]
    Chain(#[from] ChainError),
    /// The journal has reached its ceiling and is configured to refuse.
    #[error("the device audit journal is full: {used_bytes} of {ceiling_bytes} bytes used, and the configured behaviour is to refuse new records")]
    Full {
        /// The configured ceiling.
        ceiling_bytes: u64,
        /// What the journal occupies.
        used_bytes: u64,
    },
    /// A record carried a field that may never be recorded. Nothing was
    /// written.
    #[error("a record was refused: the field `{field}` may never reach the journal")]
    SecretField {
        /// Path of the offending field inside the record.
        field: String,
    },
    /// The filled chain could not be rotated out of the way.
    #[error("the filled device audit journal could not be rotated: {0}")]
    Rotate(String),
    /// The attestation key refused or failed.
    #[error("the chain head could not be attested: {0}")]
    Attest(String),
    /// This process holds no audit journal. Distinguished from success so a
    /// caller that needs the record can tell "recorded" from "nowhere to
    /// record it".
    #[error("this device has no audit chain configured")]
    NotConfigured,
}

/// The device's audit journal.
///
/// # Genesis is not attested, and enrolment is what closes that
///
/// Until the first head signature lands, nothing outside the file vouches for
/// any of it. A device installed an hour ago and a device whose journal was
/// wiped an hour ago are, from the file alone, the same device: both hold a
/// short chain that verifies perfectly from genesis. No property of the chain
/// can separate them, because the chain is entirely inside the machine whose
/// owner is the one being audited.
///
/// What separates them is enrolment: the device's identity is established once,
/// against a fleet that remembers it, and a device presenting a fresh journal
/// under an identity the fleet has been talking to for a year is visible as
/// exactly that. This journal does not close the gap and does not pretend to —
/// stating it here is the alternative to an auditor discovering it during an
/// incident.
#[derive(Debug)]
pub struct AuditJournal {
    chain: Chain<FileStorage, AuditRecord>,
    policy: AuditPolicy,
    last_attested_ts: Option<u64>,
    full_reported: bool,
}

impl AuditJournal {
    /// Opens the journal described by `policy`, creating nothing until the
    /// first record.
    ///
    /// A chain that does not verify is still opened: refusing to open it would
    /// mean that tampering with the journal also stops it recording what
    /// happens next, which is a reward for tampering. What a broken chain does
    /// is fail [`AuditJournal::verify`], loudly and with a position.
    ///
    /// # Errors
    ///
    /// [`AuditError::Chain`] if the existing records cannot be read.
    pub fn open(policy: AuditPolicy) -> Result<Self, AuditError> {
        let storage = FileStorage::new(policy.path.clone());
        let last_attested_ts = last_attested_ts(&storage)?;
        // A journal that already ends in the notice has said it is full. Each
        // process would otherwise announce it again on its first refusal, and a
        // journal configured to refuse records would grow by one line per
        // refused record — which is the opposite of refusing.
        let full_reported = tail_is_full_notice(&storage)?;
        let chain = Chain::load(storage)?;
        Ok(Self {
            chain,
            policy,
            last_attested_ts,
            full_reported,
        })
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> &AuditPolicy {
        &self.policy
    }

    /// The current chain head.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.chain.head()
    }

    /// When the head was last attested, if it ever was.
    #[must_use]
    pub fn last_attested_ts(&self) -> Option<u64> {
        self.last_attested_ts
    }

    /// Records one event.
    ///
    /// The ceiling is checked first, then the secret filter, then the append.
    /// The order matters: a record refused for either reason must not leave a
    /// partial line behind, and a journal at its ceiling must say so before it
    /// grows further.
    ///
    /// The caller decides what a failure costs by asking the record —
    /// [`AuditRecord::write_discipline`] — and this method never decides for it.
    ///
    /// # Errors
    ///
    /// [`AuditError::Full`] when the ceiling is reached under
    /// [`WhenFull::Refuse`], [`AuditError::SecretField`] when the record carries
    /// a field that may never be written, [`AuditError::Rotate`] when a full
    /// journal cannot be moved aside, and [`AuditError::Chain`] for a storage or
    /// encoding failure.
    pub fn record(&mut self, record: &AuditRecord, now_unix: u64) -> Result<(), AuditError> {
        if let AuditRecord::Annotation(annotation) = record {
            if let Some(field) = find_secret_field(&annotation.data) {
                return Err(AuditError::SecretField { field });
            }
        }

        // How much this record will take, measured rather than guessed: the
        // ceiling has to know before the line lands, and the encoding is the
        // only thing that knows the size.
        let incoming = serde_json::to_string(record).map_or(0, |line| line.len() as u64 + 1);
        self.enforce_ceiling(now_unix, incoming)?;
        self.chain.append(record, now_unix)?;
        Ok(())
    }

    /// Records writer-defined context under `kind`.
    ///
    /// The chain carries it on the same terms as its own events: removing it
    /// breaks the chain at its position. Nothing here reads `data`, which is
    /// why it goes past the secret filter first — an annotation is the one place
    /// where the fields are chosen by somebody this crate has never seen.
    ///
    /// # Errors
    ///
    /// As [`AuditJournal::record`], plus [`AuditError::Chain`] carrying
    /// [`ChainError::EmptyAnnotationKind`] or
    /// [`ChainError::AnnotationDataNotObject`] for an annotation the format does
    /// not admit.
    pub fn annotate(
        &mut self,
        kind: &str,
        data: serde_json::Value,
        now_unix: u64,
    ) -> Result<(), AuditError> {
        if kind.is_empty() {
            return Err(ChainError::EmptyAnnotationKind.into());
        }
        if !data.is_object() {
            return Err(ChainError::AnnotationDataNotObject.into());
        }
        self.record(
            &AuditRecord::Annotation(tessera_hashchain::Annotation {
                kind: kind.to_owned(),
                data,
            }),
            now_unix,
        )
    }

    /// Attests the current head, on command.
    ///
    /// # Errors
    ///
    /// [`AuditError::Attest`] if the key store refuses, or the errors of
    /// [`AuditJournal::record`] if the signature line cannot be written.
    pub fn attest(&mut self, signer: &dyn HeadSigner, now_unix: u64) -> Result<(), AuditError> {
        use base64::Engine as _;

        let head = self.chain.head();
        let signature = signer.sign(&head).map_err(AuditError::Attest)?;
        self.record(
            &AuditRecord::HeadSignature(tessera_hashchain::HeadSignature {
                algorithm: signer.algorithm().to_owned(),
                signature: base64::engine::general_purpose::STANDARD.encode(&signature),
            }),
            now_unix,
        )?;
        self.last_attested_ts = Some(now_unix);
        Ok(())
    }

    /// Attests the head if the schedule says it is due, and reports whether it
    /// did.
    ///
    /// A journal that has never been attested is always due: the first
    /// attestation is the one that matters most, because everything before it is
    /// vouched for by nothing.
    ///
    /// # Errors
    ///
    /// As [`AuditJournal::attest`].
    pub fn attest_if_due(
        &mut self,
        signer: &dyn HeadSigner,
        now_unix: u64,
    ) -> Result<bool, AuditError> {
        let due = match self.last_attested_ts {
            None => true,
            Some(last) => now_unix.saturating_sub(last) >= self.policy.attest_interval_secs,
        };
        if !due {
            return Ok(false);
        }
        self.attest(signer, now_unix)?;
        Ok(true)
    }

    /// Verifies the chain: recompute from genesis, check `seq`, report the
    /// position of the first break.
    ///
    /// The result distinguishes "intact, tail not yet attested"
    /// ([`tessera_hashchain::ChainStatus::IntactUnsignedTail`]) from "broken"
    /// ([`tessera_hashchain::ChainStatus::Broken`]). Both are things an operator
    /// will see; only one of them is an incident.
    ///
    /// # Errors
    ///
    /// [`AuditError::Chain`] if the records cannot be read.
    pub fn verify(&self) -> Result<ChainReport, AuditError> {
        Ok(self.chain.verify()?)
    }

    /// Applies the ceiling before a record is appended.
    ///
    /// The `journal_full` line is written once, when the ceiling is first
    /// reached, and writing it takes the journal a line past its ceiling. That
    /// is deliberate: a journal that is too full to say it is full leaves the
    /// fact to be inferred from an absence, which is the very inference this
    /// whole construction exists to make unnecessary.
    fn enforce_ceiling(&mut self, now_unix: u64, incoming_bytes: u64) -> Result<(), AuditError> {
        let used_bytes = self.chain.storage().byte_len()?;
        // The ceiling is compared against what the journal will occupy once
        // this record lands, not against what it occupies now. Comparing the
        // current size alone turns "one line past the ceiling" — the deliberate
        // exception below — into "as far past it as the writer felt like",
        // because the record about to be written is unbounded: an annotation
        // comes from outside this crate and can be megabytes.
        if used_bytes.saturating_add(incoming_bytes) <= self.policy.ceiling_bytes {
            self.full_reported = false;
            return Ok(());
        }

        if !self.full_reported {
            self.full_reported = true;
            let notice = AuditRecord::JournalFull {
                ceiling_bytes: self.policy.ceiling_bytes,
                used_bytes,
                when_full: self.policy.when_full,
            };
            // This one line is written past the ceiling on purpose, and it is
            // the only one that may be: a journal too full to say it is full
            // leaves the fact to be inferred from an absence of records, which
            // is the very inference the chain exists to make unnecessary. Every
            // other record is measured against the ceiling before it lands.
            //
            // The diagnostic goes out whether or not the line lands: under
            // `Refuse` the next thing that happens is a refusal, and an
            // operator seeing only the refusal would have to guess why.
            tracing::error!(
                target: super::TRACING_TARGET,
                event = notice.event_name(),
                ceiling_bytes = self.policy.ceiling_bytes,
                used_bytes,
                when_full = ?self.policy.when_full,
                "the device audit journal has reached its ceiling"
            );
            self.chain.append(&notice, now_unix)?;
        }

        match self.policy.when_full {
            WhenFull::Refuse => Err(AuditError::Full {
                ceiling_bytes: self.policy.ceiling_bytes,
                used_bytes,
            }),
            WhenFull::Rotate => self.rotate(now_unix),
        }
    }

    /// Moves the filled chain aside and starts a new one whose first line says
    /// so.
    fn rotate(&mut self, now_unix: u64) -> Result<(), AuditError> {
        let report = self.chain.verify()?;
        let previous_head = hex::encode(self.chain.head());
        let rotated = rotated_path(&self.policy.path);

        // Rotating on top of an already-rotated chain would destroy it, and it
        // would do so exactly when the device is furthest behind on exporting
        // its audit — the case this whole mechanism exists for. A second
        // rotation is refused until the first one has been taken away.
        if rotated.exists() {
            return Err(AuditError::Rotate(format!(
                "{} is still there: the previously rotated chain has not been taken away, and \
                 overwriting it would destroy the history rotation was supposed to preserve",
                rotated.display()
            )));
        }

        std::fs::rename(&self.policy.path, &rotated)
            .map_err(|error| AuditError::Rotate(error.to_string()))?;

        let break_record = AuditRecord::ChainBreak {
            previous_head,
            previous_entries: report.entry_count,
            rotated_to: rotated.display().to_string(),
        };

        // The record of the break has to land, or the rotation is undone.
        //
        // The failure here is not hypothetical and not rare: the disk is full
        // exactly when a journal reaches its ceiling, which is exactly when
        // rotation happens. Leaving the rename in place after a failed write
        // would give a fresh chain starting at genesis with nothing anywhere
        // saying an older one exists — silent rotation, which task 3.3 declares
        // impossible and which is indistinguishable from somebody having
        // deleted the journal.
        let storage = FileStorage::new(self.policy.path.clone());
        let mut fresh = Chain::load(storage)?;
        if let Err(error) = fresh.append(&break_record, now_unix) {
            // Put the filled chain back where it was. A journal that refuses
            // further records is a bad state an operator can see and act on; a
            // journal that quietly lost its past is not.
            let restored = std::fs::remove_file(&self.policy.path)
                .or_else(|remove| match remove.kind() {
                    std::io::ErrorKind::NotFound => Ok(()),
                    _ => Err(remove),
                })
                .and_then(|()| std::fs::rename(&rotated, &self.policy.path));
            return Err(match restored {
                Ok(()) => AuditError::Rotate(format!(
                    "the record of the break could not be written, so the rotation was undone \
                     and the filled journal is back in place: {error}"
                )),
                Err(undo) => AuditError::Rotate(format!(
                    "the record of the break could not be written ({error}) and the rotation \
                     could not be undone ({undo}): the filled journal is at {}",
                    rotated.display()
                )),
            });
        }

        self.chain = fresh;
        self.last_attested_ts = None;
        self.full_reported = false;

        tracing::warn!(
            target: super::TRACING_TARGET,
            event = break_record.event_name(),
            rotated_to = %rotated.display(),
            previous_entries = report.entry_count,
            "the device audit journal was rotated; the chain is broken here on purpose"
        );
        Ok(())
    }
}

/// Where a filled chain is moved to.
fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(ROTATED_SUFFIX);
    PathBuf::from(name)
}

/// Whether the chain already ends in a "journal full" notice.
fn tail_is_full_notice(storage: &FileStorage) -> Result<bool, AuditError> {
    let lines = storage.read_lines()?;
    let Some(last) = lines.last() else {
        return Ok(false);
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(last) else {
        return Ok(false);
    };
    Ok(value.get("op").and_then(serde_json::Value::as_str) == Some("journal_full"))
}

/// Reads the timestamp of the last head signature out of an existing chain.
///
/// Parsed as plain JSON rather than through the record type: the only two fields
/// that matter are `op` and `ts`, and a line this build cannot otherwise read
/// must not stop the journal from knowing when it was last attested.
fn last_attested_ts(storage: &FileStorage) -> Result<Option<u64>, AuditError> {
    let mut latest = None;
    for line in storage.read_lines()? {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if value.get("op").and_then(serde_json::Value::as_str)
            != Some(tessera_hashchain::OP_HEAD_SIGNATURE)
        {
            continue;
        }
        if let Some(ts) = value.get("ts").and_then(serde_json::Value::as_u64) {
            latest = Some(ts);
        }
    }
    Ok(latest)
}

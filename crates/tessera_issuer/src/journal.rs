//! The issuance journal: a hash-chained, append-only NDJSON record of every
//! certificate and CRL the tool issues.
//!
//! Each issuance appends one line before its artifact is handed back to the
//! operator, so a lost or failed write blocks the issuance (fail-closed). A
//! line carries a monotonic `seq`, the SHA-256 of the previous line
//! (`prev_hash`; the first line chains to a fixed genesis anchor), a
//! caller-supplied timestamp, and an operation payload. Tampering with,
//! deleting, or reordering any line breaks the chain, which
//! [`verify_lines`] reports with the position of the first bad entry.
//!
//! The journal is secondary evidence — the primary record of access is the
//! login audit on the devices — so it exists for inventory and incident
//! review, not enforcement.
//!
//! The core is byte- and string-only and carries no clock: timestamps are
//! passed in, and persistence is a [`JournalStorage`] the caller supplies (a
//! file natively, browser storage in the cabinet). That keeps the module
//! `wasm32`-compatible.
//!
//! # Head signatures
//!
//! [`Journal::sign_head`] signs the current chain head (its 32-byte hash)
//! through the shared [`SignatureBackend`] and records the signature as its own
//! line. Verification distinguishes a chain whose tail is covered by a head
//! signature ([`JournalStatus::Intact`]) from one with records added after the
//! last signature ([`JournalStatus::IntactUnsignedTail`]). The *cryptographic*
//! check of a head signature needs the CA public key and is delegated to the
//! caller: [`verify_lines`] confirms structure and reports which head each
//! signature covers; a caller re-signs or verifies out of band.
//!
//! # Annotations
//!
//! [`Journal::append_annotation`] records a general-purpose `annotation` line
//! carrying a `kind` (a non-empty namespace tag chosen by the writer) and an
//! opaque `data` JSON object. The core neither interprets nor validates
//! `kind`/`data` beyond structure: an annotation chains, hashes, and verifies
//! exactly like any other line, so tampering with one breaks the chain at its
//! position, but an unknown `kind` verifies without complaint. This lets a
//! caller attach out-of-band context to the record without the core growing a
//! new operation for every use.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::IssueError;
use crate::sign::{KeyId, SignatureAlgorithm, SignatureBackend};

/// The fixed domain-separation preimage whose SHA-256 anchors an empty chain.
const GENESIS_PREIMAGE: &[u8] = b"tessera-issuance-journal/v1/genesis";

/// Errors from journal storage or record encoding.
///
/// These are fail-closed at the issuance boundary: an issuance that cannot be
/// journaled does not return an artifact (see [`IssueError::Journal`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The backing storage could not append or read (permissions, disk, a
    /// browser-side failure).
    #[error("journal storage unavailable: {0}")]
    Storage(String),
    /// A record could not be serialized to NDJSON.
    #[error("journal record encoding failed: {0}")]
    Encoding(String),
    /// An annotation was appended with an empty `kind`. The `kind` is the
    /// writer's namespace tag and MUST identify who wrote the annotation, so an
    /// empty one is rejected before it reaches the chain.
    #[error("annotation kind must not be empty")]
    EmptyAnnotationKind,
    /// An annotation's `data` was not a JSON object. The format promises an
    /// object (a null, array, or scalar would let writers smuggle a bare value
    /// past the contract), so a non-object is rejected before it reaches the
    /// chain.
    #[error("annotation data must be a JSON object")]
    AnnotationDataNotObject,
}

/// Append-only storage backing a [`Journal`].
///
/// The core works only with record lines (no newline framing of its own): a
/// native caller backs this with a file, the browser cabinet with its own
/// persistence. Implementations MUST persist an appended line before returning
/// `Ok`, and MUST return the lines from [`read_lines`](JournalStorage::read_lines)
/// in append order.
pub trait JournalStorage {
    /// Appends one record line. The line contains no trailing newline; the
    /// storage owns line framing.
    ///
    /// # Errors
    ///
    /// [`JournalError::Storage`] if the line could not be durably appended.
    fn append(&mut self, line: &str) -> Result<(), JournalError>;

    /// Reads every record line, in append order.
    ///
    /// # Errors
    ///
    /// [`JournalError::Storage`] if the records could not be read.
    fn read_lines(&self) -> Result<Vec<String>, JournalError>;
}

/// One journal line: chain metadata plus an operation payload.
///
/// The payload is flattened, so a line is a single flat JSON object whose `op`
/// field selects the operation, e.g.
/// `{"seq":0,"prev_hash":"…","ts":1,"op":"issue_leaf","serial":"2a",…}`.
///
/// `Eq` is not derived: the `annotation` payload carries an arbitrary
/// [`serde_json::Value`], which is only `PartialEq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Entry {
    /// Monotonic position, from 0, incremented for every line (head signatures
    /// included).
    seq: u64,
    /// Lowercase hex SHA-256 of the previous line's bytes; the genesis anchor
    /// for `seq == 0`.
    prev_hash: String,
    /// Caller-supplied issuance time, Unix seconds.
    ts: u64,
    /// The operation this line records.
    #[serde(flatten)]
    payload: Payload,
}

/// The operation a journal line records, tagged by its `op` field. No secret,
/// PIN, or key material ever appears here.
///
/// `Eq` is not derived because [`Payload::Annotation`] holds an arbitrary
/// [`serde_json::Value`], which implements only `PartialEq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op")]
enum Payload {
    /// A self-signed fleet-root issuance (issuer == subject).
    #[serde(rename = "issue_root")]
    IssueRoot {
        /// Lowercase hex of the serial's DER `INTEGER` content octets.
        serial: String,
        /// Lowercase hex SHA-256 fingerprint of the root's own certificate.
        parent: String,
        /// The root's subject (RFC 4514).
        subject: String,
    },
    /// A shift-leaf issuance.
    #[serde(rename = "issue_leaf")]
    IssueLeaf {
        /// Lowercase hex of the serial's DER `INTEGER` content octets.
        serial: String,
        /// Lowercase hex SHA-256 fingerprint of the parent (issuer) certificate.
        parent: String,
        /// The issued certificate's subject (RFC 4514).
        subject: String,
    },
    /// An organisation-CA issuance.
    #[serde(rename = "issue_ca")]
    IssueCa {
        /// Lowercase hex of the serial's DER `INTEGER` content octets.
        serial: String,
        /// Lowercase hex SHA-256 fingerprint of the parent (issuer) certificate.
        parent: String,
        /// The issued certificate's subject (RFC 4514).
        subject: String,
    },
    /// A CRL issuance.
    #[serde(rename = "issue_crl")]
    IssueCrl {
        /// The `crlNumber` carried by the CRL.
        crl_number: u64,
        /// Lowercase hex SHA-256 fingerprint of the issuing CA certificate.
        parent: String,
    },
    /// A signature over the chain head, recorded as its own line.
    #[serde(rename = "head_signature")]
    HeadSignature {
        /// The signing algorithm label.
        algorithm: String,
        /// Base64 of the raw signature over the covered head's 32-byte hash.
        signature: String,
    },
    /// A general-purpose annotation. The core chains and verifies it like any
    /// other line but never interprets `kind` or `data`.
    #[serde(rename = "annotation")]
    Annotation {
        /// The writer's namespace tag. Non-empty; opaque to the core.
        kind: String,
        /// An arbitrary JSON object of writer-defined context. Opaque to the
        /// core, which neither reads nor validates its contents.
        data: serde_json::Value,
    },
}

/// SHA-256 of `bytes` as a 32-byte array.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// The anchor a fresh chain's first `prev_hash` points at.
fn genesis_hash() -> [u8; 32] {
    sha256(GENESIS_PREIMAGE)
}

/// The stable label recorded for a signing algorithm.
fn algorithm_label(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::EcdsaWithSha256 => "ecdsa-sha256",
        SignatureAlgorithm::EcdsaWithSha384 => "ecdsa-sha384",
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::RsaPkcs1Sha256 => "rsa-pkcs1-sha256",
    }
}

/// An append-only, hash-chained issuance journal over a [`JournalStorage`].
///
/// [`Journal::load`] resumes an existing chain (or starts an empty one); the
/// `record_*` methods append an issuance line and the artifact is only returned
/// once that append succeeds. In-memory state (`next_seq`, `head`) advances only
/// after a durable append, so a storage failure leaves the journal unchanged.
#[derive(Debug)]
pub struct Journal<S: JournalStorage> {
    storage: S,
    next_seq: u64,
    head: [u8; 32],
}

impl<S: JournalStorage> Journal<S> {
    /// Opens the journal over `storage`, resuming from its current tail.
    ///
    /// New lines chain from the physical last line; if a stored line was
    /// tampered with, the break is reported by [`Journal::verify`] rather than
    /// here — `load` only positions the append point.
    ///
    /// # Errors
    ///
    /// [`JournalError::Storage`] if the existing records cannot be read.
    pub fn load(storage: S) -> Result<Self, JournalError> {
        let lines = storage.read_lines()?;
        let next_seq = lines.len() as u64;
        let head = lines
            .last()
            .map_or_else(genesis_hash, |line| sha256(line.as_bytes()));
        Ok(Self {
            storage,
            next_seq,
            head,
        })
    }

    /// The current chain head — the SHA-256 of the last appended line, or the
    /// genesis anchor for an empty journal. This is the value a head signature
    /// covers.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// The seq the next appended line will carry.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Borrows the backing storage (for reading lines out for verification).
    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Records a shift-leaf issuance.
    ///
    /// # Errors
    ///
    /// [`JournalError`] if the line cannot be encoded or durably appended.
    pub fn record_leaf(
        &mut self,
        serial: &[u8],
        parent_cert_der: &[u8],
        subject: &str,
        now_unix: u64,
    ) -> Result<(), JournalError> {
        self.append(
            Payload::IssueLeaf {
                serial: hex::encode(serial),
                parent: fingerprint(parent_cert_der),
                subject: subject.to_owned(),
            },
            now_unix,
        )
    }

    /// Records a self-signed fleet-root issuance.
    ///
    /// The root is its own parent, so `root_cert_der` is the root's own
    /// certificate (its fingerprint is recorded as the `parent`).
    ///
    /// # Errors
    ///
    /// [`JournalError`] if the line cannot be encoded or durably appended.
    pub fn record_root(
        &mut self,
        serial: &[u8],
        root_cert_der: &[u8],
        subject: &str,
        now_unix: u64,
    ) -> Result<(), JournalError> {
        self.append(
            Payload::IssueRoot {
                serial: hex::encode(serial),
                parent: fingerprint(root_cert_der),
                subject: subject.to_owned(),
            },
            now_unix,
        )
    }

    /// Records an organisation-CA issuance.
    ///
    /// # Errors
    ///
    /// [`JournalError`] if the line cannot be encoded or durably appended.
    pub fn record_ca(
        &mut self,
        serial: &[u8],
        parent_cert_der: &[u8],
        subject: &str,
        now_unix: u64,
    ) -> Result<(), JournalError> {
        self.append(
            Payload::IssueCa {
                serial: hex::encode(serial),
                parent: fingerprint(parent_cert_der),
                subject: subject.to_owned(),
            },
            now_unix,
        )
    }

    /// Records a CRL issuance.
    ///
    /// # Errors
    ///
    /// [`JournalError`] if the line cannot be encoded or durably appended.
    pub fn record_crl(
        &mut self,
        crl_number: u64,
        issuer_cert_der: &[u8],
        now_unix: u64,
    ) -> Result<(), JournalError> {
        self.append(
            Payload::IssueCrl {
                crl_number,
                parent: fingerprint(issuer_cert_der),
            },
            now_unix,
        )
    }

    /// Signs the current chain head through `backend` and records the signature
    /// as its own line.
    ///
    /// The bytes signed are the head's 32-byte SHA-256 (the value
    /// [`Journal::head`] returns before this call). Subsequent records chain on
    /// as usual; verification then reports the tail as signed up to this point.
    ///
    /// # Errors
    ///
    /// [`IssueError::Sign`] or [`IssueError::AlgorithmMismatch`] from the
    /// backend, or [`IssueError::Journal`] if the signature line cannot be
    /// appended.
    pub fn sign_head<B: SignatureBackend>(
        &mut self,
        backend: &B,
        key_id: &KeyId,
        now_unix: u64,
    ) -> Result<(), IssueError> {
        let algorithm = backend.algorithm(key_id)?;
        let signature = backend.sign(&self.head, key_id)?;
        if signature.algorithm != algorithm {
            return Err(IssueError::AlgorithmMismatch {
                declared: algorithm,
                returned: signature.algorithm,
            });
        }
        self.append(
            Payload::HeadSignature {
                algorithm: algorithm_label(algorithm).to_owned(),
                signature: base64::engine::general_purpose::STANDARD.encode(&signature.bytes),
            },
            now_unix,
        )?;
        Ok(())
    }

    /// Records a general-purpose annotation on the chain.
    ///
    /// `kind` is the writer's namespace tag (e.g. `"acme.review"`); it must be
    /// non-empty. `data` is a JSON object of writer-defined context; a non-object
    /// (null, array, or scalar) is refused so the format's object promise holds.
    /// The core stores both opaquely — it never interprets `kind` or `data` —
    /// and chains the annotation like any other line, so a later
    /// [`verify_lines`] covers it in the hash chain and the head-signature
    /// accounting without needing to understand it.
    ///
    /// # Errors
    ///
    /// [`JournalError::EmptyAnnotationKind`] if `kind` is empty, or
    /// [`JournalError::AnnotationDataNotObject`] if `data` is not a JSON object;
    /// otherwise [`JournalError::Encoding`] or [`JournalError::Storage`] if the
    /// line cannot be encoded or durably appended (fail-closed: on any error the
    /// chain state is left untouched).
    pub fn append_annotation(
        &mut self,
        kind: &str,
        data: serde_json::Value,
        now_unix: u64,
    ) -> Result<(), JournalError> {
        if kind.is_empty() {
            return Err(JournalError::EmptyAnnotationKind);
        }
        if !data.is_object() {
            return Err(JournalError::AnnotationDataNotObject);
        }
        self.append(
            Payload::Annotation {
                kind: kind.to_owned(),
                data,
            },
            now_unix,
        )
    }

    /// Verifies the chain from the journal's own storage.
    ///
    /// # Errors
    ///
    /// [`JournalError::Storage`] if the records cannot be read.
    pub fn verify(&self) -> Result<JournalReport, JournalError> {
        Ok(verify_lines(&self.storage.read_lines()?))
    }

    /// Encodes and appends one entry, advancing chain state only on success.
    fn append(&mut self, payload: Payload, now_unix: u64) -> Result<(), JournalError> {
        let entry = Entry {
            seq: self.next_seq,
            prev_hash: hex::encode(self.head),
            ts: now_unix,
            payload,
        };
        let line =
            serde_json::to_string(&entry).map_err(|e| JournalError::Encoding(e.to_string()))?;
        // Fail-closed: if the append errors, `head`/`next_seq` are left untouched
        // and no artifact is released by the caller.
        self.storage.append(&line)?;
        self.head = sha256(line.as_bytes());
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(())
    }
}

/// The lowercase hex SHA-256 fingerprint of a certificate's DER.
fn fingerprint(cert_der: &[u8]) -> String {
    hex::encode(sha256(cert_der))
}

/// The outcome of verifying a journal's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JournalStatus {
    /// The chain is intact and every record is covered by a later head
    /// signature (no unsigned tail).
    Intact,
    /// The chain is intact, but records after the last head signature (or all
    /// records, if none is signed) are not yet covered by a signature.
    IntactUnsignedTail {
        /// The `seq` of the first record in the unsigned tail.
        unsigned_from_seq: u64,
    },
    /// The chain is broken: the entry at `position` (its index / expected
    /// `seq`) is missing, reordered, or altered.
    Broken {
        /// Zero-based position of the first invalid entry.
        position: u64,
    },
}

/// A verification result: the [`JournalStatus`] plus summary counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalReport {
    /// The chain status.
    pub status: JournalStatus,
    /// The number of lines examined.
    pub entry_count: u64,
    /// The `seq` of the last head-signature line, if any.
    pub last_signed_seq: Option<u64>,
}

/// Verifies a journal's `lines` (in append order): recomputes the hash chain
/// from genesis, checks `seq` is dense and monotonic from 0, and classifies the
/// tail as signed or not.
///
/// On the first altered, reordered, or malformed line it returns
/// [`JournalStatus::Broken`] with that position. The cryptographic validity of
/// a head signature is not checked here (it needs the CA public key); a signed
/// tail means only that a `head_signature` line structurally covers it.
///
/// Annotation lines are checked structurally too — valid JSON, a non-empty
/// `kind`, an object `data`, correct chaining — without the verifier knowing any
/// `kind`: an unknown `kind` passes, an empty `kind` or a non-object `data` is
/// [`JournalStatus::Broken`]. An annotation counts as an unsigned-tail record
/// exactly like an issuance line.
#[must_use]
pub fn verify_lines(lines: &[String]) -> JournalReport {
    let mut expected_prev = genesis_hash();
    let mut last_signed_seq: Option<u64> = None;
    let mut unsigned_from: Option<u64> = None;

    for (index, line) in lines.iter().enumerate() {
        let position = index as u64;
        let broken = |last_signed_seq| JournalReport {
            status: JournalStatus::Broken { position },
            entry_count: lines.len() as u64,
            last_signed_seq,
        };

        let Ok(entry) = serde_json::from_str::<Entry>(line) else {
            return broken(last_signed_seq);
        };
        if entry.seq != position {
            return broken(last_signed_seq);
        }
        let Some(prev) = decode_hash(&entry.prev_hash) else {
            return broken(last_signed_seq);
        };
        if prev != expected_prev {
            return broken(last_signed_seq);
        }

        match &entry.payload {
            Payload::HeadSignature { .. } => {
                last_signed_seq = Some(entry.seq);
                unsigned_from = None;
            }
            // An annotation is structurally invalid without a namespace tag or
            // with a non-object `data`; a hand-crafted empty `kind` or a bare
            // value breaks the chain at this position even though its JSON
            // parses. The core still reads neither `kind`'s value (beyond
            // non-emptiness) nor `data`'s contents (beyond being an object).
            Payload::Annotation { kind, data } if kind.is_empty() || !data.is_object() => {
                return broken(last_signed_seq);
            }
            _ => {
                if unsigned_from.is_none() {
                    unsigned_from = Some(entry.seq);
                }
            }
        }
        expected_prev = sha256(line.as_bytes());
    }

    let status = match unsigned_from {
        Some(seq) => JournalStatus::IntactUnsignedTail {
            unsigned_from_seq: seq,
        },
        None => JournalStatus::Intact,
    };
    JournalReport {
        status,
        entry_count: lines.len() as u64,
        last_signed_seq,
    }
}

/// Decodes a lowercase-hex 32-byte hash, returning `None` on any malformed input.
fn decode_hash(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// In-memory and file storage backends, plus a failure-injecting storage for
/// the fail-closed tests. Available under `test-support` (and this crate's own
/// tests); the file backend is native-only.
#[cfg(any(test, feature = "test-support"))]
pub mod storage {
    use std::cell::RefCell;

    use super::{JournalError, JournalStorage};

    /// A `Vec`-backed storage for tests and the wasm/browser core.
    #[derive(Debug, Default, Clone)]
    pub struct MemoryStorage {
        lines: RefCell<Vec<String>>,
    }

    impl MemoryStorage {
        /// An empty in-memory journal store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// The currently stored lines.
        #[must_use]
        pub fn lines(&self) -> Vec<String> {
            self.lines.borrow().clone()
        }
    }

    impl JournalStorage for MemoryStorage {
        fn append(&mut self, line: &str) -> Result<(), JournalError> {
            self.lines.borrow_mut().push(line.to_owned());
            Ok(())
        }

        fn read_lines(&self) -> Result<Vec<String>, JournalError> {
            Ok(self.lines.borrow().clone())
        }
    }

    /// A storage whose `append` always fails, to drive the fail-closed path
    /// (an issuance whose journal write fails must not return an artifact).
    #[derive(Debug, Default, Clone)]
    pub struct FailingStorage;

    impl JournalStorage for FailingStorage {
        fn append(&mut self, _line: &str) -> Result<(), JournalError> {
            Err(JournalError::Storage("append disabled for test".to_owned()))
        }

        fn read_lines(&self) -> Result<Vec<String>, JournalError> {
            Ok(Vec::new())
        }
    }
}

/// A file-backed journal storage: one NDJSON line per record.
///
/// Appends are opened `create(true).append(true)`; reads split the file on
/// newlines and drop the trailing empty segment. Native only — the wasm core
/// receives a host-supplied [`JournalStorage`] instead.
#[cfg(feature = "native")]
#[derive(Debug, Clone)]
pub struct FileStorage {
    path: std::path::PathBuf,
}

#[cfg(feature = "native")]
impl FileStorage {
    /// A file store at `path` (created on first append).
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(feature = "native")]
impl JournalStorage for FileStorage {
    fn append(&mut self, line: &str) -> Result<(), JournalError> {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| JournalError::Storage(e.to_string()))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|e| JournalError::Storage(e.to_string()))
    }

    fn read_lines(&self) -> Result<Vec<String>, JournalError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(text.lines().map(str::to_owned).collect()),
            // A never-written journal has no lines yet.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(JournalError::Storage(e.to_string())),
        }
    }
}

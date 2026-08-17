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
//! The framing, the head-signature accounting and the verification are not
//! written here: they live in `tessera_hashchain` and are shared with the
//! device's audit chain, so the two records cannot drift into two dialects of
//! the same format. What stays here is the vocabulary — the issuance operations
//! a line can record — and the genesis anchor that keeps a line of this journal
//! from verifying inside another.
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
use tessera_hashchain::{Annotation, Chain, ChainPayload, EntryKind, HeadSignature};

use crate::error::IssueError;
use crate::sign::{KeyId, SignatureAlgorithm, SignatureBackend};

/// The fixed domain-separation preimage whose SHA-256 anchors an empty chain.
///
/// Declared with the format it identifies, in [`tessera_hashchain::domain`].
/// The bytes are unchanged and must stay so: they are in every issuance journal
/// ever written.
use tessera_hashchain::domain::ISSUANCE_JOURNAL as GENESIS_PREIMAGE;

/// Errors from journal storage or record encoding.
///
/// These are fail-closed at the issuance boundary: an issuance that cannot be
/// journaled does not return an artifact (see [`IssueError::Journal`]).
pub use tessera_hashchain::ChainError as JournalError;

/// Append-only storage backing a [`Journal`].
///
/// The core works only with record lines (no newline framing of its own): a
/// native caller backs this with a file, the browser cabinet with its own
/// persistence. Implementations MUST persist an appended line before returning
/// `Ok`, and MUST return the lines from `read_lines` in append order.
pub use tessera_hashchain::ChainStorage as JournalStorage;

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
        /// Where the certified key pair came from.
        #[serde(default, skip_serializing_if = "KeyOrigin::is_requester")]
        key_origin: KeyOrigin,
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
    /// A signature over the chain head, recorded as its own line. Its fields
    /// are the shared ones, so this journal and the device's audit chain spell
    /// a head signature identically.
    #[serde(rename = "head_signature")]
    HeadSignature(HeadSignature),
    /// A general-purpose annotation. The core chains and verifies it like any
    /// other line but never interprets `kind` or `data`.
    #[serde(rename = "annotation")]
    Annotation(Annotation),
}

impl ChainPayload for Payload {
    const GENESIS_PREIMAGE: &'static [u8] = GENESIS_PREIMAGE;

    fn kind(&self) -> EntryKind {
        match self {
            Payload::HeadSignature { .. } => EntryKind::HeadSignature,
            _ => EntryKind::Record,
        }
    }

    /// An annotation is structurally invalid without a namespace tag or with a
    /// non-object `data`; a hand-crafted empty `kind` or a bare value breaks the
    /// chain at this position even though its JSON parses. The core still reads
    /// neither `kind`'s value (beyond non-emptiness) nor `data`'s contents
    /// (beyond being an object).
    fn is_structurally_valid(&self) -> bool {
        match self {
            Payload::Annotation(annotation) => annotation.is_structurally_valid(),
            _ => true,
        }
    }
}

/// Where the key pair a leaf certifies came from.
///
/// The distinction is not bookkeeping: when the issuer generated the pair, the
/// private key is known to two parties and nothing signed with it can be
/// attributed to the holder alone. An inventory that cannot separate the two
/// cannot answer which issued credentials have that property — the first
/// question an assessor or an incident review asks.
///
/// `Requester` is the default so the many lines written before this field
/// existed read back as what they were: issuances where the key came from the
/// engineer. For the same reason a `Requester` line does not carry the field at
/// all, leaving those lines byte-identical to the ones already in the chain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KeyOrigin {
    /// The key came from the requester: an explicit public key, or a
    /// certificate request they signed.
    #[default]
    Requester,
    /// The issuing tool generated the key pair.
    Issuer,
}

impl KeyOrigin {
    /// Whether this is the default origin (used to keep it off the wire).
    ///
    /// Takes a reference because that is the shape `skip_serializing_if` calls.
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's skip_serializing_if is handed a reference to the field"
    )]
    fn is_requester(&self) -> bool {
        matches!(self, KeyOrigin::Requester)
    }
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
    chain: Chain<S, Payload>,
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
        Ok(Self {
            chain: Chain::load(storage)?,
        })
    }

    /// The current chain head — the SHA-256 of the last appended line, or the
    /// genesis anchor for an empty journal. This is the value a head signature
    /// covers.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.chain.head()
    }

    /// The seq the next appended line will carry.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.chain.next_seq()
    }

    /// Borrows the backing storage (for reading lines out for verification).
    #[must_use]
    pub fn storage(&self) -> &S {
        self.chain.storage()
    }

    /// Records a shift-leaf issuance, noting where the certified key came from.
    ///
    /// # Errors
    ///
    /// [`JournalError`] if the line cannot be encoded or durably appended.
    pub fn record_leaf(
        &mut self,
        serial: &[u8],
        parent_cert_der: &[u8],
        subject: &str,
        key_origin: KeyOrigin,
        now_unix: u64,
    ) -> Result<(), JournalError> {
        self.append(
            &Payload::IssueLeaf {
                serial: hex::encode(serial),
                parent: fingerprint(parent_cert_der),
                subject: subject.to_owned(),
                key_origin,
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
            &Payload::IssueRoot {
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
            &Payload::IssueCa {
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
            &Payload::IssueCrl {
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
        let signature = backend.sign(&self.chain.head(), key_id)?;
        if signature.algorithm != algorithm {
            return Err(IssueError::AlgorithmMismatch {
                declared: algorithm,
                returned: signature.algorithm,
            });
        }
        self.append(
            &Payload::HeadSignature(HeadSignature {
                algorithm: algorithm_label(algorithm).to_owned(),
                signature: base64::engine::general_purpose::STANDARD.encode(&signature.bytes),
            }),
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
            &Payload::Annotation(Annotation {
                kind: kind.to_owned(),
                data,
            }),
            now_unix,
        )
    }

    /// Verifies the chain from the journal's own storage.
    ///
    /// # Errors
    ///
    /// [`JournalError::Storage`] if the records cannot be read.
    pub fn verify(&self) -> Result<JournalReport, JournalError> {
        self.chain.verify()
    }

    /// Encodes and appends one entry, advancing chain state only on success.
    fn append(&mut self, payload: &Payload, now_unix: u64) -> Result<(), JournalError> {
        self.chain.append(payload, now_unix)
    }
}

/// The lowercase hex SHA-256 fingerprint of a certificate's DER.
fn fingerprint(cert_der: &[u8]) -> String {
    hex::encode(tessera_hashchain::sha256(cert_der))
}

/// The outcome of verifying a journal's chain.
pub use tessera_hashchain::ChainStatus as JournalStatus;

/// A verification result: the [`JournalStatus`] plus summary counters.
pub use tessera_hashchain::ChainReport as JournalReport;

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
    tessera_hashchain::verify_lines::<Payload>(lines)
}

/// In-memory storage plus a failure-injecting one for the fail-closed tests.
///
/// Both come from `tessera_hashchain`, which is where the chain itself lives;
/// they are re-exported here so a caller reaches them through the journal it is
/// testing rather than through a second crate name.
#[cfg(any(test, feature = "test-support"))]
pub mod storage {
    pub use tessera_hashchain::storage::{FailingStorage, MemoryStorage};
}

/// A file-backed journal storage: one NDJSON line per record.
///
/// Native only — the wasm core receives a host-supplied [`JournalStorage`]
/// instead.
#[cfg(feature = "native")]
pub use tessera_hashchain::storage::FileStorage;

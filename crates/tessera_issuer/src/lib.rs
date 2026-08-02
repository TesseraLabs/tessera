//! Certificate-issuance core for Tessera.
//!
//! This crate turns an issuance request into a signed X.509 artifact that the
//! Tessera Engine accepts. It does three things a stack of OpenSSL config files
//! cannot do safely:
//!
//! 1. **Builds exactly what the Engine parses.** The project's custom extensions
//!    (host/user binding, allowed roles, the delegation envelope, the integrity
//!    ceiling, the profile version) are encoded through [`tessera_ext`] — the
//!    same crate the Engine decodes them with — so the wire format has one
//!    definition, not two.
//! 2. **Refuses to widen a delegation envelope.** Before anything is signed, a
//!    CA request is checked to narrow-or-equal its parent's envelope, and a leaf
//!    request is checked to stay inside the parent CA's roles, integrity ceiling
//!    and TTL. A widening request is rejected with the exact dimension named.
//! 3. **Self-checks the finished artifact.** After signing, the certificate is
//!    re-parsed with the shared code and re-validated; an artifact the parsers
//!    would reject is never returned.
//!
//! The core is synchronous and free of `tokio`, OpenSSL and PKCS#11: it builds
//! for `wasm32-unknown-unknown` (with `--no-default-features`) so the same code
//! can back a browser issuer cabinet. Signing is abstracted behind
//! [`SignatureBackend`]; key material never crosses that boundary.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "test-support")] {
//! use tessera_issuer::{issue_leaf, Journal, LeafRequest, Validity, Serial};
//! use tessera_issuer::sign::{KeyId, MockSigner, SignatureAlgorithm};
//! use tessera_issuer::test_support::{self_signed_ca, spki_fixture, MemoryStorage};
//! use tessera_issuer::{CaRequest};
//! use tessera_ext::delegation::DelegationConstraints;
//!
//! let key = KeyId::new("ca-key");
//! let signer = MockSigner::ecdsa_sha256(key.clone());
//! let spki = spki_fixture();
//! // Every issuance is journaled; here into an in-memory store.
//! let mut journal = Journal::load(MemoryStorage::new()).unwrap();
//! let now = 1_600_000_000;
//!
//! // Mint a root/org CA that allows the `oper` role up to integrity level 5.
//! let ca_req = CaRequest {
//!     subject: "CN=Org CA".to_owned(),
//!     subject_spki_der: spki.clone(),
//!     validity: Validity { not_before: 1_600_000_000, not_after: 1_900_000_000 },
//!     constraints: DelegationConstraints {
//!         require_tags: vec![],
//!         allow_roles: vec!["oper".to_owned()],
//!         max_level: 5,
//!         max_ttl: 86_400,
//!     },
//!     profile_version: 1,
//! };
//! let ca = self_signed_ca(&signer, &key, &ca_req, &Serial::generate(), &mut journal, now).unwrap();
//!
//! // Issue a leaf under it. Login happens *into a role account* named for the
//! // role (`oper@host`), so `allowed_roles` names both the roles the holder may
//! // activate and the accounts they may log into — not a person; the engineer's
//! // identity lives in the subject CN and the journal.
//! let leaf_req = LeafRequest {
//!     subject: "CN=ivanov".to_owned(),
//!     subject_spki_der: spki,
//!     validity: Validity { not_before: 1_600_000_000, not_after: 1_600_003_600 },
//!     host_binding: vec!["*".to_owned()],
//!     allowed_roles: vec!["oper".to_owned()],
//!     max_integrity: None,
//!     profile_version: 1,
//! };
//! let leaf = issue_leaf(&signer, &key, &ca.der, &leaf_req, &Serial::generate(), &mut journal, now).unwrap();
//! assert!(!leaf.der.is_empty());
//! # }
//! ```

pub mod crl;
pub mod csr;
mod error;
pub mod journal;
pub mod keygen;
pub mod l10n;
pub mod monotonicity;
pub mod pkcs12;
mod profile;
pub mod serial;
// The owner-only gate shared by the file backend's key file and the CLI's
// `--pin-file` / `--key-passphrase-file` / `--p12-passphrase-file` sources.
// Compiled only where one of those readers exists, so no other build carries an
// unused check.
#[cfg(any(feature = "file", feature = "cli"))]
mod secret_file;
pub mod sign;
pub mod summary;
mod tbs;
mod verify;

// The command-line surface, built only for the `issuer` binary. Its handlers
// wrap the same core the cabinet uses (no re-implemented checks), so it lives in
// the library where it can be unit-tested without spawning a process.
#[cfg(feature = "cli")]
pub mod cli;

// Laying issued artifacts out on a carrier: filesystem paths the device's check
// looks at. Native-only (it touches the filesystem), so the wasm core, which
// hands its container to the browser rather than to a mount point, pulls none of
// it.
#[cfg(feature = "native")]
pub mod carrier;

// The operator-confirmation channel: a generic surface a signing frontend uses
// to show a parsed TBS and gate the operation on an explicit yes. Native-only
// (it drives a pinentry subprocess / the terminal), so the wasm core pulls none
// of it; it does not depend on any signing backend.
#[cfg(feature = "native")]
pub mod confirm;

// Native-only signing adapters, each behind its feature flag so the wasm core
// (built with `--no-default-features`) pulls none of them.
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "vault")]
pub mod vault;

#[cfg(test)]
mod tests;

pub use crl::{issue_crl, CrlReason, CrlRequest, IssuedCrl, RevokedEntry};
pub use csr::{
    issue_leaf_from_csr, Csr, CsrContents, LeafRequestFromCsr, LeafScope, RequestedExtension,
};
pub use error::IssueError;
pub use journal::{
    verify_lines, Journal, JournalError, JournalReport, JournalStatus, JournalStorage, KeyOrigin,
};
pub use keygen::{generate_key_pair, Entropy, GeneratedKeyPair, LeafKeyType};
pub use l10n::Locale;
pub use profile::{CaRequest, IntegrityCeiling, LeafRequest, RootRequest, Validity};
pub use serial::Serial;
pub use sign::{KeyId, SignError, Signature, SignatureAlgorithm, SignatureBackend};
pub use summary::{
    parse_operation_summary, OperationKind, OperationSummary, SummaryError, SummaryLine,
};

use monotonicity::{check_ca_within_parent, check_leaf_within_parent, parent_constraints};
use tessera_ext::ext::extract_subject_der;

/// A signed certificate and its serial number.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// The DER-encoded `Certificate`.
    pub der: Vec<u8>,
    /// The serial's DER `INTEGER` content octets.
    pub serial: Vec<u8>,
}

/// Assembles a `Certificate` from a TBS that was signed out of band.
///
/// The browser cabinet builds a `TBSCertificate` in its WASM core, hands it to
/// the local signing agent, and receives back only a signature. This frames the
/// final `Certificate` from the exact TBS bytes that were signed and the
/// returned signature. The outer `signatureAlgorithm` is `algorithm`; the caller
/// MUST ensure it equals the `signature` `AlgorithmIdentifier` already inside the
/// TBS, or the certificate is internally inconsistent.
///
/// This is the assembly half of split signing; the build and self-check halves
/// stay with the caller (the cabinet re-parses the assembled certificate with
/// the shared parsers before releasing it).
///
/// # Errors
///
/// [`IssueError::Encoding`] if the signature `AlgorithmIdentifier` cannot be
/// encoded.
pub fn assemble_signed_certificate(
    tbs_der: &[u8],
    algorithm: SignatureAlgorithm,
    signature_bytes: &[u8],
) -> Result<Vec<u8>, IssueError> {
    let algid_der = tbs::algorithm_identifier_der(algorithm)?;
    Ok(tbs::assemble_certificate(
        tbs_der,
        &algid_der,
        signature_bytes,
    ))
}

/// Validates that a validity window is non-empty and correctly ordered.
fn check_validity(validity: Validity) -> Result<(), IssueError> {
    if validity.not_after <= validity.not_before {
        return Err(IssueError::InvalidValidity {
            not_before: validity.not_before,
            not_after: validity.not_after,
        });
    }
    Ok(())
}

/// The DER-encoded pieces of a certificate, ready to frame into a TBS.
struct CertParts<'a> {
    issuer_der: &'a [u8],
    subject_der: &'a [u8],
    validity_der: &'a [u8],
    spki_der: &'a [u8],
    extensions_body: &'a [u8],
    serial: &'a Serial,
}

/// Assembles a signed certificate from encoded components: builds the TBS,
/// signs it, checks the returned algorithm, and assembles the certificate.
fn sign_and_assemble<B: SignatureBackend>(
    backend: &B,
    key_id: &KeyId,
    parts: &CertParts<'_>,
) -> Result<Vec<u8>, IssueError> {
    let algorithm = backend.algorithm(key_id)?;
    let algid_der = tbs::algorithm_identifier_der(algorithm)?;
    let tbs_der = tbs::assemble_tbs(
        parts.serial,
        &algid_der,
        parts.issuer_der,
        parts.validity_der,
        parts.subject_der,
        parts.spki_der,
        parts.extensions_body,
    );
    let signature = backend.sign(&tbs_der, key_id)?;
    if signature.algorithm != algorithm {
        return Err(IssueError::AlgorithmMismatch {
            declared: algorithm,
            returned: signature.algorithm,
        });
    }
    Ok(tbs::assemble_certificate(
        &tbs_der,
        &algid_der,
        &signature.bytes,
    ))
}

/// Issues an engineer shift-leaf under the parent CA in `parent_der`.
///
/// The request's `host_binding` must be non-empty, the
/// validity must be well-ordered, and the leaf scope must stay inside the parent
/// CA's delegation envelope (`allowed_roles`, `max_integrity` level, and
/// validity duration). The finished certificate is self-checked before it is
/// returned.
///
/// The issuance is journaled before the artifact is returned: the entry is
/// appended to `journal` (timestamped `now_unix`, Unix seconds) and, if that
/// append fails, the certificate is withheld and [`IssueError::Journal`] is
/// returned (fail-closed).
///
/// # Errors
///
/// A typed [`IssueError`]: a missing mandatory field, a widened scope naming the
/// dimension, a parent CA with no envelope, a signing failure, a self-check
/// rejection, or a journal-append failure.
#[expect(
    clippy::too_many_arguments,
    reason = "issuance threads the signer, key, parent, request, serial, and a \
              journaling target and clock; each is a distinct required input and \
              grouping them would obscure the call"
)]
pub fn issue_leaf<B: SignatureBackend, S: JournalStorage>(
    backend: &B,
    key_id: &KeyId,
    parent_der: &[u8],
    req: &LeafRequest,
    serial: &Serial,
    journal: &mut Journal<S>,
    now_unix: u64,
) -> Result<IssuedCert, IssueError> {
    issue_leaf_recording_origin(
        backend,
        key_id,
        parent_der,
        req,
        serial,
        journal,
        KeyOrigin::Requester,
        now_unix,
    )
}

/// [`issue_leaf`], with the journal's record of where the key came from made
/// explicit.
///
/// The checks, the signing and the self-check are identical for every key
/// source — only the journal line differs — so all three entry points share this
/// body rather than each running its own copy of the issuance path.
#[expect(
    clippy::too_many_arguments,
    reason = "the shared issuance body threads every input of the public entry \
              points plus the journal's key-origin marker"
)]
pub(crate) fn issue_leaf_recording_origin<B: SignatureBackend, S: JournalStorage>(
    backend: &B,
    key_id: &KeyId,
    parent_der: &[u8],
    req: &LeafRequest,
    serial: &Serial,
    journal: &mut Journal<S>,
    key_origin: KeyOrigin,
    now_unix: u64,
) -> Result<IssuedCert, IssueError> {
    if req.host_binding.is_empty() {
        return Err(IssueError::MissingHostBinding);
    }
    check_validity(req.validity)?;

    let parent = parent_constraints(parent_der)?.ok_or(IssueError::ParentEnvelopeMissing)?;
    check_leaf_within_parent(req, &parent)?;

    let issuer_der = extract_subject_der(parent_der)?;
    let subject_der = tbs::subject_name_der(&req.subject)?;
    let validity_der = tbs::validity_der(&req.validity)?;
    let spki_der = tbs::validated_spki_der(&req.subject_spki_der)?;
    let extensions_body = tbs::leaf_extensions(req)?;

    let cert = sign_and_assemble(
        backend,
        key_id,
        &CertParts {
            issuer_der: &issuer_der,
            subject_der: &subject_der,
            validity_der: &validity_der,
            spki_der: &spki_der,
            extensions_body: &extensions_body,
            serial,
        },
    )?;

    verify::self_check_leaf(&cert, req, &parent)?;
    // Journal before releasing the artifact; a failed write withholds it.
    journal.record_leaf(
        serial.as_bytes(),
        parent_der,
        &req.subject,
        key_origin,
        now_unix,
    )?;
    Ok(IssuedCert {
        der: cert,
        serial: serial.as_bytes().to_vec(),
    })
}

/// A leaf issuance in which the tool generates the key pair.
///
/// The scope is the operator's, exactly as for every other key source; what the
/// requester contributes here is nothing at all, which is the point of the
/// process this supports.
#[derive(Debug, Clone)]
pub struct GeneratedLeafRequest<'a> {
    /// Subject distinguished name (RFC 4514).
    pub subject: String,
    /// The key type to generate.
    pub key_type: keygen::LeafKeyType,
    /// Operator-set scope, identical in meaning to the CSR path's.
    pub scope: LeafScope,
    /// Chain certificates to package beside the leaf (typically the issuing
    /// CA), DER, in order.
    pub chain_der: &'a [Vec<u8>],
}

/// The result of a leaf issuance with a generated key: the certificate, and the
/// container that carries the key.
///
/// The private key is deliberately *not* a field: it exists only inside
/// `container`, and returning it separately would invite a caller to write it
/// somewhere.
pub struct GeneratedLeaf {
    /// The issued certificate.
    pub cert: IssuedCert,
    /// The PKCS#12 container holding the key, the certificate and the chain.
    pub container: zeroize::Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for GeneratedLeaf {
    /// The container holds the private key, so its bytes stay out of any
    /// formatted output.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GeneratedLeaf")
            .field("cert", &self.cert)
            .field("container", &"<redacted>")
            .finish()
    }
}

/// Issues a shift-leaf over a key pair this call generates, and packages it.
///
/// Generation, issuance and packaging are one operation on purpose. Split into
/// two commands, the private key would have to survive between them — that is,
/// on disk — which is exactly what the process is meant to avoid. Here it never
/// leaves memory: it is generated, certified, packaged, and dropped into wiped
/// memory before the call returns.
///
/// The issuance itself runs the same path as every other key source: the same
/// scope checks against the parent envelope, the same signing, the same
/// self-check of the finished certificate. Only the journal line differs — it
/// records that the issuer, not the requester, holds the key.
///
/// `passphrase` protects the container. Callers are responsible for its
/// strength ([`pkcs12::check_passphrase`] enforces the floor on an
/// operator-supplied one) and for holding it in wiped memory.
///
/// # Errors
///
/// Everything [`issue_leaf`] can return, plus [`IssueError::KeyGeneration`]
/// when the key cannot be generated and [`IssueError::Container`] when the
/// container cannot be assembled or does not read back as what went into it.
///
/// A container failure comes *after* the issuance has been journaled: the
/// certificate is genuinely issued at that point, and a journal that omitted it
/// would under-report. No artifact is returned.
#[expect(
    clippy::too_many_arguments,
    reason = "the operation spans issuance and packaging: signer, key, parent, \
              request, container password, serial, journal, entropy and clock \
              are each a distinct required input"
)]
pub fn issue_leaf_generating_key<B: SignatureBackend, S: JournalStorage, E: keygen::Entropy>(
    backend: &B,
    key_id: &KeyId,
    parent_der: &[u8],
    req: &GeneratedLeafRequest<'_>,
    passphrase: &str,
    serial: &Serial,
    journal: &mut Journal<S>,
    entropy: &mut E,
    now_unix: u64,
) -> Result<GeneratedLeaf, IssueError> {
    issue_leaf_generating_key_with(
        backend, key_id, parent_der, req, passphrase, serial, journal, entropy, now_unix, None,
    )
}

/// [`issue_leaf_generating_key`] with the container's key-derivation cost
/// overridable.
///
/// `pbkdf2_iterations` is `None` everywhere but in the crate's own tests, which
/// build containers in bulk and cannot each afford the shipped cost; one test
/// goes through the public entry point and pays it.
#[expect(
    clippy::too_many_arguments,
    reason = "the shared body threads every input of the public entry point plus \
              the test-only derivation cost"
)]
fn issue_leaf_generating_key_with<B: SignatureBackend, S: JournalStorage, E: keygen::Entropy>(
    backend: &B,
    key_id: &KeyId,
    parent_der: &[u8],
    req: &GeneratedLeafRequest<'_>,
    passphrase: &str,
    serial: &Serial,
    journal: &mut Journal<S>,
    entropy: &mut E,
    now_unix: u64,
    pbkdf2_iterations: Option<u32>,
) -> Result<GeneratedLeaf, IssueError> {
    let pair = keygen::generate_key_pair(req.key_type, entropy)?;

    let leaf_req = LeafRequest {
        subject: req.subject.clone(),
        subject_spki_der: pair.spki_der.clone(),
        validity: req.scope.validity,
        host_binding: req.scope.host_binding.clone(),
        allowed_roles: req.scope.allowed_roles.clone(),
        max_integrity: req.scope.max_integrity,
        profile_version: req.scope.profile_version,
    };
    let cert = issue_leaf_recording_origin(
        backend,
        key_id,
        parent_der,
        &leaf_req,
        serial,
        journal,
        KeyOrigin::Issuer,
        now_unix,
    )?;

    let contents = pkcs12::ContainerContents {
        private_key_pkcs8_der: &pair.private_key_pkcs8_der,
        leaf_der: &cert.der,
        chain_der: req.chain_der,
    };
    let container = match pbkdf2_iterations {
        Some(iterations) => {
            pkcs12::build_with_iterations(&contents, passphrase, entropy, iterations)?
        }
        None => pkcs12::build_container(&contents, passphrase, entropy)?,
    };
    Ok(GeneratedLeaf { cert, container })
}

/// Issues an organisation CA under the parent in `parent_der`.
///
/// The assigned delegation envelope must narrow-or-equal the parent's (a parent
/// with no envelope is treated as a root establishing the first envelope). The
/// finished certificate is self-checked before it is returned.
///
/// The issuance is journaled before the artifact is returned: the entry is
/// appended to `journal` (timestamped `now_unix`, Unix seconds) and, if that
/// append fails, the certificate is withheld and [`IssueError::Journal`] is
/// returned (fail-closed).
///
/// # Errors
///
/// A typed [`IssueError`]: an ill-formed validity, a widened envelope naming the
/// dimension, a signing failure, a self-check rejection, or a journal-append
/// failure.
#[expect(
    clippy::too_many_arguments,
    reason = "issuance threads the signer, key, parent, request, serial, and a \
              journaling target and clock; each is a distinct required input and \
              grouping them would obscure the call"
)]
pub fn issue_ca<B: SignatureBackend, S: JournalStorage>(
    backend: &B,
    key_id: &KeyId,
    parent_der: &[u8],
    req: &CaRequest,
    serial: &Serial,
    journal: &mut Journal<S>,
    now_unix: u64,
) -> Result<IssuedCert, IssueError> {
    check_validity(req.validity)?;

    let parent = parent_constraints(parent_der)?;
    check_ca_within_parent(req, parent.as_ref())?;

    let issuer_der = extract_subject_der(parent_der)?;
    let subject_der = tbs::subject_name_der(&req.subject)?;
    let validity_der = tbs::validity_der(&req.validity)?;
    let spki_der = tbs::validated_spki_der(&req.subject_spki_der)?;
    let extensions_body = tbs::ca_extensions(req)?;

    let cert = sign_and_assemble(
        backend,
        key_id,
        &CertParts {
            issuer_der: &issuer_der,
            subject_der: &subject_der,
            validity_der: &validity_der,
            spki_der: &spki_der,
            extensions_body: &extensions_body,
            serial,
        },
    )?;

    verify::self_check_ca(&cert, req, parent.as_ref())?;
    // Journal before releasing the artifact; a failed write withholds it.
    journal.record_ca(serial.as_bytes(), parent_der, &req.subject, now_unix)?;
    Ok(IssuedCert {
        der: cert,
        serial: serial.as_bytes().to_vec(),
    })
}

/// Issues a self-signed fleet root: a CA whose issuer equals its subject,
/// establishing the fleet's first delegation envelope.
///
/// A root has no parent to narrow against, so its envelope is taken as given; it
/// is the bootstrap of the serverless issuance model, which cannot start without
/// one. The certificate is assembled with issuer == subject, self-checked
/// against the shared parsers before it is returned, and journaled (`op` =
/// `issue_root`, with the root's own fingerprint as its parent) before the
/// artifact is released — a failed journal write withholds it (fail-closed).
///
/// # Errors
///
/// A typed [`IssueError`]: an ill-formed validity, an encoding failure, a
/// signing failure, a self-check rejection, or a journal-append failure.
pub fn issue_root<B: SignatureBackend, S: JournalStorage>(
    backend: &B,
    key_id: &KeyId,
    req: &RootRequest,
    serial: &Serial,
    journal: &mut Journal<S>,
    now_unix: u64,
) -> Result<IssuedCert, IssueError> {
    check_validity(req.validity)?;

    let subject_der = tbs::subject_name_der(&req.subject)?;
    let validity_der = tbs::validity_der(&req.validity)?;
    let spki_der = tbs::validated_spki_der(&req.subject_spki_der)?;
    let extensions_body = tbs::ca_extensions(req)?;

    // Self-signed: the subject is also the issuer.
    let cert = sign_and_assemble(
        backend,
        key_id,
        &CertParts {
            issuer_der: &subject_der,
            subject_der: &subject_der,
            validity_der: &validity_der,
            spki_der: &spki_der,
            extensions_body: &extensions_body,
            serial,
        },
    )?;

    verify::self_check_ca(&cert, req, None)?;
    // Journal before releasing the artifact; the root is its own parent.
    journal.record_root(serial.as_bytes(), &cert, &req.subject, now_unix)?;
    Ok(IssuedCert {
        der: cert,
        serial: serial.as_bytes().to_vec(),
    })
}

/// Test scaffolding: minting a self-signed root and a fixture public key.
///
/// A fleet root has to be created without a parent; production roots are minted
/// offline, but tests and the contract suite need one in-process. Gated behind
/// the `test-support` feature so it never ships in the wasm/native library.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::{
        CaRequest, IssueError, IssuedCert, Journal, JournalStorage, KeyId, Serial, SignatureBackend,
    };

    pub use super::journal::storage::{FailingStorage, MemoryStorage};

    /// Issues a self-signed CA (issuer == subject): the root of a chain, which
    /// establishes the first delegation envelope and has no parent to narrow.
    ///
    /// A thin wrapper over the product [`crate::issue_root`] (a [`CaRequest`] is
    /// a [`crate::RootRequest`]), kept so the many tests and the contract suite
    /// that mint an in-process root read the same regardless of the underlying
    /// entry point.
    ///
    /// # Errors
    ///
    /// A typed [`IssueError`] on a bad validity, encoding failure, signing
    /// failure, self-check rejection, or journal-append failure.
    pub fn self_signed_ca<B: SignatureBackend, S: JournalStorage>(
        backend: &B,
        key_id: &KeyId,
        req: &CaRequest,
        serial: &Serial,
        journal: &mut Journal<S>,
        now_unix: u64,
    ) -> Result<IssuedCert, IssueError> {
        super::issue_root(backend, key_id, req, serial, journal, now_unix)
    }

    /// A syntactically valid `SubjectPublicKeyInfo` (a fixed P-256 point) for
    /// tests that only need a well-formed key, not a matching private key.
    #[must_use]
    pub fn spki_fixture() -> Vec<u8> {
        // SubjectPublicKeyInfo { ecPublicKey, prime256v1 }, 65-byte uncompressed
        // point — a valid, well-formed generator-derived public key.
        const SPKI: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6b,
            0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
            0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
            0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
            0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb,
            0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        SPKI.to_vec()
    }
}

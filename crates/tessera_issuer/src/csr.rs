//! CSR (PKCS#10) issuance: mint a shift-leaf whose key and subject come from a
//! certificate request the engineer generated on their own token.
//!
//! An engineer keeps their private key on their token and hands the operator a
//! CSR. Before issuing, the core verifies the CSR's self-signature under its
//! own public key — proof the requester holds the matching private key. Only
//! the CSR's **public key and subject** are used: its requested attributes and
//! extensions never shape the issued certificate, or a CSR would become a
//! channel for an engineer to grant themselves a wider scope. The scope
//! (roles, bindings, integrity ceiling, validity) is set entirely by the
//! operator, exactly as for a direct [`crate::issue_leaf`].
//!
//! Parsing and verification are pure Rust (`x509-cert` for PKCS#10, `p256` and
//! `rsa` for the two supported signature algorithms) so the browser cabinet can
//! run the same path in `wasm32`.
//!
//! [`Csr::requested_extensions`] surfaces what a CSR asked for so a UI can
//! prefill and label it as *requested* — the issuance path itself never reads
//! it.

use base64::Engine as _;
use der::{Decode as _, Encode as _};
use sha2::{Digest as _, Sha256};
use x509_cert::request::CertReq;

use crate::error::IssueError;
use crate::journal::{Journal, JournalStorage};
use crate::profile::{IntegrityCeiling, LeafRequest, Validity};
use crate::serial::Serial;
use crate::sign::{KeyId, SignatureBackend};
use crate::IssuedCert;

/// `ecdsa-with-SHA256` (RFC 5758) — a P-256 CSR self-signature.
const ECDSA_WITH_SHA256_OID: &str = "1.2.840.10045.4.3.2";
/// `sha256WithRSAEncryption` (PKCS#1 v1.5) — an RSA CSR self-signature.
const RSA_PKCS1_SHA256_OID: &str = "1.2.840.113549.1.1.11";
/// PKCS#9 `extensionRequest` attribute — the requested-extensions carrier.
const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";

/// Minimum accepted RSA modulus size, in bits. 2048 is the floor for a CSR key
/// the issuer will certify; anything below is refused as proof of possession of
/// a key too weak to bind a leaf to. ECDSA curves (P-256/P-384) carry their own
/// strength in the curve choice and are not size-gated here.
const MIN_RSA_KEY_BITS: u64 = 2048;

/// The ASN.1 `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2): the fixed
/// `SEQUENCE { SEQUENCE { id-sha256, NULL }, OCTET STRING }` header that
/// precedes the 32-byte digest in a PKCS#1 v1.5 signature.
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// The operator-set scope of a CSR-issued leaf.
///
/// These are the only inputs that shape the issued certificate's extensions; a
/// CSR contributes solely its public key and subject. The fields mirror the
/// scope portion of [`LeafRequest`] (everything but subject and key).
#[derive(Debug, Clone)]
pub struct LeafScope {
    /// Validity window.
    pub validity: Validity,
    /// Host descriptors (`"*"`, `"sha256:<hex>"`, or a raw `machine_id`).
    pub host_binding: Vec<String>,
    /// User descriptors (`"*"` or exact PAM usernames).
    pub user_binding: Vec<String>,
    /// Roles the leaf may activate.
    pub allowed_roles: Vec<String>,
    /// Optional integrity ceiling.
    pub max_integrity: Option<IntegrityCeiling>,
    /// Certificate-format version.
    pub profile_version: u32,
}

/// A request to issue a leaf from a CSR: the request bytes plus the
/// operator-set scope.
#[derive(Debug, Clone)]
pub struct LeafRequestFromCsr {
    /// PKCS#10 CSR bytes, PEM or DER. Only its subject public key and subject
    /// name are used.
    pub csr: Vec<u8>,
    /// Operator-set scope; the CSR's requested attributes never feed this.
    pub scope: LeafScope,
}

/// One extension a CSR requested, surfaced for form prefill only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedExtension {
    /// The requested extension's OID, dotted decimal.
    pub oid: String,
    /// Whether the request marked it critical.
    pub critical: bool,
    /// The requested `extnValue` (DER), verbatim.
    pub value_der: Vec<u8>,
}

/// The advisory contents of a CSR: its verified subject and key, plus any
/// requested extensions. Requested extensions are for UI prefill only and never
/// influence issuance.
#[derive(Debug, Clone)]
pub struct CsrContents {
    /// Subject distinguished name (RFC 4514).
    pub subject: String,
    /// Subject public key info, DER.
    pub subject_spki_der: Vec<u8>,
    /// Extensions the CSR asked for (advisory).
    pub requested_extensions: Vec<RequestedExtension>,
}

/// A parsed PKCS#10 certificate request.
///
/// Parsing does not verify the self-signature; call
/// [`Csr::verify_proof_of_possession`] for that. The high-level
/// [`issue_leaf_from_csr`] does both before issuing.
#[derive(Debug, Clone)]
pub struct Csr {
    subject: String,
    subject_spki_der: Vec<u8>,
    /// The DER of the signed `CertReqInfo` — the bytes the self-signature covers.
    info_der: Vec<u8>,
    signature_alg_oid: String,
    signature: Vec<u8>,
    requested_extensions: Vec<RequestedExtension>,
}

impl Csr {
    /// Parses a CSR from PEM or DER.
    ///
    /// # Errors
    ///
    /// [`IssueError::CsrParse`] if the input is neither valid PEM-wrapped nor
    /// valid DER PKCS#10.
    pub fn parse(csr: &[u8]) -> Result<Self, IssueError> {
        let der = normalize_to_der(csr)?;
        let req = CertReq::from_der(&der).map_err(|e| IssueError::CsrParse(e.to_string()))?;
        let subject = req.info.subject.to_string();
        let subject_spki_der = req
            .info
            .public_key
            .to_der()
            .map_err(|e| IssueError::CsrParse(e.to_string()))?;
        let info_der = req
            .info
            .to_der()
            .map_err(|e| IssueError::CsrParse(e.to_string()))?;
        let signature_alg_oid = req.algorithm.oid.to_string();
        let signature = req.signature.raw_bytes().to_vec();
        let requested_extensions = parse_requested_extensions(&req);
        Ok(Self {
            subject,
            subject_spki_der,
            info_der,
            signature_alg_oid,
            signature,
            requested_extensions,
        })
    }

    /// The CSR's subject distinguished name (RFC 4514).
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The CSR's subject public key info, DER.
    #[must_use]
    pub fn subject_spki_der(&self) -> &[u8] {
        &self.subject_spki_der
    }

    /// The extensions the CSR requested (advisory; never used for issuance).
    #[must_use]
    pub fn requested_extensions(&self) -> &[RequestedExtension] {
        &self.requested_extensions
    }

    /// The advisory contents of the CSR (subject, key, requested extensions).
    #[must_use]
    pub fn contents(&self) -> CsrContents {
        CsrContents {
            subject: self.subject.clone(),
            subject_spki_der: self.subject_spki_der.clone(),
            requested_extensions: self.requested_extensions.clone(),
        }
    }

    /// Verifies the CSR's self-signature under its own public key (proof of
    /// possession).
    ///
    /// # Errors
    ///
    /// [`IssueError::CsrUnsupportedAlgorithm`] for a signature algorithm other
    /// than ECDSA-P256/SHA-256 or RSA-PKCS1v1.5/SHA-256,
    /// [`IssueError::CsrInvalidKey`] if the public key is not the declared
    /// type, or [`IssueError::CsrProofOfPossession`] if the signature does not
    /// verify.
    pub fn verify_proof_of_possession(&self) -> Result<(), IssueError> {
        match self.signature_alg_oid.as_str() {
            ECDSA_WITH_SHA256_OID => {
                verify_ecdsa_p256(&self.subject_spki_der, &self.info_der, &self.signature)
            }
            RSA_PKCS1_SHA256_OID => {
                verify_rsa_pkcs1_sha256(&self.subject_spki_der, &self.info_der, &self.signature)
            }
            other => Err(IssueError::CsrUnsupportedAlgorithm(other.to_owned())),
        }
    }
}

/// Issues a shift-leaf from a CSR: parse, verify proof of possession, then
/// [`crate::issue_leaf`] with the CSR's key and subject and the operator's
/// scope.
///
/// The self-signature is verified before anything reaches the signing backend,
/// so a bad CSR is rejected without a signing operation. The issuance is
/// journaled before the artifact is returned (see [`crate::issue_leaf`]).
///
/// # Errors
///
/// A CSR error ([`IssueError::CsrParse`], [`IssueError::CsrUnsupportedAlgorithm`],
/// [`IssueError::CsrInvalidKey`], [`IssueError::CsrProofOfPossession`]) before
/// signing, or any [`crate::issue_leaf`] error thereafter.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors issue_leaf: signer, key, parent, request, serial, and a \
              journaling target and clock are each distinct required inputs"
)]
pub fn issue_leaf_from_csr<B: SignatureBackend, S: JournalStorage>(
    backend: &B,
    key_id: &KeyId,
    parent_der: &[u8],
    req: &LeafRequestFromCsr,
    serial: &Serial,
    journal: &mut Journal<S>,
    now_unix: u64,
) -> Result<IssuedCert, IssueError> {
    let csr = Csr::parse(&req.csr)?;
    // Proof of possession before any signing: a bad CSR never reaches the backend.
    csr.verify_proof_of_possession()?;

    // Only the key and subject come from the CSR; the scope is the operator's.
    let leaf_req = LeafRequest {
        subject: csr.subject,
        subject_spki_der: csr.subject_spki_der,
        validity: req.scope.validity,
        host_binding: req.scope.host_binding.clone(),
        user_binding: req.scope.user_binding.clone(),
        allowed_roles: req.scope.allowed_roles.clone(),
        max_integrity: req.scope.max_integrity,
        profile_version: req.scope.profile_version,
    };
    crate::issue_leaf(
        backend, key_id, parent_der, &leaf_req, serial, journal, now_unix,
    )
}

/// Verifies an ECDSA-P256/SHA-256 signature over `message` with the key in
/// `spki_der`.
fn verify_ecdsa_p256(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), IssueError> {
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;

    let verifying_key = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| IssueError::CsrInvalidKey(e.to_string()))?;
    let signature = p256::ecdsa::Signature::from_der(signature)
        .map_err(|_| IssueError::CsrProofOfPossession)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| IssueError::CsrProofOfPossession)
}

/// Verifies an RSA PKCS#1 v1.5 / SHA-256 signature over `message` with the key
/// in `spki_der`.
fn verify_rsa_pkcs1_sha256(
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), IssueError> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa::traits::PublicKeyParts as _;

    let key = rsa::RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| IssueError::CsrInvalidKey(e.to_string()))?;
    // Refuse a modulus below the strength floor before spending a verification:
    // a weak key must never back an issued leaf, regardless of whether its
    // self-signature checks out.
    let bits = u64::from(key.n().bits());
    if bits < MIN_RSA_KEY_BITS {
        return Err(IssueError::CsrWeakRsaKey {
            bits,
            minimum: MIN_RSA_KEY_BITS,
        });
    }
    let mut hashed = [0u8; 32];
    hashed.copy_from_slice(&Sha256::digest(message));
    // The digest plus the fixed SHA-256 DigestInfo prefix is the PKCS#1 v1.5
    // padding the verifier expects.
    let scheme = Pkcs1v15Sign {
        hash_len: Some(hashed.len()),
        prefix: Box::from(SHA256_DIGEST_INFO_PREFIX.as_slice()),
    };
    key.verify(scheme, &hashed, signature)
        .map_err(|_| IssueError::CsrProofOfPossession)
}

/// Collects the extensions a CSR requested via its PKCS#9 `extensionRequest`
/// attribute. Best-effort and advisory: any attribute that does not parse as a
/// `SEQUENCE OF Extension` is skipped.
fn parse_requested_extensions(req: &CertReq) -> Vec<RequestedExtension> {
    let mut out = Vec::new();
    for attribute in req.info.attributes.iter() {
        if attribute.oid.to_string() != EXTENSION_REQUEST_OID {
            continue;
        }
        for value in attribute.values.iter() {
            let Ok(der) = value.to_der() else { continue };
            let Ok(extensions) = Vec::<x509_cert::ext::Extension>::from_der(&der) else {
                continue;
            };
            for extension in extensions {
                out.push(RequestedExtension {
                    oid: extension.extn_id.to_string(),
                    critical: extension.critical,
                    value_der: extension.extn_value.as_bytes().to_vec(),
                });
            }
        }
    }
    out
}

/// Returns the DER of a CSR, decoding a PEM wrapper when present.
fn normalize_to_der(input: &[u8]) -> Result<Vec<u8>, IssueError> {
    // DER PKCS#10 opens with a SEQUENCE (0x30); PEM opens with the `-----BEGIN`
    // armor after optional whitespace. Keying on the leading bytes (rather than
    // searching for `-----` anywhere) avoids misreading a DER value that merely
    // contains dashes as PEM.
    let looks_pem = input
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|&byte| byte == b'-');
    if looks_pem {
        decode_pem(input)
    } else {
        Ok(input.to_vec())
    }
}

/// Extracts and base64-decodes the body of a PEM block (any label).
fn decode_pem(input: &[u8]) -> Result<Vec<u8>, IssueError> {
    let text = core::str::from_utf8(input)
        .map_err(|_| IssueError::CsrParse("PEM is not UTF-8".to_owned()))?;
    let mut body = String::new();
    let mut in_body = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_body = true;
        } else if trimmed.starts_with("-----END") {
            break;
        } else if in_body {
            body.push_str(trimmed);
        }
    }
    if body.is_empty() {
        return Err(IssueError::CsrParse("no PEM body found".to_owned()));
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| IssueError::CsrParse(format!("PEM base64: {e}")))
}

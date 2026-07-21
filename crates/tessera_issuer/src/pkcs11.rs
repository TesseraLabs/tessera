//! PKCS#11 signing adapter: one code path for any token or HSM.
//!
//! Any provider that exposes a PKCS#11 module — a smartcard/USB token, a
//! network HSM, a GOST token that speaks a PKCS#11 mechanism — signs a built
//! `TBSCertificate` (or `TBSCertList`) through the same [`Pkcs11Signer`], with
//! no per-vendor branching. The signing mechanism is chosen from the CA key's
//! declared [`SignatureAlgorithm`]; the mapping table
//! ([`mechanism_for`]) is the single extension point for new key types.
//!
//! The private key never leaves the token: the adapter hands the token the TBS
//! bytes, gets back a signature, and re-frames only ECDSA's raw `r || s` into
//! the DER `Ecdsa-Sig-Value` the certificate's `signature` `BIT STRING` needs.
//!
//! # PIN handling
//!
//! The token PIN is fetched from a caller-supplied [`PinSource`] *immediately
//! before* `C_Login` and dropped (zeroized by [`secrecy::SecretString`]) as
//! soon as login returns — it lives only for the duration of one signing
//! operation. The PIN never enters a log line, an error message, the
//! [`Debug`] of any type here, or a command-line argument: the adapter holds no
//! PIN field and its errors carry only PKCS#11 status categories, never
//! secret input.

use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use secrecy::SecretString;

use tessera_ext::der::{encode_tlv, TAG_INTEGER, TAG_SEQUENCE};

use crate::sign::{KeyId, SignError, Signature, SignatureAlgorithm, SignatureBackend};

/// Supplies the token PIN for exactly one signing operation.
///
/// The returned [`SecretString`] is used only to log in and is dropped (and so
/// zeroized) before the TBS is signed. Implementations MUST NOT persist, log,
/// or echo the PIN, and MUST NOT read it from a process argument. The local
/// agent implements this with a terminal/pinentry prompt; tests inject a fixed
/// value.
///
/// A blanket impl covers any `Fn() -> Result<SecretString, Pkcs11SignError>`,
/// so a closure is the usual way to supply one.
pub trait PinSource {
    /// Obtain the PIN to log into the token with.
    ///
    /// # Errors
    ///
    /// [`Pkcs11SignError::PinUnavailable`] when no PIN could be obtained.
    fn pin(&self) -> Result<SecretString, Pkcs11SignError>;
}

impl<F> PinSource for F
where
    F: Fn() -> Result<SecretString, Pkcs11SignError>,
{
    fn pin(&self) -> Result<SecretString, Pkcs11SignError> {
        self()
    }
}

/// How to reach the CA key inside a PKCS#11 module.
///
/// `key_id` is both the value the issuance core passes to
/// [`SignatureBackend::sign`] and the `CKA_LABEL` the private-key object is
/// found by; `algorithm` fixes the signing mechanism and the
/// `AlgorithmIdentifier` written into the certificate.
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// Filesystem path to the PKCS#11 `.so`/`.dylib` module.
    pub module_path: PathBuf,
    /// Token label to select, or `None` to use the first slot with a token.
    pub token_label: Option<String>,
    /// The CA key: its string is matched against the private key's `CKA_LABEL`.
    pub key_id: KeyId,
    /// The algorithm the key signs with; picks the mechanism and the
    /// `AlgorithmIdentifier`.
    pub algorithm: SignatureAlgorithm,
    /// An optional second key, in the *same* module, used only to sign device
    /// registries (the agent's `/sign-registry` endpoint). Its `CKA_LABEL` is
    /// matched like `key_id`; it always signs with
    /// [`SignatureAlgorithm::EcdsaWithSha256`] (P-256), the algorithm the
    /// cabinet's registry verifier expects. Loading it here keeps both keys
    /// behind one `C_Initialize`, since a second module context on the same
    /// library would be refused.
    pub registry_key: Option<KeyId>,
}

/// A [`SignatureBackend`] backed by a PKCS#11 module.
///
/// Load once per process with [`Pkcs11Signer::open`] (the underlying
/// `C_Initialize` may run only once per library instance). Each `sign` opens a
/// fresh R/W session, logs in with a just-fetched PIN, signs, and logs out.
pub struct Pkcs11Signer<P: PinSource> {
    ctx: Pkcs11,
    config: Pkcs11Config,
    pin_source: P,
}

// Manual `Debug` so neither the loaded module context nor — crucially — the PIN
// source can be printed. Only non-secret configuration is shown.
impl<P: PinSource> core::fmt::Debug for Pkcs11Signer<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("module_path", &self.config.module_path)
            .field("token_label", &self.config.token_label)
            .field("key_id", &self.config.key_id)
            .field("algorithm", &self.config.algorithm)
            .finish_non_exhaustive()
    }
}

impl<P: PinSource> Pkcs11Signer<P> {
    /// Load the configured PKCS#11 module, run `C_Initialize`, and bind the
    /// signer to `pin_source`.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11SignError::ModulePathMissing`] when the module path is absent.
    /// - [`Pkcs11SignError::ModuleLoad`] when the library cannot be loaded.
    /// - [`Pkcs11SignError::Init`] when `C_Initialize` fails.
    pub fn open(config: Pkcs11Config, pin_source: P) -> Result<Self, Pkcs11SignError> {
        if !config.module_path.exists() {
            return Err(Pkcs11SignError::ModulePathMissing(
                config.module_path.clone(),
            ));
        }
        let ctx = Pkcs11::new(&config.module_path)
            .map_err(|e| Pkcs11SignError::ModuleLoad(e.to_string()))?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| Pkcs11SignError::Init(e.to_string()))?;
        let signer = Self {
            ctx,
            config,
            pin_source,
        };
        // A configured registry key must be ECDSA P-256 (the cabinet's registry
        // verifier accepts nothing else). Confirm the real curve from the token
        // now, at startup, so a P-384/RSA key is refused before the agent
        // listens rather than failing only on the first registry signature.
        signer.verify_registry_key_p256()?;
        Ok(signer)
    }

    /// Confirm the configured registry key is an ECDSA P-256 key by reading its
    /// real type from the token; a no-op when no registry key is configured.
    ///
    /// Reads `CKA_KEY_TYPE` (must be `CKK_EC`) and `CKA_EC_PARAMS` (must name the
    /// P-256 curve) from the key's public object, which a token exposes without a
    /// login. If the token has no public object for the label, it logs in once
    /// and reads the same non-sensitive attributes from the private key. The
    /// check fails closed: a key whose type cannot be confirmed P-256 is refused.
    ///
    /// # Errors
    ///
    /// - [`Pkcs11SignError::RegistryKeyNotP256`] when the key is not EC or not on
    ///   the P-256 curve.
    /// - [`Pkcs11SignError::KeyNotFound`] when no key object carries the label.
    /// - [`Pkcs11SignError::Session`] / [`Pkcs11SignError::Login`] on a token or
    ///   login failure while reading the attributes.
    fn verify_registry_key_p256(&self) -> Result<(), Pkcs11SignError> {
        let Some(registry) = self.config.registry_key.as_ref() else {
            return Ok(());
        };
        let label = registry.as_str();
        let slot = self.find_slot()?;
        let session = self
            .ctx
            .open_rw_session(slot)
            .map_err(|e| Pkcs11SignError::Session(e.to_string()))?;

        // Prefer the public key object: it is readable without a login. Fall back
        // to the private key (after a login) only when no public object exists.
        let handle =
            if let Some(handle) = find_key_by_label(&session, ObjectClass::PUBLIC_KEY, label)? {
                handle
            } else {
                let pin = self.pin_source.pin()?;
                session
                    .login(UserType::User, Some(&pin))
                    .map_err(|e| Pkcs11SignError::Login(e.to_string()))?;
                find_key_by_label(&session, ObjectClass::PRIVATE_KEY, label)?
                    .ok_or_else(|| Pkcs11SignError::KeyNotFound(label.to_owned()))?
            };

        let attributes = session
            .get_attributes(handle, &[AttributeType::KeyType, AttributeType::EcParams])
            .map_err(|e| Pkcs11SignError::Session(e.to_string()))?;
        let mut key_type = None;
        let mut ec_params = None;
        for attribute in attributes {
            match attribute {
                Attribute::KeyType(value) => key_type = Some(value),
                Attribute::EcParams(value) => ec_params = Some(value),
                _ => {}
            }
        }
        if key_type != Some(KeyType::EC) {
            return Err(Pkcs11SignError::RegistryKeyNotP256(
                "the registry key is not an EC key".to_owned(),
            ));
        }
        match ec_params {
            Some(params) if ec_params_is_p256(&params) => Ok(()),
            _ => Err(Pkcs11SignError::RegistryKeyNotP256(
                "the registry key is not on the P-256 curve".to_owned(),
            )),
        }
    }

    /// Resolve the slot to sign in: the labelled token, or the first present.
    fn find_slot(&self) -> Result<Slot, Pkcs11SignError> {
        let slots = self
            .ctx
            .get_slots_with_token()
            .map_err(|e| Pkcs11SignError::Session(e.to_string()))?;
        let Some(want) = self.config.token_label.as_deref() else {
            return slots.into_iter().next().ok_or(Pkcs11SignError::NoToken);
        };
        for slot in slots {
            let info = self
                .ctx
                .get_token_info(slot)
                .map_err(|e| Pkcs11SignError::Session(e.to_string()))?;
            if info.label().trim_end() == want {
                return Ok(slot);
            }
        }
        Err(Pkcs11SignError::TokenNotFound(want.to_owned()))
    }

    /// Resolve the algorithm `key_id` signs with, or `None` when the signer
    /// addresses neither the issuance nor the registry key.
    ///
    /// The `CKA_LABEL` to look up is always `key_id` itself, so only the
    /// algorithm varies: the issuance key uses its configured algorithm, and the
    /// registry key always signs P-256, so the two never share a mechanism by
    /// accident.
    fn resolve_algorithm(&self, key_id: &KeyId) -> Option<SignatureAlgorithm> {
        if key_id == &self.config.key_id {
            return Some(self.config.algorithm);
        }
        if self.config.registry_key.as_ref() == Some(key_id) {
            return Some(SignatureAlgorithm::EcdsaWithSha256);
        }
        None
    }

    /// Sign `tbs_der` on the token with the key at `label` using `algorithm`,
    /// returning the certificate-ready signature.
    fn sign_on_token(
        &self,
        tbs_der: &[u8],
        label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<u8>, Pkcs11SignError> {
        let slot = self.find_slot()?;
        let session = self
            .ctx
            .open_rw_session(slot)
            .map_err(|e| Pkcs11SignError::Session(e.to_string()))?;

        // The PIN exists only across `C_Login`: fetched here, dropped at the end
        // of this block, before the key is ever used.
        {
            let pin = self.pin_source.pin()?;
            session
                .login(UserType::User, Some(&pin))
                .map_err(|e| Pkcs11SignError::Login(e.to_string()))?;
        }

        let key = find_private_key(&session, label)?;
        let mechanism = mechanism_for(algorithm)?;
        let raw = session
            .sign(&mechanism, key, tbs_der)
            .map_err(|e| Pkcs11SignError::Sign(e.to_string()))?;
        // Best-effort logout; the session's Drop closes it regardless.
        if session.logout().is_err() {
            // Nothing actionable on a failed logout — the handle is dropped next.
        }
        post_process_signature(algorithm, raw)
    }
}

impl<P: PinSource> SignatureBackend for Pkcs11Signer<P> {
    fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
        self.resolve_algorithm(key_id)
            .ok_or_else(|| SignError::UnknownKey(key_id.as_str().to_owned()))
    }

    fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
        let Some(algorithm) = self.resolve_algorithm(key_id) else {
            return Err(SignError::UnknownKey(key_id.as_str().to_owned()));
        };
        // Map the rich PKCS#11 error to the trait's `Backend` variant. The
        // Display of `Pkcs11SignError` never contains PIN bytes.
        let bytes = self
            .sign_on_token(tbs_der, key_id.as_str(), algorithm)
            .map_err(|e| SignError::Backend(e.to_string()))?;
        Ok(Signature { algorithm, bytes })
    }
}

/// Find the private-key object whose `CKA_LABEL` equals `label`.
fn find_private_key(session: &Session, label: &str) -> Result<ObjectHandle, Pkcs11SignError> {
    find_key_by_label(session, ObjectClass::PRIVATE_KEY, label)?
        .ok_or_else(|| Pkcs11SignError::KeyNotFound(label.to_owned()))
}

/// Find the first object of `class` whose `CKA_LABEL` equals `label`, or `None`
/// when the token exposes no such object (e.g. a private object before login).
fn find_key_by_label(
    session: &Session,
    class: ObjectClass,
    label: &str,
) -> Result<Option<ObjectHandle>, Pkcs11SignError> {
    let template = [
        Attribute::Class(class),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let handles = session
        .find_objects(&template)
        .map_err(|e| Pkcs11SignError::Session(e.to_string()))?;
    Ok(handles.into_iter().next())
}

/// DER encoding of the `prime256v1` / `secp256r1` named-curve OID
/// (`1.2.840.10045.3.1.7`) — the value `CKA_EC_PARAMS` carries for a P-256 key.
const P256_EC_PARAMS: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// Whether `CKA_EC_PARAMS` names the P-256 curve (the named-curve OID form).
fn ec_params_is_p256(ec_params: &[u8]) -> bool {
    ec_params == P256_EC_PARAMS
}

/// Map a [`SignatureAlgorithm`] to the PKCS#11 mechanism that produces it.
///
/// The mechanisms are the hashing single-shot variants, so the token digests
/// the TBS itself and the host passes the raw TBS bytes to `C_Sign`. Add a row
/// here to support a new key type.
///
/// # Errors
///
/// [`Pkcs11SignError::UnsupportedAlgorithm`] for an algorithm with no PKCS#11
/// mechanism in the table (currently Ed25519).
fn mechanism_for(algorithm: SignatureAlgorithm) -> Result<Mechanism<'static>, Pkcs11SignError> {
    match algorithm {
        SignatureAlgorithm::EcdsaWithSha256 => Ok(Mechanism::EcdsaSha256),
        SignatureAlgorithm::EcdsaWithSha384 => Ok(Mechanism::EcdsaSha384),
        SignatureAlgorithm::RsaPkcs1Sha256 => Ok(Mechanism::Sha256RsaPkcs),
        SignatureAlgorithm::Ed25519 => Err(Pkcs11SignError::UnsupportedAlgorithm(algorithm)),
    }
}

/// Turn a raw `C_Sign` result into the octets the certificate `signature`
/// `BIT STRING` carries.
///
/// PKCS#11 `CKM_ECDSA*` returns a fixed-width `r || s` string; the certificate
/// wants the DER `Ecdsa-Sig-Value` (RFC 3279), so ECDSA is re-encoded. RSA
/// PKCS#1 v1.5 is already the final signature and passes through.
fn post_process_signature(
    algorithm: SignatureAlgorithm,
    raw: Vec<u8>,
) -> Result<Vec<u8>, Pkcs11SignError> {
    match algorithm {
        SignatureAlgorithm::EcdsaWithSha256 | SignatureAlgorithm::EcdsaWithSha384 => {
            ecdsa_raw_to_der(&raw)
        }
        SignatureAlgorithm::RsaPkcs1Sha256 | SignatureAlgorithm::Ed25519 => Ok(raw),
    }
}

/// Re-encode a raw `r || s` ECDSA signature into DER `SEQUENCE { INTEGER r,
/// INTEGER s }`.
///
/// # Errors
///
/// [`Pkcs11SignError::MalformedEcdsaSignature`] when the input is empty or its
/// length is odd (it cannot split into equal `r` and `s` halves).
fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, Pkcs11SignError> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(Pkcs11SignError::MalformedEcdsaSignature);
    }
    let half = raw.len() / 2;
    let (r, s) = raw.split_at(half);
    let mut body = der_positive_integer(r);
    body.extend_from_slice(&der_positive_integer(s));
    Ok(encode_tlv(TAG_SEQUENCE, &body))
}

/// Encode a big-endian byte string as a DER positive `INTEGER` (TLV).
///
/// Leading zero octets are stripped to the minimal form, and a `0x00` prefix is
/// added when the high bit is set so the value stays unambiguously positive; an
/// empty or all-zero input encodes as `0`.
fn der_positive_integer(bytes: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = match bytes.iter().position(|&b| b != 0) {
        Some(first) => bytes.get(first..).unwrap_or(&[0]),
        None => &[0],
    };
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().copied().unwrap_or(0) & 0x80 != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(trimmed);
    encode_tlv(TAG_INTEGER, &content)
}

/// Errors from the PKCS#11 signing adapter.
///
/// No variant carries PIN bytes: PKCS#11 status codes and configuration values
/// are the only data these errors expose.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Pkcs11SignError {
    /// The configured module path does not exist.
    #[error("pkcs#11 module not found: {0}")]
    ModulePathMissing(PathBuf),
    /// The PKCS#11 library could not be loaded (ABI mismatch, missing dep).
    #[error("pkcs#11 module load failed: {0}")]
    ModuleLoad(String),
    /// `C_Initialize` failed.
    #[error("pkcs#11 initialization failed: {0}")]
    Init(String),
    /// No slot reports a present token.
    #[error("no pkcs#11 token present")]
    NoToken,
    /// No present token matched the configured label.
    #[error("pkcs#11 token not found: {0}")]
    TokenNotFound(String),
    /// No private-key object matched the configured `CKA_LABEL`.
    #[error("pkcs#11 private key not found for label: {0}")]
    KeyNotFound(String),
    /// The algorithm has no PKCS#11 mechanism in the mapping table.
    #[error("algorithm has no pkcs#11 mechanism: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    /// No PIN could be obtained from the [`PinSource`].
    #[error("pin unavailable: {0}")]
    PinUnavailable(String),
    /// `C_Login` failed (wrong PIN, locked token, transport error). The message
    /// is the PKCS#11 status, never the PIN.
    #[error("pkcs#11 login failed: {0}")]
    Login(String),
    /// A session-management call (`C_OpenSession`, slot enumeration) failed.
    #[error("pkcs#11 session failure: {0}")]
    Session(String),
    /// `C_Sign` failed on the token.
    #[error("pkcs#11 sign failed: {0}")]
    Sign(String),
    /// The token returned an ECDSA signature that is not a `r || s` pair.
    #[error("token returned a malformed ecdsa signature")]
    MalformedEcdsaSignature,
    /// The configured registry key is not an ECDSA P-256 key, read from the
    /// token at startup. The registry signature format the cabinet verifies
    /// accepts only P-256.
    #[error("registry key must be ecdsa p-256: {0}")]
    RegistryKeyNotP256(String),
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::err_expect,
        clippy::indexing_slicing
    )]

    use super::*;
    use secrecy::ExposeSecret;

    /// A recognisable PIN used to assert it never surfaces in `Debug`/`Display`.
    const SECRET_PIN: &str = "hunter2-secret-pin-xyz";

    fn config() -> Pkcs11Config {
        Pkcs11Config {
            module_path: PathBuf::from("/nonexistent/__tessera_no_module__.so"),
            token_label: Some("Tessera CA".to_owned()),
            key_id: KeyId::new("ca-key"),
            algorithm: SignatureAlgorithm::EcdsaWithSha256,
            registry_key: None,
        }
    }

    #[test]
    fn open_reports_missing_module_without_touching_pin() {
        let signer = Pkcs11Signer::open(config(), || Ok(SecretString::from(SECRET_PIN.to_owned())));
        let err = signer.err().expect("missing module must fail to open");
        assert!(
            matches!(err, Pkcs11SignError::ModulePathMissing(_)),
            "{err:?}"
        );
    }

    #[test]
    fn debug_of_signer_config_never_contains_the_pin() {
        // Build a signer struct directly (no module load) to format its Debug.
        // The pin source closes over the secret; Debug must not reach it.
        let pin = SecretString::from(SECRET_PIN.to_owned());
        // A closure PinSource capturing the secret.
        let source = move || Ok(pin.clone());
        // We cannot construct `Pkcs11Signer` without a live `Pkcs11`, so assert
        // the property on the config Debug plus the PinSource contract: the
        // secret is only reachable via `pin()`, never via any Debug here.
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains(SECRET_PIN));
        // The source yields the secret only through the trait method.
        assert_eq!(source.pin().unwrap().expose_secret(), SECRET_PIN);
    }

    #[test]
    fn error_display_never_contains_the_pin() {
        // Login/session errors are built from PKCS#11 status text, never the
        // PIN. Even a hostile status string cannot smuggle the PIN because the
        // adapter never places it in an error.
        for err in [
            Pkcs11SignError::Login("CKR_PIN_INCORRECT".to_owned()),
            Pkcs11SignError::Sign("CKR_DEVICE_ERROR".to_owned()),
            Pkcs11SignError::PinUnavailable("prompt cancelled".to_owned()),
        ] {
            let shown = format!("{err} | {err:?}");
            assert!(!shown.contains(SECRET_PIN), "{shown}");
        }
    }

    #[test]
    fn ecdsa_mechanisms_are_selected_by_algorithm() {
        assert!(matches!(
            mechanism_for(SignatureAlgorithm::EcdsaWithSha256).unwrap(),
            Mechanism::EcdsaSha256
        ));
        assert!(matches!(
            mechanism_for(SignatureAlgorithm::EcdsaWithSha384).unwrap(),
            Mechanism::EcdsaSha384
        ));
        assert!(matches!(
            mechanism_for(SignatureAlgorithm::RsaPkcs1Sha256).unwrap(),
            Mechanism::Sha256RsaPkcs
        ));
        let err = mechanism_for(SignatureAlgorithm::Ed25519).unwrap_err();
        assert!(
            matches!(err, Pkcs11SignError::UnsupportedAlgorithm(_)),
            "{err:?}"
        );
    }

    #[test]
    fn rsa_signature_passes_through_unchanged() {
        let raw = vec![0xAB; 256];
        let out = post_process_signature(SignatureAlgorithm::RsaPkcs1Sha256, raw.clone()).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn ecdsa_raw_is_reencoded_to_der_sequence() {
        // r and s each 32 bytes; r has its high bit set, s does not.
        let mut raw = vec![0u8; 64];
        raw[0] = 0x80; // r starts with a high-bit octet -> needs a 0x00 prefix.
        raw[32] = 0x01; // s is a small positive integer.
        let der = post_process_signature(SignatureAlgorithm::EcdsaWithSha256, raw).unwrap();
        // Parse back with a real ECDSA DER reader to prove the shape.
        let sig = p256::ecdsa::Signature::from_der(&der);
        assert!(sig.is_ok(), "re-encoded ECDSA DER must parse: {der:02x?}");
    }

    #[test]
    fn ecdsa_raw_rejects_odd_length() {
        let err = ecdsa_raw_to_der(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, Pkcs11SignError::MalformedEcdsaSignature));
    }

    #[test]
    fn ecdsa_raw_rejects_empty() {
        let err = ecdsa_raw_to_der(&[]).unwrap_err();
        assert!(matches!(err, Pkcs11SignError::MalformedEcdsaSignature));
    }

    #[test]
    fn ec_params_p256_check_accepts_only_the_p256_named_curve() {
        // The exact prime256v1 OID bytes are accepted; this is what the startup
        // registry-key probe reads from CKA_EC_PARAMS on the token.
        assert!(ec_params_is_p256(&[
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
        ]));
        // secp384r1 (1.3.132.0.34) — a real EC key, wrong curve.
        assert!(!ec_params_is_p256(&[
            0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
        ]));
        // Empty and truncated params fail closed.
        assert!(!ec_params_is_p256(&[]));
        assert!(!ec_params_is_p256(&[0x06, 0x08, 0x2A, 0x86]));
    }

    #[test]
    fn der_positive_integer_strips_leading_zeros_and_stays_positive() {
        // 0x00 0x80 0x01 -> minimal, high bit set -> 0x00 prefix kept once.
        let tlv = der_positive_integer(&[0x00, 0x80, 0x01]);
        assert_eq!(tlv, vec![TAG_INTEGER, 0x03, 0x00, 0x80, 0x01]);
        // All-zero encodes as INTEGER 0.
        assert_eq!(
            der_positive_integer(&[0x00, 0x00]),
            vec![TAG_INTEGER, 0x01, 0x00]
        );
        // Small value, no prefix.
        assert_eq!(der_positive_integer(&[0x2A]), vec![TAG_INTEGER, 0x01, 0x2A]);
    }
}

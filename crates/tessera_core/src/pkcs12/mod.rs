//! PKCS#12 bundle loader and bounded PIN-retry acquisition loop.
//!
//! `from_p12` parses a `.p12` byte stream, decrypts it with the supplied PIN,
//! and returns a [`LoadedKeyMaterial`] containing the end-entity certificate,
//! the presented chain certificates, and the private key serialised as PKCS#8
//! DER kept inside [`zeroize::Zeroizing`] (so the key is wiped from memory on
//! drop).
//!
//! Wrong-PIN failures are classified into [`Pkcs12Error::WrongPin`] so the PAM
//! layer can drive a bounded retry loop without leaking the PIN.

pub mod error;

pub use error::{AcquireError, P12EnvelopeError, Pkcs12Error};

use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::pam_conv::PamConvError;
use crate::x509::Certificate;

/// Material extracted from a decrypted PKCS#12 bundle.
///
/// The private key is held in PKCS#8 DER form inside [`Zeroizing`] so that the
/// raw bytes are scrubbed from memory when this value is dropped.  Call
/// [`Self::private_key`] to materialise an [`PKey<Private>`] handle on demand;
/// the resulting handle is owned by OpenSSL and will be freed when it drops.
pub struct LoadedKeyMaterial {
    /// End-entity certificate parsed from the bundle.
    pub end_entity: Certificate,
    /// Optional chain certificates that accompanied the end-entity (typically
    /// the issuing intermediate CA).
    pub presented_chain: Vec<Certificate>,
    /// PKCS#8 DER serialisation of the private key, zeroized on drop.
    pub key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for LoadedKeyMaterial {
    /// Debug-formatted view that intentionally hides the key bytes — printing
    /// only the chain length and the end-entity subject prevents the private
    /// key (or its length) from leaking into logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedKeyMaterial")
            .field("end_entity_subject_cn", &self.end_entity.subject_cn().ok())
            .field("presented_chain_len", &self.presented_chain.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl LoadedKeyMaterial {
    /// Decrypt a PKCS#12 bundle with the supplied PIN.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs12Error::WrongPin`] when the bundle's MAC fails to verify
    /// (i.e. the PIN is wrong).  Returns [`Pkcs12Error::MissingKey`] /
    /// [`Pkcs12Error::MissingCert`] when the bundle is well-formed but lacks a
    /// required component.  Any other DER / OpenSSL failure becomes
    /// [`Pkcs12Error::Corrupt`].
    pub fn from_p12(bytes: &[u8], pin: &SecretString) -> Result<Self, Pkcs12Error> {
        let p12 = Pkcs12::from_der(bytes).map_err(|e| Pkcs12Error::Corrupt(e.to_string()))?;
        let parsed = p12
            .parse2(pin.expose_secret())
            .map_err(|e| classify_parse_error(&e))?;

        let pkey = parsed.pkey.ok_or(Pkcs12Error::MissingKey)?;
        let cert = parsed.cert.ok_or(Pkcs12Error::MissingCert)?;
        let chain = parsed.ca;

        let end_entity_der = cert
            .to_der()
            .map_err(|e| Pkcs12Error::Corrupt(e.to_string()))?;
        let end_entity = Certificate::from_der(&end_entity_der)
            .map_err(|e| Pkcs12Error::Corrupt(format!("end-entity: {e}")))?;

        let mut presented_chain = Vec::new();
        if let Some(stack) = chain {
            presented_chain.reserve(stack.len());
            for c in &stack {
                let der = c
                    .to_der()
                    .map_err(|e| Pkcs12Error::Corrupt(e.to_string()))?;
                let parsed = Certificate::from_der(&der)
                    .map_err(|e| Pkcs12Error::Corrupt(format!("chain cert: {e}")))?;
                presented_chain.push(parsed);
            }
        }

        let key_der = pkey
            .private_key_to_pkcs8()
            .map_err(|e| Pkcs12Error::Corrupt(e.to_string()))?;

        Ok(Self {
            end_entity,
            presented_chain,
            key: Zeroizing::new(key_der),
        })
    }

    /// Materialise the private key as an OpenSSL handle.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs12Error::Corrupt`] if the stored PKCS#8 DER is rejected by
    /// OpenSSL (which would indicate memory corruption — the bytes were
    /// produced by OpenSSL itself in [`Self::from_p12`]).
    pub fn private_key(&self) -> Result<PKey<Private>, Pkcs12Error> {
        PKey::private_key_from_pkcs8(&self.key).map_err(|e| Pkcs12Error::Corrupt(e.to_string()))
    }
}

/// Map an OpenSSL `parse2` error stack into [`Pkcs12Error`].
///
/// OpenSSL 0.10 surfaces wrong-PIN failures as `mac verify failure` (modern
/// OpenSSL 3.x) or `wrong password` / `bad decrypt` (older 1.1.x).  Any other
/// message is treated as structural corruption — retrying the PIN will not
/// help and the caller should bail out.
fn classify_parse_error(e: &openssl::error::ErrorStack) -> Pkcs12Error {
    let raw = e.to_string();
    let lc = raw.to_lowercase();
    if lc.contains("mac verify")
        || lc.contains("wrong password")
        || lc.contains("bad decrypt")
        || lc.contains("invalid mac")
    {
        Pkcs12Error::WrongPin
    } else {
        Pkcs12Error::Corrupt(raw)
    }
}

/// Pre-parse the outer ASN.1 envelope of a PKCS#12 buffer **without**
/// using the password.
///
/// Used to detect the "this is not actually a PKCS#12 file" case — for
/// example a foreign file on a multi-partition USB device whose name
/// happens to match `pkcs12_path_pattern` (a common collision on
/// Apple-formatted media).  When this succeeds the caller may still fail
/// later in [`LoadedKeyMaterial::from_p12`] (wrong PIN, MAC verify, ...)
/// — those failures are the password-dependent boundary and must remain
/// fail-closed.  When *this* fails, however, no password has been touched
/// yet, so the caller can safely try the next USB partition without
/// creating a PIN-oracle.
///
/// # Errors
///
/// Returns [`P12EnvelopeError::Asn1`] when the bytes do not decode as a
/// valid PKCS#12 ASN.1 envelope (random data, truncated bundle, empty
/// buffer, foreign file with a coincidentally matching name).
pub fn validate_p12_envelope(bytes: &[u8]) -> Result<(), P12EnvelopeError> {
    // `Pkcs12::from_der` runs `d2i_PKCS12` which validates the outer
    // ASN.1 structure but does NOT verify the MAC nor try to decrypt
    // anything — exactly the boundary we want.
    Pkcs12::from_der(bytes)
        .map(|_| ())
        .map_err(|e| P12EnvelopeError::Asn1(e.to_string()))
}

/// Attempt to extract the end-entity certificate from a PKCS#12 buffer
/// **without** a password.
///
/// Newer issuance tooling (`issue-service-cert.sh` v2 and later)
/// places the leaf certificate in an unencrypted `SafeBag` so an admin
/// can inspect host/user bindings without the PIN. When that layout is
/// present this returns `Some(Certificate)`; when the cert is encrypted
/// (legacy bundles) or the bundle is malformed it returns `None`.
///
/// Used by the PAM flow to enrich the "wrong PIN" diagnostic with the
/// host/user the cert was issued for — strictly best-effort. The cert
/// is NOT validated against any trust anchor; it is only parsed enough
/// to read its extensions for display.
#[must_use]
pub fn try_extract_cert_without_pin(bytes: &[u8]) -> Option<Certificate> {
    let p12 = Pkcs12::from_der(bytes).ok()?;
    let parsed = p12.parse2("").ok()?;
    let cert = parsed.cert?;
    let der = cert.to_der().ok()?;
    Certificate::from_der(&der).ok()
}

/// PIN prompt used when the operator did not configure
/// `pkcs12_pin_prompt`.
pub const DEFAULT_PKCS12_PIN_PROMPT: &str = "Smart-card PIN: ";

/// Bounded PIN-retry loop.
///
/// Calls `prompter` up to `max_tries` times.  Each prompt's result is fed to
/// [`LoadedKeyMaterial::from_p12`].  On [`Pkcs12Error::WrongPin`] the loop
/// continues; on any other parse error it bails out immediately.  When all
/// attempts are exhausted, returns [`AcquireError::MaxTries`] so the PAM layer
/// can map it to `PAM_MAXTRIES`.
///
/// `prompt` is the user-facing PIN prompt (the operator-configured
/// `pkcs12_pin_prompt`); `None` falls back to
/// [`DEFAULT_PKCS12_PIN_PROMPT`].  The prompter receives the string
/// verbatim on every attempt.
///
/// `max_tries == 0` returns `MaxTries` without invoking the prompter.
///
/// # Errors
///
/// * [`AcquireError::Conv`] — the PAM conv layer failed (propagated).
/// * [`AcquireError::MaxTries`] — every attempt returned `WrongPin`.
/// * [`AcquireError::Corrupt`] / [`AcquireError::Missing`] — the bundle is
///   structurally broken and retrying will not help.
pub fn acquire_p12_material_with_prompter<F>(
    bytes: &[u8],
    max_tries: u8,
    prompt: Option<&str>,
    mut prompter: F,
) -> Result<LoadedKeyMaterial, AcquireError>
where
    F: FnMut(&str) -> Result<SecretString, PamConvError>,
{
    let prompt = prompt.unwrap_or(DEFAULT_PKCS12_PIN_PROMPT);
    for _ in 0..max_tries {
        let pin = prompter(prompt)?;
        match LoadedKeyMaterial::from_p12(bytes, &pin) {
            Ok(m) => return Ok(m),
            Err(Pkcs12Error::WrongPin) => {
                tracing::debug!(target: "tessera.pkcs12", "pkcs12_pin_invalid");
            }
            Err(Pkcs12Error::MissingKey) => return Err(AcquireError::Missing("key")),
            Err(Pkcs12Error::MissingCert) => return Err(AcquireError::Missing("cert")),
            Err(Pkcs12Error::Corrupt(m)) => return Err(AcquireError::Corrupt(m)),
        }
    }
    Err(AcquireError::MaxTries)
}

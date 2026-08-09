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
mod unencrypted;

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
/// Issuance places the leaf certificate and its chain in an unencrypted safe so
/// that a reader without the PIN can still see who the container was issued
/// for. This walks that safe directly — the container's `AuthenticatedSafe`,
/// its `id-data` sections, their certificate bags — because the container's key
/// is encrypted in every issuance and a reader that goes through
/// `PKCS12_parse` stops at that key without returning the certificates it
/// already recovered.
///
/// No password is consulted anywhere on this path and no key material is
/// interpreted. A shrouded key bag is recognised by its bag identifier and its
/// content dropped; what the ASN.1 decoder copies of it along the way is the
/// still-encrypted blob, which without the password is no more than opaque
/// bytes. The `unencrypted` module states exactly what the walk touches.
///
/// Returns `None` when the container keeps its certificates encrypted (bundles
/// of the older layout), when it carries no end-entity certificate, when more
/// than one of its certificates could be the end-entity, or when the bytes are
/// malformed. That is a normal outcome — the caller loses the
/// diagnostic, not the login.
///
/// Used by the PAM flow to enrich the "wrong PIN" diagnostic with the
/// host/user the cert was issued for — strictly best-effort. The cert
/// is NOT validated against any trust anchor; it is only parsed enough
/// to read its extensions for display, and it does not enter the
/// authentication decision.
#[must_use]
pub fn try_extract_cert_without_pin(bytes: &[u8]) -> Option<Certificate> {
    select_end_entity(&unencrypted::certificates_in_clear(bytes))
}

/// The certificate of a container that carries exactly one in the clear.
///
/// For the caller that does not display a certificate but *records* it — the
/// enrollment report and its `device_enrolled` audit event. There the name has
/// to be the certificate the device will authenticate with, and
/// [`try_extract_cert_without_pin`] cannot promise that: it picks the single
/// non-CA certificate, while the authentication path lets OpenSSL follow the
/// key's `localKeyID`, and on a container whose CA precedes its leaf the two
/// answers differ. An audit record naming a certificate the device never
/// authenticates with is worse than one naming none.
///
/// A container holding a single certificate leaves the two rules nothing to
/// disagree about, so that is the only shape answered here. Anything else — a
/// leaf with its chain beside it, a container whose certificates are encrypted,
/// malformed bytes — yields `None`, and the caller records nothing.
///
/// The certificates this can see are those in the clear; one kept in an
/// encrypted safe stays invisible to it, as it does to every part of this
/// module. No password is consulted and the certificate is not validated
/// against any trust anchor.
#[must_use]
pub fn try_extract_sole_cert_without_pin(bytes: &[u8]) -> Option<Certificate> {
    match unencrypted::certificates_in_clear(bytes).as_slice() {
        [only] => Certificate::from_der(only).ok(),
        _ => None,
    }
}

/// The one non-CA certificate a container carries, if there is exactly one.
///
/// A container holds the leaf together with the CAs above it, so "the first
/// bag" is the wrong answer whenever the writer put the chain first. The rule
/// applied here is this path's own and deliberately conservative: a certificate
/// is named only when a single one of the readable certificates is not a CA
/// (an absent `basicConstraints` means `cA = FALSE`, per RFC 5280). Zero
/// candidates, or two and more, yield `None` and the caller falls back to its
/// generic message.
///
/// This rule is *not* the one [`LoadedKeyMaterial::from_p12`] applies. OpenSSL
/// picks the certificate whose `localKeyID` matches the container's key, which
/// on a container carrying two non-CA certificates — a foreign drive, a
/// mis-issued bundle, two issuances concatenated — can be a different one.
/// Matching that would mean reading the key bag's attributes, and the whole
/// point of this path is not to touch the key bag at all. Naming a certificate
/// only when the choice is unambiguous keeps the diagnostic from confidently
/// pointing an engineer at the wrong device, which is the very mistake it
/// exists to prevent.
///
/// Certificates that do not parse, and those whose `basicConstraints` do not
/// decode, are passed over: a container may carry a bag this Engine cannot
/// read, and that is no reason to lose the diagnostic carried by the others.
fn select_end_entity(ders: &[Vec<u8>]) -> Option<Certificate> {
    let mut candidate = None;
    for der in ders {
        let Ok(cert) = Certificate::from_der(der) else {
            continue;
        };
        let Ok(bc) = cert.basic_constraints() else {
            continue;
        };
        if bc.is_some_and(|bc| bc.is_ca) {
            continue;
        }
        if candidate.is_some() {
            return None;
        }
        candidate = Some(cert);
    }
    candidate
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// DER of a committed PEM fixture.
    fn fixture_der(name: &str) -> Vec<u8> {
        let pem = std::fs::read(format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture is committed under tests/fixtures");
        openssl::x509::X509::from_pem(&pem)
            .expect("fixture is a certificate")
            .to_der()
            .expect("a parsed certificate re-encodes")
    }

    /// A self-signed certificate with no `basicConstraints` extension at all.
    ///
    /// Absent means `cA = FALSE` (RFC 5280), and a container written by a
    /// foreign tool may well leave the extension out — no committed fixture
    /// does, so this one is minted here.
    fn without_basic_constraints(cn: &str) -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    fn cn_of(cert: &Certificate) -> String {
        cert.subject_cn().expect("the fixtures carry a CN")
    }

    #[test]
    fn the_single_non_ca_is_the_end_entity() {
        let certs = vec![fixture_der("leaf_rsa.pem"), fixture_der("int.pem")];
        let picked = select_end_entity(&certs).expect("one non-CA is unambiguous");
        assert_eq!(cn_of(&picked), "alice");
    }

    #[test]
    fn a_ca_written_before_the_leaf_does_not_take_its_place() {
        let certs = vec![
            fixture_der("ca.pem"),
            fixture_der("int.pem"),
            fixture_der("leaf_rsa.pem"),
        ];
        let picked = select_end_entity(&certs).expect("one non-CA is unambiguous");
        assert_eq!(cn_of(&picked), "alice");
    }

    #[test]
    fn two_non_ca_certificates_name_nobody() {
        // A foreign drive, a mis-issue or two bundles concatenated: naming
        // either one would send an engineer to check the wrong device.
        let certs = vec![
            fixture_der("leaf_rsa.pem"),
            fixture_der("int.pem"),
            fixture_der("leaf_ecdsa.pem"),
        ];
        assert!(select_end_entity(&certs).is_none());
    }

    #[test]
    fn two_certificates_without_basic_constraints_name_nobody() {
        let certs = vec![
            without_basic_constraints("first"),
            without_basic_constraints("second"),
        ];
        assert!(select_end_entity(&certs).is_none());
    }

    #[test]
    fn a_certificate_without_basic_constraints_counts_as_the_end_entity() {
        let certs = vec![without_basic_constraints("alone"), fixture_der("ca.pem")];
        let picked = select_end_entity(&certs).expect("an absent extension means cA = FALSE");
        assert_eq!(cn_of(&picked), "alone");
    }

    #[test]
    fn a_container_of_cas_only_names_nobody() {
        let certs = vec![fixture_der("ca.pem"), fixture_der("int.pem")];
        assert!(select_end_entity(&certs).is_none());
    }

    #[test]
    fn nothing_at_all_names_nobody() {
        assert!(select_end_entity(&[]).is_none());
    }

    #[test]
    fn certificates_that_do_not_parse_are_passed_over() {
        let certs = vec![
            b"not a certificate".to_vec(),
            Vec::new(),
            fixture_der("leaf_rsa.pem"),
        ];
        let picked = select_end_entity(&certs).expect("the readable one still decides");
        assert_eq!(cn_of(&picked), "alice");
    }
}

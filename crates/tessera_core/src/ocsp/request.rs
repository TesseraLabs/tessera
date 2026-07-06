//! `OCSPRequest` building: `CertID` by issuer plus an RFC 8954 nonce.

use crate::error::TrustError;
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspRequest};
use openssl::x509::X509Ref;

/// Nonce length in bytes.  RFC 8954 allows 1..=32 octets and recommends
/// at least 16; we always send the maximum.
pub const OCSP_NONCE_LEN: usize = 32;

/// A fully built `OCSPRequest`, ready to POST to the responder.
///
/// Holds the DER encoding (`CertID` single request + nonce extension) and the
/// raw nonce bytes.  The nonce comparison against the response is performed
/// structurally over the DER (see [`crate::ocsp::response`]), not by callers
/// inspecting [`Self::nonce`]; the accessor exists for audit/diagnostics.
pub struct OcspRequestData {
    der: Vec<u8>,
    nonce: [u8; OCSP_NONCE_LEN],
}

impl std::fmt::Debug for OcspRequestData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspRequestData")
            .field("der_len", &self.der.len())
            .finish_non_exhaustive()
    }
}

impl OcspRequestData {
    /// Builds an `OCSPRequest` for `subject`, identified relative to its
    /// `issuer`, with a fresh random nonce.
    ///
    /// The `CertID` hash is SHA-1.  That is deliberate and safe: per RFC 6960
    /// the `CertID` digest is a *lookup identifier* the responder uses to find
    /// the certificate record (issuer name/key hash + serial), not a trust
    /// decision — authenticity of the answer rests entirely on the response
    /// signature, which is verified separately.  Responders overwhelmingly
    /// index their records by SHA-1 `CertIDs`, so SHA-1 maximises
    /// interoperability without weakening anything.
    ///
    /// # Errors
    ///
    /// * [`TrustError::OcspRequestBuild`] when any OpenSSL primitive fails
    ///   (`CertID` construction, DER encoding, RNG, nonce attachment).
    pub fn build(subject: &X509Ref, issuer: &X509Ref) -> Result<Self, TrustError> {
        let cert_id =
            OcspCertId::from_cert(MessageDigest::sha1(), subject, issuer).map_err(|e| {
                TrustError::OcspRequestBuild {
                    reason: format!("CertID: {e}"),
                }
            })?;
        let mut request = OcspRequest::new().map_err(|e| TrustError::OcspRequestBuild {
            reason: format!("OCSP_REQUEST_new: {e}"),
        })?;
        request
            .add_id(cert_id)
            .map_err(|e| TrustError::OcspRequestBuild {
                reason: format!("add_id: {e}"),
            })?;
        let bare_der = request.to_der().map_err(|e| TrustError::OcspRequestBuild {
            reason: format!("request DER encode: {e}"),
        })?;
        let mut nonce = [0_u8; OCSP_NONCE_LEN];
        openssl::rand::rand_bytes(&mut nonce).map_err(|e| TrustError::OcspRequestBuild {
            reason: format!("nonce RNG: {e}"),
        })?;
        let der = super::sys::request_add_nonce(&bare_der, &nonce)
            .map_err(|reason| TrustError::OcspRequestBuild { reason })?;
        Ok(Self { der, nonce })
    }

    /// DER encoding of the request (`CertID` + nonce extension).
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Raw nonce bytes embedded in [`Self::der`].
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::{OcspRequestData, OCSP_NONCE_LEN};
    use openssl::ocsp::OcspRequest;
    use openssl::x509::X509;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn load_cert(name: &str) -> X509 {
        let pem = std::fs::read(fixture_path(name)).expect("fixture readable");
        X509::from_pem(&pem).expect("fixture parses")
    }

    fn assert_request_well_formed(data: &OcspRequestData) {
        assert!(!data.der().is_empty());
        assert_eq!(data.nonce().len(), OCSP_NONCE_LEN);
        // The DER must remain a parseable OCSPRequest after the nonce
        // extension was spliced in.
        OcspRequest::from_der(data.der()).expect("request DER round-trips");
        // The raw nonce value is embedded verbatim inside the nonce
        // extension's OCTET STRING, so it must appear in the encoding.
        let der = data.der();
        let nonce = data.nonce();
        assert!(
            der.windows(nonce.len()).any(|w| w == nonce),
            "nonce bytes not found in request DER"
        );
    }

    #[test]
    fn builds_request_for_rsa_issuer() {
        let subject = load_cert("leaf_rsa.pem");
        let issuer = load_cert("int.pem");
        let data = OcspRequestData::build(&subject, &issuer).expect("build");
        assert_request_well_formed(&data);
    }

    #[test]
    fn builds_request_for_ecdsa_subject() {
        let subject = load_cert("leaf_ecdsa.pem");
        let issuer = load_cert("int.pem");
        let data = OcspRequestData::build(&subject, &issuer).expect("build");
        assert_request_well_formed(&data);
    }

    #[test]
    fn consecutive_requests_use_fresh_nonces() {
        let subject = load_cert("leaf_rsa.pem");
        let issuer = load_cert("int.pem");
        let a = OcspRequestData::build(&subject, &issuer).expect("build a");
        let b = OcspRequestData::build(&subject, &issuer).expect("build b");
        assert_ne!(a.nonce(), b.nonce());
        assert_ne!(a.der(), b.der());
    }

    /// GOST issuer: `CertID` hashing uses SHA-1 over name/key bytes, so no
    /// gost-engine is needed to *build* the request.  Gated because the
    /// GOST fixtures (`tests/fixtures/gost/`, produced by `gen_gost.sh` on
    /// a Linux host with gost-engine) may be absent locally; the test then
    /// skips instead of failing.
    #[test]
    #[cfg(feature = "gost-tests")]
    fn builds_request_for_gost_issuer() {
        let subject_path = fixture_path("gost/gost_ee_256.pem");
        let issuer_path = fixture_path("gost/gost_ca_256.pem");
        if !subject_path.exists() || !issuer_path.exists() {
            eprintln!("skipped: GOST fixtures not present (run tests/fixtures/gen_gost.sh)");
            return;
        }
        let subject = load_cert("gost/gost_ee_256.pem");
        let issuer = load_cert("gost/gost_ca_256.pem");
        let data = OcspRequestData::build(&subject, &issuer).expect("build");
        assert_request_well_formed(&data);
    }
}

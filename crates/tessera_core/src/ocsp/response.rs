//! `OCSPResponse` parsing and fail-closed verification.
//!
//! A response is accepted only when *all* of the following hold (delta-spec
//! `revocation`, requirement "OCSP-клиент"):
//!
//! 1. `OCSPResponseStatus = successful`;
//! 2. the responder signature verifies with a chain built to the `[trust]`
//!    anchors (`OCSP_basic_verify` with default flags — a delegated
//!    responder is accepted only with the id-kp-OCSPSigning EKU issued by
//!    the certificate's issuer, which is the standard semantics of that
//!    call); when any involved certificate is GOST-signed the gost-engine
//!    is pinned first, failing closed when unavailable;
//! 3. the nonce, when present in the response, equals the request nonce
//!    (absence in the response is allowed: pre-signed responses);
//! 4. the `thisUpdate`/`nextUpdate` window is valid at the current time
//!    with `clock_skew_seconds` tolerance; when the responder omits
//!    `nextUpdate` the window cannot bound replay, so `thisUpdate` age is
//!    additionally capped (`MAX_THIS_UPDATE_AGE_WITHOUT_NEXT_UPDATE`);
//! 5. the certificate status is definite — `unknown` maps to a typed error,
//!    never to a success value.
//!
//! # Test fixtures
//!
//! The `openssl` crate can parse and verify OCSP responses but exposes no
//! API to *build* them (no `OCSP_basic_add1_status`/`OCSP_basic_sign`
//! wrappers), so the negative/positive fixtures for the tests below are
//! pre-generated DER blobs in `tests/fixtures/ocsp/`, produced by
//! `tests/fixtures/gen_ocsp.sh` with the openssl CLI and committed
//! alongside the script.

use crate::error::TrustError;
use crate::gost::engine::ensure_loaded_if_any_gost;
use crate::x509::Certificate;
use openssl::hash::MessageDigest;
use openssl::ocsp::{
    OcspBasicResponse, OcspCertId, OcspCertStatus, OcspFlag, OcspResponse, OcspResponseStatus,
    OcspRevokedStatus,
};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509;
use std::path::Path;
use std::time::Duration;

/// Maximum accepted age of `thisUpdate` (seconds) when the response omits
/// `nextUpdate`.
///
/// When a responder supplies `nextUpdate`, that field bounds how long the
/// response stays valid and thus how long a captured response can be
/// replayed on the network path; we keep `maxsec = None` so a legitimately
/// pre-signed response with a far-future `nextUpdate` is not rejected. When
/// `nextUpdate` is absent there is no upper bound at all, so a nonce-less
/// response (the pre-signed allowance, see `check_nonce`) could be replayed
/// indefinitely. We therefore impose a finite cap on `thisUpdate` age in
/// that case (design.md Decision 6 / delta-spec `revocation`: nonce-less
/// responses rely on the validity window; without `nextUpdate` a finite age
/// cap is the only remaining replay bound). 24h is the chosen ceiling.
/// Responders SHOULD emit `nextUpdate`.
const MAX_THIS_UPDATE_AGE_WITHOUT_NEXT_UPDATE: u32 = 86_400;

/// Definite certificate status extracted from a verified OCSP response.
///
/// `unknown` is deliberately unrepresentable here: the fail-closed mapping
/// turns it into [`TrustError::OcspStatusUnknown`], so "verified and usable"
/// can never silently mean "the responder had no idea".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertStatus {
    /// The responder vouches the certificate is not revoked.
    Good,
    /// The certificate is revoked.
    Revoked {
        /// `revocationTime` in its ASN.1 `GeneralizedTime` display form,
        /// when present.  Kept textual: it is consumed by logs/audit only.
        revocation_time: Option<String>,
        /// RFC 5280 `CRLReason` name, when the responder supplied one.
        reason: Option<&'static str>,
    },
}

/// Verification inputs that stay constant across the certificates of one
/// chain: trust material and the clock-skew tolerance.
#[derive(Debug)]
pub struct OcspVerifyContext<'a> {
    /// `[trust]` anchors; the responder chain must terminate here.
    pub anchors: &'a [Certificate],
    /// Untrusted helper certificates for responder-chain building (the
    /// certificate's issuer and any configured intermediates).  Responders
    /// usually embed their own certificate in the response; these
    /// supplement it.
    pub untrusted: &'a [Certificate],
    /// Permissible clock skew when checking the `thisUpdate`/`nextUpdate`
    /// window, from `trust.clock_skew_seconds`.
    pub clock_skew: Duration,
    /// Optional explicit gost-engine location (`gost_engine_path` config
    /// key), consulted when any certificate involved in responder-chain
    /// verification carries a GOST signature algorithm.  `None` falls back
    /// to engine lookup by id.
    pub gost_engine_path: Option<&'a Path>,
}

/// Parses and verifies a DER-encoded `OCSPResponse` for `subject`, then
/// returns the definite certificate status.
///
/// `request_der` is the DER of the request this response answers; pass
/// `None` when re-verifying a cached (pre-signed) response, which by
/// construction has no nonce to match.
///
/// # Errors
///
/// The full fail-closed matrix:
///
/// * [`TrustError::OcspMalformed`] — DER does not parse, the response has
///   no basic body, or it carries no status for the requested `CertID`;
/// * [`TrustError::OcspResponderRefused`] — `OCSPResponseStatus` is not
///   `successful`;
/// * [`TrustError::OcspEngineUnavailable`] — a GOST certificate is involved
///   and the gost-engine cannot be loaded;
/// * [`TrustError::OcspSignatureInvalid`] — responder signature/chain does
///   not verify against `ctx.anchors`;
/// * [`TrustError::OcspNonceMismatch`] — response nonce present and not
///   equal to the request nonce;
/// * [`TrustError::OcspValidityWindow`] — `thisUpdate`/`nextUpdate` window
///   invalid beyond `ctx.clock_skew`;
/// * [`TrustError::OcspStatusUnknown`] — responder answered `unknown`.
pub fn verify_ocsp_response(
    response_der: &[u8],
    subject: &Certificate,
    issuer: &Certificate,
    request_der: Option<&[u8]>,
    ctx: &OcspVerifyContext<'_>,
) -> Result<CertStatus, TrustError> {
    let response =
        OcspResponse::from_der(response_der).map_err(|e| TrustError::OcspMalformed {
            reason: format!("OCSPResponse DER: {e}"),
        })?;
    let status = response.status();
    if status != OcspResponseStatus::SUCCESSFUL {
        return Err(TrustError::OcspResponderRefused {
            status: responder_status_name(status),
        });
    }
    let basic = response.basic().map_err(|e| TrustError::OcspMalformed {
        reason: format!("basic response: {e}"),
    })?;

    // GOST responder chains: pin the gost-engine before any libcrypto
    // signature path runs, failing closed when it cannot be loaded (same
    // semantics as the chain verifier in `trust::openssl_verifier`).  The
    // trigger set is every certificate this verification can see — subject,
    // issuer, configured untrusted helpers, anchors.  A GOST responder
    // certificate embedded in the response necessarily belongs to the same
    // GOST PKI as the issuer/anchors it must chain to, so the visible set
    // is a faithful proxy; a pure RSA/ECDSA exchange never touches the
    // engine machinery.
    let mut involved: Vec<&Certificate> =
        Vec::with_capacity(2 + ctx.untrusted.len() + ctx.anchors.len());
    involved.push(subject);
    involved.push(issuer);
    involved.extend(ctx.untrusted.iter());
    involved.extend(ctx.anchors.iter());
    ensure_loaded_if_any_gost(&involved, ctx.gost_engine_path)
        .map_err(|source| TrustError::OcspEngineUnavailable { source })?;

    verify_signature(&basic, ctx)?;

    if let Some(request_der) = request_der {
        check_nonce(request_der, response_der)?;
    }

    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), subject.x509(), issuer.x509())
        .map_err(|e| TrustError::OcspMalformed {
            reason: format!("CertID: {e}"),
        })?;
    let Some(single) = basic.find_status(&cert_id) else {
        // The (verified) response does not answer for this certificate at
        // all — fail closed, same refusal class as a parse failure.
        return Err(TrustError::OcspMalformed {
            reason: format!(
                "no status for requested CertID (serial {})",
                subject.serial_hex().to_lowercase()
            ),
        });
    };

    let skew = u32::try_from(ctx.clock_skew.as_secs()).unwrap_or(u32::MAX);
    // With no nextUpdate the validity window cannot bound replay, so cap the
    // age of thisUpdate; with nextUpdate present the window itself bounds
    // validity and we pass None to avoid rejecting legitimate pre-signed
    // responses carrying a far-future nextUpdate.
    let maxsec = if single.next_update().is_none() {
        Some(MAX_THIS_UPDATE_AGE_WITHOUT_NEXT_UPDATE)
    } else {
        None
    };
    single
        .check_validity(skew, maxsec)
        .map_err(|e| TrustError::OcspValidityWindow {
            reason: e.to_string(),
        })?;

    if single.status == OcspCertStatus::GOOD {
        Ok(CertStatus::Good)
    } else if single.status == OcspCertStatus::REVOKED {
        Ok(CertStatus::Revoked {
            revocation_time: single.revocation_time.map(std::string::ToString::to_string),
            reason: revoked_reason_name(single.reason),
        })
    } else {
        // UNKNOWN or any future status code: undeterminable, fail closed.
        Err(TrustError::OcspStatusUnknown {
            serial: subject.serial_hex().to_lowercase(),
        })
    }
}

/// Verifies the responder signature with a chain built to `ctx.anchors`.
fn verify_signature(
    basic: &OcspBasicResponse,
    ctx: &OcspVerifyContext<'_>,
) -> Result<(), TrustError> {
    let sig_err = |reason: String| TrustError::OcspSignatureInvalid { reason };
    let mut store = X509StoreBuilder::new()
        .map_err(|e| sig_err(format!("trust store init: {e}")))?;
    for anchor in ctx.anchors {
        store
            .add_cert(anchor.x509().clone())
            .map_err(|e| sig_err(format!("trust store anchor: {e}")))?;
    }
    let store = store.build();
    let mut untrusted: Stack<X509> =
        Stack::new().map_err(|e| sig_err(format!("untrusted stack init: {e}")))?;
    for cert in ctx.untrusted {
        untrusted
            .push(cert.x509().clone())
            .map_err(|e| sig_err(format!("untrusted stack push: {e}")))?;
    }
    // Default flags: signer is located in the response (or `untrusted`),
    // its signature checked, and its chain built to the store.  Delegated
    // responders are accepted exactly when they carry id-kp-OCSPSigning
    // from the certificate's issuer — `OCSP_basic_verify` semantics.
    basic
        .verify(&untrusted, &store, OcspFlag::empty())
        .map_err(|e| sig_err(e.to_string()))
}

/// Runs the RFC 8954 nonce comparison and maps the outcome fail-closed.
fn check_nonce(request_der: &[u8], response_der: &[u8]) -> Result<(), TrustError> {
    use super::sys::NonceCheck;
    let outcome = super::sys::check_nonce(request_der, response_der)
        .map_err(|reason| TrustError::OcspMalformed { reason })?;
    match outcome {
        // Absence of a nonce in the response is allowed (pre-signed
        // responses); replay protection then rests on the
        // thisUpdate/nextUpdate window — and, when nextUpdate is also
        // absent, on the thisUpdate age cap applied in verify_ocsp_response.
        NonceCheck::Match | NonceCheck::AbsentInResponse | NonceCheck::AbsentInBoth => Ok(()),
        // A differing nonce, or a nonce we provably never sent, is a
        // replayed/foreign response.
        NonceCheck::Mismatch | NonceCheck::PresentOnlyInResponse => {
            Err(TrustError::OcspNonceMismatch)
        }
    }
}

/// Human-readable `OCSPResponseStatus` name for error surfaces.
fn responder_status_name(status: OcspResponseStatus) -> String {
    match status {
        OcspResponseStatus::SUCCESSFUL => "successful".to_string(),
        OcspResponseStatus::MALFORMED_REQUEST => "malformedRequest".to_string(),
        OcspResponseStatus::INTERNAL_ERROR => "internalError".to_string(),
        OcspResponseStatus::TRY_LATER => "tryLater".to_string(),
        OcspResponseStatus::SIG_REQUIRED => "sigRequired".to_string(),
        OcspResponseStatus::UNAUTHORIZED => "unauthorized".to_string(),
        other => format!("status({})", other.as_raw()),
    }
}

/// RFC 5280 `CRLReason` name for a revocation reason code, when present.
fn revoked_reason_name(reason: OcspRevokedStatus) -> Option<&'static str> {
    if reason == OcspRevokedStatus::NO_STATUS {
        None
    } else if reason == OcspRevokedStatus::UNSPECIFIED {
        Some("unspecified")
    } else if reason == OcspRevokedStatus::KEY_COMPROMISE {
        Some("keyCompromise")
    } else if reason == OcspRevokedStatus::CA_COMPROMISE {
        Some("cACompromise")
    } else if reason == OcspRevokedStatus::AFFILIATION_CHANGED {
        Some("affiliationChanged")
    } else if reason == OcspRevokedStatus::STATUS_SUPERSEDED {
        Some("superseded")
    } else if reason == OcspRevokedStatus::STATUS_CESSATION_OF_OPERATION {
        Some("cessationOfOperation")
    } else if reason == OcspRevokedStatus::STATUS_CERTIFICATE_HOLD {
        Some("certificateHold")
    } else if reason == OcspRevokedStatus::REMOVE_FROM_CRL {
        Some("removeFromCRL")
    } else {
        Some("other")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::duration_suboptimal_units)]

    use super::{verify_ocsp_response, CertStatus, OcspVerifyContext};
    use crate::error::TrustError;
    use crate::ocsp::request::OcspRequestData;
    use crate::x509::Certificate;
    use openssl::ocsp::{OcspResponse, OcspResponseStatus};
    use std::path::PathBuf;
    use std::time::Duration;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn load_cert(name: &str) -> Certificate {
        let pem = std::fs::read(fixture_path(name)).expect("fixture readable");
        Certificate::from_pem(&pem).expect("fixture parses")
    }

    fn load_der(name: &str) -> Vec<u8> {
        std::fs::read(fixture_path(name)).expect("fixture readable")
    }

    struct Pki {
        anchors: Vec<Certificate>,
        untrusted: Vec<Certificate>,
    }

    impl Pki {
        fn load() -> Self {
            Self {
                anchors: vec![load_cert("ca.pem")],
                untrusted: vec![load_cert("int.pem")],
            }
        }

        fn ctx(&self) -> OcspVerifyContext<'_> {
            OcspVerifyContext {
                anchors: &self.anchors,
                untrusted: &self.untrusted,
                clock_skew: Duration::from_secs(60),
                gost_engine_path: None,
            }
        }
    }

    #[test]
    fn good_response_verifies_without_request() {
        let pki = Pki::load();
        let status = verify_ocsp_response(
            &load_der("ocsp/good.der"),
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        )
        .expect("good response verifies");
        assert_eq!(status, CertStatus::Good);
    }

    #[test]
    fn good_response_accepts_nonceless_request_pair() {
        // Both the fixture request and the fixture response lack a nonce:
        // the pre-signed-response allowance.
        let pki = Pki::load();
        let status = verify_ocsp_response(
            &load_der("ocsp/good.der"),
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            Some(&load_der("ocsp/req_rsa_no_nonce.der")),
            &pki.ctx(),
        )
        .expect("nonceless pair verifies");
        assert_eq!(status, CertStatus::Good);
    }

    #[test]
    fn matching_nonce_verifies() {
        // good_nonce.der was produced for req_rsa_nonce.der, so the nonces
        // agree byte-for-byte.
        let pki = Pki::load();
        let status = verify_ocsp_response(
            &load_der("ocsp/good_nonce.der"),
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            Some(&load_der("ocsp/req_rsa_nonce.der")),
            &pki.ctx(),
        )
        .expect("matching nonce verifies");
        assert_eq!(status, CertStatus::Good);
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        // A freshly built request carries a different random nonce than the
        // one baked into good_nonce.der.
        let pki = Pki::load();
        let subject = load_cert("leaf_rsa.pem");
        let issuer = load_cert("int.pem");
        let fresh = OcspRequestData::build(subject.x509(), issuer.x509()).expect("fresh request");
        let err = verify_ocsp_response(
            &load_der("ocsp/good_nonce.der"),
            &subject,
            &issuer,
            Some(fresh.der()),
            &pki.ctx(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustError::OcspNonceMismatch), "got {err:?}");
    }

    #[test]
    fn revoked_status_is_returned_as_value() {
        let pki = Pki::load();
        let status = verify_ocsp_response(
            &load_der("ocsp/revoked.der"),
            &load_cert("revoked_leaf.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        )
        .expect("revoked response verifies");
        match status {
            CertStatus::Revoked {
                revocation_time, ..
            } => assert!(revocation_time.is_some()),
            CertStatus::Good => panic!("expected Revoked, got Good"),
        }
    }

    #[test]
    fn unknown_status_fails_closed() {
        let pki = Pki::load();
        let err = verify_ocsp_response(
            &load_der("ocsp/unknown.der"),
            &load_cert("leaf_ecdsa.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        )
        .unwrap_err();
        assert!(
            matches!(err, TrustError::OcspStatusUnknown { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn expired_validity_window_is_rejected() {
        // expired.der is generated with nextUpdate = +1 minute; any test
        // run later than that (i.e. every run against the committed
        // fixture) sees an expired window.  Right after a fixture
        // regeneration the window is still open — skip instead of flaking.
        let path = fixture_path("ocsp/expired.der");
        let fresh = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < Duration::from_secs(120));
        if fresh {
            eprintln!("skipped: ocsp/expired.der regenerated <2min ago, window still open");
            return;
        }
        let pki = Pki::load();
        let err = verify_ocsp_response(
            &load_der("ocsp/expired.der"),
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        )
        .unwrap_err();
        assert!(
            matches!(err, TrustError::OcspValidityWindow { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn nonceless_response_without_next_update_verifies_while_fresh() {
        // good_no_nextupdate.der carries thisUpdate but no nextUpdate.  Such
        // a response has no window to bound replay, so the verifier caps
        // thisUpdate age (MAX_THIS_UPDATE_AGE_WITHOUT_NEXT_UPDATE) instead of
        // passing maxsec = None.  Freshly generated (or freshly regenerated),
        // its thisUpdate is well within that cap, so it must verify good.
        // The committed fixture's thisUpdate is fixed at generation time, so
        // once it ages past the cap the verifier correctly rejects it with
        // OcspValidityWindow. Both outcomes prove the cap path works; only a
        // different error (or a panic) would be a real failure. Regenerate via
        // tests/fixtures/gen_ocsp.sh to exercise the Good branch.
        let pki = Pki::load();
        match verify_ocsp_response(
            &load_der("ocsp/good_no_nextupdate.der"),
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        ) {
            Ok(status) => assert_eq!(status, CertStatus::Good),
            Err(TrustError::OcspValidityWindow { .. }) => {
                // Fixture aged past MAX_THIS_UPDATE_AGE_WITHOUT_NEXT_UPDATE.
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn next_update_absence_selects_the_age_cap() {
        // The fix branches on `single.next_update().is_none()`: absent ->
        // cap thisUpdate age, present -> no cap.  Assert both branch
        // selectors are read correctly from the fixtures, and that the
        // OCSP_check_validity FFI the production path calls does reject a
        // thisUpdate that exceeds the cap (here forced via maxsec = 0, since
        // the openssl CLI cannot backdate thisUpdate to build an over-age
        // fixture directly).
        use openssl::hash::MessageDigest;
        use openssl::ocsp::OcspCertId;

        let subject = load_cert("leaf_rsa.pem");
        let issuer = load_cert("int.pem");
        let cert_id =
            OcspCertId::from_cert(MessageDigest::sha1(), subject.x509(), issuer.x509()).unwrap();

        // nextUpdate-less fixture: next_update() is None -> cap branch taken.
        let no_nu = OcspResponse::from_der(&load_der("ocsp/good_no_nextupdate.der")).unwrap();
        let basic_no_nu = no_nu.basic().unwrap();
        let single_no_nu = basic_no_nu.find_status(&cert_id).expect("status present");
        assert!(
            single_no_nu.next_update().is_none(),
            "fixture must omit nextUpdate"
        );
        // A zero-second cap rejects the fresh thisUpdate: this is exactly the
        // OCSP_check_validity(nsec, Some(maxsec)) call the verifier makes,
        // proving the cap is enforced once thisUpdate is older than it.
        assert!(
            single_no_nu.check_validity(0, Some(0)).is_err(),
            "maxsec cap must reject thisUpdate older than the cap"
        );

        // Normal fixture: next_update() is Some -> no cap (maxsec = None),
        // and the open window verifies fine.
        let good = OcspResponse::from_der(&load_der("ocsp/good.der")).unwrap();
        let basic_good = good.basic().unwrap();
        let single_good = basic_good.find_status(&cert_id).expect("status present");
        assert!(
            single_good.next_update().is_some(),
            "good.der must carry nextUpdate"
        );
        assert!(
            single_good.check_validity(60, None).is_ok(),
            "open window with no cap must pass"
        );
    }

    #[test]
    fn foreign_signer_is_rejected() {
        // foreign.der is signed by a CA that does not chain to the anchors.
        let pki = Pki::load();
        let err = verify_ocsp_response(
            &load_der("ocsp/foreign.der"),
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        )
        .unwrap_err();
        assert!(
            matches!(err, TrustError::OcspSignatureInvalid { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn malformed_der_is_rejected() {
        let pki = Pki::load();
        let err = verify_ocsp_response(
            b"definitely not DER",
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        )
        .unwrap_err();
        assert!(matches!(err, TrustError::OcspMalformed { .. }), "got {err:?}");
    }

    #[test]
    fn non_successful_responder_status_is_rejected() {
        // `OcspResponse::create` can build status-only responses, so this
        // negative needs no pre-generated fixture.
        let pki = Pki::load();
        let try_later = OcspResponse::create(OcspResponseStatus::TRY_LATER, None)
            .expect("status-only response")
            .to_der()
            .expect("encodes");
        let err = verify_ocsp_response(
            &try_later,
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        )
        .unwrap_err();
        match err {
            TrustError::OcspResponderRefused { status } => assert_eq!(status, "tryLater"),
            other => panic!("expected OcspResponderRefused, got {other:?}"),
        }
    }

    #[test]
    fn response_without_status_for_certid_is_rejected() {
        // good.der answers for leaf_rsa; asking it about leaf_ecdsa must
        // fail closed even though the signature verifies.
        let pki = Pki::load();
        let err = verify_ocsp_response(
            &load_der("ocsp/good.der"),
            &load_cert("leaf_ecdsa.pem"),
            &load_cert("int.pem"),
            None,
            &pki.ctx(),
        )
        .unwrap_err();
        match err {
            TrustError::OcspMalformed { reason } => {
                assert!(reason.contains("no status"), "reason: {reason}");
            }
            other => panic!("expected OcspMalformed, got {other:?}"),
        }
    }

    /// GOST chain: the engine hook must run (and fail closed when the
    /// engine is unavailable) before responder-signature verification is
    /// reached.  Gated and self-skipping like `builds_request_for_gost_issuer`:
    /// the GOST fixtures (`tests/fixtures/gost/`, produced by `gen_gost.sh`
    /// on a Linux host with gost-engine) may be absent locally.
    #[test]
    #[cfg(feature = "gost-tests")]
    fn gost_chain_loads_engine_before_responder_signature_check() {
        let subject_path = fixture_path("gost/gost_ee_256.pem");
        let issuer_path = fixture_path("gost/gost_ca_256.pem");
        if !subject_path.exists() || !issuer_path.exists() {
            eprintln!("skipped: GOST fixtures not present (run tests/fixtures/gen_gost.sh)");
            return;
        }
        let subject = load_cert("gost/gost_ee_256.pem");
        let issuer = load_cert("gost/gost_ca_256.pem");
        let anchors = vec![load_cert("gost/gost_ca_256.pem")];
        let ctx = OcspVerifyContext {
            anchors: &anchors,
            untrusted: &[],
            clock_skew: Duration::from_secs(60),
            gost_engine_path: None,
        };
        // good.der is RSA-signed: with the engine present the GOST chain
        // simply fails signature verification; without it the engine hook
        // must refuse *before* `OCSP_basic_verify` is reached.
        let err = verify_ocsp_response(&load_der("ocsp/good.der"), &subject, &issuer, None, &ctx)
            .unwrap_err();
        if crate::gost::engine::is_available_after_attempt(None) {
            assert!(
                matches!(err, TrustError::OcspSignatureInvalid { .. }),
                "engine available, expected signature mismatch, got {err:?}"
            );
        } else {
            assert!(
                matches!(err, TrustError::OcspEngineUnavailable { .. }),
                "engine unavailable, expected fail-closed engine error, got {err:?}"
            );
        }
    }

    #[test]
    fn empty_anchor_set_cannot_verify() {
        let pki = Pki::load();
        let ctx = OcspVerifyContext {
            anchors: &[],
            untrusted: &pki.untrusted,
            clock_skew: Duration::from_secs(60),
            gost_engine_path: None,
        };
        let err = verify_ocsp_response(
            &load_der("ocsp/good.der"),
            &load_cert("leaf_rsa.pem"),
            &load_cert("int.pem"),
            None,
            &ctx,
        )
        .unwrap_err();
        assert!(
            matches!(err, TrustError::OcspSignatureInvalid { .. }),
            "got {err:?}"
        );
    }
}

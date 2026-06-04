//! S11 regression: `Crl::verify_signature_with_issuer` engine wiring.
//!
//! RSA-issued CRLs must NOT cause the gost-engine `OnceLock` to be written
//! to.  No GOST-issued CRL fixture exists yet (those land in S15).

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use tessera_core::crl::Crl;
use tessera_core::gost::engine::is_available;
use tessera_core::x509::Certificate;

const INT: &[u8] = include_bytes!("fixtures/int.pem");
const CRL_VALID: &[u8] = include_bytes!("fixtures/crl_valid.pem");

#[test]
fn rsa_issued_crl_verify_does_not_load_engine() {
    let observed_before = is_available();

    // The fixture CRL is signed by the intermediate CA (which is RSA-signed
    // in turn — see the test fixture generation script).
    let int_cert = Certificate::from_pem(INT).unwrap();
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    crl.verify_signature_with_issuer(&int_cert, None).unwrap();

    let observed_after = is_available();
    assert_eq!(
        observed_before, observed_after,
        "engine state changed during an RSA-issued CRL verify",
    );
}

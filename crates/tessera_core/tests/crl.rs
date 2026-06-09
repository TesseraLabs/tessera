#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::duration_suboptimal_units)]

use tessera_core::crl::{check_revocation, Crl, CrlStore, RevocationConfig};
use tessera_core::x509::{Certificate, TrustError};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const REVOKED: &[u8] = include_bytes!("fixtures/revoked_leaf.pem");
const LEAF: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");
const INT_KEY: &[u8] = include_bytes!("fixtures/int.key");
const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const CRL_VALID: &[u8] = include_bytes!("fixtures/crl_valid.pem");
const CRL_FOREIGN: &[u8] = include_bytes!("fixtures/crl_foreign.pem");

fn chain(leaf_bytes: &[u8]) -> Vec<Certificate> {
    vec![
        Certificate::from_pem(leaf_bytes).unwrap(),
        Certificate::from_pem(INT).unwrap(),
        Certificate::from_pem(CA).unwrap(),
    ]
}

fn strict_cfg() -> RevocationConfig {
    RevocationConfig {
        crl_strict: true,
        ..RevocationConfig::default()
    }
}

fn lenient_cfg() -> RevocationConfig {
    RevocationConfig {
        crl_strict: false,
        ..RevocationConfig::default()
    }
}

// --- DER helpers for hand-built CRLs -------------------------------------

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![u8::try_from(len).unwrap()]
    } else if len < 0x100 {
        vec![0x81, u8::try_from(len).unwrap()]
    } else {
        vec![
            0x82,
            u8::try_from(len >> 8).unwrap(),
            u8::try_from(len & 0xff).unwrap(),
        ]
    }
}

fn der_seq(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// `sha256WithRSAEncryption` `AlgorithmIdentifier` (OID 1.2.840.113549.1.1.11 + NULL).
fn sha256_rsa_alg_id() -> Vec<u8> {
    der_seq(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ])
}

/// Builds a minimal v1 CRL DER *without* a `nextUpdate` field (openssl's CLI
/// cannot emit one), signed by the intermediate CA key from the fixtures.
fn crl_without_next_update() -> Crl {
    let int = Certificate::from_pem(INT).unwrap();
    let issuer_der = int.x509().subject_name().to_der().unwrap();

    let mut tbs_content = sha256_rsa_alg_id();
    tbs_content.extend_from_slice(&issuer_der);
    // thisUpdate: UTCTime 250101000000Z; nextUpdate intentionally absent.
    tbs_content.extend_from_slice(b"\x17\x0d250101000000Z");
    let tbs = der_seq(&tbs_content);

    let pkey = openssl::pkey::PKey::private_key_from_pem(INT_KEY).unwrap();
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
    signer.update(&tbs).unwrap();
    let sig = signer.sign_to_vec().unwrap();

    let mut crl_content = tbs;
    crl_content.extend_from_slice(&sha256_rsa_alg_id());
    crl_content.push(0x03); // BIT STRING
    crl_content.extend(der_len(sig.len() + 1));
    crl_content.push(0x00); // zero unused bits
    crl_content.extend_from_slice(&sig);
    let crl_der = der_seq(&crl_content);

    Crl::from_der(&crl_der).unwrap()
}

/// Re-encodes `crl_valid.pem` as DER and corrupts the trailing signature byte.
fn tampered_crl() -> Crl {
    let inner = openssl::x509::X509Crl::from_pem(CRL_VALID).unwrap();
    let mut der = inner.to_der().unwrap();
    let last = der.last_mut().unwrap();
    *last ^= 0xff;
    Crl::from_der(&der).unwrap()
}

/// Captures `tracing` output (WARN and up) emitted while running `f`.
fn capture_warnings<T>(f: impl FnOnce() -> T) -> (T, String) {
    #[derive(Clone)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }
    let buf = Buf(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_max_level(tracing::Level::WARN)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    let logs = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    (result, logs)
}

// --- parsing ---------------------------------------------------------------

#[test]
fn parses_crl_metadata() {
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    assert!(crl.this_update() <= crl.next_update());
    // Our gen.sh revokes serial 0x99 (mallory).
    assert!(crl
        .revoked_serials()
        .iter()
        .any(|s| s.eq_ignore_ascii_case("99")));
    assert!(!crl.issuer_dn_der().is_empty());
}

// --- revocation matching ----------------------------------------------------

#[test]
fn passes_unrevoked_chain() {
    // Also exercises the in-path CRL signature verification: crl_valid.pem is
    // genuinely signed by the intermediate present in the chain.
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    check_revocation(&chain(LEAF), &store, &strict_cfg(), SystemTime::now()).unwrap();
}

#[test]
fn rejects_revoked_cert() {
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let err =
        check_revocation(&chain(REVOKED), &store, &strict_cfg(), SystemTime::now()).unwrap_err();
    match err {
        TrustError::Revoked(serial) => {
            assert!(
                serial.eq_ignore_ascii_case("99"),
                "unexpected serial {serial}"
            )
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[test]
fn empty_store_is_noop() {
    let store = CrlStore::empty();
    check_revocation(&chain(LEAF), &store, &strict_cfg(), SystemTime::now()).unwrap();
}

#[test]
fn foreign_issuer_crl_does_not_revoke_matching_serial() {
    // crl_foreign.pem is signed by the *root* CA but lists serial 0x99 as
    // revoked.  revoked_leaf.pem is issued by the *intermediate* and also
    // carries serial 0x99.  Because the CRL issuer DN (root) does not match
    // the certificate issuer DN (intermediate), RFC 5280 § 6.3.3 says the
    // CRL is out of scope and must not revoke the leaf.
    let store = CrlStore::from_pems(&[CRL_FOREIGN]).unwrap();
    check_revocation(&chain(REVOKED), &store, &strict_cfg(), SystemTime::now()).unwrap();
}

// --- freshness (nextUpdate / crl_max_age) -----------------------------------

#[test]
fn strict_rejects_expired_crl() {
    // Our valid CRL has nextUpdate ~10y into the future. Pretend "now" is
    // eleven years ahead so the CRL appears expired.
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let future = SystemTime::now() + Duration::from_secs(11 * 365 * 24 * 3600);
    let err = check_revocation(&chain(LEAF), &store, &strict_cfg(), future).unwrap_err();
    assert!(matches!(err, TrustError::Crl(_)), "{err:?}");
}

#[test]
fn lenient_skips_expired_crl() {
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let future = SystemTime::now() + Duration::from_secs(11 * 365 * 24 * 3600);
    // No error: lenient mode logs and continues.
    check_revocation(&chain(LEAF), &store, &lenient_cfg(), future).unwrap();
}

#[test]
fn strict_rejects_crl_older_than_max_age() {
    // nextUpdate is ~10y away, but the configured max age (1h) is exceeded
    // 2h after thisUpdate — the CRL must be considered stale.
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    let now = crl.this_update() + Duration::from_secs(2 * 3600);
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let cfg = RevocationConfig {
        crl_max_age: Some(Duration::from_secs(3600)),
        ..strict_cfg()
    };
    let err = check_revocation(&chain(LEAF), &store, &cfg, now).unwrap_err();
    assert!(matches!(err, TrustError::Crl(_)), "{err:?}");
}

#[test]
fn lenient_skips_crl_older_than_max_age() {
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    let now = crl.this_update() + Duration::from_secs(2 * 3600);
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let cfg = RevocationConfig {
        crl_max_age: Some(Duration::from_secs(3600)),
        ..lenient_cfg()
    };
    // No error: lenient mode logs and continues — even a revoked serial is
    // not consulted because the stale CRL is skipped entirely.
    check_revocation(&chain(REVOKED), &store, &cfg, now).unwrap();
}

#[test]
fn crl_within_max_age_passes() {
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    let now = crl.this_update() + Duration::from_secs(1800);
    let store = CrlStore::from_pems(&[CRL_VALID]).unwrap();
    let cfg = RevocationConfig {
        crl_max_age: Some(Duration::from_secs(3600)),
        ..strict_cfg()
    };
    check_revocation(&chain(LEAF), &store, &cfg, now).unwrap();
}

#[test]
fn max_age_bounds_crl_without_next_update() {
    // A CRL with no nextUpdate is still bounded by crl_max_age.
    let crl = crl_without_next_update();
    let now = crl.this_update() + Duration::from_secs(2 * 3600);
    let store = CrlStore::from_crls(vec![crl]);
    let cfg = RevocationConfig {
        crl_max_age: Some(Duration::from_secs(3600)),
        ..strict_cfg()
    };
    let err = check_revocation(&chain(LEAF), &store, &cfg, now).unwrap_err();
    assert!(matches!(err, TrustError::Crl(_)), "{err:?}");
}

#[test]
fn no_next_update_and_no_max_age_warns_but_does_not_fail() {
    // Documented behaviour: freshness is unverifiable, so a warning is
    // logged on target tessera.crl, but authentication is not refused.
    let store = CrlStore::from_crls(vec![crl_without_next_update()]);
    let (result, logs) = capture_warnings(|| {
        check_revocation(&chain(LEAF), &store, &strict_cfg(), SystemTime::now())
    });
    result.unwrap();
    assert!(
        logs.contains("freshness cannot be verified"),
        "expected freshness warning, got: {logs}"
    );
}

// --- CRL signature verification ----------------------------------------------

#[test]
fn tampered_crl_signature_fails_closed() {
    // The CRL is in scope for the leaf (issuer DN matches the intermediate),
    // but its signature has been corrupted — the chain must be refused even
    // though the leaf's serial is not listed.
    let store = CrlStore::from_crls(vec![tampered_crl()]);
    let err = check_revocation(&chain(LEAF), &store, &strict_cfg(), SystemTime::now()).unwrap_err();
    assert!(matches!(err, TrustError::CrlSignatureInvalid(_)), "{err:?}");
}

#[test]
fn tampered_crl_signature_fails_closed_even_in_lenient_mode() {
    // crl_strict only governs freshness; an unauthentic CRL is always fatal.
    let store = CrlStore::from_crls(vec![tampered_crl()]);
    let err =
        check_revocation(&chain(LEAF), &store, &lenient_cfg(), SystemTime::now()).unwrap_err();
    assert!(matches!(err, TrustError::CrlSignatureInvalid(_)), "{err:?}");
}

#[test]
fn issuer_signed_crl_passes_in_path_verification() {
    // crl_valid.pem is signed by the intermediate; crl_foreign.pem by the
    // root.  Both issuers are present in the chain, so both signatures
    // verify and the unrevoked chain passes.
    let store = CrlStore::from_pems(&[CRL_VALID, CRL_FOREIGN]).unwrap();
    check_revocation(&chain(LEAF), &store, &strict_cfg(), SystemTime::now()).unwrap();
}

#[test]
fn crl_signature_validates_against_correct_issuer() {
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let pk = int.public_key().unwrap();
    crl.verify_signature(&pk).unwrap();
}

#[test]
fn crl_signature_rejects_wrong_key() {
    // CRL is signed by the intermediate.  Verifying it under the root
    // public key must fail.
    let crl = Crl::from_pem(CRL_VALID).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    let pk = ca.public_key().unwrap();
    let err = crl.verify_signature(&pk).unwrap_err();
    assert!(matches!(err, TrustError::CrlSignatureInvalid(_)), "{err:?}");
}

#[test]
fn foreign_crl_signature_validates_under_its_own_issuer() {
    // The foreign CRL is signed by the *root*. It should validate under
    // the root's key but not under the intermediate's.
    let crl = Crl::from_pem(CRL_FOREIGN).unwrap();
    let ca = Certificate::from_pem(CA).unwrap();
    crl.verify_signature(&ca.public_key().unwrap()).unwrap();
    let int = Certificate::from_pem(INT).unwrap();
    let err = crl
        .verify_signature(&int.public_key().unwrap())
        .unwrap_err();
    assert!(matches!(err, TrustError::CrlSignatureInvalid(_)), "{err:?}");
}

//! Integration tests for the revocation-mode dispatcher's OCSP path
//! (`ocsp` and `crl_then_ocsp` modes).
//!
//! A tiny in-process HTTP responder serves the pre-generated DER fixtures
//! (`tests/fixtures/ocsp/*.der`) chosen by the serial encoded in the
//! request's `CertID`.  The chain `[leaf, int, ca]` has two non-anchor
//! certificates (leaf and int), so the responder answers for both.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(missing_docs)]
#![allow(clippy::duration_suboptimal_units)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::let_underscore_must_use)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, SystemTime};

use tessera_core::config::validated::RevocationMode;
use tessera_core::ocsp::OcspUrl;
use tessera_core::trust::openssl_verifier::{OpensslVerifier, OpensslVerifierConfig};
use tessera_core::x509::{Certificate, TrustError};

const LEAF_RSA: &[u8] = include_bytes!("fixtures/leaf_rsa.pem");
const REVOKED: &[u8] = include_bytes!("fixtures/revoked_leaf.pem");
const INT: &[u8] = include_bytes!("fixtures/int.pem");
const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const CRL_VALID: &[u8] = include_bytes!("fixtures/crl_valid.pem");

const GOOD_DER: &[u8] = include_bytes!("fixtures/ocsp/good.der");
const GOOD_INT_DER: &[u8] = include_bytes!("fixtures/ocsp/good_int.der");
const REVOKED_DER: &[u8] = include_bytes!("fixtures/ocsp/revoked.der");

// Serials of the fixture certificates (lowercase, as in the DER CertID).
const LEAF_RSA_SERIAL_HEX: &str = "44E056A8B426D4727A82EC2A41EDFFFEA4B3D0E3";
const INT_SERIAL_HEX: &str = "1365075C61FB19C4708DA106BCC786FC9FC337F4";
const REVOKED_SERIAL_HEX: &str = "99"; // revoked_leaf serial is hex 0x99

fn whitelist() -> Vec<String> {
    vec!["sha256WithRSAEncryption".into(), "ecdsa-with-SHA256".into()]
}

/// Decodes a hex serial into the raw big-endian bytes that appear verbatim
/// in the `CertID`'s `serialNumber` INTEGER inside the request DER.
fn serial_bytes_hex(hex: &str) -> Vec<u8> {
    let padded = if hex.len() % 2 == 1 {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    let bytes = hex::decode(&padded).expect("valid hex serial");
    // Strip a single leading 0x00 sign byte if present (DER INTEGER form):
    // the request encodes the minimal-length serial, so e.g. 0x63 appears
    // as one byte, not two.
    match bytes.split_first() {
        Some((0x00, rest)) if !rest.is_empty() => rest.to_vec(),
        _ => bytes,
    }
}

/// Builds a verifier config for these tests: `[ca]` anchor, `[int]`
/// intermediate, RSA+ECDSA whitelist, cache disabled.
fn config(
    mode: RevocationMode,
    responder: Option<OcspUrl>,
    crl_pems: Vec<Vec<u8>>,
) -> OpensslVerifierConfig {
    OpensslVerifierConfig {
        max_supported_profile_version: tessera_core::trust::openssl_verifier::DEFAULT_MAX_SUPPORTED_PROFILE_VERSION,
        anchors: vec![Certificate::from_pem(CA).unwrap()],
        intermediates: vec![Certificate::from_pem(INT).unwrap()],
        crl_pems,
        crl_strict: true,
        crl_max_age: None,
        clock_skew: Duration::from_secs(60),
        signature_alg_whitelist: whitelist(),
        spki_pins: vec![],
        max_depth: 4,
        gost_engine_path: None,
        revocation_mode: mode,
        ocsp_responder_url: responder,
        ocsp_timeout: Duration::from_secs(5),
        ocsp_cache_dir: std::path::PathBuf::from("/var/cache/tessera/ocsp"),
        ocsp_cache_ttl: Duration::ZERO,
    }
}

/// Reads one HTTP request (head + Content-Length body) from `stream`.
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1024];
    // Read until we have the full header block.
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let content_length = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    buf[header_end..].to_vec()
}

fn write_response(stream: &mut TcpStream, der: &[u8]) {
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/ocsp-response\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        der.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(der);
    let _ = stream.flush();
}

fn write_500(stream: &mut TcpStream) {
    let _ = stream.write_all(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let _ = stream.flush();
}

/// Spawns a multi-connection mock OCSP responder.
///
/// `routes` is a list of `(serial_bytes, response_der)`.  For each incoming
/// connection the responder reads the request, finds the route whose serial
/// bytes appear as a contiguous window of the request body, and returns that
/// DER; a request whose serial matches no route gets a 500.  The accept loop
/// is a detached daemon thread — the test process tears it down on exit.
fn spawn_responder(routes: Vec<(Vec<u8>, Vec<u8>)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let body = read_request(&mut stream);
            let matched = routes.iter().find(|(serial, _)| {
                !serial.is_empty() && body.windows(serial.len()).any(|w| w == serial.as_slice())
            });
            match matched {
                Some((_, der)) => write_response(&mut stream, der),
                None => write_500(&mut stream),
            }
        }
    });
    format!("http://127.0.0.1:{port}/")
}

/// Binds and immediately drops a listener, returning a responder URL whose
/// port refuses connections.
fn dead_responder_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    format!("http://127.0.0.1:{port}/")
}

fn url(raw: &str) -> OcspUrl {
    OcspUrl::parse(raw).expect("responder URL parses")
}

#[test]
fn ocsp_mode_good_chain_verifies() {
    let responder = spawn_responder(vec![
        (serial_bytes_hex(LEAF_RSA_SERIAL_HEX), GOOD_DER.to_vec()),
        (serial_bytes_hex(INT_SERIAL_HEX), GOOD_INT_DER.to_vec()),
    ]);
    let v = OpensslVerifier::new(config(RevocationMode::Ocsp, Some(url(&responder)), vec![]))
        .unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    v.verify_at(&leaf, &presented, SystemTime::now())
        .expect("good chain verifies under OCSP");
}

#[test]
fn ocsp_mode_revoked_is_rejected() {
    let responder = spawn_responder(vec![
        (serial_bytes_hex(REVOKED_SERIAL_HEX), REVOKED_DER.to_vec()),
        (serial_bytes_hex(INT_SERIAL_HEX), GOOD_INT_DER.to_vec()),
    ]);
    let v = OpensslVerifier::new(config(RevocationMode::Ocsp, Some(url(&responder)), vec![]))
        .unwrap();
    let leaf = Certificate::from_pem(REVOKED).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let err = v
        .verify_at(&leaf, &presented, SystemTime::now())
        .unwrap_err();
    assert!(matches!(err, TrustError::Revoked(_)), "{err:?}");
}

/// The fail-closed test: an unreachable responder must refuse, never accept.
#[test]
fn ocsp_mode_responder_unreachable_is_rejected() {
    let dead = dead_responder_url();
    let v =
        OpensslVerifier::new(config(RevocationMode::Ocsp, Some(url(&dead)), vec![])).unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let err = v
        .verify_at(&leaf, &presented, SystemTime::now())
        .unwrap_err();
    assert!(
        matches!(err, TrustError::Ocsp(_)),
        "unreachable responder must fail closed via TrustError::Ocsp, got {err:?}"
    );
}

/// `crl_then_ocsp`: a fresh covering CRL answers for the leaf offline, so the
/// responder is never asked for the leaf's serial.  The intermediate is not
/// covered by `crl_valid.pem` (issued by the intermediate, not the root), so
/// it falls to OCSP and is answered `good`.  If the leaf had hit the network
/// the responder would 500 (no route for the leaf serial) and verification
/// would fail — Ok proves the CRL short-circuit.
#[test]
fn crl_then_ocsp_covering_crl_uses_crl_not_ocsp_for_leaf() {
    let responder = spawn_responder(vec![
        // Only the intermediate is routed; the leaf serial deliberately has
        // no route, so any OCSP query for the leaf would 500.
        (serial_bytes_hex(INT_SERIAL_HEX), GOOD_INT_DER.to_vec()),
    ]);
    let v = OpensslVerifier::new(config(
        RevocationMode::CrlThenOcsp,
        Some(url(&responder)),
        vec![CRL_VALID.to_vec()],
    ))
    .unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    v.verify_at(&leaf, &presented, SystemTime::now())
        .expect("leaf covered by CRL, int answered by OCSP good");
}

/// `crl_then_ocsp` with no CRL: both non-anchor certs fall to OCSP.  With a
/// live responder serving `good` for both, verification succeeds.
#[test]
fn crl_then_ocsp_no_crl_uses_ocsp_good() {
    let responder = spawn_responder(vec![
        (serial_bytes_hex(LEAF_RSA_SERIAL_HEX), GOOD_DER.to_vec()),
        (serial_bytes_hex(INT_SERIAL_HEX), GOOD_INT_DER.to_vec()),
    ]);
    let v = OpensslVerifier::new(config(
        RevocationMode::CrlThenOcsp,
        Some(url(&responder)),
        vec![],
    ))
    .unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    v.verify_at(&leaf, &presented, SystemTime::now())
        .expect("no CRL coverage falls through to OCSP good");
}

/// `crl_then_ocsp` with no CRL and a dead responder: OCSP is mandatory, so
/// the unreachable responder fails closed.  Proves OCSP was actually
/// required (not silently skipped) when no CRL covers the chain.
#[test]
fn crl_then_ocsp_no_crl_requires_ocsp() {
    let dead = dead_responder_url();
    let v = OpensslVerifier::new(config(
        RevocationMode::CrlThenOcsp,
        Some(url(&dead)),
        vec![],
    ))
    .unwrap();
    let leaf = Certificate::from_pem(LEAF_RSA).unwrap();
    let presented = vec![Certificate::from_pem(INT).unwrap()];
    let err = v
        .verify_at(&leaf, &presented, SystemTime::now())
        .unwrap_err();
    assert!(matches!(err, TrustError::Ocsp(_)), "{err:?}");
}

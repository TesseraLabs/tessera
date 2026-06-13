//! Isolated FFI shim around the OpenSSL OCSP nonce helpers
//! (`OCSP_request_add1_nonce` / `OCSP_check_nonce`), which the `openssl`
//! crate (0.10) does not wrap.
//!
//! All raw FFI for the OCSP module lives here; the rest of the crate stays
//! under `#![deny(unsafe_code)]`.  Mirrors the pattern established by
//! `crate::gost::sys`.
//!
//! # Why DER round-trips
//!
//! The safe `openssl::ocsp` wrappers do not expose their raw pointers
//! without pulling `foreign-types` in as a direct dependency, so the shim
//! works on DER byte slices instead: parse with `d2i_*`, operate, serialize
//! back with `i2d_*`.  An OCSP exchange happens at most a handful of times
//! per login, so the extra encode/decode is irrelevant.
//!
//! # Linkage
//!
//! `openssl-sys` already pulls libcrypto into the link-line and declares
//! most `OCSP_*` symbols; the three functions it does not re-export are
//! declared locally below with prototypes cross-checked against
//! `<openssl/ocsp.h>` of OpenSSL 1.1.1 and 3.x.
#![allow(unsafe_code)]

use std::ptr::NonNull;

use libc::{c_int, c_long, c_uchar};
use openssl_sys::{
    ASN1_INTEGER, ASN1_OBJECT, ASN1_OCTET_STRING, ASN1_STRING, OCSP_BASICRESP, OCSP_CERTID,
    OCSP_REQUEST, OCSP_RESPONSE, X509,
};

// ---------------------------------------------------------------------
// Raw FFI declarations missing from `openssl-sys 0.9`.
// ---------------------------------------------------------------------
//
// SAFETY: each function below is declared with the exact prototype from
// `<openssl/ocsp.h>`.  `i2d_OCSP_REQUEST` is declared with a `*mut` first
// argument: openssl-sys gates the pointer constness on the detected
// libcrypto version (const since 3.0), but the C ABI is identical either
// way and the function never mutates the request.  `OCSP_id_get0_info`
// fills any non-null out-pointer with a borrowed (`get0`) reference into
// the `CertID` and accepts null for fields the caller does not need.
extern "C" {
    fn OCSP_request_add1_nonce(req: *mut OCSP_REQUEST, val: *mut c_uchar, len: c_int) -> c_int;
    fn OCSP_check_nonce(req: *mut OCSP_REQUEST, bs: *mut OCSP_BASICRESP) -> c_int;
    fn i2d_OCSP_REQUEST(a: *mut OCSP_REQUEST, pp: *mut *mut c_uchar) -> c_int;
    fn OCSP_id_get0_info(
        pi_name_hash: *mut *mut ASN1_OCTET_STRING,
        pmd: *mut *mut ASN1_OBJECT,
        pi_key_hash: *mut *mut ASN1_OCTET_STRING,
        pserial: *mut *mut ASN1_INTEGER,
        cid: *mut OCSP_CERTID,
    ) -> c_int;
}

/// Owned `OCSP_REQUEST*`, freed on drop.
struct Request(NonNull<OCSP_REQUEST>);

impl Drop for Request {
    fn drop(&mut self) {
        // SAFETY: the pointer was returned non-null by `d2i_OCSP_REQUEST`
        // and ownership has not been transferred elsewhere.
        unsafe { openssl_sys::OCSP_REQUEST_free(self.0.as_ptr()) }
    }
}

/// Owned `OCSP_RESPONSE*`, freed on drop.
struct Response(NonNull<OCSP_RESPONSE>);

impl Drop for Response {
    fn drop(&mut self) {
        // SAFETY: the pointer was returned non-null by `d2i_OCSP_RESPONSE`
        // and ownership has not been transferred elsewhere.
        unsafe { openssl_sys::OCSP_RESPONSE_free(self.0.as_ptr()) }
    }
}

/// Owned `X509*`, freed on drop.
struct Cert(NonNull<X509>);

impl Drop for Cert {
    fn drop(&mut self) {
        // SAFETY: the pointer was returned non-null by `d2i_X509` and
        // ownership has not been transferred elsewhere.
        unsafe { openssl_sys::X509_free(self.0.as_ptr()) }
    }
}

/// Owned `OCSP_CERTID*`, freed on drop.
struct CertId(NonNull<OCSP_CERTID>);

impl Drop for CertId {
    fn drop(&mut self) {
        // SAFETY: the pointer was returned non-null by `OCSP_cert_to_id`
        // (an owned structure) and ownership has not been transferred
        // elsewhere; borrowed `get0` field pointers never outlive `self`.
        unsafe { openssl_sys::OCSP_CERTID_free(self.0.as_ptr()) }
    }
}

/// Owned `OCSP_BASICRESP*`, freed on drop.
struct BasicResponse(NonNull<OCSP_BASICRESP>);

impl Drop for BasicResponse {
    fn drop(&mut self) {
        // SAFETY: the pointer was returned non-null by
        // `OCSP_response_get1_basic` (the `get1` contract hands us our own
        // reference) and ownership has not been transferred elsewhere.
        unsafe { openssl_sys::OCSP_BASICRESP_free(self.0.as_ptr()) }
    }
}

fn parse_request(der: &[u8]) -> Result<Request, String> {
    let len =
        c_long::try_from(der.len()).map_err(|_| "OCSP request DER too large".to_string())?;
    let mut pp = der.as_ptr();
    // SAFETY: `pp` points to `len` readable bytes; with a null first
    // argument d2i allocates a fresh structure and only advances our local
    // copy of the data pointer.
    let raw = unsafe { openssl_sys::d2i_OCSP_REQUEST(std::ptr::null_mut(), &raw mut pp, len) };
    NonNull::new(raw)
        .map(Request)
        .ok_or_else(|| "OCSP request DER parse failed".to_string())
}

fn parse_response(der: &[u8]) -> Result<Response, String> {
    let len =
        c_long::try_from(der.len()).map_err(|_| "OCSP response DER too large".to_string())?;
    let mut pp = der.as_ptr();
    // SAFETY: `pp` points to `len` readable bytes; with a null first
    // argument d2i allocates a fresh structure and only advances our local
    // copy of the data pointer.
    let raw = unsafe { openssl_sys::d2i_OCSP_RESPONSE(std::ptr::null_mut(), &raw mut pp, len) };
    NonNull::new(raw)
        .map(Response)
        .ok_or_else(|| "OCSP response DER parse failed".to_string())
}

fn request_to_der(req: &Request) -> Result<Vec<u8>, String> {
    // SAFETY: a null output pointer asks i2d only for the encoded length.
    let len = unsafe { i2d_OCSP_REQUEST(req.0.as_ptr(), std::ptr::null_mut()) };
    let len_usize =
        usize::try_from(len).map_err(|_| format!("i2d_OCSP_REQUEST length failed: {len}"))?;
    if len_usize == 0 {
        return Err("i2d_OCSP_REQUEST produced an empty encoding".to_string());
    }
    let mut buf = vec![0_u8; len_usize];
    let mut out = buf.as_mut_ptr();
    // SAFETY: `buf` provides exactly `len` writable bytes, the size i2d
    // reported for this same request one call earlier; i2d advances only
    // our local copy of the output pointer.
    let written = unsafe { i2d_OCSP_REQUEST(req.0.as_ptr(), &raw mut out) };
    if written == len {
        Ok(buf)
    } else {
        Err(format!(
            "i2d_OCSP_REQUEST wrote {written} bytes, expected {len}"
        ))
    }
}

/// Adds an RFC 8954 nonce extension to a DER-encoded `OCSPRequest` and
/// returns the re-encoded request.
///
/// # Errors
///
/// Returns a human-readable reason when the request fails to parse, the
/// nonce cannot be attached, or re-encoding fails.
pub(crate) fn request_add_nonce(request_der: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let req = parse_request(request_der)?;
    let len = c_int::try_from(nonce.len()).map_err(|_| "nonce too large".to_string())?;
    // SAFETY: `val` points to `len` valid bytes; OCSP_request_add1_nonce
    // (`add1`) copies the value into the request and does not retain the
    // pointer or mutate the buffer.
    let rc = unsafe { OCSP_request_add1_nonce(req.0.as_ptr(), nonce.as_ptr().cast_mut(), len) };
    if rc != 1 {
        return Err("OCSP_request_add1_nonce failed".to_string());
    }
    request_to_der(&req)
}

/// Outcome of comparing the request nonce against the response nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonceCheck {
    /// Present in both, values equal.
    Match,
    /// The request carries a nonce, the response does not.  Allowed:
    /// pre-signed responses cannot echo a nonce; replay protection falls
    /// back to the `thisUpdate`/`nextUpdate` window.
    AbsentInResponse,
    /// Neither side carries a nonce (e.g. re-verifying a cached response
    /// without an originating request).
    AbsentInBoth,
    /// Both present, values differ.
    Mismatch,
    /// The response carries a nonce but the request does not — the value
    /// cannot have been ours, so it is treated as a mismatch by callers.
    PresentOnlyInResponse,
}

/// Runs `OCSP_check_nonce` over a DER-encoded request/response pair.
///
/// # Errors
///
/// Returns a human-readable reason when either blob fails to parse or the
/// response carries no basic response body.
pub(crate) fn check_nonce(request_der: &[u8], response_der: &[u8]) -> Result<NonceCheck, String> {
    let req = parse_request(request_der)?;
    let resp = parse_response(response_der)?;
    // SAFETY: `resp` is a valid OCSP_RESPONSE; get1 returns a new reference
    // (or null when there is no basic body), owned by us.
    let basic_raw = unsafe { openssl_sys::OCSP_response_get1_basic(resp.0.as_ptr()) };
    let basic = NonNull::new(basic_raw)
        .map(BasicResponse)
        .ok_or_else(|| "OCSP response has no basic response body".to_string())?;
    // SAFETY: both pointers are valid for the duration of the call;
    // OCSP_check_nonce only reads the nonce extensions.
    let rc = unsafe { OCSP_check_nonce(req.0.as_ptr(), basic.0.as_ptr()) };
    match rc {
        1 => Ok(NonceCheck::Match),
        0 => Ok(NonceCheck::Mismatch),
        -1 => Ok(NonceCheck::AbsentInResponse),
        2 => Ok(NonceCheck::AbsentInBoth),
        3 => Ok(NonceCheck::PresentOnlyInResponse),
        other => Err(format!("OCSP_check_nonce returned unexpected {other}")),
    }
}

fn parse_cert(der: &[u8], what: &str) -> Result<Cert, String> {
    let len = c_long::try_from(der.len()).map_err(|_| format!("{what} DER too large"))?;
    let mut pp = der.as_ptr();
    // SAFETY: `pp` points to `len` readable bytes; with a null first
    // argument d2i allocates a fresh structure and only advances our local
    // copy of the data pointer.
    let raw = unsafe { openssl_sys::d2i_X509(std::ptr::null_mut(), &raw mut pp, len) };
    NonNull::new(raw)
        .map(Cert)
        .ok_or_else(|| format!("{what} DER parse failed"))
}

/// Copies the content octets of an ASN.1 string field out of a `CertID`.
///
/// `ASN1_OCTET_STRING` and `ASN1_INTEGER` are both `ASN1_STRING` in
/// libcrypto (`asn1_string_st`), so a single helper serves the hash fields
/// and the serial; for the (positive) serial the content octets are the
/// big-endian magnitude.
fn asn1_string_bytes(s: *const ASN1_STRING, what: &str) -> Result<Vec<u8>, String> {
    if s.is_null() {
        return Err(format!("{what}: null ASN1 string"));
    }
    // SAFETY: `s` is non-null and points to an ASN1_STRING kept alive by
    // the owning CertID for the duration of this call.
    let len = unsafe { openssl_sys::ASN1_STRING_length(s) };
    let len = usize::try_from(len).map_err(|_| format!("{what}: negative length"))?;
    if len == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: same liveness as above; get0 returns a pointer borrowed from
    // the string, valid while the CertID lives.
    let data = unsafe { openssl_sys::ASN1_STRING_get0_data(s) };
    if data.is_null() {
        return Err(format!("{what}: null data pointer"));
    }
    // SAFETY: libcrypto guarantees `data` points to `len` readable bytes
    // for a string whose reported length is `len`.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    Ok(bytes.to_vec())
}

/// Returns the `CertID` field material for `(subject, issuer)`:
/// `issuerNameHash ‖ issuerKeyHash ‖ serialNumber` of the SHA-1 `CertID` —
/// the same identifier [`crate::ocsp::request::OcspRequestData::build`]
/// puts into the OCSP request (`OCSP_cert_to_id` with `EVP_sha1`).
///
/// Used by the on-disk cache to derive its deterministic file-name key
/// (design Decision 3: `hex(sha256(material))`).
///
/// # Errors
///
/// Returns a human-readable reason when either certificate fails to parse
/// or any `CertID` primitive fails.
pub(crate) fn cert_id_cache_material(
    subject_der: &[u8],
    issuer_der: &[u8],
) -> Result<Vec<u8>, String> {
    let subject = parse_cert(subject_der, "subject certificate")?;
    let issuer = parse_cert(issuer_der, "issuer certificate")?;
    // SAFETY: trivially safe; returns a pointer to a static method table.
    let sha1 = unsafe { openssl_sys::EVP_sha1() };
    // SAFETY: both X509 pointers are valid for the duration of the call;
    // OCSP_cert_to_id reads them and returns an owned CertID.
    let raw = unsafe { openssl_sys::OCSP_cert_to_id(sha1, subject.0.as_ptr(), issuer.0.as_ptr()) };
    let cert_id = NonNull::new(raw)
        .map(CertId)
        .ok_or_else(|| "OCSP_cert_to_id failed".to_string())?;
    let mut name_hash: *mut ASN1_OCTET_STRING = std::ptr::null_mut();
    let mut key_hash: *mut ASN1_OCTET_STRING = std::ptr::null_mut();
    let mut serial: *mut ASN1_INTEGER = std::ptr::null_mut();
    // SAFETY: `cert_id` is valid; the out-pointers are writable locals; the
    // digest-algorithm slot is null (not needed) which the function allows.
    let rc = unsafe {
        OCSP_id_get0_info(
            &raw mut name_hash,
            std::ptr::null_mut(),
            &raw mut key_hash,
            &raw mut serial,
            cert_id.0.as_ptr(),
        )
    };
    if rc != 1 {
        return Err("OCSP_id_get0_info failed".to_string());
    }
    let mut material = asn1_string_bytes(name_hash.cast::<ASN1_STRING>(), "issuerNameHash")?;
    material.extend_from_slice(&asn1_string_bytes(
        key_hash.cast::<ASN1_STRING>(),
        "issuerKeyHash",
    )?);
    material.extend_from_slice(&asn1_string_bytes(
        serial.cast::<ASN1_STRING>(),
        "serialNumber",
    )?);
    Ok(material)
}

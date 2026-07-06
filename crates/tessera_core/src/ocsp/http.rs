//! Minimal blocking HTTP/1.1 client for the single OCSP POST exchange.
//!
//! Deliberately not a general-purpose HTTP client (design decision: no new
//! supply-chain surface for one POST).  Constraints baked in:
//!
//! * one request per connection, `Connection: close`, no keep-alive;
//! * no redirects — any non-200 status is a hard error;
//! * `Content-Length` framing only — `Transfer-Encoding` (chunked or
//!   otherwise) is rejected with a typed error;
//! * a single overall deadline covers connect + TLS handshake + write +
//!   read (`ocsp_timeout_seconds`);
//! * the response body is capped at [`MAX_RESPONSE_BYTES`].
//!
//! `https://` responders are reached through `openssl::ssl::SslConnector`
//! with default peer verification (system trust store + hostname check).
//! Note that HTTPS adds nothing to OCSP's own security — responses are
//! signed and verified against `[trust]` anchors — but if an operator
//! configures it, it is enforced, not silently downgraded.

use crate::error::TrustError;
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Hard cap on the accepted OCSP response body size.
///
/// Anti-DoS bound for a compromised/misbehaving responder.  Real OCSP
/// responses (including GOST chains with embedded responder certs) are a
/// few KiB; 1 MiB leaves three orders of magnitude of headroom.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Cap on the HTTP status line + header block.
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// URL scheme accepted for OCSP responders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspScheme {
    /// Plain HTTP (the common case for OCSP — responses are self-signed
    /// material, transport secrecy is not required).
    Http,
    /// HTTPS via `SslConnector` with default peer verification.
    Https,
}

/// Parsed `ocsp_responder_url`.
///
/// A deliberately small parser for the subset of URLs valid in
/// `trust.revocation.ocsp_responder_url` (scheme, host, optional port,
/// path+query).  Userinfo (`user@host`) and fragments are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspUrl {
    /// Scheme.
    pub scheme: OcspScheme,
    /// Host name or IP literal (IPv6 without the surrounding brackets).
    pub host: String,
    /// TCP port (defaulted from the scheme when absent).
    pub port: u16,
    /// Absolute request path including any query string; never empty
    /// (defaults to `/`).
    pub path: String,
}

impl OcspUrl {
    /// Parses an `http://` / `https://` URL.
    ///
    /// # Errors
    ///
    /// * [`TrustError::OcspResponderInvalid`] for any unsupported scheme,
    ///   empty host, userinfo, fragment, or malformed port.
    pub fn parse(url: &str) -> Result<Self, TrustError> {
        let invalid = |reason: String| TrustError::OcspResponderInvalid { reason };
        let (scheme, rest) = if let Some(rest) = strip_prefix_ascii_ci(url, "http://") {
            (OcspScheme::Http, rest)
        } else if let Some(rest) = strip_prefix_ascii_ci(url, "https://") {
            (OcspScheme::Https, rest)
        } else {
            return Err(invalid(format!(
                "unsupported scheme in {url:?}: must be http:// or https://"
            )));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err(invalid("userinfo in URL is not supported".to_string()));
        }
        if path.contains('#') {
            return Err(invalid("fragment in URL is not supported".to_string()));
        }
        let (host, port_str) = split_authority(authority).map_err(invalid)?;
        if host.is_empty() {
            return Err(invalid("empty host".to_string()));
        }
        let default_port = match scheme {
            OcspScheme::Http => 80,
            OcspScheme::Https => 443,
        };
        let port = match port_str {
            None | Some("") => default_port,
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| invalid(format!("invalid port {p:?}")))?,
        };
        Ok(Self {
            scheme,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// Value for the `Host` header (port elided when it is the scheme
    /// default).
    fn host_header(&self) -> String {
        let default_port = match self.scheme {
            OcspScheme::Http => 80,
            OcspScheme::Https => 443,
        };
        let host = if self.host.contains(':') {
            // IPv6 literal: re-bracket for the header.
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Case-insensitive ASCII prefix strip.
fn strip_prefix_ascii_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        s.get(prefix.len()..)
    } else {
        None
    }
}

/// Splits `host[:port]`, handling bracketed IPv6 literals (`[::1]:8080`).
fn split_authority(authority: &str) -> Result<(&str, Option<&str>), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err("unterminated IPv6 literal".to_string());
        };
        let (host, after) = rest.split_at(end);
        let after = after.get(1..).unwrap_or("");
        if after.is_empty() {
            return Ok((host, None));
        }
        let Some(port) = after.strip_prefix(':') else {
            return Err(format!(
                "unexpected characters after IPv6 literal: {after:?}"
            ));
        };
        return Ok((host, Some(port)));
    }
    match authority.rfind(':') {
        Some(i) => {
            let (host, port) = authority.split_at(i);
            Ok((host, port.get(1..)))
        }
        None => Ok((authority, None)),
    }
}

/// Either a plain TCP stream or a TLS stream over TCP.
enum Transport {
    Plain(TcpStream),
    Tls(SslStream<TcpStream>),
}

impl Transport {
    /// The underlying TCP stream, for per-operation timeout updates.
    fn tcp(&self) -> &TcpStream {
        match self {
            Transport::Plain(s) => s,
            Transport::Tls(s) => s.get_ref(),
        }
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

/// Remaining budget until `deadline`; fails closed once it is exhausted.
fn remaining(deadline: Instant) -> Result<Duration, TrustError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(TrustError::OcspTimeout)
    } else {
        Ok(left)
    }
}

/// Maps an I/O error to the typed OCSP error, folding both timeout kinds
/// (`TimedOut` on Linux, `WouldBlock` on BSD/macOS for socket timeouts)
/// into [`TrustError::OcspTimeout`].
fn map_io(e: &std::io::Error, what: &str) -> TrustError {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => TrustError::OcspTimeout,
        _ => TrustError::OcspTransport {
            reason: format!("{what}: {e}"),
        },
    }
}

fn connect(url: &OcspUrl, deadline: Instant) -> Result<TcpStream, TrustError> {
    // Note: std offers no timeout control over DNS resolution itself; the
    // connect/read/write budget starts applying from the first socket op.
    let addrs = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|e| TrustError::OcspTransport {
            reason: format!("resolve {}:{}: {e}", url.host, url.port),
        })?;
    let mut last: Option<TrustError> = None;
    for addr in addrs {
        let budget = remaining(deadline)?;
        match TcpStream::connect_timeout(&addr, budget) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(map_io(&e, &format!("connect {addr}"))),
        }
    }
    Err(last.unwrap_or_else(|| TrustError::OcspTransport {
        reason: format!("no addresses resolved for {}:{}", url.host, url.port),
    }))
}

fn set_timeouts(tcp: &TcpStream, deadline: Instant) -> Result<(), TrustError> {
    let budget = remaining(deadline)?;
    tcp.set_read_timeout(Some(budget))
        .map_err(|e| map_io(&e, "set_read_timeout"))?;
    tcp.set_write_timeout(Some(budget))
        .map_err(|e| map_io(&e, "set_write_timeout"))?;
    Ok(())
}

fn open_transport(url: &OcspUrl, deadline: Instant) -> Result<Transport, TrustError> {
    let tcp = connect(url, deadline)?;
    set_timeouts(&tcp, deadline)?;
    match url.scheme {
        OcspScheme::Http => Ok(Transport::Plain(tcp)),
        OcspScheme::Https => {
            let connector = SslConnector::builder(SslMethod::tls_client())
                .map_err(|e| TrustError::OcspTransport {
                    reason: format!("TLS init: {e}"),
                })?
                .build();
            let stream =
                connector
                    .connect(&url.host, tcp)
                    .map_err(|e| TrustError::OcspTransport {
                        reason: format!("TLS handshake: {e}"),
                    })?;
            Ok(Transport::Tls(stream))
        }
    }
}

/// Parsed response head: status code plus the relevant framing headers.
struct ResponseHead {
    status: u16,
    content_length: Option<usize>,
    transfer_encoding: Option<String>,
}

fn parse_head(head: &str) -> Result<ResponseHead, TrustError> {
    let bad = |reason: String| TrustError::OcspHttp { reason };
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.split_ascii_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(bad(format!("unsupported status line {status_line:?}")));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad(format!("unparseable status line {status_line:?}")))?;
    let mut content_length = None;
    let mut transfer_encoding = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad(format!("malformed header line {line:?}")));
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                let n: usize = value
                    .parse()
                    .map_err(|_| bad(format!("invalid Content-Length {value:?}")))?;
                content_length = Some(n);
            }
            "transfer-encoding" => transfer_encoding = Some(value.to_string()),
            _ => {}
        }
    }
    Ok(ResponseHead {
        status,
        content_length,
        transfer_encoding,
    })
}

/// Reads bytes until the `\r\n\r\n` head terminator; returns the head text
/// and any body bytes that arrived in the same reads.
fn read_head(
    transport: &mut Transport,
    deadline: Instant,
) -> Result<(String, Vec<u8>), TrustError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        if let Some(pos) = find_head_end(&buf) {
            let head_bytes = buf.get(..pos).unwrap_or_default();
            let head = String::from_utf8_lossy(head_bytes).into_owned();
            let body = buf.get(pos + 4..).unwrap_or_default().to_vec();
            return Ok((head, body));
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(TrustError::OcspHttp {
                reason: format!("response head exceeds {MAX_HEADER_BYTES} bytes"),
            });
        }
        set_timeouts(transport.tcp(), deadline)?;
        let n = transport
            .read(&mut chunk)
            .map_err(|e| map_io(&e, "read response head"))?;
        if n == 0 {
            return Err(TrustError::OcspTransport {
                reason: "connection closed before response head completed".to_string(),
            });
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn read_body(
    transport: &mut Transport,
    deadline: Instant,
    mut body: Vec<u8>,
    expected: usize,
) -> Result<Vec<u8>, TrustError> {
    if body.len() > expected {
        return Err(TrustError::OcspHttp {
            reason: format!(
                "response body longer than Content-Length ({} > {expected})",
                body.len()
            ),
        });
    }
    let mut chunk = [0_u8; 4096];
    while body.len() < expected {
        set_timeouts(transport.tcp(), deadline)?;
        let n = transport
            .read(&mut chunk)
            .map_err(|e| map_io(&e, "read response body"))?;
        if n == 0 {
            return Err(TrustError::OcspTransport {
                reason: format!(
                    "connection closed mid-body ({} of {expected} bytes received)",
                    body.len()
                ),
            });
        }
        if body.len() + n > expected {
            return Err(TrustError::OcspHttp {
                reason: format!("response body longer than Content-Length {expected}"),
            });
        }
        body.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    Ok(body)
}

/// Performs the single OCSP POST exchange and returns the raw response
/// body (a DER-encoded `OCSPResponse`, parsed/verified by the caller).
///
/// `timeout` is the *total* deadline across connect, TLS handshake, write
/// and read, per `ocsp_timeout_seconds`.
///
/// # Errors
///
/// * [`TrustError::OcspTimeout`] when the overall deadline elapses.
/// * [`TrustError::OcspTransport`] on connect/IO failures and premature
///   connection close.
/// * [`TrustError::OcspHttp`] on any HTTP-level refusal: status != 200,
///   `Transfer-Encoding` present, missing or oversized `Content-Length`,
///   malformed framing.
pub fn post_ocsp_request(
    url: &OcspUrl,
    request_der: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, TrustError> {
    let deadline = Instant::now() + timeout;
    let mut transport = open_transport(url, deadline)?;

    let head = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/ocsp-request\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        url.path,
        url.host_header(),
        request_der.len()
    );
    set_timeouts(transport.tcp(), deadline)?;
    transport
        .write_all(head.as_bytes())
        .map_err(|e| map_io(&e, "write request head"))?;
    transport
        .write_all(request_der)
        .map_err(|e| map_io(&e, "write request body"))?;
    transport.flush().map_err(|e| map_io(&e, "flush request"))?;

    let (head_text, early_body) = read_head(&mut transport, deadline)?;
    let head = parse_head(&head_text)?;
    if head.status != 200 {
        return Err(TrustError::OcspHttp {
            reason: format!("HTTP status {}", head.status),
        });
    }
    if let Some(te) = head.transfer_encoding {
        // Content-Length framing only; chunked responders are out of scope
        // by design (documented client constraint).
        return Err(TrustError::OcspHttp {
            reason: format!("Transfer-Encoding {te:?} is not supported"),
        });
    }
    let Some(expected) = head.content_length else {
        return Err(TrustError::OcspHttp {
            reason: "missing Content-Length".to_string(),
        });
    };
    if expected == 0 {
        return Err(TrustError::OcspHttp {
            reason: "empty response body".to_string(),
        });
    }
    if expected > MAX_RESPONSE_BYTES {
        return Err(TrustError::OcspHttp {
            reason: format!("Content-Length {expected} exceeds limit {MAX_RESPONSE_BYTES}"),
        });
    }
    read_body(&mut transport, deadline, early_body, expected)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::indexing_slicing)]

    use super::{post_ocsp_request, OcspScheme, OcspUrl, MAX_RESPONSE_BYTES};
    use crate::error::TrustError;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::time::Duration;

    // ----------------------------------------------------------------
    // URL parser
    // ----------------------------------------------------------------

    #[test]
    fn parses_plain_http_with_defaults() {
        let u = OcspUrl::parse("http://ocsp.example.org").unwrap();
        assert_eq!(u.scheme, OcspScheme::Http);
        assert_eq!(u.host, "ocsp.example.org");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/");
    }

    #[test]
    fn parses_https_with_port_and_path() {
        let u = OcspUrl::parse("https://ocsp.example.org:8443/ocsp/v1?x=1").unwrap();
        assert_eq!(u.scheme, OcspScheme::Https);
        assert_eq!(u.host, "ocsp.example.org");
        assert_eq!(u.port, 8443);
        assert_eq!(u.path, "/ocsp/v1?x=1");
    }

    #[test]
    fn parses_ipv6_literal() {
        let u = OcspUrl::parse("http://[::1]:8080/ocsp").unwrap();
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/ocsp");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let err = OcspUrl::parse("ftp://ocsp.example.org").unwrap_err();
        assert!(matches!(err, TrustError::OcspResponderInvalid { .. }));
    }

    #[test]
    fn rejects_userinfo_and_bad_port() {
        assert!(OcspUrl::parse("http://user@host/").is_err());
        assert!(OcspUrl::parse("http://host:99999/").is_err());
        assert!(OcspUrl::parse("http://").is_err());
    }

    // ----------------------------------------------------------------
    // Mock responder plumbing
    // ----------------------------------------------------------------

    /// Spawns a one-shot TCP server; the handler receives the accepted
    /// stream after the full request (head + declared body) was consumed.
    fn spawn_server<F>(handler: F) -> SocketAddr
    where
        F: FnOnce(std::net::TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Drain the request: head until CRLFCRLF, then Content-Length
            // body bytes.
            let mut buf = Vec::new();
            let mut chunk = [0_u8; 1024];
            let head_end = loop {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos;
                }
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "client closed before request head completed");
                buf.extend_from_slice(&chunk[..n]);
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            assert!(head.starts_with("POST "), "expected POST, got {head:?}");
            assert!(head
                .to_ascii_lowercase()
                .contains("content-type: application/ocsp-request"));
            let body_len: usize = head
                .to_ascii_lowercase()
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().to_owned())
                })
                .and_then(|v| v.parse().ok())
                .expect("request Content-Length");
            let mut got = buf.len() - head_end - 4;
            while got < body_len {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0);
                got += n;
            }
            handler(stream);
        });
        addr
    }

    fn url_for(addr: SocketAddr) -> OcspUrl {
        OcspUrl::parse(&format!("http://{addr}/")).unwrap()
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    // ----------------------------------------------------------------
    // Exchange scenarios
    // ----------------------------------------------------------------

    #[test]
    fn happy_path_returns_body() {
        let body = b"fake-der-bytes";
        let addr = spawn_server(move |mut s| {
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
            s.write_all(body).unwrap();
        });
        let got = post_ocsp_request(&url_for(addr), b"request", TIMEOUT).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn slow_response_times_out() {
        let addr = spawn_server(|_s| {
            // Keep the connection open without ever answering; the short
            // client deadline must fire first.
            std::thread::sleep(Duration::from_secs(3));
        });
        let err =
            post_ocsp_request(&url_for(addr), b"request", Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, TrustError::OcspTimeout), "got {err:?}");
    }

    #[test]
    fn connection_drop_mid_body_is_transport_error() {
        let addr = spawn_server(|mut s| {
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly-ten-")
                .unwrap();
            // Drop the stream: 100 bytes promised, ~9 delivered.
        });
        let err = post_ocsp_request(&url_for(addr), b"request", TIMEOUT).unwrap_err();
        assert!(
            matches!(err, TrustError::OcspTransport { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn oversize_content_length_is_rejected_without_reading_body() {
        let oversize = MAX_RESPONSE_BYTES + 1;
        let addr = spawn_server(move |mut s| {
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {oversize}\r\n\r\n");
            s.write_all(resp.as_bytes()).unwrap();
        });
        let err = post_ocsp_request(&url_for(addr), b"request", TIMEOUT).unwrap_err();
        match err {
            TrustError::OcspHttp { reason } => assert!(reason.contains("exceeds limit")),
            other => panic!("expected OcspHttp, got {other:?}"),
        }
    }

    #[test]
    fn http_500_is_rejected() {
        let addr = spawn_server(|mut s| {
            s.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let err = post_ocsp_request(&url_for(addr), b"request", TIMEOUT).unwrap_err();
        match err {
            TrustError::OcspHttp { reason } => assert!(reason.contains("500")),
            other => panic!("expected OcspHttp, got {other:?}"),
        }
    }

    #[test]
    fn chunked_transfer_encoding_is_rejected() {
        let addr = spawn_server(|mut s| {
            s.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
            )
            .unwrap();
        });
        let err = post_ocsp_request(&url_for(addr), b"request", TIMEOUT).unwrap_err();
        match err {
            TrustError::OcspHttp { reason } => assert!(reason.contains("Transfer-Encoding")),
            other => panic!("expected OcspHttp, got {other:?}"),
        }
    }

    #[test]
    fn missing_content_length_is_rejected() {
        let addr = spawn_server(|mut s| {
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\nbody-without-length")
                .unwrap();
        });
        let err = post_ocsp_request(&url_for(addr), b"request", TIMEOUT).unwrap_err();
        match err {
            TrustError::OcspHttp { reason } => assert!(reason.contains("Content-Length")),
            other => panic!("expected OcspHttp, got {other:?}"),
        }
    }

    #[test]
    fn connect_refused_is_transport_error() {
        // Bind-then-drop to find a port that refuses connections.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let err = post_ocsp_request(&url_for(addr), b"request", TIMEOUT).unwrap_err();
        assert!(
            matches!(
                err,
                TrustError::OcspTransport { .. } | TrustError::OcspTimeout
            ),
            "got {err:?}"
        );
    }
}

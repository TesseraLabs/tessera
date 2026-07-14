//! `issuer serve` — the browser-bridging local signing agent.
//!
//! The web cabinet runs as static files in the browser and cannot talk to a
//! PKCS#11 token directly. This agent is the bridge: a synchronous HTTP server
//! bound **strictly to `127.0.0.1`** that accepts a built TBS from the cabinet
//! and returns a signature from a [`SignatureBackend`] (in production, the
//! PKCS#11 adapter).
//!
//! Three defences gate every request, and the first two run *before* the
//! signing backend is ever touched:
//!
//! 1. **Origin allowlist.** A request with no `Origin`, or an `Origin` outside
//!    the configured allowlist, is refused — the CSRF / DNS-rebinding guard.
//!    CORS preflight (`OPTIONS`) is answered only for allowlisted origins.
//! 2. **Paired session token.** The agent mints a random token at startup and
//!    prints it once for the operator to paste into the cabinet; every request
//!    must echo it in the [`SESSION_HEADER`] header, compared in constant time.
//! 3. **Routing.** `POST /sign` and `GET /info` only.
//!
//! The token PIN is entered on the agent side (terminal/pinentry, via the
//! backend's own PIN source). The HTTP surface has **no PIN field**: the sign
//! request carries only a key id and the base64 TBS, so a PIN can neither be
//! sent to nor leaked by the agent.

use std::io::Read as _;

use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq as _;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::confirm::{parse_operation_summary, Confirmer};
use crate::sign::{KeyId, SignatureAlgorithm, SignatureBackend};

pub use crate::confirm::DefaultConfirmer;

/// Header carrying the paired session token on every request.
pub const SESSION_HEADER: &str = "X-Tessera-Session";

/// Largest request body the agent will read (a TBS plus base64 overhead is a
/// few KiB; this is a generous ceiling that bounds memory per request).
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Configuration for the local signing agent.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// TCP port to bind on `127.0.0.1`; `0` picks an ephemeral port (printed at
    /// startup).
    pub bind_port: u16,
    /// Exact `Origin` values allowed (scheme + host + optional port), e.g.
    /// `https://cabinet.example`.
    pub allowed_origins: Vec<String>,
    /// Algorithms advertised by `GET /info`.
    pub advertised_algorithms: Vec<SignatureAlgorithm>,
    /// How the pairing token is delivered at startup.
    pub token_delivery: TokenDelivery,
}

/// Where the startup pairing token is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenDelivery {
    /// Print the token to stdout (interactive operator copies it).
    #[default]
    Stdout,
    /// Write the token to a private per-user runtime file (background/daemon
    /// use); the file path is printed instead of the token.
    RuntimeFile,
}

/// The signing agent: a backend, an operator-confirmation channel, and the
/// request-gating policy.
pub struct Agent<B: SignatureBackend, C: Confirmer> {
    backend: B,
    confirmer: C,
    allowed_origins: Vec<String>,
    advertised_algorithms: Vec<SignatureAlgorithm>,
    session_token: SecretString,
}

/// The HTTP method, decoupled from `tiny_http` so the handler is unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReqMethod {
    Get,
    Post,
    Options,
    Other,
}

impl From<&Method> for ReqMethod {
    fn from(m: &Method) -> Self {
        match m {
            Method::Get => ReqMethod::Get,
            Method::Post => ReqMethod::Post,
            Method::Options => ReqMethod::Options,
            _ => ReqMethod::Other,
        }
    }
}

/// A request decomposed into just what the policy needs.
struct HttpInput<'a> {
    method: ReqMethod,
    path: &'a str,
    origin: Option<&'a str>,
    session_token: Option<&'a str>,
    body: &'a [u8],
}

/// What to send back: a status, a JSON body (or empty), and whether the allowed
/// origin should be echoed in an `Access-Control-Allow-Origin` header.
struct HttpOutput {
    status: u16,
    body: String,
    cors_origin: Option<String>,
    preflight: bool,
}

impl HttpOutput {
    fn json(status: u16, body: String, origin: &str) -> Self {
        Self {
            status,
            body,
            cors_origin: Some(origin.to_owned()),
            preflight: false,
        }
    }

    /// A refusal that carries no CORS header — used when the origin itself is
    /// rejected, so nothing is advertised back to a foreign page.
    fn refused(status: u16) -> Self {
        Self {
            status,
            body: String::new(),
            cors_origin: None,
            preflight: false,
        }
    }
}

impl<B: SignatureBackend, C: Confirmer> Agent<B, C> {
    /// Build an agent with an explicit session token (tests supply a known
    /// value; [`serve`] generates a random one) and a confirmation channel.
    #[must_use]
    pub fn new(backend: B, confirmer: C, config: AgentConfig, session_token: SecretString) -> Self {
        Self {
            backend,
            confirmer,
            allowed_origins: config.allowed_origins,
            advertised_algorithms: config.advertised_algorithms,
            session_token,
        }
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == origin)
    }

    /// Constant-time comparison of the presented token against the session
    /// token. A length mismatch (the token length is fixed and non-secret) is a
    /// definite non-match.
    fn token_ok(&self, presented: Option<&str>) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        let expected = self.session_token.expose_secret().as_bytes();
        let presented = presented.as_bytes();
        if presented.len() != expected.len() {
            return false;
        }
        presented.ct_eq(expected).into()
    }

    /// Apply the full policy to a decomposed request. Origin and token are
    /// checked before any backend call.
    fn handle(&self, input: &HttpInput<'_>) -> HttpOutput {
        // 1. Origin allowlist — refuse foreign/absent origins outright.
        let Some(origin) = input.origin.filter(|o| self.origin_allowed(o)) else {
            return HttpOutput::refused(403);
        };

        // 2. Preflight for an allowlisted origin.
        if input.method == ReqMethod::Options {
            return HttpOutput {
                status: 204,
                body: String::new(),
                cors_origin: Some(origin.to_owned()),
                preflight: true,
            };
        }

        // 3. Paired session token — refuse before touching the backend.
        if !self.token_ok(input.session_token) {
            return HttpOutput::json(403, error_json("invalid or missing session token"), origin);
        }

        // 4. Route.
        match (input.method, input.path) {
            (ReqMethod::Post, "/sign") => self.handle_sign(origin, input.body),
            (ReqMethod::Get, "/info") => self.handle_info(origin),
            _ => HttpOutput::json(404, error_json("not found"), origin),
        }
    }

    fn handle_sign(&self, origin: &str, body: &[u8]) -> HttpOutput {
        let Ok(request) = serde_json::from_slice::<SignRequest>(body) else {
            return HttpOutput::json(400, error_json("malformed sign request"), origin);
        };
        let Ok(tbs) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            request.tbs_der_b64.as_bytes(),
        ) else {
            return HttpOutput::json(400, error_json("tbs_der_b64 is not base64"), origin);
        };
        let key = KeyId::new(request.key_id);

        // The agent is a trusted display: parse the TBS with the shared code and
        // refuse anything unreadable *before* prompting — what cannot be shown
        // cannot be signed.
        let Ok(summary) = parse_operation_summary(&tbs) else {
            println!("issuer serve: rejected sign — TBS not a readable issuance operation");
            return HttpOutput::json(400, error_json("TBS is not a readable operation"), origin);
        };
        // The session token authenticated the cabinet; operator confirmation
        // authorizes this specific operation. Both are required.
        match self.confirmer.confirm(&summary) {
            Ok(true) => {}
            Ok(false) => {
                println!(
                    "issuer serve: operator declined — {} for {}",
                    summary.kind.label(),
                    summary.subject
                );
                return HttpOutput::json(
                    403,
                    error_json("operation not confirmed by operator"),
                    origin,
                );
            }
            Err(e) => {
                println!("issuer serve: confirmation channel failed — {e}");
                return HttpOutput::json(
                    500,
                    error_json("confirmation channel unavailable"),
                    origin,
                );
            }
        }

        // sign() is reached only after origin, token, and confirmation pass.
        match self.backend.sign(&tbs, &key) {
            Ok(signature) => {
                let body = serde_json::json!({
                    "signature_b64": base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &signature.bytes,
                    ),
                    "algorithm": algorithm_str(signature.algorithm),
                })
                .to_string();
                HttpOutput::json(200, body, origin)
            }
            Err(e) => HttpOutput::json(502, error_json(&format!("signing failed: {e}")), origin),
        }
    }

    fn handle_info(&self, origin: &str) -> HttpOutput {
        let algorithms: Vec<&str> = self
            .advertised_algorithms
            .iter()
            .map(|a| algorithm_str(*a))
            .collect();
        let body = serde_json::json!({
            "algorithms": algorithms,
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string();
        HttpOutput::json(200, body, origin)
    }
}

/// Run the agent: bind `127.0.0.1:<port>`, print the ephemeral address and a
/// freshly generated session token, then serve requests until the process is
/// stopped.
///
/// # Errors
///
/// [`ServeError::Bind`] when the loopback socket cannot be bound.
pub fn serve<B: SignatureBackend, C: Confirmer>(
    backend: B,
    confirmer: C,
    config: AgentConfig,
) -> Result<(), ServeError> {
    let hex = random_session_token();
    let server = Server::http(("127.0.0.1", config.bind_port))
        .map_err(|e| ServeError::Bind(e.to_string()))?;
    let bound = server
        .server_addr()
        .to_ip()
        .map_or_else(|| "127.0.0.1".to_owned(), |a| a.to_string());
    println!("issuer serve: listening on http://{bound}");
    // Deliver the pairing token: printed for an interactive operator, or written
    // to a private per-user runtime file for a background/daemon agent.
    match config.token_delivery {
        TokenDelivery::Stdout => println!("issuer serve: session token: {hex}"),
        TokenDelivery::RuntimeFile => {
            let path = write_token_file(&hex)?;
            println!("issuer serve: session token written to {}", path.display());
        }
    }
    let agent = Agent::new(backend, confirmer, config, SecretString::from(hex));
    for request in server.incoming_requests() {
        agent.serve_one(request);
    }
    Ok(())
}

impl<B: SignatureBackend, C: Confirmer> Agent<B, C> {
    /// Read one `tiny_http` request, apply the policy, and respond.
    fn serve_one(&self, mut request: Request) {
        let method = ReqMethod::from(request.method());
        // `url()` is the request target (path + optional query); route on the
        // path only.
        let path = request.url().split('?').next().unwrap_or("").to_owned();
        let origin = header_value(&request, "Origin");
        let token = header_value(&request, SESSION_HEADER);

        let body = read_bounded_body(&mut request);
        let output = match body {
            Ok(body) => self.handle(&HttpInput {
                method,
                path: &path,
                origin: origin.as_deref(),
                session_token: token.as_deref(),
                body: &body,
            }),
            Err(()) => HttpOutput::json(
                413,
                error_json("request body too large"),
                origin.as_deref().unwrap_or(""),
            ),
        };

        if request.respond(build_response(&output)).is_err() {
            // The client hung up before the response finished; nothing to do.
        }
    }
}

/// Read the request body, capped at [`MAX_BODY_BYTES`]. Returns `Err` if the
/// declared length exceeds the cap.
fn read_bounded_body(request: &mut Request) -> Result<Vec<u8>, ()> {
    if request.body_length().is_some_and(|n| n > MAX_BODY_BYTES) {
        return Err(());
    }
    let mut body = Vec::new();
    let capped = u64::try_from(MAX_BODY_BYTES).unwrap_or(u64::MAX) + 1;
    if request
        .as_reader()
        .take(capped)
        .read_to_end(&mut body)
        .is_err()
    {
        return Err(());
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(());
    }
    Ok(body)
}

/// Look up a request header by name (case-insensitive), returning its value.
fn header_value(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_owned())
}

/// Turn an [`HttpOutput`] into a `tiny_http` response with the right headers.
fn build_response(output: &HttpOutput) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut response = Response::from_string(output.body.clone()).with_status_code(output.status);
    if !output.body.is_empty() {
        if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
            response = response.with_header(h);
        }
    }
    if let Some(origin) = &output.cors_origin {
        if let Ok(h) = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], origin.as_bytes()) {
            response = response.with_header(h);
        }
        if output.preflight {
            for (name, value) in [
                (
                    &b"Access-Control-Allow-Methods"[..],
                    &b"GET, POST, OPTIONS"[..],
                ),
                (
                    &b"Access-Control-Allow-Headers"[..],
                    format!("Content-Type, {SESSION_HEADER}").as_bytes(),
                ),
                (&b"Access-Control-Max-Age"[..], &b"600"[..]),
            ] {
                if let Ok(h) = Header::from_bytes(name, value) {
                    response = response.with_header(h);
                }
            }
        }
    }
    response
}

/// The sign request body. Only these two fields are read; any other field (a
/// stray `pin`, say) is ignored by serde and never reaches the backend.
#[derive(serde::Deserialize)]
struct SignRequest {
    key_id: String,
    tbs_der_b64: String,
}

/// The wire name for a [`SignatureAlgorithm`].
fn algorithm_str(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::EcdsaWithSha256 => "ecdsa-with-sha256",
        SignatureAlgorithm::EcdsaWithSha384 => "ecdsa-with-sha384",
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::RsaPkcs1Sha256 => "rsa-pkcs1-sha256",
    }
}

/// A minimal `{"error": "..."}` JSON body.
fn error_json(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

/// Generate a 256-bit random session token, hex-encoded.
fn random_session_token() -> String {
    use rand::Rng as _;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(64);
    for byte in buf {
        // Each nibble maps to a fixed hex digit; the value is always < 16.
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Resolve the per-user runtime directory for the token file, by platform.
///
/// Linux: `$XDG_RUNTIME_DIR/tessera-issuer`; macOS:
/// `~/Library/Application Support/tessera-issuer`; Windows:
/// `%LOCALAPPDATA%\tessera-issuer`.
fn runtime_dir() -> Result<std::path::PathBuf, ServeError> {
    #[cfg(target_os = "linux")]
    {
        let base = std::env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
            ServeError::NoRuntimeDir(
                "XDG_RUNTIME_DIR is not set; start the agent inside a user session \
                 (e.g. systemd --user) or export XDG_RUNTIME_DIR=/run/user/$(id -u)"
                    .to_owned(),
            )
        })?;
        Ok(std::path::PathBuf::from(base).join("tessera-issuer"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| ServeError::NoRuntimeDir("HOME is not set".to_owned()))?;
        Ok(std::path::PathBuf::from(home).join("Library/Application Support/tessera-issuer"))
    }
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| ServeError::NoRuntimeDir("LOCALAPPDATA is not set".to_owned()))?;
        Ok(std::path::PathBuf::from(base).join("tessera-issuer"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(ServeError::NoRuntimeDir(
            "no known per-user runtime directory on this platform".to_owned(),
        ))
    }
}

/// Write the pairing token to the platform runtime directory.
fn write_token_file(token: &str) -> Result<std::path::PathBuf, ServeError> {
    write_token_at(&runtime_dir()?, token)
}

/// Write the pairing token into `dir`, creating it if needed.
///
/// On Unix the directory is `0700` and the file `0600`; on Windows the file
/// inherits the user profile's ACLs (the directory is not shared). A restart
/// overwrites (truncates) any existing token file.
fn write_token_at(dir: &std::path::Path, token: &str) -> Result<std::path::PathBuf, ServeError> {
    use std::io::Write as _;

    std::fs::create_dir_all(dir)
        .map_err(|e| ServeError::TokenFile(format!("{}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| ServeError::TokenFile(format!("{}: {e}", dir.display())))?;
    }

    let path = dir.join("token");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| ServeError::TokenFile(format!("{}: {e}", path.display())))?;
    file.write_all(token.as_bytes())
        .map_err(|e| ServeError::TokenFile(format!("{}: {e}", path.display())))?;
    Ok(path)
}

/// Errors from starting the agent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The loopback socket could not be bound.
    #[error("failed to bind 127.0.0.1 agent socket: {0}")]
    Bind(String),
    /// No per-user runtime directory is available for the token file.
    #[error("no runtime directory for the token file: {0}")]
    NoRuntimeDir(String),
    /// The token file could not be written.
    #[error("failed to write the token file: {0}")]
    TokenFile(String),
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unnecessary_wraps
    )]

    use std::cell::Cell;
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::confirm::{ConfirmError, OperationSummary};
    use crate::sign::{MockSigner, SignError, Signature};
    use crate::test_support::{self_signed_ca, spki_fixture, MemoryStorage};
    use crate::{issue_leaf, CaRequest, IntegrityCeiling, Journal, LeafRequest, Serial, Validity};
    use tessera_ext::delegation::DelegationConstraints;
    use tessera_ext::der::{read_tlv_expect, TAG_SEQUENCE};

    const TOKEN: &str = "0011223344556677889900112233445566778899001122334455667788990011";
    const ORIGIN: &str = "https://cabinet.example";

    /// A confirmer as a bare `fn` pointer, for the auto-approve path.
    type ConfirmFn = fn(&OperationSummary) -> Result<bool, ConfirmError>;

    /// An auto-approving confirmer (a plain `fn` so it names a concrete type).
    fn auto_confirm(_summary: &OperationSummary) -> Result<bool, ConfirmError> {
        Ok(true)
    }

    /// Wraps [`MockSigner`], recording whether the backend was reached so tests
    /// can prove a request was refused *before* any signing.
    struct RecordingSigner {
        inner: MockSigner,
        signed: Cell<bool>,
    }

    impl RecordingSigner {
        fn new() -> Self {
            Self {
                inner: MockSigner::ecdsa_sha256(KeyId::new("ca-key")),
                signed: Cell::new(false),
            }
        }
    }

    impl SignatureBackend for RecordingSigner {
        fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
            self.inner.algorithm(key_id)
        }
        fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
            self.signed.set(true);
            self.inner.sign(tbs_der, key_id)
        }
    }

    /// A confirmer that returns a fixed decision and records whether it ran, so
    /// tests can prove an unreadable TBS is refused *before* confirmation.
    struct RecordingConfirmer {
        decision: bool,
        called: Cell<bool>,
    }

    impl Confirmer for RecordingConfirmer {
        fn confirm(&self, _summary: &OperationSummary) -> Result<bool, ConfirmError> {
            self.called.set(true);
            Ok(self.decision)
        }
    }

    fn config() -> AgentConfig {
        AgentConfig {
            bind_port: 0,
            allowed_origins: vec![ORIGIN.to_owned()],
            advertised_algorithms: vec![SignatureAlgorithm::EcdsaWithSha256],
            token_delivery: TokenDelivery::Stdout,
        }
    }

    fn agent(backend: RecordingSigner) -> Agent<RecordingSigner, ConfirmFn> {
        Agent::new(
            backend,
            auto_confirm as ConfirmFn,
            config(),
            SecretString::from(TOKEN.to_owned()),
        )
    }

    fn agent_with<C: Confirmer>(
        backend: RecordingSigner,
        confirmer: C,
    ) -> Agent<RecordingSigner, C> {
        Agent::new(
            backend,
            confirmer,
            config(),
            SecretString::from(TOKEN.to_owned()),
        )
    }

    /// Extract the `TBSCertificate` bytes from a full certificate DER.
    fn tbs_of(cert_der: &[u8]) -> Vec<u8> {
        let outer = read_tlv_expect(cert_der, TAG_SEQUENCE).unwrap();
        let start = outer.value;
        let tbs = read_tlv_expect(start, TAG_SEQUENCE).unwrap();
        let consumed = start.len() - tbs.rest.len();
        start[..consumed].to_vec()
    }

    /// Base64 of a real shift-leaf TBS the summary parser accepts.
    fn leaf_tbs_b64() -> String {
        let key = KeyId::new("ca-key");
        let signer = MockSigner::ecdsa_sha256(key.clone());
        let ca_req = CaRequest {
            subject: "CN=Tessera Root".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: Validity {
                not_before: 1_600_000_000,
                not_after: 1_900_000_000,
            },
            constraints: DelegationConstraints {
                require_tags: vec![],
                allow_roles: vec!["oper".to_owned()],
                max_level: 5,
                max_ttl: 86_400,
            },
            profile_version: 1,
        };
        let mut journal = Journal::load(MemoryStorage::new()).unwrap();
        let ca = self_signed_ca(
            &signer,
            &key,
            &ca_req,
            &Serial::generate(),
            &mut journal,
            1_600_000_000,
        )
        .unwrap();
        let leaf_req = LeafRequest {
            subject: "CN=ivanov".to_owned(),
            subject_spki_der: spki_fixture(),
            validity: Validity {
                not_before: 1_600_000_000,
                not_after: 1_600_003_600,
            },
            host_binding: vec!["*".to_owned()],
            user_binding: vec!["ivanov".to_owned()],
            allowed_roles: vec!["oper".to_owned()],
            max_integrity: Some(IntegrityCeiling {
                level: 5,
                categories: 0,
            }),
            profile_version: 1,
        };
        let leaf = issue_leaf(
            &signer,
            &key,
            &ca.der,
            &leaf_req,
            &Serial::generate(),
            &mut journal,
            1_600_000_000,
        )
        .unwrap();
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            tbs_of(&leaf.der),
        )
    }

    fn sign_body() -> String {
        serde_json::json!({ "key_id": "ca-key", "tbs_der_b64": leaf_tbs_b64() }).to_string()
    }

    #[test]
    fn foreign_origin_is_refused_before_signing() {
        let backend = RecordingSigner::new();
        let out = {
            let a = agent(backend);
            let body = sign_body();
            let out = a.handle(&HttpInput {
                method: ReqMethod::Post,
                path: "/sign",
                origin: Some("https://evil.example"),
                session_token: Some(TOKEN),
                body: body.as_bytes(),
            });
            assert!(!a.backend.signed.get(), "backend must not be reached");
            out
        };
        assert_eq!(out.status, 403);
        assert!(
            out.cors_origin.is_none(),
            "no CORS header for foreign origin"
        );
    }

    #[test]
    fn absent_origin_is_refused_before_signing() {
        let a = agent(RecordingSigner::new());
        let body = sign_body();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: None,
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(out.status, 403);
        assert!(!a.backend.signed.get());
    }

    #[test]
    fn missing_token_is_refused_before_signing() {
        let a = agent(RecordingSigner::new());
        let body = sign_body();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: None,
            body: body.as_bytes(),
        });
        assert_eq!(out.status, 403);
        assert!(!a.backend.signed.get(), "backend must not be reached");
    }

    #[test]
    fn wrong_token_is_refused_before_signing() {
        let a = agent(RecordingSigner::new());
        let body = sign_body();
        let wrong = "f".repeat(TOKEN.len());
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(&wrong),
            body: body.as_bytes(),
        });
        assert_eq!(out.status, 403);
        assert!(!a.backend.signed.get());
    }

    #[test]
    fn valid_request_signs_and_returns_signature() {
        let a = agent(RecordingSigner::new());
        let body = sign_body();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(out.status, 200, "body: {}", out.body);
        assert!(a.backend.signed.get(), "backend must be reached");
        assert_eq!(out.cors_origin.as_deref(), Some(ORIGIN));
        let value: serde_json::Value = serde_json::from_str(&out.body).unwrap();
        assert!(value.get("signature_b64").is_some());
        assert_eq!(value["algorithm"], "ecdsa-with-sha256");
    }

    #[test]
    fn a_pin_field_in_the_request_is_ignored_and_never_echoed() {
        let a = agent(RecordingSigner::new());
        // A hostile cabinet tries to smuggle a PIN; it must be dropped.
        let body = serde_json::json!({
            "key_id": "ca-key",
            "tbs_der_b64": leaf_tbs_b64(),
            "pin": "1234-secret-pin",
        })
        .to_string();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(out.status, 200);
        assert!(
            !out.body.contains("1234-secret-pin"),
            "pin must not surface"
        );
    }

    #[test]
    fn operator_decline_refuses_and_backend_is_not_reached() {
        let backend = RecordingSigner::new();
        let a = agent_with(
            backend,
            RecordingConfirmer {
                decision: false,
                called: Cell::new(false),
            },
        );
        let body = sign_body();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(out.status, 403, "body: {}", out.body);
        assert!(a.confirmer.called.get(), "confirmer must have been asked");
        assert!(
            !a.backend.signed.get(),
            "backend must not sign a declined op"
        );
    }

    #[test]
    fn unreadable_tbs_is_refused_before_confirmation() {
        let backend = RecordingSigner::new();
        // A confirmer that would approve — but must never be consulted, because
        // an unparseable TBS cannot be shown and so cannot be signed.
        let a = agent_with(
            backend,
            RecordingConfirmer {
                decision: true,
                called: Cell::new(false),
            },
        );
        let garbage = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"this is not a DER TBS",
        );
        let body = serde_json::json!({ "key_id": "ca-key", "tbs_der_b64": garbage }).to_string();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(out.status, 400, "body: {}", out.body);
        assert!(
            !a.confirmer.called.get(),
            "confirmer must not run on garbage TBS"
        );
        assert!(!a.backend.signed.get(), "backend must not sign garbage");
    }

    #[test]
    fn valid_request_with_confirmation_signs() {
        let a = agent_with(
            RecordingSigner::new(),
            RecordingConfirmer {
                decision: true,
                called: Cell::new(false),
            },
        );
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: sign_body().as_bytes(),
        });
        assert_eq!(out.status, 200, "body: {}", out.body);
        assert!(a.confirmer.called.get());
        assert!(a.backend.signed.get());
    }

    #[test]
    fn preflight_for_allowed_origin_carries_cors() {
        let a = agent(RecordingSigner::new());
        let out = a.handle(&HttpInput {
            method: ReqMethod::Options,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: None,
            body: &[],
        });
        assert_eq!(out.status, 204);
        assert!(out.preflight);
        assert_eq!(out.cors_origin.as_deref(), Some(ORIGIN));
        assert!(!a.backend.signed.get());
    }

    #[test]
    fn preflight_for_foreign_origin_is_refused() {
        let a = agent(RecordingSigner::new());
        let out = a.handle(&HttpInput {
            method: ReqMethod::Options,
            path: "/sign",
            origin: Some("https://evil.example"),
            session_token: None,
            body: &[],
        });
        assert_eq!(out.status, 403);
        assert!(out.cors_origin.is_none());
    }

    #[test]
    fn info_reports_algorithms_and_version() {
        let a = agent(RecordingSigner::new());
        let out = a.handle(&HttpInput {
            method: ReqMethod::Get,
            path: "/info",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: &[],
        });
        assert_eq!(out.status, 200);
        let value: serde_json::Value = serde_json::from_str(&out.body).unwrap();
        assert_eq!(value["algorithms"][0], "ecdsa-with-sha256");
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    }

    // --- Real-socket tests over the tiny_http server on an ephemeral port. ---

    /// A backend that flips a shared flag when it signs, so a background-thread
    /// server can be observed from the test thread.
    struct FlagSigner {
        inner: MockSigner,
        signed: Arc<AtomicBool>,
    }
    impl SignatureBackend for FlagSigner {
        fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
            self.inner.algorithm(key_id)
        }
        fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
            self.signed.store(true, Ordering::SeqCst);
            self.inner.sign(tbs_der, key_id)
        }
    }

    /// Start the agent on an ephemeral loopback port in a background thread.
    /// Returns the bound address and a flag that flips when the backend signs.
    fn spawn_agent() -> (String, Arc<AtomicBool>) {
        let signed = Arc::new(AtomicBool::new(false));
        let signed_for_backend = Arc::clone(&signed);

        let server = Server::http(("127.0.0.1", 0u16)).expect("bind loopback");
        let addr = server.server_addr().to_ip().expect("ip addr").to_string();
        // Assert we bound loopback and nothing else.
        assert!(
            addr.starts_with("127.0.0.1:"),
            "must bind only 127.0.0.1: {addr}"
        );

        let agent = Agent::new(
            FlagSigner {
                inner: MockSigner::ecdsa_sha256(KeyId::new("ca-key")),
                signed: signed_for_backend,
            },
            auto_confirm as ConfirmFn,
            config(),
            SecretString::from(TOKEN.to_owned()),
        );
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                agent.serve_one(request);
            }
        });
        (addr, signed)
    }

    /// Send one HTTP/1.1 request and return the raw response text.
    fn http_roundtrip(addr: &str, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream.write_all(request.as_bytes()).expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    }

    #[test]
    fn socket_bind_is_loopback_only_and_valid_request_signs() {
        let (addr, signed) = spawn_agent();
        let body =
            serde_json::json!({ "key_id": "ca-key", "tbs_der_b64": leaf_tbs_b64() }).to_string();
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {ORIGIN}\r\n{SESSION_HEADER}: {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len(),
        );
        let response = http_roundtrip(&addr, &request);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("signature_b64"), "{response}");
        assert!(signed.load(Ordering::SeqCst), "backend must have signed");
    }

    #[test]
    fn socket_foreign_origin_is_refused_and_backend_untouched() {
        let (addr, signed) = spawn_agent();
        let body =
            serde_json::json!({ "key_id": "ca-key", "tbs_der_b64": leaf_tbs_b64() }).to_string();
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\n{SESSION_HEADER}: {TOKEN}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len(),
        );
        let response = http_roundtrip(&addr, &request);
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(
            !signed.load(Ordering::SeqCst),
            "backend must not have signed"
        );
    }

    // --- Token file (daemon mode) ---

    /// A throwaway directory under the system temp dir, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir = std::env::temp_dir().join(format!("tessera-issuer-{tag}-{nanos}"));
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            if std::fs::remove_dir_all(&self.0).is_err() {
                // Best-effort cleanup.
            }
        }
    }

    #[test]
    fn token_file_has_private_permissions_and_overwrites() {
        let temp = TempDir::new("tokfile");
        let dir = temp.0.join("tessera-issuer");

        let path = write_token_at(&dir, "first-token").expect("write token");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first-token");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600, "token file must be 0600");
            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "token directory must be 0700");
        }

        // A restart overwrites (truncates) the previous token.
        let path2 = write_token_at(&dir, "second").expect("rewrite token");
        assert_eq!(path2, path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
    }
}

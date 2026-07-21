//! `issuer serve` — the browser-bridging local signing agent.
//!
//! The web cabinet runs as static files in the browser and cannot talk to a
//! PKCS#11 token directly. This agent is the bridge: a synchronous HTTP server
//! bound **strictly to `127.0.0.1`** that accepts a built TBS from the cabinet
//! and returns a signature from a [`SignatureBackend`] (in production, the
//! PKCS#11 adapter).
//!
//! Three defences gate every *signing* request, and the first two run *before*
//! the signing backend is ever touched:
//!
//! 1. **Paired session token (primary).** The agent mints a random token at
//!    startup and prints it once for the operator to paste into the cabinet;
//!    every request must echo it in the [`SESSION_HEADER`] header, compared in
//!    constant time. A request without the token is refused.
//! 2. **Origin (secondary).** A *present* `Origin` must be in the allowlist — the
//!    CSRF / DNS-rebinding guard — but an *absent* `Origin` is not itself a
//!    refusal, since browsers omit it on same-origin `GET` and the agent's own
//!    served cabinet must reach `/info`. CORS preflight (`OPTIONS`) is answered
//!    only for allowlisted origins.
//! 3. **Routing.** `POST /sign` and `GET /info`.
//!
//! The token PIN is entered on the agent side (terminal/pinentry, via the
//! backend's own PIN source). The HTTP surface has **no PIN field**: the sign
//! request carries only a key id and the base64 TBS, so a PIN can neither be
//! sent to nor leaked by the agent.
//!
//! # Serving the cabinet
//!
//! The agent may *also* serve the cabinet SPA on the same loopback origin as
//! `/sign`, from an external directory the operator points it at with
//! `--cabinet-dir` (see [`CabinetSource::Directory`]). The cabinet ships as a
//! separate static bundle, so the agent treats the directory as an opaque SPA
//! root: it serves the files as they are, falls back to `index.html` for any
//! non-file path (client-side routing), and never inspects what the bundle
//! contains. Static serving answers browser navigations and subresource
//! fetches — which carry neither an `Origin` nor the session token — so it runs
//! *ahead* of the gates above, but the API routes (`/sign`, `/sign-registry`,
//! `/info`) are reserved and stay gated, and a resolved file is verified to stay
//! inside the directory so nothing outside it is ever read. When it serves
//! `index.html` the agent injects the current session token and key label as
//! `<meta>` tags so the operator need not retype them.
//!
//! Without `--cabinet-dir` the agent still starts and serves a small localized
//! placeholder page at `/` telling the operator how to attach a cabinet; the
//! signing bridge works either way.

use std::io::Read as _;
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq as _;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::confirm::Confirmer;
use crate::l10n::{Caption, Locale, Msg};
use crate::sign::{KeyId, SignatureAlgorithm, SignatureBackend};
use crate::summary::{parse_operation_summary, OperationKind, OperationSummary, SummaryLine};

pub use crate::confirm::DefaultConfirmer;

/// Header carrying the paired session token on every request.
pub const SESSION_HEADER: &str = "X-Tessera-Session";

/// Largest request body the agent will read (a TBS plus base64 overhead is a
/// few KiB; this is a generous ceiling that bounds memory per request).
const MAX_BODY_BYTES: usize = 256 * 1024;

/// The SPA entry document, served for `GET /` and as the fallback for any path
/// that does not resolve to a file in the cabinet directory.
const INDEX_FILE: &str = "index.html";

/// Content type for the cabinet document.
const INDEX_CONTENT_TYPE: &str = "text/html; charset=utf-8";

/// The API routes the agent owns. They are reserved: static cabinet serving
/// never answers them (even in SPA-fallback mode), so `/sign`, `/sign-registry`,
/// and `/info` always reach their gated handlers rather than a served file or
/// `index.html`.
const RESERVED_ROUTES: &[&str] = &["/sign", "/sign-registry", "/info"];

/// The Content-Security-Policy the agent sends as a real header when it serves
/// the cabinet. It mirrors the cabinet's own `<meta>` CSP and adds
/// `frame-ancestors 'none'`, which a `<meta>` CSP cannot enforce — only an HTTP
/// header can, so hosting the cabinet from the agent is what finally applies it.
const CABINET_CSP: &str = "default-src 'self'; connect-src 'self' \
     http://127.0.0.1:* http://localhost:*; img-src 'self' data:; \
     style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; \
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// What the agent serves on the cabinet's static-file surface, if anything.
///
/// Default is [`CabinetSource::Disabled`] — a pure signing bridge. The usual
/// mode is [`CabinetSource::Directory`], an external SPA bundle the operator
/// points at with `--cabinet-dir`; [`CabinetSource::Placeholder`] is what the
/// agent serves when no directory is given, so `GET /` explains how to attach
/// one instead of returning nothing.
#[derive(Debug, Clone, Default)]
pub enum CabinetSource {
    /// Do not serve any static surface; act only as the `/sign` + `/info`
    /// bridge. `GET /` is a 404.
    #[default]
    Disabled,
    /// Serve a small localized page at `/` telling the operator to attach a
    /// cabinet with `--cabinet-dir`. The signing bridge still works.
    Placeholder,
    /// Serve an external SPA bundle from this directory. The directory is
    /// canonicalized and every resolved file is verified to stay inside it; any
    /// path that is not a file falls back to `index.html`.
    Directory(std::path::PathBuf),
}

impl CabinetSource {
    /// Whether this source serves a real cabinet SPA (as opposed to a
    /// placeholder or nothing). Only an SPA source auto-opens the browser and
    /// allowlists the agent's own loopback origin for same-origin `POST`s.
    #[must_use]
    fn serves_spa(&self) -> bool {
        matches!(self, CabinetSource::Directory(_))
    }
}

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
    /// Source of the cabinet's static assets, or [`CabinetSource::Disabled`] to
    /// run as a pure bridge.
    pub cabinet: CabinetSource,
    /// The CA key label the agent signs with, injected into the served
    /// `index.html` as `<meta name="tessera-agent-key">` so the operator need
    /// not retype it.
    pub key_label: String,
    /// The locale for the agent's operator messages.
    pub locale: Locale,
    /// Suppress auto-opening the operator's browser at startup. Ignored in pure
    /// bridge mode ([`CabinetSource::Disabled`]), where there is nothing to open.
    pub no_browser: bool,
}

/// The signing agent: a backend, an operator-confirmation channel, and the
/// request-gating policy.
pub struct Agent<B: SignatureBackend, C: Confirmer> {
    backend: B,
    confirmer: C,
    allowed_origins: Vec<String>,
    advertised_algorithms: Vec<SignatureAlgorithm>,
    cabinet: CabinetSource,
    key_label: String,
    session_token: SecretString,
    locale: Locale,
    /// The registry-signing key id, when configured. The same `backend` signs
    /// with it (a distinct key it also recognises), so `/sign-registry` never
    /// needs a second signer; `None` disables that endpoint.
    registry_key: Option<KeyId>,
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

/// What to send back: a status, a body, its content type, and whether the
/// allowed origin should be echoed in an `Access-Control-Allow-Origin` header.
struct HttpOutput {
    status: u16,
    body: Vec<u8>,
    /// The `Content-Type` to send, or `None` for an empty-body response.
    content_type: Option<&'static str>,
    cors_origin: Option<String>,
    preflight: bool,
    /// Whether to attach the cabinet [`CABINET_CSP`] header (static serving).
    csp: bool,
}

impl HttpOutput {
    /// A JSON response. `origin` is echoed in `Access-Control-Allow-Origin` when
    /// present (a cross-origin cabinet request); a same-origin request carries no
    /// `Origin`, so no CORS header is emitted.
    fn json(status: u16, body: String, origin: Option<&str>) -> Self {
        Self {
            status,
            body: body.into_bytes(),
            content_type: Some("application/json"),
            cors_origin: origin.map(str::to_owned),
            preflight: false,
            csp: false,
        }
    }

    /// A refusal that carries no CORS header — used when the origin itself is
    /// rejected, so nothing is advertised back to a foreign page.
    fn refused(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
            content_type: None,
            cors_origin: None,
            preflight: false,
            csp: false,
        }
    }

    /// A served cabinet asset: its own content type, no CORS header (the SPA is
    /// same-origin), and the cabinet CSP header attached.
    fn asset(status: u16, body: Vec<u8>, content_type: &'static str) -> Self {
        Self {
            status,
            body,
            content_type: Some(content_type),
            cors_origin: None,
            preflight: false,
            csp: true,
        }
    }

    /// A 404 within the cabinet route set (asset missing on disk): carries the
    /// CSP header but no body, and never touches the filesystem beyond the set.
    fn asset_not_found() -> Self {
        Self {
            status: 404,
            body: Vec::new(),
            content_type: None,
            cors_origin: None,
            preflight: false,
            csp: true,
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
            cabinet: config.cabinet,
            key_label: config.key_label,
            session_token,
            locale: config.locale,
            registry_key: None,
        }
    }

    /// Configure the registry-signing key the agent's `/sign-registry` endpoint
    /// uses. The `backend` passed to [`Agent::new`] must also recognise this key
    /// id (a second key in the same store); the caller is expected to have
    /// validated it first with [`validate_registry_key`].
    #[must_use]
    pub fn with_registry_key(mut self, registry_key: KeyId) -> Self {
        self.registry_key = Some(registry_key);
        self
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

    /// Apply the full policy to a decomposed request.
    ///
    /// The paired token is the primary gate and is always required. Origin is a
    /// secondary check: a *present* `Origin` must be allowlisted, but an *absent*
    /// one is not itself a refusal — browsers omit `Origin` on same-origin `GET`,
    /// so the agent's own served cabinet must be able to reach `/info`. A
    /// cross-origin page cannot read the injected token, nor set the session
    /// header on a cross-origin request without a preflight the allowlist blocks,
    /// and DNS-rebinding carries the attacker's own `Origin` — caught here.
    fn handle(&self, input: &HttpInput<'_>) -> HttpOutput {
        // Static cabinet serving (opt-in) answers browser navigations and asset
        // fetches, which carry neither an Origin nor the session token. It runs
        // ahead of the gates below but only for the fixed cabinet asset set, and
        // never for `/sign` or `/info`, which stay gated.
        if input.method == ReqMethod::Get {
            if let Some(response) = self.try_serve_cabinet(input.path) {
                return response;
            }
        }

        // 1. Origin — a present Origin must be allowlisted; an absent one falls
        //    through to the token gate (same-origin requests omit it).
        let origin = match input.origin {
            Some(o) if self.origin_allowed(o) => Some(o),
            Some(_) => return HttpOutput::refused(403),
            None => None,
        };

        // 2. Preflight for an allowlisted origin.
        if input.method == ReqMethod::Options {
            return HttpOutput {
                status: 204,
                body: Vec::new(),
                content_type: None,
                cors_origin: origin.map(str::to_owned),
                preflight: true,
                csp: false,
            };
        }

        // 3. Paired session token — the primary gate, refused before the backend.
        if !self.token_ok(input.session_token) {
            return HttpOutput::json(403, error_json("invalid or missing session token"), origin);
        }

        // 4. Route.
        match (input.method, input.path) {
            (ReqMethod::Post, "/sign") => self.handle_sign(origin, input.body),
            (ReqMethod::Post, "/sign-registry") => self.handle_sign_registry(origin, input.body),
            (ReqMethod::Get, "/info") => self.handle_info(origin),
            _ => HttpOutput::json(404, error_json("not found"), origin),
        }
    }

    fn handle_sign(&self, origin: Option<&str>, body: &[u8]) -> HttpOutput {
        let Ok(request) = serde_json::from_slice::<SignRequest>(body) else {
            return HttpOutput::json(400, error_json("malformed sign request"), origin);
        };
        let Ok(tbs) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            request.tbs_der_b64.as_bytes(),
        ) else {
            return HttpOutput::json(400, error_json("tbs_der_b64 is not base64"), origin);
        };
        // Domain separation: the registry key signs registries and nothing else.
        // Even though the backend can address it, `/sign` must never let a caller
        // borrow it to sign a TBS — so refuse a request naming the registry key
        // here, before the backend is touched.
        if self
            .registry_key
            .as_ref()
            .is_some_and(|reg| reg.as_str() == request.key_id)
        {
            return HttpOutput::json(
                403,
                error_json("the registry key cannot sign issuance requests"),
                origin,
            );
        }
        let key = KeyId::new(request.key_id);

        // The agent is a trusted display: parse the TBS with the shared code and
        // refuse anything unreadable *before* prompting — what cannot be shown
        // cannot be signed.
        let Ok(summary) = parse_operation_summary(&tbs) else {
            println!("{}", Msg::ServeUnreadableTbs.text(self.locale));
            return HttpOutput::json(400, error_json("TBS is not a readable operation"), origin);
        };
        // The session token authenticated the cabinet; operator confirmation
        // authorizes this specific operation. Both are required.
        match self.confirmer.confirm(&summary) {
            Ok(true) => {}
            Ok(false) => {
                println!(
                    "{} {} — {}",
                    Msg::ServeOperatorDeclined.text(self.locale),
                    summary.kind.label(self.locale),
                    summary.subject
                );
                return HttpOutput::json(
                    403,
                    error_json("operation not confirmed by operator"),
                    origin,
                );
            }
            Err(e) => {
                println!("{} {e}", Msg::ServeConfirmChannelFailed.text(self.locale));
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

    /// Sign an exported device registry with the dedicated registry key.
    ///
    /// The key is fixed by configuration — the request carries only the payload,
    /// never a key id — so a caller can never redirect this to the issuance key.
    /// The payload is signed as raw bytes (the backend digests it with SHA-256),
    /// and the DER `Ecdsa-Sig-Value` the backend returns is converted to the raw
    /// `r || s` the cabinet's snapshot verifier expects.
    ///
    /// Signing goes through the same operator-confirmation channel as issuance:
    /// the operator is shown the registry's SHA-256 digest, its size, and the
    /// signing-key label, and a decline is refused before the backend is touched.
    /// The session token authenticates the cabinet; this confirmation authorizes
    /// the specific registry — a substituted cabinet cannot get a silent
    /// attestation signature.
    fn handle_sign_registry(&self, origin: Option<&str>, body: &[u8]) -> HttpOutput {
        let Some(registry_key) = self.registry_key.as_ref() else {
            return HttpOutput::json(400, error_json("registry key is not configured"), origin);
        };
        let Ok(request) = serde_json::from_slice::<SignRegistryRequest>(body) else {
            return HttpOutput::json(400, error_json("malformed registry sign request"), origin);
        };
        let Ok(payload) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            request.payload_b64.as_bytes(),
        ) else {
            return HttpOutput::json(400, error_json("payload_b64 is not base64"), origin);
        };

        // The session token authenticated the cabinet; operator confirmation
        // authorizes this specific registry. A registry has no TBS to parse, so
        // the operator is shown its SHA-256 digest, size, and the signing-key
        // label — enough to attest to the exact bytes without trusting the
        // (possibly substituted) cabinet. Both are required, as for issuance.
        let summary = registry_summary(registry_key, &payload);
        match self.confirmer.confirm(&summary) {
            Ok(true) => {}
            Ok(false) => {
                println!(
                    "{} {} — {}",
                    Msg::ServeOperatorDeclined.text(self.locale),
                    summary.kind.label(self.locale),
                    registry_key.as_str()
                );
                return HttpOutput::json(
                    403,
                    error_json("operation not confirmed by operator"),
                    origin,
                );
            }
            Err(e) => {
                println!("{} {e}", Msg::ServeConfirmChannelFailed.text(self.locale));
                return HttpOutput::json(
                    500,
                    error_json("confirmation channel unavailable"),
                    origin,
                );
            }
        }

        match self.backend.sign(&payload, registry_key) {
            Ok(signature) => match ecdsa_der_to_raw(&signature.bytes) {
                Ok(raw) => {
                    let body = serde_json::json!({
                        "signature_b64": base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            raw,
                        ),
                    })
                    .to_string();
                    HttpOutput::json(200, body, origin)
                }
                Err(()) => HttpOutput::json(
                    502,
                    error_json("registry backend returned a non-P-256 signature"),
                    origin,
                ),
            },
            Err(e) => HttpOutput::json(
                502,
                error_json(&format!("registry signing failed: {e}")),
                origin,
            ),
        }
    }

    fn handle_info(&self, origin: Option<&str>) -> HttpOutput {
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

    /// Serve the cabinet's static surface for a `GET` `path`, or `None` to fall
    /// through to the gated routes (`/info`, `/sign`, and any other path).
    ///
    /// The reserved API routes are never served here, so they stay gated; a
    /// [`CabinetSource::Directory`] otherwise serves files as they are and falls
    /// back to `index.html` for non-file paths, and [`CabinetSource::Placeholder`]
    /// answers only `/` with the attach-a-cabinet page.
    fn try_serve_cabinet(&self, path: &str) -> Option<HttpOutput> {
        match &self.cabinet {
            CabinetSource::Disabled => None,
            CabinetSource::Placeholder => self.try_serve_placeholder(path),
            CabinetSource::Directory(root) => self.try_serve_spa(root, path),
        }
    }

    /// Serve the localized placeholder page at `/` (and `/index.html`); every
    /// other path falls through so the API routes stay gated.
    fn try_serve_placeholder(&self, path: &str) -> Option<HttpOutput> {
        if path == "/" || path == "/index.html" {
            let page = placeholder_page(self.locale);
            Some(HttpOutput::asset(
                200,
                page.into_bytes(),
                INDEX_CONTENT_TYPE,
            ))
        } else {
            None
        }
    }

    /// Serve `path` from the external SPA directory `root`.
    ///
    /// An existing file is served with a content type guessed from its
    /// extension; any other path falls back to `index.html` for client-side
    /// routing. The reserved API routes are excluded first so they never resolve
    /// to a file or the fallback. Containment is enforced in [`read_file_within`],
    /// so a path escaping the directory reads nothing and falls back like any
    /// other non-file path.
    fn try_serve_spa(&self, root: &Path, path: &str) -> Option<HttpOutput> {
        if RESERVED_ROUTES.contains(&path) {
            return None;
        }
        let rel = path.strip_prefix('/').unwrap_or(path);
        if rel != INDEX_FILE {
            if let Some(bytes) = read_file_within(root, rel) {
                return Some(HttpOutput::asset(200, bytes, content_type_for(rel)));
            }
        }
        // The entry document (requested directly, or reached as the SPA
        // fallback) gets the agent `<meta>` injection; a bundle with no
        // `index.html` is a cabinet 404 rather than a filesystem probe.
        match read_file_within(root, INDEX_FILE) {
            Some(bytes) => Some(self.serve_index(&bytes)),
            None => Some(HttpOutput::asset_not_found()),
        }
    }

    /// Build the `index.html` response, injecting the session token and key
    /// label as `<meta>` tags so the served cabinet pairs without manual entry.
    fn serve_index(&self, bytes: &[u8]) -> HttpOutput {
        let html = String::from_utf8_lossy(bytes);
        let injected =
            inject_agent_meta(&html, self.session_token.expose_secret(), &self.key_label);
        HttpOutput::asset(200, injected.into_bytes(), INDEX_CONTENT_TYPE)
    }
}

/// Read `rel` from within `root`, refusing anything that escapes it.
///
/// Both the root and the resolved file are canonicalized and containment is
/// checked, so a `..` segment or a symlink pointing outside the directory reads
/// nothing (returns `None`). `rel` is an untrusted request path, so this check
/// is the only thing standing between the caller and the wider filesystem.
fn read_file_within(root: &Path, rel: &str) -> Option<Vec<u8>> {
    let root = root.canonicalize().ok()?;
    let candidate = root.join(rel).canonicalize().ok()?;
    if !candidate.starts_with(&root) {
        return None;
    }
    std::fs::read(&candidate).ok()
}

/// Guess a response content type from a file's extension, defaulting to
/// `application/octet-stream` for anything unrecognized. The cabinet is an
/// opaque external bundle, so this covers the common SPA asset types rather than
/// a fixed manifest.
fn content_type_for(rel: &str) -> &'static str {
    let ext = Path::new(rel)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    match ext {
        "html" | "htm" => INDEX_CONTENT_TYPE,
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "wasm" => "application/wasm",
        "json" | "map" => "application/json",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// The localized placeholder document served at `/` when no cabinet directory is
/// attached. It carries no script and no operator input, only two static
/// localized strings, so no escaping is needed.
fn placeholder_page(locale: Locale) -> String {
    let title = Msg::CabinetNotConnectedTitle.text(locale);
    let body = Msg::CabinetNotConnectedBody.text(locale);
    let lang = match locale {
        Locale::Ru => "ru",
        Locale::En => "en",
    };
    format!(
        "<!doctype html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\" />\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n\
         <title>{title}</title>\n</head>\n<body>\n<main>\n<h1>{title}</h1>\n<p>{body}</p>\n\
         </main>\n</body>\n</html>\n",
    )
}

/// Inject the session token and key label into the cabinet's `index.html` as
/// `<meta>` tags, right after the opening `<head>` tag.
///
/// Only `<meta>` tags are added — no inline script — so the cabinet's
/// `script-src` CSP is untouched. Both values are HTML-attribute-escaped. If no
/// `<head>` is found (not the case for the project's own asset), the HTML is
/// returned unchanged.
fn inject_agent_meta(html: &str, token: &str, key_label: &str) -> String {
    let Some(insert_at) = head_insert_index(html) else {
        // Fail-safe: the cabinet still loads and falls back to manual entry. But
        // a silent skip would hide a future index.html restructure that quietly
        // disables pairing, so make it visible on the agent's console.
        eprintln!(
            "issuer serve: warning — cabinet index.html has no <head>; \
             session token and key were not injected (manual entry required)"
        );
        return html.to_owned();
    };
    let meta = format!(
        "\n    <meta name=\"tessera-agent-token\" content=\"{}\" />\
         \n    <meta name=\"tessera-agent-key\" content=\"{}\" />",
        escape_attr(token),
        escape_attr(key_label),
    );
    let mut out = String::with_capacity(html.len() + meta.len());
    out.push_str(&html[..insert_at]);
    out.push_str(&meta);
    out.push_str(&html[insert_at..]);
    out
}

/// The byte offset just past the first `<head …>` opening tag, or `None`.
fn head_insert_index(html: &str) -> Option<usize> {
    let start = html.find("<head")?;
    let close = html[start..].find('>')?;
    Some(start + close + 1)
}

/// Escape a string for use inside a double-quoted HTML attribute.
fn escape_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Run the agent: bind `127.0.0.1:<port>`, print the ephemeral address and a
/// freshly generated session token, then serve requests until the process is
/// stopped.
///
/// When `registry_key` is set, the agent also answers `/sign-registry`, signing
/// exported device registries with that key (a second key the same `backend`
/// recognises). It is validated with [`validate_registry_key`] *before* the
/// socket is bound, so a misconfigured registry key fails fast.
///
/// # Errors
///
/// - [`ServeError::Bind`] when the loopback socket cannot be bound.
/// - [`ServeError::RegistryKeyCollision`], [`ServeError::RegistryKeyNotP256`],
///   or [`ServeError::RegistryKeyUnavailable`] when a configured registry key
///   fails validation.
pub fn serve<B: SignatureBackend, C: Confirmer>(
    backend: B,
    confirmer: C,
    mut config: AgentConfig,
    registry_key: Option<KeyId>,
) -> Result<(), ServeError> {
    // Validate the registry key before touching the socket, so a misconfigured
    // key never reaches a listening state.
    if let Some(registry_key) = &registry_key {
        validate_registry_key(&backend, registry_key, &config.key_label)?;
    }
    let hex = random_session_token();
    let server = Server::http(("127.0.0.1", config.bind_port))
        .map_err(|e| ServeError::Bind(e.to_string()))?;
    let bound = server
        .server_addr()
        .to_ip()
        .map_or_else(|| "127.0.0.1".to_owned(), |a| a.to_string());
    let address = format!("http://{bound}");
    println!("{} {address}", Msg::ServeListening.text(config.locale));
    // When the agent serves a real cabinet SPA, the served page's same-origin
    // `POST` carries the agent's own loopback origin — known only now that the
    // port is bound (important under `--port 0`). Add it so that gate passes
    // without the operator supplying `--allow-origin`.
    let serves_spa = config.cabinet.serves_spa();
    if serves_spa {
        config.allowed_origins.extend(self_origins(&bound));
    }
    // The pairing token is printed for the operator to paste into the cabinet;
    // when the agent also serves the cabinet, it is injected into the served
    // page so no manual entry is needed.
    println!("{} {hex}", Msg::ServeSessionToken.text(config.locale));
    // The agent runs in the foreground until interrupted; tell the operator how.
    println!("{}", Msg::ServeStopHint.text(config.locale));
    // Auto-open the operator's browser at the cabinet — but only when a real
    // cabinet SPA is served and the operator did not opt out. A failed open is
    // non-fatal: the address is already printed for manual use.
    if should_open_browser(serves_spa, config.no_browser) && !open_browser(&address) {
        eprintln!("{}", Msg::ServeBrowserOpenFailed.text(config.locale));
    }
    let mut agent = Agent::new(backend, confirmer, config, SecretString::from(hex));
    if let Some(registry_key) = registry_key {
        agent = agent.with_registry_key(registry_key);
    }
    for request in server.incoming_requests() {
        agent.serve_one(request);
    }
    Ok(())
}

/// Whether to auto-open the operator's browser at the agent address.
///
/// Only when the agent serves a real cabinet SPA (a pure bridge or the
/// placeholder page has nothing worth opening) and the operator did not pass
/// `--no-browser`.
fn should_open_browser(serves_spa: bool, no_browser: bool) -> bool {
    serves_spa && !no_browser
}

/// Best-effort launch of the operator's default browser at `url`.
///
/// Spawns the platform opener (`open` on macOS, `xdg-open` on Linux/BSD, `cmd /C
/// start` on Windows) detached — no wait — with its streams discarded. Returns
/// `true` when the opener was spawned; `false` when it could not be (missing
/// binary, spawn error), so the caller can warn and carry on. The address is
/// already printed, so a failed open is never fatal.
fn open_browser(url: &str) -> bool {
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        // `start` is a `cmd` builtin; the empty `""` is its window-title argument
        // so a URL with spaces is not mistaken for the title.
        let mut command = Command::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };

    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

/// The agent's own loopback origins for a bound `host:port`, in both the
/// `127.0.0.1` and `localhost` spellings (matching the cabinet CSP's
/// `connect-src`), so a same-origin cabinet `POST` is accepted however the
/// operator opened the page.
fn self_origins(bound_addr: &str) -> Vec<String> {
    let mut origins = vec![format!("http://{bound_addr}")];
    if let Some(port) = bound_addr.rsplit(':').next() {
        origins.push(format!("http://localhost:{port}"));
    }
    origins
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
            Err(()) => {
                HttpOutput::json(413, error_json("request body too large"), origin.as_deref())
            }
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
    let mut response = Response::from_data(output.body.clone()).with_status_code(output.status);
    if let Some(content_type) = output.content_type {
        if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()) {
            response = response.with_header(h);
        }
    }
    // The `csp` flag marks a static cabinet response (an asset, the placeholder,
    // or a cabinet 404). Such responses carry the cabinet CSP and, since their
    // Content-Type is guessed from the file extension, `nosniff` so the browser
    // does not MIME-sniff a served file into a more dangerous type.
    if output.csp {
        if let Ok(h) = Header::from_bytes(&b"Content-Security-Policy"[..], CABINET_CSP.as_bytes()) {
            response = response.with_header(h);
        }
        if let Ok(h) = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]) {
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

/// The registry-sign request body. Only the payload is read: there is no key
/// field, so a caller cannot select which key signs — it is always the
/// configured registry key. Any extra field is ignored by serde.
#[derive(serde::Deserialize)]
struct SignRegistryRequest {
    payload_b64: String,
}

/// Convert a DER `Ecdsa-Sig-Value` (`SEQUENCE { INTEGER r, INTEGER s }`) to the
/// fixed-width raw `r || s` (64 bytes for P-256) the cabinet's snapshot verifier
/// expects — `WebCrypto`'s default ECDSA encoding.
///
/// Returns `Err(())` when the bytes are not a valid P-256 signature (the backend
/// signed with a curve other than P-256, or returned something unparsable).
fn ecdsa_der_to_raw(der: &[u8]) -> Result<[u8; 64], ()> {
    let signature = p256::ecdsa::Signature::from_der(der).map_err(|_| ())?;
    Ok(signature.to_bytes().into())
}

/// Build the operator-confirmation summary for a registry signing request.
///
/// A registry carries no certificate structure to parse, so the summary shows
/// the exact payload's SHA-256 digest and byte length, plus the signing-key
/// label — the datum the operator attests to. It has no subject or validity
/// window (see [`OperationKind::DeviceRegistry`]).
fn registry_summary(key: &KeyId, payload: &[u8]) -> OperationSummary {
    use sha2::{Digest as _, Sha256};

    let digest = hex::encode(Sha256::digest(payload));
    OperationSummary {
        kind: OperationKind::DeviceRegistry,
        subject: String::new(),
        not_before: String::new(),
        not_after: String::new(),
        lines: vec![
            SummaryLine {
                caption: Caption::Key,
                value: key.as_str().to_owned(),
            },
            SummaryLine {
                caption: Caption::Digest,
                value: format!("sha256:{digest}"),
            },
            SummaryLine {
                caption: Caption::Size,
                value: format!("{} bytes", payload.len()),
            },
        ],
    }
}

/// Validate a registry-signing key before the agent accepts it.
///
/// Two conditions must hold, checked in this order so a label collision is
/// reported as such even when both keys happen to be P-256:
///
/// 1. The registry key label differs from the issuance key label. The check is a
///    plain string comparison of labels: aliasing one physical key under two
///    labels is not detected and is the operator's responsibility (see the
///    `issuer` docs).
/// 2. The backend signs the registry key with ECDSA P-256, the only algorithm
///    the cabinet's registry verifier accepts.
///
/// # Errors
///
/// - [`ServeError::RegistryKeyCollision`] when the labels are equal.
/// - [`ServeError::RegistryKeyNotP256`] when the backend reports a non-P-256
///   algorithm for the registry key.
/// - [`ServeError::RegistryKeyUnavailable`] when the backend does not recognise
///   the registry key at all.
pub fn validate_registry_key<B: SignatureBackend>(
    backend: &B,
    registry_key: &KeyId,
    issue_label: &str,
) -> Result<(), ServeError> {
    if registry_key.as_str() == issue_label {
        return Err(ServeError::RegistryKeyCollision);
    }
    match backend.algorithm(registry_key) {
        Ok(SignatureAlgorithm::EcdsaWithSha256) => Ok(()),
        Ok(other) => Err(ServeError::RegistryKeyNotP256(other)),
        Err(e) => Err(ServeError::RegistryKeyUnavailable(e.to_string())),
    }
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

/// Errors from starting the agent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The loopback socket could not be bound.
    #[error("failed to bind 127.0.0.1 agent socket: {0}")]
    Bind(String),
    /// The registry key label equals the issuance key label. A distinct key must
    /// sign registries so the issuance and registry domains never share a key.
    #[error("registry key label must differ from the issuance key label")]
    RegistryKeyCollision,
    /// The registry key does not sign with ECDSA P-256, the only algorithm the
    /// cabinet's registry verifier accepts.
    #[error("registry key must be ECDSA P-256, but the backend reports {0:?}")]
    RegistryKeyNotP256(SignatureAlgorithm),
    /// The signing backend does not recognise the configured registry key.
    #[error("registry key is not usable by the signing backend: {0}")]
    RegistryKeyUnavailable(String),
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
    use crate::confirm::ConfirmError;
    use crate::sign::{MockSigner, SignError, Signature};
    use crate::summary::OperationSummary;
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

    const KEY_LABEL: &str = "ca-key";

    fn config() -> AgentConfig {
        config_with_cabinet(CabinetSource::Disabled)
    }

    fn config_with_cabinet(cabinet: CabinetSource) -> AgentConfig {
        AgentConfig {
            bind_port: 0,
            allowed_origins: vec![ORIGIN.to_owned()],
            advertised_algorithms: vec![SignatureAlgorithm::EcdsaWithSha256],
            cabinet,
            key_label: KEY_LABEL.to_owned(),
            locale: Locale::En,
            no_browser: true,
        }
    }

    #[test]
    fn browser_opens_only_when_serving_cabinet_and_not_opted_out() {
        // Serving the cabinet and not opted out: open.
        assert!(should_open_browser(true, false));
        // Opted out with `--no-browser`: do not open.
        assert!(!should_open_browser(true, true));
        // Pure bridge (no cabinet): nothing to open, regardless of the flag.
        assert!(!should_open_browser(false, false));
        assert!(!should_open_browser(false, true));
    }

    fn agent(backend: RecordingSigner) -> Agent<RecordingSigner, ConfirmFn> {
        Agent::new(
            backend,
            auto_confirm as ConfirmFn,
            config(),
            SecretString::from(TOKEN.to_owned()),
        )
    }

    fn agent_serving(
        backend: RecordingSigner,
        cabinet: CabinetSource,
    ) -> Agent<RecordingSigner, ConfirmFn> {
        Agent::new(
            backend,
            auto_confirm as ConfirmFn,
            config_with_cabinet(cabinet),
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
            user_binding: vec!["oper".to_owned()],
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
    fn absent_origin_with_valid_token_is_served() {
        // A same-origin `POST` from the served cabinet carries the token but the
        // browser may omit `Origin`; the token is the gate, so it is honoured.
        let a = agent(RecordingSigner::new());
        let body = sign_body();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: None,
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(a.backend.signed.get(), "backend must sign");
        assert!(
            out.cors_origin.is_none(),
            "no CORS header when the request had no Origin"
        );
    }

    #[test]
    fn absent_origin_without_token_is_refused() {
        // Absent Origin is not a free pass: the token still gates.
        let a = agent(RecordingSigner::new());
        let body = sign_body();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: None,
            session_token: None,
            body: body.as_bytes(),
        });
        assert_eq!(out.status, 403);
        assert!(!a.backend.signed.get(), "backend must not be reached");
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
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(a.backend.signed.get(), "backend must be reached");
        assert_eq!(out.cors_origin.as_deref(), Some(ORIGIN));
        let value: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
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
            !String::from_utf8_lossy(&out.body).contains("1234-secret-pin"),
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
        assert_eq!(
            out.status,
            403,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
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
        assert_eq!(
            out.status,
            400,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
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
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
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
        let value: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
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

    // --- Cabinet static serving ---

    /// A throwaway directory under the system temp dir, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir = std::env::temp_dir().join(format!("tessera-issuer-{tag}-{nanos}"));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn write(&self, name: &str, contents: &[u8]) {
            std::fs::write(self.0.join(name), contents).expect("write asset");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            if std::fs::remove_dir_all(&self.0).is_err() {
                // Best-effort cleanup.
            }
        }
    }

    /// A cabinet bundle directory with a minimal `index.html` (carrying a
    /// `<head>`) and a spread of typical SPA assets, served from a temporary
    /// directory. Includes a `fonts/` subdirectory so tests can prove a file in a
    /// subdirectory serves.
    fn cabinet_dir() -> TempDir {
        let dir = TempDir::new("cabinet");
        dir.write(
            "index.html",
            b"<!doctype html>\n<html>\n  <head>\n    <title>Cabinet</title>\n  </head>\n  <body></body>\n</html>\n",
        );
        dir.write("main.js", b"export const x = 1;\n");
        dir.write("styles.css", b"body{}\n");
        dir.write("cabinet.wasm", b"\0asm\x01\0\0\0");
        std::fs::create_dir_all(dir.0.join("fonts")).expect("create fonts dir");
        dir.write("fonts/inter-400.woff2", b"wOF2-inter-400-fake");
        dir
    }

    fn source(dir: &TempDir) -> CabinetSource {
        CabinetSource::Directory(dir.0.clone())
    }

    fn get(agent: &Agent<RecordingSigner, ConfirmFn>, path: &str) -> HttpOutput {
        // A browser navigation / subresource GET carries no Origin and no token.
        agent.handle(&HttpInput {
            method: ReqMethod::Get,
            path,
            origin: None,
            session_token: None,
            body: &[],
        })
    }

    #[test]
    fn index_is_served_with_html_content_type_and_injected_meta() {
        let dir = cabinet_dir();
        let a = agent_serving(RecordingSigner::new(), source(&dir));
        let out = get(&a, "/");
        assert_eq!(out.status, 200);
        assert_eq!(out.content_type, Some(INDEX_CONTENT_TYPE));
        let html = String::from_utf8(out.body).unwrap();
        assert!(
            html.contains(&format!(
                "<meta name=\"tessera-agent-token\" content=\"{TOKEN}\" />"
            )),
            "index must carry the session token meta: {html}"
        );
        assert!(
            html.contains(&format!(
                "<meta name=\"tessera-agent-key\" content=\"{KEY_LABEL}\" />"
            )),
            "index must carry the key label meta: {html}"
        );
        assert!(out.csp, "served document must carry the CSP header");
    }

    #[test]
    fn each_asset_is_served_with_its_content_type() {
        let dir = cabinet_dir();
        let a = agent_serving(RecordingSigner::new(), source(&dir));
        for (path, expected) in [
            ("/main.js", "text/javascript"),
            ("/styles.css", "text/css"),
            ("/cabinet.wasm", "application/wasm"),
        ] {
            let out = get(&a, path);
            assert_eq!(out.status, 200, "{path}");
            assert_eq!(out.content_type, Some(expected), "{path}");
            assert!(!out.body.is_empty(), "{path}");
        }
    }

    #[test]
    fn a_file_in_a_subdirectory_is_served_with_its_guessed_type() {
        let dir = cabinet_dir();
        let a = agent_serving(RecordingSigner::new(), source(&dir));

        // A file under `fonts/` is served with a type guessed from its
        // extension. Static serving runs ahead of the gates, so it answers a
        // request that carries a token...
        let with_token = a.handle(&HttpInput {
            method: ReqMethod::Get,
            path: "/fonts/inter-400.woff2",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: &[],
        });
        assert_eq!(with_token.status, 200);
        assert_eq!(with_token.content_type, Some("font/woff2"));
        assert!(!with_token.body.is_empty());
        assert!(with_token.csp, "a served font carries the cabinet CSP");

        // ...and, like every other subresource, one that carries none: a browser
        // font fetch sends neither an Origin nor the session token.
        let without_token = get(&a, "/fonts/inter-400.woff2");
        assert_eq!(without_token.status, 200);
        assert_eq!(without_token.content_type, Some("font/woff2"));
    }

    #[test]
    fn a_non_file_path_falls_back_to_the_index() {
        // A client-side route (no file on disk) resolves to index.html so the SPA
        // router can take over; the served document carries the injected meta.
        let dir = cabinet_dir();
        let a = agent_serving(RecordingSigner::new(), source(&dir));
        let out = get(&a, "/issue/some/deep/route");
        assert_eq!(out.status, 200);
        assert_eq!(out.content_type, Some(INDEX_CONTENT_TYPE));
        let html = String::from_utf8(out.body).unwrap();
        assert!(
            html.contains("tessera-agent-token"),
            "the fallback document is the injected index: {html}"
        );
    }

    #[test]
    fn a_missing_asset_with_an_extension_also_falls_back_to_the_index() {
        // A subresource that does not exist is not a 404 file probe: it too falls
        // back to index.html (standard SPA catch-all), never leaking a filesystem
        // miss as a distinct status.
        let dir = cabinet_dir();
        let a = agent_serving(RecordingSigner::new(), source(&dir));
        let out = get(&a, "/does-not-exist.js");
        assert_eq!(out.status, 200);
        assert_eq!(out.content_type, Some(INDEX_CONTENT_TYPE));
    }

    #[test]
    fn path_traversal_reads_nothing_outside_the_directory() {
        let dir = cabinet_dir();
        // Plant a file next to (outside) the served directory.
        std::fs::write(dir.0.join("..").join("outside.txt"), b"secret").ok();
        let a = agent_serving(RecordingSigner::new(), source(&dir));
        for path in ["/../outside.txt", "/../../Cargo.toml", "/..%2fCargo.toml"] {
            let out = a.handle(&HttpInput {
                method: ReqMethod::Get,
                path,
                origin: Some(ORIGIN),
                session_token: Some(TOKEN),
                body: &[],
            });
            // Containment means nothing outside the directory is ever read; the
            // path is just an unknown route, so it falls back to index.html — the
            // outside file's contents can never appear in the response.
            assert!(
                !out.body.windows(6).any(|w| w == b"secret"),
                "{path} must not leak file contents"
            );
            assert!(
                !out.body.windows(11).any(|w| w == b"[workspace]"),
                "{path} must not leak the workspace Cargo.toml"
            );
        }
    }

    #[test]
    fn sign_without_token_is_still_refused_while_serving_cabinet() {
        let dir = cabinet_dir();
        let a = agent_serving(RecordingSigner::new(), source(&dir));
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: None,
            body: sign_body().as_bytes(),
        });
        assert_eq!(out.status, 403);
        assert!(!a.backend.signed.get(), "backend must not be reached");
    }

    #[test]
    fn without_cabinet_root_is_not_served() {
        // Pure bridge mode (`--no-cabinet`): `GET /` with a valid origin and
        // token is a 404, never a document.
        let a = agent(RecordingSigner::new());
        let out = a.handle(&HttpInput {
            method: ReqMethod::Get,
            path: "/",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: &[],
        });
        assert_eq!(out.status, 404);
        assert!(!out.csp, "bridge mode sends no cabinet CSP");
    }

    #[test]
    fn placeholder_page_is_served_at_root_without_a_cabinet_dir() {
        // No `--cabinet-dir`: `GET /` serves the localized placeholder page, and
        // it carries no injected session token (there is no cabinet to pair).
        let a = agent_serving(RecordingSigner::new(), CabinetSource::Placeholder);
        let out = get(&a, "/");
        assert_eq!(out.status, 200);
        assert_eq!(out.content_type, Some(INDEX_CONTENT_TYPE));
        assert!(out.csp, "the placeholder page carries the cabinet CSP");
        let html = String::from_utf8(out.body).unwrap();
        assert!(
            html.contains("--cabinet-dir"),
            "the placeholder tells the operator how to attach a cabinet: {html}"
        );
        assert!(
            !html.contains("tessera-agent-token"),
            "the placeholder must not inject a session token"
        );
    }

    #[test]
    fn placeholder_mode_keeps_info_gated_and_signing_working() {
        let a = agent_serving(RecordingSigner::new(), CabinetSource::Placeholder);
        // `/info` is reserved, so the placeholder never shadows it: no token → 403.
        let refused = a.handle(&HttpInput {
            method: ReqMethod::Get,
            path: "/info",
            origin: Some(ORIGIN),
            session_token: None,
            body: &[],
        });
        assert_eq!(refused.status, 403);
        // The signing bridge still works in placeholder mode.
        let signed = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: sign_body().as_bytes(),
        });
        assert_eq!(
            signed.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&signed.body)
        );
        assert!(a.backend.signed.get(), "backend must sign");
    }

    #[test]
    fn missing_asset_is_a_cabinet_404_not_a_filesystem_probe() {
        let dir = TempDir::new("empty-cabinet");
        // No index.html on disk, but serving is enabled.
        let a = agent_serving(RecordingSigner::new(), source(&dir));
        let out = get(&a, "/");
        assert_eq!(out.status, 404);
        assert!(out.csp);
        assert!(out.body.is_empty());
    }

    #[test]
    fn info_stays_gated_while_serving_cabinet() {
        let dir = cabinet_dir();
        let a = agent_serving(RecordingSigner::new(), source(&dir));
        // No token: `/info` is not a cabinet asset, so it falls through and the
        // token gate refuses it.
        let refused = a.handle(&HttpInput {
            method: ReqMethod::Get,
            path: "/info",
            origin: Some(ORIGIN),
            session_token: None,
            body: &[],
        });
        assert_eq!(refused.status, 403);
        // With a token, `/info` answers as usual.
        let ok = a.handle(&HttpInput {
            method: ReqMethod::Get,
            path: "/info",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: &[],
        });
        assert_eq!(ok.status, 200);
    }

    #[test]
    fn attribute_escaping_neutralizes_a_hostile_key_label() {
        let escaped = escape_attr("evil\"><script>alert(1)</script>");
        assert!(!escaped.contains('<'), "{escaped}");
        assert!(!escaped.contains('"'), "{escaped}");
        assert!(
            escaped.contains("&quot;") && escaped.contains("&lt;"),
            "{escaped}"
        );
    }

    #[test]
    fn self_origins_cover_both_loopback_spellings() {
        let origins = self_origins("127.0.0.1:53421");
        assert!(
            origins.contains(&"http://127.0.0.1:53421".to_owned()),
            "{origins:?}"
        );
        assert!(
            origins.contains(&"http://localhost:53421".to_owned()),
            "{origins:?}"
        );
    }

    #[test]
    fn same_origin_post_from_served_cabinet_is_accepted() {
        // Mirror what `serve` does after bind: add the bound loopback origin to
        // the allowlist, then a `POST /sign` carrying that Origin passes.
        let bound = "127.0.0.1:53999";
        let self_origin = format!("http://{bound}");
        let mut cfg = config_with_cabinet(CabinetSource::Disabled);
        cfg.allowed_origins.extend(self_origins(bound));
        let a = Agent::new(
            RecordingSigner::new(),
            auto_confirm as ConfirmFn,
            cfg,
            SecretString::from(TOKEN.to_owned()),
        );
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(&self_origin),
            session_token: Some(TOKEN),
            body: sign_body().as_bytes(),
        });
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(a.backend.signed.get());
        assert_eq!(out.cors_origin.as_deref(), Some(self_origin.as_str()));
    }

    // --- Agent over real backends (file, and gated Vault) --------------------

    /// The agent's `/info` + `/sign` cycle backed by a real on-disk file key,
    /// standing in for the mock: a genuine P-256 signature comes back and
    /// verifies against the CA public key.
    #[cfg(feature = "file")]
    #[test]
    fn agent_over_file_backend_serves_info_and_signs() {
        use std::io::Write as _;

        use p256::ecdsa::signature::Verifier as _;
        use p256::pkcs8::{EncodePrivateKey as _, LineEnding};

        use crate::file::{FileConfig, FileSignError, FileSigner};

        // A plaintext P-256 CA key on disk (0600), key id matching `config()`.
        let secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let verifying = *p256::ecdsa::SigningKey::from(secret.clone()).verifying_key();
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(pem.as_bytes()).unwrap();
        key_file.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(key_file.path(), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        // The passphrase source must never be consulted for a plaintext key.
        let passphrase = || Err(FileSignError::PassphraseUnavailable("n/a".to_owned()));
        let signer = FileSigner::open(
            FileConfig {
                path: key_file.path().to_path_buf(),
                key_id: KeyId::new(KEY_LABEL),
                requested_algorithm: None,
            },
            &passphrase,
        )
        .unwrap();

        let agent = Agent::new(
            signer,
            auto_confirm as ConfirmFn,
            config(),
            SecretString::from(TOKEN.to_owned()),
        );

        // GET /info reports the advertised algorithm.
        let info = agent.handle(&HttpInput {
            method: ReqMethod::Get,
            path: "/info",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: &[],
        });
        assert_eq!(info.status, 200);
        let info_json: serde_json::Value = serde_json::from_slice(&info.body).unwrap();
        assert_eq!(info_json["algorithms"][0], "ecdsa-with-sha256");

        // POST /sign returns a real signature over the submitted TBS.
        let tbs_b64 = leaf_tbs_b64();
        let body = serde_json::json!({ "key_id": KEY_LABEL, "tbs_der_b64": tbs_b64 }).to_string();
        let out = agent.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        let value: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(value["algorithm"], "ecdsa-with-sha256");
        let sig_b64 = value["signature_b64"].as_str().expect("signature present");

        // The returned signature verifies under the file key's public half.
        let b64 = base64::engine::general_purpose::STANDARD;
        let tbs = base64::Engine::decode(&b64, tbs_b64).unwrap();
        let sig_der = base64::Engine::decode(&b64, sig_b64).unwrap();
        let signature = p256::ecdsa::Signature::from_der(&sig_der).unwrap();
        verifying
            .verify(&tbs, &signature)
            .expect("agent's file-backed signature must verify");
    }

    /// The dev-server address and root token the Vault agent test uses.
    #[cfg(feature = "vault-tests")]
    const VAULT_DEV_ADDR: &str = "http://127.0.0.1:8210";
    #[cfg(feature = "vault-tests")]
    const VAULT_DEV_TOKEN: &str = "tessera-dev-root-token";

    /// A Vault dev-server killed when the guard drops.
    #[cfg(feature = "vault-tests")]
    struct VaultGuard(std::process::Child);

    #[cfg(feature = "vault-tests")]
    impl Drop for VaultGuard {
        fn drop(&mut self) {
            // Best-effort teardown; `drop` consumes the must-use results.
            drop(self.0.kill());
            drop(self.0.wait());
        }
    }

    /// Whether the `vault` binary is on `PATH`.
    #[cfg(feature = "vault-tests")]
    fn vault_available() -> bool {
        std::process::Command::new("vault")
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Start a throwaway Vault dev-server with a P-256 Transit key `ca-key`,
    /// returning a guard that tears it down on drop.
    #[cfg(feature = "vault-tests")]
    fn start_vault_dev_server() -> VaultGuard {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        fn vault_cmd(args: &[&str]) {
            let status = Command::new("vault")
                .args(args)
                .env("VAULT_ADDR", VAULT_DEV_ADDR)
                .env("VAULT_TOKEN", VAULT_DEV_TOKEN)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run vault command");
            assert!(status.success(), "vault {args:?} failed");
        }

        let child = Command::new("vault")
            .args([
                "server",
                "-dev",
                "-dev-root-token-id",
                VAULT_DEV_TOKEN,
                "-dev-listen-address",
                "127.0.0.1:8210",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vault dev server");
        let guard = VaultGuard(child);

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if ureq::get(&format!("{VAULT_DEV_ADDR}/v1/sys/health"))
                .call()
                .is_ok()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "vault dev-server did not come up"
            );
            std::thread::sleep(Duration::from_millis(150));
        }
        vault_cmd(&["secrets", "enable", "transit"]);
        vault_cmd(&["write", "-f", "transit/keys/ca-key", "type=ecdsa-p256"]);
        guard
    }

    /// A [`VaultSigner`](crate::vault::VaultSigner) bound to the dev-server's
    /// `ca-key` Transit key.
    #[cfg(feature = "vault-tests")]
    fn vault_dev_signer() -> crate::vault::VaultSigner {
        crate::vault::VaultSigner::new(
            crate::vault::VaultConfig {
                address: VAULT_DEV_ADDR.to_owned(),
                mount: "transit".to_owned(),
                key_name: "ca-key".to_owned(),
                key_id: KeyId::new(KEY_LABEL),
                algorithm: SignatureAlgorithm::EcdsaWithSha256,
                prehashed: false,
                ca_bundle_path: None,
            },
            SecretString::from(VAULT_DEV_TOKEN.to_owned()),
        )
        .expect("build vault signer")
    }

    /// The agent's `/info` + `/sign` cycle backed by a live Vault Transit key.
    ///
    /// Gated by `vault-tests` and a runtime check for the `vault` binary; when it
    /// is absent the test prints `skipped:` and returns, mirroring
    /// `tests/vault_sign.rs`.
    #[cfg(feature = "vault-tests")]
    #[test]
    fn agent_over_vault_backend_serves_info_and_signs() {
        if !vault_available() {
            println!("skipped: `vault` binary not found on PATH");
            return;
        }
        let _guard = start_vault_dev_server();

        let agent = Agent::new(
            vault_dev_signer(),
            auto_confirm as ConfirmFn,
            config(),
            SecretString::from(TOKEN.to_owned()),
        );

        let info = agent.handle(&HttpInput {
            method: ReqMethod::Get,
            path: "/info",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: &[],
        });
        assert_eq!(info.status, 200);

        let out = agent.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: sign_body().as_bytes(),
        });
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        let value: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(value["algorithm"], "ecdsa-with-sha256");
        assert!(value.get("signature_b64").is_some());
    }

    // --- Registry signing (`/sign-registry`) ---------------------------------

    const REGISTRY_LABEL: &str = "registry-key";

    /// A real P-256 backend that recognises both the issuance and the registry
    /// key label, signing with one on-disk key so `/sign-registry` output can be
    /// verified. It records the last key id it signed for, so a test can prove
    /// `/sign` never borrows the registry key.
    struct P256Backend {
        signing_key: p256::ecdsa::SigningKey,
        issue_key: KeyId,
        registry_key: KeyId,
        last_signed: Cell<Option<String>>,
    }

    impl P256Backend {
        fn new() -> Self {
            Self {
                signing_key: p256::ecdsa::SigningKey::from_slice(&[0x33; 32]).unwrap(),
                issue_key: KeyId::new(KEY_LABEL),
                registry_key: KeyId::new(REGISTRY_LABEL),
                last_signed: Cell::new(None),
            }
        }

        fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
            *self.signing_key.verifying_key()
        }

        fn knows(&self, key_id: &KeyId) -> bool {
            key_id == &self.issue_key || key_id == &self.registry_key
        }
    }

    impl SignatureBackend for P256Backend {
        fn algorithm(&self, key_id: &KeyId) -> Result<SignatureAlgorithm, SignError> {
            if self.knows(key_id) {
                Ok(SignatureAlgorithm::EcdsaWithSha256)
            } else {
                Err(SignError::UnknownKey(key_id.as_str().to_owned()))
            }
        }

        fn sign(&self, tbs_der: &[u8], key_id: &KeyId) -> Result<Signature, SignError> {
            use p256::ecdsa::signature::Signer as _;
            if !self.knows(key_id) {
                return Err(SignError::UnknownKey(key_id.as_str().to_owned()));
            }
            self.last_signed.set(Some(key_id.as_str().to_owned()));
            // A real ECDSA-with-SHA256 signature: the signer digests the bytes
            // itself, and the certificate-shaped output is DER, like every real
            // backend returns.
            let signature: p256::ecdsa::Signature = self.signing_key.try_sign(tbs_der).unwrap();
            Ok(Signature {
                algorithm: SignatureAlgorithm::EcdsaWithSha256,
                bytes: signature.to_der().as_bytes().to_vec(),
            })
        }
    }

    /// An agent over a real P-256 backend with the registry key configured.
    fn registry_agent() -> Agent<P256Backend, ConfirmFn> {
        Agent::new(
            P256Backend::new(),
            auto_confirm as ConfirmFn,
            config(),
            SecretString::from(TOKEN.to_owned()),
        )
        .with_registry_key(KeyId::new(REGISTRY_LABEL))
    }

    fn sign_registry_body(payload: &[u8]) -> String {
        serde_json::json!({
            "payload_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                payload,
            ),
        })
        .to_string()
    }

    /// A registry agent over the real P-256 backend with a custom confirmer.
    fn registry_agent_with<C: Confirmer>(confirmer: C) -> Agent<P256Backend, C> {
        Agent::new(
            P256Backend::new(),
            confirmer,
            config(),
            SecretString::from(TOKEN.to_owned()),
        )
        .with_registry_key(KeyId::new(REGISTRY_LABEL))
    }

    #[test]
    fn sign_registry_operator_decline_refuses_and_backend_untouched() {
        // A registry, like an issuance, needs operator confirmation: a decline is
        // refused before the backend signs, so a substituted cabinet cannot get a
        // silent attestation signature.
        let a = registry_agent_with(RecordingConfirmer {
            decision: false,
            called: Cell::new(false),
        });
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign-registry",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: sign_registry_body(b"{\"generated_at\":1}").as_bytes(),
        });
        assert_eq!(
            out.status,
            403,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(a.confirmer.called.get(), "confirmer must have been asked");
        assert!(
            a.backend.last_signed.take().is_none(),
            "backend must not sign a declined registry"
        );
        let value: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(value["error"], "operation not confirmed by operator");
    }

    #[test]
    fn sign_registry_confirmation_channel_failure_is_a_server_error() {
        // A broken confirmation channel (not a decline) is a 500, and the backend
        // is never reached — symmetric to the issuance path.
        fn broken(_: &OperationSummary) -> Result<bool, ConfirmError> {
            Err(ConfirmError::Io("no channel".to_owned()))
        }
        let a = registry_agent_with(broken as ConfirmFn);
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign-registry",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: sign_registry_body(b"{}").as_bytes(),
        });
        assert_eq!(out.status, 500);
        assert!(
            a.backend.last_signed.take().is_none(),
            "backend must not sign when the channel failed"
        );
    }

    #[test]
    fn sign_registry_shows_the_operator_the_digest_size_and_key() {
        use std::cell::RefCell;

        use sha2::{Digest as _, Sha256};

        // Capture what the operator is shown: it must carry the registry kind,
        // the signing-key label, the payload size, and the SHA-256 of the exact
        // payload bytes — enough to attest without trusting the cabinet.
        let seen = RefCell::new(String::new());
        let confirm = |summary: &OperationSummary| -> Result<bool, ConfirmError> {
            *seen.borrow_mut() = summary.render(Locale::En);
            Ok(true)
        };
        let payload = br#"{"generated_at":1750000000,"hosts":[]}"#;
        let a = registry_agent_with(confirm);
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign-registry",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: sign_registry_body(payload).as_bytes(),
        });
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        let shown = seen.borrow();
        assert!(shown.contains("device registry"), "{shown}");
        assert!(shown.contains(REGISTRY_LABEL), "{shown}");
        assert!(shown.contains("size"), "{shown}");
        let digest = hex::encode(Sha256::digest(payload));
        assert!(
            shown.contains(&digest),
            "the payload digest must be shown to the operator: {shown}"
        );
    }

    #[test]
    fn sign_registry_without_a_configured_key_reports_not_configured() {
        // A plain agent (no registry key) refuses `/sign-registry` with the
        // documented "not configured" error, and never touches the backend.
        let a = agent(RecordingSigner::new());
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign-registry",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: sign_registry_body(b"{\"generated_at\":1}").as_bytes(),
        });
        assert_eq!(
            out.status,
            400,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        let value: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(value["error"], "registry key is not configured");
        assert!(!a.backend.signed.get(), "backend must not be reached");
    }

    #[test]
    fn sign_registry_produces_a_signature_the_cabinet_verifier_accepts() {
        use p256::ecdsa::signature::Verifier as _;

        let a = registry_agent();
        let payload = br#"{"generated_at":1750000000,"hosts":[],"users":[],"roles":[],"tags":[]}"#;
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign-registry",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: sign_registry_body(payload).as_bytes(),
        });
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(
            a.backend.last_signed.take().as_deref(),
            Some(REGISTRY_LABEL)
        );

        let value: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        let sig_b64 = value["signature_b64"].as_str().expect("signature present");
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .expect("signature is base64");
        // The cabinet verifies raw `r || s` P-256 over SHA-256 of the exact
        // payload bytes — reproduce that here.
        assert_eq!(raw.len(), 64, "raw ecdsa signature is r||s (64 bytes)");
        let signature = p256::ecdsa::Signature::from_slice(&raw).expect("valid raw signature");
        a.backend
            .verifying_key()
            .verify(payload, &signature)
            .expect("registry signature must verify as P-256 over SHA-256 of the payload");
    }

    #[test]
    fn sign_registry_requires_the_session_token() {
        let a = registry_agent();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign-registry",
            origin: Some(ORIGIN),
            session_token: None,
            body: sign_registry_body(b"{}").as_bytes(),
        });
        assert_eq!(out.status, 403);
        assert!(
            a.backend.last_signed.take().is_none(),
            "backend must not sign"
        );
    }

    #[test]
    fn sign_registry_refuses_a_foreign_origin() {
        let a = registry_agent();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign-registry",
            origin: Some("https://evil.example"),
            session_token: Some(TOKEN),
            body: sign_registry_body(b"{}").as_bytes(),
        });
        assert_eq!(out.status, 403);
        assert!(
            out.cors_origin.is_none(),
            "no CORS header for a foreign origin"
        );
        assert!(
            a.backend.last_signed.take().is_none(),
            "backend must not sign"
        );
    }

    #[test]
    fn sign_registry_ignores_a_smuggled_key_field() {
        // The request has no key field; an extra one is ignored and the registry
        // key still signs — a caller cannot redirect this to the issuance key.
        let a = registry_agent();
        let body = serde_json::json!({
            "payload_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"{}",
            ),
            "key_id": KEY_LABEL,
        })
        .to_string();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign-registry",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(
            out.status,
            200,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert_eq!(
            a.backend.last_signed.take().as_deref(),
            Some(REGISTRY_LABEL),
            "the registry key must sign, never the issuance key"
        );
    }

    #[test]
    fn sign_refuses_the_registry_key_for_issuance() {
        // The other half of domain separation: `/sign` must not sign a TBS with
        // the registry key even though the backend can address it.
        let a = registry_agent();
        let body = serde_json::json!({ "key_id": REGISTRY_LABEL, "tbs_der_b64": leaf_tbs_b64() })
            .to_string();
        let out = a.handle(&HttpInput {
            method: ReqMethod::Post,
            path: "/sign",
            origin: Some(ORIGIN),
            session_token: Some(TOKEN),
            body: body.as_bytes(),
        });
        assert_eq!(
            out.status,
            403,
            "body: {}",
            String::from_utf8_lossy(&out.body)
        );
        assert!(
            a.backend.last_signed.take().is_none(),
            "the registry key must never sign a TBS"
        );
    }

    #[test]
    fn validate_registry_key_rejects_a_label_collision() {
        let backend = MockSigner::ecdsa_sha256(KeyId::new(KEY_LABEL));
        let err = validate_registry_key(&backend, &KeyId::new(KEY_LABEL), KEY_LABEL).unwrap_err();
        assert!(matches!(err, ServeError::RegistryKeyCollision), "{err:?}");
    }

    #[test]
    fn validate_registry_key_rejects_a_non_p256_key() {
        // A registry key the backend signs with P-384 is refused at startup.
        let backend = MockSigner::new(
            KeyId::new(REGISTRY_LABEL),
            SignatureAlgorithm::EcdsaWithSha384,
        );
        let err =
            validate_registry_key(&backend, &KeyId::new(REGISTRY_LABEL), KEY_LABEL).unwrap_err();
        assert!(
            matches!(
                err,
                ServeError::RegistryKeyNotP256(SignatureAlgorithm::EcdsaWithSha384)
            ),
            "{err:?}"
        );
    }

    #[test]
    fn validate_registry_key_reports_an_unknown_key() {
        // The backend does not recognise the registry label at all.
        let backend = MockSigner::ecdsa_sha256(KeyId::new("some-other-key"));
        let err =
            validate_registry_key(&backend, &KeyId::new(REGISTRY_LABEL), KEY_LABEL).unwrap_err();
        assert!(
            matches!(err, ServeError::RegistryKeyUnavailable(_)),
            "{err:?}"
        );
    }

    #[test]
    fn validate_registry_key_accepts_a_distinct_p256_key() {
        let backend = MockSigner::ecdsa_sha256(KeyId::new(REGISTRY_LABEL));
        assert!(validate_registry_key(&backend, &KeyId::new(REGISTRY_LABEL), KEY_LABEL).is_ok());
    }

    #[test]
    fn ecdsa_der_to_raw_round_trips_a_real_signature() {
        use p256::ecdsa::signature::Signer as _;
        let key = p256::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap();
        let signature: p256::ecdsa::Signature = key.sign(b"payload bytes");
        let raw = ecdsa_der_to_raw(signature.to_der().as_bytes()).expect("valid p256 der");
        assert_eq!(raw, <[u8; 64]>::from(signature.to_bytes()));
    }

    #[test]
    fn ecdsa_der_to_raw_rejects_non_signature_bytes() {
        assert!(ecdsa_der_to_raw(b"not a der signature").is_err());
    }
}

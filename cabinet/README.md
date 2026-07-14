# Tessera Issuer Cabinet

A serverless, static web cabinet for certificate issuance — one SPA, WASM
core, no server, no framework, no runtime dependencies. See
`specs/issuer-cabinet/spec.md` and `docs/ru/issuer.md` ("Веб-кабинет") for
the product contract this implements; `openspec/changes/issuer-tooling/`
for the design this is part of.

## Layout

```
cabinet/
  src/
    types.ts             the WASM/serve JSON contracts, mirrored from Rust
    main.ts               entry point
    i18n/                 RU/EN dictionary + locale resolution (pure, tested)
    core/                 pure logic: envelope scoping, snapshot format,
                           error rendering, journal text, WASM/agent clients
    state/                sessionStorage-backed operator config
    ui/                   DOM rendering (app.ts, forms.ts, widgets.ts, dom.ts)
  public/                 index.html (with the CSP), styles.css
  wasm/                   generated `wasm-bindgen --target web` bindings —
                           tessera_issuer_wasm.{js,d.ts} are checked-in
                           *placeholder* stubs so `tsc`/`node --test` work
                           without a WASM build; build.sh regenerates them
                           for real (and the *_bg.wasm binary) — see below
  dist/                   build output (gitignored)
  build.sh                the one build entry point (see "Build" below)
```

## Build

```sh
./build.sh
```

Produces `dist/` — `index.html`, `main.js` (+ sourcemap), `styles.css`,
`tessera_issuer_wasm_bg.wasm`, and a `SHA256SUMS` manifest of the lot. This
is the whole CI/release contract: no arguments, no prior setup implied.

Steps: (1) `cargo build -p tessera_issuer_wasm --target wasm32-unknown-unknown
--release`; (2) `wasm-bindgen --target web` (installs `wasm-bindgen-cli` at
the exact version pinned in the workspace `Cargo.lock` if missing — the CLI
and the `wasm-bindgen` crate version must match exactly or the generated
glue and the compiled module disagree on ABI); (3) `npm ci` + `esbuild`
bundle; (4) SHA-256 manifest.

Running the script overwrites `wasm/tessera_issuer_wasm.{js,d.ts}` with the
real generated bindings (a strict superset of the checked-in stub's shape).
That's a normal local modification, not a problem — `git checkout --
wasm/tessera_issuer_wasm.js wasm/tessera_issuer_wasm.d.ts` restores the
lightweight stub if you want to `tsc`/`node --test` again without rebuilding
the WASM crate.

**Self-hosting note:** the CSP (`public/index.html`) restricts `script-src`
and `style-src` to `'self'` and `connect-src` to `'self'` plus the loopback
origins — serve `dist/` from an actual (even local) HTTP server (e.g.
`python3 -m http.server` from inside `dist/`), not by double-clicking
`index.html`: browsers apply CORS to `file://` fetches independently of CSP,
and the WASM binary is loaded via `fetch()`.

## Why the bundling shape it is

`wasm-bindgen --target web`'s generated `init()` fetches
`new URL('tessera_issuer_wasm_bg.wasm', import.meta.url)` by default.
`esbuild` bundles that glue module into `main.js` as-is (`import.meta.url`
is a runtime construct, not rewritten at bundle time), so at runtime
`import.meta.url` is `main.js`'s own URL — `build.sh` therefore copies the
`.wasm` binary to sit *next to* `main.js` in `dist/`, not in a `wasm/`
subdirectory.

## Decisions not obvious from the spec

**Snapshot format** (spec `issuer-cabinet` — "Инвентарь для форм"; see
`src/core/snapshot.ts` for the authoritative doc comment). The file is:

```json
{ "payload_json": "<exact UTF-8 text of the payload object>", "signature_b64": "<base64 or null>" }
```

`payload_json` is signed *as bytes*, not re-serialised — this sidesteps
canonical-JSON ambiguity entirely: any tool that produces that exact string
and signs its SHA-256 digest with ECDSA P-256 (raw `r || s`, WebCrypto's
default signature encoding) produces a snapshot the cabinet accepts. The
payload itself is `{ generated_at, hosts: [{id, label?}], users: [string],
roles: [string], tags: [{key, value}] }`. `signature_b64: null` is always
accepted and labelled "manual" per the spec (no snapshot must not block
issuance).

**Snapshot verification key.** Not derived from the parent certificate — the
parent's key algorithm has no reason to be P-256, and coupling the two would
make a snapshot re-verify differently every time the operator swaps parents.
Instead it's an operator-supplied JWK (ECDSA P-256), pasted into the
"Snapshot verification key" field and held in `sessionStorage` for the rest
of the session (`src/state/sessionConfig.ts`) — the honest option: a
snapshot is valid only against whatever key the operator actually trusts
*right now*. Self-hosted deployments that want a fixed org-wide key can
still pre-fill it (see that field's code) at build time if desired; this
implementation ships the simpler runtime-entry version.

**Agent key label.** `issuer serve`'s `/sign` rejects a request whose
`key_id` doesn't match the label the agent was started with (`--key`,
`crates/tessera_issuer/src/pkcs11.rs`). The cabinet's "Signing agent"
section therefore has a third field beyond address/token — the CA key
label — which must be entered to match the agent's own `--key` flag.

**Journal.** Held in memory as the raw NDJSON lines loaded from (and saved
back to) a file the operator picks, per the serverless "stateless statics,
state lives in files" invariant. `journal_append`/`journal_verify`
(hash-chain logic) run in the WASM core; `src/core/journal.ts` only handles
the browser-side file text and status rendering.

**Locale.** Resolution order: explicit in-UI choice (persisted in
`sessionStorage` for the session) > hosting domain (`*.ru` → `ru`, per D13)
> `navigator.language` prefix match > English fallback. See
`src/i18n/locale.ts`.

## Tests

```sh
npm test        # node --test src/**/*.test.ts — pure logic only
npm run typecheck
```

Uses Node's built-in TypeScript type stripping (`node --test *.ts` runs
directly, no `ts-node`/`tsx`/Jest) — the only `devDependencies` are
`typescript` and `esbuild`. Tests cover the pure modules only (`i18n/`,
`core/envelope.ts`, `core/snapshot.ts`, `core/errorLabels.ts`,
`core/journal.ts`, `core/agentClient.ts`'s algorithm mapping,
`state/sessionConfig.ts`) — `ui/*` and `core/wasmBridge.ts` need a live
WASM instance and a DOM and are exercised by the end-to-end run (tasks.md
6.5), not by this unit suite.

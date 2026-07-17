# Issuer tooling (`tessera_issuer`)

## Overview

Tessera verifies certificates on the device, but something has to issue them.
The issuer tooling covers that side: a single Rust core assembles a
`TBSCertificate` with the Tessera extensions, checks the monotonic narrowing of
the delegation envelope **before** signing, and signs the result with a key that
never leaves the token/HSM/Vault. The tool is **not a custodian**: no private key
material passes through the issuing code.

Components:

- **Core** (`tessera_issuer`, a library) — assembly of the shift-leaf and
  organisation-CA TBS, the envelope checks, random 128-bit serials, CRL
  issuance, and the issuance journal. The core is pure Rust and builds for
  `wasm32` (for the web cabinet); the signing adapters sit behind feature
  flags.
- **CLI `issuer`** — the same issuing code for automation (ticketing systems,
  scripts). No check is re-implemented in the CLI: a request the core would
  refuse, the CLI refuses identically.
- **Agent `issuer serve`** — a local HTTP server bound strictly to `127.0.0.1`
  with two roles: the browser-to-token bridge and serving the cabinet itself
  (by default).
- **Web cabinet** — one static SPA (a WASM build of the same core):
  issuance through the browser with no server side. Served locally by the agent
  itself (`issuer serve`, the cabinet is embedded in the binary)
  or by separate static hosting in an air-gapped environment (see the
  "Web cabinet" section below).

The role model comes from the parent certificate presented: any CA with a
delegation envelope (the fleet root or an organisation CA) issues both
subordinate organisation CAs and engineers' shift-leaves — strictly inside its
delegation envelope, which can only narrow at every step. There is no separate
"mode by job title".

The semantics of the extensions themselves (`host_binding`, `user_binding`,
`allowed_roles`, `max_integrity`, `profile_version`, `delegation_constraints`)
and their OIDs are in [cert-issuance.md](cert-issuance.md) — this document
describes the tool, not the format. The attack surface of the issuer tooling is
covered in [threat-model.md §11](threat-model.md) and is not duplicated here.

## CLI quick start

Every issuing subcommand selects a signing backend with `--backend` (`pkcs11` is
the default, `vault`), `--key` (the CA key label) and `--algorithm`
(`ecdsa-p256` is the default, `ecdsa-p384`, `rsa-sha256`). Times
(`--not-before`, `--not-after`, `--this-update`, …) are Unix seconds. Inputs
(`--parent`, `--spki`, `--csr`, `--issuer`) are accepted as PEM or DER (the
format is detected from the content). Output is PEM, or DER with `--der`.

The token PIN is **never** a command-line argument: the PKCS#11 backend prompts
for it through pinentry for the duration of the operation, falling back to the
`TESSERA_ISSUER_PIN` environment variable when no pinentry is available (see
[Signing backends](#signing-backends)).

### Issue an organisation CA

Under the fleet root, an organisation CA is issued with an assigned delegation
envelope (roles, the МКЦ level ceiling, the TTL ceiling, required tags):

```sh
issuer issue-ca \
    --backend pkcs11 --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    --key tessera-root --algorithm ecdsa-p256 \
    --parent root.pem \
    --spki org-ca.spki.der \
    --subject "CN=Org North CA,O=Org" \
    --not-before 1750000000 --not-after 1900000000 \
    --allow-role oper --allow-role serv \
    --max-level 5 --max-ttl 14400 \
    --require-tag region=north \
    --journal issuance.ndjson \
    --out org-ca.pem
```

`--allow-role` and `--require-tag` repeat for several values. The issued CA's
envelope must be ⊆ the parent's; otherwise the core refuses before signing,
naming the dimension (see the monotonic narrowing in
[cert-issuance.md](cert-issuance.md)).

### Issue a shift-leaf

The leaf's public key comes from an explicit `--spki` (then `--subject` is
required) **or** from `--csr` (then the subject and key are taken from the
request). The two flags are mutually exclusive.

Direct path (SPKI):

```sh
issuer issue-leaf \
    --backend pkcs11 --module /usr/lib/.../opensc-pkcs11.so \
    --key org-north-ca \
    --parent org-ca.pem \
    --spki ivanov.spki.der \
    --subject "CN=ivanov,O=Org" \
    --host "sha256:<host_id_hash>" \
    --user ivanov \
    --role oper \
    --not-before 1750000000 --not-after 1750086400 \
    --max-integrity-level 2 --max-integrity-categories 0x1 \
    --journal issuance.ndjson \
    --out ivanov.pem
```

CSR path (see [The CSR flow](#the-csr-flow)):

```sh
issuer issue-leaf \
    --backend pkcs11 --module /usr/lib/.../opensc-pkcs11.so \
    --key org-north-ca \
    --parent org-ca.pem \
    --csr ivanov.csr.pem \
    --host "sha256:<host_id_hash>" --user ivanov --role oper \
    --not-before 1750000000 --not-after 1750086400 \
    --journal issuance.ndjson \
    --out ivanov.pem
```

`--host`, `--user` and `--role` repeat. `--max-integrity-level` is optional
(without it no integrity ceiling is set); `--max-integrity-categories` (a
bitmask) is honoured only together with a level.

### Issue a CRL

```sh
issuer issue-crl \
    --backend pkcs11 --module /usr/lib/.../opensc-pkcs11.so \
    --key org-north-ca \
    --issuer org-ca.pem \
    --this-update 1750000000 --next-update 1750604800 \
    --crl-number 7 --last-crl-number 6 \
    --revoke 2a:1750000500:1 \
    --revoke 3b:1750000600 \
    --journal issuance.ndjson \
    --out org-ca.crl
```

`--crl-number` must be strictly greater than `--last-crl-number` (the monotonic
`crlNumber` in the CA's state); otherwise the operation is refused. Each
`--revoke` is `serial_hex:unix_date[:reason_code]`, where `reason_code` is an
RFC 5280 reason code (0–6) and is optional; the flag repeats.

### Verify the journal

```sh
issuer verify-journal --journal issuance.ndjson
```

Prints one of three states: the chain is intact and fully signed; intact but
with an unsigned tail (with the `seq` it starts at); broken (with the position
of the first invalid record — then a non-zero exit code). See
[The issuance journal](#the-issuance-journal).

### Message language

Operator result messages are localized (Russian/English). The locale resolves as
`--lang` (`ru`/`en`) → `TESSERA_ISSUER_LANG` → `LANG` → English by default.
Matching is by language prefix: any value beginning with `ru` selects Russian.
Technical identifiers (an RFC 4514 subject, an OID, `crlNumber`, serials) are not
translated. See [Localization](#localization).

## The CSR flow

A CSR (PKCS#10) is a peer to the direct SPKI source for the leaf key. It removes
the need to hand the tool a public key separately and provides proof of
possession: the engineer generates the key on their own token and signs the
request with it.

Engineer side — build a CSR with the token key:

```sh
issuer csr \
    --backend pkcs11 --module /usr/lib/.../opensc-pkcs11.so \
    --key ivanov-token-key --algorithm ecdsa-p256 \
    --subject "CN=ivanov,O=Org" \
    --spki ivanov.spki.der \
    --out ivanov.csr.pem
```

The tool is signing-only: the engineer's public key (`--spki`) is supplied
explicitly, and the request is signed with the token key that `--key` addresses.
Proof of possession holds only when that token key matches `--spki` — the
engineer's responsibility, since the tool does not generate keys.

Operator side — `issue-leaf --csr` (above). What matters:

- The core verifies the CSR's self-signature (P-256/RSA, pure Rust) **before**
  issuing; a broken self-signature → refused before signing. The CLI also prints
  the CSR subject and self-signature status before issuing.
- The subject and public key are taken from the CSR. **The scope (envelope,
  bindings, roles) is set exclusively by the operator** via flags — CSR
  attributes do not influence the extensions. Otherwise a CSR would become a
  channel for "the engineer requested a wider scope for themselves".

## The `issuer serve` agent

`issuer serve` is a local HTTP server bound strictly to `127.0.0.1`: (1) the
browser-to-token bridge — it accepts a built TBS from the cabinet and returns a
signature (the cabinet cannot talk to PKCS#11 directly); (2) by default it serves
the cabinet itself from the same address. When serving the cabinet, the whole
cabinet lives in a single signed binary — no separate hosting is needed. The
`--no-cabinet` flag disables serving (pure bridge mode, when the SPA is served
externally).

```sh
issuer serve \
    --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    --key tessera-ca --algorithm ecdsa-p256 \
    --port 0
```

`--module` and `--key` are required; `--token-label` selects a token when there
are several; `--pinentry` names the pinentry program explicitly. `--port 0` (the
default) picks an ephemeral port — the actual address is printed at startup and
is the one to open in the browser. When serving the cabinet (by default, or
`--cabinet-dir <dist>`) `--allow-origin` is not required: the agent is in its own
allowlist. For the pure bridge mode (`--no-cabinet`, or when there is no embedded
cabinet and it is served by separate static hosting) `--allow-origin` is required
(at least one; it repeats).

### Access model

The primary gate is the **paired session token**. The agent mints a random token
at startup, prints it to stdout and (when serving the cabinet) injects it into
the page it serves; the cabinet passes it in the `X-Tessera-Session` header on
every request, and the comparison is constant-time. A request without a valid
token is rejected **before** the signing module is touched.

**Origin** is a secondary barrier against cross-origin requests: if a request
carries an `Origin` header, it must be in the allowlist (otherwise refused); a
missing `Origin` (a legitimate same-origin GET, which browsers do not accompany
with this header) is not a refusal in itself — the token gates it. A cross-origin
page cannot read the injected token nor set `X-Tessera-Session` without a
preflight, which the agent controls; a DNS-rebind carries the attacker's Origin
and is cut off by the allowlist.

**Routing:** `POST /sign`, `GET /info` and — when serving — the cabinet's static
assets as a fixed set; everything else answers 404, and the static assets do not
shadow the signing routes.

The PIN is **not** sent over HTTP — the protocol has no field for it. A sign
request carries only a key id and the base64 TBS; stray fields (a `pin`, say) are
dropped by serde and never reach the backend.

### Operation confirmation

The session token authenticates the cabinet; **the operation itself is
authorized by the operator**. Before touching the signing backend, the agent:

1. Parses the TBS with the same shared code (`tessera_ext`) the Engine enforces.
   A TBS that cannot be read as an issuance operation is refused **before** the
   confirmation prompt — what cannot be shown cannot be signed.
2. Shows the operator the operation kind (shift-leaf / organisation CA / CRL),
   the subject, the validity, and the roles/bindings/envelope — and signs only
   after an explicit yes.

The agent here is a **trusted display**: even a substituted SPA or a foreign
local process holding a valid token cannot get a signature the operator did not
confirm (see [threat-model.md §11.1.1, §11.3](threat-model.md)).

The confirmation/PIN channel is **pinentry** (the Assuan protocol, the gpg-agent
precedent) when available, falling back to the **terminal**. This decouples the
trusted channel from how the agent was launched. The answers `y`/`yes`/`д`/`да`
are accepted regardless of locale. A failure of the pinentry channel itself (not
a decline, but an inability to spawn / a protocol error) falls back to the
terminal; an operator decline is honestly treated as a decline.

### Serving the cabinet

`issuer serve` by default serves the cabinet (SPA) embedded in the binary
from the same `127.0.0.1` address as `/sign`. The canonical path: start the agent
→ open the printed localhost address → issue, offline, from a single signed
binary. `--cabinet-dir <dist>` serves the cabinet from an external `dist/`
directory (for self-hosting and development) and overrides the embedded one.
`--no-cabinet` disables serving — the agent runs as a pure bridge, the cabinet is
then served by separate static hosting. Priority: `--no-cabinet` → bridge;
otherwise `--cabinet-dir` → external directory; otherwise the embedded cabinet
(if the binary is built with the `embed-cabinet` feature); otherwise → bridge
(without error).

When serving the page, the agent injects the paired session token and the key
label into it — the cabinet preconfigures its connection itself, the operator
does not have to retype the address and token, and the agent settings block
collapses to a "connected / not connected" indicator. Cabinet integrity rests on
the binary signature: from a substituted agent the keys are still unreachable —
the private cryptography sits behind the token (see
[threat-model.md §11](threat-model.md)).

The agent runs for the duration of the issuing session (foreground): a smaller
attack window. A system service and daemon autostart are not provided — the agent
is launched explicitly when you sit down to issue; issuance itself is the reason
to bring it up.

## Signing backends

The core does not know where the key is: signing a built TBS goes behind a single
interface, and no key material passes through it. The backend is chosen with
`--backend`.

### PKCS#11 (token and HSM)

The default backend, one code path for hardware tokens and HSMs. Flags:
`--module` (path to the `.so`/`.dylib`/`.dll` — required), `--token-label`
(select a token when there are several), `--key` (the CA key's `CKA_LABEL`),
`--pinentry` (the pinentry program explicitly).

The PIN is requested through pinentry for the duration of the operation
(`Secret` + `zeroize`, never in logs or argv); absent pinentry, from
`TESSERA_ISSUER_PIN`.

For trials and CI, **SoftHSM** works as a software PKCS#11 module. GOST tokens
work through the same adapter when the token exposes the required PKCS#11
mechanism.

### Vault / OpenBao Transit

Signs a built TBS through the Transit HTTP API. Flags: `--vault-addr` (e.g.
`https://vault.example:8200` — required), `--mount` (the Transit mount, default
`transit`), `--vault-key` (the Transit key name; defaults to `--key`),
`--ca-bundle` (a PEM CA bundle to trust instead of the platform store — for
private Vault CAs), `--prehashed` (send a locally computed digest with
`prehashed=true` — for keys configured for pre-hashed input).

The Vault token is read from the `VAULT_TOKEN` environment variable (empty/unset
→ refused), sent in the `X-Vault-Token` header, and never logged. For ECDSA the
adapter requests `marshaling_algorithm=asn1` (Vault returns a DER signature).

> **Transit only, not Vault PKI.** The Vault PKI engine is unusable for Tessera:
> Go's `encoding/asn1` does not parse OID arcs larger than `int64`, and our
> extensions sit in the `2.25.<UUID>` arc — such a certificate cannot be issued
> through Vault PKI. Transit therefore signs the TBS we assemble, rather than
> building a certificate.

Transit does not check **what** it signs — all issuance checks run before
signing, in the core, on the client; who may call `sign` is constrained by Vault
policy.

## The issuance journal

Every operation (issuing a leaf, a CA, a CRL) is a record in an NDJSON journal
linked into a hash chain: a monotonic `seq`, the hash of the previous record, a
fixed genesis. The journal is **fail-closed**: the record is written **before**
the artifact is emitted, and if the journal is unavailable the operation is
refused (no certificate is issued without a record). The path is set by the
`--journal` flag of each issuing subcommand.

The head of the chain is periodically signed through the same signing interface
(at the end of a session and on command). `issuer verify-journal` distinguishes
three states:

- **intact, tail fully signed** — all good;
- **intact, unsigned tail from seq N** — the chain is not broken, but records
  from `N` are not yet covered by a head signature;
- **broken at position N** — a break/substitution/reordering at record `N` (a
  non-zero exit code).

The journal is **secondary**: the primary truth is the login audit on the
devices themselves; the journal serves issuance inventory and incident review.

## Web cabinet

The cabinet is one static artifact (an SPA + the WASM core) **with no
server-side logic**: all checks and TBS assembly happen on the client, and all
state is files (the parent certificate, the issued certificates, the journal, the
CRL, the inventory snapshot). It runs self-hosted and offline; the only network
call is to the local `issuer serve` agent on `127.0.0.1`. Issuance data is not
sent to any external address.

There is one cabinet for all issuing roles: the available operations are derived
from the parent certificate presented. Any CA with a delegation envelope (the
root or an organisation CA) issues both subordinate organisation CAs with a
narrowed assigned envelope and shift-leaves within its own envelope — the
operation is chosen with a switch; a leaf/unsuitable certificate → operations
unavailable, with an explanation. There are no separate "by job title" builds.

The cabinet is part of the signed `issuer` binary: `issuer serve` by default
serves it from `127.0.0.1`, with no separate hosting. The
artifact is bilingual, with a language switch in the UI. Cabinet integrity rests
on the binary's own signature — no separate hash pinning is needed; the private
cryptography is always behind the agent and the token, and the keys are
unreachable from a substituted SPA (see [threat-model.md §11](threat-model.md)).

### Building and serving the static assets

`cabinet/build.sh` builds the `dist/` directory — `index.html`, `main.js`,
`styles.css`, the WASM binary and a `SHA256SUMS` manifest. The release binary
embeds this directory (served by default). For an air-gapped
environment the same `dist/` can be served by any static web server or pointed to
the agent with `--cabinet-dir <dist>`; the cabinet has no server side.

### How to work with the cabinet

1. On the machine with the token, start the agent with the cabinet:
   `issuer serve --module <…> --key <…>` and open the
   `http://127.0.0.1:<port>` address it prints (see ["The `issuer serve`
   agent"](#the-issuer-serve-agent)). The agent preconfigures the connection
   itself — the agent block in the cabinet shows only a "connected" status.
2. Present the parent certificate — the available
   operations are derived from it: a CA with a delegation envelope (the
   root or an organisation CA) → issue subordinate organisation CAs with
   a narrowed assigned envelope, or shift-leaves within its own envelope;
   the operation is chosen with a switch (defaults: root — organisation
   CA, organisation CA — shift-leaf); a leaf or an unsuitable certificate
   → operations unavailable, with an explanation.
3. Device inventory: build it right in the cabinet (a constructor —
   devices, users, roles, tags; the result is a "manual" snapshot that
   downloads as a file) or load a ready snapshot file. A signed snapshot
   the cabinet verifies (broken signature → refusal) and labels the
   source ("signed"/"manual") with its age. The inventory feeds the
   issuance-form suggestions: devices and users are offered from it (a
   typed value is still kept), and the leaf's role set narrows to the
   intersection of the parent's envelope with the inventory's roles. The
   inventory is optional — without it the fields are filled in manually.
4. The leaf key: local generation or a CSR upload. From a CSR the cabinet
   shows the subject and the self-signature status and prefills the
   attributes marked "requested in the CSR"; with a broken self-signature
   the issuance is unavailable.
5. The agent signs on the token after the operator confirms
   (see ["Operation confirmation"](#operation-confirmation)) — the PIN
   never leaves the machine running the agent. The issued certificate is
   downloaded as a file, and the operation is recorded in the issuance
   journal.

The cabinet UI is split into two tabs: **"Issue"** (parent, operation,
inventory, agent, summary) and **"Journal"** (loading, chain
verification and export of the issuance journal). The parent-certificate
and signing-agent blocks carry context help — how to obtain a parent and
how to bring up and configure `issuer serve`.

## Localization

The tool's operator surfaces (the confirmation summary in pinentry/the terminal,
the `issuer serve` messages, the CLI output, the cabinet SPA) are
localized to Russian and English without an i18n framework (a compact string
table). The cabinet picks its language by the browser language, with a UI switch; for the
CLI and the agent the locale is resolved once at startup:

1. an explicit setting — the `--lang` flag (`ru`/`en`);
2. the `TESSERA_ISSUER_LANG` variable;
3. the `LANG` variable;
4. the fallback — English.

Matching is by language prefix, case-insensitive: `ru_RU.UTF-8` and `RU` yield
Russian, `en_GB` English; an unrecognized value simply falls through to the next
source. Only field captions are translated — the technical data (an RFC 4514
subject, an OID, a `role_id`, serials, `crlNumber`, timestamps) is reproduced
byte-for-byte in every locale.

## See also

- [cert-issuance.md](cert-issuance.md) — the Tessera extensions, their OIDs and
  semantics, and the monotonic narrowing of the delegation envelope.
- [threat-model.md §11](threat-model.md) — the attack surface of the issuer
  tooling, damage containment, and residual risks.

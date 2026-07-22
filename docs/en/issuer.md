# Issuer tooling (`tessera_issuer`)

## Overview

Tessera verifies certificates on the device, but something has to issue them.
The issuer tooling covers that side: a single Rust core assembles a
`TBSCertificate` with the Tessera extensions, checks the monotonic narrowing of
the delegation envelope **before** signing, and signs the result with the key of
the selected backend — a token/HSM (PKCS#11), Vault Transit, or a local PKCS#8
file. With the PKCS#11 and Vault backends the tool is **not a custodian**: no
private key material passes through the issuing code; the file backend is a
deliberate trade-off with the key resident in the issuance process memory (see
[threat-model.md §11](threat-model.md)).

Components:

- **Core** (`tessera_issuer`, a library) — assembly of the shift-leaf and
  organisation-CA TBS, the envelope checks, random 128-bit serials, CRL
  issuance, and the issuance journal. The core is pure Rust and also builds for
  `wasm32`; the signing adapters sit behind feature flags.
- **CLI `issuer`** — the issuing code for automation (ticketing systems,
  scripts) and hands-on use. No check is re-implemented in the CLI: a request
  the core would refuse, the CLI refuses identically.

Browser-based issuance — a local signing agent and a web cabinet driving the
same core from a browser — is delivered separately, as part of the commercial
tooling (see ["Browser-based issuance"](#browser-based-issuance)). The open
repository ships the CLI.

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
the default, `vault`, `file`), `--key` (the CA key label; optional for `file`,
defaulting to the key file's name) and `--algorithm` (`ecdsa-p256` is the
default, `ecdsa-p384`, `rsa-sha256`; for `file` the algorithm is derived from
the key itself and the flag acts as a cross-check). Times
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

## Browser-based issuance

Issuing from a browser — a local signing agent bound to `127.0.0.1` that bridges
the browser to the token/HSM, plus a web cabinet (an SPA over the same WASM core)
that assembles the TBS client-side and shows the operator a summary to confirm —
is delivered separately, as part of the commercial tooling (`tessera-enterprise`).
It is not built from this repository. For contact, see
[LICENSE.commercial](../../LICENSE.commercial).

The open repository ships the `issuer` CLI, which drives the same core and the
same signing backends and enforces the same pre-signing checks. Everything below
— the signing backends and the issuance journal — applies to the CLI.

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

### Key in a file

The `file` backend signs with a CA key from a local file: `--key-file <path>`.
The format is PKCS#8 (PEM or DER), including encrypted (`ENCRYPTED PRIVATE
KEY`, PBES2); the key types are ECDSA P-256/P-384 and RSA. GOST keys are not
supported by the file backend — for GOST, PKCS#11 remains the path. Other
formats convert with stock tooling:

```sh
# a new encrypted P-256 key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    | openssl pkcs8 -topk8 -v2 aes-256-cbc -out ca-key.p8
chmod 600 ca-key.p8

# converting an existing key (SEC1/PKCS#1 → PKCS#8)
openssl pkcs8 -topk8 -v2 aes-256-cbc -in old-key.pem -out ca-key.p8
```

The backend's rules:

- The key file must not be accessible to the group or to others (`chmod 600`) —
  otherwise the backend refuses before reading the contents. File ownership and
  directory permissions are not checked — keep the key in your own directory
  with `700` permissions.
- The passphrase of an encrypted key is prompted through pinentry, falling back
  to `TESSERA_ISSUER_KEY_PASSPHRASE`; the passphrase never appears in
  command-line arguments or logs, and memory is zeroized.
- An unencrypted key is accepted, but with a warning on every start; the
  recommendation is encrypted PKCS#8.
- The signing algorithm is derived from the key itself; an `--algorithm` that
  does not match the key is an error. `--key` is optional (defaulting to the
  file name) and serves as the key identifier in the issuance journal.

A key in a file is a deliberate trade-off for test benches, CI and small
installations: on host compromise it is extractable, unlike a token/HSM/Vault
key. For production, PKCS#11 or Vault Transit are recommended (see
[threat-model.md §11](threat-model.md)).

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

## Localization

The tool's operator surfaces (the operation summary rendered from a TBS and the
CLI output) are localized to Russian and English without an i18n framework (a
compact string table). For the CLI the locale is resolved once at startup:

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

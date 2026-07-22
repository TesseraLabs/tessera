# Proposal: drop-serve

## Why

The open issuer is a plain CLI. The local signing agent (`issuer serve`) — the
browser-to-token bridge and the operator-confirmation display — is delivered
separately, as part of the commercial tooling, together with the web cabinet it
serves. It no longer belongs in the open repository, so the `serve` command and
all of its code are removed.

## What Changes

- **BREAKING**: the `issuer serve` command, the `serve` crate feature, the
  `serve.rs` module, and the `tiny_http`/`subtle` (serve-only) dependencies are
  removed. The open `issuer` binary is a CLI:
  `issue-root`/`issue-ca`/`issue-leaf`/`issue-crl`/`csr`/`verify-journal` over
  the `pkcs11`/`vault`/`file` backends.
- The `confirm` module (the generic operator-confirmation channel: pinentry /
  terminal over a parsed `OperationSummary`) is **retained** and un-gated from
  `serve` to the `native` feature — it is public library API for external
  signing frontends (the commercial agent is one such consumer). It no longer
  depends on the crate `Msg` table (its fixed strings are localized inline).
- The agent-only parts of registry signing leave with `serve`: the
  `/sign-registry` endpoint and the CLI wiring (`--registry-key`,
  `resolve_registry_key`/`reject_registry_key`). The **backend capability
  stays** as public library API: the PKCS#11 `Pkcs11Config.registry_key` field
  and its P-256 startup probe (external signing frontends configure a dedicated
  registry key and rely on the check). The `issuer-registry-signing` change is
  removed — its agent surface is commercial, and its backend requirement is
  folded into this change's `issuer-signing` delta (an ADDED requirement).
- Serve-only operator messages leave the `l10n` table (`Msg` is no longer
  published for external frontends — they bring their own localization); the
  operation-summary parsing (`summary`, wasm-compatible) stays in the open core.
- CI (`issuer.yml`) and the release pipeline (`release-issuer.yml`) drop `serve`
  from their feature sets; the release binary is CLI-only
  (`cli,pkcs11,vault,file`).
- Docs (`docs/{ru,en}`): the agent/cabinet narrative in `issuer.md` becomes a
  "browser-based issuance ships commercially" pointer; `index.md` drops the
  agent/cabinet from the issuer summary; `threat-model.md` §11 keeps the
  browser-issuance analysis but marks the surface as moved to the commercial
  product.

## Capabilities

### New Capabilities

_нет_

### Modified Capabilities

- `issuer-signing`: the local `issuer serve` agent and the agent-side operator
  confirmation leave the open spec; the cross-platform and localization
  requirements narrow to the CLI (see the delta spec).
- `build-release`: the release `issuer` binary is CLI-only
  (`cli,pkcs11,vault,file`), no embedded cabinet or agent. Overlaps
  `cabinet-externalization` (which also MODIFIES `Release job`) — the two must
  be reconciled at sync/archive so `serve` is not re-introduced (see the
  archive-ordering note below).

## Archive ordering

Archive this change **strictly after** `cabinet-externalization`. That change's
`build-release` delta records the post-#55 state (release features still
`...,serve`); this change's delta records the final CLI-only state
(`cli,pkcs11,vault,file`). Archiving `drop-serve` last makes its delta win, so
`serve` is not reintroduced into the `Release job` requirement.

## Impact

- `crates/tessera_issuer`: `cli.rs`, `lib.rs`, `l10n.rs`, `summary.rs`,
  `pkcs11.rs`, `confirm.rs` (un-gated to `native`, Msg dependency dropped),
  `Cargo.toml`; removed `serve.rs`; `tests/pkcs11_sign.rs`.
- Root `Cargo.toml` (`tiny_http` workspace dependency removed).
- `.github/workflows/issuer.yml`, `.github/workflows/release-issuer.yml`.
- `docs/{ru,en}` (issuer, index, threat-model).
- `openspec/changes/issuer-registry-signing` removed (its subject moved out with
  the agent).

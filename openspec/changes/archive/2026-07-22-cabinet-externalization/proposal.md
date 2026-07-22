# Proposal: cabinet-externalization

## Why

The issuance cabinet (SPA) moves out of this repository and ships as an
external static bundle. The issuer binary must stop embedding it, and
`issuer serve` becomes the single agent that serves whatever bundle the
operator points it at.

## What Changes

- **BREAKING**: `cabinet/` and `crates/tessera_issuer_wasm` are removed from
  this repository; the `embed-cabinet` feature is gone.
- `issuer serve` serves an external bundle via `--cabinet-dir` (SPA
  fallback to `index.html`, reserved API routes never shadowed); without
  the flag it starts fine and shows a localized placeholder page.
- Release pipeline publishes the `issuer` binary without a cabinet
  (`cli,pkcs11,vault,serve`); CI drops the cabinet jobs.
- The `issuer-cabinet` spec leaves this repository together with the SPA.

## Capabilities

### New Capabilities

_нет_

### Modified Capabilities

- `build-release`: release `issuer` binary no longer embeds a cabinet.

## Impact

- `crates/tessera_issuer` (serve, cli, l10n), root `Cargo.toml`,
  `.github/workflows/issuer.yml`, `.github/workflows/release-issuer.yml`,
  `docs/{ru,en}` (issuer, architecture, threat-model).

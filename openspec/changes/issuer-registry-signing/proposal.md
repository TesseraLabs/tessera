# Proposal: issuer-registry-signing

## Why

External issuance cabinets need the local agent (`issuer serve`) to sign
merged device-registry snapshots, and that signing must not share a key with
certificate issuance: a registry signature and an issuance signature answer
different questions and must not be confusable.

## What Changes

- `issuer serve` gains a dedicated registry signing key (`--registry-key`,
  ECDSA P-256, verified at startup) and a `/sign-registry` endpoint.
- The issuance key MUST NOT sign registries and the registry key MUST NOT
  sign anything else; identical key labels refuse to start.
- Without a configured registry key the endpoint answers an explicit
  "key not configured" error.

## Capabilities

### New Capabilities

_нет_

### Modified Capabilities

- `issuer-signing`: registry signing as a separate agent operation with a
  dedicated key (see delta spec).

## Impact

- `crates/tessera_issuer`: `cli.rs`, `pkcs11.rs`, `serve.rs`, tests.
- Consumers: external cabinets talking to `issuer serve` over HTTP.

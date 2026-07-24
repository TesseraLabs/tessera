# Mandatory integrity control (МКЦ) — the open-source part

Tessera integrates with Astra Linux SE's mandatory integrity control (МКЦ, Biba):
an X.509 certificate carries a **ceiling** on the session's integrity level (the
`pam_cert_max_integrity` extension), and the effective session label =
`min(ceiling_from_cert, user_МНКЦ)` component-wise, where МНКЦ is the user
integrity ceiling.

## What is in the open-source part

| Component | Where |
|---|---|
| The `MacBackend` SPI + `StubBackend` | `crates/tessera_core/src/mac/backend.rs` |
| Policy (`[mac].cert_integrity` = required/optional/ignore; `[mac].runtime` = required/auto/disabled) | `mac/orchestrator.rs` |
| Label algebra (level i8 + categories u64, DER codec) | `mac/label.rs` |
| `mac_*` / `integrity_*` audit events (target `mac.audit`) | `mac/audit.rs` |
| C ABI, signature verification, and runtime backend loader | `plugin/` |
| The `[mac]` config section | `config/` |

All of the decision logic is open and auditable.

## What is in the commercial distribution

Actual application of labels to the kernel (the signed Parsec plugin:
libpdp/libparsec FFI),
activation in strict mode (capdb, systemd drop-in, PAMName), protection of the
configuration with МКЦ labels, and the full integration documentation are part of
the commercial package (`tessera-enterprise`). For contact, see
[LICENSE.commercial](../../LICENSE.commercial).

## Behavior of the open-source build

- Without `[mac].backend`, the host uses `StubBackend` (no-op enforcement);
  files in the plugin directory are never activated automatically.
- With `backend = "parsec"`, the same open host looks up only
  `/usr/lib/tessera/plugins/tessera_backend_parsec.so`, verifies its signature,
  ABI/kind/name, and only then calls `dlopen`.
- `[mac].cert_integrity = "required"` or `[mac].runtime = "required"` require
  an explicitly selected backend. A missing or rejected selected plugin fails
  closed instead of imitating enforcement.
- With `runtime = "auto"`, a missing or rejected plugin falls back to
  `StubBackend` with an audit event; a role carrying `mac_mask` is still
  rejected.

Official release builds embed raw Ed25519 public keys from
`TESSERA_PLUGIN_PUBKEYS` (64 hex characters per key, comma-separated). The
detached file format is `ed25519:<128 hex>` over the exact `.so` bytes, and
release CI rejects an empty trust store. Configuration has no signature-check
bypass.

## The МКЦ / МРД boundary

Astra SE carries two independent PARSEC mandatory mechanisms:

- **МКЦ** (mandatory integrity control, Biba) — *integrity*. This is the only
  axis Tessera assigns: the session label, the role's `mac_mask`, and the
  `pam_cert_max_integrity` ceiling.
- **МРД** (mandatory confidentiality control, Bell–LaPadula family; active at
  the "Smolensk" security level, state-secret grade) — *confidentiality*. It is
  assigned by the OS's own mechanisms. Tessera **does not assign, choose, or
  change** the confidentiality level (field 0 of the parsec label).

Systems with МРД active are **not supported**: Tessera works only with the
integrity axis and has no model for the confidentiality axis. Any parsec-label
write (session, file, descriptor) preserves the target's existing
confidentiality field unchanged — lowering the level is impossible.

### The `mac_mrd_active` startup check

The daemon detects active МРД at startup (and in `tessera check`). There is a
single record code, `mac_mrd_active`; the severity depends on `[mac].runtime`
and the probe state (in the open-source build the probe returns `Unknown`):

| `[mac].runtime` | МРД `Active` | МРД `Unknown` | МРД `Inactive` |
|---|---|---|---|
| `required` | ERROR — the daemon does not start | WARN | INFO |
| `auto` | WARN — the configuration is unsupported, the daemon starts | INFO | INFO |
| `disabled` | INFO | INFO | INFO |

ERROR obeys the general fail-closed gate of the startup check: the daemon
refuses to start. The `auto`/`disabled` modes are a deliberate acceptance of an
unsupported configuration.

## The certificate extension

`pam_cert_max_integrity`, OID `2.25.273824307386008814506455310913083078403`,
`SEQUENCE { level INTEGER (-128..127), categories BIT STRING DEFAULT ''B }`,
non-critical. For issuance, see [cert-issuance.md](cert-issuance.md).

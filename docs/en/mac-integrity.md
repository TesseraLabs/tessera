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
| The `[mac]` config section | `config/` |

All of the decision logic is open and auditable.

## What is in the commercial distribution

Actual application of labels to the kernel (ParsecBackend: libpdp/libparsec FFI),
activation in strict mode (capdb, systemd drop-in, PAMName), protection of the
configuration with МКЦ labels, and the full integration documentation are part of
the commercial package (`tessera-enterprise`). For contact, see
[LICENSE.commercial](../../LICENSE.commercial).

## Behavior of the open-source build

- The backend is always `StubBackend` (no-op enforcement).
- `[mac].cert_integrity = "required"` or `[mac].runtime = "required"` are
  **rejected at config validation**: the open-source build does not silently
  imitate enforcement.
- `optional` / `ignore` / `auto` / `disabled` all work (the policy is computed,
  events are emitted, the label is not applied).

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

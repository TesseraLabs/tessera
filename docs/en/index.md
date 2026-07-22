# Tessera documentation

This is the technical documentation: installation, configuration,
operations. For a product overview — features, use cases, contacts —
see [tessera-access.com](https://tessera-access.com/).

The Russian documents in `docs/ru/` are the primary source; this
English tree (`docs/en/`) mirrors them. The changelog is Russian-only —
see [../ru/changelog.md](../ru/changelog.md) (Russian).

> **Note:** the project was previously named `pam_certauth`.

## Routes by role

### Operator / integrator (rollout to machines)

1. [terminal-deployment.md](terminal-deployment.md) — a typical
   terminal-fleet configuration: the deployment picture, roles, and
   permission boundaries (read this first, before the pilot).
2. [install.md](install.md) — step-by-step installation of `tessera`.
3. [pam-integration.md](pam-integration.md) — editing `/etc/pam.d/*`,
   modes (`2fa` / `optional` / `cert-only`), SysV.
4. [configuration.md](configuration.md) — `config.toml` reference.
5. [mac-integrity.md](mac-integrity.md) — opt-in activation of
   mandatory integrity control (МКЦ) on Astra strict mode.
6. [clone-image.md](clone-image.md) — fleet rollout via a cloned image.
7. [fly-dm-greeter.md](fly-dm-greeter.md) — the wallpaper banner on
   fly-dm under МКЦ.
8. [operations.md](operations.md) — the runbook for routine operations.

### CA admin (certificate issuance)

1. [cert-issuance.md](cert-issuance.md) — the
   `pam_cert_host_binding`, `pam_cert_user_binding`, and
   `pam_cert_max_integrity` extensions, and issuance scenarios.
2. [issuer.md](issuer.md) — the issuer tooling (`tessera_issuer`):
   the `issuer` CLI, the CSR flow, the PKCS#11, Vault Transit and file
   backends, and the issuance journal.
3. [clone-image.md §6](clone-image.md) — the CA side of the clone-image
   workflow (per-host issuance).

### Security engineer

1. [threat-model.md](threat-model.md) — a threat model with evidence.
2. [architecture.md](architecture.md) — the IPC protocol, fail-closed
   rules, and the host identity chain.
3. [mac-integrity.md](mac-integrity.md) — МКЦ activation and protecting
   `config.toml` via ilevel=63.

### Developer

1. [development.md](development.md) — the contributor guide.
2. [architecture.md](architecture.md) — internal architecture.
3. [../ru/changelog.md](../ru/changelog.md) — change history (Russian).
4. API: `cargo doc --workspace --no-deps` → `target/doc/tessera_core/index.html`.

### When something breaks

- [troubleshooting.md](troubleshooting.md) — the single diagnostics
  reference. Cert/auth errors, USB, monitord, PAM lockout, МКЦ,
  fly-dm, clone-image, security incidents.

## What's new in 0.4.0

- The project was renamed `pam_certauth` → **Tessera**: package `tessera`,
  module `/lib/security/pam_tessera.so`, binary `/usr/bin/tessera`.
- Paths moved: `/etc/tessera`, `/run/tessera`, `/var/lib/tessera`,
  `/var/cache/tessera`; unit `tessera.service`, system user `tessera`.
- Hook environment contract `PAM_CERTAUTH_*` → `TESSERA_*`; log
  filter `TESSERA_LOG`.
- Unchanged: the X.509 extension OIDs, the `config.toml` schema, the
  IPC protocol.
- First public release (dual-license AGPL-3.0 OR commercial).

## What's new in 0.3.19

- `tessera dump-host-id` — a TSV dump of all host_identity sources.
- `finish-bootstrap.sh` — a single-pass transition from the clone-image
  bootstrap to production.
- `[fly_dm_greeter].update_wallpaper` — imprint the `host_id` into the
  fly-dm JPG background.
- CA tools removed from the `.deb` (shipped separately).

See [../ru/changelog.md](../ru/changelog.md) (Russian).

## What's new in 0.3.0

- Integration of mandatory integrity control (МКЦ) for Astra SE
  strict mode.
- The `pam_cert_max_integrity` X.509 extension — the integrity ceiling
  of an engineer's session.
- A `[mac]` section in `config.toml` with the ternary `cert_integrity`
  policy (`required` / `optional` / `ignore`).
- The `astra-mac` feature flag; a stub build for non-Astra hosts.

## Russian documentation

- [../ru/index.md](../ru/index.md) — the Russian documentation tree
  (primary).
- [README.md](../../README.md) — the project overview (English).

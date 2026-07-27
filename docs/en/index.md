# Tessera documentation

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
5. [mac-integrity.md](mac-integrity.md) — the open/commercial boundary
   for МКЦ and the МКЦ/МРД line (activation — [install.md](install.md)
   and [operations.md §7](operations.md#7-мкц-mac-integrity)).
6. [clone-image.md](clone-image.md) — fleet rollout via a cloned image.
7. [fly-dm-greeter.md](fly-dm-greeter.md) — host_id on the login screen
   (for fly-dm under МКЦ — via the wallpaper).
8. [operations.md](operations.md) — the runbook for routine operations.

### CA admin (certificate issuance)

1. [cert-issuance.md](cert-issuance.md) — the
   `pam_cert_host_binding`, `pam_cert_allowed_roles`, and
   `pam_cert_max_integrity` extensions, and issuance scenarios.
2. [issuer.md](issuer.md) — the issuer tooling (`tessera_issuer`):
   the `issuer` CLI, the `serve` agent, the CSR flow, the PKCS#11 and
   Vault Transit backends, the issuance journal, and the web cabinet.
3. [clone-image.md §6](clone-image.md) — the CA side of the clone-image
   workflow (per-host issuance).

### Security engineer

1. [threat-model.md](threat-model.md) — a threat model with evidence.
2. [architecture.md](architecture.md) — the IPC protocol, fail-closed
   rules, and the host identity chain.
3. [mac-integrity.md](mac-integrity.md) — the МКЦ/МРД boundary, the
   makeup of the open-source part and the commercial distribution.

### Developer

1. [development.md](development.md) — the contributor guide.
2. [architecture.md](architecture.md) — internal architecture.
3. [../ru/changelog.md](../ru/changelog.md) — change history (Russian).
4. API: `cargo doc --workspace --no-deps` → `target/doc/tessera_core/index.html`.

### When something breaks

- [troubleshooting.md](troubleshooting.md) — the single diagnostics
  reference. Cert/auth errors, USB, monitord, PAM lockout, МКЦ,
  fly-dm, clone-image, security incidents.

## What's new

The change history ("what's new" per version) is kept in
[../ru/changelog.md](../ru/changelog.md) (Russian only).

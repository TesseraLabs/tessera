# Tessera — USB-token certificate authentication for Linux

> **Note:** this project was formerly named `pam_certauth`.

> **License:** dual-licensed — [AGPL-3.0](LICENSE) OR
> [commercial](LICENSE.commercial). Releases up to v0.3.19 were
> published under Apache-2.0 and remain available under it.
> Contributions require a CLA (see [CONTRIBUTING.md](CONTRIBUTING.md)).

> Russian translation: [README.ru.md](README.ru.md). Reference
> documentation: [docs/en/](docs/en/index.md) (English),
> [docs/ru/](docs/ru/index.md) (Russian, canonical); the changelog is
> Russian-only.

Tessera is a Linux PAM module that replaces
password-based authentication with X.509 certificate verification. The
private key lives on a USB token (Rutoken EDS 2.0/3.0 via PKCS#11,
JaCarta GOST-2 via PKCS#11) or, for development setups, in a
passphrase-protected `.p12` on a USB filesystem.

## Capabilities

- X.509 certificate authentication via PKCS#11 token or PKCS#12 file.
- GOST R 34.10-2012 (256/512) and Streebog via Astra's `gost-engine`.
- RSA / ECDSA via OpenSSL for mixed environments.
- Host binding through per-cert X.509 v3 extensions — a stolen token on
  another machine does not work.
- Explicit role selection at login (`user+role` suffix or PAM prompt,
  no default role), authorised by the cert's `pam_cert_allowed_roles`.
- USB-removal monitoring via udev plus configurable response
  (`lock` / `logout` / `hook` / `shutdown`) via `systemd-logind` D-Bus.
- Correct suspend/resume handling with a configurable grace window.
- Integration with `fly-dm`, `sudo`, `login`, `gdm`.
- CRL and/or OCSP revocation with offline cache for air-gapped
  environments.
- Reproducible build: byte-identical `.deb` rebuilds.

## Supported operating systems

| OS             | Version       | Status                                             |
|----------------|---------------|----------------------------------------------------|
| Astra Linux SE | 1.8           | Primary target, smoke-tested in a VM.              |
| Ubuntu         | 22.04 LTS     | Best-effort, no GOST (no certified `gost-engine`). |
| Debian         | 12 «bookworm» | Best-effort, no GOST.                              |

## Supported tokens

- Rutoken EDS 2.0/3.0 — PKCS#11 module `librtpkcs11ecp.so`.
- JaCarta GOST-2 — PKCS#11 module `libjcPKCS11.so`.
- eToken Pro / 5110 — best-effort, no GOST.
- USB-filesystem + `.p12` (Mode A) — software-protected key only.

## Architecture (one-picture)

```mermaid
flowchart LR
    user([User])
    flydm[fly-dm / sudo / login]
    libpam[libpam.so]
    cdylib[libpam_tessera.so]
    daemon[tessera daemon]
    user --> flydm --> libpam --> cdylib
    cdylib -. NDJSON .-> daemon
```

Detailed architecture: [docs/en/architecture.md](docs/en/architecture.md).

## Install

```bash
sudo apt install ./tessera_0.4.0-1_amd64.deb
```

Dependencies (`gost-engine`, `pcsc-lite`, `libssl3`, `lsb-base` for the
SysV init wrapper on non-systemd hosts) are pulled in by APT. Full
step-by-step walkthrough: [docs/en/install.md](docs/en/install.md).

## Authorisation model

Authorisation ("which user on which host") lives **inside each
end-entity certificate** as two private X.509 v3 extensions:

| Extension              | OID                                            | Encoding                |
|------------------------|------------------------------------------------|-------------------------|
| `pam_cert_host_binding`| `2.25.183976554325829274683049824615098`        | `SEQUENCE OF UTF8String` |
| `pam_cert_user_binding`| `2.25.215438916728501023845629178354627`        | `SEQUENCE OF UTF8String` |

When present, these extensions are the **sole source** of authorisation
— they decide which hosts and which PAM users a certificate may sign in
to. The `[[user_mapping]]` list in `config.toml` is a **legacy fallback**
used only for certificates that ship without `pam_cert_user_binding`.
See [docs/en/cert-issuance.md](docs/en/cert-issuance.md) for the
`openssl.cnf` cookbook.

## Authentication modes

Three modes are shipped as separate PAM snippets and selected via
`integrate-pam.sh --mode=...`:

| Mode        | Snippet (`/etc/pam.d/`)   | Control                       | Behaviour                                   |
|-------------|---------------------------|-------------------------------|---------------------------------------------|
| `2fa`       | `tessera` (default)      | `auth required`               | Cert AND password (classic 2FA).            |
| `optional`  | `tessera-optional`       | `auth sufficient`             | Cert OR password — phased rollout.          |
| `cert-only` | `tessera-only`           | `auth [success=done default=die]` | Cert is the sole factor — **lockout-strict**. |

```bash
sudo /usr/share/tessera/integrate-pam.sh --mode=2fa       /etc/pam.d/sudo
sudo /usr/share/tessera/integrate-pam.sh --mode=optional  /etc/pam.d/sudo
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/sudo
```

The legacy flags `--strict` / `--optional` are still accepted as
deprecated aliases for `--mode=2fa` / `--mode=optional`. Before
deploying `cert-only`, read the lockout warning in
[docs/en/install.md §8](docs/en/install.md) and
[docs/en/operations.md §3.6](docs/en/operations.md).

## Logging

The PAM cdylib emits `tracing` records to syslog (facility `LOG_AUTH`,
ident `tessera`) — they land in `/var/log/auth.log` (classic
syslog) or in journald with the `tessera[<pid>]:` prefix. The
`tessera` daemon logs to journald via `Type=notify`.

## Quick start (10-minute test bench)

A 12-step quick-start scenario for a clean Astra Linux SE 1.7.5 VM is
provided in [README.ru.md](README.ru.md#быстрый-старт-за-10-минут-тестовый-стенд).
It covers test CA generation, issuing a test cert for
`alice`, mounting it on a USB stick, configuring `/etc/tessera/`,
enabling the `tessera` service, integrating `/etc/pam.d/sudo`, and
validating with `pamtester`.

## Project structure

```
.
├─ Cargo.toml                 # workspace manifest
├─ README.md                  # this file (English, primary)
├─ README.ru.md               # Russian translation
├─ crates/
│   ├─ pam_tessera/      # cdylib libpam_tessera.so
│   ├─ tessera_core/     # synchronous core
│   ├─ tessera_proto/    # IPC wire protocol
│   └─ tessera_cli/      # tessera daemon
├─ debian/                    # Debian packaging
├─ dist/                      # example configs, systemd unit, integrate-pam.sh
├─ docs/                      # documentation (en/ + ru/, cla/)
└─ scripts/                   # build + checksum + reproducibility scripts
```

Documentation index: [docs/en/index.md](docs/en/index.md) (English), [docs/ru/index.md](docs/ru/index.md) (Russian, canonical).

## License

Dual-licensed: [GNU AGPL-3.0](LICENSE) OR [commercial](LICENSE.commercial).
Releases up to v0.3.19 (as `pam_certauth`) were published under
Apache-2.0 and remain available under it.

## Maintainer contact

- Repository: <https://github.com/TesseraLabs/tessera>.
- Bug tracker: GitHub Issues.

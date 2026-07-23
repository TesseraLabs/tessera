# Reference configuration: terminals

This section shows how Tessera is deployed across a fleet of terminals and
**which engineers can do what on a device**. It is written for the customer's
support engineers and information-security specialists: after reading it, the
access device, the roles, and the permission boundaries are clear even before
a pilot.

The concrete values (roles, lifetimes, groups) are an example of one safe
profile, not the only possibility. For the full parameter reference see
[configuration.md](configuration.md); for login modes see
[pam-integration.md](pam-integration.md); for mandatory control on Astra see
[mac-integrity.md](mac-integrity.md).

## 1. The deployment picture

A terminal is a device with no management network (zero-egress): at the moment
an engineer logs in, reaching the server is impossible. All access checks are
therefore local, on the device itself.

On the terminal:

- **Tessera Engine** — verifies the credential and enforces permissions
  (enforcement);
- **Tessera Login** (PAM module) — the entry point into the OS;
- **monitord** — watches the media (pull the USB stick and the session closes);
- a local role database in `/var/lib/tessera/roles/`;
- the certificate authority's root certificate in `/etc/tessera/`.

The engineer brings the credential along — a certificate on a PIN-protected USB
medium or on a hardware token (Rutoken, JaCarta). When connectivity is
available, the server (Tessera Control) delivers role and revocation-list
updates, but it **is not needed at login time**.

## 2. Who logs in and under which role

A "role" in Tessera is a named set of OS permissions activated for a session at
login. We refer to people by their job title; a role is about permissions, not
about a person. A single engineer may log in under different roles if their
credential allows them.

The reference profile for a terminal fleet has three roles:

- **`oper`** — operator: day-to-day maintenance (replacing consumables, viewing
  logs, rebooting). Minimal permissions.
- **`serv`** — service engineer: setup, diagnostics, access to service commands
  via `sudo`, raised resource limits.
- **`admin`** — administrator (on Astra — with mandatory integrity control): a
  high access level, a short session lifetime.

## 3. The "operation × role" matrix

What each role permits on the terminal. "✓" — allowed by the role's
permissions, "—" — unavailable. Tessera does not replace the terminal's
application software (peripheral drivers, the terminal application, the
monitoring service): a role grants the session the groups and `sudo` rules
through which the OS lets the engineer reach that software and its service
operations.

> **Status in v0.4.0.** The matrix describes the target profile. Today Tessera
> applies the identity, the lifetime (TTL), and — on Astra, through the
> commercial MIC adapter — the integrity mask `mac_mask` to the session.
> Groups, `sudo` rules, and limits are defined by the role format and validated,
> but are not yet applied to the session: OS enforcement for them is under
> development
> ([linux-session-enforcement](../../openspec/changes/linux-session-enforcement/proposal.md)).

| Operation | `oper` | `serv` | `admin` |
|---|:---:|:---:|:---:|
| Log in to the device with a credential | ✓ | ✓ | ✓ |
| View logs and status | ✓ | ✓ | ✓ |
| Peripheral maintenance, consumables | ✓ | ✓ | ✓ |
| Reboot the device | ✓ | ✓ | ✓ |
| Access to the application software's service operations | — | ✓ | ✓ |
| Setup commands via `sudo` | — | ✓ | ✓ |
| Change the system configuration | — | — | ✓ |
| Manage account permissions on the device | — | — | ✓ |
| Disable protective barriers (ЗПС, МКЦ, software-launch control) | — | — | — |
| Session lifetime (TTL) | 8 h | 4 h | 2 h |

TTL is the upper bound on a session: once it expires the engineer logs in
again. The higher the permissions, the shorter the session.

## 4. What the engineer's credential carries

A certificate is not just a "friend/foe" pass. Embedded in it are:

- **the engineer's identity** — the certificate subject; it lands in every log
  record;
- **host binding** (host-binding) — the certificate is issued for a specific
  terminal; a stolen USB stick is useless on a neighbouring device in the fleet;
- **the allowed roles** — which roles the engineer may log in under;
- **the lifetime** (TTL) — hours or a shift, not indefinite.

All four are checked on the device, without a network.

## 5. Session lifecycle

1. The engineer inserts the media, enters the PIN, selects a role.
2. Engine checks locally: the certificate signature against the trust chain →
   host binding (this device) → lifetime → whether the requested role is
   allowed.
3. On success a session opens under the requested role, following the principle
   of least privilege — even if the certificate allows more.
4. `monitord` watches the media. Pull the USB stick and the session ends (for
   terminals: immediately).
5. Once the TTL expires the login must be repeated.

## 6. config.toml: the safe profile

The keys are given as they appear in `/etc/tessera/config.toml`; a full
description of each is in [configuration.md](configuration.md). The profile's
principle is fail-closed: when in doubt, access is denied.

```toml
# Credential in a PKCS#12 container on a USB stick. Native PKCS#11 token
# removal monitoring is not available yet, so PKCS#11 cannot provide this
# terminal profile's immediate-removal guarantee.
crypto_backend = "openssl"
mode = "pkcs12"
pkcs12_path_pattern = "certs/${user}.p12"

# Reaction to media removal. For a terminal — close the session at once.
on_usb_removed = "logout"     # or "shutdown" — power off the host
usb_removed_grace_seconds = 0 # no grace period

# A monitoring daemon failure is treated as access denial.
monitor_fail_mode = "strict"

[trust]
# The certificate authority's root certificate. At least one.
anchors = ["/etc/tessera/ca/bundle.pem"]

[trust.revocation]
# "none"  — revocation by certificate lifetime (TTL backstop);
# "crl"   — plus a local revocation list, refreshed when connectivity is available.
mode = "crl"
crl_paths = ["/etc/tessera/crl/parkruntime.crl"]
crl_max_age_hours = 24

[host_identity]
# Source of the device's identity (machine-id, DMI serials).
# fallback = "deny" — if the identity is not confirmed, login is denied.
fallback = "deny"
```

Minimal file permissions: root certificate — `0640 root:root`, the role
directory `/var/lib/tessera/roles/` — `0755 root:root`, the role slices —
`0644`.

## 7. Login: cert-only mode

For terminals the **cert-only** mode is recommended — the certificate is the
sole factor, with no fallback to a password. Loss or lockout of the token means
the login is completely unavailable — a deliberate choice for an unattended
device (the pre-rollout checklist is in [operations.md](operations.md)).

PAM snippet (`/etc/pam.d/tessera-only`):

```
auth     [success=done default=die]  pam_tessera.so
account  required                    pam_tessera.so
```

It is wired in by a script that puts the lines in the right order and adds the
session phase after `common-session`:

```bash
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/login
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/sudo
```

## 8. Roles in detail

A role is a slice file in the role-database directory. A database is for a
single OS: Linux and Astra slices are not mixed in one directory. The slices are
checked before rollout:
`tessera role lint --dir /var/lib/tessera/roles --os linux`.

### 8.1. On an OS without mandatory control (Linux)

Permissions are granted through standard OS mechanisms: supplementary groups,
`sudo` roles, systemd session limits. Engine sets the groups itself (not via
`pam_group`) — so that the permissions cannot be bypassed through DBus or sudo.

> **Important.** This section describes the target mechanics. In v0.4.0
> `groups`, `sudo_role`, and `limits` are parsed and validated
> (`tessera role lint`) but are not applied to the session — the
> implementation is being carried out in the change
> [linux-session-enforcement](../../openspec/changes/linux-session-enforcement/proposal.md).
> The examples below are correct as a role format and will work unchanged.

Operator — the minimal profile:

```toml
role = "oper"
version = 1
os = "linux"
name = "Operator"
level = 1

[payload]
groups = ["operators"]      # group membership for the session

[session]
max_ttl_seconds = 28800     # 8 h
```

Service engineer — `sudo` and raised limits:

```toml
role = "serv"
version = 1
os = "linux"
name = "Service Engineer"
level = 5

[payload]
groups = ["service", "wheel"]
sudo_role = "service"       # sudoers rule in effect during the session

[payload.limits]
nofile = 4096               # open-file limit

[session]
max_ttl_seconds = 14400     # 4 h
memory_max = "2G"           # systemd MemoryMax — hard memory ceiling
tasks_max = 512             # systemd TasksMax
```

The engineer's access to the terminal application software's service operations
is defined exactly this way: the group and the `sudo` rule in the role
determine which of the device's commands and services are available to the
engineer. Where the application software itself lives and how it is built is
determined by its vendor; Tessera only manages access permissions to it.

### 8.2. On Astra with mandatory integrity control (МКЦ)

On Astra Linux SE a role additionally carries an integrity-level ceiling
(mandatory integrity control, МКЦ). The engineer's certificate sets the maximum
level, the role a bit mask; the effective session level = the minimum of the
certificate ceiling and the role mask.

```toml
role = "admin"
version = 1
os = "astra"
name = "Administrator"
level = 63                  # reflects the МКЦ level on Astra

[payload]
mac_mask = "0x3f"           # МКЦ bit mask

[session]
max_ttl_seconds = 7200      # 2 h
```

> **Important.** In the open build of Tessera the `mac_mask` mask is parsed but
> **not applied**: the enforcement adapter via МКЦ is a commercial extension. On
> the open build a role slice with `mac_mask` is rejected at login time. For
> more on the mechanism see [mac-integrity.md](mac-integrity.md).

## 9. What no role can do

Tessera manages **access**: who logged in, under which role, which groups and
`sudo` rules are in effect during the session. It does not manage the device's
protective barriers and does not grant the right to disable them. These barriers
are a separate layer that acts independently of who logged in and under which
role. The `admin` role means high permissions within the OS, but not an
"off switch" for protection.

Independent barriers on the terminal:

- **Closed software environment (ЗПС / DIGSIG on Astra)** — the kernel launches
  only signed executables; an unsigned binary is rejected at `execve`/`mmap`.
  Running foreign software is impossible regardless of role. The same applies to
  other launch-control modules if they are installed.
- **Mandatory integrity control (МКЦ)** — a PARSEC kernel mechanism. A high
  integrity mask in a role sets the level *within* МКЦ, but not the right to
  *disable* МКЦ.
- **Integrity control of Tessera itself** — the Engine and PAM-module binaries
  are signed and protected by ЗПС; an engineer with the `admin` role cannot
  substitute them or the configuration while bypassing the check.

The key principle of a safe profile: **a role must not carry `sudo` rules that
allow switching ЗПС or МКЦ into a no-enforcement mode, stopping their services,
or substituting the signing keys.** Toggling these subsystems is not a routine
engineer operation but a change to the device's trusted state; it is performed
outside the ordinary login and under a separate procedure. Here Tessera is not
the last line of defence but an access layer on top of an already immutable
environment.

## 10. Revocation and lifetime

An engineer's access is terminated by two paths:

- **By command** (requires connectivity to the device): the revocation list
  (CRL) and termination of live sessions, device quarantine. It reaches the
  terminal at the next connectivity session.
- **By lifetime** (works always, without a network): the certificate expires by
  TTL — hours or a shift. This is a backstop: even on a fully isolated terminal
  a revoked engineer loses access once the lifetime expires.

A profile with `mode = "crl"` combines both: with connectivity the revocation
list is fresh, without connectivity it relies on the TTL. On a fleet without
connectivity `mode = "none"`, relying on the TTL alone, is acceptable.

## 11. What happens on failures

| Event | Behaviour |
|---|---|
| The engineer pulls the USB stick | The session ends (per the profile — immediately) |
| The session TTL expires | A repeated login is required |
| The server is unavailable | Login with valid certificates works; expired ones are not renewed |
| Revocation not delivered (no connectivity) | The certificate will expire by TTL anyway |
| The monitoring daemon failed | `monitor_fail_mode = "strict"` → login is denied |
| The device identity is not confirmed | `fallback = "deny"` → login is denied |

A failure of the server component neither opens the door nor locks out a valid
engineer with a valid certificate. Security is the same with and without the
server — the server adds scale and data freshness, not security.

## 12. Safe-rollout checklist

- [ ] Root certificate on the device, permissions `0640 root:root`.
- [ ] `host_identity.fallback = "deny"`.
- [ ] `monitor_fail_mode = "strict"`.
- [ ] `on_usb_removed` = `logout` or `shutdown`, `usb_removed_grace_seconds = 0`.
- [ ] cert-only login mode wired into the required services (login, sudo, graphical login).
- [ ] Role slices have passed `tessera role lint`.
- [ ] Role TTLs match the risk (higher permissions — shorter session).
- [ ] For Astra with МКЦ — the commercial enforcement adapter is installed.
- [ ] ЗПС (DIGSIG) in `enforce` mode; Tessera binaries are signed.
- [ ] No role contains `sudo` rights to manage ЗПС, МКЦ, or the signing keys.
- [ ] The revocation list (if `mode = "crl"`) is refreshed at least once per shift.
- [ ] The token-loss scenario and the emergency-access procedure have been tested.

## 13. Next

- [configuration.md](configuration.md) — the full `config.toml` reference.
- [pam-integration.md](pam-integration.md) — login modes and PAM integration.
- [cert-issuance.md](cert-issuance.md) — issuance of credentials and certificate extensions.
- [mac-integrity.md](mac-integrity.md) — mandatory integrity control on Astra.
- [operations.md](operations.md) — operations, the pre-rollout checklist.

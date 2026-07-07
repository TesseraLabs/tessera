# Tessera configuration reference

This document is the reference for the main `tessera`
configuration file:

- `/etc/tessera/config.toml` — the main configuration of the `tessera`
  module and daemon.

The "which user on which host" authorization lives inside the
certificate itself — in the X.509 extensions `pam_cert_host_binding` and
`pam_cert_user_binding`. When the `pam_cert_user_binding` extension is
present on the leaf certificate, it fully determines which PAM user is
allowed to log in, and the `[[user_mapping]]` array from this file is
**ignored**. `[[user_mapping]]` is kept in the schema as a legacy
fallback — it applies only to certificates issued without the
`pam_cert_user_binding` extension. See
[docs/cert-issuance.md](cert-issuance.md).

Each field is described in the format "type → default value →
allowed values → effect on behavior → security implication".
All fields are validated on load through
`tessera_core::config::ValidatedConfig::try_from`
(see [`crates/tessera_core/src/config/validated.rs`](../../crates/tessera_core/src/config/validated.rs)
and [`crates/tessera_core/src/config/raw.rs`](../../crates/tessera_core/src/config/raw.rs)).
Unknown fields or wrong types are a load error → fail-closed.

> All examples use test data (`alice@example.test`,
> `TERMINAL-001`, `ca-test.example`). There are no real CAs, passwords,
> or customer hosts in this document.

## The `/etc/tessera/config.toml` file

The full shipped example lives in
[`dist/config/config.toml.example`](../../dist/config/config.toml.example).
This example is checked by the regression test
`crates/tessera_core/tests/dist_examples_parse.rs` — it guarantees that
the example really validates through `ValidatedConfig::try_from`.

### Global parameters

| Field                      | Type               | Default     | Allowed values                                                 | Effect                                                        | Security implication                                                                 |
|----------------------------|--------------------|-------------|----------------------------------------------------------------|---------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `crypto_backend`           | string             | —           | `"openssl"`, `"pkcs11_native"`                                 | Which backend computes signatures and hashes.                | `"openssl"` is required for GOST via `gost-engine`.                                  |
| `mode`                     | string             | —           | `"pkcs12"`, `"pkcs11"`                                         | Where the user's key lives.                                   | `"pkcs11"` — non-extractable key; `"pkcs12"` — software protection.                  |
| `pkcs11_module`            | path               | —           | absolute path to a `.so`                                       | Which PKCS#11 module is used.                                 | Required when `mode = "pkcs11"`.                                                     |
| `pkcs11_token_label`       | string             | `None`      | `≤ 64` bytes, no NUL                                           | Filter by the token's `CKA_LABEL`.                           | Guards against accidentally selecting someone else's token on the machine.          |
| `pkcs11_object_label`      | string             | `None`      | `≤ 64` bytes, no NUL                                           | Filter by the object's `CKA_LABEL` (cert/privkey).           | Likewise, protection against selecting the wrong object.                             |
| `pkcs11_max_pin_attempts`  | integer            | `3`         | `1..=5`                                                        | How many times the module offers to enter the PIN.           | Too many → anti-paranoia; too few → poor UX.                                         |
| `pkcs11_locking_mode`      | string             | `"os"`      | `"os"`, `"mutex"`                                              | PKCS#11 locking strategy.                                    | Depends on the shipped PKCS#11 module (see the vendor documentation).                |
| `pkcs11_pin_prompt`        | string             | `"Введите PIN токена: "` | UTF-8, non-empty, `≤ 128` bytes                  | PIN prompt text on the PKCS#11 path. The default is the Russian string `"Введите PIN токена: "` ("Enter token PIN: "). | UX localization, not security.                                       |
| `pkcs11_slot_wait_seconds` | integer            | `10`        | `0..=60`                                                       | How many seconds to wait for the token to be inserted.       | `0` — do not wait; UX vs. convenience.                                               |
| `pkcs11_allow_extractable_keys` | boolean       | `false`     | `true`, `false`                                                | Whether to accept keys with `CKA_EXTRACTABLE = TRUE`.        | `false` (default) — reject (fail-closed): an extractable key breaks the invariant of mode B. `true` — only `pkcs11_extractable_key` WARN; enable deliberately. |
| `pkcs12_path_pattern`      | string             | `"certs/user.p12"` | path relative to the USB mountpoint, optional `${user}` | Where to look for the `.p12` on the USB media (supports `${user}`). | Relative path only; `..`/`.` segments and absolute paths are rejected by the validator. |
| `pkcs12_pin_prompt`        | string             | `"Smart-card PIN: "` | UTF-8, non-empty, `≤ 128` bytes                     | Prompt text for the `.p12` password.                         | UX localization.                                                                    |
| `gost_engine_path`         | path               | `None`      | absolute path to a `.so`                                       | Explicit path to `gost-engine`. By default, lookup by id.    | `None` — the engine is looked up via `OPENSSL_ENGINES`.                              |
| `usb_wait_seconds`         | integer            | `10`        | `0..=300`                                                      | How many seconds to wait for the USB media.                  | UX. At `0` — fail-fast.                                                              |
| `usb_allowed_devices`      | array of strings   | `[]`        | `"vid:pid"` strings, 4 hex digits each (lsusb format), e.g. `["0951:1666"]` | Allow-list of USB devices treated as `.p12` media; empty/absent = any USB block device. | Hygiene against accidental/foreign flash drives, NOT a trust boundary: VID/PID are forgeable, trust comes only from decrypting the `.p12` + chain validation. |
| `max_usb_partitions`       | integer            | `8`         | `1..=64`                                                       | Maximum number of partitions scanned when searching for the `.p12`. | DoS protection: a physical attacker cannot force a huge number of mount/umount operations. |
| `on_usb_removed`           | string             | `"lock"`    | `"lock"`, `"logout"`, `"hook"`, `"shutdown"`                   | Action on confirmed USB removal.                             | `"shutdown"` fits terminals; `"lock"` fits workstations.                             |
| `usb_removed_grace_seconds`| integer            | `0`         | `0..=300`                                                      | Cancellation window: reinserting the same serial cancels the action. | Protects against false triggers; set to `0` on terminals.                    |
| `suspend_grace_seconds`    | integer            | `0`         | `0..=600`                                                      | Window after resume during which USB removal is ignored.     | Hubs often make noise during suspend; `30` seconds is a typical value.               |
| `monitor_fail_mode`        | string             | `"strict"`  | `"strict"`, `"permissive"`                                     | Whether to propagate non-fatal `monitord` IPC errors to the calling code (`strict`) or swallow them with a WARN (`permissive`). | `DeviceGone`/`Unauthorized` are always fatal; `monitord` transport failures do not override a successful auth (see architecture.md §13). |

> **Authorization (host + user) is described in the certificate itself
> via X.509 v3 extensions** `pam_cert_host_binding` and
> `pam_cert_user_binding`. This file contains only trust + identity +
> monitor + hooks; see [cert-issuance.md](cert-issuance.md) for issuing
> certificates with the required extensions.

#### Values of `on_usb_removed`

| Value        | Action on confirmed USB removal                                                          | Typical scenario                     |
|--------------|-------------------------------------------------------------------------------------------|--------------------------------------|
| `"lock"`     | `LockSession` via D-Bus to logind for **this** session. The host keeps running.           | Operator workstation.                |
| `"logout"`   | `TerminateSession` for **this** session. The host keeps running, other sessions intact. | Kiosks, terminals (if the host must not power off). |
| `"hook"`     | Runs the external executable given in `monitor.on_usb_removed_hook_path`.                  | Complex scenarios (audit + custom action). |
| `"shutdown"` | `PowerOff` via D-Bus to logind — powers the host off.                                     | Terminals / dedicated workstations.  |

With `"hook"`, the `[monitor]` section must contain
`on_usb_removed_hook_path = "/absolute/path"`. The validator refuses to
load the config when `on_usb_removed = "hook"` and no `hook_path` is set.

### The `[monitor]` section

| Field                        | Type   | Default | Allowed values       | Effect                                                              | Security implication                                           |
|------------------------------|--------|---------|----------------------|----------------------------------------------------------------------|------------------------------------------------------------------|
| `on_usb_removed_hook_path`   | path   | `None`  | absolute path        | Executable for `on_usb_removed = "hook"`. Valid **only** with that value of `on_usb_removed`. | Runs as root; the path is checked for unsafe permissions.       |
| `idle_timeout_seconds`       | integer| `30`    | `1..=3600`           | Idle timeout of the IPC connection to monitord.                     | Anti-DoS: hanging connections are closed.                       |
| `max_concurrent_connections` | integer| `64`    | `1..=4096`           | Maximum simultaneous IPC connections to monitord.                   | Anti-DoS: caps the daemon's resource consumption.               |
| `socket_path`                | path   | `/run/tessera/monitord.sock` | absolute path | monitord's Unix socket.                                | The socket's permissions restrict access to the IPC.            |
| `timeout_ms`                 | integer| `2000`  | milliseconds         | Connect+IO timeout of a single RPC.                                 | Fail-mode responsiveness when the daemon hangs.                 |
| `fail_mode`                  | string | —       | same as `monitor_fail_mode` | Per-section override of the top-level `monitor_fail_mode`.    | Determines behavior when monitord is unavailable.               |
| `state_file_path`            | path   | `/run/tessera/sessions.json` | absolute path | Session registry (tmpfs; survives a daemon restart, not a boot). | Moving it off tmpfs would leave stale records after a reboot. |
| `on_usb_removed`             | string | —       | same as top-level    | Per-section override of `on_usb_removed`.                           | See the top-level key.                                          |
| `usb_removed_grace_seconds`  | integer| —       | same as top-level    | Per-section override of the cancellation window.                    | See the top-level key.                                          |
| `suspend_grace_seconds`      | integer| —       | seconds              | Window after resume during which removal events are ignored (default 30). | Too large a window weakens the response to removal.       |

### The `[trust]` section

| Field                           | Type         | Default | Allowed values                     | Effect                                                 | Security implication                                              |
|---------------------------------|--------------|---------|------------------------------------|--------------------------------------------------------|-------------------------------------------------------------------|
| `anchors`                       | list of paths | —      | `≥ 1` PEM file                     | Root trust CAs.                                        | The root of trust. Must be `0640 root:root`.                     |
| `intermediates`                 | list of paths | `[]`   | PEM files                          | Intermediate CAs (optional).                           | Relieves the load of chain building.                             |
| `max_chain_depth`               | integer      | `5`     | `1..=16`                           | Maximum X.509 chain depth.                             | Anti-DoS.                                                        |
| `clock_skew_seconds`            | integer      | `0`     | `0..=600`                          | Allowed clock deviation when checking `notBefore`/`notAfter`. | Too much — an attacker with a stale certificate.          |
| `allowed_signature_algorithms`  | list of strings | `[]` | OIDs or names                      | Signature whitelist. Empty/omitted is replaced by a safe default: `sha256/384/512WithRSAEncryption`, `ecdsa-with-SHA256/384/512` (no SHA-1 and no GOST). | The SHA-1/MD5/weak-RSA ban applies even without explicit configuration; GOST requires an explicit opt-in. |
| `max_supported_profile_version` | integer      | compiled-in default | `u32`                   | Maximum understood `pam_cert_profile_version`; a cert with a higher version rejects the whole chain (fail-closed, version-gate). | Protection against silently ignoring the unknown semantics of newer profile versions. |

Entries are compared **exactly** (no substrings) against the OpenSSL
display form of the certificate's algorithm (see `pre_validate_end_entity`
in [`crates/tessera_core/src/x509/pre_validate.rs`](../../crates/tessera_core/src/x509/)):

- RSA: `"sha256WithRSAEncryption"`, `"sha384WithRSAEncryption"`, `"sha512WithRSAEncryption"`
- ECDSA: `"ecdsa-with-SHA256"`, `"ecdsa-with-SHA384"`, `"ecdsa-with-SHA512"`
- GOST R 34.10-2012-256: `"id-tc26-signwithdigest-gost3410-12-256"`
- GOST R 34.10-2012-512: `"id-tc26-signwithdigest-gost3410-12-512"`

### The `[trust.revocation]` section

| Field                      | Type      | Default  | Allowed values                                            | Effect                                                   | Security implication                                                  |
|----------------------------|-----------|----------|-----------------------------------------------------------|----------------------------------------------------------|------------------------------------------------------------------------|
| `mode`                     | string    | `"none"` | `"none"`, `"crl"`, `"ocsp"`, `"crl_then_ocsp"`           | Which revocation sources are used.                       | `"none"` — revocation is not checked (NOT for production).            |
| `crl_paths`                | list of paths | `[]` | PEM/DER files                                             | Local CRLs.                                              | Required when `mode = "crl"`.                                         |
| `crl_max_age_hours`        | integer   | `None`   | `1..=8760` (hours)                                        | Maximum age of a CRL from `thisUpdate` before rejection. | Not set — CRL freshness is not checked; not recommended.             |
| `ocsp_responder_url`       | URL string | —       | `http://…` / `https://…`                                 | Address of the OCSP responder. REQUIRED when `mode ∈ {ocsp, crl_then_ocsp}`. The AIA is not extracted from the cert. | The only source of the address is the config (predictability for offline audit). |
| `ocsp_timeout_seconds`     | integer   | `5`      | `1..=30`                                                  | Overall deadline for one OCSP exchange (connect+write+read). | Login budget = (chain depth − 1) × timeout.                      |
| `ocsp_cache_ttl_seconds`   | integer   | `3600`   | `0..=86400`                                               | Upper bound on cache-entry lifetime (`0` = cache disabled). | The cache limits network calls; an entry is valid until `min(nextUpdate, mtime+ttl)`. |

**Revocation-mode semantics:**

| `mode`           | Behavior |
|------------------|-----------|
| `none`           | Revocation is not checked; the compensation is a short TTL on leaf certs (a deployment policy). |
| `crl`            | Strict offline CRL: an expired/missing covering CRL → reject. |
| `ocsp`           | Every non-anchor cert in the chain is checked via OCSP; the CRL store is not involved. |
| `crl_then_ocsp`  | CRL first: a fresh CRL whose issuer DN covers the cert gives a status without a network call; otherwise OCSP is required. |

> **Fail-closed in OCSP modes.** An unavailable responder, a timeout,
> an `unknown` status, an unverifiable response signature, or a
> `thisUpdate/nextUpdate` window outside tolerance (accounting for
> `clock_skew_seconds`) → **authentication is rejected** (`PAM_AUTH_ERR`).
> There is no "WARN and skip" degradation in OCSP modes — whoever wants
> leniency chooses `none` or non-strict CRL.
>
> **Do not enable OCSP for zero-egress segments (terminals)** — there is
> no network to the responder there; their mode is `none` + a short TTL,
> or offline `crl`. OCSP is for network-connected segments (office
> workstations, customer test benches). The `ocsp_*` keys are rejected by
> validation when `mode ∈ {none, crl}` (they cannot be silently ignored).
> The cache is `/var/cache/tessera/ocsp/*.der`, and the directory is
> created by the package's postinst.

### The `[trust.pinning]` section

| Field                      | Type      | Default  | Allowed values                     | Effect                                                 | Security implication                                                  |
|----------------------------|-----------|----------|-------------------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `enabled`                  | bool      | `false`  | `true`, `false`                    | Enables pinning on the SPKI of root CAs.               | Protection against CA compromise.                                    |
| `allowed_root_spki_sha256` | list of strings | `[]` | 64-character lower-case hex        | List of allowed root SPKI hashes.                      | Any root not in the list is rejected.                                |

### The `[host_identity]` section

| Field                           | Type         | Default          | Allowed values                                                            | Effect                                                            | Security implication                                             |
|---------------------------------|--------------|------------------|---------------------------------------------------------------------------|-------------------------------------------------------------------|--------------------------------------------------------------------|
| `sources`                       | list of strings | —             | `"machine_id"`, `"dmi_board_serial"`, `"dmi_system_uuid"`, `"dmi_system_serial"`, `"hostname"`, `"custom_command"`, `"override"` | Chain of `host_id` sources. The first non-empty one wins.      | The more stable the source, the stronger the host binding.       |
| `fallback`                      | string       | `"deny"`         | `"deny"`, `"warn"`, `"allow"`                                             | What to do if all sources are empty.                              | In production — `"deny"` only.                                    |
| `override`                      | string       | `None`           | UTF-8, no line breaks                                                     | A hard-coded `host_id` value (for tests).                         | Do NOT use in production.                                        |
| `custom_command`                | path         | `None`           | absolute path to a script                                                | A script that prints `host_id` to stdout.                         | The script runs as `root`. Must be `0750 root:root`.             |
| `custom_command_timeout_seconds`| integer      | `5`              | `1..=30`                                                                  | Timeout for executing `custom_command`.                           | Anti-DoS.                                                        |

The chain implementation is in
[`crates/tessera_core/src/host_identity/chain.rs`](../../crates/tessera_core/src/host_identity/chain.rs).
The `fallback = "deny"` behavior guarantees fail-closed: if no source
yields a value, authentication does not pass.

### The `[[user_mapping]]` section (legacy fallback)

> **Only for certificates without the `pam_cert_user_binding` extension.**
> If the `pam_cert_user_binding` extension is present on the leaf
> certificate, the `[[user_mapping]]` array is **fully ignored** — the
> certificate itself determines authorization. New issuances must always
> set the extension (mandatory-extension policy, see
> [docs/threat-model.md §3.8](threat-model.md)).

An array of tables. Each entry is a "PAM user → certificate criterion"
pair.

| Field              | Type   | Default | Allowed values                    | Effect                                                   | Security implication                                                |
|--------------------|--------|---------|-----------------------------------|----------------------------------------------------------|----------------------------------------------------------------------|
| `pam_user`         | string | —       | UNIX user name                    | Which UNIX user is presented to the PAM stack.          | Must be a local account.                                            |
| `cert_subject_cn`  | string | `None`  | the `CN` value from the subject DN | Match by `CN`.                                          | Exactly one of the three criteria must be set.                     |
| `cert_san_email`   | string | `None`  | RFC822 name from the SAN          | Match by `subjectAltName`.                              | Exact string, no regex.                                            |
| `cert_san_upn`     | string | `None`  | UPN name from the SAN OtherName   | Match by UPN (Microsoft AD).                           | Applicable to mixed AD environments.                              |

> Exactly one of `cert_subject_cn`/`cert_san_email`/`cert_san_upn` must
> be set in each entry. Failing this is a validation error.

### The `[logging]` section

| Field               | Type   | Default  | Allowed values                                            | Effect                                                 | Security implication                                                  |
|---------------------|--------|----------|-----------------------------------------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `level`             | string | —        | `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`       | Verbosity level of the **daemon's** log. The `TESSERA_LOG` environment variable takes priority over this field. | `"trace"` — debugging; do not leave it on in production.              |
| `syslog_facility`   | string | optional | `"auth"`, `"authpriv"`, `"user"`, `"daemon"`              | **Deprecated, ignored.** The PAM module writes to the syslog `auth` facility, fixed. The field is validated (`local0..7` are not supported — a load error), but has no runtime effect; if the key is present, a "deprecated and ignored" WARN is emitted to the log. | No effect on behavior.                                                |
| `journald_priority` | bool   | optional | `true`, `false`                                           | **Deprecated, ignored.** If the key is present — a "deprecated and ignored" WARN. | No effect on behavior.                                                |

> PINs and passwords are never logged. Full certificate DNs are logged at
> `debug` and above; at `info` and below — only the CN.

### The `[roles]` section

Controls role selection at login and the device's role store (see
[`docs/cert-issuance.md`](cert-issuance.md) — the `pam_cert_allowed_roles`
extension).

| Field                        | Type   | Default                  | Allowed values                   | Effect                                                                 | Security implication                                                  |
|------------------------------|--------|--------------------------|---------------------------------|--------------------------------------------------------------------------|------------------------------------------------------------------------|
| `enforce`                    | string | `"false"`                | `"false"`, `"warn"`, `"require"` | Migration stage of role enforcement.                                   | `"false"` — roles are not checked (v0.3.19 behavior); `"require"` — full fail-closed. |
| `dir`                        | path   | `/var/lib/tessera/roles` | absolute path to a directory     | Role-store directory (`<role>.toml` slices).                            | `root:root`, directory `0755`, files `0644`.                          |
| `default_session_ttl_seconds`| integer| `43200` (12 h)           | seconds                          | Session TTL when neither the credential nor the role sets one.          | No unbounded session arises — the ceiling is always finite.          |

**`enforce` semantics:**

| Value       | Behavior |
|-------------|-----------|
| `"false"`   | No suffix/prompt is requested, coverage is not checked — login works as in v0.3.19. |
| `"warn"`    | The role is checked, a mismatch is logged, but login is not refused (migration mode). |
| `"require"` | Full enforcement: a role is mandatory and must be covered by the credential. |

> **Fail-closed with `enforce = "require"`.** An empty or invalid role
> store under `require` leads to refusal of logins that require a role,
> with a "roles not configured" diagnostic.

**Role selection at login.** There is no default role — the role is
specified explicitly, in two DM-agnostic ways: by the account-name
suffix `<user>+<role>` (for example `ssh ivanov+serv@device`) or by a
textual PAM prompt if no suffix is given. Without a specified role (and
when a prompt cannot be shown) login is refused. The module canonicalizes
PAM_USER — it rewrites the name to the canonical form (`ivanov`) before
the rest of the stack's modules; the `+` character is forbidden in
canonical account names.

### The `[tags]` section

Device tags for delegation constraints (`device-tags`). Absence of the
section = the device has no tags (a fail-closed default): a delegation
envelope with a group constraint on an untagged device is rejected.

| Field     | Type    | Default      | Allowed values          | Effect                                                                 | Security implication                                        |
|-----------|---------|--------------|-------------------------|------------------------------------------------------------------------|--------------------------------------------------------------|
| `enforce` | boolean | `false`      | `true`/`false`          | Whether to read the tag source. `false` — a device with no applied tags. | Group delegations on an untagged device are rejected anyway (fail-closed). |
| `mode`    | string  | `standalone` | `standalone`, `managed` | Trust model of the source: a tags file or a signed `manifest.toml`.    | `managed` requires a signed manifest.                       |
| `source`  | path    | `/var/lib/tessera/tags.toml` (standalone) / role-store directory (managed) | absolute path | The tags file or the directory with the manifest. | The permissions on the source file are part of the trust boundary. |

### The `[[hooks]]` section

An array of tables. Each hook is an external command executed at a
lifecycle stage. The full implementation is in
[`crates/tessera_core/src/hooks/`](../../crates/tessera_core/src/hooks/).

| Field              | Type         | Default | Allowed values                                                                                       | Effect                                                   | Security implication                                                                  |
|--------------------|--------------|---------|-------------------------------------------------------------------------------------------------------|----------------------------------------------------------|----------------------------------------------------------------------------------------|
| `stage`            | string       | —       | `"pre_auth"`, `"post_auth_success"`, `"session_open"`, `"session_close"`, `"usb_removed"`             | At which lifecycle stage the hook is invoked.           | Hooks run under sandbox restrictions (see [docs/threat-model.md](threat-model.md)).    |
| `command`          | list of strings | —    | `[ "/usr/local/sbin/foo", "arg" ]`, the first element is an absolute path                             | The hook's argv. Passed **literally**; placeholders in argv are NOT substituted. | Dynamic data is passed only through `env` — argv injection is impossible. |
| `timeout_seconds`  | integer      | `10`    | `1..=120`                                                                                             | Execution timeout.                                      | The hook is killed with `SIGKILL` when it expires.                                     |
| `on_failure`       | string       | `None`  | `"warn"`, `"ignore"`; any other value → abort                                                        | What to do on a non-zero hook return code.              | Default: abort (deny) for `pre_auth` (there, `"warn"` is also forced to abort); `"warn"` for the other stages. |
| `run_as`           | string       | `None`  | UNIX name                                                                                             | The UID the hook runs under.                            | Defaults to `root`. Dropping privileges is best practice.                             |
| `env`              | table        | `{}`    | `{ KEY = "literal ${placeholder}" }` strings                                                         | Environment variables passed to the hook.               | Base: a whitelist of `PATH`/`HOME`/`USER`/`LOGNAME`/`LANG` + all `TESSERA_*` variables; custom keys may override them. |

`${...}` substitution works **only in `env` values** — `command` is
executed literally (see
[`crates/tessera_core/src/hooks/fork_exec.rs`](../../crates/tessera_core/src/hooks/fork_exec.rs)).
In addition, the hook always receives a ready-made set of variables
`TESSERA_STAGE`, `TESSERA_USER`, `TESSERA_SERVICE`, `TESSERA_HOST_ID`,
`TESSERA_HOST_ID_HASH`, `TESSERA_HOST_ID_SOURCE`, `TESSERA_CERT_CN`,
`TESSERA_CERT_SERIAL`, `TESSERA_USB_SERIAL`, `TESSERA_USB_VID_PID`,
`TESSERA_SESSION_ID` (an empty string if the value is unavailable).

Allowed placeholders for `env` values (see
[`crates/tessera_core/src/hooks/placeholder.rs`](../../crates/tessera_core/src/hooks/placeholder.rs)):

- `${pam_user}` — the UNIX user.
- `${pam_service}` — the PAM service.
- `${host_id}` / `${host_id_hash}` / `${host_id_source}` — the computed
  `host_id`, its SHA-256, and the source name.
- `${cert_cn}` — the certificate's Common Name.
- `${cert_serial}` — the certificate serial (hex).
- `${usb_serial}` / `${usb_vid_pid}` — the USB media's data.
- `${session_id}` — the PAM session UUID.

Example: dynamic data — through `env`, not through argv:

```toml
[[hooks]]
stage           = "post_auth_success"
command         = ["/usr/local/sbin/audit-login"]
timeout_seconds = 5
on_failure      = "warn"
env             = { AUDIT_USER = "${pam_user}", AUDIT_SERIAL = "${cert_serial}" }
```

### The `[fly_dm_greeter]` section (0.3.19+)

Optional. Controls the wallpaper writer for fly-dm — it stamps `host_id`
into the JPG background pointed to by `[background].path` in
`/etc/X11/fly-dm/fly-modern/settings.ini`. A workaround for the MIC-3
(mandatory integrity control, МКЦ, level 3) fly-modern theme, where
PAM_TEXT_INFO is not forwarded to the UI.

| Field                   | Type   | Default                                                       | Description                                                              |
|-------------------------|--------|---------------------------------------------------------------|--------------------------------------------------------------------------|
| `update_wallpaper`      | bool   | `false`                                                       | Enable the wallpaper writer.                                             |
| `wallpaper_target`      | path   | `/usr/share/wallpapers/fly-default-light.jpg`                 | The JPG that the daemon repaints.                                       |
| `wallpaper_backup`      | path   | `/var/lib/tessera/wallpaper.orig.jpg`                    | Where the one-time original of the source is saved.                     |
| `wallpaper_font`        | path   | `/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf`        | The TrueType font used for rendering.                                   |
| `wallpaper_font_size`   | int    | `64`                                                          | Font size in points.                                                    |
| `wallpaper_text_color`  | string | `"#000000"`                                                   | Color in hex (`#RRGGBB`).                                               |
| `wallpaper_gravity`     | enum   | `"south"`                                                     | `north` / `south` / `east` / `west` / `center` — the positioning anchor. |
| `wallpaper_offset_x`    | int    | `0`                                                           | Horizontal offset in pixels from the gravity anchor.                    |
| `wallpaper_offset_y`    | int    | `120`                                                         | Vertical offset in pixels from the gravity anchor (for `south` — upward). |
| `template_ru`           | string | `"Устройство %n  host_id={host_id_short} ({source})"`           | Template for the ru locale.                                             |
| `template_en`           | string | `"Device %n  host_id={host_id_short} ({source})"`                | Template for the en locale.                                             |

Substitutions in the template: `{host_id_short}` (the first 8 hex of the
sha256), `{source}` (the source name — `MachineId`, `DmiBoardSerial` …),
`%n` (hostname). Behavior, the baseline for `settings.ini`, and
troubleshooting — see **[fly-dm-greeter.md](fly-dm-greeter.md)**.

The legacy field `update_greet_string` (0.3.16–0.3.18) rewrote
`/etc/X11/fly-dm/override/GreetString.desktop`. On production MIC-3
fly-modern it is ignored (a no-op). Kept for backward compatibility, but
does NOT work on terminals. Use `update_wallpaper` instead.

### The `[[trust_override]]` section

An array of tables. Each entry is an override of `[trust]` for a limited
set of `host_id`s.

| Field              | Type         | Default | Allowed values             | Effect                                                 | Security implication                                                  |
|--------------------|--------------|---------|-----------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `when_host_id_in`  | list of strings | —     | list of `host_id`s          | On which machines to apply the override.                | Must be non-empty.                                                     |
| `anchors`          | list of paths | `[]`   | PEM files                   | Which trust roots to use instead of the main ones.      | Narrows trust on specific machines.                                    |
| `intermediates`    | list of paths | `[]`   | PEM files                   | Which intermediates to use.                             | Likewise.                                                              |

### Worked example: a minimal valid configuration

```toml
crypto_backend = "openssl"
mode           = "pkcs12"
pkcs12_path_pattern = "certs/${user}.p12"  # relative to the USB mountpoint

usb_wait_seconds         = 10
on_usb_removed           = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds    = 30
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/tessera/ca/bundle.pem"]

[trust.revocation]
mode = "none"

[host_identity]
sources  = ["machine_id", "hostname"]
fallback = "deny"

[[user_mapping]]
pam_user        = "alice"
cert_subject_cn = "Alice"

[logging]
level = "info"
```

## Authorization in the certificate

The certificate's binding to hosts and users is fully described by two
X.509 v3 extensions of the leaf certificate:

- `pam_cert_host_binding` (OID `2.25.183976554325829274683049824615098`)
  — a `SEQUENCE OF UTF8String`, where each entry is either `*`, or
  `sha256:<HEX>`, or a "raw" `machine_id` value (in which case the
  comparison goes through SHA-256 of the string).
- `pam_cert_user_binding` (OID `2.25.215438916728501023845629178354627`)
  — a `SEQUENCE OF UTF8String`, where each entry is either `*` or an
  exact PAM user name.

To authorize a certificate for a specific `host_id` / `pam_user`, **at
least one matching entry in each** of the extensions is required. The
absence of either extension, a corrupt DER encoding, or a complete
absence of matches is a rejection (`PAM_AUTH_ERR`).

Details and ready-made `openssl.cnf` recipes are in
[cert-issuance.md](cert-issuance.md).

## Typical scenarios

### 3.1 Terminal — offline, CRL with TTL, USB required

Properties: the machine is in a metal enclosure, no Internet, the key is
on a token, USB removal → immediate session termination (no grace).

```toml
crypto_backend = "openssl"
mode           = "pkcs11"
pkcs11_module  = "/usr/lib/librtpkcs11ecp.so"
pkcs11_max_pin_attempts = 3
pkcs11_slot_wait_seconds = 5

usb_wait_seconds         = 5
on_usb_removed           = "shutdown"   # terminal — power off
usb_removed_grace_seconds = 0           # no cancellation
suspend_grace_seconds    = 0
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/tessera/ca/terminal-ca.pem"]
allowed_signature_algorithms = [
    "1.2.643.7.1.1.3.2",   # GOST-2012-256
]

[trust.revocation]
mode             = "crl"
crl_paths        = ["/etc/tessera/crl/terminal.crl"]
crl_max_age_hours = 72

[trust.pinning]
enabled = true
allowed_root_spki_sha256 = [
    "ee0bd4f3a3c8e21d4a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f"
]

[host_identity]
sources  = ["dmi_board_serial", "machine_id"]
fallback = "deny"

[[user_mapping]]
pam_user      = "operator"
cert_san_upn  = "operator@terminal.example.test"

[logging]
level = "warn"
```

Rationale for the choices:

- `mode = "pkcs11"` + `librtpkcs11ecp.so`: a non-extractable key.
- `on_usb_removed = "shutdown"`: a terminal must not stay powered on with
  an unlocked session.
- `usb_removed_grace_seconds = 0`: on a terminal there can be no "pulled
  it out and changed my mind".
- `mode = "crl"` with `crl_max_age_hours = 72`: three days is a
  compromise between UX (the CRL is updated daily) and security.
- `host_identity.sources = ["dmi_board_serial", ...]`: the motherboard is
  tied to the enclosure, a replacement → a new `host_id` → the
  certificate must be reissued with the new value in
  `pam_cert_host_binding`.
- `pinning.enabled = true`: a CA compromise does not automatically open
  all terminals.

### 3.2 Workstation in a protected segment — CRL, GOST token

```toml
crypto_backend = "openssl"
mode           = "pkcs11"
pkcs11_module  = "/usr/lib/librtpkcs11ecp.so"
pkcs11_token_label = "STAFF"
pkcs11_max_pin_attempts = 3
pkcs11_slot_wait_seconds = 10

usb_wait_seconds         = 10
on_usb_removed           = "lock"
usb_removed_grace_seconds = 30
suspend_grace_seconds    = 60
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/tessera/ca/staff-ca.pem"]
intermediates = ["/etc/tessera/ca/staff-int.pem"]
allowed_signature_algorithms = [
    "1.2.643.7.1.1.3.2",  # GOST-2012-256
    "1.2.643.7.1.1.3.3",  # GOST-2012-512
]

[trust.revocation]
mode               = "crl"
crl_paths          = ["/etc/tessera/crl/staff.crl"]
crl_max_age_hours  = 24

[host_identity]
sources  = ["machine_id", "hostname"]
fallback = "deny"

[[user_mapping]]
pam_user        = "staff"
cert_subject_cn = "Staff Operator"

[logging]
level = "info"

[[hooks]]
stage           = "post_auth_success"
command         = ["/usr/local/sbin/audit-login"]
timeout_seconds = 5
on_failure      = "warn"
run_as          = "audit"
env             = { AUDIT_USER = "${pam_user}", AUDIT_SERIAL = "${cert_serial}" }
```

Rationale:

- `usb_removed_grace_seconds = 30`: the user may pull out the token to
  reinsert something and keep working.
- `mode = "crl"` + `crl_max_age_hours = 24`: the only supported
  revocation source; CRL freshness is controlled by the TTL.
- `[[hooks]]` for auditing: a third-party audit system receives the
  "login" event (data — through `env`, argv is passed literally).

### 3.3 Test environment — `mode = "pkcs12"`, no revocation

```toml
crypto_backend = "openssl"
mode           = "pkcs12"
pkcs12_path_pattern = "certs/${user}.p12"  # relative to the USB mountpoint
pkcs12_pin_prompt   = "PKCS#12 password: "

usb_wait_seconds         = 5
on_usb_removed           = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds    = 0
monitor_fail_mode        = "permissive"

[trust]
anchors = ["/etc/tessera/ca/test-ca.pem"]

[trust.revocation]
mode = "none"

[host_identity]
sources  = ["hostname"]
fallback = "warn"

[[user_mapping]]
pam_user        = "alice"
cert_subject_cn = "Alice"

[logging]
level = "debug"
```

Rationale:

- `mode = "pkcs12"`: to avoid dealing with a real token in tests.
- `monitor_fail_mode = "permissive"`: monitord crashes on dev machines
  more often than in production.
- `level = "debug"`: everything is visible, for debugging.
- `revocation.mode = "none"`: tests must not depend on external services.

> **This configuration must not be used in production.** Marker: the file
> comment reads `# TEST CONFIG — DO NOT DEPLOY`.

## MAC integrity (Astra МКЦ, 0.3.0+)

The `[mac]` section is optional. On a build without the `astra-mac`
feature (Debian, Ubuntu, Astra without strict-mode) the presence of the
section is not forbidden — but `cert_integrity = "required"` is rejected
at config load: the stub backend cannot apply labels and must not
silently pass an authentication that promised to apply them.

### Fields

| Field                             | Type          | Default      | Description                                                                                                |
|-----------------------------------|---------------|--------------|-----------------------------------------------------------------------------------------------------------|
| `cert_integrity`                  | enum          | `"optional"` | One of `required` / `optional` / `ignore`. See below.                                                    |
| `fallback_max_integrity.level`    | int (-128..127) | —          | The fallback label's level, when the `MAX_INTEGRITY` extension is absent and `cert_integrity = "optional"`. |
| `fallback_max_integrity.categories` | string (hex or CSV) | —    | The category bitmask for the fallback. An empty string = `''B`.                                          |
| `runtime`                         | enum          | `"auto"`     | One of `required` / `auto` / `disabled`. See below (0.3.7+).                                             |
| `warn_on_homedir_label_mismatch`  | bool          | `true`       | Log `homedir_label_above_session_cap` on a mismatch.                                                      |

### `cert_integrity` semantics

- **`required`** — the certificate must contain `MAX_INTEGRITY`. If the
  extension is absent or the DER is broken, authentication is rejected
  (`mac_required_no_label` / `mac_parse_failed`).
- **`optional`** — the extension is applied when present. If it is absent:
  - `[mac.fallback_max_integrity]` is present → the fallback is applied;
  - no fallback → the labeling step is skipped (`mac_label_skipped` is
    logged).
- **`ignore`** — the extension is parsed for diagnostics
  (`mac_label_parsed`) but not applied. Safe for migrating a fleet of
  machines without runtime MIC.

### `runtime` semantics (0.3.7+)

The compile-time `astra-mac` feature decides **whether** the binary can
link against libpdp. The `runtime` field decides **whether** the binary
will actually use the real backend in the current process. This matters
for a mixed fleet: the same `.deb` is installed on both MIC and non-MIC
machines, and the behavior is controlled through `config.toml`.

- **`required`** — a `ParsecBackend` + an active MIC kernel
  (`parsec_strict_mode() == 1`) are mandatory. If the kernel is not
  active, authentication is rejected with a `mac_runtime_required` event
  (ERROR). Requires a binary built with `astra-mac` — otherwise the
  config is rejected at startup.
- **`auto`** *(default)* — at session start `parsec_strict_mode` is
  probed; if active — the real `ParsecBackend`, otherwise a fallback to
  `StubBackend` with a one-time `mac_runtime_fallback` event (WARN).
  Suitable for dev machines and a mixed fleet.
- **`disabled`** — always `StubBackend`, even if the binary is built with
  `astra-mac`. Used on terminals without a MIC kernel to guarantee that
  `pdp_*` is never called. A `mac_runtime_disabled` event is logged (INFO).

Config validation:

- `runtime = "disabled"` + `cert_integrity = "required"` is rejected at
  startup (logically incompatible: the stub cannot read or set the label
  that the cert policy requires).
- `runtime = "required"` in a binary without `astra-mac` is rejected at
  startup.

### The effective label

At `open_session` the following is chosen:

```
effective = intersect(cert_label, runtime_caps)
```

where `runtime_caps` is the ceiling that libpdp returns from
`ipdp_get_caps()`. The effective label's level is `min(cert.level,
caps.level)`; the categories are `cert.categories & caps.categories`. If,
after the intersection, `effective.level < cert.level`, a
`mac_level_intersected` event is written; likewise for categories.

### Full example

```toml
[mac]
cert_integrity = "optional"

[mac.fallback_max_integrity]
level = 0
categories = ""
```

See `docs/threat-model.md` §"Privilege-escalation via MAC label" and
`docs/cert-issuance.md` §"MAX_INTEGRITY".

## Further reading

- [docs/install.md](install.md) — step-by-step installation.
- [docs/architecture.md](architecture.md) — the trust model and the IPC
  protocol.
- [docs/threat-model.md](threat-model.md) — every field through the lens
  of threats.
- [docs/operations.md](operations.md) — how to change the config on a
  running machine without dropping sessions.

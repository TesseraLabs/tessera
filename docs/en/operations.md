# Tessera operations runbook

For the on-duty Astra Linux SE administrator maintaining a fleet of
machines with `tessera` installed. This collects what you do on a
shift — grouped by what triggers the operation:

- **regular, on a schedule** — monitoring (§1), the daily CRL refresh
  (§2.2), configuration backup (§4);
- **event-driven** — CA renewal (§2.1), changing a certificate's scope
  (§2.3), rolling out a cloned image (§2.4), rotating `gost-engine`
  after an Astra upgrade (§5);
- **during an incident** — security incidents, a lost token, a daemon
  failure: moved into [troubleshooting.md](troubleshooting.md) (§3).

Where an operation has a deadline or trigger, it is given in the
**When** field. Logs, МКЦ, and the emergency contact are at the end
(§6–§8).

## 1. Monitoring

> The daemon has **no** separate health file — the liveness signals are:
> the systemd state of the unit (`Type=notify` + `sd_notify`), the
> presence of the IPC socket, and journal entries.

### 1.1 The systemd service

```bash
systemctl is-active tessera
```

Expected: `active`. Any other value is an alert. The unit runs in
`Type=notify` mode: systemd itself sees that the daemon is alive and
restarts it per the `Restart=` policy.

### 1.2 The socket

```bash
test -S /run/tessera/monitord.sock && echo OK || echo FAIL
```

### 1.3 The journal

Fresh daemon errors over the polling interval:

```bash
journalctl -u tessera --since '5 min ago' -p err --no-pager -q
```

Empty output is normal; any line is a reason to look manually.

### 1.4 Snippet for a Zabbix UserParameter

`UserParameter=<key>,<command>` — one line per key (Zabbix does not
allow a line break):

```ini
UserParameter=tessera.active,systemctl is-active tessera
UserParameter=tessera.socket,test -S /run/tessera/monitord.sock && echo 1 || echo 0
```

### 1.5 Snippet for the Prometheus textfile collector

`/var/lib/node_exporter/textfile_collector/tessera.prom`:

```
# HELP tessera_up 1 if monitord is active.
# TYPE tessera_up gauge
tessera_up <0|1>
# HELP tessera_socket_present 1 if the IPC socket exists.
# TYPE tessera_socket_present gauge
tessera_socket_present <0|1>
```

Update script (cron every 30 s):

```bash
#!/usr/bin/env bash
set -e
UP=$([[ "$(systemctl is-active tessera)" == "active" ]] && echo 1 || echo 0)
SOCK=$([[ -S /run/tessera/monitord.sock ]] && echo 1 || echo 0)
TMP=$(mktemp)
{
    echo "# HELP tessera_up 1 if monitord is active."
    echo "# TYPE tessera_up gauge"
    echo "tessera_up $UP"
    echo "# HELP tessera_socket_present 1 if the IPC socket exists."
    echo "# TYPE tessera_socket_present gauge"
    echo "tessera_socket_present $SOCK"
} > "$TMP"
mv "$TMP" /var/lib/node_exporter/textfile_collector/tessera.prom
```

## 2. Certificate and CRL operations

### 2.1 Renewing the CA certificate

**When:** 6 months before the current CA expires.

**How:**

1. Generate a new CA in an HSM or a protected segment.
2. Sign the new CA with the old one (cross-sign) for a smooth
   transition.
3. Distribute the new `chain.pem` to every device:
   - onto USB media (Mode A) — update `certs/chain.pem`;
   - into `/etc/tessera/ca/bundle.pem` (via the organization's apt
     repository or ansible/puppet).
4. Reissue the user certificates with the new CA pair, preserving the
   correct `pam_cert_host_binding` and `pam_cert_allowed_roles`
   extensions in them (see [cert-issuance.md](cert-issuance.md)).
5. After the full transition — revoke the old CA via CRL and remove it
   from `[trust].anchors`.

**Verification:**

```bash
openssl x509 -in /etc/tessera/ca/bundle.pem -noout -enddate
```

### 2.2 Refreshing the CRL

**When:** daily, via cron / a systemd timer.

**How:**

systemd timer (`/etc/systemd/system/tessera-crl-update.timer`):

```
[Unit]
Description=tessera daily CRL refresh

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Service (`/etc/systemd/system/tessera-crl-update.service`):

```
[Unit]
Description=tessera CRL refresh

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/tessera-crl-fetch
```

`/usr/local/sbin/tessera-crl-fetch` is a script that downloads the CRL
over a signed HTTP channel or from a CA share and atomically overwrites
`/etc/tessera/crl/*.crl`.

**Verification:**

```bash
ls -la /etc/tessera/crl/
openssl crl -in /etc/tessera/crl/staff.crl -noout -lastupdate -nextupdate
```

### 2.3 Changing a certificate's scope

**When:** when adding/removing a role or a machine from the scope of a
specific certificate.

Because authorization is described in the X.509 extensions themselves
(`pam_cert_host_binding`, `pam_cert_allowed_roles`), there is no separate
configuration to update. The lifecycle goes through the CA:

1. Revoke the current certificate via CRL (the revocation procedure is
   in [troubleshooting.md §8](troubleshooting.md#8-security-incidents)).
2. Reissue the certificate with updated lists in the extensions
   (`openssl.cnf` recipes are in [cert-issuance.md](cert-issuance.md)).
3. Distribute the new certificate to the user's USB/token.
4. Update the CRL on the endpoints (see §2.2).

`monitord` does not need to re-read the config — the changes take effect
at the next `pam_sm_authenticate`.

### 2.4 Rolling out a cloned image

**When:** you have set up one reference workstation, taken an image, and
are rolling it out across the fleet. On each machine the `machine_id` /
DMI / hostname are unique and differ from the reference.

**Full workflow:** [docs/clone-image.md](clone-image.md) — bootstrapping
the reference, `finish-bootstrap.sh` on the clone, per-host certificate
issuance, Ansible rollout, and troubleshooting.

The short outline for the on-duty operator:

1. Reference: `[host_identity].sources = ["override"]` +
   a bootstrap cert with `host_binding = "installation"`.
2. Clone → boot → bootstrap auth works.
3. On each workstation: `sudo /usr/share/tessera/finish-bootstrap.sh`
   (or Ansible with `--non-interactive`). Flip + dump the host_id to
   USB.
4. The CA admin issues a per-host certificate by the `hash_hex` from the
   `active_under_current_config=yes` line (with the CA tool; shipped
   separately, see [clone-image.md §6.1](clone-image.md)).
5. The USB with the new `.p12` comes back to the workstation — bootstrap
   is no longer used, and the per-host chain is in effect.

## 3. Actions during incidents

All incidents and troubleshooting are moved into a single reference —
**[docs/troubleshooting.md](troubleshooting.md)**:

- [§8 Security incidents](troubleshooting.md#8-security-incidents): a compromised cert, a lost token, CA worst-case, DIGSIG
- [§2 USB and tokens](troubleshooting.md#2-usb-and-tokens): USBGuard, ЗПС, a lost/blocked token
- [§3 monitord and the daemon](troubleshooting.md#3-monitord-and-daemon): a failed start, an unreachable socket
- [§4 The PAM stack and lockout](troubleshooting.md#4-pam-stack-and-lockout): replay from rescue.target, `Logout requested but session has no logind id`
## 4. Backing up and restoring the configuration

### 4.1 What to back up

- `/etc/tessera/` (config, ca/, crl/);
- `/var/lib/tessera/` (root-owned policy/enrollment material and persistent daemon state);
- `/etc/pam.d/` (with the `.bak.*` backup copies).

### 4.2 What NOT to back up

- `/run/tessera/` — runtime (the socket, `sessions.json`,
  `daemon.lock`); created by the unit's `RuntimeDirectory=tessera`
  directive on every daemon start.
- `/var/cache/tessera/` — reserved for caches, restored at runtime.

### 4.3 Commands

Backup:

```bash
sudo tar --acls --xattrs -czf /backup/tessera-$(date +%F).tgz \
    /etc/tessera /var/lib/tessera /etc/pam.d
gpg --encrypt --recipient backup@example.test \
    /backup/tessera-$(date +%F).tgz
```

Restore:

```bash
gpg --decrypt /backup/tessera-2026-05-01.tgz.gpg \
    | sudo tar -xzC /
sudo systemctl reload tessera
```

## 5. Rotating `gost-engine` on an Astra upgrade

### 5.1 When

After `apt upgrade`, when the logs indicate an update of the
`gost-engine` or `libgost-engine` package.

### 5.2 What to check

```bash
sudo tessera check
# Primary check: exercises the same engine-load code path a real
# authentication does. Expect [INFO] gost_engine_ok. On
# [ERROR] gost_engine_load_failed, see troubleshooting.md §10.
openssl engine gost -t
# A one-shot check in a separate process — doesn't reproduce the
# ambient-registration race possible in long-lived processes (fly-dm);
# don't rely on it alone. Right after the update it should show
# [ available ].
pamtester sudo alice authenticate
# An authentication smoke test after the update.
```

### 5.3 Rollback

If the update broke compatibility:

```bash
apt install gost-engine=<previous-version>
apt-mark hold gost-engine
sudo systemctl restart tessera
```

## 6. Logs: where to look, what to look for

### 6.1 monitord

```bash
sudo journalctl -u tessera
sudo journalctl -u tessera -g 'tessera.monitord'
```

> The name `tessera.monitord` is kept as an operational ABI: it is used
> by log aggregators and journalctl-filter templates. The binary and
> unit themselves are named `tessera`, but the `tracing target` and the
> Unix-socket path (`/run/tessera/monitord.sock`) remain historical —
> renaming them would break the filters in production.

There are **no** separate targets like `tessera.monitord.start` /
`.removal` / `.lock`: the daemon has a single `tessera.monitord` target
with free-form message text. The outcome and event details live in the
message text and the `key=value` fields, not in the target name. The
daemon's main targets and examples of real messages (verbatim from the
journal):

- `tessera.monitord` — the daemon lifecycle, udev events, the grace
  window, action dispatch:
  - `starting` — the daemon starts;
  - `grace window expired, dispatching action` (field `serial=…`) —
    the grace window after media removal has expired, the action goes
    to the action-runner;
  - `grace cancelled` (`serial=…`) — the media was reinserted within
    the grace window, the action is cancelled;
  - `session target updated` (`session_id=…`, `new_target=…`) —
    `pam_sm_open_session` delivered the real `XDG_SESSION_ID`, and the
    session's registry entry is updated from the placeholder target to
    `LogindSession`.
- `tessera.mount` — mounting and cleanup of stale mountpoints under the
  mountpoint base.
- `tessera.daemon.singleton` — the `daemon.lock` singleton lock.
- `tessera.fly_dm_greeter` — redrawing the wallpaper banner.
- `tessera.startup_check` — startup config validation.
- `role.audit` — role-store events (`role_deny`, `role_session_open`
  with a `reason=…` field); the target has **no** `tessera.` prefix.

**Media removal from a session with no logind id.** In 0.4.0 the action
is not "dropped" (there is no `USB-removal action dropped` line) — it
fails closed by rebooting the host. This is an ERROR line (field
`action=Lock` or `Logout`):

```
ERROR tessera.monitord: ALERT: USB-removal Logout has no logind id; failing closed with reboot session_id=… target=… pam_user=… pam_service=…
```

It is followed by an INFO tip (the text starts with
`tip: pam_sm_open_session pushes XDG_SESSION_ID to monitord`) saying you
need to fix the `pam_systemd.so` / `pam_tessera.so` ordering in the
session phase. The cause analysis and fix are in
[troubleshooting.md §4](troubleshooting.md#4-pam-stack-and-lockout).

### 6.2 cdylib (the PAM module)

```bash
sudo tail -f /var/log/auth.log
sudo journalctl -t pam_tessera
```

> The PAM module writes to syslog (facility `auth`) under the process
> identifier `pam_tessera` — hence the `-t pam_tessera` filter, not
> `-t tessera`. On journald hosts the lines are visible both in
> `journalctl -t pam_tessera` and in `/var/log/auth.log`.

There are **no** separate targets like `tessera.auth.success` /
`.fail.<reason>` or `tessera.cert_scope.*` — the authentication outcome
and the denial reason live in the message text and the fields
(`error=…`, `reason=…`), not in the target name. The module's main
targets:

- `tessera.auth` — the entry and result of `pam_sm_authenticate`:
  - `authentication failed` (WARN, the `error=…` field carries the
    denial category);
  - `host identity unresolved` (ERROR, `error=…`).
- `tessera.flow` — the step-by-step flow trace:
  - `usb devices/partitions enumerated` (`count=…`);
  - `trying USB candidate` (`devnode=…`, `vid=…`, `pid=…`, `fs_type=…`);
  - `candidate mounted` (`devnode=…`, `mountpoint=…`);
  - `no .p12 on this partition, trying next` (`mountpoint=…`, `missing=…`);
  - `cert chain validated`;
  - `auth result: success (pkcs12)` — success of the PKCS#12 path.
- `tessera.session` — `pam_sm_open_session` / `pam_sm_close_session`:
  - `open_session: running session_open hooks` (`session_id=…`, `pam_user=…`);
  - `close_session: running session_close hooks` (`session_id=…`).
- `role.audit` — a role denial/grant: `role_deny` with a `reason=…`
  field (`not_found` / `not_covered` / `backend_unavailable` /
  `mask_exceeds_ceiling` / `syntax` / `system_account`), `role_session_open`.

### 6.3 Useful `grep` filters

```bash
# All failed authentications over a day:
sudo journalctl -t pam_tessera --since="1 day ago" \
    | grep -F 'authentication failed'

# All role denials (the role-store registry):
sudo journalctl -t pam_tessera | grep -F 'role_deny'

# USB-removal events that triggered an action:
sudo journalctl -u tessera | grep -F 'grace window expired, dispatching action'

# Fail-closed reboots due to a missing logind id:
sudo journalctl -u tessera | grep -F 'failing closed with reboot'

# The step-by-step partition-probing trace on multi-partition media:
sudo journalctl -t pam_tessera \
    | grep -E 'trying USB candidate|candidate mounted|no \.p12 on this partition'

# A specific user's sessions/denials (the role audit):
sudo journalctl -t pam_tessera | grep -E 'role_(deny|session_open)' | grep alice
```

### 6.4 What is not logged (by policy)

- PINs and passphrases — `<redacted>`.
- Full certificate DNs at the `info` level — only the CN is shown. At
  the `debug` level — the full DN.
- The full contents of the `pam_cert_host_binding` /
  `pam_cert_allowed_roles` X.509 extensions — at the `info` level only
  the matched entry is logged; the full list — at the `debug` level.

## 7. МКЦ (MAC integrity)

Activating mandatory integrity control is an optional step, performed by
the operator manually after the package is installed. By default the
`tessera.service` daemon runs as `tessera` without
`CAP_MAC_ADMIN`/`PARSEC_CAP_CHMAC`. Activation is three operator steps:

1. install the drop-in
   `/usr/share/tessera/systemd/mac-integrity.conf.example` into
   `/etc/systemd/system/tessera.service.d/`;
2. install the paired PAM stack
   `/usr/share/tessera/pam.d/tessera.example` into `/etc/pam.d/tessera`
   (it uses `pam_parsec_cap.so` + `pam_parsec_mac.so`);
3. grant the daemon `PARSEC_CAP_CHMAC` via `usercaps -m "+3" tessera`
   plus `pdpl-user --ilevel 63 tessera`.

The full activation, verification, and rollback procedure is described in
[docs/install.md §"МКЦ (MAC integrity): optional activation"](install.md#мкц-mac-integrity-optional-activation).

**Session state.** The `sessions.json` registry lives on tmpfs
(`/run/tessera/sessions.json`, `RuntimeDirectory=`). It is volatile
across reboot — this is by design: the sshd/login/sudo processes holding
these sessions die on reboot anyway. The singleton lock `daemon.lock`
lives next to `sessions.json` (fallback —
`/var/lib/tessera/daemon/`); the daemon's persistent state is the
wallpaper backup in `/var/lib/tessera/daemon/`. The parent
`/var/lib/tessera/` remains root-owned because it also contains trusted
roles, tags, and enrollment material.

## 8. Emergency contact

For confidential security reports — see the contacts in
[README.md](../../README.md#maintainer-contact).

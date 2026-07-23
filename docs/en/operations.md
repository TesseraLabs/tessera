# Tessera operations runbook

This document is an operational runbook for an Astra Linux SE
administrator maintaining a fleet of machines with `tessera` installed.
Each incident is described as "symptom → diagnosis → action →
verification".

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

```ini
UserParameter=tessera.active,
    systemctl is-active tessera
UserParameter=tessera.socket,
    test -S /run/tessera/monitord.sock && echo 1 || echo 0
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

## 2. Routine operations

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
   correct `pam_cert_host_binding` and `pam_cert_user_binding`
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

**When:** when adding/removing a user or a machine from the scope of a
specific certificate.

Because authorization is described in the X.509 extensions themselves
(`pam_cert_host_binding`, `pam_cert_user_binding`), there is no separate
configuration to update. The lifecycle goes through the CA:

1. Revoke the current certificate via CRL (see §3.1).
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
  `daemon.lock`); restored by systemd-tmpfiles at boot.
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
openssl engine gost -t
# Right after the update it should show [ available ].
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

Useful tags:

- `tessera.monitord.start` — startup.
- `tessera.monitord.removal` — udev REMOVE events.
- `tessera.monitord.reinsert` — cancellation within the grace window.
- `tessera.monitord.lock` — sending `LockSession` to logind.
- `tessera.monitord.reload` — a config reload.
- `USB-removal action dropped` (WARN, 0.3.10+) — the action was not
  sent because the session has no logind id. See §3.6.1.
- `pushed logind session target to monitord` (INFO, `tessera.session`,
  0.3.10+) — `pam_sm_open_session` successfully proxied `XDG_SESSION_ID`
  to monitord; normal for a logind session.

### 6.2 cdylib (the PAM module)

```bash
sudo tail -f /var/log/auth.log
sudo journalctl -t tessera
```

Useful tags:

- `tessera.auth.start` — the start of `pam_sm_authenticate`.
- `tessera.auth.success` — success.
- `tessera.auth.fail.<reason>` — a denial; `<reason>` is the category.
- `tessera.cert_scope.host_mismatch` — `host_id_hash` is not in
  `pam_cert_host_binding`.
- `tessera.cert_scope.user_mismatch` — `pam_user` is not in
  `pam_cert_user_binding`.
- `tessera.session.open` — a session opened.
- `tessera.session.close` — a session closed.

### 6.3 Useful `grep` filters

```bash
# All denials over a day:
sudo journalctl -t tessera --since="1 day ago" | grep -F 'auth.fail'

# All USB-removal events:
sudo journalctl -u tessera | grep -F 'monitord.removal'

# All cert-scope mismatches (host/user binding):
sudo journalctl -t tessera | grep -E 'cert_scope\.(host|user)_mismatch'

# A specific user's sessions:
sudo journalctl -t tessera | grep -E 'pam_user[=:]"alice"'
```

### 6.4 What is not logged (by policy)

- PINs and passphrases — `<redacted>`.
- Full certificate DNs at the `info` level — only the CN is shown. At
  the `debug` level — the full DN.
- The full contents of the `pam_cert_host_binding` /
  `pam_cert_user_binding` X.509 extensions — at the `info` level only
  the matched entry is logged; the full list — at the `debug` level.

## 7. МКЦ (MAC integrity)

Activation of mandatory integrity control (МКЦ) is an optional step,
performed by the operator manually after the package is installed. The
`tessera.service` daemon runs as `tessera` without
`CAP_MAC_ADMIN`/`PARSEC_CAP_CHMAC` until the operator installs the
shipped drop-in `/usr/share/tessera/systemd/mac-integrity.conf.example`
into `/etc/systemd/system/tessera.service.d/`, the paired PAM stack
`/usr/share/tessera/pam.d/tessera.example` into `/etc/pam.d/tessera`
(which uses `pam_parsec_cap.so` + `pam_parsec_mac.so`), and grants
`PARSEC_CAP_CHMAC` via `usercaps -m "+3" tessera` plus
`pdpl-user --ilevel 63 tessera`. The full activation, verification, and
rollback procedure is described in
[docs/install.md §"MIC (MAC integrity): optional activation"](install.md#mic-mac-integrity-optional-activation).

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

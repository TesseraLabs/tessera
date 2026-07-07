# Troubleshooting `tessera`

A single diagnostics reference. Sections:

- [§1 Cert/auth errors](#1-certauth-errors)
- [§2 USB and tokens](#2-usb-and-tokens)
- [§3 monitord and daemon](#3-monitord-and-daemon)
- [§4 PAM stack and lockout](#4-pam-stack-and-lockout)
- [§5 Mandatory integrity control (МКЦ)](#5-mandatory-integrity-control-мкц-astra-strict-mode)
- [§6 fly-dm and greeter](#6-fly-dm-and-greeter)
- [§7 Clone-image / golden image](#7-clone-image--golden-image)
- [§8 Security incidents](#8-security-incidents)
- [§9 Backup / recovery](#9-backup--recovery)
- [§10 Installation / `gost-engine`](#10-installation--gost-engine)

For each case: symptom → diagnosis → fix. The logging commands are
universal:

```bash
sudo journalctl -u tessera --since '5 min ago'
sudo journalctl -t tessera | tail -50
sudo tail -f /var/log/auth.log
```

---

## 1. Cert/auth errors

### `host_binding mismatch`

**Symptom:** PAM denies with `HostNotAllowed` or
`HostExtensionMissing`. Since 0.3.6, on the banner (TTY/sshd/sudo):

```
Сертификат выпущен для другого устройства.
host_id этой машины: <8-hex-префикс> (source=DmiBoardSerial)
Передайте администратору для перевыпуска.
```

_(English: "This certificate was issued for a different device. host_id
of this machine: &lt;8-hex-prefix&gt; (source=DmiBoardSerial). Hand it to
your administrator for re-issuance.")_

(The full `host_id_hash` is in syslog; the screen shows the 8-character
prefix.)

**Diagnosis:**

```bash
# What each configured host_identity source returned
sudo journalctl -t tessera | grep 'host_identity: probe' | tail -20
# probe ok      source=MachineId raw=abc... host_id_hash_prefix=a1b2c3d4 host_id_hash=<full sha256 hex>
# probe error   source=DmiBoardSerial error="ENOENT"
# probe selected source=MachineId (first successful) host_id_hash_prefix=a1b2c3d4

# What is baked into the certificate
openssl x509 -in /etc/tessera/<host>.pem -noout -text \
    | grep -A1 '2\.25\.183976554325829274683049824615098'
```

**Fix:** re-issue the cert with the CA tool using the correct
`host_id_hash`. Do **NOT** compute the hash by hand with
`sha256sum /etc/machine-id` — the source of truth is determined by the
deployed `[host_identity].sources`. See
[architecture.md](architecture.md#12-host-identity-chain).

### `user_binding mismatch`

**Symptom:** the cert chain is valid, but a specific user is rejected
with `UserNotAllowed` / `UserExtensionMissing`.

**Diagnosis:**

```bash
openssl x509 -in /tmp/ca/alice.pem -noout -text \
    | grep -A1 '2\.25\.215438916728501023845629178354627'
```

**Fix:** re-issue the cert with the correct `pam_cert_user_binding`.

### `Authentication failed (PAM_AUTH_ERR)` immediately

**Symptom:** `pamtester` denies immediately, with no delay.

**Diagnosis:**

```bash
sudo tail -f /var/log/auth.log &
pamtester sudo alice authenticate
```

Look for `tessera.auth.fail.<reason>` in the log. The list of reasons is
in [architecture.md](architecture.md#13-fail-closed-rules).

### Certificate not accepted on the terminal (general checklist)

Since 0.3.6, PAM prints a `PAM_TEXT_INFO` on screen with diagnostics for
a `host_binding` mismatch and a wrong PIN. Check the screen **and**
syslog:

```bash
# The real host_id_hash of this machine
sudo journalctl -t tessera | grep 'host_id resolved' | tail -1

# Step-by-step trace (mount → discovery → envelope → chain → result)
sudo journalctl -t tessera --since '5 min ago' \
    | grep -E 'tessera\.(flow|host_identity)'
```

Cross-check against the issuance registry (`host-registry.tsv` on the
admin machine):

- `host_id_hash` in the log ≠ the value in the cert → the cert was
  issued for a different workstation. Re-issue it.
- No `host_id resolved` in the log → the resolver did not run. Check
  `[host_identity].sources` in `config.toml`.
- `PAM_TEXT_INFO` «Пароль .p12 неверный. Этот сертификат выпущен
  для host_id_hash=…, пользователь=…» (_English: "The .p12 password is
  wrong. This certificate was issued for host_id_hash=…, user=…"_) → the
  engineer inserted another engineer's USB stick. If the cert is encoded
  in the legacy format, the message is the shorter «Пароль .p12
  неверный»; read it on the admin machine:

```bash
openssl pkcs12 -in service.p12 -nokeys -nomacver -passin pass: \
    | openssl x509 -noout -text
```

### `[trust.revocation] mode = "ocsp"` — config won't load

**Symptom:** the daemon/module fails to load its config with
`mode = "ocsp"` / `mode = "crl_then_ocsp"`.

**Cause:** OCSP modes require `ocsp_responder_url` — without it, config
validation rejects the section (fail-closed). Also check the
`ocsp_timeout_seconds` / `ocsp_cache_ttl_seconds` ranges.

**Fix:** set `ocsp_responder_url`; for zero-egress environments
(terminals with no network path to the responder) OCSP is not suitable —
use `mode = "crl"` with a regularly refreshed local CRL and freshness
control via `crl_max_age_hours`, or `mode = "none"` with a short-TTL
discipline. See
[configuration.md](configuration.md#the-trustrevocation-section).

---

## 2. USB and tokens

### `usb_wait_seconds` window expired

**Symptom:** `pamtester` waits ~10 s, then `usb medium not found`.

**Fix:** check with `lsblk` that the USB is mounted and visible. For a
larger window, increase `usb_wait_seconds` in `config.toml` (see
[configuration.md](configuration.md#general-parameters)).

### `pcscd not running`

**Symptom:** the PKCS#11 token (Rutoken) is not visible in
`pkcs11-tool -L`.

```bash
sudo systemctl enable --now pcscd
sudo systemctl status pcscd
pcsc_scan          # should show the inserted token
```

### `Token PIN locked`

**Symptom:** `pkcs11-tool` returns `CKR_PIN_LOCKED`.

**Fix:** unlock with the SO-PIN, re-initialize the user PIN via
`pkcs11-tool --init-pin`.

### 14-second silence after `trying USB candidate`

**Symptom** (0.3.5 and earlier): 10–30 s with no logs between
`trying USB candidate devnode=/dev/sdb1` and the module finishing. On a
Ventoy / multi-partition USB.

**Cause:** 0.3.5 has no per-candidate logging — the module iterated over
partitions with no output. Duration = number of partitions × timeout.

**Fix:** upgrade to 0.3.6+ — step-by-step INFO logging was added:

```
INFO tessera.flow: candidate mounted devnode="/dev/sdb1"
INFO tessera.flow: p12 not found at <path>, skipping candidate
INFO tessera.flow: trying USB candidate devnode="/dev/sdb2"
```

### USB token blocked by USBGuard or the closed software environment (ЗПС)

ЗПС — closed software environment, Astra's signed-executables
enforcement.

**Symptom:** auth fails with `AUTHINFO_UNAVAIL` right after insertion:

```
tessera: WARN  tessera.flow: usb device found ...
tessera: WARN  tessera.auth: authentication failed
              error=mount: mount(2) failed: Operation not permitted
```

**Diagnosis:**

```bash
# USBGuard
sudo usbguard list-devices              # "block" column → the token is blocked
sudo usbguard list-rules
journalctl -u usbguard.service -n 30 --no-pager

# ЗПС
sudo astra-digsig-control status        # "ВКЛЮЧЕНО"/"НЕАКТИВНО" (ENABLED / INACTIVE)
sudo dmesg | grep -i digsig | tail
```

**Fix — USBGuard:**

```bash
sudo usbguard append-rule \
    'allow id 0aca:1234 name "Rutoken ECP" hash "ABC..."'
# or add the rule to /etc/usbguard/rules.conf:
sudo systemctl restart usbguard
```

To keep the daemon from starting before USBGuard:

```bash
sudo mkdir -p /etc/systemd/system/tessera.service.d
sudo tee /etc/systemd/system/tessera.service.d/usbguard.conf <<EOF
[Unit]
After=usbguard.service
Wants=usbguard.service
EOF
sudo systemctl daemon-reload
```

**Fix — ЗПС:** see §10 below.

### USB token lost / blocked — the user can't log in

**By design.** `tessera` is a hard second factor: without a valid token
carrying the right extensions, the user **will not pass** the PAM stack
the module is integrated into. There is no alternative auth path.

**BEFORE the first rollout, the admin must:**

1. Keep a local root shell with `tessera` disabled, or a sudoers rule
   for the admin that skips the second factor — otherwise losing the
   single token takes the machine out of service.
2. Prepare **backup** certificates: two physical USB sticks per
   privileged user, both signed by the CA, both with the same
   `pam_cert_user_binding`.
3. Document the SLA for re-issuing a lost cert.

**What happens if the token is lost:**

- Every auth attempt → `PAM_AUTHINFO_UNAVAIL` after `usb_wait_seconds`.
- `monitord` runs but registers no active sessions —
  `on_usb_removed` won't fire.

**When blocked by USBGuard / ЗПС:** the same, plus error lines in
`auth.log`. Keep an admin channel (SSH key-only auth without the
`tessera` chain) until the deployment is validated.

---

## 3. monitord and daemon

### `monitord not reachable`

**Symptom:** PAM denies with `monitord unavailable` or hangs.

```bash
sudo systemctl status tessera
sudo journalctl -xeu tessera -n 200
sudo ls -la /run/tessera/
```

**Typical causes:**

- the `/run/tessera/monitord.sock` socket wasn't created → check
  `RuntimeDirectory=tessera` in the unit;
- permissions on `/run/tessera/` are wrong → should be
  `drwxr-x--- root root` (0750);
- `config.toml` is corrupted → run it manually:
  `sudo /usr/bin/tessera` and read the diagnostic output.

### monitord won't start

**Symptom:** `systemctl status tessera` shows `failed`.

```bash
sudo journalctl -xeu tessera -n 200
```

**Typical causes:**

- socket in use: `lsof /run/tessera/monitord.sock`;
- wrong permissions on `/run/tessera/`: `ls -la`, should be `0750 root:root`;
- corrupted `config.toml`: run manually `sudo /usr/bin/tessera`;
- missing `gost-engine`: `openssl engine gost -t`.

---

## 4. PAM stack and lockout

### Lockout after a failed PAM edit

**Symptom:** no user can log in, not even the root shell.

**Recovery:**

1. Reboot into single-user mode: on GRUB, append
   `systemd.unit=rescue.target init=/bin/bash` to the kernel line.
2. Remount `/` read-write: `mount -o remount,rw /`.
3. Roll back `/etc/pam.d/*` from the `*.bak.<TS>` backups:
   ```bash
   ls /etc/pam.d/*.bak.* | tail
   cp /etc/pam.d/sudo.bak.20260501T103000Z /etc/pam.d/sudo
   ```
4. `systemctl reboot`.

### `tessera` in `/etc/pam.d/login` is not found

**Symptom:** after editing, login denies with `Module is unknown` or
won't start.

```bash
ls -la /lib/security/pam_tessera.so
test -f /lib/security/pam_tessera.so && echo "module installed"
sudo ldd /lib/security/pam_tessera.so | grep -i 'not found'
```

- `not found` → a missing dependency (`libparsec-mic.so.3` on older
  builds). Upgrade to 0.3.7+ — it has
  `cargo:rustc-link-lib=parsec-mic` in `build.rs`.
- File missing → `dpkg -l tessera`. Possibly an interrupted install →
  `sudo dpkg --configure -a`.

### `Logout requested but session has no logind id`

**Symptom** (0.3.10+): USB removal is detected correctly in journald
(`grace window expired, dispatching action`), but logout doesn't
happen:

```
ERROR tessera.monitord: ALERT: USB-removal Logout has no logind id; failing closed with reboot ...
```

**Cause:** at `pam_sm_open_session` time, `XDG_SESSION_ID` was not in the
PAM environment — the monitord entry was left with a placeholder target
(`Tty` / `Display` / `Unknown`) captured during the auth phase. The
action-runner can't call `terminate_session` without a logind id.

**Action-runner fail-closed (0.4.0):**

| Configuration             | Without a logind id                                   |
|---------------------------|-------------------------------------------------------|
| `action = "lock"`         | Fail-closed: **reboot** the device (ALERT in the log) |
| `action = "logout"`       | Fail-closed: **reboot** the device (ALERT in the log) |
| `action = "shutdown"`     | Fires — `power_off` doesn't need logind               |
| `action = "hook"`         | Fires — the hook receives the SESSION_ID env          |

A session with no logind id can't be terminated by address, so instead
of silently dropping it, the action degrades to a reboot — the media is
removed, and an open session is unacceptable.

**Cause 1 (typical, 0.3.11 and earlier — pre-fix):** `@include tessera*`
pulled in `session required pam_tessera.so` inside the snippet, and the
snippet ended up above `@include common-session` (which has
`pam_systemd.so`). `sm_open_session` fired before `pam_systemd`. In
0.3.12 the session phase was moved out of the snippets into a separate
line that `integrate-pam.sh` places AFTER `@include common-session`. The
0.3.12+ daemon fails at startup with `ERROR pam_stack_session_misorder`
if the order is wrong.

Check:

```bash
sudo tessera check 2>&1 | grep pam_stack_session
# OR:
sudo grep -nE 'session.*(pam_systemd|tessera)|@include[[:space:]]+(common-session|tessera)' \
    /etc/pam.d/login /etc/pam.d/fly-dm
```

Fix — re-integrate with the 0.3.12+ script:

```bash
sudo /usr/share/tessera/integrate-pam.sh --unintegrate /etc/pam.d/login
sudo /usr/share/tessera/integrate-pam.sh --mode=<your-mode> /etc/pam.d/login
sudo systemctl restart tessera
```

**Cause 2:** `pam_systemd.so` is missing from the service's `session`
phase. The startup check emits INFO `pam_stack_session_no_systemd`. Fix —
restore the stock template with `dpkg-reconfigure libpam-runtime`, then
run `integrate-pam.sh`.

**Cause 3:** a console session without systemd (sysvinit, OpenRC).
`pam_systemd` isn't loaded, and `XDG_SESSION_ID` is physically never
created. Until a TTY-based logout fallback is implemented:

- `[on_usb_removed].action = "shutdown"` (blunt, but works);
- or `"hook"` with a script — `pkill -KILL -u <pam_user>` / `chvt 1`;
- or enable systemd on the host.

**Verify the fix:**

```bash
sudo journalctl -u tessera -f &
# log in, wait for:
#   INFO tessera.session: pushed logind session target to monitord
#   target=LogindSession { id: "..." }
# remove the USB:
#   INFO tessera.monitord: grace window expired, dispatching action
```

---

## 5. Mandatory integrity control (МКЦ, Astra strict-mode)

Mandatory integrity control (МКЦ) is a Biba-family integrity control on
Astra; below it is referred to as MIC.

### `pam_parsec_mac(login:account): Can't obtain required data`

**Symptom:** `tessera` ran successfully, but a few seconds later
`pam_parsec_mac` fails login in the `account` phase:

```
pam_parsec_mac(login:account): Can't obtain required data.
Did you forget add pam_parsec_mac to "auth" stack?
```

`pam_parsec_mac.so` stores PAM data across phases: the auth instance
writes, account/session read. This appears when the auth instance **did
not run**, even though it is formally present in the file.

**Cause 1 (most common, integrate-pam.sh < 0.3.8):** our
`@include tessera-only` ended up BEFORE `auth required
pam_parsec_mac.so`. `tessera-only` uses
`auth [success=done default=die] pam_tessera.so` — `success=done`
short-circuits the auth stack on success, so pam_parsec_mac never gets
to store its data in auth.

Check:

```bash
sudo grep -n -E 'tessera|parsec_mac' /etc/pam.d/login /etc/pam.d/fly-dm
```

If the line number of `@include tessera*` is **lower** than that of
`auth ... pam_parsec_mac.so`, that's it.

Fix:

```bash
# integrate-pam.sh >= 0.3.8 orders it correctly on its own
sudo /usr/share/tessera/integrate-pam.sh --unintegrate /etc/pam.d/login
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/login
# repeat for fly-dm
```

**Cause 2:** the MIC kernel is off (`parsec.mac=0` in GRUB), but
`pam_parsec_mac.so` is in `/etc/pam.d/login`. The module has no MAC data —
account fails. See the next case.

**Cause 3:** the MIC kernel is on, but `service` has no MAC level.

```bash
sudo /sbin/pdpl-user service
sudo ls /etc/parsec/macdb/$(id -u service)
```

If `pdpl-user` shows only `0:0:0x0:0x0` with no entry under
`/etc/parsec/macdb/<uid>`:

```bash
sudo /sbin/pdpl-user --ilevel 63 service
sudo systemctl restart fly-dm
```

### `parsec.mac=0` + `pam_parsec_mac` in the stack

**Symptom:** the MIC kernel is disabled via GRUB (`parsec.mac=0`), but
`/etc/pam.d/login` contains `pam_parsec_mac.so` in auth/account/session.
The module waits for MAC data that doesn't exist — login denied.

```bash
cat /proc/cmdline | tr ' ' '\n' | grep parsec
cat /sys/module/parsec/parameters/strict_mode    # N = off
sudo astra-strictmode-control status             # НЕАКТИВНО
```

**(A) You need MIC** — enable the kernel:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="... parsec.mac=1 parsec.max_ilev=63 ..."
sudo update-grub
sudo reboot
sudo /sbin/pdpl-user --ilevel 63 service
```

**(B) You don't need MIC** — remove `pam_parsec_mac.so`, set
`runtime = "disabled"`:

```toml
[mac]
runtime        = "disabled"
cert_integrity = "ignore"
```

```bash
for f in /etc/pam.d/login /etc/pam.d/fly-dm; do
    sudo sed -i.bak 's|^\(\s*\(auth\|account\|session\).*pam_parsec_mac\.so\)|# disabled МКЦ off: \1|' "$f"
done
sudo systemctl restart tessera fly-dm
```

See [install.md §8.5](install.md) — the matrix of PAM stacks with/without
MIC.

### `unknown field 'enabled', expected one of ... 'runtime'`

**Symptom:** the daemon won't start, TOML parse error:

```
failed to load monitord config from /etc/tessera/config.toml:
unknown field `enabled`, expected one of `cert_integrity`,
`fallback_max_integrity`, `warn_on_homedir_label_mismatch`, `runtime`
```

**Cause:** the legacy `[mac].enabled = true` field from 0.3.0–0.3.6.
Removed in 0.3.7, replaced by `[mac].runtime`.

```toml
# was
[mac]
enabled        = true
cert_integrity = "optional"

# now (for the MIC kernel ON)
[mac]
runtime        = "required"     # or "auto"
cert_integrity = "optional"

# or (for the MIC kernel OFF)
[mac]
runtime        = "disabled"
cert_integrity = "ignore"
```

### WARN `mac_caps_missing` / `pdp_set_fd rc=-1`

**Symptom:** at daemon startup:

```
WARN mac.audit: F_event="mac_caps_missing" F_detail="PARSEC_CAP_CHMAC not present in effective set"
WARN mac.audit: F_event="mac_sessions_file_label_warning" F_error="parsec error: op=pdp_set_fd rc=-1"
```

**Non-blocking.** The daemon starts and runs. It means the MIC label
could not be set on `sessions.json`. It doesn't affect the auth flow.

To clear it (optional):

```bash
sudo /sbin/usercaps -m "+3" tessera
sudo cp /usr/share/tessera/systemd/mac-integrity.conf.example \
    /etc/systemd/system/tessera.service.d/mac-integrity.conf
sudo systemctl daemon-reload
sudo systemctl restart tessera
```

### `dmi_board_serial = 0` (VM), hash changes when the VM is rebuilt

**Symptom:** on VirtualBox/QEMU, `/sys/class/dmi/id/board_serial` is
empty or `0`. The resolver falls back to `machine_id`, but when the VM is
rebuilt the `machine-id` can change too → the cert with its embedded hash
stops validating.

```bash
cat /sys/class/dmi/id/board_serial   # 0 or empty = unusable
sudo journalctl -t tessera | grep 'host_identity:' | tail -10
```

For dev/test:

```toml
[host_identity]
sources  = ["override"]
fallback = "deny"
override = "test-vm-stable-id"
```

In production on physical workstations, `dmi_board_serial` is usually
valid.

---

## 6. fly-dm and greeter

### fly-dm doesn't show host_id on the login screen

**Symptom:** at login, fly-dm shows no `host_id` — neither via
`PAM_TEXT_INFO` nor via the stock «Добро пожаловать в %n» (_English:
"Welcome to %n"_).

**Cause:** on Astra with MIC-3, the fly-modern theme
(`libfly-dm_greet_modern.so`) hardcodes «Усиленный уровень
защищенности» (_"Hardened security level"_) into the headline.
GreetString and PAM messages are ignored.

**Fix — wallpaper banner (0.3.19+):**

```toml
# /etc/tessera/config.toml
[fly_dm_greeter]
update_wallpaper = true
```

If heavy dimming / blur on the host hides the text:

```ini
# /etc/X11/fly-dm/fly-modern/settings.ini
[background]
color_overlay=0,0,0,30

[background][blur]
enable=false
```

```bash
sudo systemctl restart tessera     # redraws the banner
sudo systemctl restart fly-dm           # picks up the new JPG
```

Full set of options, baseline, and implementation —
[fly-dm-greeter.md](fly-dm-greeter.md).

**Cargo-cult approaches (removed in 0.3.19):**

- `greeter-show-messages = true` in `/etc/X11/fly-dm/fly-dmrc` — a legacy
  KDM/LightDM key that fly-qdm 2.15+ doesn't parse.
- `/etc/X11/fly-dm/override/GreetString.desktop` — on MIC-3, fly-modern
  ignores GreetString, the headline is taken by the MIC status.

### Wallpaper isn't updating

- The daemon lacks permission on `wallpaper_target`: `ls -l` the source.
  The daemon runs as root, so 0644 is enough.
- Any error (including a missing font): WARN `fly-dm wallpaper
  update failed (continuing)` with an `error` field (target
  `tessera.fly_dm_greeter`). For the font, install
  `fonts-dejavu-core`.
- Text not visible: `color_overlay` is too dense, blur is on —
  see the fix above.

---

## 7. Clone-image / golden image

### `dump-host-id`: all sources empty

**Symptom:** the TSV contains only `status=err`, exit ≠ 0.

**Causes:**

- **`dmi_board_serial = 0`** — typical for VMs (KVM/VMware without a
  SMBIOS override). Fix: SMBIOS strings in the hypervisor, or
  `--sources machine_id`.
- **`machine_id` empty** — cleared before cloning, and systemd didn't
  generate one on first boot. Fix:
  `systemd-machine-id-setup && systemctl restart tessera`.
- **`custom_command` exit ≠ 0** — the script's path/permissions, see
  `reason` in the TSV.

### USB doesn't show up during `--usb`

`finish-bootstrap.sh` / `dump-host-id --usb` retries for up to 60 s
(polling every 5 s). If the stick isn't detected:

- run `lsblk` in parallel;
- an FS from the allowlist (`vfat`/`exfat`/`ext4`/`ntfs`);
- use the fallback under `/var/lib/tessera/`.

### `active_under_current_config=no` for every row

Happens when `--sources` names non-existent sources (a typo).
`tessera check` usually catches it, but if it slipped through, check
`[host_identity].sources` in `config.toml`.

### Bootstrap cert rejected on the clone

- The trust anchor didn't make it into the image: `tessera check` will
  show `trust_anchor_missing`.
- `host_binding` in the cert doesn't equal the `override` string —
  rebuild the bootstrap cert with `--mode bootstrap`.
- `[host_identity].override` ≠ `host_binding` in the cert — usually
  `installation` on both sides, sync them.

### Repeated flip after a motherboard swap

`dmi_board_serial` changed → `host_id_hash` is different → the per-host
cert is no longer valid.

1. Restore the bootstrap state: `config.toml` →
   `sources = ["override"]`, `override = "installation"`.
2. Put the bootstrap cert on the USB.
3. Run `finish-bootstrap.sh` again — a new TSV dump with the new
   `host_id_hash`.
4. Issue a new per-host cert (see [clone-image.md §6](clone-image.md)).

`finish-bootstrap.sh` does not do steps 1–2 automatically —
deliberately (it requires an operator decision + a physical stick).

---

## 8. Security incidents

### Compromise of a user certificate

**Symptom:** a report from the user / SOC.

1. Add the serial to the CA's CRL.
2. Re-issue and publish the CRL.
3. Update the CRL on the endpoints (see [operations.md §2.2](operations.md);
   the expedited procedure is `systemctl start tessera-crl-update.service`).
4. Check the log:
   ```bash
   sudo journalctl -u tessera -g 'revoked' -n 100
   ```
5. Notify the user; arrange issuance of a new certificate.

### Lost token

1. Revoke the serial (see above).
2. Wait for CRL propagation.
3. Issue a replacement token with a new certificate, setting
   `pam_cert_host_binding` and `pam_cert_user_binding` correctly
   (see [cert-issuance.md](cert-issuance.md)).

### Loss of the CA private key (worst case)

1. **Immediately** stop all new issuance.
2. Declare a Critical incident; engage the security team.
3. Disaster recovery — a separate sub-runbook
   `docs/operations-disaster-recovery.md` (created by the organization;
   10–20 pages).
4. Prepare a new CA from a cold-storage backup, or re-issue from
   scratch.
5. A coordinated update of all endpoints.
6. Publish the incident via `security@...` and in the `Security` section
   of [changelog.md](../ru/changelog.md) (Russian).

### DIGSIG `enforce` with no signature on `pam_tessera.so`

**Symptom:** `PAM unable to dlopen(pam_tessera.so)` or
`DIGSIG: blocked unsigned ELF` in `dmesg`. On a production Astra with
`astra-digsig-control` on in enforce mode.

```bash
sudo astra-digsig-control status   # ВКЛЮЧЕНО = enforce
sudo dmesg | grep -i digsig | grep tessera
```

**Two options:**

1. Sign the `.deb` through the Astra partner CI/CD (`bsign` with a key
   from `/etc/digsig/keys/`). The standard pipeline for production.
2. Temporarily switch to logging-only:
   ```bash
   sudo astra-digsig-control logging
   ```
   **Not for production** — syslog will fill up with
   `DIGSIG: NOT_ELF_SIGNED`.

See [threat-model.md §3.7](threat-model.md).

---

## 9. Backup / recovery

See [operations.md §4](operations.md) — what to back up, what not to back
up, and the commands.

---

## 10. Installation / `gost-engine`

### `gost-engine not loaded`

**Symptom:** `openssl engine gost -t` prints `engine "gost" not found`,
or `dynamic` without `[ available ]`.

```bash
sudo apt install --reinstall gost-engine
sudo systemctl restart pcscd
openssl engine gost -t
```

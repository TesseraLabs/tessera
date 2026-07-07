# Integrating `tessera` into `/etc/pam.d/*`

A guide to editing PAM stacks on Astra/Debian/Ubuntu. This document is
split out of install.md §8 + §11 — here is everything about
`integrate-pam.sh`, the two-include pattern, the modes, the specifics of
fly-dm/sudo/login/sshd, and SysV init.

> **IMPORTANT.** Before editing the PAM stack, **open a second root
> shell** (for example, `ssh root@<host>`). If the main shell cannot
> authenticate after the changes, the second terminal will be the only
> way to roll them back.

## 1. The shipped snippet and `integrate-pam.sh`

`tessera` ships an includable snippet, `/etc/pam.d/tessera`
(see [`dist/pam.d/tessera`](../../dist/pam.d/tessera)). Include it with
the line `@include tessera`.

The shipped script `/usr/share/tessera/integrate-pam.sh` automatically
inserts `@include tessera` at the correct position and saves a backup
copy `<file>.bak.<UTC-timestamp>`.

### Insertion point

- **If the file has an `auth ... pam_parsec_mac.so` line** (typical for
  Astra SE `/etc/pam.d/login`, `/etc/pam.d/fly-dm`), the `@include` goes
  **after** that line. Otherwise the `tessera-only` snippet with
  `success=done` would cut the auth stack off before `pam_parsec_mac`
  runs, and its account/session instances would fail with
  `"Can't obtain required data"` → login deny.
- **Otherwise** the `@include` goes before the first `auth` line (the
  legacy behaviour for systems without a mandatory integrity control
  (МКЦ) stack, i.e. Ubuntu/Debian).

## 2. The two-include pattern (0.3.12+)

Since 0.3.12 `integrate-pam.sh` wires the module in with **two** lines:

1. `@include tessera*` (the auth + account phases) — lands at the top of
   the file after `auth ... pam_parsec_mac.so` (or before the first
   `auth` line if МКЦ is off);
2. `session    required   pam_tessera.so` — placed **after**
   `@include common-session` (or after the last `session` line if there
   is no common-session).

### Why

Our module's `pam_sm_open_session` reads `XDG_SESSION_ID` from the PAM
environment and pushes it to monitord, so that the USB-removal action
(`Lock` / `Logout`) can address the user's logind session.
`XDG_SESSION_ID` is created by `pam_systemd.so` (usually via
`@include common-session`) — so our `session` line **must** come after
it.

### Migrating from 0.3.11 to 0.3.12

The shipped snippets (`tessera`, `tessera-only`, `tessera-optional`)
contain only `auth`+`account` since 0.3.12 — `session` lives on a
separate line in the host pam.d file. After upgrading from 0.3.11,
operators need to run this **once**:

```bash
sudo /usr/share/tessera/integrate-pam.sh --unintegrate /etc/pam.d/login
sudo /usr/share/tessera/integrate-pam.sh --mode=<mode> /etc/pam.d/login
```

for each previously integrated service — the old session line from the
snippet disappears after the `.deb` update, and only a re-run inserts
the new one.

### Order validation

The daemon raises `ERROR pam_stack_session_misorder` at startup if our
session line stands **before** `@include common-session` /
`pam_systemd.so`. Check it without a restart:

```bash
sudo tessera check
```

Otherwise the following appears in journald:

```
WARN tessera.session: XDG_SESSION_ID not in PAM env during sm_open_session
WARN tessera.monitord: USB-removal action dropped: session has no logind id
```

When the stick is removed, logout will NOT happen — see
[troubleshooting.md §4](troubleshooting.md#4-pam-stack-and-lockout).

## 3. fly-dm

### Why integrate fly-dm specifically

`fly-dm` is the graphical display manager of Astra Linux SE; it is the
**first** PAM consumer through which a user reaches a graphical session.
Without integrating `tessera` into `/etc/pam.d/fly-dm`, the USB token is
not checked at the GUI-login stage, and the user will log in with a
password as if the module were not installed. The other services
(`sudo`, `login`, `sshd`) only protect subsequent actions.

The specific reasons:

1. **The session entry point.** The МКЦ label
   (`pam_cert_max_integrity ∩ the user's user integrity ceiling
   (МНКЦ)`) is applied in `pam_sm_open_session` and inherited by all
   child processes of the desktop session. If the session was not opened
   by `tessera`, the label will not be set.
2. **Binding the USB to the session.** `tessera daemon` registers the
   removal of the token and sends a lock event to the screen locker.
   Registration is only possible if the module itself opened the session
   — otherwise the daemon has no `(uid, session_id, token_serial)`
   record.
3. **Hot-plug before login.** `fly-dm` starts earlier than the user
   services; `tessera.service` must be `Before=fly-dm.service` (the
   shipped unit does this) — otherwise, on the first login after a
   reboot, the USB may not yet be initialized.
4. **The GUI prompt for the PIN.** `fly-dm` renders
   `PAM_PROMPT_ECHO_OFF` as a password field. Without integration, the
   PKCS#11 prompt goes to the DM process's `stderr` and the user does
   not see it — which looks like "the token doesn't work".
5. **Root context at the auth stage.** `fly-dm` runs as root, so access
   to `/dev/bus/usb/*` and the PCSC socket is allowed without extra udev
   configuration.

### Applying it

```bash
sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/fly-dm
sudo cat /etc/pam.d/fly-dm | head -5
```

The expected top of the file:

```
@include tessera
auth        requisite   pam_nologin.so
auth        required    pam_env.so
...
```

The control in the [`dist/pam.d/tessera`](../../dist/pam.d/tessera)
snippet is `required`: without successful cert authentication, login is
impossible, and there is NO password fallback (this is the default `2fa`
mode of the `integrate-pam.sh` script). The softer variant with a
fallback to the following modules (`pam_unix.so`) is a separate snippet,
[`dist/pam.d/tessera-optional`](../../dist/pam.d/tessera-optional), with
`sufficient` control; use it only for a transition period, while not
everyone has a token.

### The screen locker (a separate stack)

`fly-dm-screensaver` / `fly-wm-locker` have their **own** PAM stack.
Integrating `/etc/pam.d/fly-dm` does not control screen unlock. For
unlocking to work by token:

```bash
sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/fly-dm-screensaver
```

Without this, removing the token correctly locks the screen (via
`tessera daemon` + the D-Bus screen-lock hook), but you will only be
able to unlock the session with a password.

### Checking the bench

```bash
systemctl status tessera        # is the daemon up before fly-dm starts?
pamtester fly-dm $USER authenticate  # a dry run of the auth stack without GUI
journalctl -u fly-dm -f              # logs during a live login
```

### A banner with host_id on the screen

See [fly-dm-greeter.md](fly-dm-greeter.md) — the wallpaper writer for
МКЦ-3 fly-modern, where PAM_TEXT_INFO is not forwarded to the UI.

## 4. Authentication modes

`tessera` supports three operational modes, switched by choosing a PAM
snippet:

| Mode              | snippet                            | Scenario                              | Login without USB             |
|-------------------|------------------------------------|---------------------------------------|-------------------------------|
| `2fa` (default)   | `/etc/pam.d/tessera`              | Cert + password (classic 2FA)         | password works, but you can't log in without USB |
| `optional`        | `/etc/pam.d/tessera-optional`     | Cert OR password (migration)          | yes, by password              |
| `cert-only`       | `/etc/pam.d/tessera-only`         | Cert as the only factor               | NO, full lockout              |

### Activation

```bash
# 2FA on sudo (the default):
sudo /usr/share/tessera/integrate-pam.sh --mode=2fa /etc/pam.d/sudo

# Migration mode:
sudo /usr/share/tessera/integrate-pam.sh --mode=optional /etc/pam.d/sudo

# Cert-only (losing the stick = lockout!):
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/sudo
```

Rollback is the same for all modes:

```bash
sudo /usr/share/tessera/integrate-pam.sh --unintegrate /etc/pam.d/sudo
```

### The lockout warning for `cert-only`

Before switching a service to `cert-only`, the admin must have a backup
access channel:

1. **An open root shell in another terminal** (TTY/SSH) for the whole
   duration of the check — at least until you have confirmed that
   cert-only auth works on a test account on this machine.
2. **An alternative login path** that does NOT go through `tessera` —
   for example, a separate sshd stack with `PubkeyAuthentication=yes` +
   `UsePAM=no`, or a sudoers rule for the admin account without
   `@include tessera`. Otherwise the loss or blocking of the single
   token (USBGuard, ЗПС, physical loss) will take the host out of
   service — nobody will be able to log in, including local root.

Rollback is `integrate-pam.sh --unintegrate` from a live root shell or
via the rescue target (see
[troubleshooting.md §4 "Locked out after a failed PAM edit"](troubleshooting.md#4-pam-stack-and-lockout)).

## 5. sudo

```bash
sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/sudo
```

## 6. login

```bash
sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/login
```

## 7. The PAM stack with МКЦ in mind

The stack depends on whether the PARSEC МКЦ kernel is enabled.
`pam_parsec_mac.so` is needed in the stack **only when the МКЦ kernel is
actually working**. Details —
[mac-integrity.md §6 "The PAM stack for МКЦ scenarios"](mac-integrity.md#6-pam-stack-for-mic-scenarios).

### Check the state of МКЦ

```bash
mount | grep -i parsec                           # empty → МКЦ is off
cat /etc/parsec/mswitch.conf 2>/dev/null         # zero_if_notfound: yes → МКЦ is off
ls /sys/kernel/security/parsec 2>/dev/null       # ENOENT → МКЦ is off
```

### Short templates

**МКЦ off** — without `pam_parsec_mac.so` in the stack,
`[mac].runtime = "disabled"`.

**МКЦ on** — `auth required pam_parsec_mac.so` + `@include tessera` +
`pam_parsec_cap.so`/`pam_parsec_mac.so` in session.
`[mac].runtime = "required"`.

**Mixed fleet** — `runtime = "auto"`, a stack with `pam_parsec_mac.so`
is safe.

Full stack examples, validation, and the `runtime × cert_integrity`
matrix — [mac-integrity.md](mac-integrity.md).

## 8. Safety of the edit

- Before editing, make sure there is a second open root shell.
- Check every change with `pamtester` right after the edit.
- If it breaks, restore from the backup:
  ```bash
  sudo cp /etc/pam.d/sudo.bak.<TS> /etc/pam.d/sudo
  ```
- Full recovery from the rescue target — see
  [troubleshooting.md §4](troubleshooting.md#4-pam-stack-and-lockout).

## 9. Verification

```bash
pamtester sudo alice authenticate
```

Expected: `Authentication successful` (with the USB media or token
inserted).

```bash
sudo tessera check    # catches pam_stack_session_misorder etc.
```

## 10. Hosts without systemd: SysV init

The `tessera` package installs **both** init variants:

- **the systemd unit** `tessera.service` — the primary one; on hosts
  with systemd it is activated automatically via `dh_installsystemd`;
- **the SysV init script** `/etc/init.d/tessera` — for non-systemd
  environments (pure sysvinit, OpenRC). It is enabled via `update-rc.d`
  or manually:

  ```bash
  sudo update-rc.d tessera defaults
  sudo service tessera start
  sudo service tessera status
  ```

The script wraps the launch of `/usr/bin/tessera` via
`start-stop-daemon`, puts a PID file in `/run/tessera/tessera.pid`, and
reads `/etc/tessera/config.toml`.

### Caveats

- On SysV hosts there is no hardening sandbox (cgroups, ProtectSystem) —
  the operator accepts this trade-off consciously.
- USB-removal `Lock`/`Logout` does **not** work without `pam_systemd.so`
  — `XDG_SESSION_ID` is physically not created. Fallback:
  `[on_usb_removed].action = "shutdown"` or `"hook"`. See
  [troubleshooting.md §4 "Logout requested but session has no logind id", Cause 3](troubleshooting.md#4-pam-stack-and-lockout).
- On systemd hosts the SysV script does not need editing — the
  authoritative source of the service configuration is
  `tessera.service`.

## 11. See also

- [install.md](install.md) — installing `tessera` in full.
- [mac-integrity.md](mac-integrity.md) — МКЦ end-to-end activation and
  the full matrix of PAM stacks.
- [fly-dm-greeter.md](fly-dm-greeter.md) — the wallpaper banner on
  fly-dm.
- [troubleshooting.md §4](troubleshooting.md#4-pam-stack-and-lockout) —
  lockout, recovery, `Logout requested but session has no logind id`.
- [configuration.md](configuration.md) — the `config.toml` reference.

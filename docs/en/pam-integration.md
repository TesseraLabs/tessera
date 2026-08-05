# Integrating `tessera` into `/etc/pam.d/*`

The goal of this document is to wire Tessera's certificate check into the
PAM stack of the services you need (`fly-dm`, `login`, `sudo`, `sshd`)
and **not lock yourself out** in the process. All edits to
`/etc/pam.d/*` are made by a single shipped script,
`/usr/share/tessera/integrate-pam.sh`, which inserts the module's include
at the correct position and saves a backup copy of each file.

Reading order: first choose a mode (§1) — it determines whether you will
be able to log in without the USB media and what its loss means; then how
the script edits the files (§2–§3) and the specifics of each service
(§4–§6); finally the edge cases (МКЦ, hosts without systemd) and
recovery.

> **IMPORTANT.** Before editing the PAM stack, **open a second root
> shell** (for example, `ssh root@<host>`). If the main shell cannot
> authenticate after the changes, the second terminal will be the only
> way to roll them back.

## 1. Authentication modes

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

## 2. The shipped snippet and `integrate-pam.sh`

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

## 3. The two-include pattern (0.3.12+)

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

With the wrong order, `XDG_SESSION_ID` does not make it into the PAM
environment by the time our `pam_sm_open_session` runs (in the PAM
module's log at DEBUG level: `XDG_SESSION_ID not yet in PAM env`, target
`tessera.session`), and the session is left without a logind id. The cost
of the mistake is high: when the stick is removed, the `lock`/`logout`
action cannot address the session, and the daemon goes fail-closed — the
device reboots, with the ALERT line
`USB-removal … has no logind id; failing closed with reboot` in the log.
For details, see
[troubleshooting.md §4](troubleshooting.md#4-pam-stack-and-lockout).

## 4. fly-dm

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
impossible. This is the default `2fa` mode of the `integrate-pam.sh`
script; "there is NO password fallback" means that the password does
**not** replace the certificate. The password is still requested by the
rest of the PAM stack (`pam_unix.so`, etc.) as a second factor — but it
cannot bypass a failed or missing cert authentication. The softer variant
with a fallback to the following modules (`pam_unix.so`) is a separate
snippet, [`dist/pam.d/tessera-optional`](../../dist/pam.d/tessera-optional),
with `sufficient` control; use it only for a transition period, while not
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

## 5. sudo

```bash
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/sudo
```

**For role accounts (password locked via `passwd -l`, see
[install.md §8.4](install.md#84-closing-the-remaining-ways-into-a-role-account)),
the mode must be `--mode=cert-only`.** Both `2fa` and `optional` fall
through to `pam_unix.so` on some branch of the stack — and `pam_unix`
on a locked password (`!`/`*` in `/etc/shadow`) always refuses, and
that refusal looks like "the cert didn't work" even though the real
cause is the password. `cert-only` is the only mode in which
`pam_unix` never takes part in the decision at all. Regular
(non-role) accounts with a normal password work fine under any of the
three modes — the choice there is described in §1.

A separate concern is keeping other engineers out of the role account
via `sudo -u serv` / `sudo -i -u serv`: that's runas scoping, unrelated
to whether `tessera` is wired in here — the recipe (the
`tessera-roles` group, a negation in `sudoers`, checking with
`sudo -l -U`) is in [install.md §8.4 "`su` and
`sudo -u`"](install.md#84-closing-the-remaining-ways-into-a-role-account).

## 6. login

```bash
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/login
```

Same reason as in §5: a role account logs into `login` with a locked
password, so the mode is `cert-only` only.

## 6½ sshd

```bash
sudo /usr/share/tessera/integrate-pam.sh --mode=cert-only /etc/pam.d/sshd
```

Like `login`/`sudo`, `sshd` needs `--mode=cert-only` for role
accounts, for the same locked-password reason.

`sshd` also needs its own `Match User` block closing every login
method except keyboard-interactive (the one PAM/Tessera comes through)
— the recipe, the `Match`-scope trap, and both `sshd -T -C` checks are
in [install.md §8.4 "`sshd`: leave a single authentication
method"](install.md#84-closing-the-remaining-ways-into-a-role-account).

> **Known limitation: privilege separation.** OpenSSH with
> `UsePrivilegeSeparation` enabled (the default on every target
> distribution) runs the PAM auth phase and the session-open phase in
> **different** processes/PAM handles. The `AuthContext` that
> `pam_sm_authenticate` stores via `pam_set_data` only lives within
> one `pam_start()`/`pam_end()` — it does not survive the transition
> between privsep processes. In practice this means a real `ssh`
> certificate login in `cert-only` mode can pass the auth phase
> successfully and then immediately break on session open. The
> `pamtester` smoke test (§9 below) will not show this — `pamtester`
> itself doesn't separate privileges and keeps one process for the
> whole run. The only reliable check is a real SSH connection (see §9
> "Verifying with a real login"). If it drops right after entering the
> PIN, that's this limitation, not a misconfiguration — temporarily
> roll back the integration (`--unintegrate`) and use `login`/`fly-dm`
> for certificate login until this is fixed.

## 6¾ su

`su` **does not need**, and should not get, `tessera` integration.
Blocking the switch into a role account is enough at the
`pam_succeed_if.so` level (`requisite … notingroup tessera-roles`,
recipe and both checks in [install.md §8.4 "`su` and
`sudo -u`"](install.md#84-closing-the-remaining-ways-into-a-role-account)):
that rule blocks switching into `serv` for everyone, `root` included,
without the `tessera` PAM stack being involved at all. There's no need
to add `@include tessera*` here — `su` shouldn't grow its own
certificate-login path; the bearer already went through `tessera` in
whichever service (`login`/`sshd`/`fly-dm`) gave them their current
session.

## 7. The PAM stack with МКЦ in mind

The stack depends on whether the PARSEC МКЦ kernel is enabled.
`pam_parsec_mac.so` is needed in the stack **only when the МКЦ kernel is
actually working**. Details —
[operations.md §7 "МКЦ (MAC integrity)"](operations.md#7-мкц-mac-integrity)
and [mac-integrity.md](mac-integrity.md).

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

The shipped stack and the МКЦ activation procedure —
[operations.md §7](operations.md#7-мкц-mac-integrity) and
[install.md §"МКЦ (MAC integrity): optional activation"](install.md#мкц-mac-integrity-optional-activation).
The full `runtime × cert_integrity` matrix and the integration
documentation are in the commercial distribution (see
[mac-integrity.md, "What is in the commercial distribution"](mac-integrity.md#what-is-in-the-commercial-distribution)).

## 8. Safety of the edit

- Before editing, make sure there is a second open root shell.
- Check every change with `pamtester` right after the edit.
- If it breaks, restore from the backup:
  ```bash
  sudo cp /etc/pam.d/sudo.bak.<TS> /etc/pam.d/sudo
  ```
- Full recovery from the rescue target — see
  [troubleshooting.md §4](troubleshooting.md#4-pam-stack-and-lockout).

## 9. `pamtester` does not replace a real login

The `AuthContext` that `pam_sm_authenticate` stores via `pam_set_data`
only lives within one `pam_start()`/`pam_end()` — one process reading
and writing the same PAM handle. Three separate `pamtester` calls
(`authenticate`, `open_session`, `close_session` invoked one at a
time) are three independent PAM transactions: the `account`/`session`
phases of such a run won't see the context left by the auth phase of a
previous call, and will fail with an error unrelated to how the module
actually behaves. The correct invocation passes every operation as one
list, so a single `pam_start()` covers the whole run:

```bash
pamtester sudo alice authenticate acct_mgmt open_session close_session
```

Expected: `pamtester` prints `successfully` for each operation in turn
(with the USB media or token inserted).

```bash
sudo tessera check    # catches pam_stack_session_misorder etc.
```

### `pamtester` ≠ a real login

`pamtester` is not a full login stack: it does not separate
privileges between processes the way `sshd` does (see §6½, "Known
limitation") or the way `login`/`fly-dm` sometimes does in a
display-manager configuration, and it doesn't go through the PAM
conversation the way a real service does (PIN prompt, TTY, X11
session). A successful `pamtester` run confirms the PAM stack itself
is correct (line order, `pam_tessera` is invoked, `AuthContext`
crosses phases within one process) — but it does not guarantee a real
login through the service under test will behave the same way.

### Verifying with a real login

After `pamtester`, always verify with a live login on every integrated
service:

```bash
ssh serv@<host>                 # sshd
login: serv                     # login (local console/TTY)
sudo -u serv -i                 # sudo, if the caller has runas rights
```

Expected: a PIN prompt, a successful login, and — for services with a
session phase — a working USB-removal reaction (`lock`/`logout`) when
the token is removed. `pamtester` doesn't check that either, since it
never opens a real logind session.

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
  — `XDG_SESSION_ID` is physically not created. Fallback: the top-level
  key `on_usb_removed = "shutdown"` (or `"hook"`). See
  [troubleshooting.md §4 "Logout requested but session has no logind id", Cause 3](troubleshooting.md#4-pam-stack-and-lockout).
- On systemd hosts the SysV script does not need editing — the
  authoritative source of the service configuration is
  `tessera.service`.

## 11. See also

- [install.md](install.md) — installing `tessera` in full.
- [mac-integrity.md](mac-integrity.md) — the open/commercial boundary for
  МКЦ and the МКЦ / МРД line.
- [operations.md §7](operations.md#7-мкц-mac-integrity) — МКЦ activation
  (the shipped stack, drop-in, privileges).
- [fly-dm-greeter.md](fly-dm-greeter.md) — host_id on the login screen.
- [troubleshooting.md §4](troubleshooting.md#4-pam-stack-and-lockout) —
  lockout, recovery, `Logout requested but session has no logind id`.
- [configuration.md](configuration.md) — the `config.toml` reference.

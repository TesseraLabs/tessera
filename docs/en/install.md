# Installing Tessera on Astra Linux SE

This document is a step-by-step scenario for installing and doing the
basic configuration of `tessera` on a clean Astra Linux SE 1.7+
machine. At the end — a working certificate login, verified via
`pamtester` (§10). Every section ends with a verification command; if the
check fails, see §11 "Troubleshooting" and
[troubleshooting.md](troubleshooting.md).

> All commands are run as `root` or with `sudo`. While editing the PAM
> stack, keep a root shell open in **another** terminal. If the PAM
> stack breaks authentication, that second terminal is the only way to
> roll the changes back.

## 1. Preparing the machine

### 1.1 OS check

```bash
cat /etc/astra_version 2>/dev/null || cat /etc/os-release
```

Expected output: version `1.7.5` or newer. On other Astra Linux
editions (the "Oryol", "Voronezh", and "Smolensk" 1.7+ security
levels — increasing grade, up to state-secret) the procedure is
identical. On Ubuntu/Debian it is best-effort.

### 1.2 Kernel check

```bash
uname -r
```

Expected: `5.15.0-93-generic` or newer (required for correct delivery
of USB-removal udev events).

### 1.3 Installing system dependencies

```bash
sudo apt update
sudo apt install -y \
    libpam0g \
    libssl3 \
    libudev1 \
    libdbus-1-3 \
    libsystemd0 \
    pcscd \
    opensc-pkcs11 \
    pamtester
```

If `apt install` can't find `pamtester` (or other packages above) on
Ubuntu/Debian, check whether the `universe`/`multiverse` component is
enabled (`sudo add-apt-repository universe && sudo apt update` on
Ubuntu): `pamtester` is a real `.deb` dependency (see
`debian/control`), it just doesn't live in `main`. **On Astra SE
`pamtester` isn't packaged at all** — not in any component
(`main`/`contrib`/`non-free`/`non-free-firmware`) of either
`repository-main` or `repository-extended`; `apt-cache search
pamtester` there is always empty, no repository will fix it. It builds
from source in about a minute (upstream hasn't moved since 2005,
version is always `0.1.2`, the only dependency is `libpam0g-dev`):

```bash
sudo apt install -y build-essential libpam0g-dev
cd /tmp
wget -L "https://sourceforge.net/projects/pamtester/files/pamtester/0.1.2/pamtester-0.1.2.tar.gz/download" -O pamtester-0.1.2.tar.gz
# fallback mirror of the same tarball if SourceForge serves an
# interstitial page instead of the file:
#   wget http://deb.debian.org/debian/pool/main/p/pamtester/pamtester_0.1.2.orig.tar.gz -O pamtester-0.1.2.tar.gz
tar xzf pamtester-0.1.2.tar.gz
cd pamtester-0.1.2
./configure && make
sudo make install
```

Installs to `/usr/local/bin/pamtester` — it lands on `PATH`
automatically, and is used exactly as in §10 from there on.

> Sections 3–4 (issuing a test CA and credentials) are plain `openssl`
> invocations with no engine at all (ECDSA P-256 is supported by the
> built-in `default` provider everywhere, including macOS), don't have
> to run on the target Astra machine, and are split into a separate
> document — [cert-issuance-lab.md](cert-issuance-lab.md).

### 1.4 Preflight: USBGuard and Astra ЗПС (DIGSIG)

Before installation it is worth making sure that the environment will
not block either the token on the USB bus or the launch of
`pam_tessera.so` / `tessera` via digital-signature enforcement.

#### USBGuard

If USBGuard is installed on the host in `block` mode, the USB token
must be on the allowlist — otherwise the kernel will not hand the
device to `udev`, and `tessera` will not see it.

```bash
sudo systemctl is-active usbguard          # active / inactive / not-found
sudo usbguard list-devices 2>/dev/null     # a "block" column → the token is blocked
```

Allow a specific token (by vid:pid or by hash) with a separate rule in
`/etc/usbguard/rules.conf`:

```
allow id 0aca:0030 name "Rutoken ECP" hash "ABC..."
```

After editing the rules, run `sudo systemctl reload usbguard`. Details
of the runtime aspect (the start order of `monitord` relative to
USBGuard) are in [docs/operations.md §3.5](operations.md).

#### Astra ЗПС / DIGSIG (`astra-digsig-control`)

In a production deployment on Astra SE, one of two things is required
under the closed software environment (ЗПС, Astra's signed-executables
enforcement):

1. **`astra-digsig-control`** is switched to `logging-only` mode (the
   module does not block the execution of unsigned ELF binaries but
   spams `/var/log/syslog` with `DIGSIG: NOT_ELF_SIGNED` messages); or
2. the `pam_tessera.so` and `tessera` binaries are signed via the Astra
   partner's signing service (`bsign` with a GPG key from the trusted
   keyring in `/etc/digsig/keys/`) — usually this is a build step of
   the `.deb` in the Astra CI.

```bash
sudo astra-digsig-control status     # ВКЛЮЧЕНО / НЕАКТИВНО / logging-only
sudo dmesg | grep -i digsig | tail   # whether signature rejections are visible
```

In `enforce` mode, without a valid signature, PAM authentication does
not go through — `pam_tessera.so` simply does not load. See also
[docs/threat-model.md §3.7](threat-model.md).

## 2. Installing the `.deb`

### 2.1 Download

Releases are published on GitHub:
[github.com/TesseraLabs/tessera/releases](https://github.com/TesseraLabs/tessera/releases).
The release publishes only the `.deb` in two variants (`…-astra.deb`
and `…-ubuntu.deb`), plus `.changes` and `.buildinfo` for audit — there
are no ready-made checksum files there; the operator computes them on a
trusted machine (see §2.2). Download the variant you need via the `gh`
CLI or manually from the browser:

```bash
gh release download v0.5.0 --repo TesseraLabs/tessera --pattern '*-astra.deb'
# or for an Ubuntu target:
# gh release download v0.5.0 --repo TesseraLabs/tessera --pattern '*-ubuntu.deb'
```

### 2.2 Generating the checksums (trusted machine)

The checksums are computed by the builder or the operator on a
**trusted** machine (not the target) with the `generate-checksums.sh`
script. The script lives in the repository
(`scripts/generate-checksums.sh`) and is not bundled into the `.deb` —
the trusted machine needs either a clone of `tessera` at the matching
tag (`git clone --branch v0.5.0 --depth 1
https://github.com/TesseraLabs/tessera.git`) or just the file itself:

```bash
curl -fsSL -o generate-checksums.sh \
    https://raw.githubusercontent.com/TesseraLabs/tessera/v0.5.0/scripts/generate-checksums.sh
chmod +x generate-checksums.sh
./generate-checksums.sh tessera_0.5.0-1_amd64.deb checksums
```

The script puts a `checksums.txt` file into the `checksums/` directory —
a SHA-256 report for the `.deb` itself and for every file inside the
package — plus standalone `*.sha256` files. (The script can also emit a
Streebog-256 section when `gost-engine` is present, but this ECDSA-only
scenario doesn't use it.)

Three things are delivered to the target machine: the `.deb` itself,
`checksums.txt` (generated on the trusted machine in §2.2, transferred
manually — scp, USB, etc.), and `verify-checksums.sh` (the script is
self-contained — the only external thing it needs is `openssl`). Unlike
`checksums.txt`, the script itself is a static repository file, so it's simpler to download it
directly on the target machine rather than copy it from the trusted
one:

```bash
curl -fsSL -o verify-checksums.sh \
    https://raw.githubusercontent.com/TesseraLabs/tessera/v0.5.0/scripts/verify-checksums.sh
chmod +x verify-checksums.sh
```

### 2.3 Verifying on the target machine

```bash
./verify-checksums.sh tessera_0.5.0-1_amd64.deb checksums.txt
```

Expected: `OK: N checksum(s) verified`. The script (described in
[scripts/verify-checksums.sh](../../scripts/verify-checksums.sh)) checks
the SHA-256 sum. A non-zero exit code means either a checksum mismatch
(code 1) or a launch problem: invalid arguments (2). In any of these
cases do not install the package until the cause is understood.

### 2.4 Installation

```bash
sudo apt install ./tessera_0.5.0-1_amd64.deb
```

`apt` will pull in the missing dependencies (`libpkcs11-helper1`,
`librtpkcs11ecp`).

### 2.4½ Preflight check (`tessera check`)

Before `systemctl restart tessera`, or on a first installation, run the
preflight: it validates `config.toml` and reports ALL potential
misconfigurations in a single pass — without opening the socket and
without restarting the daemon.

```bash
sudo tessera check
```

What is checked:

- **The PAM stack.** It scans `/etc/pam.d/{login,fly-dm,fly-dm-np,sshd,sudo,su}`
  and raises an ERROR in two cases:
  1. `@include tessera-*` stands BEFORE `auth required pam_parsec_mac.so`
     (on Astra SE this kills the account phase with "Can't obtain required data").
     Check id: `pam_stack_misorder`.
  2. `session required pam_tessera.so` stands BEFORE
     `pam_systemd.so` / `@include common-session` —
     `XDG_SESSION_ID` is not yet available at the moment of `pam_sm_open_session`,
     `UpdateSessionTarget` is not sent, and monitord cannot call
     logind Logout/Lock on USB removal. Check id:
     `pam_stack_session_misorder`. Both errors suggest the fix command
     via `integrate-pam.sh`. The health check for the session phase writes
     `pam_stack_session_ok` (INFO) when the order is correct, or
     `pam_stack_session_no_systemd` (INFO) if the stack has no
     pam_systemd at all — typical for sysvinit/OpenRC hosts.
- **`[mac].runtime` vs the kernel.** `runtime=required` without an active
  `parsec_strict_mode()=1` is an ERROR (`required` in strict mode without a
  МКЦ kernel makes the daemon useless). `auto` + a missing kernel is a WARN
  (silent fallback to `StubBackend`, MAC is NOT enforced). `disabled` is INFO.
- **Trust anchors / intermediates.** Every path from `[trust].anchors`
  and `[trust].intermediates` must exist, be non-empty, and contain at
  least one `-----BEGIN CERTIFICATE-----` marker. Otherwise it is an
  ERROR — the daemon cannot validate any chain.
- **`/etc/tessera/ca/`.** A WARN if it is world-writable
  (`mode & 0o002 != 0`).
- **`PARSEC_CAP_CHMAC`.** If the МКЦ kernel is active and `[mac].runtime ≠ disabled`
  but the process lacks the capability — a WARN: the labels on `sessions.json` will not stick.
- **`host_identity` sources.** One INFO/WARN line per configured source
  (`machine_id`, `dmi_*`, `hostname`, `custom_command`) — you can see at
  once what resolves and what fails.

Exit code: **0** — only INFO/WARN; **1** — there is at least one ERROR. The
same check is performed by the daemon at startup: if there is an ERROR,
boot aborts, and structured messages with `target=tessera.startup_check`
for each check remain in `journalctl -u tessera`.

### 2.4¾ Cloned-image scenario (golden image → terminal)

If you are installing onto many terminals via a clone of a single image,
the full end-to-end workflow is split into a separate document:
**[docs/clone-image.md](clone-image.md)** — the bootstrap cert on the
reference machine, `finish-bootstrap.sh` on each clone, `dump-host-id`
for the CA admin, per-host certificate issuance, troubleshooting, and
Ansible rollout.

Tldr — two tools shipped in the `.deb`:

- `tessera dump-host-id [--output FILE | --usb]` — tries all known
  `host_identity` sources and writes a TSV report. The
  `active_under_current_config=yes` column marks the source the daemon
  actually uses right now. `--usb` automatically mounts the first USB
  stick r/w and writes `host-ids-<hostname>-<UTC>.tsv`.
- `/usr/share/tessera/finish-bootstrap.sh` — a single-pass transition
  from bootstrap state to production: it rewrites `config.toml`
  (`sources = ["override"]` → `["dmi_board_serial", "machine_id"]`),
  runs `tessera check`, restarts the daemon, and dumps the host_ids to
  USB. Idempotent. For flags, see [clone-image.md §4.2](clone-image.md).

### 2.5 Checking the systemd unit

```bash
systemctl status tessera
```

Expected: `Active: active (running)`. If it is `inactive (dead)`, start
it manually:

```bash
sudo systemctl enable --now tessera
```

### Verification (section 2)

```bash
tessera --version
test -d /run/tessera && echo "runtime dir OK"
test -S /run/tessera/monitord.sock && echo "socket OK"
```

Expected: version `0.5.0`. On a **fresh** machine where
`/etc/tessera/config.toml` does not exist yet (see the `.deb`'s
post-install hint — `cp config.toml.example config.toml`), the other
two lines are expected to stay empty: the daemon starts, but a valid
`config.toml` needs material from §3 (CA), §7 (cert extensions) and §8
(role store) that doesn't exist yet at this point in the walkthrough.
Both lines should only appear after `systemctl restart tessera` at the
end of §8 — the full daemon/socket check happens there, in Verification
(section 8) and the §10 smoke test.

## 3. Creating a test CA

Split into a separate document — [cert-issuance-lab.md §"Creating a
test CA"](cert-issuance-lab.md#creating-a-test-ca): directory, CA key,
self-signed certificate, verification. All plain `openssl` invocations
with no engine (ECDSA P-256), runnable on the administrator's
workstation, not the target Astra machine.

The result of this section is `ca.pem` and `ca.key` in `/tmp/ca/`,
needed further in §4 and §5.

## 4. Creating a test role account

The role at login is the name of the login account: the engineer logs
into a **role account** named after the role (`ssh serv@device`), and the
requested role equals the name of that account. There is no separate
role prompt.

The rest of the scenario uses the role `serv` ("service engineer") — the
repository ships a ready-made role slice for it, `dist/roles/serv.toml`,
which is needed in §8. The login account is called `serv` as well; it is
created in §8, together with the role store.

The key, the CSR, both required extensions
(`pam_cert_host_binding`, `pam_cert_allowed_roles`) and packing into
P12 are in a separate document: [cert-issuance-lab.md §"Creating the
role account's
credential"](cert-issuance-lab.md#creating-the-role-accounts-credential).
That document also has the OID table, the fail-closed behavior when
extensions are missing (see §7 and §10 of this document), and getting
`host_id_hash` via `sudo tessera dump-host-id` from the target machine.

The result of this section is `serv.p12` in `/tmp/ca/`, ready to be
copied onto the USB media (§5).

## 5. Preparing the USB media (`pkcs12` mode / Mode A)

> Mode A: the key is stored in a `.p12` on the USB media, protected by a
> passphrase. For production, choose Mode B (a PKCS#11 token).

### 5.1 Formatting

`tessera` looks for a `.p12` on **any** partition whose filesystem is on
the allowlist (`vfat`, `exfat`, `ext4`, `ntfs`). The partition label
does not matter — protection is provided at the level of decrypting the
`.p12` with the user's password and validating the certificate chain in
the trust module. The limit on the number of partitions scanned is set
by the `max_usb_partitions` parameter in `config.toml` (8 by default,
range 1..=64).

> If the USB stick has several partitions and some of them
> contain foreign files with a name matching `pkcs12_path_pattern`
> (typical for Apple-formatted media and USB sticks with multiple
> partitions), `tessera` recognizes them as "not PKCS#12" by the ASN.1
> envelope (without asking for a PIN) and keeps looking for the real
> `.p12` on the following partitions. Errors that require a password
> (wrong PIN / MAC verify / decrypt / chain) are still fail-closed,
> without scanning further.

A typical recipe (`sdX1` is the USB-media partition from the output of
`lsblk | grep -i usb`):

```bash
# WARNING: this command DESTROYS the data on device /dev/sdX1.
# Supported filesystems: vfat, exfat, ext4, ntfs.
sudo mkfs.ext4 /dev/sdX1
sudo mount /dev/sdX1 /mnt/usb
sudo install -m 0600 service.p12 /mnt/usb/service.p12
sudo umount /mnt/usb
```

If the stick is formatted without a partition table (the filesystem
lives directly on the whole device), this also works: `tessera` reads
the udev `ID_FS_TYPE` and mounts the whole device directly.

### 5.2 Layout

```
/mnt/usb/
├─ certs/
│   ├─ user.p12
│   └─ chain.pem
└─ tessera.marker
```

### 5.3 Copying

```bash
sudo mkdir -p /mnt/usb/certs
sudo cp /tmp/ca/serv.p12   /mnt/usb/certs/user.p12
sudo cp /tmp/ca/ca.pem     /mnt/usb/certs/chain.pem
sudo touch /mnt/usb/tessera.marker
sudo umount /mnt/usb
```

### Verification (section 5)

```bash
sudo mount /dev/sdX1 /mnt/usb
ls -la /mnt/usb/certs/
sudo umount /mnt/usb
```

Expected: both files present, size > 0.

## 6. Preparing a Rutoken ECP 2.0 (`pkcs11` mode / Mode B)

### 6.1 Installing the driver

```bash
sudo apt install librtpkcs11ecp
```

### 6.2 Checking the slot

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so -L
```

Expected: output of the form `Slot 0 (0x...): ...` with the token
model.

### 6.3 Initialization (only for a new, uninitialized token)

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --init-token --label "serv-token" \
    --so-pin '12345678'
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --init-pin --so-pin '12345678' --pin '1234567890'
```

### 6.4 Importing the key and certificate

`pkcs11-tool` expects the key and certificate as separate DER/PEM objects,
not as a PKCS#12 container. First extract them from `serv.p12` (the
password is from [cert-issuance-lab.md §"Packing into
P12"](cert-issuance-lab.md#6-packing-into-p12)):

```bash
openssl pkcs12 -in serv.p12 -nocerts -nodes -passin pass:test \
    -out serv.token.key             # private key, PEM, no password
openssl pkcs12 -in serv.p12 -clcerts -nokeys -passin pass:test \
    -out serv.token.crt             # credential, PEM
# Some tokens accept only DER — convert if needed:
#   openssl pkey -in serv.token.key -outform DER -out serv.token.key.der
#   openssl x509 -in serv.token.crt -outform DER -out serv.token.crt.der
```

Import the credential and the private key into the token:

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --login --pin '1234567890' \
    --write-object serv.token.crt --type cert --label serv --id 01
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --login --pin '1234567890' \
    --write-object serv.token.key --type privkey --label serv --id 01
```

Wipe the temporary private key that was lying in the clear on disk:

```bash
shred -u serv.token.key serv.token.key.der 2>/dev/null || shred -u serv.token.key
```

### Verification (section 6)

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --pin '1234567890' -O
```

Expected: the output contains a `Private Key Object` and a
`Certificate Object` with `label=serv`.

## 7. Authorization: credential extensions

The binding of "on which device, in which role" lives in the credential
itself. The PAM module reads two X.509 v3 extensions of the leaf:

- `pam_cert_host_binding` (OID `2.25.183976554325829274683049824615098`)
  — the list of allowed devices;
- `pam_cert_allowed_roles`
  (OID `2.25.185305973969816596290730578528098241367`, non-critical)
  — the list of roles the credential may activate.

These are two independent axes: the first answers "where", the second
"as whom". There is no separate list of permitted accounts: the name of
the login account IS the role, so `pam_cert_allowed_roles` also answers
the question of admission into the account. Admission is decided by the
credential alone — the configuration holds no mechanism by which the
device could admit a login on its own terms. A rejection by either of
the two is fail-closed.

Ready-made `openssl.cnf` recipes for issuing credentials with the
correct extensions are given in [cert-issuance.md](cert-issuance.md).

### Verification (section 7)

```bash
openssl x509 -in /tmp/ca/serv.pem -noout -text \
    | grep -E '2\.25\.(183976554325829274683049824615098|185305973969816596290730578528098241367)'
```

Expected: both dotted-OID lines are present in the output.

## 8. The device role store

A role is required at every login, and the module takes its definition
from the **role store** — a directory of `<role>.toml` slices on the
device itself. While the store is empty or unreadable, the device admits
nobody: this is deliberate fail-closed behavior, not a misconfiguration.

### 8.1 Installing the role slice

A ready-made sample of the `serv` slice lives in the repository —
`dist/roles/serv.toml`; role samples are not part of the `.deb`, so on a
clean machine it is easier to create the slice in place:

```bash
sudo install -d -m 0755 -o root -g root /var/lib/tessera/roles
sudo tee /var/lib/tessera/roles/serv.toml >/dev/null <<'EOF'
role = "serv"
version = 1
os = "linux"
name = "Service Engineer"
level = 5
description = "Service engineer with sudo and higher resource limits."

[payload]
groups = ["service", "wheel"]
sudo_role = "service"

[payload.limits]
nofile = 4096

[session]
max_ttl_seconds = 14400
memory_max = "2G"
tasks_max = 512
EOF
sudo chown root:root /var/lib/tessera/roles/serv.toml
sudo chmod 0644 /var/lib/tessera/roles/serv.toml
```

If the repository is available on this machine, the same in one command:

```bash
sudo install -m 0644 -o root -g root \
    dist/roles/serv.toml /var/lib/tessera/roles/serv.toml
```

Trust in the store rests on filesystem permissions — the same model as
`sudoers.d`: the directory, every slice and every parent directory must
be owned by `root:root` and must not be group- or world-writable. A
slice living in an unprivileged user's directory is rejected by the
product: otherwise the role — and with it the groups, sudo and session
limits — could be redefined by the very person it constrains.

### 8.2 Configuring `[roles]` in `/etc/tessera/config.toml`

```toml
[roles]
dir = "/var/lib/tessera/roles"
# Session cap used when neither the credential nor the role sets one.
# default_session_ttl_seconds = 43200   # 12h, the default value
```

The full description of the section is in
[configuration.md](configuration.md).

### 8.3 The login account

The account name *is* the role, so the account `serv` must exist on the
device. Across a fleet, role accounts are provisioned separately; for a
lab bench this is enough:

```bash
sudo useradd --create-home --shell /bin/bash serv
```

**A role account must be a regular account, not a system one.** The
absence of `--system` is deliberate: that flag hands out a uid outside
the regular-user range, and the product refuses to let anyone into an
account with such a uid. That account simply will not let an engineer
in.

**The regular-user range is set by two boundaries: 1000 and 61183
inclusive.** Everything below is accounts the distribution and its
packages created for themselves; the lower boundary matches `UID_MIN`
from `/etc/login.defs` on Debian, Ubuntu and Astra. Everything above is
not a regular user either: 61184 opens the block systemd hands out to
units with `DynamicUser=yes`, and beyond it sit `nobody` (65534) and
`nogroup` (65535). The check keys on exactly these two boundaries
rather than on a list of reserved names; a uid above the upper boundary
is not arithmetic exotica but the normal state of any system running
systemd.

The upper boundary deliberately differs from `UID_MAX` (60000 on
Debian): `UID_MAX` only bounds what `useradd` allocates by itself,
whereas a role account provisioned above that value must still be able
to log in. `UID_MAX` remains a sensible recommendation for
provisioning, but it is not the refusal boundary.

The reason for the refusal is that the role namespace and the Unix
account namespace became the same namespace. `root`, `daemon`, `bin`,
`sys`, `mail` and `nobody` all satisfy the `role_id` grammar
(`^[a-z][a-z0-9-]{0,15}$`), and a single `root.toml` slice — a
provisioning typo, or a copied sample — would turn `ssh root@device`
into an ordinary role login with privileges the role model never
granted. So the product looks not at the name but at the uid the account
has on this very device: the danger is not the name but the fact that an
account with somebody else's privileges already exists under it. A list
of names would encode a guess about which names those are, drift from
the distribution, and reject legitimate roles — on Debian `mail` is a
system account and a sensible role name at the same time.

The product carries the boundaries inside it rather than reading
`/etc/login.defs` at login time: editing that file on the device must
not widen the gate. That is also why the acceptance check below tests
against the product's boundaries rather than the contents of
`login.defs` — otherwise it would answer a different question from the
one the module answers at login time.

If the account was already created with `--system`, changing the uid of
a live account is not worth it — files would stay behind with the old
owner. It is simpler to delete and recreate it:

```bash
id -u serv                      # outside the range → logins will not work
sudo userdel -r serv
sudo useradd --create-home --shell /bin/bash serv
```

When provisioning through Census this step is already done: Census
creates the role account with `useradd -u <uid> …`, taking the uid from
the `uid_range` declared in the declaration — which lies entirely inside
the regular-user range — and checks that every role falls inside it.

### 8.4 Closing the remaining ways into a role account

The account from §8.3 is created with a home directory and a login
shell. The absence of a password closes exactly one way in — the
password one; `~/.ssh/authorized_keys`, `su serv`, `sudo -u serv -i` and
any PAM stack without `pam_tessera` stay open. The product does not
close those paths — it manages neither `sshd_config` nor `sudoers` nor
anybody else's PAM stacks. Provisioning and the device administrator
close them.

The price of a skipped step grew together with the model. A bypass used
to yield the personal account of one engineer; now `serv` is a *shared*
role account carrying the role's privileges, and a login that goes
around `pam_tessera` leaves no trace in `role.audit` or in the issuance
journal: there is nobody to record who actually came in.

Below is the minimum to perform on every device. Everything touching
`sshd` should be done with a second root shell open (see
[pam-integration.md §8](pam-integration.md#8-safety-of-the-edit)).

#### The password: lock it, do not merely "leave it unset"

```bash
sudo passwd -l serv
sudo passwd -S serv     # expected: L in the second column
```

`passwd -S` on somebody else's account reads `/etc/shadow`, so it runs
as `root`; without `sudo` the command is refused.

"No password set" and "password locked" are different states. `useradd`
leaves a `!` in the password field, and such an account really does
refuse password logins — but that is a default state, not a declared
intent: a single `passwd serv` typed while debugging silently opens the
password path, and nothing in the device configuration shows it.
`passwd -l` makes the lock explicit and `passwd -S` makes it visible:
the `L` in the second column is one command to check, both at acceptance
and later.

Separately: `passwd -l` does not close the non-password methods. A key
in `authorized_keys`, `su` from `root` and `sudo -u` keep working —
which is exactly why the remaining steps follow.

When provisioning through Census, `passwd -l` has already been run: it
is part of the role-account creation sequence. Running it again is
harmless, and on a hand-built device it is mandatory.

#### `authorized_keys`: must not exist, and must not appear

Take the home directory from the passwd database rather than guessing
it — under provisioning it comes from the declaration and need not be
`/home/serv`:

```bash
HOME_SERV=$(getent passwd serv | cut -d: -f6)
sudo test -e "$HOME_SERV/.ssh/authorized_keys" \
    && echo "authorized_keys exists — find out where it came from"
```

Expected: the command prints nothing. Census never creates that file; if
it is there, it was placed by hand or shipped in an image.

To keep it from appearing later, hand the `.ssh` directory to `root` and
take write access to it away from the role account:

```bash
sudo mkdir -p "$HOME_SERV/.ssh"
sudo chown root:root "$HOME_SERV/.ssh"
sudo chmod 0500 "$HOME_SERV/.ssh"
```

The honest limit of this measure: it stops a key from being added as
`serv` (including from inside an already open role session), but not as
`root`. Moreover, `sshd` with `StrictModes yes` accepts an
`authorized_keys` owned by the directory's owner **or** by `root` — so a
root-owned key placed here would be accepted. The public-key path for
this account is fully closed only by the `sshd` settings in the next
step; directory permissions are a second line, not the first.

#### `sshd`: leave a single authentication method

Tessera certificate authentication reaches `sshd` through
keyboard-interactive and PAM, so everything else must be closed while
`UsePAM yes` and `KbdInteractiveAuthentication yes` are kept:

```bash
sudo tee /etc/ssh/sshd_config.d/50-tessera-roles.conf >/dev/null <<'EOF'
Match User serv
    PubkeyAuthentication no
    PasswordAuthentication no
    KbdInteractiveAuthentication yes
    HostbasedAuthentication no
    GSSAPIAuthentication no
    PermitEmptyPasswords no
Match all
EOF
sudo sshd -t
sudo sshd -T -C user=serv,host=localhost,addr=127.0.0.1 \
    | grep -E '^(usepam|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|hostbasedauthentication)'
sudo sshd -T -C user=<a-regular-account>,host=localhost,addr=127.0.0.1 \
    | grep -E '^(usepam|pubkeyauthentication)'
```

Expected from the first check: `usepam yes`,
`kbdinteractiveauthentication yes`, and `no` for the other three.
Expected from the second: `usepam yes` and `pubkeyauthentication yes` —
that is, the block did not affect another user. It is `sshd -T -C` that
shows the *effective* configuration for a given account, accounting for
every `Match` block and the order of includes; reading the config files
by eye does not replace it.

> **The trailing `Match all` is not decoration — do not delete it.** A
> `Match` block's scope runs until the next `Match` **or the end of the
> whole configuration**, not the end of the file it was written in.
> Debian and Ubuntu put `Include /etc/ssh/sshd_config.d/*.conf` on the
> **first** line of `sshd_config` — so without a closing `Match all` the
> `User serv` condition would cover the entire remaining
> configuration: the other included files and the whole body of the
> parent `sshd_config`. Global directives declared below would stop
> applying to every other user — including `UsePAM yes`, which on Debian
> is declared exactly there. A setting meant to close the ways into one
> account would switch PAM off for the whole device. `Match all` returns
> parsing to the global context, and the second `sshd -T -C` check above
> is the one that catches this mistake.

Two places where distributions diverge, and where no universal command
exists:

- **The `sshd_config.d/` directory.** The line `Include
  /etc/ssh/sshd_config.d/*.conf` ships with Debian 11+, Ubuntu 20.04+
  and Astra with OpenSSH 8.2+. Check it with
  `grep -n '^Include' /etc/ssh/sshd_config`. If the line is absent,
  creating the file is pointless — append the block **at the end** of
  `/etc/ssh/sshd_config`. The closing `Match all` is needed there too: a
  trailing block is safe only until the first edit made after it, and
  appending a global directive to the end of `sshd_config` is an
  everyday thing to do — it would silently land inside the `User serv`
  condition.
- **The unit name.** `sudo systemctl reload ssh` on Debian/Ubuntu,
  `sudo systemctl reload sshd` on Astra and some builds. Check with
  `systemctl list-units 'ssh*'`; reload only after `sshd -t` succeeds.

If the installed OpenSSH understands `AuthorizedKeysFile none` (8.2+),
add the directive to the same `Match` block as a third line of defence
on top of `PubkeyAuthentication no`. Older builds do not support it and
`sshd` fails to start; check with the same `sshd -t` right after the
edit.

#### `su` and `sudo -u`: close the switch into a role account

There is no single command that works identically on Debian, Ubuntu and
Astra here: `su` and `sudo` are different mechanisms with different
configuration files, and each has to be closed on its own.

For `su`, `pam_succeed_if` works. The module ships in `libpam-modules`,
which is part of the base install on all three target distributions and
is not split into a separate dependency. Confirm it is present before
editing the stack — the line below is written as `requisite`, and if the
module is missing `su` will close for everyone, `root` included:

```bash
ls /lib/*/security/pam_succeed_if.so /lib/security/pam_succeed_if.so 2>/dev/null
```

Collect role accounts into a dedicated group and forbid switching into a
member of that group:

```bash
sudo groupadd -f tessera-roles
sudo usermod -aG tessera-roles serv
```

In `/etc/pam.d/su`, **above** the `auth sufficient pam_rootok.so` line:

```
auth       requisite   pam_succeed_if.so quiet user notingroup tessera-roles
```

`user` here is the *target* account of `su`, so the rule reads "the
switch is allowed only if the target is not a role account". It goes
above `pam_rootok.so` because otherwise `root` bypasses the check.
`root` cannot be shut out entirely anyway: it has `chsh`, direct edits
of `shadow` and a dozen other routes. The point of the line is to stop
`su serv` from being an everyday command for everyone else.

Both sides need verifying — that the prohibition took effect, and that
it did not catch everyone else. From an unprivileged account:

```bash
su - serv                     # expected: refused
su - <a-regular-account>      # expected: a password prompt and a login
```

The second command is mandatory. If it is refused as well, the problem
is not the rule but the line itself: with the module missing or
misspelled, `requisite` closes `su` entirely. Sort that out with a
second root shell open — recovery means editing `/etc/pam.d/su`.

For `sudo`, the same is done by a negation in the runas list:

```bash
sudo visudo -cf /etc/sudoers.d/40-tessera-roles   # after creating the file
```

Contents (create it through `visudo -f`, not `tee`):

```
%engineers ALL = (ALL, !%tessera-roles) ALL
```

One caveat matters here. A negation in a runas list only affects the
rule it is written in. If the engineer is granted `(serv) ALL` somewhere
else, or a broader rule appears later in the file, the last match wins
and the prohibition does not take effect. So check the result, not the
file:

```bash
sudo -l -U <engineer-account>
```

Expected: no line in the output permits running as `serv`.

#### PAM stacks without the module

Every service that authenticates and opens a session is a way in. A
stack without `pam_tessera` will let a caller into the role account on
its own terms, past the role and past `role.audit`. Check every stack
people actually enter the device through: `sshd`, `login`, `fly-dm` (and
the screen locker), `su`, `sudo`. What to add and where —
[pam-integration.md](pam-integration.md); `tessera check` catches module
ordering errors in stacks where the module is already present, but will
not tell you about a stack it was never added to.

### Verification (section 8)

```bash
ls -la /var/lib/tessera/roles/
id serv

# uid inside the regular-user range (product boundaries, see §8.3)
u=$(id -u serv)
[ "$u" -ge 1000 ] && [ "$u" -le 61183 ] \
    && echo "uid inside the regular-user range: ok"

sudo passwd -S serv
sudo test -e "$(getent passwd serv | cut -d: -f6)/.ssh/authorized_keys" \
    && echo "authorized_keys exists — find out where it came from"
sudo sshd -T -C user=serv,host=localhost,addr=127.0.0.1 \
    | grep -E '^(usepam|pubkeyauthentication|passwordauthentication)'
sudo sshd -T -C user=<a-regular-account>,host=localhost,addr=127.0.0.1 \
    | grep -E '^(usepam|pubkeyauthentication)'
sudo tessera check
```

Expected: `serv.toml` is present with `-rw-r--r-- root root`, `id serv`
prints uid/gid, the uid falls inside the regular-user range, `passwd -S`
shows `L` in the second column, nothing is printed about
`authorized_keys`, for `serv` — `usepam yes` with `pubkeyauthentication
no` and `passwordauthentication no`, for the other account — `usepam
yes` and `pubkeyauthentication yes` (the block did not leak past its
bounds), and `tessera check` finishes with no ERROR.

## 9. Editing `/etc/pam.d/*`

PAM-stack editing is split into a separate document —
**[docs/pam-integration.md](pam-integration.md)**:

- `integrate-pam.sh` and the shipped snippet
- The two-include pattern (0.3.12+) and the order of `pam_systemd.so`
- fly-dm (why + applying it + the screen locker)
- The three modes: `2fa` / `optional` / `cert-only`, with a lockout warning
- sudo, login, sshd
- The PAM stack with МКЦ in mind → [pam-integration.md §7](pam-integration.md#7-the-pam-stack-with-мкц-in-mind)
- Safety of the edit + recovery

> **IMPORTANT.** Open a second root shell before editing PAM.
> Detail — [pam-integration.md §8 "Safety of the edit"](pam-integration.md#8-safety-of-the-edit).

### Verification (section 9)

```bash
sudo tessera check
```

`tessera check` catches PAM-stack ordering errors (for example
`pam_stack_session_misorder`). The full authentication smoke test via
`pamtester` is in section 10.
## 10. Smoke test via `pamtester`

The name passed to `pamtester` is the name of the role account, which is
also the requested role.

### 10.1 Full cycle: auth + account + session

The `AuthContext` that `pam_sm_authenticate` stores via `pam_set_data`
only lives within one `pam_start()`/`pam_end()` — that is, one process
reading and writing the same PAM handle. Three separate `pamtester`
invocations are three independent handles, and the `account`/`session`
phases of such a run tell you nothing about how `pam_tessera` actually
behaves in the service under test — the module simply won't find the
context left by a previous invocation. That's why every operation that
must happen within a single login is passed to `pamtester` as one
list — so a single `pam_start()` covers the whole run:

```bash
pamtester sudo serv authenticate acct_mgmt open_session close_session
```

Positive result: `pamtester` prints `successfully` for each operation in
turn (four lines).

> `pamtester` is not a full login stack (it has no privilege separation
> between processes, unlike `sshd` or `login`), so this smoke test
> confirms the PAM stack and `pam_tessera` are correct, but does not
> replace checking through a real service. The difference, and the
> follow-up verification order, are in [pam-integration.md
> §9](pam-integration.md#9-pamtester-does-not-replace-a-real-login).

### 10.2 Negative test: remove the USB

In one terminal, run:

```bash
pamtester sudo serv authenticate
```

Right after entering it, remove the USB. Expected: `monitord` writes to
the journal:

```bash
sudo journalctl -u tessera -n 20 -g 'medium absent'
```

## 11. Troubleshooting

The full diagnostics reference is **[docs/troubleshooting.md](troubleshooting.md)**:

- Cert/auth errors (`host_binding mismatch`, a role outside `allowed_roles`, a general checklist)
- USB and tokens (`pcscd`, `Token PIN locked`, USBGuard, ЗПС)
- monitord and the daemon (`monitord not reachable`, a `failed` start)
- The PAM stack and lockout (`Logout requested but session has no logind id`, recovery from rescue.target)
- МКЦ (`pam_parsec_mac: Can't obtain required data`, `parsec.mac=0`, `mac_caps_missing`, `dmi_board_serial = 0`)
- fly-dm and the greeter (the wallpaper is not visible) — see also [fly-dm-greeter.md](fly-dm-greeter.md)
- Clone-image / golden image (`dump-host-id` empty, a repeated flip) — see also [clone-image.md](clone-image.md)
- Security incidents (a compromised cert, a lost token, CA worst-case, DIGSIG)

## 12. Hosts without systemd: SysV init

The package installs **both** init variants: `tessera.service` (systemd)
and `/etc/init.d/tessera` (SysV). On systemd hosts the SysV script does
not need to be touched. On non-systemd hosts:

```bash
sudo update-rc.d tessera defaults
sudo service tessera start
```

Details (caveats, the absence of logind logout) —
[pam-integration.md §10](pam-integration.md#10-hosts-without-systemd-sysv-init).
## Next steps

- [docs/configuration.md](configuration.md) — a reference to all
  `config.toml` parameters.
- [docs/cert-issuance.md](cert-issuance.md) — issuing credentials with
  the `pam_cert_host_binding` and `pam_cert_allowed_roles` extensions.
- [docs/operations.md](operations.md) — the operations runbook and
  incident-response procedures.
- [docs/threat-model.md](threat-model.md) — the threat model and which
  attacks the module protects against.

## МКЦ (MAC integrity): optional activation

Full activation of mandatory integrity control (МКЦ) (the capability to
the daemon, the shipped PAM stack, the systemd drop-in, per-user MNKC,
protecting `config.toml` via ilevel=63, verification, rollback) is a
separate document: **[docs/mac-integrity.md](mac-integrity.md)**.

The short path:

1. `astra-strictmode-control enable` + reboot.
2. `usercaps -m "+3" tessera` + `pdpl-user --ilevel 63 tessera`.
3. Copy `tessera.example` and `mac-integrity.conf.example` from
   `/usr/share/tessera/` into `/etc/pam.d/` and
   `/etc/systemd/system/tessera.service.d/`.
4. `pdpl-user --ilevel 63 <pam_user>` for each end user.
5. `[mac].cert_integrity = "required"` + `runtime = "required"`, restart
   the daemon.

The default (`cert_integrity = "ignore"`, `runtime = "disabled"`) is
production-ready without МКЦ activation. Nothing needs to be configured.

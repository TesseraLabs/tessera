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
identical. On Ubuntu/Debian it is best-effort, without GOST.

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
    pcsc-lite \
    pcscd \
    opensc-pkcs11 \
    gost-engine \
    pamtester
```

The exact package names match the Astra SE 1.7 repository. On
Ubuntu 22.04 the `gost-engine` package is not in the main repository —
you have to build it from source or take it from a third-party PPA, and
in that case the GOST functionality will not work (see the README,
"Supported operating systems" section).

### 1.4 Checking `gost-engine`

```bash
openssl engine gost -t
```

Expected: the output contains `[ available ]` and a list of available
algorithms, including `id-GostR3411-2012-256` (Streebog-256) and
`gost2012_256` (GOST 34.10-2012-256).

### Verification (section 1)

```bash
openssl dgst -engine gost -md_gost12_256 /etc/hostname
```

Expected: a 64-character hexadecimal hash in the output. If you got
`engine "gost" set.` without a hash, `gost-engine` connected but
something went wrong with the algorithm; the `gost-engine` version is
probably out of sync with the system OpenSSL. See the "What to do if…"
section.

### 1.5 Preflight: USBGuard and Astra ЗПС (DIGSIG)

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

```bash
# The release link is a placeholder; replace it with the real URL after
# v0.4.0 is published (usually GitHub Releases or the Astra Linux
# internal repository). The release publishes only the `.deb` in two
# variants (`…-astra.deb` and `…-ubuntu.deb`, plus `.changes` and
# `.buildinfo` for audit) — there are no ready-made checksum files there;
# the operator computes them on a trusted machine (see §2.2).
wget https://example.test/releases/tessera_0.4.0-1_amd64.deb
```

### 2.2 Generating the checksums (trusted machine)

The checksums are computed by the builder or the operator on a
**trusted** machine (not the target) with the `generate-checksums.sh`
script:

```bash
scripts/generate-checksums.sh tessera_0.4.0-1_amd64.deb checksums
```

The script puts a `checksums.txt` file into the `checksums/` directory —
a combined report of SHA-256 and Streebog-256 (GOST R 34.11-2012-256) for
the `.deb` itself and for every file inside the package — plus standalone
`*.sha256` and `*.streebog256` files. The Streebog-256 section requires
`gost-engine` (on Astra SE 1.7+ it is available by default); without it
the section is skipped, and SHA-256 is still computed.

Three things are delivered to the target machine: the `.deb` itself,
`checksums.txt`, and a copy of `verify-checksums.sh` (the script is
self-contained — the only external thing it needs is `openssl` with
`gost-engine` for the GOST section).

### 2.3 Verifying on the target machine

```bash
./verify-checksums.sh tessera_0.4.0-1_amd64.deb checksums.txt
```

Expected: `OK: N checksum(s) verified`. The script (described in
[scripts/verify-checksums.sh](../../scripts/verify-checksums.sh)) checks
both sums: SHA-256 always, Streebog-256 only if `checksums.txt` has a GOST
section and `gost-engine` is available on the machine. A non-zero exit
code means either a checksum mismatch (code 1) or a launch problem:
invalid arguments (2) or a missing `gost-engine` when a GOST section is
present (3). In any of these cases do not install the package until the
cause is understood.

### 2.4 Installation

```bash
sudo apt install ./tessera_0.4.0-1_amd64.deb
```

`apt` will pull in the missing dependencies (`libgost-engine | gost-engine`,
`libpkcs11-helper1`, `librtpkcs11ecp`).

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

Expected: version `0.4.0`, both `OK` lines.

## 3. Creating a test CA (GOST)

> The test CA is only suitable for a lab deployment. For production an
> external CA is used — see [docs/operations.md](operations.md).

### 3.1 Directory

```bash
mkdir -p /tmp/ca && cd /tmp/ca
```

### 3.2 CA key

```bash
openssl genpkey -engine gost -algorithm gost2012_256 \
    -pkeyopt paramset:A -out ca.key
chmod 0600 ca.key
```

### 3.3 CA certificate

```bash
openssl req -new -x509 -engine gost -key ca.key \
    -out ca.pem -days 3650 \
    -subj "/CN=tessera Test CA/O=Test/OU=Internal" \
    -addext "extendedKeyUsage=clientAuth" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
```

### 3.4 Check

```bash
openssl x509 -in ca.pem -text -noout | head -30
```

Expected line: `Signature Algorithm: GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)`.

### Verification (section 3)

```bash
openssl verify -CAfile ca.pem ca.pem
```

Expected: `ca.pem: OK`.

## 4. Creating a test role account

The role at login is the name of the login account: the engineer logs
into a **role account** named after the role (`ssh serv@device`), and the
requested role equals the name of that account. There is no separate
role prompt.

The rest of the scenario uses the role `serv` ("service engineer") — the
repository ships a ready-made role slice for it, `dist/roles/serv.toml`,
which is needed in §8. The login account is called `serv` as well; it is
created in §8, together with the role store.

### 4.1 Key

```bash
openssl genpkey -engine gost -algorithm gost2012_256 \
    -pkeyopt paramset:A -out serv.key
chmod 0600 serv.key
```

### 4.2 CSR

```bash
openssl req -new -engine gost -key serv.key -out serv.csr \
    -subj "/CN=service-engineer/UID=serv"
```

The engineer's identity lives in the credential and in the issuance
journal, not in the name of the login account. The `CN` does not affect
authorization: the decision is made from the extensions in §4.3.

### 4.3 Signing the CSR

The leaf must carry **three** extensions:

| Extension | OID | Question it answers |
|-----------|-----|---------------------|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` | on which devices the bearer may log in |
| `pam_cert_user_binding` | `2.25.215438916728501023845629178354627` | is the bearer admitted into this account |
| `pam_cert_allowed_roles` | `2.25.185305973969816596290730578528098241367` | is the bearer allowed to activate this role |

Each is a `SEQUENCE OF UTF8String`; `pam_cert_allowed_roles` is issued
non-critical. The OIDs and the ASN.1 syntax are from
[cert-issuance.md](cert-issuance.md).

`user_binding` and `allowed_roles` are two different statements by the
issuer, and in the target model both apply to the same name. The first
permits entry into the account, the second permits activation of the
role. A credential that admits into the account `serv` but does not
permit the role `serv` is a legitimate configuration: such a credential
must refuse the login, because role coverage is proven precisely by
`pam_cert_allowed_roles`.

Without any one of the three the module rejects authentication
**fail-closed**: a missing host/user extension yields
`HostExtensionMissing` / `UserExtensionMissing`, and a missing
`pam_cert_allowed_roles` means the credential grants no role at all —
while a role is required at every login. In both cases §7 will not find
the OID in the credential, and `pamtester` in §10 will not pass.

First find out this machine's `host_id_hash` — the source the daemon uses
right now (the row with `active_under_current_config=yes`, column
`hash_hex`):

```bash
HOST_HASH=$(sudo tessera dump-host-id | awk -F'\t' '$7 == "yes" { print $3 }')
echo "host_id_hash = ${HOST_HASH}"   # 64 hex characters
```

Assemble the `extfile` with all three extensions (host — only this
machine, account — only `serv`, role — only `serv`):

```bash
cat > serv.ext <<EOF
extendedKeyUsage = clientAuth
keyUsage = critical,digitalSignature

# Host: only this machine (host_id_hash obtained above)
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb
# Login account: only serv
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub
# Roles the credential may activate: only serv
2.25.185305973969816596290730578528098241367 = ASN1:SEQUENCE:ar

[ hb ]
e0 = UTF8String:sha256:${HOST_HASH}

[ ub ]
e0 = UTF8String:serv

[ ar ]
e0 = UTF8String:serv
EOF
```

Sign the CSR with this `extfile`:

```bash
openssl x509 -req -engine gost -in serv.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out serv.pem -days 365 \
    -extfile serv.ext
```

### 4.4 Packing into P12

```bash
openssl pkcs12 -export -engine gost -inkey serv.key -in serv.pem \
    -out serv.p12 -name serv -passout pass:test
chmod 0600 serv.p12
```

### Verification (section 4)

```bash
openssl pkcs12 -in serv.p12 -nokeys -passin pass:test \
    | openssl x509 -noout -subject
```

Expected: `subject=CN=service-engineer, UID=serv` (the exact RDN order
depends on the OpenSSL version).

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
password is from §4.4):

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

> The behavior of `--write-object` for GOST keys depends on the token model
> and the `librtpkcs11ecp` version — check it on your token model.

### Verification (section 6)

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --pin '1234567890' -O
```

Expected: the output contains a `Private Key Object` and a
`Certificate Object` with `label=serv`.

## 7. Authorization: credential extensions

The binding of "who, on which device, in which role" lives in the
credential itself. The PAM module reads three X.509 v3 extensions of the
leaf:

- `pam_cert_host_binding` (OID `2.25.183976554325829274683049824615098`)
  — the list of allowed devices;
- `pam_cert_user_binding` (OID `2.25.215438916728501023845629178354627`)
  — the list of allowed login accounts;
- `pam_cert_allowed_roles`
  (OID `2.25.185305973969816596290730578528098241367`, non-critical)
  — the list of roles the credential may activate.

The last two are checked independently, even though in the role-account
model they refer to the same name: `user_binding` permits entry into the
account, `allowed_roles` permits activation of the role. A rejection by
any of the three is fail-closed.

Ready-made `openssl.cnf` recipes for issuing credentials with the
correct extensions are given in [cert-issuance.md](cert-issuance.md).

### Verification (section 7)

```bash
openssl x509 -in /tmp/ca/serv.pem -noout -text \
    | grep -E '2\.25\.(183976554325829274683049824615098|215438916728501023845629178354627|185305973969816596290730578528098241367)'
```

Expected: all three dotted-OID lines are present in the output.

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

The account name *is* the role, so the system account `serv` must exist
on the device. Across a fleet, role accounts are provisioned separately;
for a lab bench this is enough:

```bash
sudo useradd --system --create-home --shell /bin/bash serv
```

No password is set for it: entry into a role account is open only
through Tessera certificate authentication.

### Verification (section 8)

```bash
ls -la /var/lib/tessera/roles/
id serv
sudo tessera check
```

Expected: `serv.toml` is present with `-rw-r--r-- root root`, `id serv`
prints uid/gid, `tessera check` finishes with no ERROR.

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

### 10.1 Authentication

```bash
pamtester sudo serv authenticate
```

Positive result: `pamtester: successfully authenticated`.

### 10.2 Session

```bash
pamtester sudo serv open_session
pamtester sudo serv close_session
```

Positive result: both calls return `pamtester: successfully ...`.

### 10.3 Negative test: remove the USB

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

- Cert/auth errors (`host_binding mismatch`, `user_binding mismatch`, a general checklist)
- USB and tokens (`pcscd`, `Token PIN locked`, USBGuard, ЗПС)
- monitord and the daemon (`monitord not reachable`, a `failed` start)
- The PAM stack and lockout (`Logout requested but session has no logind id`, recovery from rescue.target)
- МКЦ (`pam_parsec_mac: Can't obtain required data`, `parsec.mac=0`, `mac_caps_missing`, `dmi_board_serial = 0`)
- fly-dm and the greeter (the wallpaper is not visible) — see also [fly-dm-greeter.md](fly-dm-greeter.md)
- Clone-image / golden image (`dump-host-id` empty, a repeated flip) — see also [clone-image.md](clone-image.md)
- Security incidents (a compromised cert, a lost token, CA worst-case, DIGSIG)
- Installation / `gost-engine`
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
  the `pam_cert_host_binding`, `pam_cert_user_binding` and
  `pam_cert_allowed_roles` extensions.
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

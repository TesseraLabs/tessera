# Installing Tessera on Astra Linux SE

This document is a step-by-step scenario for installing and doing the
basic configuration of `tessera` on a clean Astra Linux SE 1.7+
machine. Every section ends with a verification command. If the check
fails, read the "What to do if…" section at the end of the document.

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
# internal repository).
wget https://example.test/releases/tessera_0.4.0-1_amd64.deb
wget https://example.test/releases/tessera_0.4.0-1_amd64.deb.sha256
wget https://example.test/releases/tessera_0.4.0-1_amd64.deb.streebog256
```

### 2.2 SHA-256 verification

```bash
sha256sum -c tessera_0.4.0-1_amd64.deb.sha256
```

Expected: `tessera_0.4.0-1_amd64.deb: OK`.

### 2.3 Streebog-256 verification

```bash
./scripts/verify-checksums.sh \
    tessera_0.4.0-1_amd64.deb \
    checksums/checksums.txt
```

The script is described in [scripts/verify-checksums.sh](../../scripts/verify-checksums.sh)
and checks both sums (SHA-256 and Streebog-256). See
[configuration.md](configuration.md) for details.

### 2.4 Installation

```bash
sudo apt install ./tessera_0.4.0-1_amd64.deb
```

> Since 0.2.0 the `tessera-monitord` binary has been renamed to
> `tessera`. Daemon mode is started as `tessera daemon`; the systemd
> unit `tessera.service` already uses the new name.

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
  2. (0.3.12+) `session required pam_tessera.so` stands BEFORE
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

## 4. Creating a test user

### 4.1 alice's key

```bash
openssl genpkey -engine gost -algorithm gost2012_256 \
    -pkeyopt paramset:A -out alice.key
chmod 0600 alice.key
```

### 4.2 CSR

```bash
openssl req -new -engine gost -key alice.key -out alice.csr \
    -subj "/CN=Alice/UID=alice"
```

### 4.3 Signing the CSR

```bash
openssl x509 -req -engine gost -in alice.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out alice.pem -days 365 \
    -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n")
```

### 4.4 Packing into P12

```bash
openssl pkcs12 -export -engine gost -inkey alice.key -in alice.pem \
    -out alice.p12 -name alice -passout pass:test
chmod 0600 alice.p12
```

### Verification (section 4)

```bash
openssl pkcs12 -in alice.p12 -nokeys -passin pass:test \
    | openssl x509 -noout -subject
```

Expected: `subject=CN=Alice, UID=alice` (the exact RDN order depends on
the OpenSSL version).

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

> Since 0.3.5: if the USB stick has several partitions and some of them
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
sudo cp /tmp/ca/alice.p12  /mnt/usb/certs/user.p12
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
    --init-token --label "alice-token" \
    --so-pin '12345678'
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --init-pin --so-pin '12345678' --pin '1234567890'
```

### 6.4 Importing the key and certificate

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --login --pin '1234567890' \
    --write-object alice.pem --type cert --label alice --id 01
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --login --pin '1234567890' \
    --write-object alice.p12 --type privkey --label alice --id 01
```

### Verification (section 6)

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --pin '1234567890' -O
```

Expected: the output contains a `Private Key Object` and a
`Certificate Object` with `label=alice`.

## 7. Authorization: certificate extensions

The binding of "which user on which host" lives in the certificate
itself. The PAM module reads two X.509 v3 extensions of the leaf
certificate:

- `pam_cert_host_binding` (OID `2.25.183976554325829274683049824615098`)
  — the list of allowed hosts;
- `pam_cert_user_binding` (OID `2.25.215438916728501023845629178354627`)
  — the list of allowed PAM users.

Ready-made `openssl.cnf` recipes for issuing certificates with the
correct extensions are given in [cert-issuance.md](cert-issuance.md).

### Verification (section 7)

```bash
openssl x509 -in /tmp/ca/alice.pem -noout -text \
    | grep -E '2\.25\.(183976554325829274683049824615098|215438916728501023845629178354627)'
```

Expected: both dotted-OID lines are present in the output.

## 8. Editing `/etc/pam.d/*`

PAM-stack editing is split into a separate document —
**[docs/pam-integration.md](pam-integration.md)**:

- `integrate-pam.sh` and the shipped snippet
- The two-include pattern (0.3.12+) and the order of `pam_systemd.so`
- fly-dm (why + applying it + the screen locker)
- The three modes: `2fa` / `optional` / `cert-only`, with a lockout warning
- sudo, login, sshd
- The PAM stack with МКЦ in mind → [mac-integrity.md](mac-integrity.md)
- Safety of the edit + recovery

> **IMPORTANT.** Open a second root shell before editing PAM.
> Detail — [pam-integration.md §1](pam-integration.md).

### Verification (section 8)

```bash
pamtester sudo alice authenticate
sudo tessera check
```

Expected: `Authentication successful` (with the USB or token inserted).
`tessera check` catches PAM-stack ordering errors (for example
`pam_stack_session_misorder`).
## 9. Smoke test via `pamtester`

### 9.1 Authentication

```bash
pamtester sudo alice authenticate
```

Positive result: `pamtester: successfully authenticated`.

### 9.2 Session

```bash
pamtester sudo alice open_session
pamtester sudo alice close_session
```

Positive result: both calls return `pamtester: successfully ...`.

### 9.3 Negative test: remove the USB

In one terminal, run:

```bash
pamtester sudo alice authenticate
```

Right after entering it, remove the USB. Expected: `monitord` writes to
the journal:

```bash
sudo journalctl -u tessera -n 20 -g 'medium absent'
```

## 10. Troubleshooting

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
## 11. Hosts without systemd: SysV init

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
- [docs/cert-issuance.md](cert-issuance.md) — issuing certificates with
  the `pam_cert_host_binding` and `pam_cert_user_binding` extensions.
- [docs/operations.md](operations.md) — the operations runbook and
  incident-response procedures.
- [docs/threat-model.md](threat-model.md) — the threat model and which
  attacks the module protects against.

## MIC (MAC integrity): optional activation

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

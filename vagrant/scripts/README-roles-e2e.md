# role-format E2E — runbook

Manual E2E for the `role-format` change (`pam_cert_allowed_roles` X.509
extension + on-device role store + `user+role` login selection). Mirrors the
MAC runbook (`test-mac.sh`). Not wired into CI — `vagrant up` is too expensive
for per-PR runs.

**Validated end-to-end on Astra SE 1.8.4 (2026-06-15)** — all five scenarios
(R1–R5) reproduce as asserted (results table below).

The harness drives the **PAM auth phase** through a dedicated throwaway
service (`/etc/pam.d/tessera-roletest`, auth-only) with `pamtester`. It never
modifies `sshd`/`login`/`sudo`. Role resolution + `allowed_roles` coverage run
in the auth phase (`crates/pam_tessera/src/flow.rs::resolve_role_stage`), so a
coverage/resolve failure denies auth — which is exactly what `pamtester
... authenticate` observes.

## How the credential reaches the module (loop + udev USB emulation)

The production module reads the leaf as a PKCS#12 at the configured
`pkcs12_path_pattern` (default `certs/user.p12`) on a **USB block device**
discovered via udev (`ID_BUS=usb`, block subsystem). The VM has no real USB, so
the harness emulates one with a **loopback FAT image + a udev rule that forces
`ID_BUS=usb` on `loop*` devices**:

1. Build a 16 MiB FAT image, seed `certs/user.p12`:
   ```sh
   dd if=/dev/zero of=/var/lib/tessera/usbtok.img bs=1M count=16 status=none
   mkfs.vfat /var/lib/tessera/usbtok.img
   mount -o loop /var/lib/tessera/usbtok.img /mnt/...; \
     mkdir -p /mnt/.../certs; cp role-serv.p12 /mnt/.../certs/user.p12; umount /mnt/...
   ```
2. udev rule `/etc/udev/rules.d/99-tessera-roletest.rules`:
   ```
   SUBSYSTEM=="block", KERNEL=="loop*", ENV{ID_BUS}="usb", ENV{ID_VENDOR_ID}="dead", ENV{ID_MODEL_ID}="beef", ENV{ID_SERIAL_SHORT}="TESSERATEST01"
   ```
   then `udevadm control --reload-rules`.
3. Attach + announce:
   ```sh
   LOOP=$(losetup --find --show /var/lib/tessera/usbtok.img)
   udevadm trigger --action=add "$LOOP"; udevadm settle
   udevadm info --query=property "$LOOP"   # must show ID_BUS=usb, ID_FS_TYPE=vfat
   ```
4. **Per-scenario leaf swap** = mount `/dev/loopN`, replace `certs/user.p12`,
   `umount` (the loop device stays attached + announced throughout).

`setup_usb()`/`teardown_usb()`/`stage_leaf()` in `test-roles.sh` implement all
of this; an `EXIT` trap detaches the loop, removes the udev rule, and reloads
rules. It never touches `sshd`/`login`/`sudo`.

> The same loop+udev USB-emulation technique applies to the MAC harness
> (`test-mac.sh`), whose fixtures share the missing host/user-binding gap —
> their leaves also need the mandatory cert extensions (below) and a USB to be
> presented on. Reuse this block when wiring per-scenario leaves there.

## The PIN

The module raises a single `PAM_PROMPT_ECHO_OFF` for the PKCS#12 export
password. The fixture bundles use **`123456`** (override with `PIN=...`). The
harness feeds it on stdin: `printf '%s\n' "$PIN" | pamtester ... authenticate`.

## Mandatory cert extensions on every leaf

`verify_host_binding` is **fail-closed on a missing extension**
(`crates/pam_tessera/src/flow.rs`), so each leaf `.cnf` carries **three**
extensions (see `tests/fixtures/roles/*.cnf`):

| Extension | OID | DER (test value) |
|-----------|-----|------------------|
| `pam_cert_host_binding` (**mandatory**) | `2.25.183976554325829274683049824615098` | `DER:30:03:0c:01:2a` — `["*"]` wildcard host |
| `pam_cert_user_binding` | `2.25.215438916728501023845629178354627` | `DER:30:08:0c:06:69:76:61:6e:6f:76` — `["ivanov"]` |
| `pam_cert_allowed_roles` | `2.25.185305973969816596290730578528098241367` | `[serv]` / `[oper]` / malformed per file |

The cert-driven `user_binding` (`ivanov`) wins, so no `[[user_mapping]]` entry
is needed in the config.

## OID and DER (locked)

- `pam_cert_allowed_roles` OID:
  `2.25.185305973969816596290730578528098241367`
  (`crates/tessera_core/src/x509/oids.rs::ALLOWED_ROLES_OID`).
- `extnValue ::= SEQUENCE OF UTF8String`, each entry a `role_id`
  (`^[a-z][a-z0-9-]{0,15}$`). Fail-closed: malformed DER **or** any bad
  `role_id` rejects the whole list (no per-string skip). Absent extension =
  cert grants no roles.
- DER bodies used by the fixtures:
  - `[serv]` → `30 06 0c 04 73 65 72 76`
  - `[oper]` → `30 06 0c 04 6f 70 65 72`
  - malformed → `30 05 0c 01` (SEQUENCE claims 5 octets, truncated
    UTF8String — same shape as the `malformed_der_returns_err` unit test).

## Prerequisites on the VM

1. Package installed: `/lib/security/pam_tessera.so` + `tessera` CLI on PATH
   (`>= 0.4.0`, role-format compiled in). Install the `.deb` as in
   `tests/scripts/install-and-test.sh`.
2. A working **base** config at `/etc/tessera/config.toml` (the harness copies
   it to `base-config.toml` and appends a `[roles]` section per scenario). It
   must NOT already contain a `[roles]` section. The base used for the proven
   run was:
   ```toml
   mode = "pkcs12"
   pkcs12_path_pattern = "certs/user.p12"
   monitor_fail_mode   = "permissive"   # monitord NOT required for auth phase
   [trust]
   anchors = ["/etc/tessera/ca/bundle.pem"]
   [trust.revocation]
   mode = "none"
   [host_identity]
   sources  = ["machine_id", "hostname"]
   fallback = "deny"
   [logging]
   level = "debug"
   ```
   With `monitor_fail_mode="permissive"` the auth flow logs `monitord call
   failed (permissive mode, ignoring)` and **succeeds without `tessera.service`
   running** — no daemon needed for the auth phase.
3. CA trust anchor at `/etc/tessera/ca/bundle.pem` = the CA that signed the
   role leaves (`tests/fixtures/roles/ca.crt.pem`, the shared test CA).
4. `pamtester` installed (already in `vagrant/provision.sh`).
5. `losetup` (util-linux), `mkfs.vfat` (dosfstools), and `udevadm` (udev)
   available — used by `setup_usb()` for the loop USB emulation.

## Build the fixtures (on the build host)

```sh
cd tests/fixtures/roles
# Shared test CA (same one setup-mac-fixtures.sh uses):
cp ../../../crates/tessera_core/tests/fixtures/ca.key ca.key.pem
cp ../../../crates/tessera_core/tests/fixtures/ca.pem ca.crt.pem
./gen-role-certs.sh
# Produces role-serv / role-oper / role-malformed .{key,crt}.pem
openssl x509 -in role-serv.crt.pem -noout -text | grep -A2 2.25.1853   # sanity

# Bundle each leaf as the PKCS#12 the module reads off the USB (export
# password = the PIN, default 123456). The harness stages role-<x>.p12, not
# the raw PEMs:
for n in role-serv role-oper role-malformed; do
  openssl pkcs12 -export -out "$n.p12" \
    -inkey "$n.key.pem" -in "$n.crt.pem" -passout pass:123456
done
```

The checked-in `role-*.p12` bundles already use `123456`; regenerate only when
rotating the CA or changing the leaf set.

## Deploy to the VM

```sh
# Leaf PKCS#12 bundles the harness reads (one per scenario):
ssh "$VM" 'sudo install -d -m0755 /etc/tessera/test/roles/leaves /etc/tessera/test/roles/store'
scp tests/fixtures/roles/role-*.p12      "$VM":/tmp/
scp tests/fixtures/roles/store/serv.toml "$VM":/tmp/
ssh "$VM" 'sudo mv /tmp/role-*.p12 /etc/tessera/test/roles/leaves/ && \
           sudo mv /tmp/serv.toml  /etc/tessera/test/roles/store/'

# Base config the harness extends with [roles] (must have no [roles] yet):
ssh "$VM" 'sudo cp /etc/tessera/config.toml /etc/tessera/test/roles/base-config.toml'

# The harness + this README:
scp vagrant/scripts/test-roles.sh "$VM":/tmp/ && \
  ssh "$VM" 'sudo install -m0755 /tmp/test-roles.sh /usr/local/sbin/test-roles.sh'
```

## Run

```sh
ssh "$VM" 'sudo /usr/local/sbin/test-roles.sh'
# Override the PIN / image paths if needed:
ssh "$VM" 'sudo PIN=123456 USB_IMG=/var/lib/tessera/usbtok.img /usr/local/sbin/test-roles.sh'
```

Exit `0` = all scenarios passed; `1` = one or more failed; `2` = setup
precondition missing. The harness provisions the loop USB once, swaps the p12
per scenario, and always tears the loop + udev rule down on exit.

## Expected evidence per scenario

The PAM module logs via syslog auth facility (ident `pam_tessera`), so events
land in journald under `-t pam_tessera`. Field names are the `role.audit`
schema (`crates/tessera_core/src/role/audit.rs`).

All five **PASSED on Astra SE 1.8.4 (2026-06-15)**.

| # | Login | Cert `allowed_roles` | Store | `enforce` | pamtester | journald audit (proven) |
|---|-------|----------------------|-------|-----------|-----------|----------------|
| R1 | `ivanov+serv` | `[serv]` | has `serv` | `require` | **success (0)** | `event="role_session_open" user="ivanov" role="serv" role_version=1 method="cert" ttl=14400` |
| R2 | `ivanov+serv` | `[oper]` | has `serv` | `require` | **deny (1)** | `event="role_deny" reason="not_covered"` |
| R3 | `ivanov+serv` | `[serv]` | empty | `require` | **deny (1)** | `event="role_deny" reason="not_found"` |
| R4 | `ivanov+serv` | malformed | has `serv` | `require` | **deny (1)** | `event="cert_allowed_roles_parse_failed"` + `event="role_deny" reason="not_covered"` |
| R5 | `ivanov+serv` | `[oper]` | has `serv` | `false` | **success (0)** | no `role_deny`, no `role_session_open` (selection skipped) |

`ttl=14400` in R1 comes from the store slice's `session.max_ttl_seconds`
(4h, in `store/serv.toml`), which caps the config's
`default_session_ttl_seconds = 43200`.

Inspect manually:

```sh
journalctl -t pam_tessera --since "2 min ago" --no-pager | grep -E 'event=|reason='
```

## Scope notes

- **Per-scenario leaf staging — proven.** `stage_leaf()` is no longer a stub:
  it mounts the attached loop USB, replaces `certs/user.p12` with the scenario's
  `role-<x>.p12`, syncs, and unmounts (the loop device stays attached +
  udev-announced, so the module re-reads the new leaf on the next auth without
  re-triggering udev). `setup_usb()` provisions the loop+udev USB once;
  `teardown_usb()` (run from an `EXIT` trap) detaches it and removes the rule.
- **R1 group application is not asserted live.** Applying supplementary groups
  `service` + `wheel` is a later session/daemon phase, not the auth path the
  harness drives. R1 asserts the `role_session_open` audit event (which
  records the resolved role, version, and bounded TTL) as the auth-phase proof
  the `serv` payload was selected and fixed. To check live group membership,
  drive `open_session` against a session-aware service and inspect the
  session — out of scope for this auth-phase harness.
- **Standalone trust only.** The store fixture (`store/serv.toml`) uses the
  filesystem-permission (sudoers.d) trust model — `root:root`, dir `0755`,
  files `0644`, no manifest. This matches what the PAM module loads
  (`RoleStore::load(.., TrustMode::Standalone)` in
  `crates/pam_tessera/src/entry.rs`). The managed/signed-bundle path
  (`load_managed`, Ed25519 `manifest.toml`) is intentionally **not** exercised
  here: there is no `tessera role sign` subcommand (`crates/tessera_cli/src/role.rs`
  exposes only `lint` and `list`), so a signed manifest cannot be produced with
  the shipped CLI. Add a managed-mode scenario once a signing tool exists.
```

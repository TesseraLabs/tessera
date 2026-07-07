# Rolling out a workstation fleet from a cloned image

An end-to-end runbook: from preparing the reference image to a per-host
certificate on every production workstation. The scenario applies when a
single Astra SE image is rolled out onto dozens/hundreds of machines (typically
a terminal fleet), and each workstation's `host_id` is known only after the
first boot on real hardware.

> Companion documents:
> - [install.md](install.md) — step-by-step installation of `tessera` (performed on the reference machine).
> - [configuration.md](configuration.md) — the `config.toml` reference.
> - [cert-issuance.md](cert-issuance.md) — certificate structure and issuance.
> - [operations.md](operations.md) — the operations runbook.

## 1. Why a bootstrap mode

A `tessera` certificate is bound to the workstation's `host_id_hash` (the
`pam_cert_host_binding` extension). When a reference image is cloned:

- `machine_id` is identical across all clones (unless reset on first boot);
- `dmi_board_serial` is unique to each piece of hardware;
- `hostname` is assigned by the operator/Ansible.

The reference image cannot contain a per-host certificate — it does not exist at
build time. The solution: a bootstrap certificate with a fixed
`host_binding = "installation"` + a `config.toml` that resolves `host_id` to
that same value via `[host_identity].sources = ["override"]`. Bootstrap passes
auth on any machine deployed from the image. After the first boot the operator
switches the workstation to a real source (`dmi_board_serial` / `machine_id`)
and takes a dump — now the real `host_id_hash` is known, from which the CA
issues the per-host certificate.

## 2. Preparing the reference image

The steps are performed once, on the reference machine, before taking the image.

### 2.1 Installing `tessera`

See [install.md §1–§8](install.md). All sections are performed in full, except
the personal USB medium (section 5): instead of the per-user/.p12, a
**bootstrap chain** is placed on the reference machine.

### 2.2 The bootstrap certificate

Issued by the CA tools in bootstrap mode (see §6.1). The certificate must
contain the extensions:

- `pam_cert_host_binding = "installation"` (a marker string, **not** a hash);
- `pam_cert_user_binding = <service_user>`;
- the standard `extendedKeyUsage = clientAuth, emailProtection`.

`emailProtection` is required not by `tessera` but by the **stock Astra
validator** (openssl `CMS_verify`) — without this EKU it rejects the chain (see
[cert-issuance.md](cert-issuance.md)).

### 2.3 `config.toml` on the reference machine

```toml
# /etc/tessera/config.toml (fragment)

[host_identity]
sources = ["override"]
override = "installation"

[fly_dm_greeter]
update_wallpaper = true     # see §2.4
```

`sources = ["override"]` + `override = "installation"` forces the daemon to
resolve `host_id` to the string `installation` on any clone machine — exactly
what is baked into the bootstrap cert.

### 2.4 Wallpaper banner (optional, recommended on МКЦ-3)

On production fly-qdm 2.15+ under МКЦ-3 the fly-modern theme hardcodes the
rendering of `"Усиленный уровень защищенности"` in the headline slot —
PAM_TEXT_INFO with `host_id` is **not visible** in the greeter UI. Workaround:
print `host_id` directly onto the JPG background that `[background].path` in
`/etc/X11/fly-dm/fly-modern/settings.ini` points at.

It is enabled with a single line in `config.toml`:

```toml
[fly_dm_greeter]
update_wallpaper = true
```

Defaults (all overridable):

| Field                 | Value                                                   |
|-----------------------|---------------------------------------------------------|
| `wallpaper_target`    | `/usr/share/wallpapers/fly-default-light.jpg`           |
| `wallpaper_backup`    | `/var/lib/tessera/wallpaper.orig.jpg`              |
| `wallpaper_font`      | `/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf`  |
| `wallpaper_font_size` | `64`                                                    |
| `wallpaper_text_color`| `#000000`                                               |
| `wallpaper_gravity`   | `south`                                                 |
| `wallpaper_offset_x`  | `0`                                                     |
| `wallpaper_offset_y`  | `120`                                                   |
| `template_ru`         | `Устройство %n  host_id={host_id_short} ({source})`       |
| `template_en`         | `Device %n  host_id={host_id_short} ({source})`            |

At each start of `tessera.service`:

1. First time: `cp wallpaper_target → wallpaper_backup` (one-time original).
2. Opens `wallpaper_backup` as the source.
3. Renders `template_ru`/`template_en` (by locale), substituting
   `{host_id_short}` (the first 8 hex), `{source}`, `%n` (hostname).
4. Atomic save → `wallpaper_target`.

The daemon **does not edit** `settings.ini` (the operator/ansible manages
`blur`, `color_overlay`, `path`). On the reference machine, the baseline:

```ini
# /etc/X11/fly-dm/fly-modern/settings.ini
[background]
path=/usr/share/wallpapers/fly-default-light.jpg
color_overlay=0,0,0,30

[background][blur]
enable=false
```

With a strong `color_overlay` or blur enabled the text is invisible — lower the
alpha and disable blur before taking the image.

### 2.5 Validating the reference machine

```bash
sudo tessera check
```

It must return exit 0. On the reference machine the daemon log is expected to
show INFO `fly-dm wallpaper update finished` (target `tessera.fly_dm_greeter`)
and `host_identity: probe selected` with `source=Override`.

### 2.6 Taking the image

The standard path (`dd`, Clonezilla, vSphere template — at the integrator's
discretion). Before taking it:

- stop `tessera.service` (`systemctl stop tessera`);
- clear `/var/lib/tessera/sessions.json` (optional, not critical);
- **do not clear** `/etc/machine-id` — after the flip it stops being used, but
  until that moment a consistent override is needed.

## 3. Rolling a clone out to a production workstation

The clone boots, the bootstrap chain is in effect — auth works. `host_id` is
still `installation` on every machine.

> At this stage **do not issue** per-host certificates: `host_id_hash` is not
> yet known.

## 4. Flip → production: `finish-bootstrap.sh`

The single command the operator runs on each workstation after the first boot:

```bash
sudo /usr/share/tessera/finish-bootstrap.sh
```

### 4.1 What the script does

Atomic, single-pass:

1. **Rewrite `config.toml`**:
   - `[host_identity].sources = ["override"]` → `["dmi_board_serial", "machine_id"]` (default);
   - the `override = "..."` line is commented out (`#override = "..."`).
   - Backup → `/etc/tessera/config.toml.bak.<UTC-ISO8601>`.
2. **Validates** the new config: `tessera check`. If ERROR — roll back the
   backup, exit ≠ 0.
3. **Restarts** `tessera.service`, waits for `is-active=active` up to 30 s.
4. **Takes a dump**: `tessera dump-host-id --usb` with retries (up to 60 s for
   the USB to appear, polling every 5 s). Fallback: TSV in
   `/var/lib/tessera/host-ids-<hostname>-<UTC>.tsv`.

### 4.2 Flags

| Flag                          | Purpose                                                                                                                            |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `--non-interactive`           | Skip confirmations. For Ansible.                                                                                                   |
| `--sources "A,B"`             | Replace the production source list. Or the `POST_INSTALL_SOURCES` variable. Default: `dmi_board_serial,machine_id`.                |
| `--no-restart`                | Rewrite + check only, no restart. For a dry-run.                                                                                   |
| `--no-dump`                   | Skip step 4. If the operator will take the dump later.                                                                             |

### 4.3 Idempotency

The script detects `sources = ["override"]` in the current `config.toml`:

- present → runs the full pipeline;
- absent → exit 0 with no changes (the workstation is already flipped).

Safe to re-run in any Ansible rollout.

### 4.4 TSV dump format

Columns:

```
source  status  hash_hex  hash_prefix  raw  normalized  active_under_current_config  reason
```

One row per **known** source (not only the configured ones): `machine_id`,
`dmi_board_serial`, `dmi_system_uuid`, `dmi_system_serial`, `hostname`, plus
`custom_command` (if in the config) and always the synthetic `override` row
(with `status=err` when the override is not configured). The row with
`active_under_current_config=yes` is the source the daemon is using **right
now**. From it the CA admin takes `hash_hex`.

`status` ∈ {`ok`, `err`}. `reason` explains `err` (empty value,
`dmi_board_serial = 0` in a VM, `custom_command exited 1`, etc.).

`dump-host-id` exits ≠ 0 if **all** known sources returned empty/error — an
unambiguous "do not issue the certificate until the login is fixed" signal.

## 5. Returning the USB stick to the reference side

The operator physically brings the USB to the CA admin (or hands over the TSV
through a secure channel — these are just hashes, not secrets).

## 6. The CA side: issuing the per-host certificate

### 6.1 The CA tools

The CA tools (PKI setup, certificate issuance in per-host / wildcard / bootstrap
modes, USB-medium preparation) are **not included** in the `.deb` or in this
repository — they must not sit on production workstations. They are shipped
separately; they are kept on the CA machine (HSM/Vault host).

### 6.2 Issuance

The admin reads the `active_under_current_config=yes` row from the TSV, takes
`hash_hex`, and issues the per-host certificate with the CA tool.

The certificate receives the extensions:

- `pam_cert_host_binding = <host_id_hash>` (binding to the workstation);
- `pam_cert_user_binding = service`;
- `pam_cert_max_integrity = <level>` if applicable (МКЦ).

### 6.3 Packing onto the USB

The resulting `.p12` is packed onto the operator's USB stick by the CA tool: the
old `.p12`s are deleted, the new one is written with permissions `0600`, the
medium is unmounted.

**Enrollment package (tags + the first bundle).** Alongside the per-host `.p12`,
the CA places an **enrollment package** on the same returning USB — for a device
that needs tags (group delegation) and/or a role database at rollout. This is
the CA-side contract (format — the `device-enrollment` change):

- **managed** (with a server): a signed `manifest.toml` (Ed25519) with the
  device's tags, the role database, and the CRL pin + the CRL file itself. The
  signature and the monotone `bundle_version` (anti-rollback) are the same as for
  `role-store`; tags/roles/CRL are not secret → they travel in the clear (the PIN
  protects only the `.p12`).
- **standalone** (without a server): a tags file + role slices under filesystem
  permissions (`root:root`, dir `0755`, files `0644`), unsigned.

The tags/bundle are not secret and grant no access on their own — access is
still through the PIN-protected `.p12`; Engine does not interpret the tag names
(generic data, handled uniformly without hardcoded keys). A malformed/broken
package → the import is rejected fail-closed, the device stays in its previous
state.

### 6.4 Tag assignment — the server side

A device **accepts** tags from a trusted source but does not **decide** them
itself (otherwise the delegation envelope would be bypassed). The
`hash_hex → tags` mapping is the responsibility of the Control inventory (or the
operator at install): from the TSV dump (`hash_hex`) the server/operator picks
the device's tags (`region`, `class`, …) and puts them in the signed manifest
(managed) or in the standalone file. An arbitrary local tag config on the device
is **not accepted** as a source.

## 7. Returning the USB stick to the workstation

The operator plugs the USB back into the production workstation.

- the bootstrap cert on the stick is erased by step 6.3;
- the per-host cert passes auth → `host_binding` matches `host_id_hash`;
- the bootstrap chain in the trust store **remains valid** (in case of a repeat
  flip after a hardware change), but the cert on the USB no longer uses it.

**Importing the enrollment package (if present).** If the CA placed an
enrollment package on the return (§6.3), import it after `finish-bootstrap`:

```bash
# managed (signed manifest) — the verification key is given by a flag
tessera enroll --import /run/media/usb --manifest-pubkey /etc/tessera/ca/manifest.pub
# standalone (without a server)
tessera enroll --standalone --import /run/media/usb
```

The import is atomic and idempotent: repeating the same `bundle_version` is a
no-op, a smaller one is rejected (anti-rollback), a larger one is applied. After
a successful import, `tessera check` runs automatically; a failure → rollback,
exit ≠ 0 (fail-closed). The report prints `host_id` (prefix8), the cert serial,
`bundle_version`, and the mode; a `device_enrolled` event goes to audit. Without
tags, group-delegated login is rejected (fail-closed), while per-host login by
the cert works.

### 7.1 Verification on the workstation

```bash
journalctl -u tessera -g 'host_identity: probe' -n 20
journalctl -u tessera -g 'host_binding' -n 20
journalctl -u tessera -g 'device_enrolled' -n 5
```

The first command must show `probe selected source=dmi_board_serial` (or
whatever is set in `--sources`), **not** `override`. The second —
`host_binding match` on the next auth session.

## 8. Troubleshooting

Clone-specific cases (`dump-host-id` empty, USB does not appear,
`active_under_current_config=no`, bootstrap cert rejected, repeat flip after a
motherboard swap, wallpaper not updating) — see
[troubleshooting.md §7 Clone-image / golden image](troubleshooting.md#7-clone-image--golden-image).
## 9. Ansible rollout

A minimal playbook fragment:

```yaml
- name: Finish bootstrap on cloned terminal
  ansible.builtin.command:
    cmd: /usr/share/tessera/finish-bootstrap.sh --non-interactive --no-dump
  register: finish
  changed_when: "'no changes' not in finish.stdout"

- name: Fetch host_id dump
  ansible.builtin.command:
    cmd: tessera dump-host-id --output /tmp/host-ids.tsv
  changed_when: false

- name: Pull TSV to control node
  ansible.builtin.fetch:
    src: /tmp/host-ids.tsv
    dest: ./host-ids/{{ inventory_hostname }}.tsv
    flat: true
```

Afterward the TSV files are aggregated on the CA machine, per-host certificates
are issued in a loop with the CA tool, and the resulting `.p12`s are distributed
back (over a USB medium or through a secure channel to the workstation).

## 10. See also

- [install.md §2.4¾](install.md) — a short aside about the tooling.
- [install.md §8.5.1](install.md) — the wallpaper baseline in detail.
- [cert-issuance.md](cert-issuance.md) — certificate extensions,
  per-host vs wildcard vs bootstrap.
- [operations.md §2.4](operations.md) — where this workflow sits in the
  operations runbook.
- [configuration.md](configuration.md) — the `[host_identity]`,
  `[fly_dm_greeter]` fields in full.

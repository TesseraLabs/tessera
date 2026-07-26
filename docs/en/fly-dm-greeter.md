# Host_id on the login screen

A Tessera certificate is bound to a specific device: the `host_id_hash` is
embedded in it (see [cert-issuance.md](cert-issuance.md)). This creates a
chicken-and-egg problem for the operator in the field: to learn a device's
`host_id` you have to log in, but you cannot log in without a certificate for
that very `host_id`.

Tessera breaks the loop by showing the `host_id` right on the login screen.
Without logging in, this lets you:

- read the `host_id` of a new device and pass it on for issuing a per-host
  certificate (the typical rollout step for a cloned image —
  [clone-image.md](clone-image.md) §2.4);
- on a login failure, check whether the `host_id` on screen matches the one
  the certificate was issued for (`host_binding mismatch` —
  [troubleshooting.md](troubleshooting.md#host_binding-mismatch)).

## Where host_id is visible immediately, and where configuration is needed

At the start of `pam_sm_authenticate`, `tessera` sends an informational
message to PAM (`PAM_TEXT_INFO`):

```
Это устройство: host_id=a1b2c3d4 (source=MachineId)
```

It is visible with no configuration everywhere the PAM dialog reaches the
user: console login (`/etc/pam.d/login`), interactive sshd, sudo. The full
`host_id_hash` is written to the PAM module's log:
`journalctl -t pam_tessera -g host_identity`.

The exception is the fly-dm graphical login on Astra: the `fly-modern` theme
under МКЦ-3 ignores PAM messages and `GreetString`, substituting the
hardcoded string «Усиленный уровень защищенности» ("Enhanced security level")
into the headline (from the theme's `.mo` file, selected via the PARSEC API).
So for fly-dm the `host_id` is shown differently — it is imprinted into the
background image of the login screen. The theme itself is left untouched: the
text becomes part of the JPG wallpaper that `[background].path` in
`/etc/X11/fly-dm/fly-modern/settings.ini` points at. (The history of rejected
approaches is in [changelog.md](../ru/changelog.md) (Russian), 0.3.15–0.3.19.)

## Enabling it

```toml
# /etc/tessera/config.toml
[fly_dm_greeter]
update_wallpaper = true
```

Apply:

```bash
sudo systemctl restart tessera
```

At the bottom of the fly-dm login screen a line like this will appear:

```
Устройство astra184  host_id=a1b2c3d4 (dmi_board_serial)
```

## How it works

On every start of `tessera.service` the daemon:

1. On the first run it saves the original wallpaper: it copies
   `wallpaper_target` to `wallpaper_backup`. After that the copy is not
   refreshed — if the original background has changed, delete
   `wallpaper_backup` manually and the daemon will take a new copy.
2. It uses the clean original from `wallpaper_backup` as the base (so the text
   does not stack up from run to run).
3. It renders the line from the `template_ru` or `template_en` template (by
   the system locale) with these substitutions:
   - `{host_id_short}` — the first 8 hex characters of the host_id sha256 hash;
   - `{source}` — the host identity source name in snake_case (`machine_id`,
     `dmi_board_serial`, …);
   - `%n` — the machine's hostname.
4. It writes the result to `wallpaper_target` atomically (via a temp file and
   a rename) — fly-dm never sees a half-written JPG.

The rendering needs no external programs (ImageMagick and the like are not
required). Any error on this path is only logged — an engineer's login is
never blocked by wallpaper problems.

## The full set of options

```toml
[fly_dm_greeter]
update_wallpaper      = true
wallpaper_target      = "/usr/share/wallpapers/fly-default-light.jpg"
wallpaper_backup      = "/var/lib/tessera/daemon/wallpaper.orig.jpg"
wallpaper_font        = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
wallpaper_font_size   = 64
wallpaper_text_color  = "#000000"
wallpaper_gravity     = "south"     # north | south | east | west | center
wallpaper_offset_x    = 0           # offset from the anchor point, horizontal, px
wallpaper_offset_y    = 120         # offset from the anchor point (for south — upward), px
template_ru           = "Устройство %n  host_id={host_id_short} ({source})"
template_en           = "Device %n  host_id={host_id_short} ({source})"
```

## Text visibility: `settings.ini`

The daemon does **not** edit `settings.ini` — that file stays with the
operator (or Ansible). If strong dimming (`color_overlay`) or blur (`blur`)
is enabled in the theme, the imprinted text may not be visible. A working
baseline for a production terminal:

```ini
# /etc/X11/fly-dm/fly-modern/settings.ini
[background]
path=/usr/share/wallpapers/fly-default-light.jpg
color_overlay=0,0,0,30

[background][blur]
enable=false
```

After editing `settings.ini`, restart fly-dm:

```bash
sudo systemctl restart fly-dm
```

Edits to `[fly_dm_greeter]` in `config.toml` take effect with a restart of
`tessera` (see [Enabling it](#enabling-it)).

## Verification

After restarting the daemon:

```bash
sudo journalctl -u tessera -g fly_dm_greeter -n 20
```

The expected entry is a single INFO line `fly-dm wallpaper update finished`
(target `tessera.fly_dm_greeter`) with an `outcome` field:

- `Wrote { backed_up: true }` — the first run, the original was snapshotted;
- `Wrote { backed_up: false }` — a normal subsequent run;
- `Disabled` — `update_wallpaper = false`.

Any error (no permissions on the file, a corrupt JPG, a missing font —
installed by the `fonts-dejavu-core` package) produces a WARN line `fly-dm
wallpaper update failed (continuing)`; the daemon keeps running, login is not
blocked.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md), the section "fly-dm does not
show host_id on the login screen".

## See also

- [install.md](install.md) — installing `tessera` in full.
- [configuration.md](configuration.md) — the `config.toml` reference.
- [clone-image.md](clone-image.md) §2.4 — configuring the wallpaper on the
  reference machine before taking the image.

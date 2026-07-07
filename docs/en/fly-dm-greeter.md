# fly-dm greeter: show host_id on the login screen

`tessera` sends a short machine identification to PAM at the start of
`pam_sm_authenticate`:

```
Это устройство: host_id=a1b2c3d4 (source=MachineId)
```

This is a `PAM_TEXT_INFO` message. The full `host_id_hash` stays in
syslog: `journalctl -t tessera | grep host_identity`. The goal is that
the operator/engineer at the terminal sees which `host_id` the
certificate is bound to, without going into a shell.

Where the message is shown **with no extra configuration**:

- TTY login (`/etc/pam.d/login` on the console);
- sshd interactive (`/etc/pam.d/sshd`);
- sudo (`/etc/pam.d/sudo`).

Where **configuration is needed** — fly-dm (the Astra GUI display
manager): see below.

## The fly-dm problem

On Astra with mandatory integrity control level 3 (МКЦ-3; production
terminals), `fly-dm` under the `fly-modern` theme **ignores** PAM
messages and `GreetString` — it hardcodes the string «Усиленный уровень
защищенности» ("Enhanced security level") into the headline place, taken
from `/usr/share/locale/ru/LC_MESSAGES/fly-dm_greet_modern.mo`
(determined via the PARSEC API).

A history of attempts (for context):

| Version | Approach                                    | Result                  |
|---------|---------------------------------------------|-------------------------|
| 0.3.15  | `greeter-show-messages = true` in fly-dmrc  | A KDM/LightDM legacy key, fly-qdm 2.15+ does not parse it. **Cargo-cult**. |
| 0.3.16  | `/etc/X11/fly-dm/override/GreetString.desktop` | On fly-modern МКЦ-3, GreetString is replaced by the hardcode. **No-op**. |
| 0.3.19  | Wallpaper writer — imprint into the JPG background | **Works**.        |

## Workaround: the wallpaper writer (0.3.19+)

The idea: imprint `host_id` directly into the JPG that
`[background].path` in `/etc/X11/fly-dm/fly-modern/settings.ini` points
at. The daemon does this automatically, with no dependency on the theme.

### Enabling it

```toml
# /etc/tessera/config.toml
[fly_dm_greeter]
update_wallpaper = true
```

Restart:

```bash
sudo systemctl restart tessera
```

### Behaviour

On every start of `tessera.service`:

1. **The first time**: `cp wallpaper_target → wallpaper_backup` (a
   one-time snapshot of the original). Later edits of the source do NOT
   overwrite the backup — changing the original background requires
   deleting `wallpaper_backup` manually.
2. It opens `wallpaper_backup` as the source image.
3. It renders the template (`template_ru` / `template_en` by locale)
   with these substitutions:
   - `{host_id_short}` — the first 8 hex characters of the sha256;
   - `{source}` — the source name in snake_case (`machine_id`,
     `dmi_board_serial` …);
   - `%n` — the machine's hostname.
4. Atomic save → `wallpaper_target` (tmpfile + rename).

### The full set of options

```toml
[fly_dm_greeter]
update_wallpaper      = true
wallpaper_target      = "/usr/share/wallpapers/fly-default-light.jpg"
wallpaper_backup      = "/var/lib/tessera/wallpaper.orig.jpg"
wallpaper_font        = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
wallpaper_font_size   = 64
wallpaper_text_color  = "#000000"
wallpaper_gravity     = "south"     # north | south | east | west | center
wallpaper_offset_x    = 0           # pixels from the gravity anchor, horizontally
wallpaper_offset_y    = 120         # pixels from the gravity anchor (for south — upward)
template_ru           = "Устройство %n  host_id={host_id_short} ({source})"
template_en           = "Device %n  host_id={host_id_short} ({source})"
```

### Implementation

Pure Rust: the `image` crate for JPG I/O + `ab_glyph` for rasterizing
the font. No native deps (no ImageMagick / no Pango). Failures →
log-and-continue; the auth flow is **never** blocked by an error in the
wallpaper writer.

## Text visibility: `settings.ini`

The daemon does **not** edit `settings.ini` — that is managed by the
operator/Ansible. If a strong `color_overlay` or `blur` is enabled on
the host, the text may be invisible.

A baseline for a production terminal:

```ini
# /etc/X11/fly-dm/fly-modern/settings.ini
[background]
path=/usr/share/wallpapers/fly-default-light.jpg
color_overlay=0,0,0,30

[background][blur]
enable=false
```

After editing `settings.ini`:

```bash
sudo systemctl restart fly-dm
```

After editing `[fly_dm_greeter]` in `config.toml`:

```bash
sudo systemctl restart tessera
```

## Verification

After restarting the daemon:

```bash
sudo journalctl -u tessera -g fly_dm_greeter -n 20
```

The expected entry is a single INFO `fly-dm wallpaper update finished`
(target `tessera.fly_dm_greeter`) with an `outcome` field: `Wrote {
backed_up: true }` on the first run, then `backed_up: false`;
`Disabled` if `update_wallpaper = false`. Any error (no permissions, a
corrupt JPG, a missing font — install `fonts-dejavu-core`) is a WARN
`fly-dm wallpaper update failed (continuing)`, and the daemon keeps
running.

Then, visually on the fly-dm login screen: a line should appear at the
bottom — `Устройство astra184  host_id=a1b2c3d4 (dmi_board_serial)`.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md), the section "fly-dm does
not show host_id on the login screen".

## See also

- [install.md](install.md) — installing `tessera` in full.
- [configuration.md](configuration.md) — the `config.toml` reference.
- [clone-image.md](clone-image.md) §2.4 — configuring the wallpaper on
  the reference machine before taking the image.

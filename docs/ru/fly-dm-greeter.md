# fly-dm greeter: показать host_id на экране входа

`tessera` отправляет короткую идентификацию машины в PAM в
начале `pam_sm_authenticate`:

```
Это устройство: host_id=a1b2c3d4 (source=MachineId)
```

Это `PAM_TEXT_INFO`-сообщение. Полный `host_id_hash` остаётся в
syslog: `journalctl -t tessera | grep host_identity`. Цель —
оператор/инженер у терминала видит, к какому `host_id` привязан
сертификат, не заходя в shell.

Где сообщение показывается **без дополнительной настройки**:

- TTY-login (`/etc/pam.d/login` на консоли);
- sshd interactive (`/etc/pam.d/sshd`);
- sudo (`/etc/pam.d/sudo`).

Где **нужны настройки** — fly-dm (Astra GUI display manager): см. ниже.

## Проблема fly-dm

На Astra с МКЦ-3 (production-терминалы) `fly-dm` под темой
`fly-modern` **игнорирует** PAM-сообщения и `GreetString` —
hardcoded'но рендерит в headline place строку «Усиленный уровень
защищенности» из `/usr/share/locale/ru/LC_MESSAGES/fly-dm_greet_modern.mo`
(определяется по PARSEC API).

История попыток (для контекста):

| Версия | Подход                                     | Результат               |
|--------|--------------------------------------------|-------------------------|
| 0.3.15 | `greeter-show-messages = true` в fly-dmrc  | KDM/LightDM legacy key, fly-qdm 2.15+ не парсит. **Cargo-cult**. |
| 0.3.16 | `/etc/X11/fly-dm/override/GreetString.desktop` | На fly-modern МКЦ-3 GreetString hardcode'ом замещается. **No-op**. |
| 0.3.19 | Wallpaper writer — впечатать в JPG-фон     | **Работает**.           |

## Workaround: wallpaper writer (0.3.19+)

Идея: впечатать `host_id` прямо в JPG, на который смотрит
`[background].path` в `/etc/X11/fly-dm/fly-modern/settings.ini`.
Daemon делает это автоматически, без зависимостей от темы.

### Включение

```toml
# /etc/tessera/config.toml
[fly_dm_greeter]
update_wallpaper = true
```

Restart:

```bash
sudo systemctl restart tessera
```

### Поведение

При каждом старте `tessera.service`:

1. **Первый раз**: `cp wallpaper_target → wallpaper_backup` (one-time
   снимок оригинала). Дальнейшие правки источника НЕ перезаписывают
   backup — изменение оригинала фона требует ручного удаления
   `wallpaper_backup`.
2. Открывает `wallpaper_backup` как source-изображение.
3. Рендерит template (`template_ru` / `template_en` по locale) с
   подстановкой:
   - `{host_id_short}` — первые 8 hex символов sha256;
   - `{source}` — имя источника в snake_case (`machine_id`, `dmi_board_serial` ...);
   - `%n` — hostname машины.
4. Atomic save → `wallpaper_target` (tmpfile + rename).

### Полный набор опций

```toml
[fly_dm_greeter]
update_wallpaper      = true
wallpaper_target      = "/usr/share/wallpapers/fly-default-light.jpg"
wallpaper_backup      = "/var/lib/tessera/wallpaper.orig.jpg"
wallpaper_font        = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
wallpaper_font_size   = 64
wallpaper_text_color  = "#000000"
wallpaper_gravity     = "south"     # north | south | east | west | center
wallpaper_offset_x    = 0           # пиксели от gravity-anchor по горизонтали
wallpaper_offset_y    = 120         # пиксели от gravity-anchor (для south — вверх)
template_ru           = "Устройство %n  host_id={host_id_short} ({source})"
template_en           = "Device %n  host_id={host_id_short} ({source})"
```

### Реализация

Pure Rust: crate `image` для JPG I/O + `ab_glyph` для растеризации
шрифта. Без native deps (no ImageMagick / no Pango). Failures →
log-and-continue, auth-flow **никогда** не блокируется ошибкой
wallpaper writer'а.

## Видимость текста: `settings.ini`

Daemon **не редактирует** `settings.ini` — этим управляет
оператор/Ansible. Если на хосте включён сильный `color_overlay` или
`blur` — текст может быть невидим.

Baseline для production-терминала:

```ini
# /etc/X11/fly-dm/fly-modern/settings.ini
[background]
path=/usr/share/wallpapers/fly-default-light.jpg
color_overlay=0,0,0,30

[background][blur]
enable=false
```

После правки `settings.ini`:

```bash
sudo systemctl restart fly-dm
```

После правки `[fly_dm_greeter]` в `config.toml`:

```bash
sudo systemctl restart tessera
```

## Verification

После рестарта daemon'а:

```bash
sudo journalctl -u tessera -g fly_dm_greeter -n 20
```

Ожидаемая запись — одна INFO `fly-dm wallpaper update finished`
(target `tessera.fly_dm_greeter`) с полем `outcome`: `Wrote {
backed_up: true }` на первом запуске, дальше `backed_up: false`;
`Disabled` — если `update_wallpaper = false`. Любая ошибка (нет
прав, битый JPG, отсутствующий шрифт — поставить
`fonts-dejavu-core`) — WARN `fly-dm wallpaper update failed
(continuing)`, демон продолжает работу.

Затем визуально на экране login fly-dm: внизу должна появиться
строка `Устройство astra184  host_id=a1b2c3d4 (dmi_board_serial)`.

## Troubleshooting

См. [troubleshooting.md](troubleshooting.md) раздел
«fly-dm не показывает host_id на экране входа».

## См. также

- [install.md](install.md) — установка `tessera` целиком.
- [configuration.md](configuration.md) — справочник по `config.toml`.
- [clone-image.md](clone-image.md) §2.4 — настройка wallpaper на эталоне
  перед снятием образа.

# Host_id на экране входа

Сертификат Tessera привязан к конкретному устройству: в него зашит
`host_id_hash` (см. [cert-issuance.md](cert-issuance.md)). Из-за этого
у оператора в поле возникает замкнутый круг: чтобы узнать `host_id`
устройства, нужно войти в систему, а войти без сертификата на этот
самый `host_id` нельзя.

Tessera разрывает круг, показывая `host_id` прямо на экране входа.
Это позволяет без входа в систему:

- прочитать `host_id` нового устройства и передать его для выпуска
  per-host сертификата (типовой шаг раскатки через клонированный
  образ — [clone-image.md](clone-image.md) §2.4);
- при отказе входа сверить, совпадает ли `host_id` на экране с тем,
  на который выписан сертификат (`host_binding mismatch` —
  [troubleshooting.md](troubleshooting.md#host_binding-mismatch)).

## Где host_id виден сразу, а где нужна настройка

`tessera` в начале `pam_sm_authenticate` отправляет в PAM
информационное сообщение (`PAM_TEXT_INFO`):

```
Это устройство: host_id=a1b2c3d4 (source=MachineId)
```

Оно видно без настройки везде, где PAM-диалог доходит до
пользователя: вход на консоли (`/etc/pam.d/login`), интерактивный
sshd, sudo. Полный `host_id_hash` пишется в журнал PAM-модуля:
`journalctl -t pam_tessera -g host_identity`.

Исключение — графический вход fly-dm на Astra: тема `fly-modern`
под МКЦ-3 игнорирует PAM-сообщения и `GreetString`, подставляя в
заголовок жёстко зашитую строку «Усиленный уровень защищенности»
(из `.mo`-файла темы, выбор по PARSEC API). Поэтому для fly-dm
`host_id` выводится иначе — впечатывается в фоновое изображение
экрана входа. Тема при этом не трогается: текст становится частью
JPG-обоев, на которые указывает `[background].path` в
`/etc/X11/fly-dm/fly-modern/settings.ini`. (История отвергнутых
подходов — в [changelog.md](changelog.md), 0.3.15–0.3.19.)

## Включение

```toml
# /etc/tessera/config.toml
[fly_dm_greeter]
update_wallpaper = true
```

Применить:

```bash
sudo systemctl restart tessera
```

На экране входа fly-dm внизу появится строка вида:

```
Устройство astra184  host_id=a1b2c3d4 (dmi_board_serial)
```

## Как это работает

При каждом старте `tessera.service` демон:

1. При первом запуске сохраняет оригинал обоев: копирует
   `wallpaper_target` в `wallpaper_backup`. Дальше копия не
   обновляется — если оригинальный фон поменялся, удалите
   `wallpaper_backup` вручную, и демон снимет новую копию.
2. Берёт за основу чистый оригинал из `wallpaper_backup` (поэтому
   текст не наслаивается от запуска к запуску).
3. Рендерит строку по шаблону `template_ru` или `template_en`
   (по локали системы) с подстановками:
   - `{host_id_short}` — первые 8 hex-символов sha256-хэша host_id;
   - `{source}` — имя источника host identity в snake_case
     (`machine_id`, `dmi_board_serial`, …);
   - `%n` — hostname машины.
4. Записывает результат в `wallpaper_target` атомарно (через
   временный файл и переименование) — fly-dm никогда не увидит
   недописанный JPG.

Отрисовка не требует внешних программ (ImageMagick и т. п. не
нужны). Любая ошибка на этом пути только логируется — вход
инженера из-за проблем с обоями никогда не блокируется.

## Справочник опций

```toml
[fly_dm_greeter]
update_wallpaper      = true
wallpaper_target      = "/usr/share/wallpapers/fly-default-light.jpg"
wallpaper_backup      = "/var/lib/tessera/daemon/wallpaper.orig.jpg"
wallpaper_font        = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
wallpaper_font_size   = 64
wallpaper_text_color  = "#000000"
wallpaper_gravity     = "south"     # north | south | east | west | center
wallpaper_offset_x    = 0           # смещение от точки привязки по горизонтали, px
wallpaper_offset_y    = 120         # смещение от точки привязки (для south — вверх), px
template_ru           = "Устройство %n  host_id={host_id_short} ({source})"
template_en           = "Device %n  host_id={host_id_short} ({source})"
```

## Видимость текста: `settings.ini`

Демон **не редактирует** `settings.ini` — этот файл остаётся за
оператором (или Ansible). Если в теме включены сильное затемнение
(`color_overlay`) или размытие (`blur`), впечатанный текст может
быть не виден. Рабочая основа для production-терминала:

```ini
# /etc/X11/fly-dm/fly-modern/settings.ini
[background]
path=/usr/share/wallpapers/fly-default-light.jpg
color_overlay=0,0,0,30

[background][blur]
enable=false
```

После правки `settings.ini` перезапустите fly-dm:

```bash
sudo systemctl restart fly-dm
```

Правки `[fly_dm_greeter]` в `config.toml` применяются рестартом
`tessera` (см. [Включение](#включение)).

## Проверка

После рестарта демона:

```bash
sudo journalctl -u tessera -g fly_dm_greeter -n 20
```

Ожидаемая запись — одна INFO-строка `fly-dm wallpaper update finished`
(таргет `tessera.fly_dm_greeter`) с полем `outcome`:

- `Wrote { backed_up: true }` — первый запуск, снята копия оригинала;
- `Wrote { backed_up: false }` — обычный последующий запуск;
- `Disabled` — `update_wallpaper = false`.

Любая ошибка (нет прав на файл, повреждённый JPG, отсутствующий
шрифт — ставится пакетом `fonts-dejavu-core`) даёт WARN-строку
`fly-dm wallpaper update failed (continuing)`; демон продолжает
работу, вход не блокируется.

## Диагностика

См. [troubleshooting.md](troubleshooting.md), раздел
«fly-dm не показывает host_id на экране входа».

## См. также

- [install.md](install.md) — установка `tessera` целиком.
- [configuration.md](configuration.md) — справочник по `config.toml`.
- [clone-image.md](clone-image.md) §2.4 — настройка wallpaper на эталоне
  перед снятием образа.

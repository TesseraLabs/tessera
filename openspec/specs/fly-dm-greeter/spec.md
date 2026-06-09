# fly-dm-greeter Specification

## Purpose

Показ `host_id` оператору на экране входа fly-dm (Astra). Единственный механизм, работающий на боевом МКЦ-3, — wallpaper banner: впечатывание host_id в JPG-фон. Прошёл 3 pivot'а: fly-dmrc `greeter-show-messages` (0.3.15, cargo-cult — fly-qdm не парсит) → GreetString.desktop (0.3.16, no-op на МКЦ-3: fly-modern хардкодит «Усиленный уровень защищенности» в headline) → wallpaper (0.3.19, работает).

Код: `crates/tessera_cli/src/fly_dm_wallpaper_writer.rs`, вызов в `daemon/mod.rs:146–175`.

## Requirements

### Requirement: Opt-in и невмешательство в auth

`[fly_dm_greeter].update_wallpaper` default=false; при false → `Disabled`, никакого FS-I/O. Любая ошибка writer'а ДОЛЖНА (MUST) логироваться и НЕ ДОЛЖНА (MUST NOT) блокировать ни старт демона, ни auth (НЕ fail-closed by design).

#### Scenario: Ошибка writer'а
- **WHEN** writer падает с ошибкой при рендере wallpaper
- **THEN** ошибка логируется, но ни старт демона, ни auth не блокируются

### Requirement: Backup-цикл

Первый запуск (backup нет, target есть): writer ДОЛЖЕН (MUST) снять one-time backup `wallpaper_target → wallpaper_backup` (default `/var/lib/tessera/wallpaper.orig.jpg` — вне владений пакета fly-qdm, переживает apt-upgrade). Последующие запуски: backup НЕ перезаписывается; рендер ВСЕГДА из backup (идемпотентно). Обновление оригинала требует ручного удаления backup. Нет ни backup, ни target → тихий skip (хост без fly-dm).

#### Scenario: Первый запуск
- **WHEN** backup отсутствует, target существует
- **THEN** снимается one-time backup `wallpaper_target → wallpaper_backup`, затем рендер из backup

### Requirement: Рендер

Шаблон по локали (`LC_MESSAGES`/`LANG` startswith "ru" → template_ru) ДОЛЖЕН (MUST) поддерживать подстановки `{host_id_short}` (prefix8), `{source}`, `%n` (hostname). Дефолты: DejaVuSans-Bold 64pt, чёрный, gravity=south, offset_y=120, `wallpaper_offset_x`=0 (горизонтальный сдвиг баннера, может быть отрицательным; raw.rs:162, validated.rs:590, fly_dm_wallpaper_writer.rs:165). Запись atomic (tmpfile+rename), выход всегда JPEG. Pure Rust (`image`+`ab_glyph`) — без ImageMagick/Pango. Writer НЕ ДОЛЖЕН (MUST NOT) редактировать settings.ini (blur/color_overlay/path — зона оператора/Ansible; baseline для читаемости: `color_overlay=0,0,0,30`, `blur enable=false`).

#### Scenario: Русская локаль
- **WHEN** `LANG` начинается с "ru"
- **THEN** используется template_ru с подстановками `{host_id_short}`, `{source}`, `%n`, запись atomic в JPEG

- Замечание: `update_greet_string` (0.3.16–0.3.18) удалён из схемы — присутствие в конфиге теперь ОТВЕРГАЕТСЯ deny_unknown_fields, а не no-op.

### Requirement: Контекст платформы (зачем wallpaper)

Будущие изменения greeter'а ДОЛЖНЫ (MUST) учитывать ограничения платформы fly-modern theme: layout зашит в .so (не редактируется); при МКЦ-3 headline занят hardcoded MAC-статусом из `.mo`; `PAM_TEXT_INFO` fly-dm не показывает (фильтруется; работает на TTY/sshd/GDM/LightDM). На банкоматах AutoLogin → greeter виден только при logout оператора. Wallpaper — единственная поверхность, не зависящая от theme/MAC-статуса; в kiosk-сессии скрыт fullscreen-окном.

#### Scenario: МКЦ-3 headline недоступен
- **WHEN** хост на боевом МКЦ-3, fly-modern theme хардкодит MAC-статус в headline
- **THEN** host_id показывается только через wallpaper banner — единственную поверхность, не зависящую от theme/MAC-статуса

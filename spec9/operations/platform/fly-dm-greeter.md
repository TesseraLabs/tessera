---
id: fly-dm-greeter
kind: операция
context: platform
name: "Интеграция с Fly DM"
aliases:
  - "fly-dm-greeter"
relations:
  references:
    - auth.pam-module
anchors:
  code:
    - "crates/tessera_cli/src/fly_dm_wallpaper_writer.rs"
  test:
    - "dist/systemd/tests/verify.sh"
requirements:
  FLY-001:
    kind: операционное
    subjects:
      - platform.fly-dm-greeter
    origins:
      - "fly-dm-greeter::Opt-in и невмешательство в auth"
    evidence:
      code:
        - "crates/tessera_cli/src/fly_dm_wallpaper_writer.rs"
  FLY-002:
    kind: операционное
    subjects:
      - platform.fly-dm-greeter
    origins:
      - "fly-dm-greeter::Backup-цикл"
    evidence:
      code:
        - "crates/tessera_cli/src/fly_dm_wallpaper_writer.rs"
  FLY-003:
    kind: операционное
    subjects:
      - platform.fly-dm-greeter
    origins:
      - "fly-dm-greeter::Рендер"
    evidence:
      code:
        - "crates/tessera_cli/src/fly_dm_wallpaper_writer.rs"
  FLY-004:
    kind: операционное
    subjects:
      - platform.fly-dm-greeter
    origins:
      - "fly-dm-greeter::Контекст платформы (зачем wallpaper)"
    evidence:
      code:
        - "crates/tessera_cli/src/fly_dm_wallpaper_writer.rs"
---
# Интеграция с Fly DM

Эта страница заменяет процедурную capability-спеку OpenSpec «fly-dm-greeter»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### FLY-001 — Opt-in и невмешательство в auth

[[platform.fly-dm-greeter|Интеграция с Fly DM]] MUST соблюдать правило «Opt-in и невмешательство в auth» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/fly-dm-greeter/spec.md, requirement «Opt-in и невмешательство в auth».

`[fly_dm_greeter].update_wallpaper` default=false; при false → `Disabled`, никакого FS-I/O. Любая ошибка writer'а должна логироваться и не должна блокировать ни старт демона, ни auth (НЕ fail-closed by design).

#### Scenario: Ошибка writer'а
- **WHEN** writer падает с ошибкой при рендере wallpaper
- **THEN** ошибка логируется, но ни старт демона, ни auth не блокируются

### FLY-002 — Backup-цикл

[[platform.fly-dm-greeter|Интеграция с Fly DM]] MUST соблюдать правило «Backup-цикл» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/fly-dm-greeter/spec.md, requirement «Backup-цикл».

Первый запуск (backup нет, target есть): writer должен снять one-time backup `wallpaper_target → wallpaper_backup` (default `/var/lib/tessera/daemon/wallpaper.orig.jpg` — в отдельном daemon-writable подкаталоге, вне владений пакета fly-qdm, переживает apt-upgrade). Последующие запуски: backup НЕ перезаписывается; рендер ВСЕГДА из backup (идемпотентно). Обновление оригинала требует ручного удаления backup. Нет ни backup, ни target → тихий skip (хост без fly-dm).

#### Scenario: Первый запуск
- **WHEN** backup отсутствует, target существует
- **THEN** снимается one-time backup `wallpaper_target → wallpaper_backup`, затем рендер из backup

### FLY-003 — Рендер

[[platform.fly-dm-greeter|Интеграция с Fly DM]] MUST соблюдать правило «Рендер» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/fly-dm-greeter/spec.md, requirement «Рендер».

Шаблон по локали (`LC_MESSAGES`/`LANG` startswith "ru" → template_ru) должен поддерживать подстановки `{host_id_short}` (prefix8), `{source}`, `%n` (hostname). Дефолты: DejaVuSans-Bold 64pt, чёрный, gravity=south, offset_y=120, `wallpaper_offset_x`=0 (горизонтальный сдвиг баннера, может быть отрицательным). Размер шрифта ограничен `1..=512`, шаблон — 1024 байтами, text raster — 16 Mi pixels. Запись atomic (tmpfile+rename), выход всегда JPEG. Pure Rust (`image` + maintained `skrifa` + `ab_glyph_rasterizer`) — без ImageMagick/Pango и без unmaintained `ttf-parser`. Writer не должен редактировать settings.ini (blur/color_overlay/path — зона оператора/Ansible; baseline для читаемости: `color_overlay=0,0,0,30`, `blur enable=false`).

#### Scenario: Русская локаль
- **WHEN** `LANG` начинается с "ru"
- **THEN** используется template_ru с подстановками `{host_id_short}`, `{source}`, `%n`, запись atomic в JPEG

- Замечание: `update_greet_string` (0.3.16–0.3.18) удалён из схемы — присутствие в конфиге теперь ОТВЕРГАЕТСЯ deny_unknown_fields, а не no-op.

### FLY-004 — Контекст платформы (зачем wallpaper)

[[platform.fly-dm-greeter|Интеграция с Fly DM]] MUST соблюдать правило «Контекст платформы (зачем wallpaper)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/fly-dm-greeter/spec.md, requirement «Контекст платформы (зачем wallpaper)».

Будущие изменения greeter'а должны учитывать ограничения платформы fly-modern theme: layout зашит в .so (не редактируется); при МКЦ-3 headline занят hardcoded MAC-статусом из `.mo`; `PAM_TEXT_INFO` fly-dm не показывает (фильтруется; работает на TTY/sshd/GDM/LightDM). На терминалах AutoLogin → greeter виден только при logout оператора. Wallpaper — единственная поверхность, не зависящая от theme/MAC-статуса; в kiosk-сессии скрыт fullscreen-окном.

#### Scenario: МКЦ-3 headline недоступен
- **WHEN** хост на боевом МКЦ-3, fly-modern theme хардкодит MAC-статус в headline
- **THEN** host_id показывается только через wallpaper banner — единственную поверхность, не зависящую от theme/MAC-статуса


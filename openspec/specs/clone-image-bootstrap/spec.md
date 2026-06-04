# clone-image-bootstrap Specification

## Purpose

Раскатка парка из клонированного эталонного образа: bootstrap-cert валиден на любом клоне; первый запуск на железе атомарно «привязывает» машину и убивает bootstrap-cert. Выбран override-механизм (vs TTL): не зависит от часов, отключение атомарно через config-flip, не требует правок модуля.

Состав: `dump-host-id` (см. [cli-diagnostics](../cli-diagnostics/spec.md)), `dist/scripts/finish-bootstrap.sh`, admin-tools tarball, wallpaper banner (см. [fly-dm-greeter](../fly-dm-greeter/spec.md)).

## Requirements

### Requirement: Эталонный образ

Эталон ДОЛЖЕН (MUST) содержать: `[host_identity] sources=["override"], override="installation"` + bootstrap-cert с `host_binding="installation"` (raw UTF8String, без `sha256:`). Resolver возвращает SHA-256("installation") на всех клонах → bootstrap-cert совпадает везде. Опционально `update_wallpaper=true` (host_id виден оператору на МКЦ-3). Перед снятием образа: stop service; `/etc/machine-id` НЕ очищать.

#### Scenario: Запуск на любом клоне
- **WHEN** клон стартует с эталонной конфигурацией `sources=["override"], override="installation"`
- **THEN** resolver возвращает SHA-256("installation") → bootstrap-cert совпадает на всех клонах

### Requirement: finish-bootstrap.sh — single-pass flip

Скрипт ДОЛЖЕН (MUST) (offline, root, идемпотентно):
1. Детект `sources=["override"]`; нет → exit 0 без изменений. Есть sources=["override"] без `override="..."` → ERROR, отказ.
2. Atomic rewrite: `sources` → production-набор (default `["dmi_board_serial","machine_id"]`; override: `--sources` > env `POST_INSTALL_SOURCES` > default), строка `override=` комментируется; tmpfile + проверка обеих замен + сохранение perms/owner + mv; backup `config.toml.bak.<UTC>`.
3. `tessera check`; провал → rollback из backup + exit ≠ 0, демон не рестартится (fail-closed).
4. restart `tessera.service`, ожидание active до 30s.
5. `dump-host-id --usb` с poll до **60s** (⚠ док clone-image.md:182 говорит ~30s); без USB — fallback-файл в `/var/lib/tessera/`.

Флаги: `--non-interactive`, `--no-restart`, `--no-dump`, `--sources`.

#### Scenario: После flip
- **WHEN** config переключён на реальные источники
- **THEN** host_id_hash меняется → bootstrap-cert «installation» больше не совпадает → reject на этом хосте (атомарная инвалидация); параллельно CA выпускает per-host cert по hash_hex из TSV

### Requirement: Admin-tools tarball (CA-сторона)

Admin-tools ДОЛЖЕН (MUST) распространяться отдельным `tessera-admin-tools-<ver>.tar.gz` в GitHub Release, НЕ в .deb (CA-инструменты не должны лежать на терминале). Состав: `vault-pki-setup.sh`, `issue-service-cert.sh` (режимы per-host / wildcard / bootstrap), `prepare-usb-flash.sh`, README. Сборка — только на тегах `v*`.

#### Scenario: Сборка tarball
- **WHEN** пушится тег `v*`
- **THEN** собирается `tessera-admin-tools-<ver>.tar.gz` и публикуется в GitHub Release, но НЕ кладётся в .deb

- ⚠ KNOWN GAP (docs, КРУПНОЕ): clone-image.md показывает неинтерактивные флаги (`--mode/--ca-dir/--host-id-hash/--device/...`) — фактически оба скрипта ИНТЕРАКТИВНЫЕ (`read -rp`), параметры через env (CA_DIR/OUTPUT_BASE/...). admin-tools/README.md соответствует коду; clone-image.md — нет.
- Guard: `prepare-usb-flash.sh` ДОЛЖЕН (MUST) отказываться копировать PEM-файл (начинается с `-----BEGIN`) как .p12.

### Requirement: Смежный деплой-констрейнт (информативно)

Runbook парка ДОЛЖЕН (MUST) учитывать: клонирование с TPM2-LUKS требует отдельной ручной процедуры пере-enroll TPM (wipe-slot+cryptenroll) — вне зоны tessera, но в одном runbook'е парка.

#### Scenario: Клон с TPM2-LUKS
- **WHEN** эталон с TPM2-LUKS клонируется на новое железо
- **THEN** требуется отдельная ручная процедура пере-enroll TPM (wipe-slot+cryptenroll) вне зоны tessera

# clone-image-bootstrap Specification

## Purpose

Раскатка парка из клонированного эталонного образа: bootstrap-cert валиден на любом клоне; первый запуск на железе атомарно «привязывает» машину и убивает bootstrap-cert. Выбран override-механизм (vs TTL): не зависит от часов, отключение атомарно через config-flip, не требует правок модуля.

Состав: `dump-host-id` (см. [cli-diagnostics](../cli-diagnostics/spec.md)), `dist/scripts/finish-bootstrap.sh`, wallpaper banner (см. [fly-dm-greeter](../fly-dm-greeter/spec.md)). CA-сторона (выпуск удостоверений, подготовка USB) — закрытые инструменты вне этого репозитория.
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
5. `dump-host-id --usb` с poll до **60s**; без USB — fallback-файл в `/var/lib/tessera/`.

Флаги: `--non-interactive`, `--no-restart`, `--no-dump`, `--sources`.

#### Scenario: После flip
- **WHEN** config переключён на реальные источники
- **THEN** host_id_hash меняется → bootstrap-cert «installation» больше не совпадает → reject на этом хосте (атомарная инвалидация); параллельно CA выпускает per-host cert по hash_hex из TSV

### Requirement: CA-сторона (контракт)

CA-инструменты (настройка PKI, выпуск удостоверений, подготовка USB) НЕ ДОЛЖНЫ (MUST NOT) входить в `.deb` и в этот репозиторий — они не должны лежать на устройстве; поставляются отдельно. Контракт со стороны устройства: CA выпускает per-host
удостоверение по `hash_hex` из строки `active_under_current_config=yes` TSV-дампа `dump-host-id`.
Дополнительно (managed-enrollment): на том же USB-возврате CA-сторона ДОЛЖНА (MUST) отдавать
подписанный manifest с тегами устройства и первым bundle (роли+CRL, baseline `bundle_version`)
рядом с per-host удостоверением; теги и bundle не секретны и едут открыто. Назначение тегов
конкретному устройству — серверная сторона (Control inventory `hash_hex`→теги либо оператор при
установке), device их не выбирает.

#### Scenario: Выпуск per-host удостоверения
- **WHEN** CA-админ получает TSV-дамп от устройства после flip
- **THEN** per-host удостоверение выпускается по `hash_hex` активного источника и доставляется на устройство на USB-носителе (старые `.p12` удаляются)

#### Scenario: Доставка тегов и первого bundle на возврате
- **WHEN** CA-сторона готовит возвратный USB для managed-enrollment
- **THEN** рядом с per-host сертом кладётся подписанный manifest с тегами этого устройства и первым bundle (роли+CRL, baseline `bundle_version`)

### Requirement: Смежный деплой-констрейнт (информативно)

Runbook парка ДОЛЖЕН (MUST) учитывать: клонирование с TPM2-LUKS требует отдельной ручной процедуры пере-enroll TPM (wipe-slot+cryptenroll) — вне зоны tessera, но в одном runbook'е парка.

#### Scenario: Клон с TPM2-LUKS
- **WHEN** эталон с TPM2-LUKS клонируется на новое железо
- **THEN** требуется отдельная ручная процедура пере-enroll TPM (wipe-slot+cryptenroll) вне зоны tessera


---
id: clone-bootstrap
kind: операция
context: fleet
name: "Завершение клонированного образа"
aliases:
  - "clone-image-bootstrap"
relations:
  references:
    - auth.host-identity
    - auth.device-config
anchors:
  code:
    - "dist/scripts/finish-bootstrap.sh"
  test:
    - "tests/e2e/cases/14-device-enrollment.yaml"
requirements:
  BOOT-001:
    kind: операционное
    subjects:
      - fleet.clone-bootstrap
    origins:
      - "clone-image-bootstrap::Эталонный образ"
    evidence:
      code:
        - "dist/scripts/finish-bootstrap.sh"
  BOOT-002:
    kind: операционное
    subjects:
      - fleet.clone-bootstrap
    origins:
      - "clone-image-bootstrap::finish-bootstrap.sh — single-pass flip"
    evidence:
      code:
        - "dist/scripts/finish-bootstrap.sh"
  BOOT-003:
    kind: контракт
    subjects:
      - fleet.clone-bootstrap
    origins:
      - "clone-image-bootstrap::CA-сторона (контракт)"
    evidence:
      test:
        - "tests/e2e/cases/14-device-enrollment.yaml"
  BOOT-004:
    kind: контракт
    subjects:
      - fleet.clone-bootstrap
    origins:
      - "clone-image-bootstrap::Смежный деплой-констрейнт (информативно)"
    evidence:
      test:
        - "tests/e2e/cases/14-device-enrollment.yaml"
---
# Завершение клонированного образа

Эта страница заменяет процедурную capability-спеку OpenSpec «clone-image-bootstrap»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### BOOT-001 — Эталонный образ

[[fleet.clone-bootstrap|Завершение клонированного образа]] MUST соблюдать правило «Эталонный образ» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/clone-image-bootstrap/spec.md, requirement «Эталонный образ».

Эталон должен содержать: `[host_identity] sources=["override"], override="installation"` + bootstrap-cert с `host_binding="installation"` (raw UTF8String, без `sha256:`). Resolver возвращает SHA-256("installation") на всех клонах → bootstrap-cert совпадает везде. Опционально `update_wallpaper=true` (host_id виден оператору на МКЦ-3). Перед снятием образа: stop service; `/etc/machine-id` НЕ очищать.

#### Scenario: Запуск на любом клоне
- **WHEN** клон стартует с эталонной конфигурацией `sources=["override"], override="installation"`
- **THEN** resolver возвращает SHA-256("installation") → bootstrap-cert совпадает на всех клонах

### BOOT-002 — finish-bootstrap.sh — single-pass flip

[[fleet.clone-bootstrap|Завершение клонированного образа]] MUST соблюдать правило «finish-bootstrap.sh — single-pass flip» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/clone-image-bootstrap/spec.md, requirement «finish-bootstrap.sh — single-pass flip».

Скрипт должен (offline, root, идемпотентно):
1. Детект `sources=["override"]`; нет → exit 0 без изменений. Есть sources=["override"] без `override="..."` → ERROR, отказ.
2. Atomic rewrite: `sources` → production-набор (default `["dmi_board_serial","machine_id"]`; override: `--sources` > env `POST_INSTALL_SOURCES` > default), строка `override=` комментируется; tmpfile + проверка обеих замен + сохранение perms/owner + mv; backup `config.toml.bak.<UTC>`.
3. `tessera check`; провал → rollback из backup + exit ≠ 0, демон не рестартится (fail-closed).
4. restart `tessera.service`, ожидание active до 30s.
5. `dump-host-id --usb` с poll до **60s**; без USB — fallback-файл в `/var/lib/tessera/`.

Флаги: `--non-interactive`, `--no-restart`, `--no-dump`, `--sources`.

#### Scenario: После flip
- **WHEN** config переключён на реальные источники
- **THEN** host_id_hash меняется → bootstrap-cert «installation» больше не совпадает → reject на этом хосте (атомарная инвалидация); параллельно CA выпускает per-host cert по hash_hex из TSV

### BOOT-003 — CA-сторона (контракт)

[[fleet.clone-bootstrap|Завершение клонированного образа]] MUST соблюдать правило «CA-сторона (контракт)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/clone-image-bootstrap/spec.md, requirement «CA-сторона (контракт)».

CA-инструменты (настройка PKI, выпуск удостоверений, подготовка USB) не должны входить в `.deb` и в этот репозиторий — они не должны лежать на устройстве; поставляются отдельно. Контракт со стороны устройства: CA выпускает per-host
удостоверение по `hash_hex` из строки `active_under_current_config=yes` TSV-дампа `dump-host-id`.
Дополнительно (managed-enrollment): на том же USB-возврате CA-сторона должна отдавать
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

### BOOT-004 — Смежный деплой-констрейнт (информативно)

[[fleet.clone-bootstrap|Завершение клонированного образа]] MUST соблюдать правило «Смежный деплой-констрейнт (информативно)» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/clone-image-bootstrap/spec.md, requirement «Смежный деплой-констрейнт (информативно)».

Runbook парка должен учитывать: клонирование с TPM2-LUKS требует отдельной ручной процедуры пере-enroll TPM (wipe-slot+cryptenroll) — вне зоны tessera, но в одном runbook'е парка.

#### Scenario: Клон с TPM2-LUKS
- **WHEN** эталон с TPM2-LUKS клонируется на новое железо
- **THEN** требуется отдельная ручная процедура пере-enroll TPM (wipe-slot+cryptenroll) вне зоны tessera


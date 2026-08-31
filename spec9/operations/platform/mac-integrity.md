---
id: mac-integrity
kind: операция
context: platform
name: "Мандатная целостность"
aliases:
  - "mac-integrity"
relations:
  references:
    - auth.role
    - auth.credential
anchors:
  code:
    - "crates/tessera_core/src/mac/orchestrator.rs"
  test:
    - "crates/tessera_core/tests/mac_orchestrator.rs"
requirements:
  MAC-001:
    kind: операционное
    subjects:
      - platform.mac-integrity
    origins:
      - "mac-integrity::SPI MacBackend"
    evidence:
      code:
        - "crates/tessera_core/src/mac/orchestrator.rs"
  MAC-002:
    kind: операционное
    subjects:
      - platform.mac-integrity
    origins:
      - "mac-integrity::Поведение открытой сборки при required-политиках"
    evidence:
      code:
        - "crates/tessera_core/src/mac/orchestrator.rs"
  MAC-003:
    kind: операционное
    subjects:
      - platform.mac-integrity
    origins:
      - "mac-integrity::Политика применения (orchestrator) — открыта для аудита"
    evidence:
      code:
        - "crates/tessera_core/src/mac/orchestrator.rs"
  MAC-004:
    kind: операционное
    subjects:
      - platform.mac-integrity
    origins:
      - "mac-integrity::Расширение pam_cert_max_integrity"
    evidence:
      code:
        - "crates/tessera_core/src/mac/orchestrator.rs"
---
# Мандатная целостность

Эта страница заменяет процедурную capability-спеку OpenSpec «mac-integrity»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### MAC-001 — SPI MacBackend

[[platform.mac-integrity|Мандатная целостность]] MUST соблюдать правило «SPI MacBackend» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/mac-integrity/spec.md, requirement «SPI MacBackend».

Trait `MacBackend`, `StubBackend` и мост C-vtable должны оставаться в открытом
ядре. Реальный enforcement подключается подписанным runtime-плагином; один и тот же
открытый бинарь работает со StubBackend без плагина и с PluginBackend при явном выборе.

#### Scenario: Открытая сборка
- **WHEN** собран и запущен публичный host без выбранного валидного плагина
- **THEN** активен StubBackend; закрытый МКЦ-enforcement в Cargo-графе отсутствует

### MAC-002 — Поведение открытой сборки при required-политиках

[[platform.mac-integrity|Мандатная целостность]] MUST соблюдать правило «Поведение открытой сборки при required-политиках» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/mac-integrity/spec.md, requirement «Поведение открытой сборки при required-политиках».

Конфиг с `[mac].cert_integrity=required` или `[mac].runtime=required` должен
явно называть `[mac].backend`. Названный, но отсутствующий/невалидный плагин должен
(обязательно) давать runtime fail-closed и audit, а не ошибку Cargo-сборки.

#### Scenario: required в открытой сборке
- **WHEN** конфиг с required-политикой не называет backend
- **THEN** конфиг отвергается с ошибкой валидации

### MAC-003 — Политика применения (orchestrator) — открыта для аудита

[[platform.mac-integrity|Мандатная целостность]] MUST соблюдать правило «Политика применения (orchestrator) — открыта для аудита» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/mac-integrity/spec.md, requirement «Политика применения (orchestrator) — открыта для аудита».

Orchestrator (матрица ignore/optional/required, эффективная метка, audit-события `mac_*`/`integrity_*`), label-кодек (`SEQUENCE{INTEGER i8, BIT STRING}`) и конфиг-схема `[mac]` должны оставаться в открытом ядре — политика проверяема и аудируема независимо от закрытого FFI-слоя (orchestrator.rs, label.rs, audit.rs).

С введением ролей источник **запрошенной** метки сессии — `payload.mac_mask` выбранной роли.
Эффективная метка = пересечение `mac_mask` роли с потолком серта (`pam_cert_max_integrity`)
и МНКЦ пользователя. Если `mac_mask` роли НЕ покрывается потолком (`(потолок & mac_mask) != mac_mask`),
вход должен быть отклонён с audit-событием — НЕ молчаливое сужение метки: роль обязана
давать ровно то, что заявляет. До введения ролей (роль без `mac_mask` или `roles.enforce != require`)
действует прежняя семантика `min(потолок серта, МНКЦ)`.

#### Scenario: Аудит политики третьей стороной
- **WHEN** безопасник заказчика исследует открытый код
- **THEN** вся логика принятия решения МКЦ (политика, алгебра меток, события) доступна; закрыт только механизм применения метки к ядру ОС

#### Scenario: mac_mask роли не покрыт потолком серта
- **WHEN** роль требует `mac_mask = 0b110`, а потолок серта = `0b100`
- **THEN** отказ входа с audit-событием (не молчаливое сужение до `0b100`)

#### Scenario: Роль без mac_mask
- **WHEN** выбрана роль без секции `mac_mask` (только группы/sudo)
- **THEN** МКЦ-метка сессии определяется прежней семантикой `min(потолок серта, МНКЦ пользователя)`

### MAC-004 — Расширение pam_cert_max_integrity

[[platform.mac-integrity|Мандатная целостность]] MUST соблюдать правило «Расширение pam_cert_max_integrity» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/mac-integrity/spec.md, requirement «Расширение pam_cert_max_integrity».

Расширение должно иметь OID `2.25.273824307386008814506455310913083078403`, DER `SEQUENCE { level INTEGER(-128..127), categories BIT STRING DEFAULT ''B }`, non-critical. Извлечение должно выполняться только из верифицированного сертификата (`VerifiedX509`); ошибка парсинга — audit `cert_max_integrity_parse_failed`, метка трактуется как отсутствующая (x509/max_integrity_ext.rs).

#### Scenario: Malformed расширение
- **WHEN** расширение присутствует, но DER некорректен
- **THEN** эмитится audit-событие, метка = None, аутентификация не блокируется этим полем

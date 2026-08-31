---
id: licensing-distribution
kind: операция
context: platform
name: "Лицензирование и граница поставки"
aliases:
  - "licensing-distribution"
relations:
  references:
    - auth.pam-module
anchors:
  code:
    - "crates/tessera_core/src/mac/backend.rs"
  test:
    - "tests/e2e/cases/26-challenge-license.yaml"
requirements:
  LIC-001:
    kind: операционное
    subjects:
      - platform.licensing-distribution
    origins:
      - "licensing-distribution::Двойная лицензия"
    evidence:
      code:
        - "crates/tessera_core/src/mac/backend.rs"
  LIC-002:
    kind: операционное
    subjects:
      - platform.licensing-distribution
    origins:
      - "licensing-distribution::Граница открытого и коммерческого"
    evidence:
      code:
        - "crates/tessera_core/src/mac/backend.rs"
  LIC-003:
    kind: контракт
    subjects:
      - platform.licensing-distribution
    origins:
      - "licensing-distribution::SPI-контракт MacBackend"
    evidence:
      test:
        - "tests/e2e/cases/26-challenge-license.yaml"
  LIC-004:
    kind: операционное
    subjects:
      - platform.licensing-distribution
    origins:
      - "licensing-distribution::CLA для внешних контрибьюторов"
    evidence:
      code:
        - "crates/tessera_core/src/mac/backend.rs"
---
# Лицензирование и граница поставки

Эта страница заменяет процедурную capability-спеку OpenSpec «licensing-distribution»: она
помещает каждое прежнее требование в адресуемую норму с владельцем, видом и
проверяемым происхождением. Под каждым нормативным предложением сохранены подробные условия, отрицательные
сценарии и rationale; они входят в ту же страницу и уточняют границы нормы.

### LIC-001 — Двойная лицензия

[[platform.licensing-distribution|Лицензирование и граница поставки]] MUST соблюдать правило «Двойная лицензия» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/licensing-distribution/spec.md, requirement «Двойная лицензия».

Открытая часть проекта должна распространяться по двойной лицензии: AGPL-3.0 (по умолчанию) ИЛИ коммерческая лицензия. Репозиторий должен содержать `LICENSE` (полный текст AGPL-3.0), `LICENSE.commercial` (условия и контакт) и dual-license декларацию в README и `debian/copyright`.

#### Scenario: Использование без коммерческой лицензии
- **WHEN** третья сторона использует/распространяет открытую часть без коммерческой лицензии
- **THEN** применяются условия AGPL-3.0 (включая обязанность раскрытия производного кода)

#### Scenario: Коммерческая лицензия
- **WHEN** у пользователя есть коммерческая лицензия
- **THEN** действуют её условия вместо обязательств AGPL

### LIC-002 — Граница открытого и коммерческого

[[platform.licensing-distribution|Лицензирование и граница поставки]] MUST соблюдать правило «Граница открытого и коммерческого» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/licensing-distribution/spec.md, requirement «Граница открытого и коммерческого».

Открытая часть включает: PAM-ядро (auth flow, challenge-response, trust chain, host/user binding), monitord (registry, removal actions, IPC), CLI (check, dump-host-id), integrate-pam.sh, clone-image bootstrap (single-host: finish-bootstrap.sh, dump-host-id), ГОСТ-делегацию в gost-engine, MAC-orchestrator/label-алгебру и StubBackend. В коммерческой поставке: ParsecBackend/libpdp FFI (МКЦ-enforcement), CA-инструменты (admin-tools), коммерческий packaging. Этот репозиторий должен собираться и проходить полный тестовый набор без какого-либо закрытого кода.

#### Scenario: Сборка репозитория
- **WHEN** репозиторий собирается и тестируется без доступа к коммерческим компонентам
- **THEN** сборка и полный тестовый набор проходят (StubBackend, без МКЦ-FFI)

### LIC-003 — SPI-контракт MacBackend

[[platform.licensing-distribution|Лицензирование и граница поставки]] MUST соблюдать правило «SPI-контракт MacBackend» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/licensing-distribution/spec.md, requirement «SPI-контракт MacBackend».

Trait `MacBackend` и `StubBackend`, а также C-ABI `backend.enforcement` должны
оставаться в открытом ядре. Коммерческий Parsec-компонент поставляется отдельной
подписанной `.so`, загружается только при явном `[mac] backend = "parsec"` и не должен
(не допускается) входить в Cargo-граф открытого репозитория. Изменение ABI version — breaking
change с согласованным релизом обеих частей.

#### Scenario: Коммерческая сборка поверх открытого ядра
- **WHEN** установлен коммерческий Parsec-плагин, собранный против открытого ABI
- **THEN** открытый host проверяет подпись и ABI до init, затем contract-тесты MacBackend проходят через C-vtable

### LIC-004 — CLA для внешних контрибьюторов

[[platform.licensing-distribution|Лицензирование и граница поставки]] MUST соблюдать правило «CLA для внешних контрибьюторов» вместе со всеми условиями и отказами, зафиксированными ниже.

Мигрировано из openspec/specs/licensing-distribution/spec.md, requirement «CLA для внешних контрибьюторов».

CONTRIBUTING.md должен требовать CLA (передача прав, достаточная для dual licensing) до принятия первого внешнего PR.

#### Scenario: Первый внешний PR
- **WHEN** внешний контрибьютор открывает PR
- **THEN** PR не мержится до подписания CLA


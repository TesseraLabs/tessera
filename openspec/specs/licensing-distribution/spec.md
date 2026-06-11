# licensing-distribution Specification

## Purpose

Модель лицензирования и распространения открытой части Tessera: двойная лицензия (AGPL-3.0 OR commercial), граница open/commercial, SPI-контракт `MacBackend`, CLA для контрибьюторов.

## Requirements

### Requirement: Двойная лицензия

Открытая часть проекта ДОЛЖНА (MUST) распространяться по двойной лицензии: AGPL-3.0 (по умолчанию) ИЛИ коммерческая лицензия. Репозиторий ДОЛЖЕН (MUST) содержать `LICENSE` (полный текст AGPL-3.0), `LICENSE.commercial` (условия и контакт) и dual-license декларацию в README и `debian/copyright`.

#### Scenario: Использование без коммерческой лицензии
- **WHEN** третья сторона использует/распространяет открытую часть без коммерческой лицензии
- **THEN** применяются условия AGPL-3.0 (включая обязанность раскрытия производного кода)

#### Scenario: Коммерческая лицензия
- **WHEN** у пользователя есть коммерческая лицензия
- **THEN** действуют её условия вместо обязательств AGPL

### Requirement: Граница открытого и коммерческого

Открытая часть включает: PAM-ядро (auth flow, challenge-response, trust chain, host/user binding), monitord (registry, removal actions, IPC), CLI (check, dump-host-id), integrate-pam.sh, clone-image bootstrap (single-host: finish-bootstrap.sh, dump-host-id), ГОСТ-делегацию в gost-engine, MAC-orchestrator/label-алгебру и StubBackend. В коммерческой поставке: ParsecBackend/libpdp FFI (МКЦ-enforcement), CA-инструменты (admin-tools), коммерческий packaging. Этот репозиторий ДОЛЖЕН (MUST) собираться и проходить полный тестовый набор без какого-либо закрытого кода.

#### Scenario: Сборка репозитория
- **WHEN** репозиторий собирается и тестируется без доступа к коммерческим компонентам
- **THEN** сборка и полный тестовый набор проходят (StubBackend, без МКЦ-FFI)

### Requirement: SPI-контракт MacBackend

Trait `MacBackend` (probe/apply_session/get_user_mnkc) и `StubBackend` ДОЛЖНЫ (MUST) оставаться в открытом ядре как стабильный публичный контракт; коммерческий компонент реализует этот trait (ParsecBackend) и подключается статической линковкой. Изменение сигнатур trait — breaking change с согласованным релизом обеих частей.

#### Scenario: Коммерческая сборка поверх открытого ядра
- **WHEN** коммерческая сборка использует открытое ядро (path-dep/submodule, pin на тег)
- **THEN** ParsecBackend линкуется статически и проходит contract-тесты MacBackend из этого репозитория

### Requirement: CLA для внешних контрибьюторов

CONTRIBUTING.md ДОЛЖЕН (MUST) требовать CLA (передача прав, достаточная для dual licensing) до принятия первого внешнего PR.

#### Scenario: Первый внешний PR
- **WHEN** внешний контрибьютор открывает PR
- **THEN** PR не мержится до подписания CLA

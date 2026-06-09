# gost-crypto Delta Specification

## MODIFIED Requirements

### Requirement: Feature-флаги

`gost-tests` ДОЛЖЕН (MUST) гейтить только интеграционные тесты `gost_*_real.rs`; runtime-код
engine компилируется всегда. Интеграционные GOST-тесты ДОЛЖНЫ (MUST) гоняться в CI (nightly,
astra-ветка — gost-engine там гарантирован) на закоммиченных фикстурах `tests/fixtures/gost/`,
регенерируемых `tests/scripts/gen-gost-fixtures.sh` — ГОСТ-путь end-to-end проверяется
автоматически, а не только локально/Vagrant вручную.

#### Scenario: Сборка без gost-tests
- **WHEN** проект собирается без feature-флага `gost-tests`
- **THEN** интеграционные тесты `gost_*_real.rs` исключаются, но runtime-код engine компилируется как обычно

#### Scenario: ГОСТ-регрессия ловится nightly
- **WHEN** изменение ломает GOST-путь (engine, алгоритмы, верификация цепочки)
- **THEN** nightly-прогон `--features gost-tests` на закоммиченных фикстурах падает

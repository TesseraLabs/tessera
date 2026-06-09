# hooks Delta Specification

## ADDED Requirements

### Requirement: Hook-security инварианты в CI

Инварианты безопасности hook-раннера ДОЛЖНЫ (MUST) проверяться автоматически в CI
(nightly container-job), а не оставаться `#[ignore]`: no_new_privs выставлен,
uid-drop выполнен до exec, родительские fd не утекают в хук. Гейт прогона — переменная окружения
`TESSERA_HOOK_SECURITY_TESTS=1` (вместо безусловного ignore): без маркера тесты skip'аются
с диагностикой, с маркером — выполняются реально; окружение job обязано обеспечить
достаточный RLIMIT_NPROC и возможность uid-drop (root в контейнере).

#### Scenario: Прогон в подходящем окружении
- **WHEN** тесты запущены с `TESSERA_HOOK_SECURITY_TESTS=1` в container-job с поднятым RLIMIT_NPROC
- **THEN** инварианты no_new_privs/uid-drop/fd-leak проверяются реально; их нарушение валит job

#### Scenario: Прогон на shared-раннере без маркера
- **WHEN** тесты запущены без маркера (обычный PR-прогон, RLIMIT_NPROC=64)
- **THEN** hook-security тесты skip'аются с явной диагностикой причины (не false-green «passed»)

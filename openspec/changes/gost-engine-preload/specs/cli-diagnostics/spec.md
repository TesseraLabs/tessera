## MODIFIED Requirements

### Requirement: tessera check

Команда ДОЛЖНА (MUST) выполнять префлайт-валидацию БЕЗ запуска демона и без касания сокета: load config → startup-check pipeline (pam_stack ordering, mac runtime vs ядро, anchors, права CA-dir, parsec caps, host_identity probe, конфигурация ГОСТ). Вывод: строки `[INFO]/[WARN]/[ERROR]` в stdout + summary. Exit 0 ⟺ ноль ERROR; INFO/WARN на exit не влияют. Предназначен как `ExecStartPre=` hard-gate и валидатор в finish-bootstrap (check.rs:33–70).

**Шаг ГОСТ-конфигурации** ДОЛЖЕН (MUST) различать четыре состояния и
называть их устойчивыми идентификаторами:

| Запись | Уровень | Когда |
|---|---|---|
| `gost_engine_ok` | INFO | путь задан, ГОСТ-подпись разрешена allow-list'ом, engine загрузился |
| `gost_pkcs11_unsupported` | WARN | `mode = "pkcs11"` и allow-list разрешает ГОСТ — ГОСТ через PKCS#11-токен не поддерживается |
| `gost_engine_configured_unused` | WARN | путь задан, но ГОСТ-подписи не разрешены: engine не будет загружен никогда |
| `gost_engine_load_failed` | ERROR | конфигурация непротиворечива, но загрузка engine провалилась |

Успешная ГОСТ-конфигурация ДОЛЖНА (MUST) подтверждаться записью, а не
молчанием: оператору нужно видеть, что engine действительно загрузился, а не
что про него никто ничего не сказал.

Проверка ДОЛЖНА (MUST) выполнять ту же загрузку, которой пользуется
аутентификация, — иначе префлайт расходится с реальным поведением и
перестаёт быть гейтом.

Хост, не использующий ГОСТ (путь не задан, ГОСТ-подписи не разрешены), НЕ
ДОЛЖЕН (MUST NOT) получать по этому шагу ни одной записи.

#### Scenario: Префлайт без ERROR
- **WHEN** `tessera check` отрабатывает pipeline и не получает ни одной ERROR-записи
- **THEN** команда печатает summary и завершается с exit 0 (INFO/WARN не влияют)

#### Scenario: Корректная ГОСТ-конфигурация подтверждается
- **WHEN** задан `gost_engine_path`, allow-list разрешает ГОСТ-подпись, engine загружается
- **THEN** печатается `[INFO ] gost_engine_ok`, exit 0

#### Scenario: Engine настроен, но недостижим
- **WHEN** `gost_engine_path` задан, ГОСТ-подпись разрешена, но загрузка engine провалилась
- **THEN** печатается `[ERROR] gost_engine_load_failed` с причиной отказа, exit 1

#### Scenario: Мёртвая ГОСТ-конфигурация
- **WHEN** `gost_engine_path` задан, но ни одна ГОСТ-подпись не разрешена allow-list'ом
- **THEN** печатается `[WARN ] gost_engine_configured_unused`, exit 0 — конфигурация бесполезна, но не опасна

#### Scenario: Хост без ГОСТ
- **WHEN** `gost_engine_path` не задан и ГОСТ-подписи не разрешены
- **THEN** по ГОСТ-шагу не печатается ни одной записи

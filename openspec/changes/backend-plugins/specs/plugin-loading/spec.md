# plugin-loading Delta Specification

## ADDED Requirements

### Requirement: Конверт плагина

Плагин ДОЛЖЕН (MUST) экспортировать `extern "C" fn tessera_plugin_entry() -> *const TesseraPluginHeader`.
Заголовок (`#[repr(C)]`): `abi_version: u32`, `kind: u32` (1 = backend.enforcement; значения
для login.method и ui.companion зарезервированы, в v1 отвергаются), `name` и `plugin_version`
(NUL-терминированные строки), `vtable: *const c_void` (тип зависит от kind). `abi_version`
ДОЛЖЕН (MUST) проверяться на строгое равенство версии хоста; несовпадение — отказ загрузки.
Для kind=backend.enforcement vtable ДОЛЖЕН (MUST) зеркалить SPI MacBackend (probe,
probe_mrd, check_write_capability, get_user_mnkc, apply_session,
get/set_file_label включая fd-вариант) плюс `init(config)` / `teardown`.

#### Scenario: Несовпадение abi_version
- **WHEN** плагин собран под другой abi_version
- **THEN** загрузка отвергается до вызова init, audit `plugin_rejected reason=abi`, активен StubBackend

#### Scenario: Незарезервированный или будущий kind
- **WHEN** заголовок объявляет kind, не реализованный хостом (включая зарезервированные)
- **THEN** загрузка отвергается, audit `plugin_rejected reason=kind`

### Requirement: Верификация подписи до dlopen

В release-сборке хост ДОЛЖЕН (MUST) верифицировать detached-подпись `<plugin>.so.sig`
(над сырыми байтами файла) по списку публичных ключей, вшитому при компиляции
(`TESSERA_PLUGIN_PUBKEYS`: ключ вендора + опционально дополнительные). Подпись валидна,
если сходится с ЛЮБЫМ ключом списка. Верификация ДОЛЖНА (MUST) выполняться ДО dlopen;
механизм отключения в release НЕ ДОЛЖЕН (MUST NOT) существовать (ни конфигом, ни env).
Debug-сборка (`cfg(debug_assertions)`) подпись не проверяет. Формат подписи ДОЛЖЕН (MUST)
быть `ed25519:<128 hex>`; каждый элемент `TESSERA_PLUGIN_PUBKEYS` —
32-byte raw public key как 64 hex chars, элементы разделены запятыми.
Идентификатор алгоритма обязателен для расширяемости Ed25519/ГОСТ.

#### Scenario: Подпись отсутствует или невалидна
- **WHEN** рядом с .so нет .sig либо подпись не сходится ни с одним вшитым ключом
- **THEN** dlopen не вызывается, audit `plugin_rejected reason=signature`, активен StubBackend

#### Scenario: Попытка отключить верификацию конфигом
- **WHEN** в конфиге присутствует любой ключ, предполагающий отключение верификации
- **THEN** ключ неизвестен схеме конфига (deny_unknown_fields) — загрузка конфига падает

### Requirement: Обнаружение и явный выбор

Плагины ДОЛЖНЫ (MUST) лежать в `/usr/lib/tessera/plugins/` (root:root, 0755/0644).
Автоактивации НЕ ДОЛЖНО (MUST NOT) быть: хост грузит только плагин, явно названный
конфигом (`[mac] backend = "<name>"`, где name сверяется с заголовком); бэкенд не назван →
StubBackend. Прочие файлы каталога НЕ загружаются; их наличие — audit-событие.

#### Scenario: Подложенный, но не выбранный плагин
- **WHEN** в каталоге лежит валидно подписанный плагин, не названный в конфиге
- **THEN** он не загружается; audit-событие о неактивном файле

### Requirement: Жизненный цикл и panic-граница

Порядок ДОЛЖЕН (MUST) быть: verify → dlopen(`RTLD_NOW|RTLD_LOCAL`) → entry →
abi/kind-проверка → `init(config)` → регистрация. Загруженный плагин живёт до конца
процесса: dlclose НЕ ДОЛЖЕН (MUST NOT) вызываться. Каждая FFI-граница ДОЛЖНА (MUST)
ловить panic внутри plugin callback и возвращать статус `PLUGIN_PANIC`;
Rust unwind payload НЕ ДОЛЖЕН (MUST NOT) пересекать границу `.so`. Host
преобразует этот статус в ошибку PAM-вызова (fail-closed) + audit
`plugin_panic`. Ошибка `init` → плагин отвергнут, StubBackend.

#### Scenario: Паника внутри apply_session
- **WHEN** код плагина паникует при применении метки
- **THEN** вход завершается ошибкой (fail-closed), эмитится `plugin_panic`, процесс не падает в UB

#### Scenario: init вернул ошибку
- **WHEN** `init(config)` возвращает ненулевой код
- **THEN** плагин не регистрируется, audit `plugin_rejected reason=init`, активен StubBackend

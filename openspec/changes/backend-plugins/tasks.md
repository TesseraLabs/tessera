# Tasks: backend-plugins

## 1. Конверт и загрузчик (tessera_core, открытое)

- [ ] 1.1 `plugin/header.rs`: TesseraPluginHeader (#[repr(C)]), kind-enum, abi_version const; unit-тесты malformed-заголовка
- [ ] 1.2 `plugin/verify.rs`: detached .sig над байтами, список вшитых ключей (env TESSERA_PLUGIN_PUBKEYS на сборке), идентификатор алгоритма в формате; cfg(debug_assertions)-ветка; тесты: валид/битая/чужой ключ/нет .sig
- [ ] 1.3 `plugin/loader.rs`: verify → dlopen(RTLD_NOW|RTLD_LOCAL) → entry → проверки → init(config) → реестр; без dlclose; catch_unwind на FFI-границах; audit-события plugin.audit
- [ ] 1.4 Фикстурный тест-плагин (cdylib в tests/), сборка в CI; интеграционные тесты загрузчика по сценариям дельта-спеки

## 2. Мост MacBackend

- [ ] 2.1 C-vtable для backend.enforcement (зеркало MacBackend + init/teardown) + `PluginBackend: MacBackend` поверх vtable; контракт-тесты против фикстурного плагина
- [ ] 2.2 Конфиг `[mac] backend = "<name>"`; выбор в DI-графе pam_tessera; StubBackend-fallback + reason=missing

## 3. Enterprise-плагин (tessera-enterprise)

- [ ] 3.1 Крейт `tessera_backend_parsec` (cdylib): обёртка существующего ParsecBackend в C-vtable
- [ ] 3.2 Пайплайн: сборка, подпись, .deb (плагин + .sig, Depends на открытый пакет)
- [ ] 3.3 E2E на Astra VM: вход с `[mac] backend = "parsec"` через плагин; отказы (нет плагина/битая подпись)

## 4. Миграция и зачистка

- [ ] 4.1 CI tessera: убрать astra-mac из матрицы, добавить сборку фикстурного плагина (после зелёного 3.3)
- [ ] 4.2 Удалить feature `astra-mac` и feature-gated код; обновить README/docs
- [ ] 4.3 Threat-model §5.6 — финализировать по факту имплементации (алгоритм подписи); архив change'а

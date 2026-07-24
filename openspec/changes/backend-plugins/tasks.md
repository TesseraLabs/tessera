# Tasks: backend-plugins

## 1. Конверт и загрузчик (tessera_core, открытое)

- [x] 1.1 `plugin/header.rs`: TesseraPluginHeader (#[repr(C)]), kind/abi constants; layout и malformed-header tests
- [x] 1.2 `plugin/verify.rs`: detached Ed25519 `.sig` над байтами, список вшитых ключей (env `TESSERA_PLUGIN_PUBKEYS` на сборке), идентификатор алгоритма в формате; cfg(debug_assertions)-ветка; тесты: валид/битая/чужой ключ/нет `.sig`
- [x] 1.3 `plugin/loader.rs`: verify → dlopen(RTLD_NOW|RTLD_LOCAL) → entry → проверки → init(config) → реестр; без dlclose; plugin-side panic guard + `PLUGIN_PANIC`; audit-события plugin.audit
- [x] 1.4 Фикстурный тест-плагин (cdylib), сборка в CI; интеграционные тесты good/missing/ABI/kind/malformed/init/panic

## 2. Мост MacBackend

- [x] 2.1 C-vtable для backend.enforcement (зеркало MacBackend + init/teardown) + `PluginBackend: MacBackend` поверх vtable; контракт-тесты против фикстурного плагина
- [x] 2.2 Конфиг `[mac] backend = "<name>"`; выбор в DI-графе pam_tessera/daemon; StubBackend-fallback + reason=missing

## 3. Enterprise-плагин (tessera-enterprise)

- [x] 3.1 Крейт `tessera_backend_parsec` (cdylib): обёртка существующего ParsecBackend в C-vtable
- [x] 3.2 Пайплайн: сборка, подпись, `.deb` (плагин + `.sig`, Depends на открытый пакет)
- [ ] 3.3 E2E на Astra VM: вход с `[mac] backend = "parsec"` через плагин; отказы (нет плагина/битая подпись)

## 4. Миграция и зачистка

- [x] 4.1 CI tessera: убрать astra-mac из матрицы, добавить сборку фикстурного плагина
- [x] 4.2 Удалить feature `astra-mac` и feature-gated код; обновить README/docs
- [ ] 4.3 Threat-model §5.6 — финализировать по факту имплементации (алгоритм подписи); архив change'а

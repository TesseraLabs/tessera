# Proposal: backend-plugins

## Why

Платформо-специфичные enforcement-бэкенды (ParsecBackend сегодня, SELinux-адаптер завтра)
поставляются compile-time feature'ами (`astra-mac`) — это растущая комбинаторика сборок
(stub/astra/selinux/…), два артефакта дистрибуции и пересборка ядра при каждом обновлении
бэкенда. Решение платформенной спеки (2026-06-05): расширения = runtime-плагины — один
открытый бинарь, бэкенды отдельными подписанными `.so`.

## What Changes

- Новый механизм загрузки плагинов: typed-конверт (`tessera_plugin_entry` →
  `TesseraPluginHeader {abi_version, kind, name, plugin_version, vtable}`), C-ABI,
  строгая проверка `abi_version`; v1 реализует kind `backend.enforcement`
  (зарезервированы `login.method`, `ui.companion`).
- Доверие: верификация подписи `.so` ДО dlopen по **списку вшитых при сборке** публичных
  ключей; в release отключение невозможно; debug-сборка не верифицирует
  (`cfg(debug_assertions)`, в .deb не попадает).
- Обнаружение: `/usr/lib/tessera/plugins/`; автоактивации нет — активный бэкенд явно
  называется конфигом (`[mac] backend = "parsec"`), иначе StubBackend.
- Миграция: ParsecBackend пересобирается как `tessera_backend_parsec.so`
  (tessera-enterprise); feature `astra-mac` удаляется по завершении; CI-матрица
  упрощается до одного открытого бинаря + сборка/подпись плагина в astra-job.
- **BREAKING (поставка):** enterprise-функциональность теперь требует установленный
  плагин-пакет, а не отдельный бинарь.

## Capabilities

### New Capabilities

- `plugin-loading`: конверт, ABI-проверка, верификация подписи, обнаружение/выбор,
  жизненный цикл (init/teardown, отсутствие unload, panic-граница), аудит-события.

### Modified Capabilities

- `mac-integrity`: ParsecBackend доставляется плагином; выбор бэкенда конфигом;
  StubBackend — дефолт при отсутствии/невалидности плагина (fail-closed для ролей,
  требующих МКЦ, — по правилам change'а role-format).
- `build-release`: матрица упрощается (один открытый бинарь); сборка тест-плагина в CI;
  инжекция списка ключей на сборке; enterprise-пайплайн собирает и подписывает плагины.
- `configuration`: `[mac] backend = "<name>"` (и общий паттерн выбора бэкендов per-kind).
- `logging-audit`: target `plugin.audit` (`plugin_loaded/plugin_rejected/plugin_panic`).

## Impact

- `tessera_core`: модуль `plugin/` (заголовок, загрузчик, верификация, реестр);
  `PluginBackend`-мост C-ABI ↔ trait `MacBackend`.
- `pam_tessera`: инициализация загрузчика в DI-графе.
- tessera-enterprise: крейт `tessera_backend_parsec` (cdylib) + подпись в пайплайне.
- Threat-model: новая секция §5.6 (код в root-процессе, вшитый список ключей).
- Связанные open questions: алгоритм подписи (общий с манифестом ролей change'а role-format).

# Tasks: device-enrollment

## 1. Импорт enrollment-пакета (tessera_core, открытое)

- [x] 1.1 Модуль `enrollment/import.rs`: разбор enrollment-пакета (per-host `.p12` + manifest тегов/ролей/CRL); managed — верификация подписи + `bundle_version` (переиспользовать `role-store`); standalone — раскладка файлов под FS-perms
- [x] 1.2 Baseline anti-rollback: персист первого принятого `bundle_version`; реплей меньшего → reject; тесты (baseline, rollback, повтор=no-op, больший=применён)
- [x] 1.3 Идемпотентность: повторный импорт того же manifest — no-op; частичный сбой импорта → атомарный откат (tmp → rename), устройство в прежнем состоянии (fail-closed)
- [x] 1.4 Источник тегов: импортированные теги попадают в доверенный источник `device-tags`; произвольный локальный конфиг тегов НЕ принимается

## 2. CLI enrollment (tessera_cli)

- [x] 2.1 Подкоманда `tessera enroll --import <путь|USB>` после `finish-bootstrap`: импорт пакета, отчёт (host_id prefix8, serial, bundle_version, режим)
- [x] 2.2 Standalone-режим: `tessera enroll --standalone` — раскладка файла тегов + ролей под FS-perms (без подписи), для раскатки без сервера
- [x] 2.3 `tessera check` после импорта; провал → откат, exit ≠ 0 (fail-closed)

## 3. clone-image-bootstrap CA-контракт (docs)

- [x] 3.1 `docs/clone-image.md`: шаг — на возврате USB CA отдаёт подписанный manifest (теги+роли+CRL) рядом с per-host сертом; формат enrollment-пакета как контракт CA-стороны
- [x] 3.2 Зафиксировать: назначение тегов = серверная сторона (Control inventory `hash_hex`→теги / оператор при установке)

## 4. Аудит

- [x] 4.1 `logging-audit`: событие `device_enrolled` (host_id prefix8, serial per-host серта, bundle_version, режим standalone/managed)

## 5. Проверка

- [x] 5.1 `openspec validate device-enrollment --strict` зелёный
- [x] 5.2 Интеграционный тест: клон → flip → импорт managed-пакета (теги region:north) → вход по per-host серту с групповым листом проходит; импорт с меньшим bundle_version отвергается
- [x] 5.3 Интеграционный тест standalone: раскатка без сервера — файл тегов + роли под FS-perms, вход работает

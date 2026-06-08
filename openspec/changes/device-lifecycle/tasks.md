# Tasks: device-lifecycle

## 1. un-enroll команда (tessera_core + tessera_cli)

- [ ] 1.1 Wipe-набор `enrollment/unenroll.rs`: удаление per-host `.p12`/ключей, файла/manifest тегов, managed-набора ролей, персиста `bundle_version`, локального CRL-кэша; hash-chain журнал НЕ трогать
- [ ] 1.2 Reverse-flip конфига: продакшн-источники → `sources=["override"], override="installation"` (atomic rewrite + backup, переиспользовать логику finish-bootstrap)
- [ ] 1.3 `tessera check` после flip; провал → rollback из backup, exit ≠ 0 (fail-closed); демон не остаётся в полусостоянии
- [ ] 1.4 CLI `tessera un-enroll` (флаги `--non-interactive`, `--no-restart`); идемпотентность (повторный un-enroll на уже-bootstrap-устройстве — no-op)

## 2. RMA / кража (docs + ссылки)

- [ ] 2.1 `docs/clone-image.md`: раздел вывода устройства — un-enroll (decommission), RMA (host_id меняется → авто-инвалидация, отзыв старого серта на сервере), кража (CRL + карантин, backstop TTL)
- [ ] 2.2 Зафиксировать ссылку на revocation-design для серверного отзыва/карантина

## 3. Аудит

- [ ] 3.1 `logging-audit`: событие `device_unenrolled` (причина, перечень вытертого) в hash-chain журнал перед reverse-flip

## 4. Проверка

- [ ] 4.1 `openspec validate device-lifecycle --strict` зелёный
- [ ] 4.2 Интеграционный тест: рабочее устройство → `un-enroll` → состояние вытерто, конфиг в override=installation, следующий старт совпадает с bootstrap-сертом; провал `tessera check` → rollback

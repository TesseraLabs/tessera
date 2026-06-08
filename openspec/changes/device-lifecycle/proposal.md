# Proposal: device-lifecycle

## Why

`clone-image-bootstrap` закрывает вход устройства в парк (enrollment-in), но не выход. CAF-ревью
(`product.md` §5, **H1**) оставило открытым lifecycle: decommission (вывод из парка), RMA (замена
железа), кража устройства. Дизайн-сессия 2026-06-08
(`tessera-ws/specs/2026-06-08-enrollment-lifecycle-design.md` §6) определила device-side поведение,
переиспользуя override-механизм наоборот. Вне scope: Codes / per-device ключ (только cert-путь).

## What Changes

- Новая capability **device-unenroll**: device-side команда `tessera un-enroll` (offline, root) —
  зеркало `finish-bootstrap` наоборот: wipe per-host серта/ключей, тегов, набора ролей, персиста
  `bundle_version`, локального CRL-кэша + reverse-flip конфига в `sources=["override"],
  override="installation"` → устройство снова bootstrap-ready (перераскатываемо). Final audit.
- **RMA** (информативно): замена железа меняет `host_id` → старый per-host серт сам не совпадает
  (авто-инвалидация, без спец-логики); старый серт отзывается на сервере (CRL) для гигиены.
- **Кража / недоступное устройство**: device-side нового нет — серверный отзыв (CRL, «отзыв вечен»)
  + карантин (`revocation-design`); backstop — короткий TTL серта.
- Audit: `device_unenrolled`.

## Capabilities

### New Capabilities

- `device-unenroll`: команда un-enroll (reverse-flip + wipe-набор), fail-closed rollback через
  `tessera check`, final audit, результат bootstrap-ready; семантика RMA и кражи (информативно,
  ссылки на host-identity и revocation).

### Modified Capabilities

- `logging-audit`: событие `device_unenrolled`.

## Impact

- `tessera_core`: wipe-набор секретов/состояния; reverse-flip (переиспользует логику atomic rewrite
  `finish-bootstrap`).
- `tessera_cli`: подкоманда `tessera un-enroll` (флаги `--non-interactive`, `--no-restart`),
  `tessera check` после flip, rollback из backup при провале.
- Документация: `docs/clone-image.md` — раздел вывода устройства (un-enroll / RMA / кража).
- Control (закрытый, будущий): отзыв per-host серта при decommission/RMA/краже — контракт
  (revocation-design).

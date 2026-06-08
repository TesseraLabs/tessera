# Design: device-lifecycle

## Context

Источник — `tessera-ws/specs/2026-06-08-enrollment-lifecycle-design.md` §6. Вывод устройства из
парка зеркалит enrollment-in: `finish-bootstrap` flip'ает override→продакшн; un-enroll flip'ает
обратно + вытирает накопленное состояние. RMA опирается на `host-identity` (host_id меняется →
авто-инвалидация серта), кража — на `revocation-design` (CRL + карантин). Вне scope: Codes /
per-device ключ.

## Goals / Non-Goals

**Goals:**
- Device-side `un-enroll`: чистый возврат устройства в bootstrap-ready состояние (offline, root).
- Полный wipe enrollment-состояния (серт/ключи/теги/роли/bundle_version/CRL-кэш).
- Fail-closed: провал `tessera check` после flip → rollback.
- Зафиксировать семантику RMA и кражи (информативно, без новой device-логики).

**Non-Goals:**
- Серверный отзыв/карантин (есть в `revocation-design`); здесь только ссылки.
- Криптостирание дисков/TPM пере-enroll (вне зоны tessera — runbook парка, как в clone-image).
- Codes / per-device ключ.

## Ключевые решения

1. **Reverse-flip переиспользует override.** un-enroll = `finish-bootstrap` наоборот: atomic
   rewrite конфига продакшн-источники → `override=installation`, backup, `tessera check`, rollback
   при провале. Устройство снова совпадает с bootstrap-сертом → перераскатываемо.

2. **Wipe — явный набор.** Вытираются: per-host `.p12`/ключи, файл/manifest тегов, managed-набор
   ролей, персист `bundle_version`, локальный CRL-кэш. Локальный hash-chain журнал НЕ вытирается
   (forensics), фиксируется final-событие `device_unenrolled`.

3. **RMA и кража — без новой device-логики.** RMA: host_id меняется → серт не совпадает
   (`host-identity` first-working-wins). Кража: серверный отзыв (CRL) + карантин
   (`revocation-design`); недоступное устройство — backstop короткий TTL.

## Риски

- Злонамеренный локальный un-enroll (root) = DoS на устройство. Принято: root вне модели угроз
  (паритет finish-bootstrap, который тоже root-only offline). Защита физического доступа — вне tessera.
- Остаточный риск кражи устройства с действующим сертом до истечения TTL: host-binding не помогает
  (это то самое устройство); mitigates TTL + CRL при связности + PIN флешки инженера (серт
  устройства ≠ удостоверение инженера).

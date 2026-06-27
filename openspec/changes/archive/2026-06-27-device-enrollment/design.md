# Design: device-enrollment

## Context

Источник — `tessera-ws/specs/2026-06-08-enrollment-lifecycle-design.md` (§1–5, §7). Tessera v0.3.19:
`clone-image-bootstrap` раскатывает из золотого образа (override=installation → flip →
dump-host-id → per-host серт); `role-store` доставляет роли managed-манифестом (`bundle_version`,
anti-rollback) или standalone (права ФС); `device-tags` (change `tags-delegation`) задаёт источник
тегов (managed-манифест / standalone-файл). Enrollment наполняет эти источники при раскатке.

Ограничения: офлайн-устройство; open-core (раскатка без сервера обязательна); `tessera_core` —
sync; fail-closed на auth-пути. Вне scope: Codes / per-device ключ.

## Goals / Non-Goals

**Goals:**
- Доставка тегов и первого bundle при enrollment поверх существующего flip/USB-потока.
- Два режима: standalone (FS-perms) / managed (подпись + anti-rollback baseline).
- Baseline `bundle_version` + идемпотентный импорт.
- Теги — только из доверенного источника; назначение тегов — серверная сторона.

**Non-Goals:**
- Codes / per-device ключ Codes-MAC (отдельный дизайн при появлении Codes).
- Ротация trust-anchor (H2 — отдельный change); корень пиннится в образе.
- Canary/постепенная выкатка bundle (M5 — серверный блок).
- on-wire протокол доставки (USB-носитель — текущий канал; sync-агент — hybrid-fleets).

## Ключевые решения

1. **Теги/bundle не секретны → открытый USB.** Per-host серт остаётся PIN-защищённым `.p12`
   (существующее); теги/bundle подписаны (managed) или под FS-perms (standalone) — едут открыто
   на том же возврате. Конфиденциальный канал не нужен (нет секретов в scope).

2. **Переиспользование верификации.** Managed-импорт переиспользует проверку подписи и
   `bundle_version` `role-store`; baseline = первый принятый `bundle_version`, далее монотонно.

3. **Назначение тегов вне устройства.** Device принимает теги из доверенного источника, но не
   решает их сам (иначе обход рамок делегирования). Маппинг `hash_hex`→теги — Control/оператор.

4. **Идемпотентность.** Повторный импорт того же manifest — no-op; меньший `bundle_version` —
   reject (anti-rollback); больший — применяется.

## Риски

- Standalone теги под FS-perms (без подписи) — доверие = root/права ФС (паритет role-store
  standalone); приемлемо, root вне модели угроз.
- Кривой enrollment-пакет (битый manifest) → fail-closed: импорт отвергается, устройство
  остаётся в прежнем состоянии (после flip, но без тегов → групповой вход reject, per-host —
  работает по серту).
- bootstrap-poisoning: bootstrap-серт инвалидируется атомарно при flip (clone-image-bootstrap),
  enrollment-импорт идёт уже после flip.

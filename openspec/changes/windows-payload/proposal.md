# Proposal: windows-payload

## Why

`RoleOs::Windows` существует в схеме роли с bootstrap'а, но payload-секций для него
не определено: `validate_payload_for_os` отвергает **любое** поле payload для
`os = "windows"` (`crates/tessera_core/src/role/schema.rs:330`). Концепт
Windows-адаптера (одобрен 2026-06-07) требует, чтобы срез роли нёс
Windows-примитивы: локальные группы, integrity level, отзыв привилегий, лимиты
сессии. Схема payload — открытая часть продукта для всех платформ (формат
открыт всегда, см. licensing-distribution); определить её можно и нужно до
появления Windows-адаптера — ровно так же SELinux-секция парсится без
открытого enforcement-адаптера.

## What Changes

- **Новая вложенная секция `[payload.windows]`** в срезе роли (по образцу
  `[payload.selinux]`): `groups`, `integrity_level`, `privileges_remove`,
  `[payload.windows.limits]`. Parse-only до появления Windows-адаптера —
  открытая и коммерческая сборки парсят и валидируют секцию целиком,
  enforcement не существует.
- **Кросс-ОС валидация**: для `os = "windows"` разрешена только секция
  `windows`; для `astra`/`linux` секция `windows` отвергается
  (`PayloadOsMismatch`) — симметрично существующим правилам.
- **`[session]` для Windows-срезов** — только `max_ttl_seconds`;
  systemd-специфичные поля (`memory_max`, `tasks_max`, `cpu_weight`,
  `io_weight`) для `os = "windows"` отвергаются валидацией: ресурсные
  лимиты Windows живут в `[payload.windows.limits]` со своей семантикой
  (Job Object), а не притворяются systemd-полями.
- `tessera-cli role lint` / `role list` получают Windows-срезы без
  дополнительного кода (общий парсер); тест-фикстуры и golden-примеры
  дополняются.

Не в скоупе: применение payload к сессии (enforcement) — change
`windows-tcb-service`; UI выбора роли — change `windows-cp`; AD/доменные
SID — research отдельным проходом.

## Capabilities

### New Capabilities

_нет_

### Modified Capabilities

- `role-store`: требование «Формат среза роли» дополняется определением
  содержимого `[payload]` для `os = "windows"` (секция `windows`: группы,
  integrity level, отзыв привилегий, лимиты) и ограничением whitelist'а
  `[session]` для Windows-срезов (`max_ttl_seconds` универсален,
  systemd-поля отвергаются).

## Impact

- `crates/tessera_core/src/role/schema.rs`: struct `WindowsSection` (+
  `WindowsLimits`), поле `windows` в `Payload`, правки
  `validate_payload_for_os` (три ветки), новая валидация `[session]` по OS,
  новые варианты ошибок при необходимости; unit-тесты (включая существующий
  `windows_payload_rejected` — переписывается на новый контракт).
- `tessera-cli role lint`: без изменений кода (общий парсер), дополняются
  фикстуры.
- Спеки: delta `role-store`; после реализации sync в main-спеку.
- Docs: `docs/{ru,en}` — раздел формата роли (двуязычно, RU канон).
- Не затрагивает: auth-путь, PAM/сессии, IPC, существующие Linux/Astra-срезы
  (обратная совместимость полная — новая секция опциональна, старые срезы
  валидны без изменений; см. compat-policy).

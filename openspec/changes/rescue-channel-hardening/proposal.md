# Proposal: rescue-channel-hardening

## Why

На рекомендуемой конфигурации (вход только по удостоверению, root заблокирован)
rescue-канал Linux — единственный путь входа мимо Tessera, и его закрытость
складывается из независимых фактов (`поле root в /etc/shadow`,
`SYSTEMD_SULOGIN_FORCE`, пароль GRUB, права на `/boot/grub/user.cfg`),
которые сегодня никто не проверяет согласованно: одна «удобная» правка
(`SULOGIN_FORCE=1`, снятие пароля GRUB) молча открывает консольный root-шелл,
и наоборот — закрытый канал без оформленной процедуры восстановления
превращает поломку PAM-стека в неустранимый lockout (угроза T8).
Кроме того, rescue/emergency-загрузки сейчас бесследны для аудита Tessera:
физическое обслуживание (легитимное или нет) не оставляет события.

Исследование 2026-07-28 (upstream systemd #7115/#11596, LWN «Locked root and
rescue mode», практика FreeIPA/SSSD, стенд Astra SE 1.8.4) зафиксировало:
`sulogin` не использует PAM намеренно, и канал восстановления обязан быть
независим по отказам от подсистемы аутентификации, которую он чинит.
Поэтому change **не** добавляет аутентификацию Tessera внутрь rescue,
а делает канал проверяемым, документированным и наблюдаемым.

## What Changes

- Новые проверки в пайплайне startup-check (`tessera check` и старт демона),
  все advisory (максимум WARN — состояние rescue-канала не является
  инвариантом работоспособности демона):
  - `rescue_root_locked` — поле root в `/etc/shadow`: заблокировано (`!`/`*`) /
    хеш / пустое / нечитаемо;
  - `rescue_sulogin_force` — `SYSTEMD_SULOGIN_FORCE` в override'ах
    `rescue.service`/`emergency.service` и системных env-файлах;
  - `rescue_boot_password` — наличие `superusers`/`password_pbkdf2`
    в конфигурации GRUB;
  - `rescue_grub_user_cfg_perms` — `/boot/grub/user.cfg` (PBKDF2-хеш пароля
    загрузчика) не читается непривилегированными пользователями.
- Аудит rescue-загрузок: monitord при старте детектирует достижение
  `rescue.target`/`emergency.target` в предыдущих загрузках (по journal)
  и эмитит событие аудита «устройство загружалось в аварийный режим».
- Документация (RU канон + EN перевод): раздел «Rescue-канал и восстановление»
  в operations — рекомендуемая конфигурация (root заблокирован, пароль GRUB,
  учёт `--unrestricted` recovery-пункта), двухступенчатая процедура
  восстановления (пароль GRUB + `init=/bin/bash`; внешний носитель +
  recovery-ключ LUKS при FDE), требование организационно зафиксировать
  внеполосные секреты до перевода устройства в cert-only, поведение
  устройства в emergency (останов fail-closed, `nofail` для некритичных
  точек монтирования).
- Threat-model: обновление T8 (rescue-канал: проверки + аудит + требование
  процедуры) и фиксация принципа «канал восстановления НЕ ДОЛЖЕН (MUST NOT)
  зависеть от подсистемы аутентификации Tessera» как design-инварианта.

Вне объёма (осознанно): PAM/токен-диалог внутри rescue (противоречит
принципу независимости канала восстановления, прецедентов в upstream нет);
привязка токена к разблокировке LUKS (`systemd-cryptenroll --pkcs11-token-uri`) —
отдельный будущий change со своим анти-lockout-контуром;
enforcement состояния root (установка блокировки — предмет провижининга
образа/Census, не Tessera).

## Capabilities

### New Capabilities

- `rescue-boot-audit`: детект rescue/emergency-загрузок устройства
  по journal при старте monitord и событие аудита при обнаружении.

### Modified Capabilities

- `cli-diagnostics`: пайплайн проверок дополняется группой `rescue_*`
  (4 advisory-проверки закрытости rescue-канала); требование честного
  WARN при невозможности выполнить проверку (нет прав на `/etc/shadow`) —
  «не смогли проверить» не эквивалентно «проверка пройдена».

## Impact

- Код: `tessera_cli` — новый модуль `startup_check/rescue.rs` (проверки),
  `daemon`/startup — вызов детекта rescue-загрузок и событие аудита;
  auth-путь (pam_tessera, tessera_core) не затрагивается.
- Конфигурация: без изменений схемы `config.toml` (проверки и аудит
  безусловны, advisory).
- Документация: `docs/ru/operations.md` (новый раздел), правки
  `docs/ru/install.md`, `docs/ru/troubleshooting.md` (уточнение recovery:
  `systemd.unit=rescue.target` при заблокированном root не работает,
  рабочий путь — `init=/bin/bash`), `docs/ru/threat-model.md` (T8, принцип);
  EN-синк тех же файлов.
- Зависимости: чтение journal предыдущих загрузок (`journalctl -b -1` /
  libsystemd) — только на старте демона, не на auth-пути.

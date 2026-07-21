# Tasks: role-account-model

## 1. Спеки (delta → sync при архиве)

- [x] 1.1 Delta `role-selection`: «Явный выбор роли» — целевой вход в ролевую УЗ, суффикс/prompt — депрекейт с KNOWN GAP; «Канонизация PAM_USER» — депрекейт-механизм
- [x] 1.2 Delta `role-selection`: дополнить по аудиту — «Резолв и покрытие» (повторный выбор в prompt-режиме — пометка депрекейт-пути); при синке обновить Purpose спеки и строку в openspec/specs/README.md
- [x] 1.3 Delta `cert-scope-binding`: семантика user_binding = ролевые УЗ; Purpose («привязка к PAM-пользователю») — при синке
- [x] 1.4 `issuer-cabinet` («пользователи предлагаются из инвентаря» → «ролевые УЗ») — правится в делте change cabinet-inventory-tab-and-persistence (то же требование, тот же PR)
- [x] 1.5 ОСОЗНАННО БЕЗ ПРАВКИ: `configuration/spec.md` (сценарий enforce=false) и `logging-audit/spec.md` («не склейка user+role») — формулировки верны для живого депрекейт-пути; перепишет change перепроводки role-selection

## 2. Документация RU+EN

- [x] 2.1 `docs/{ru,en}/configuration.md` «Выбор роли на логине»: целевая модель (вход в ролевую УЗ) + явная пометка «текущий код: суффикс/prompt (депрекейт)»; убрать `ssh ivanov+serv@device` как основной пример
- [x] 2.2 `docs/{ru,en}/cert-issuance.md`: убрать `(user+role)` из описания allowed_roles
- [x] 2.3 `docs/{ru,en}/issuer.md`: примеры `issue-leaf` — `--user oper` (ролевая УЗ, зеркало `--role oper`), личность в CN; пояснение одной строкой
- [x] 2.4 `docs/{ru,en}/architecture.md`: оговорка «pam_user — имя ролевой УЗ, не человека» (low)

## 3. Тексты кода и UI

- [x] 3.1 `crates/tessera_issuer/src/lib.rs` rustdoc-пример: `user_binding: vec!["oper"]` (зеркало allowed_roles), субъект-личность в CN; тестовые фикстуры `user_binding: ["ivanov"]` подравнять, где это не ломает смысл теста
- [x] 3.2 `crates/tessera_issuer/src/l10n.rs` Caption::Users: «пользователи» → «ролевые УЗ» / "role accounts" (сводка подтверждения агента)
- [x] 3.3 Кабинет: термин «ролевые УЗ» в новых строках dict.ts → «ролевые УЗ» (запрет слова «учётка», канон терминологии 2026-07-07); проверить свежие строки этого дня на тот же запрет
- [ ] 3.4 Openspec-артефакты этой ветки: заменить «ролевые УЗ» на «ролевые УЗ» в текстах changes (cabinet-inventory-tab-and-persistence tasks/подсказки)

## 4. Финализация

- [x] 4.1 Прогоны: тесты кабинета, `cargo test -p tessera_issuer` (l10n), tsc
- [x] 4.2 Ревью в составе сводного: RU/EN синк и депрекейт-рамка подтверждены; грамматика qr-login-спеки поправлена

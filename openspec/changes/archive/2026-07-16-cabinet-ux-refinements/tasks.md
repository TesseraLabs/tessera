# Tasks: cabinet-ux-refinements

Порядок — TDD, чистая логика вперёд UI. Правка кода кабинета — через
typescript-pro. В конце каждой группы: `npm run typecheck` + `npm test` зелёные.

## 1. Чистая логика + тесты (core)

- [x] 1.1 `rolesForSelection(envelopeRoles, snapshotRoles?)` в `core/envelope.ts`: пересечение рамок родителя с ролями инвентаря; без инвентаря — рамки родителя как есть; порядок — по рамкам родителя.
- [x] 1.2 Тесты `core/envelope.test.ts`: пересечение, пустой/отсутствующий инвентарь, роль инвентаря вне рамок отбрасывается.
- [x] 1.3 `buildManualSnapshot(payload): SnapshotFile` в `core/snapshot.ts`: `{payload_json: JSON.stringify(payload), signature_b64: null}`.
- [x] 1.4 Тесты `core/snapshot.test.ts`: `buildManualSnapshot` → `acceptSnapshot` принимает как `origin:"manual"` с верным возрастом.

## 2. Виджеты + тесты (ui/widgets)

- [x] 2.1 `suggestingStringListInput(add, remove, suggestions[], initial?)` в `ui/widgets.ts`: как `stringListInput`, но `<input list>` + общий `<datalist>` из `suggestions`; `getValue`/`setValue` — паритет.
- [x] 2.2 Тест getValue: свободный ввод сохраняется, пустые строки отфильтрованы (переиспользовать стиль существующих тестов; при необходимости — минимальный DOM-shim, как в текущих ui-независимых проверках, иначе вынести чистую часть).

## 3. Конструктор инвентаря (ui + app)

- [x] 3.1 Секция инвентаря — два режима «Собрать | Загрузить файл» (радио/сегмент); файл-путь без изменений.
- [x] 3.2 Конструктор: редакторы устройств (`id`+`label`), пользователей, ролей, тегов → `buildManualSnapshot` → `#snapshot` (origin manual); кнопка «Скачать снапшот» (.json).
- [x] 3.3 Проброс `#snapshot?.payload` в `buildLeafForm`: host/user через `suggestingStringListInput`, роли через `rolesForSelection` + пометка сужения; datalist-подсказки тегов CA-формы.

## 4. Навигация (2 вкладки)

- [x] 4.1 `#activeTab` в состоянии App (default `issue`); таб-бар под шапкой; `render()` рендерит одну вкладку; журнал-секция — во вкладке «Журнал».
- [x] 4.2 i18n `tab_issue`/`tab_journal`; CSS `.tab-bar`.

## 5. Справки (модалки)

- [x] 5.1 `ui/modal.ts`: `openModal(title, bodyNodes[])` — оверлей, закрытие Esc/фон, возврат фокуса, только локальный DOM; CSS модалки.
- [x] 5.2 Кнопка «?» у блока родителя → модалка (корень vs CA организации, `issuer issue-ca`, PEM/DER, ссылка на доки).
- [x] 5.3 Кнопка «?» у блока агента → модалка (`issuer serve`, автостарт Linux/macOS/Windows, парный токен, allow-origin).
- [x] 5.4 i18n всех текстов справок (абзацы — ключами; код-сниппеты — литералы).

## 6. Агент: «Подключить» + статус

- [x] 6.1 `#agentStatus` в состоянии App; индикатор (точка+подпись) seed из состояния при `render()`.
- [x] 6.2 Кнопка «Подключить» (persist + `agentInfo` → connected/error, императивное обновление индикатора); «Сохранить» — persist. Правка полей → статус `unknown`.
- [x] 6.3 i18n: `agent_connect`, `agent_status_connected`/`_connecting`/`_disconnected`; CSS индикатора.

## 7. Верификация

- [x] 7.1 `npm run typecheck` + `npm test` зелёные (в т.ч. новые тесты).
- [x] 7.2 `bash build.sh` собирает `dist/` без ошибок.
- [x] 7.3 Визуальная проверка в браузере (обе вкладки, обе локали, модалки, конструктор→форма, статус агента) — пройдена: вкладки Выпуск/Журнал (журнал изолирован), обе локали, обе модалки справки, конструктор→manual-снапшот («заполнен вручную»), статус агента «● не подключён» после Connect, verify-key только в файловом режиме.
- [x] 7.4 master-code-reviewer по диффу — CRITICAL/HIGH нет; M1 (пустые роли), L2 (гонка connect), L5 (a11y модалки) устранены; L3/L4/L6 оставлены осознанно.

## 8. Спека и доки (после кода)

- [x] 8.1 Синхронизирован `docs/{ru,en}/issuer.md` (шаг 3 «Порядок работы»: конструктор инвентаря + питание форм; абзац про две вкладки и справки). RU прогнан через Главред.
- [ ] 8.2 `openspec archive cabinet-ux-refinements` → промоут дельты в `openspec/specs/issuer-cabinet/spec.md` (включая заполненный Purpose).

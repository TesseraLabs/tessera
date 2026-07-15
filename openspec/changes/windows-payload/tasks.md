# Tasks: windows-payload

## 1. Схема

- [ ] 1.1 `role/schema.rs`: добавить `WindowsLimits` (`memory_max: Option<String>`, `process_max: Option<u32>`) и `WindowsSection` (`groups`, `integrity_level`, `privileges_remove`, `limits`) с `deny_unknown_fields`; поле `windows: Option<WindowsSection>` в `Payload`
- [ ] 1.2 Валидация содержимого секции: whitelist `integrity_level` (`untrusted|low|medium|high`), синтаксис SID для элементов `groups` с префиксом `S-1-`, непустые строки, форма `Se…Privilege` для `privileges_remove`; новые варианты `RoleSchemaError`
- [ ] 1.3 `validate_payload_for_os`: ветка `Windows` принимает только секцию `windows` (валидируя содержимое); ветки `Astra`/`Linux` отвергают `windows`
- [ ] 1.4 Валидация `[session]` по OS: для `os = "windows"` systemd-поля (`memory_max`, `tasks_max`, `cpu_weight`, `io_weight`) — ошибка валидации, `max_ttl_seconds` разрешён

## 2. Тесты

- [ ] 2.1 Переписать `windows_payload_rejected` на новый контракт (Linux-поля в Windows-срезе отвергаются) и добавить позитив: полный валидный Windows-срез, пустая секция `[payload.windows]`
- [ ] 2.2 Негативные тесты: секция `windows` в linux/astra-срезе; невалидный `integrity_level`; битый SID; привилегия без `Se`/`Privilege`; systemd-поля `[session]` в Windows-срезе
- [ ] 2.3 Фикстуры `role lint`: валидный и невалидный Windows-срез; прогнать `tessera-cli role lint`

## 3. Спеки и доки

- [ ] 3.1 Прогнать полный тест-сьют и clippy; убедиться в зелёном
- [ ] 3.2 `openspec sync` delta `role-store` в main-спеку после реализации
- [ ] 3.3 `docs/ru` + `docs/en`: раздел формата роли — секция `[payload.windows]` и ограничение `[session]` (RU канон, EN перевод, глоссарий)

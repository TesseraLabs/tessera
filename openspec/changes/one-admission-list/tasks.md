# Tasks: one-admission-list

- [x] 1. `tessera_issuer`: убрать `--user` у `issue-leaf`, поле `user_binding` из `LeafRequest`, выпуск расширения из `leaf_extensions`
- [x] 2. `tessera_core`: убрать `verify_user_binding` (`host_binding.rs`), модуль `x509/user_binding_ext.rs` и его реэкспорты — если ничего не читает расширение
- [x] 3. `tessera_core`: удалить `mapping.rs` (legacy-сопоставление по CN/SAN) и `UserMapping` из конфига
- [x] 4. Конфиг: секция `[[user_mapping]]` отвергается адресной диагностикой (как удалённый `[roles].enforce`), а не общим «unknown field»
- [x] 5. `pam_tessera/src/flow.rs`: `authorize_user` решает допуск по `allowed_roles`; `Deps.user_mappings` уходит; трёхисходной развилки больше нет
- [x] 6. Проверить `hooks/vars.rs` — упоминание `user_binding` в контракте переменных хуков; если переменная реально отдаётся, решение о её судьбе описать в отчёте, НЕ выдумывать
- [x] 7. Тесты: допуск по `allowed_roles`; отказ при роли вне списка; отказ при отсутствии расширения; конфиг с `[[user_mapping]]` отвергается с ожидаемым текстом. Тесты legacy-сопоставления удалить, а не переписать
- [x] 8. Фикстуры: `tests/fixtures/roles/accounts/*.cnf` и `crates/tessera_core/tests/fixtures/gen.sh` — убрать выпуск `user_binding`; перевыпустить. Серийники и открытые ключи фикстур ядра НЕ менять (на них завязаны OCSP/CRL)
- [x] 9. e2e: снять кейс `ROLE-003` — его гарантия схлопнулась в `ROLE-002`; фикстура `acct-foreign` теряет смысл
- [x] 10. `dist/config/config.toml.example`: убрать `[[user_mapping]]`
- [ ] 11. `docs/{ru,en}/`: `install.md` (три расширения → два), `configuration.md` (раздел про `[[user_mapping]]`), `cert-issuance.md`, `architecture.md` — везде, где описан допуск по учётной записи
- [x] 12. `docs/ru/changelog.md` — Breaking, с миграцией
- [ ] 13. Прогон e2e — все кейсы, кроме снятого, остаются зелёными; обновить `BASELINE.md`

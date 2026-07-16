# Tasks: issuer-local-cabinet

Правка Rust — через rust-pro; правка кабинета (TS) — через typescript-pro; доки —
координатор. TDD. В конце — верификация + master-review.

## 1. Раздача кабинета из агента (Rust)

- [x] 1.1 Статик-роутинг в `serve.rs`: `GET /` → index.html, `GET /<asset>` для набора (main.js, styles.css, *.wasm; `main.js.map` НЕ раздаётся); вне набора → 404; `/sign`,`/info` не затеняются; MIME по расширению (`application/wasm`).
- [x] 1.2 Источник ассетов: фича `embed-cabinet` (`include_dir!` от `cabinet/dist/`) + `--cabinet-dir <path>` (внешний dist, канонизация пути + проверка внутри dir против path-traversal). Раздача — ПО УМОЛЧАНИЮ когда кабинет доступен; `--no-cabinet` отключает (чистый мост). Приоритет: `--no-cabinet` > `--cabinet-dir` > встроенное; без встроенного и без `--cabinet-dir` → мост.
- [x] 1.3 Заголовок CSP при раздаче (в т.ч. `frame-ancestors 'none'`), парno с `<meta>` кабинета.
- [x] 1.4 Тесты: `/` и ассеты отдаются с раздачей; path-traversal (`/../…`) отбит; вне набора → 404; `/sign` без токена по-прежнему отвергается при активной раздаче; без флага — мост (404 на `/`).

## 2. Инъекция парного токена (Rust + TS)

- [x] 2.1 Rust: при отдаче `index.html` вшить `<meta name="tessera-agent-token">` (+ origin) — CSP-совместимо, без ослабления script-src. Тест: отданный index содержит meta с текущим токеном сессии.
- [x] 2.2 TS: при старте прочитать инъекцию — если есть, предзаполнить настройки агента; если нет — ручной ввод. Чистая функция парса + тесты. (Сделано typescript-pro: `core/agentInjection.ts`.)
- [x] 2.3 TS: при наличии инъекции агент-секция сворачивается до индикатора коннекта (подключён/не подключён), поля адрес/токен/ключ + «Сохранить» скрыты; статус — авто `GET /info` при загрузке (без клика). Без инъекции — полная секция как сейчас. (Сделано typescript-pro: `ui/app.ts` — `#agentInjected`, `renderAgentSectionInjected()`, `autoCheckAgentConnection()`.)

## 3. Удаление демона/автостарта (Rust)

- [x] 3.1 Убрать `--daemon-token-file`, запись токена в per-OS рантайм-каталоги, логику демон-режима из `serve.rs`/`cli.rs`.
- [x] 3.2 Удалить `crates/tessera_issuer/examples/` (issuer-serve.service / .plist / task.xml).
- [x] 3.3 Обновить/убрать тесты демон-режима; кроссплатформенные абстракции токен-файла демона удалить (оставить путь PKCS#11 + pinentry).

## 4. Ретайр хостинга (CI/инфра)

- [x] 4.1 Удалить `.github/workflows/deploy-issuer.yml`. Проверить, что `issuer.yml` (build/test) остаётся; при необходимости добавить сборку `cabinet/dist` + `issuer` c фичей `embed-cabinet` в релизном пути.
- [ ] 4.2 (операционный хвост, вне кода) issuer.* → 301 на доки, затем снос ресурсов — отдельным проходом, НЕ в этом change.

## 5. Доки

- [x] 5.1 `docs/{ru,en}/issuer.md`: раздел «Агент issuer serve» — раздача кабинета (`--serve-cabinet`/`--cabinet-dir`), инъекция токена; удалить «Демон-режим и автостарт»; раздел «Веб-кабинет» переписать под «кабинет = локальный запуск бинаря», убрать хостинг-нарратив. RU через ru-text/Главред, EN зеркально, глоссарий.
- [x] 5.2 `docs/{ru,en}/threat-model.md` §11: убрать CDN-supply-chain-довод (целостность за подписью бинаря), отметить same-origin как упрощение.

## 6. Верификация

- [x] 6.1 `cargo test -p tessera_issuer --all-features` + workspace зелёные; `cargo test` c фичей `embed-cabinet` (нужен собранный `cabinet/dist`).
- [x] 6.2 `cabinet`: `npm run typecheck` + `npm test`.
- [x] 6.3 clippy 0 / rustfmt / cargo-deny ok.
- [x] 6.4 Ручной прогон: `cabinet/build.sh` → `cargo run -p tessera_issuer --features embed-cabinet -- serve --serve-cabinet …` → открыть localhost → кабинет с предзаполненным токеном → выпуск (SoftHSM, техника [[tessera-local-softhsm]]).
- [x] 6.5 master-code-reviewer по диффу (Rust+TS); критичные/высокие — устранить.

## 7. Спека

- [ ] 7.1 `openspec archive issuer-local-cabinet` → промоут дельты в `openspec/specs/issuer-signing/spec.md`; заполнить Purpose вручную (archive Purpose не трогает).

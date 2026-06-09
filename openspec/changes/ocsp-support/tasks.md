# Tasks: ocsp-support

## 1. Конфиг (tessera_core)

- [ ] 1.1 Перенести `ocsp_responder_url`/`ocsp_timeout_seconds`/`ocsp_cache_ttl_seconds` из Raw в ValidatedConfig (validated.rs:328–337 — снять «parsed but dropped»); диапазоны/дефолты по дельта-спеке configuration; тесты валидации (URL не http/https, таймаут вне 1..=30, ttl вне 0..=86400)
- [ ] 1.2 Запрет `ocsp_*`-ключей вне режимов `ocsp`/`crl_then_ocsp` (по образцу `on_usb_removed_hook_path`); тест «mode=crl + ocsp_responder_url → ошибка валидации»

## 2. OCSP-клиент (tessera_core, новый модуль ocsp/)

- [ ] 2.1 `ocsp/request.rs`: построение OCSPRequest (openssl::ocsp, CertID по issuer, nonce RFC 8954); unit-тесты на RSA/ECDSA/GOST issuer
- [ ] 2.2 `ocsp/http.rs`: блокирующий HTTP/1.1 POST поверх TcpStream (+SSL для https), общий deadline = `ocsp_timeout_seconds`, Content-Length-only, лимит размера ответа; тесты против локального mock-listener'а (медленный ответ → таймаут, обрыв, oversize, HTTP 500)
- [ ] 2.3 `ocsp/response.rs`: парсинг и верификация OCSPResponse — подпись цепочкой к anchors, delegated responder (id-kp-OCSPSigning), nonce-сверка (mismatch → отказ; отсутствие в ответе → допустимо), thisUpdate/nextUpdate с `clock_skew_seconds`; негативные тесты по всей fail-closed матрице
- [ ] 2.4 GOST-ответы: `ensure_loaded_if_any_gost` перед верификацией подписи responder'а; тест за feature `gost-tests`

## 3. Кэш

- [ ] 3.1 `ocsp/cache.rs`: ключ sha256(CertID), DER-файлы в `/var/cache/tessera/ocsp/`, валидность min(nextUpdate, mtime+ttl), `ttl=0` = выключен, кэш только good/revoked, re-верификация при чтении; тесты (протухание по обоим пределам, повреждённый файл → как miss + WARN, unknown не кэшируется)
- [ ] 3.2 postinst: создание `/var/cache/tessera/ocsp/` 0750 root:root; обновить таблицу путей в architecture.md при синке

## 4. Интеграция в auth-путь

- [ ] 4.1 di.rs: заменить сведение mode→`crl_strict` на диспетчер четырёх режимов; `ocsp` — OCSP для всех non-anchor сертов цепочки; `crl_then_ocsp` — порядок по дельта-спеке (свежая покрывающая CRL → без сети); тесты обоих режимов на фикстурах
- [ ] 4.2 Устранить fail-open «mode=ocsp без crl_paths → Ok»: недоступность responder'а/`unknown` → `TrustError` → `PAM_AUTH_ERR`; интеграционный тест сценария architecture.md:536
- [ ] 4.3 Audit/лог-события OCSP-пути (запрос, источник ответа cache/network, причина отказа) — согласовать словарь с logging-audit

## 5. E2E и документация

- [ ] 5.1 Интеграционные тесты против `openssl ocsp`-responder'а (фикстурный CA): good/revoked/unknown/просроченное окно/чужой подписант; happy-path в CI без сети (локальный listener)
- [ ] 5.2 Обновить docs/configuration.md:103–107 и docs/architecture.md:536 (теперь — правда), README-секцию revocation; дельта в main-спеки через `/opsx:sync` или archive
- [ ] 5.3 Ручная проверка на Astra VM: `mode="crl_then_ocsp"` с выключенным responder'ом (отказ), с включённым (вход), с CRL-покрытием (вход без сети)

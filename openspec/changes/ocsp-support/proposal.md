# Proposal: ocsp-support

## Why

Revocation-спека несёт КРУПНЫЙ KNOWN GAP: **OCSP в runtime не реализован вообще** — нет сетевого
клиента, кэша, парсинга ответов. `mode="ocsp"`/`"crl_then_ocsp"` принимаются конфигом, но в runtime
сводятся к булеву `crl_strict`; ключи `ocsp_responder_url`/`ocsp_timeout_seconds`/`ocsp_cache_ttl_seconds`
парсятся, валидируются и **теряются** при конвертации в ValidatedConfig (validated.rs:328–337).
Хуже: `mode="ocsp"` без `crl_paths` даёт пустой store → `check_revocation` сразу Ok — **fail-open**,
прямо противоречащий architecture.md:536 («OCSP недоступен → `PAM_AUTH_ERR`») и конвенции
fail-closed на auth-пути. docs/architecture.md и configuration.md описывают OCSP как рабочий — неверно.

Банкоматный парк (zero-egress) живёт на `mode="none"`+короткий TTL и offline CRL — для него ничего
не меняется. OCSP нужен сегментам с сетью (офисные АРМ, стенды заказчиков, будущий Control-контур),
где CRL-доставка внешним каналом избыточна.

## What Changes

- Новый **OCSP-клиент** в `tessera_core` (sync, без tokio): построение OCSPRequest (OpenSSL
  OCSP-примитивы — собственной криптографии нет), HTTP POST на `ocsp_responder_url` с жёстким
  таймаутом `ocsp_timeout_seconds`, парсинг и верификация OCSPResponse (подпись responder'а
  цепочкой к тем же anchors, nonce, thisUpdate/nextUpdate с учётом clock skew).
- **Дисковый кэш** ответов `/var/cache/tessera/ocsp/*.der` (путь уже зафиксирован в
  architecture.md:229,240): валидность = min(`nextUpdate`, fetch_time + `ocsp_cache_ttl_seconds`);
  кэшируются только определённые статусы (good/revoked), `unknown` не кэшируется.
- **Реальная семантика режимов**: `ocsp` — только OCSP; `crl_then_ocsp` — сначала CRL (если
  свежая CRL покрывает issuer — OCSP не вызывается), иначе OCSP обязателен.
- **Fail-closed**: responder недоступен / таймаут / malformed ответ / статус `unknown` /
  непроверяемая подпись → отказ аутентификации (`PAM_AUTH_ERR`), как обещает architecture.md:536.
  Fail-open сценарий «mode=ocsp без CRL → auth проходит» устраняется.
- **Конфиг-ключи доходят до runtime**: `ocsp_responder_url`/`ocsp_timeout_seconds`/`ocsp_cache_ttl_seconds`
  переносятся в ValidatedConfig; вне OCSP-режимов заданные `ocsp_*`-ключи отвергаются валидацией
  (по образцу `on_usb_removed_hook_path` — молчаливое игнорирование запрещено).

## Capabilities

### Modified Capabilities

- `revocation`: режимы `ocsp`/`crl_then_ocsp` получают runtime-реализацию; новые требования
  «OCSP-клиент» и «OCSP-кэш»; fail-closed семантика недоступности responder'а.
- `configuration`: ключи `[trust.revocation].ocsp_*` — типы, диапазоны, дефолты, обязательность
  при OCSP-режимах, запрет вне их; пробрасывание в ValidatedConfig.

## Impact

- `tessera_core`: новый модуль `ocsp/` (request/response/cache/client), `config/validated.rs`
  (перенос ocsp_* в ValidatedConfig), `di.rs` (замена сведения mode→`crl_strict` на полноценный
  диспетчер режимов), `trust/openssl_verifier.rs` (вызов OCSP на пути проверки).
- Сетевое исключение: architecture.md:34 уже декларирует «только OCSP-запросы» как единственный
  разрешённый сетевой выход ядра — инвариант сохраняется (один HTTP-запрос, без TLS-handshake
  при `http://`, без redirect'ов).
- docs/architecture.md:536 и docs/configuration.md:103–107 становятся правдой (сейчас описывают
  несуществующее поведение).
- Packaging: postinst создаёт `/var/cache/tessera/ocsp/` (0750 root:root).
- Банкоматный продакшн (`mode="none"`) не затрагивается; gost-engine/PKCS#11 пути не затрагиваются.

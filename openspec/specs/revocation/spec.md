# revocation Specification

## Purpose

Проверка отзыва сертификатов. Intended-модель: offline CRL, доставляемая на zero-egress машины внешним каналом (TMS-пакет); OCSP заявлен в конфиге, но в runtime не реализован.

Код: `crates/tessera_core/src/crl/store.rs`, `trust/openssl_verifier.rs`, `di.rs`.

## Requirements

### Requirement: Режимы и их фактическая семантика

`[trust.revocation].mode` ∈ {`none`, `crl`, `ocsp`, `crl_then_ocsp`}. В runtime mode ДОЛЖЕН (MUST) сводиться к булеву `crl_strict = (mode == crl | crl_then_ocsp)` (di.rs:121–139).

- ⚠ KNOWN GAP (КРУПНЫЙ): **OCSP в runtime не реализован вообще** — нет сетевого клиента, кэша, парсинга ответов. `ocsp_responder_url`/`ocsp_timeout_seconds`/`ocsp_cache_ttl_seconds` парсятся, валидируются и теряются при конвертации в ValidatedConfig (validated.rs:328–334). docs/architecture.md:536 и configuration.md:103–107 описывают OCSP как рабочий — неверно.

#### Scenario: mode="ocsp" без crl_paths
- **WHEN** `mode = "ocsp"`, CRL не заданы
- **THEN** store пуст → `check_revocation` сразу Ok → отзыв НЕ проверяется, auth проходит
- ⚠ KNOWN GAP: fail-OPEN, противоречит architecture.md:536 («OCSP недоступен → PAM_AUTH_ERR»)

#### Scenario: mode="crl_then_ocsp"
- **WHEN** задан `crl_then_ocsp`
- **THEN** работает как чистый strict-CRL; «ocsp»-часть no-op; существование CRL-файлов при этом mode НЕ проверяется валидатором (в отличие от `mode="crl"`)

### Requirement: CRL-проверка

`check_revocation` ДОЛЖНА (MUST) для каждой CRL и каждого серта цепочки (включая anchor): если serial (lowercase hex) в `crl.revoked` → `TrustError::Revoked` (store.rs:232–259). Пустой store → Ok («нет CRL = нет проверки»).

#### Scenario: Просроченная CRL (freshness)
- **WHEN** `nextUpdate` присутствует И `nextUpdate <= now`
- **THEN** при `crl_strict=true` → `Crl("CRL expired")` (fail-closed); при `crl_strict=false` → WARN + skip этой CRL (fail-open)

#### Scenario: CRL без nextUpdate
- **WHEN** в CRL нет поля nextUpdate
- **THEN** freshness НЕ проверяется — CRL вечно «свежая» даже в strict
- ⚠ KNOWN GAP: краевой случай не покрыт ни docs, ни offline-invariants дизайном (там требуется thisUpdate/nextUpdate/crlNumber TTL-семантика — не реализована)

### Requirement: Доверие к самой CRL

CRL, попадающая в store, ДОЛЖНА (MUST) в целевой модели проходить верификацию подписи и сопоставление issuer DN с issuer'ом серта; до реализации этой проверки доверие к CRL обеспечивается тем, что CRL-файлы — root-owned конфигурация.

#### Scenario: CRL без проверки подписи (текущее поведение)
- **WHEN** `check_revocation` применяет CRL из store к сертам цепочки
- **THEN** подпись CRL и issuer DN НЕ проверяются — любая CRL из store применяется ко всем сертам по серийнику (root-owned файлы как доверенная конфигурация)

- ⚠ KNOWN GAP (security): `check_revocation` НЕ верифицирует подпись CRL и НЕ сопоставляет issuer DN CRL с issuer'ом серта. Методы `verify_signature`/`verify_signature_with_issuer` реализованы (store.rs:135–173), но не вызываются на пути проверки. Любая CRL из store применяется ко всем сертам по серийнику. Текущая модель неявно доверяет CRL-файлам как конфигурации (root-owned файлы). Кандидат на фикс при включении CRL в продакшн.

### Requirement: Компенсация отсутствия отзыва

При `mode="none"` (текущий продакшн-конфиг банкоматов) компенсация ДОЛЖНА (MUST) обеспечиваться коротким TTL leaf-сертификатов (рекомендация: ≤30 дней; для привилегированных операций ≤7 дней / 24ч) — зафиксировано как deployment-политика (May 2026).

#### Scenario: Отзыв отключён, короткий TTL
- **WHEN** `mode="none"` и проверка отзыва не выполняется
- **THEN** риск компенсируется коротким TTL leaf-сертификатов (≤30 дней; ≤7 дней / 24ч для привилегированных операций) согласно deployment-политике

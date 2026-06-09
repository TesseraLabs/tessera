# revocation Specification

## Purpose

Проверка отзыва сертификатов. Intended-модель: offline CRL, доставляемая на zero-egress машины внешним каналом (TMS-пакет). OCSP в runtime не реализован; ocsp-режимы и ocsp_* ключи конфига отклоняются на валидации до реализации `openspec/changes/ocsp-support`.

Код: `crates/tessera_core/src/crl/store.rs`, `trust/openssl_verifier.rs`, `di.rs`.

## Requirements

### Requirement: Режимы и их фактическая семантика

`[trust.revocation].mode` ∈ {`none`, `crl`} — рабочие режимы. Значения `ocsp` и `crl_then_ocsp` принимаются парсером (обратная совместимость схемы), но ДОЛЖНЫ (MUST) отклоняться валидацией конфига с ошибкой «OCSP is not implemented» (ссылка на `openspec/changes/ocsp-support`) — fail-open режим, в котором OCSP-часть молча не выполняется, запрещён. В runtime mode ДОЛЖЕН (MUST) сводиться к булеву `crl_strict = (mode == crl)` (di.rs).

Ключи `ocsp_responder_url` / `ocsp_timeout_seconds` / `ocsp_cache_ttl_seconds` остаются в raw-схеме, но при их наличии в конфиге валидация ДОЛЖНА (MUST) завершаться той же ошибкой (мёртвых ключей, которые парсятся и игнорируются, быть не должно).

#### Scenario: mode="ocsp" или mode="crl_then_ocsp"
- **WHEN** в конфиге задан `mode = "ocsp"` или `mode = "crl_then_ocsp"`
- **THEN** валидация конфига завершается ошибкой `ConfigInvalid` с сообщением, что OCSP не реализован (`openspec/changes/ocsp-support`); модуль не стартует с таким конфигом

#### Scenario: ocsp_* ключи при любом mode
- **WHEN** в `[trust.revocation]` присутствует любой из ключей `ocsp_responder_url`, `ocsp_timeout_seconds`, `ocsp_cache_ttl_seconds`
- **THEN** валидация конфига завершается ошибкой `ConfigInvalid` с тем же сообщением — независимо от значения `mode`

### Requirement: CRL-проверка

`check_revocation` ДОЛЖНА (MUST) для каждой CRL и каждого серта цепочки (включая anchor): если serial (lowercase hex) в `crl.revoked` → `TrustError::Revoked` (store.rs). Пустой store → Ok («нет CRL = нет проверки»).

CRL ДОЛЖНА (MUST) считаться stale, если выполняется хотя бы одно из условий:

- `nextUpdate` присутствует И `nextUpdate <= now`;
- `crl_max_age_hours` задан И `now > thisUpdate + crl_max_age`.

Stale-CRL при `crl_strict=true` → `TrustError::Crl` (fail-closed); при `crl_strict=false` → WARN + skip этой CRL (fail-open по решению оператора).

#### Scenario: Просроченная CRL (nextUpdate)
- **WHEN** `nextUpdate` присутствует И `nextUpdate <= now`
- **THEN** при `crl_strict=true` → `Crl("CRL stale")` (fail-closed); при `crl_strict=false` → WARN + skip этой CRL

#### Scenario: CRL старше crl_max_age
- **WHEN** `crl_max_age_hours` задан И `now > thisUpdate + crl_max_age` (даже если `nextUpdate` в будущем или отсутствует)
- **THEN** CRL stale: при `crl_strict=true` → `Crl("CRL stale")`; при `crl_strict=false` → WARN + skip

#### Scenario: CRL без nextUpdate и без crl_max_age
- **WHEN** в CRL нет поля `nextUpdate` И `crl_max_age_hours` не задан
- **THEN** свежесть непроверяема: в лог (target `tessera.crl`) пишется WARN о непроверяемой свежести, CRL при этом используется (документированное поведение); отказа нет

### Requirement: Доверие к самой CRL

`check_revocation` ДОЛЖНА (MUST) применять CRL только к сертам, чей issuer DN байт-в-байт (DER) совпадает с issuer DN CRL (RFC 5280 §6.3.3). При несовпадении или при ошибке DER-кодирования issuer-имени серта (scope недоказуем) данная CRL к данному серту НЕ применяется.

Перед применением CRL к серту её подпись ДОЛЖНА (MUST) быть верифицирована публичным ключом issuer-сертификата из проверяемой цепочки (`verify_signature_with_issuer`; issuer ищется по subject DN == issuer DN CRL — цепочка leaf-first и полна вплоть до self-signed anchor, для GOST-issuer'ов предварительно поднимается gost-engine). Невалидная подпись → `TrustError::CrlSignatureInvalid` — fail-closed, тот же класс отказа, что и `Revoked`, и НЕ зависит от `crl_strict`. Подпись верифицируется не более одного раза на CRL за вызов.

#### Scenario: Issuer-DN scope CRL
- **WHEN** `check_revocation` применяет CRL из store к серту цепочки
- **THEN** issuer DN серта сравнивается с issuer DN CRL байт-в-байт по DER; при несовпадении (или DER-ошибке) серт пропускается для этой CRL — серийники чужого issuer'а отозвать нельзя

#### Scenario: CRL с невалидной подписью
- **WHEN** CRL применима к серту цепочки (issuer DN совпал), но её подпись не верифицируется ключом issuer'а
- **THEN** `check_revocation` → `TrustError::CrlSignatureInvalid`, аутентификация отклоняется (fail-closed) — даже при `crl_strict=false` и даже если серийник серта в CRL не числится

#### Scenario: CRL подписана issuer'ом из цепочки
- **WHEN** CRL применима к серту и её подпись верифицируется ключом issuer-сертификата, найденного в цепочке
- **THEN** CRL допускается к проверке серийников; неотозванная цепочка проходит

#### Scenario: Issuer CRL отсутствует в цепочке
- **WHEN** CRL применима к серту (issuer DN совпал), но в цепочке нет сертификата с subject DN == issuer DN CRL (подпись непроверяема)
- **THEN** `check_revocation` → `TrustError::CrlSignatureInvalid` (fail-closed); в верифицированной цепочке эта ветка недостижима — issuer каждого серта присутствует в цепочке

### Requirement: Компенсация отсутствия отзыва

При `mode="none"` (текущий продакшн-конфиг терминалов) компенсация ДОЛЖНА (MUST) обеспечиваться коротким TTL leaf-сертификатов (рекомендация: ≤30 дней; для привилегированных операций ≤7 дней / 24ч) — зафиксировано как deployment-политика (May 2026).

#### Scenario: Отзыв отключён, короткий TTL
- **WHEN** `mode="none"` и проверка отзыва не выполняется
- **THEN** риск компенсируется коротким TTL leaf-сертификатов (≤30 дней; ≤7 дней / 24ч для привилегированных операций) согласно deployment-политике

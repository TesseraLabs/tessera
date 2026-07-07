# revocation Specification

## Purpose

Проверка отзыва сертификатов. Offline CRL (доставляемая на zero-egress машины внешним каналом, TMS-пакет) и OCSP (для сегментов с сетью до responder'а). Четыре режима: `none` / `crl` / `ocsp` / `crl_then_ocsp`.

Код: `crates/tessera_core/src/crl/store.rs`, `crates/tessera_core/src/ocsp/` (request/http/response/cache), `trust/openssl_verifier.rs`, `di.rs`.

## Requirements

### Requirement: Режимы и их фактическая семантика

`[trust.revocation].mode` ∈ {`none`, `crl`, `ocsp`, `crl_then_ocsp`} и ДОЛЖЕН (MUST) быть задан явно: c 2026-07 пропуск секции `[trust.revocation]` или ключа `mode` — ошибка валидации конфига (молчаливого дефолта `none` больше нет; отказ от проверки отзыва требует явного `mode = "none"`). Каждый режим ДОЛЖЕН (MUST) иметь полноценную runtime-семантику (сведение к булеву `crl_strict` упразднено):

| mode | Семантика |
|---|---|
| `none` | отзыв не проверяется; компенсация — короткий TTL leaf-сертов (deployment-политика) |
| `crl` | strict offline CRL: просроченная CRL → отказ |
| `ocsp` | каждый non-anchor серт цепочки проверяется через OCSP-клиент; CRL-store не участвует |
| `crl_then_ocsp` | сначала CRL: свежая CRL, чей issuer DN покрывает серт, даёт статус без сетевого вызова; иначе OCSP обязателен |

Anchor-серты через OCSP НЕ проверяются (доверие к anchor = trust store). В OCSP-режимах неопределимость статуса отзыва ДОЛЖНА (MUST) приводить к отказу аутентификации (fail-closed, `PAM_AUTH_ERR`) — деградации «WARN и пропустить» в OCSP-режимах нет.

#### Scenario: mode не задан явно
- **WHEN** секция `[trust.revocation]` опущена, либо задана без ключа `mode`
- **THEN** валидация конфига завершается ошибкой (`mode` обязателен) — оператор не может оказаться без проверки отзыва по недосмотру; отказ от проверки требует явного `mode = "none"`

#### Scenario: mode="ocsp", responder недоступен
- **WHEN** `mode = "ocsp"`, OCSP responder не отвечает (connect error / таймаут) и валидного кэша нет
- **THEN** `TrustError` → отказ аутентификации (`PAM_AUTH_ERR`) — fail-open сценарий «пустой store → Ok» устранён

#### Scenario: mode="crl_then_ocsp", CRL покрывает issuer
- **WHEN** `mode = "crl_then_ocsp"`, в store есть свежая CRL с issuer DN, совпадающим с issuer проверяемого серта
- **THEN** статус берётся из CRL (отозван → отказ; отсутствует в списке → не отозван); OCSP-запрос НЕ выполняется

#### Scenario: mode="crl_then_ocsp", CRL нет или просрочена
- **WHEN** `mode = "crl_then_ocsp"`, покрывающей свежей CRL для issuer'а серта нет
- **THEN** выполняется OCSP-проверка; её недоступность/неопределимость → отказ (fail-closed)

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

### Requirement: OCSP-клиент

OCSP-клиент ДОЛЖЕН (MUST): строить OCSPRequest через OpenSSL-примитивы (CertID по issuer'у, nonce RFC 8954); выполнять один HTTP POST (`application/ocsp-request`) на `ocsp_responder_url` без redirect'ов и keep-alive; укладываться в общий deadline `ocsp_timeout_seconds` (connect + write + read); ограничивать размер ответа (1 MiB). Ответ ДОЛЖЕН (MUST) приниматься только если: `OCSPResponseStatus = successful`, подпись responder'а верифицируется цепочкой к `[trust]` anchors (delegated responder — только с EKU id-kp-OCSPSigning от issuer'а проверяемого серта), окно thisUpdate/nextUpdate валидно с учётом `clock_skew_seconds`, и nonce (если присутствует в ответе) совпадает с запросом. Статус `unknown` ДОЛЖЕН (MUST) трактоваться как отказ. Для GOST-подписанных ответов перед верификацией ДОЛЖЕН (MUST) загружаться gost-engine (`ensure_loaded_if_any_gost`, fail-closed при отсутствии).

Код: `crates/tessera_core/src/ocsp/{request,http,response}.rs`.

#### Scenario: Ответ со статусом unknown
- **WHEN** responder вернул валидно подписанный ответ со статусом `unknown` для серта цепочки
- **THEN** отказ аутентификации (fail-closed); `unknown` НЕ кэшируется

#### Scenario: Подпись ответа не верифицируется
- **WHEN** OCSPResponse подписан ключом, цепочка которого не строится к anchors (или delegated responder без id-kp-OCSPSigning)
- **THEN** ответ отвергается → отказ аутентификации

#### Scenario: Nonce mismatch
- **WHEN** в ответе присутствует nonce, не совпадающий с nonce запроса
- **THEN** ответ отвергается → отказ; отсутствие nonce в ответе (пре-подписанный ответ) допустимо — защита остаётся за окном thisUpdate/nextUpdate

#### Scenario: Таймаут responder'а
- **WHEN** суммарное время connect+write+read превышает `ocsp_timeout_seconds`
- **THEN** запрос обрывается, исход = недоступность → отказ (в `crl_then_ocsp` — только если CRL не дала статус раньше)

### Requirement: OCSP-кэш

Кэш ДОЛЖЕН (MUST) хранить DER-ответы в `/var/cache/tessera/ocsp/` (0640 root:root; имя файла — hex(sha256(CertID))). Запись валидна до min(`nextUpdate` ответа, mtime + `ocsp_cache_ttl_seconds`); `ocsp_cache_ttl_seconds = 0` — кэш выключен. Кэшироваться ДОЛЖНЫ (MUST) только определённые статусы (`good`, `revoked`); `unknown` НЕ ДОЛЖЕН (MUST NOT) кэшироваться. Кэшированный ответ перед использованием ДОЛЖЕН (MUST) проходить повторную верификацию (подпись, окно валидности) — файл кэша не является доверенным входом; повреждённый/неверифицируемый файл трактуется как cache miss (+WARN), не как отказ.

Код: `crates/tessera_core/src/ocsp/cache.rs`.

#### Scenario: Повторный вход при валидном кэше
- **WHEN** для серта цепочки есть кэшированный ответ в пределах валидности
- **THEN** сетевой запрос не выполняется; статус берётся из кэша после повторной верификации подписи и окна

#### Scenario: Повреждённый файл кэша
- **WHEN** файл кэша не парсится или его подпись не верифицируется
- **THEN** файл трактуется как cache miss (WARN-лог), выполняется сетевой запрос — повреждение кэша не блокирует вход само по себе

#### Scenario: Кэшированный revoked
- **WHEN** в кэше валидный ответ `revoked` для серта цепочки
- **THEN** отказ аутентификации без сетевого запроса (отзыв необратим в пределах валидности ответа)

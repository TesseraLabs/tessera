# revocation Delta Specification

## MODIFIED Requirements

### Requirement: Режимы и их фактическая семантика

`[trust.revocation].mode` ∈ {`none`, `crl`, `ocsp`, `crl_then_ocsp`}; каждый режим ДОЛЖЕН (MUST)
иметь полноценную runtime-семантику (сведение к булеву `crl_strict` упраздняется):

| mode | Семантика |
|---|---|
| `none` | отзыв не проверяется; компенсация — короткий TTL leaf-сертов (deployment-политика) |
| `crl` | strict offline CRL (как сейчас): просроченная CRL → отказ |
| `ocsp` | каждый non-anchor серт цепочки проверяется через OCSP-клиент; CRL-store не участвует |
| `crl_then_ocsp` | сначала CRL: свежая CRL, чей issuer DN покрывает серт, даёт статус без сетевого вызова; иначе OCSP обязателен |

Anchor-серты через OCSP НЕ проверяются (доверие к anchor = trust store). В OCSP-режимах
неопределимость статуса отзыва ДОЛЖНА (MUST) приводить к отказу аутентификации (fail-closed,
`PAM_AUTH_ERR`) — деградации «WARN и пропустить» в OCSP-режимах нет.

#### Scenario: mode="ocsp", responder недоступен
- **WHEN** `mode = "ocsp"`, OCSP responder не отвечает (connect error / таймаут) и валидного кэша нет
- **THEN** `TrustError` → отказ аутентификации (`PAM_AUTH_ERR`) — fail-open сценарий «пустой store → Ok» устранён

#### Scenario: mode="crl_then_ocsp", CRL покрывает issuer
- **WHEN** `mode = "crl_then_ocsp"`, в store есть свежая CRL с issuer DN, совпадающим с issuer проверяемого серта
- **THEN** статус берётся из CRL (отозван → отказ; отсутствует в списке → не отозван); OCSP-запрос НЕ выполняется

#### Scenario: mode="crl_then_ocsp", CRL нет или просрочена
- **WHEN** `mode = "crl_then_ocsp"`, покрывающей свежей CRL для issuer'а серта нет
- **THEN** выполняется OCSP-проверка; её недоступность/неопределимость → отказ (fail-closed)

## ADDED Requirements

### Requirement: OCSP-клиент

OCSP-клиент ДОЛЖЕН (MUST): строить OCSPRequest через OpenSSL-примитивы (CertID по issuer'у,
nonce RFC 8954); выполнять один HTTP POST (`application/ocsp-request`) на `ocsp_responder_url`
без redirect'ов и keep-alive; укладываться в общий deadline `ocsp_timeout_seconds` (connect +
write + read); ограничивать размер ответа. Ответ ДОЛЖЕН (MUST) приниматься только если:
`OCSPResponseStatus = successful`, подпись responder'а верифицируется цепочкой к `[trust]` anchors
(delegated responder — только с EKU id-kp-OCSPSigning от issuer'а проверяемого серта),
окно thisUpdate/nextUpdate валидно с учётом `clock_skew_seconds`, и nonce (если присутствует
в ответе) совпадает с запросом. Статус `unknown` ДОЛЖЕН (MUST) трактоваться как отказ.
Для GOST-подписанных ответов перед верификацией ДОЛЖЕН (MUST) загружаться gost-engine
(`ensure_loaded_if_any_gost`, fail-closed при отсутствии).

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

Кэш ДОЛЖЕН (MUST) хранить DER-ответы в `/var/cache/tessera/ocsp/` (0640 root:root; имя файла —
hex(sha256(CertID))). Запись валидна до min(`nextUpdate` ответа, mtime + `ocsp_cache_ttl_seconds`);
`ocsp_cache_ttl_seconds = 0` — кэш выключен. Кэшироваться ДОЛЖНЫ (MUST) только определённые
статусы (`good`, `revoked`); `unknown` НЕ ДОЛЖЕН (MUST NOT) кэшироваться. Кэшированный ответ
перед использованием ДОЛЖЕН (MUST) проходить повторную верификацию (подпись, окно валидности) —
файл кэша не является доверенным входом; повреждённый/неверифицируемый файл трактуется как
cache miss (+WARN), не как отказ.

#### Scenario: Повторный вход при валидном кэше
- **WHEN** для серта цепочки есть кэшированный ответ в пределах валидности
- **THEN** сетевой запрос не выполняется; статус берётся из кэша после повторной верификации подписи и окна

#### Scenario: Повреждённый файл кэша
- **WHEN** файл кэша не парсится или его подпись не верифицируется
- **THEN** файл трактуется как cache miss (WARN-лог), выполняется сетевой запрос — повреждение кэша не блокирует вход само по себе

#### Scenario: Кэшированный revoked
- **WHEN** в кэше валидный ответ `revoked` для серта цепочки
- **THEN** отказ аутентификации без сетевого запроса (отзыв необратим в пределах валидности ответа)

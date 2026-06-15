# Design: ocsp-support

## Context

Tessera v0.3.19: проверка отзыва = offline CRL (`crl/store.rs`), режим конфига сводится к булеву
`crl_strict` в di.rs:121–139. OCSP заявлен в конфиге и доках, в runtime отсутствует. Целевая
аудитория OCSP — машины с сетью до responder'а (НЕ zero-egress банкоматы: те остаются на
`mode="none"`+короткий TTL либо offline CRL).

Ограничения: `tessera_core` — sync, без tokio; собственная криптография запрещена (сертификационная
стратегия — крипта чужая сертифицированная); auth-путь fail-closed; PAM-вызов имеет жёсткий бюджет
времени (login не должен висеть минутами).

## Goals / Non-Goals

**Goals:**
- Рабочий OCSP на auth-пути: режимы `ocsp` и `crl_then_ocsp` делают то, что обещают доки.
- Fail-closed: неопределимость статуса отзыва = отказ входа.
- Кэш, ограничивающий сетевые вызовы и время логина при повторных входах.
- ГОСТ-цепочки: OCSP-запрос/верификация ответа работают и для GOST-сертов (через gost-engine).

**Non-Goals:**
- OCSP stapling, multi-responder failover, AIA-извлечение URL из серта (responder задаётся
  только конфигом — предсказуемость для офлайн-аудита; AIA — возможное расширение позже).
- Прокси (HTTP_PROXY и пр.) — zero-config сетевой стек, прямое соединение.
- Верификация подписи CRL (отдельный KNOWN GAP revocation-спеки, не этот change).

## Decisions

1. **OCSP-примитивы — OpenSSL** (`openssl::ocsp`: OcspRequest/OcspResponse/OcspBasicResponse).
   Сборка/парсинг DER, верификация подписи ответа — чужой сертифицированный код, своей крипты нет.
   Альтернатива (ручной ASN.1 через der-crate) отвергнута: дублирует то, что уже линкуем.
2. **HTTP-клиент — минимальный собственный POST поверх `std::net::TcpStream`** (плюс
   `openssl::ssl` для `https://`): один запрос `POST <path> HTTP/1.1` + `Content-Type:
   application/ocsp-request`, чтение ответа до Content-Length, без redirect'ов, без keep-alive.
   Альтернатива ureq/reqwest отвергнута: новая supply-chain поверхность (cargo deny) ради одного
   POST, к тому же reqwest тянет tokio. Таймаут — на connect и на read/write суммарно
   (`ocsp_timeout_seconds`, deadline через `set_read_timeout`/`set_write_timeout` + общий бюджет).
3. **Кэш — DER-файлы на диске** `/var/cache/tessera/ocsp/<hex(sha256(issuerNameHash ‖
   issuerKeyHash ‖ serial))>.der`, права 0640 root:root (таблица architecture.md:240).
   Валидность записи = min(`nextUpdate` ответа, mtime + `ocsp_cache_ttl_seconds`);
   `ocsp_cache_ttl_seconds = 0` — кэш выключен. Кэшируются только `good` и `revoked`
   (`revoked` кэшируется: статус необратим); `unknown` — никогда. Перед использованием кэшированный
   ответ повторно верифицируется (подпись, окно валидности) — кэш-файл не является доверенным
   входом сам по себе.
4. **Семантика режимов** (заменяет сведение к `crl_strict`):
   - `none` — как сейчас (компенсация коротким TTL).
   - `crl` — как сейчас (strict CRL).
   - `ocsp` — каждый non-anchor серт цепочки проверяется через OCSP; CRL-store не участвует.
   - `crl_then_ocsp` — если в store есть свежая CRL, чей issuer DN покрывает серт, статус берётся
     из неё (отозван → отказ; нет в списке → good, OCSP не вызывается — сеть не трогаем без нужды);
     если CRL нет/просрочена/не покрывает issuer — OCSP обязателен. Anchor'ы OCSP'ом не проверяются
     (responder про них не отвечает; доверие к anchor — это trust store).
5. **Fail-closed матрица**: connect/timeout/HTTP≠200/malformed DER/`OCSPResponseStatus ≠ successful`/
   статус `unknown`/подпись не верифицируется/nonce mismatch/время вне окна (с учётом
   `clock_skew_seconds`) → `TrustError::Ocsp*` → отказ. Деградации «WARN и пропустить» нет ни в
   одном OCSP-режиме — кто хочет мягкость, тот выбирает `none` или нестрогий CRL.
6. **Nonce** (RFC 8954): включается в каждый запрос; если responder вернул nonce — ДОЛЖЕН
   совпасть; если responder nonce не вернул (распространено: пре-подписанные ответы) — допускается,
   защита от replay остаётся за окном thisUpdate/nextUpdate. Кэшированные ответы по построению
   без nonce-проверки (это и есть пре-подписанный ответ).
   **Ответ без nextUpdate**: если responder опустил `nextUpdate`, окно валидности не ограничивает
   replay (ответ «вечно свежий»), поэтому nonce-less ответ без `nextUpdate` мог бы воспроизводиться
   неограниченно. В этом случае дополнительно ограничивается возраст `thisUpdate`: не старше
   `MAX_THIS_UPDATE_AGE_WITHOUT_NEXT_UPDATE` = 86 400 с (24 ч). При наличии `nextUpdate` крышка не
   ставится (`maxsec = None`), чтобы не отклонять легитимные пре-подписанные ответы с далёким
   `nextUpdate`. Responder'ам СЛЕДУЕТ выставлять `nextUpdate`.
7. **Верификация подписи ответа**: цепочка responder'а строится к тем же `[trust]` anchors;
   delegated responder принимается только с EKU id-kp-OCSPSigning от issuer'а проверяемого серта
   (стандартная семантика `OcspBasicResponse::verify`). Для GOST-ответов перед верификацией
   вызывается `ensure_loaded_if_any_gost` (gost-engine, fail-closed при отсутствии).
8. **Бюджет времени логина**: худший случай = (глубина цепочки − 1) × `ocsp_timeout_seconds`.
   Диапазон ключа 1..=30 с дефолтом 5 удерживает worst-case в разумных рамках; кэш сводит
   повторные входы к нулю сетевых вызовов.

## Risks / Trade-offs

- **Responder лёг → парк не логинится** (это и есть fail-closed). Митигация: кэш (вход недавно
  входившего работает), `crl_then_ocsp` с доставленной CRL как первичным источником, и явная
  рекомендация в доках: zero-egress сегментам OCSP не включать.
- **Самодельный HTTP** — узкое место по совместимости (chunked encoding, нестандартные responder'ы).
  Митигация: матрица интеграционных тестов против openssl `ocsp -port` как эталонного responder'а;
  Content-Length обязателен, chunked не поддерживаем (зафиксировать в спеке клиента).
- **Время на машине врёт** → валидные ответы отвергаются. Уже существующий класс проблем
  (notBefore/notAfter серта); используется тот же `clock_skew_seconds`.

## Open Questions

- Нужен ли отдельный audit-target `ocsp.audit` или хватает существующих trust-событий —
  решить при имплементации словаря logging-audit.
- Лимит размера ответа (анти-DoS при компрометации responder'а): предварительно 1 MiB, уточнить
  по реальным размерам GOST-ответов.

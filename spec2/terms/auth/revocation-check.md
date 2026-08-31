---
id: revocation-check
kind: операция
context: auth
name: Проверка отзыва
aliases:
  - проверка отзыва
  - revocation check
forbidden:
  - отзыв
migrated_from: openspec/specs/revocation/spec.md
relations:
  references:
    - auth.ADR-001
    - auth.ADR-002
    - auth.credential
    - auth.credential-revoked
    - auth.crl
    - auth.device-config
    - auth.fail-closed
    - auth.ocsp-responder
    - auth.operator
    - auth.pam-module
    - auth.pkcs12-login
    - auth.revocation-check
    - auth.trust-chain
anchors:
  code:
    - crates/tessera_core/src/crl/store.rs#check_revocation
    - crates/tessera_core/src/trust/openssl_verifier.rs#check_revocation_dispatch
  test:
    - tests/e2e/cases/25-trust-chain.yaml
applies:
  - pattern: fail-closed
    bindings:
      неопределимость: auth.ADR-002
  - pattern: explicit-config
requirements:
  REV-001:
    kind: инвариант
    decided_by:
      - auth.ADR-002
    subjects:
      - auth.device-config
      - auth.pam-module
    evidence:
      test:
        - tests/e2e/cases/15-configuration.yaml
      code:
        - crates/tessera_core/src/config/validated.rs#Validated
  REV-002:
    kind: инвариант
    decided_by:
      - auth.ADR-002
    subjects:
      - auth.revocation-check
    evidence:
      test:
        - tests/e2e/cases/25-trust-chain.yaml
      code:
        - crates/tessera_core/src/trust/openssl_verifier.rs#check_revocation_ocsp
    outcomes:
      - не отозвано
      - отозвано
      - неопределимо
    partitions:
      - outcome: неопределимо
        total: true
        classes:
          - нет покрывающей CRL
          - CRL устарела
          - responder недоступен
          - кэш просрочен
          - ответ не разобран
  REV-003:
    kind: инвариант
    subjects:
      - auth.revocation-check
    evidence:
      test:
        - tests/e2e/cases/25-trust-chain.yaml
      code:
        - crates/tessera_core/src/crl/store.rs#check_revocation
  REV-004:
    kind: инвариант
    decided_by:
      - auth.ADR-001
    subjects:
      - auth.revocation-check
      - auth.crl
    evidence:
      test:
        - tests/e2e/cases/25-trust-chain.yaml
      code:
        - crates/tessera_core/src/crl/store.rs#check_revocation
  REV-005:
    kind: инвариант
    subjects:
      - auth.crl
      - auth.revocation-check
      - auth.operator
    evidence:
      test:
        - tests/e2e/cases/25-trust-chain.yaml
      code:
        - crates/tessera_core/src/crl/store.rs#CrlStore
  REV-006:
    kind: операционное
    subjects:
      - auth.revocation-check
    evidence:
      code:
        - crates/tessera_core/src/trust/openssl_verifier.rs#check_revocation_dispatch
conformance:
  fail-closed/FC-001:
    test:
      - tests/e2e/cases/25-trust-chain.yaml
    code:
      - crates/tessera_core/src/trust/openssl_verifier.rs#check_revocation_ocsp
  fail-closed/FC-002:
    test:
      - tests/e2e/cases/22-logging-audit.yaml
    code:
      - crates/tessera_core/src/crl/store.rs#check_revocation
  fail-closed/FC-003:
    code:
      - crates/tessera_core/src/crl/store.rs#CrlStore
  explicit-config/EC-001:
    test:
      - tests/e2e/cases/15-configuration.yaml
  explicit-config/EC-002:
    test:
      - tests/e2e/cases/15-configuration.yaml
combinations:
  - dimensions:
      mode:
        - none
        - crl
        - ocsp
        - crl_then_ocsp
      CRL:
        - есть
        - нет
      свежесть:
        - свежа
        - устарела
        - непроверяема
      strict:
        - да
        - нет
      OCSP:
        - доступен
        - недоступен
      в списке:
        - да
        - нет
    rows:
      - when:
          mode: none
          CRL: "*"
          свежесть: "*"
          strict: "*"
          OCSP: "*"
          в списке: "*"
        outcome: не отозвано
        note: "`не отозвано` (не проверяется)"
      - when:
          mode: crl
          CRL: нет
          свежесть: "*"
          strict: "*"
          OCSP: "*"
          в списке: "*"
        outcome: не отозвано
        note: "`не отозвано` ⚠"
      - when:
          mode: crl
          CRL: есть
          свежесть: свежа
          strict: "*"
          OCSP: "*"
          в списке: да
        outcome: отозвано
        note: "`отозвано`"
      - when:
          mode: crl
          CRL: есть
          свежесть: свежа
          strict: "*"
          OCSP: "*"
          в списке: нет
        outcome: не отозвано
        note: "`не отозвано`"
      - when:
          mode: crl
          CRL: есть
          свежесть: непроверяема
          strict: "*"
          OCSP: "*"
          в списке: да
        outcome: отозвано
        note: "`отозвано` + предупреждение"
      - when:
          mode: crl
          CRL: есть
          свежесть: непроверяема
          strict: "*"
          OCSP: "*"
          в списке: нет
        outcome: не отозвано
        note: "`не отозвано` + предупреждение"
      - when:
          mode: crl
          CRL: есть
          свежесть: устарела
          strict: да
          OCSP: "*"
          в списке: "*"
        outcome: неопределимо
        note: "`неопределимо` → отказ"
      - when:
          mode: crl
          CRL: есть
          свежесть: устарела
          strict: нет
          OCSP: "*"
          в списке: "*"
        outcome: не отозвано
        note: "`не отозвано` + предупреждение ⚠"
      - when:
          mode: ocsp
          CRL: "*"
          свежесть: "*"
          strict: "*"
          OCSP: доступен
          в списке: да
        outcome: отозвано
        note: "`отозвано`"
      - when:
          mode: ocsp
          CRL: "*"
          свежесть: "*"
          strict: "*"
          OCSP: доступен
          в списке: нет
        outcome: не отозвано
        note: "`не отозвано`"
      - when:
          mode: ocsp
          CRL: "*"
          свежесть: "*"
          strict: "*"
          OCSP: недоступен
          в списке: "*"
        outcome: неопределимо
        note: "`неопределимо` → отказ"
      - when:
          mode: crl_then_ocsp
          CRL: есть
          свежесть: свежа
          strict: "*"
          OCSP: "*"
          в списке: да
        outcome: отозвано
        note: "`отозвано`, OCSP не вызывается"
      - when:
          mode: crl_then_ocsp
          CRL: есть
          свежесть: свежа
          strict: "*"
          OCSP: "*"
          в списке: нет
        outcome: не отозвано
        note: "`не отозвано`, OCSP не вызывается"
      - when:
          mode: crl_then_ocsp
          CRL: нет
          свежесть: "*"
          strict: "*"
          OCSP: доступен
          в списке: да
        outcome: отозвано
        note: "`отозвано`"
      - when:
          mode: crl_then_ocsp
          CRL: нет
          свежесть: "*"
          strict: "*"
          OCSP: доступен
          в списке: нет
        outcome: не отозвано
        note: "`не отозвано`"
      - when:
          mode: crl_then_ocsp
          CRL: нет
          свежесть: "*"
          strict: "*"
          OCSP: недоступен
          в списке: "*"
        outcome: неопределимо
        note: "`неопределимо` → отказ"
      - when:
          mode: crl_then_ocsp
          CRL: есть
          свежесть: устарела | непроверяема
          strict: "*"
          OCSP: "*"
          в списке: "*"
        outcome: null
        note: "**НЕ ОПРЕДЕЛЕНО**"
---

# Проверка отзыва

## Purpose

Установление того, не отозвано ли [[auth.credential|удостоверение]] и
удостоверения его [[auth.trust-chain|цепочки доверия]]. Два источника
статуса: offline [[auth.crl|CRL]], доставляемая на zero-egress-машины
внешним каналом, и [[auth.ocsp-responder|OCSP-responder]] для сегментов
с сетью.

## Requirements

### REV-001 — Режим проверки отзыва задаётся явно

[[auth.device-config|Конфигурация устройства]] MUST содержать явный
`[trust.revocation].mode` из множества `none | crl | ocsp | crl_then_ocsp`.
[[auth.pam-module|Модуль]] MUST NOT подставлять значение по умолчанию.

Оператор не может оказаться без проверки отзыва по недосмотру: отказ от проверки
записывается явным `mode = "none"`, и это видно в ревью конфигурации.

**Почему:** [[auth.ADR-002]]

#### Scenario: Секция отзыва опущена
- **WHEN** секция `[trust.revocation]` отсутствует либо задана без ключа `mode`
- **THEN** валидация конфигурации завершается ошибкой

### REV-002 — Неопределимый статус отклоняет вход

[[auth.revocation-check|Проверка отзыва]] в режимах `ocsp` и `crl_then_ocsp`
MUST завершать [[auth.pkcs12-login|вход]] отказом, если статус отзыва
установить не удалось.

Деградации «предупредить и пропустить» в этих режимах не существует.
Недоступность responder'а, таймаут и отсутствие валидного кэша — это
неопределимость, а не разрешение.

**Почему:** [[auth.ADR-002]]

#### Scenario: Responder недоступен
- **WHEN** `mode = "ocsp"`, responder не отвечает, валидного кэша нет
- **THEN** исход `неопределимо`, вход отклоняется с `PAM_AUTH_ERR`

#### Scenario: Удостоверение числится в источнике статуса
- **WHEN** серийный номер удостоверения найден в свежей CRL либо OCSP вернул статус revoked
- **THEN** исход `отозвано`, вход отклоняется

#### Scenario: Источник статуса отвечает и удостоверения в нём нет
- **WHEN** свежая CRL покрывает issuer и не содержит серийного номера, либо OCSP вернул статус good
- **THEN** исход `не отозвано`, проверка пройдена

### REV-003 — CRL применяется только к своему issuer

[[auth.revocation-check|Проверка отзыва]] MUST применять [[auth.crl|CRL]]
к удостоверению, только если issuer DN удостоверения совпадает с issuer DN CRL
байт-в-байт в DER-представлении.

При несовпадении либо при ошибке DER-кодирования имени эта CRL к этому
удостоверению не применяется: её область действия недоказуема (RFC 5280 §6.3.3).

#### Scenario: Issuer DN не совпадает
- **WHEN** issuer DN удостоверения отличается от issuer DN CRL хотя бы одним байтом
- **THEN** данная CRL к данному удостоверению не применяется

### REV-004 — Подпись CRL верифицируется

[[auth.revocation-check|Проверка отзыва]] MUST верифицировать подпись
[[auth.crl|CRL]] против issuer-удостоверения до того, как использовать её
содержимое. Неверифицированная [[auth.crl|CRL]] MUST NOT влиять на вердикт.

CRL доставляется внешним каналом на машину без сети — то есть по каналу,
который мы не контролируем. Без проверки подписи подменённая CRL становится
способом снять отзыв, а не наложить его.

**Почему:** [[auth.ADR-001]]

#### Scenario: Подпись CRL не сходится
- **WHEN** подпись CRL не верифицируется против issuer-удостоверения
- **THEN** `TrustError::CrlSignatureInvalid`, содержимое CRL не используется

### REV-005 — Устаревшая CRL при строгом режиме отклоняет вход

[[auth.crl|CRL]] MUST считаться устаревшей, если наступил её `nextUpdate`
либо истёк заданный `crl_max_age_hours` от `thisUpdate`.
[[auth.revocation-check|Проверка отзыва]] при `crl_strict = true`
MUST отклонять вход по устаревшей CRL.

[[auth.operator|Оператор]] MAY выключить строгость (`crl_strict = false`), и тогда устаревшая CRL
пропускается с предупреждением. Это осознанное послабление конкретного
развёртывания, а не поведение по умолчанию.

#### Scenario: Свежесть непроверяема
- **WHEN** у CRL нет `nextUpdate` и `crl_max_age_hours` не задан
- **THEN** CRL используется, а в журнал `tessera.crl` пишется предупреждение о непроверяемой свежести

### REV-006 — Anchor не проверяется через OCSP

[[auth.revocation-check|Проверка отзыва]] MUST NOT отправлять OCSP-запрос
для anchor-удостоверения.

Доверие к anchor задаётся trust store устройства, а не ответом внешней стороны.
Спрашивать у сети, доверять ли собственному корню, — значит отдать сети
управление доверием.

#### Scenario: Цепочка с anchor в OCSP-режиме
- **WHEN** `mode = "ocsp"` и цепочка содержит anchor
- **THEN** OCSP-запросы уходят для non-anchor удостоверений, для anchor — нет

### Строка 17 — дыра в спецификации

Шестнадцать сочетаний не покрыты ни одной нормой: `crl_then_ocsp` с покрывающей,
но несвежей CRL. Исходный текст говорит «сначала CRL: **свежая** CRL даёт статус;
иначе OCSP обязателен» — и не отвечает, отменяет ли `crl_strict = true` переход
к OCSP или нет. Оба прочтения защитимы:

- `strict` относится только к режиму `crl` → падаем в OCSP, устаревшая CRL просто
  не даёт статуса;
- `strict` — свойство доверия к CRL вообще → устаревшая CRL отклоняет вход, не
  доходя до сети.

Разница наблюдаемая: в первом прочтении машина с сетью войдёт, во втором — нет.
Требуется решение, а не догадка линта.

### Строки 2 и 8 — послабления, помеченные ⚠

Обе дают `не отозвано` там, где проверка фактически не состоялась, и обе
противоречат [[auth.fail-closed]] `FC-001`, применённому к этой операции.

Строка 8 — осознанное послабление оператора (`crl_strict = false`), то есть
`FC-003`, и вопросов не вызывает.

Строка 2 вопросы вызывает: пустой store в режиме `crl` трактуется как «нет CRL —
нет проверки». Режим назван строгим офлайн-режимом, но не отличает «CRL приехала
и удостоверения в ней нет» от «CRL не приехала». Для zero-egress-машины,
где доставка списка и есть единственный канал отзыва, это означает, что
**неудавшаяся доставка снимает отзыв** — ровно тот сценарий, от которого
защищает [[auth.ADR-001]] на соседнем шаге.

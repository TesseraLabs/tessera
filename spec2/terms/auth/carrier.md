---
id: carrier
kind: сущность
context: auth
name: Носитель
aliases:
  - носитель
  - USB-носитель
  - токен
relations:
  references:
    - auth.ADR-003
    - auth.carrier
    - auth.credential
anchors:
  type:
    - crates/tessera_proto/src/client.rs#CarrierKind
  code:
    - crates/pam_tessera/src/flow.rs#authenticate_pkcs12
  test:
    - tests/e2e/cases/24-usb-media.yaml
requirements:
  AUTH-004:
    kind: операционное
    subjects:
      - auth.carrier
    evidence:
      test:
        - tests/e2e/cases/24-usb-media.yaml
      code:
        - crates/pam_tessera/src/flow.rs#authenticate_pkcs12
---

# Носитель

## Purpose

Ограничиваемая сторона: USB-накопитель с PKCS#12-конвертом либо PKCS#11-токен,
предъявляющий [[auth.credential|удостоверение]]. Носитель доказывает
владение ключом — и только это. Материал доверия он не поставляет
(см. [[auth.ADR-003]]).

## Requirements

### AUTH-004 — Носитель размонтируется по завершении фазы аутентификации

[[auth.carrier|Носитель]] MUST размонтироваться сразу после завершения
фазы аутентификации, на любом пути выхода, включая ошибочный.

Ключ к этому моменту уже использован для challenge, а контекст аутентификации
передан дальше через `pam_data`; смонтированный конверт после этого — только
поверхность атаки.

#### Scenario: Ошибка после монтирования
- **WHEN** аутентификация прервана ошибкой уже после монтирования носителя
- **THEN** носитель размонтируется на пути выхода

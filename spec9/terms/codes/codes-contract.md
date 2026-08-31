---
id: codes-contract
kind: сущность
context: codes
name: Крейт контракта
aliases:
  - крейт контракта
  - tessera_codes_contract
relations:
  references:
    - codes.ADR-004
anchors:
  type:
    - crates/tessera_codes_contract/src/profile.rs#AlgorithmProfile
  code:
    - crates/tessera_codes_contract/src/lib.rs
  test:
    - tests/e2e/cases/27-codes-phone.yaml
---

# Крейт контракта

## Purpose

`tessera_codes_contract` — единственный источник правды по формуле кода,
компилируемый и в устройство, и в кабинет оператора под WASM. Заведён термином
потому, что он субъект целого класса запретов: чего этот крейт делать не должен,
чтобы остаться переносимым и открытым.

Границы его ответственности — байты и алгебра. Он не ходит в сеть, не пишет
файлы, не знает про PAM и не хранит якорей доверия (см. [[codes.ADR-004]]).

---
id: issuer-cli
kind: интерфейс
context: issuance
name: CLI оператора выпуска
entrypoint: crates/tessera_issuer/src/cli.rs#run
relations:
  actor: issuance.issuer-operator
  starts: issuance.leaf-certificate-issuance
  references:
    - issuance.certificate-signing-request
    - issuance.leaf-issuance-scope
anchors:
  code:
    - crates/tessera_issuer/src/cli.rs#IssueLeafJob
  test:
    - tests/e2e/cases/60-issuer.yaml
---

# CLI оператора выпуска

## Purpose

Команда `issuer issue-leaf` — текущая пользовательская поверхность процесса
[[issuance.leaf-certificate-issuance|выпуска листа]]. Она читает входы,
выбирает signing backend, вызывает общее ядро и сохраняет полученный артефакт.

## Состояния

1. Проверка совместимости аргументов и обязательных путей.
2. Чтение родительского сертификата и SPKI либо
   [[issuance.certificate-signing-request|CSR]].
3. Для CSR — показ subject и результата предварительной проверки самоподписи.
4. Выполнение ядра с выбранными [[issuance.leaf-issuance-scope|рамками]].
5. Сообщение о записанном сертификате либо различимая ошибка этапа.

## Доступность

Интерфейс текстовый и не имеет макета. Результат и ошибка доступны через
stdout/stderr и exit status; локализованное сообщение дополняет, но не заменяет
типизированную причину ошибки ядра.

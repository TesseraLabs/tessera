---
id: leaf-certificate-issuance
kind: процесс
context: issuance
name: Выпуск листового сертификата
relations:
  uses:
    - issuance.leaf-issuance-scope
    - issuance.parent-ca-certificate
  accepts:
    - issuance.certificate-signing-request
  invokes:
    - issuance.issue-leaf-certificate
  governed_by:
    - issuance.leaf-scope-policy
    - issuance.artifact-release-policy
  references:
    - issuance.issuer-operator
    - issuance.certificate-requester
anchors:
  code:
    - crates/tessera_issuer/src/cli.rs#issue_leaf_cmd
  test:
    - tests/e2e/cases/60-issuer.yaml
outcomes:
  - сертификат выпущен
  - запрос отвергнут до подписи
  - подпись не получена
  - самопроверка отклонила подписанный артефакт
  - журнал не сохранён, артефакт удержан
  - сертификат выпущен, доставка файла не состоялась
---

# Выпуск листового сертификата

## Purpose

Причинность от команды [[issuance.issuer-operator|оператора выпуска]] до факта
появления пригодного [[auth.credential|удостоверения]]. Процесс выделен отдельно,
потому что пересекает границу заявителя, signing backend, общий с Engine
валидатор и durable журнал.

## Шаги

1. Оператор выбирает родительский CA, signing backend и задаёт
   [[issuance.leaf-issuance-scope|рамки выпуска]].
2. Публичный ключ поступает напрямую либо через
   [[issuance.certificate-signing-request|CSR]]. Для CSR проверяются ключ,
   алгоритм и proof-of-possession; requested extensions не назначают scope.
3. [[issuance.leaf-scope-policy|Политика рамок]] проверяет обязательные поля и
   монотонность относительно [[issuance.parent-ca-certificate|родителя]].
4. [[issuance.issue-leaf-certificate|Операция выпуска]] собирает TBS и получает
   подпись backend.
5. [[issuance.artifact-release-policy|Политика выдачи]] проверяет готовый DER
   общим с Engine кодом.
6. Запись `issue_leaf` сохраняется в
   [[issuance.issuance-journal|журнал выпуска]]. Только после успешного append
   возникает [[issuance.leaf-certificate-issued|факт выпуска]].
7. CLI записывает DER/PEM в выходной файл. Этот шаг доставляет уже выпущенный
   артефакт и не переопределяет факт выпуска задним числом.

## Исходы

### Сертификат выпущен

Подписанный лист прошёл общий валидатор, запись журнала сохранена, ядро вернуло
сертификат. Успешная запись выходного файла подтверждает доставку оператору.

### Запрос отвергнут до подписи

CSR некорректен, host binding пуст, срок невалиден, родитель не несёт delegation
envelope либо scope расширяет хотя бы одно измерение. Signing backend не
вызывается, журнал не изменяется.

### Подпись не получена

Backend недоступен, ключ не найден, алгоритм не совпадает либо операция подписи
завершилась ошибкой. Сертификат и запись журнала не создаются.

### Самопроверка отклонила подписанный артефакт

Подпись уже была вычислена, но общий с Engine разбор или профиль не принимает
результат. Артефакт не возвращается и не записывается в журнал как выпущенный.

### Журнал не сохранён, артефакт удержан

Самопроверка прошла, но durable append завершился ошибкой. Операция возвращает
`IssueError::Journal`; факт выпуска не возникает.

### Сертификат выпущен, доставка файла не состоялась

Ядро уже записало выпуск в журнал, после чего CLI не смог сохранить DER/PEM.
Это не rollback выпуска: инвентарь уже считает сертификат существующим, а
оператору требуется восстановление или повторная доставка, не тихий повтор с
новым serial.

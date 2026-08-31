---
id: pam-conversation
kind: интерфейс
context: auth
name: PAM-диалог входа
entrypoint: crates/pam_tessera/src/entry.rs#pam_sm_authenticate
relations:
  actor: auth.login-subject
  starts: auth.pkcs12-login
  references:
    - auth.pam-conversation
    - auth.role
    - runtime.pam-monitord-ipc
anchors:
  code:
    - crates/pam_tessera/src/pam_conv.rs#prompt_pin
  test:
    - crates/pam_tessera/src/flow.rs#pkcs12_pin_prompt_from_config_reaches_prompter
requirements:
  UI-001:
    kind: операционное
    subjects:
      - auth.pam-conversation
    evidence:
      code:
        - crates/pam_tessera/src/pam_conv.rs#prompt_pin
---

# PAM-диалог входа

## Purpose

Текстовая пользовательская поверхность [[auth.pkcs12-login|входа]]. Tessera
владеет сообщениями, секретностью PIN и последовательностью состояний. Разметкой
окна владеет вызывающее PAM-приложение: Fly-DM, `login`, `sudo` или другой
consumer PAM stack.

## Состояния

1. **Ожидание носителя.** Система ещё не получила удостоверение.
2. **Ввод PIN.** [[auth.login-subject|Предъявитель]] отвечает на секретный prompt.
3. **Проверка.** Выполняются challenge-response, цепочка доверия, привязка к
   устройству и проверка [[auth.role|роли]].
4. **Успех.** PAM получает `PAM_SUCCESS`, а сессия регистрируется через
   [[runtime.pam-monitord-ipc]].
5. **Отказ.** PAM получает различимый код отказа; подробность для эксплуатации
   остаётся в журнале.

## Доступность

Отдельного макета нет: экран рисует PAM-consumer. Текст передаётся стандартными
сообщениями PAM, поэтому терминал и greeter используют собственные средства
доступности. Tessera отвечает за выбор `PAM_PROMPT_ECHO_OFF` для PIN и не
получает визуальных координат элементов.

## Requirements

### UI-001 — PIN не отображается при вводе

[[auth.pam-conversation|PAM-диалог]] MUST запрашивать PIN через
`PAM_PROMPT_ECHO_OFF`. Видимый prompt для несекретных данных является отдельной
операцией и не может использоваться на этом шаге.

#### Scenario: Запрос PIN
- **WHEN** носитель найден и для раскрытия ключа требуется PIN
- **THEN** PAM conversation получает сообщение с режимом `PAM_PROMPT_ECHO_OFF`

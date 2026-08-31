---
id: authentication-proven
kind: событие
context: auth
name: Право входа доказано
relations:
  producer: auth.pkcs12-login
  references:
    - auth.credential
    - auth.role
anchors:
  test:
    - tests/e2e/cases/20-auth.yaml
---

# Право входа доказано

## Purpose

Факт означает, что [[auth.credential|удостоверение]] прошло криптографические
проверки, проверку отзыва, привязку к устройству и допускает запрошенную
[[auth.role|роль]]. Это ещё не окончательный PAM-успех: если развёртывание
требует непрерывного контроля присутствия, сначала должна сработать
[[auth.session-registration-policy|политика регистрации сессии]].

Событие не содержит wire-представления и не отправляется в message bus. Это
адресуемая точка причинности внутри процесса входа.

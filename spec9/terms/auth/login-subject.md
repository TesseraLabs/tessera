---
id: login-subject
kind: сущность
context: auth
name: Предъявитель
aliases:
  - предъявитель
  - пользователь входа
no_anchor:
  code: предъявитель — человек; код оперирует его ролью и удостоверением, а не объектом человека
  type: человек не представлен отдельным типом программы
relations:
  references:
    - auth.credential
    - auth.operator
    - auth.pam-conversation
    - auth.role
anchors:
  test:
    - tests/e2e/cases/18-pam-runtime.yaml
---

# Предъявитель

## Purpose

Человек, который инициирует вход через [[auth.pam-conversation|PAM-диалог]],
предъявляет [[auth.credential|удостоверение]] и запрашивает
[[auth.role|роль]]. Это не [[auth.operator|оператор устройства]]:
оператор задаёт политику машины, а предъявитель является ограничиваемой стороной.

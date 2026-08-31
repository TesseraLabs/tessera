# Синтаксис spec2

Формат состоит из обычного YAML-frontmatter и Markdown-тела. Специального DSL,
версии грамматики и параллельного представления нет.

## Обязательные поля

```yaml
---
id: pam-monitord-ipc
kind: контракт
context: runtime
name: IPC между PAM и демоном
---
```

`id` уникален внутри `context`. Полный ID — `context.id`. `kind` обязан быть
объявлен в `profile.yaml`.

## Словарь

```yaml
aliases: [IPC, локальный протокол]
forbidden: [сокет] # слишком широкое или неверное имя
```

`name` — каноническое имя, `aliases` — разрешённые словоформы и исторические
названия, `forbidden` — слова, маскирующие важное различие.

## Отношения

```yaml
relations:
  transported_by: runtime.pam-monitord-ipc
  handled_by: runtime.monitor-daemon
  writes:
    - runtime.active-session
    - runtime.session-registry
```

Значение — квалифицированный ID или список ID. Имя ключа является типом ребра и
обязано быть объявлено в `profile.yaml → relation_types`. Профиль задаёт
кардинальность, допустимые виды источника и цели и, для причинных связей,
направление обхода. `references` используется только для навигационно значимой
связи, у которой нет более точной роли; причинную цепочку им строить нельзя.

Markdown-ссылка:

```markdown
[[runtime.monitor-daemon|демон]]
```

Она проверяется на существование, но не создаёт графовую связь.

## Якоря

```yaml
anchors:
  code:
    - crates/tessera_cli/src/server.rs#perform_handshake
  type:
    - crates/tessera_proto/src/client.rs#ClientMessage
  schema:
    - crates/tessera_proto/src/client.rs#ClientMessage
  test:
    - crates/tessera_cli/tests/handshake.rs
```

Допустимые типы: `code`, `type`, `test`, `schema`, `exemplar`,
`counterexample`. Допустимость и обязательность типа определяет `kind` в
профиле. `#symbol` необязателен, но предпочтителен для кода и типов.

Если требуемого якоря принципиально нет, причина объявляется явно:

```yaml
no_anchor:
  type: внешний человек не представлен типом программы
```

## Требования

```yaml
requirements:
  IPC-001:
    kind: контракт
    origins: ["ipc-protocol::Сообщения"]
    decided_by: [runtime.ADR-005]
    subjects: [runtime.pam-monitord-ipc]
    evidence:
      schema: [crates/tessera_proto/src/client.rs#ClientMessage]
      test: [crates/tessera_cli/tests/handshake.rs]
    outcomes: [соединение принято, несовместимая версия, неверный первый кадр]
    partitions:
      - outcome: неверный первый кадр
        total: true
        classes: [рабочее сообщение, неизвестный вариант, битый payload]
```

Для каждого ключа под `requirements` в Markdown нужен заголовок:

```markdown
### IPC-001 — Hello предшествует рабочим сообщениям

[[runtime.pam-monitord-ipc|IPC-контракт]] MUST принимать первым кадром только
`Hello`.
```

Заголовок и prose не являются вторым хранилищем метаданных: ID связывает текст
с записью frontmatter, а `kind`, `subjects`, evidence и outcomes читаются только
из YAML. При этом каждый объявленный субъект обязан встретиться типизированной
вики-ссылкой в тексте нормы непосредственно перед нормативным оператором.
`decided_by` необязателен и используется только для нормы, возникшей из явной
развилки; он всегда содержит квалифицированные ID решений.

`origins` — не второй ID нормы, а проверяемый след миграции. Значение имеет вид
`<capability>::<точный заголовок Requirement>` и должно соответствовать
существующему заголовку в `openspec/specs/<capability>/spec.md`. Полноту и
единственность владельца проверяет `spec.mjs coverage`. Для новых норм, которые
не происходят из OpenSpec, поле не задаётся.

## Решения

Принятое решение не переписывается при смене выбора. Новое решение объявляет
замену или отмену и широкий impact:

```yaml
id: ADR-006
kind: решение
context: runtime
status: предложено
date: 2026-08-31
relations:
  replaces: [runtime.ADR-005]
  affects:
    - runtime.pam-monitord-ipc
    - runtime.open-monitored-session
```

После принятия `status` становится `принято`; эффективный статус ADR-005
вычисляется как `заменено`. `revokes` используется для отмены без сохранения
прежней политики. Старый файл менять для этого не нужно.

## Исходы процесса

Файловые исходы применяются к процессу целиком:

```yaml
outcomes:
  - успех
  - отказ по существу
  - отказ по неопределимости
  - исчерпание бюджета попыток
  - таймаут ожидания носителя
```

## Решающая таблица

```yaml
combinations:
  - dimensions:
      mode: [none, crl, ocsp]
      source: [есть, нет]
    rows:
      - when: { mode: none, source: "*" }
        outcome: не отозвано
      - when: { mode: crl, source: нет }
        outcome: null
        note: поведение ещё не определено
```

`*` раскрывается во все значения измерения. `null` — явная дыра, а не wildcard.

## Паттерны

Страница паттерна объявляет требования обычным способом, но использует
`subjects: [application]`. Применение и доказательства:

```yaml
applies:
  - pattern: fail-closed
    bindings:
      неопределимость: auth.ADR-002
conformance:
  fail-closed/FC-001:
    test: [tests/e2e/cases/25-trust-chain.yaml]
  fail-closed/FC-002:
    code: [crates/tessera_core/src/crl/store.rs#check_revocation]
```

Bindings принимают только квалифицированные ID. Паттерн не имеет номера версии.

## Поля профилей границ

Дополнительные поля задаются видом и остаются обычным YAML. Например:

```yaml
# интерфейс
relations: { actor: auth.login-subject }
entrypoint: crates/pam_tessera/src/entry.rs#pam_sm_authenticate

# контракт
relations:
  provider: runtime.monitor-daemon
  consumers: [auth.pam-module]
owner: runtime
compatibility: additive-fields-within-v2

# конфигурация
owner: auth.operator
source: /etc/tessera/config.toml
reload: each-pam-call-and-daemon-start

# хранилище
owner: runtime
format: JSON snapshot
compatibility: additive-serde-defaults
```

Обязательные поля и Markdown-разделы перечислены в `profile.yaml`; линт не
зашивает их по именам вида.

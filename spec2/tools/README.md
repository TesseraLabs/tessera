# spec2/tools

CLI и линт для `spec2/`. Node 20+, ESM. YAML разбирается пакетом `yaml`;
самописного YAML-подмножества нет.

## Команды

```
node tools/spec.mjs lint
node tools/spec.mjs graph
node tools/spec.mjs flow <id>
node tools/spec.mjs draft <kind> <context.id> --name <название>
node tools/spec.mjs trace [<requirement-id|context.id>] [--missing] [--json]
node tools/spec.mjs decision <context.ADR-id> [--json]
node tools/spec.mjs context <id> --slice <implement|why|review>
node tools/spec.mjs why <path>[#symbol]
node tools/spec.mjs outcomes <requirement-id>
node tools/spec.mjs candidates [--new]
node tools/spec.mjs quality [--all] [--json] [--strict]
node tools/spec.mjs next [--all] [--json] [--strict]
node tools/spec.mjs review --base <ref> [--head <ref>] [--json] [--strict]
node tools/spec.mjs change --base <ref> [--head <ref>] [--json]
```

Запускать из корня `spec2/` (или указывать пути от него — `SPEC2_ROOT`
вычисляется относительно `tools/`).

## Тесты

```
npm test
```

Форма `node --test tools/` (директорией, без маски) на Node 24 падает с
`MODULE_NOT_FOUND` — раннер пытается require'ить саму директорию как модуль,
а не обойти её рекурсивно. Рабочая форма с несколькими файлами тестов —
glob-маска:

```
node --test "tools/**/*.test.mjs"
```

(кавычки обязательны — иначе маску раскрывает shell, а не `node --test`).

## Структура

- `parse.mjs` — разбор frontmatter-first файла: relations, требования, evidence,
  outcomes, partitions и combinations читаются только из YAML.
- `markdown.mjs` — низкоуровневый разбор markdown-тела (зоны, ссылки, операторы).
- `combinations.mjs` — проверка модели Combinations (раскрытие `*`
  и дизъюнкций, полнота, непересечение).
- `graph.mjs` — модель репозитория: профиль, сущности, разрешение ссылок и
  evidence-якорей, обязательства паттернов, граф узлов/рёбер.
- `lint.mjs` — все проверки линта.
- `slice.mjs` — именованные срезы графа (`context`, `why`).
- `flow.mjs` — причинный срез с учётом направления `relation_types.*.flow`.
- `draft.mjs` — profile-aware заготовка страницы в stdout; не записывает файл и
  не угадывает доменные отношения или требования.
- `trace.mjs` — матрица `норма → субъект → evidence → реализация → outcomes`;
  `--missing` оставляет только дыры, `--json` даёт стабильный вход для CI и
  агентов.
- `decision.mjs` — declared/effective status ADR, цепочки `replaces/revokes`,
  прямой `affects`, reverse impact на один hop, связанные нормы и trace gaps.
- `adapters/` — адаптеры Rust, TypeScript/JavaScript, C# и Python для
  сопоставления объявленных и escaping-исходов по `code:`-якорю.
- `outcomes-cmd.mjs` — команда `outcomes`: сверка Outcomes требования с
  исходами кода. Без `--fix` — конституция §10 запрещает автоисправление
  расхождения, разрешение делает человек.
- `git-snapshot.mjs` — безопасно материализует `spec2/` из Git-ref во временный
  каталог через `git archive`, не меняя worktree.
- `semantic-review.mjs` — сравнивает два состояния по терминам, нормам,
  relations, anchors, границам и ADR; текстовый diff файлов для этого не нужен.

## Контракт профиля

`profile.yaml` может дать каждому `kind` не только допустимые ссылки и anchors,
но и собственную проверяемую форму:

```yaml
kinds:
  контракт:
    required_fields: [relations.provider, relations.consumers, owner, compatibility]
    required_sections: [Граница, Совместимость, Отказы]
```

`required_fields` поддерживает dotted path и требует непустые значения во frontmatter; пустые строка,
список и объект не засчитываются. `required_sections` требует Markdown-заголовки
с точным именем. Неизвестный ключ профиля является ошибкой: каждый ключ обязан
иметь реализованного владельца либо явно объявленную причину неподдержки в
`profile-registry.mjs`.

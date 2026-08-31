# Spec9 — спецификация Tessera

Этот каталог — продуктовый экземпляр [Spec9](../../../spec9/README.md). Здесь
живут только профиль Tessera, доменные страницы, решения, процессы, границы и
реестр кандидатов. Движок, контракт формата, конституция и agent skills находятся
в отдельном репозитории [RoboNET/Spec9](https://github.com/RoboNET/Spec9).

Структурным источником служит YAML-frontmatter, а Markdown объясняет смысл и
сценарии. Вики-ссылки вида `[[auth.credential|удостоверение]]` дают навигацию;
проверяемые связи находятся в `relations`, носители норм — в
`requirements.*.subjects`, доказательства — в типизированных якорях.

## Состав

- `terms/` — доменные сущности и понятия;
- `operations/` — адресуемые операции и capability;
- `processes/`, `policies/`, `events/` — причинность;
- `interfaces/`, `contracts/` — человеческие и сервисные границы;
- `persistence/` — сохранённое состояние;
- `patterns/` — плоские пакеты обязательств;
- `decisions/` — append-only ADR;
- `profile.yaml` — допустимые виды, связи, якоря и срезы;
- `OPEN_SPEC_MIGRATION.md` — покрытие прежнего OpenSpec.

## Локальная настройка

Для локальной разработки checkout Spec9 ожидается по относительному пути
`../../../spec9` от этого каталога:

```bash
npm --prefix spec9 install
```

Зависимость `file:../../../spec9` делает Tessera интеграционным потребителем
локального движка. После публикации Spec9 её можно заменить обычной версией
пакета без изменения страниц спецификации.

## Команды

Из корня Tessera:

```bash
npm --prefix spec9 test
npm --prefix spec9 run lint
npm --prefix spec9 run graph
npm --prefix spec9 run doctor
npm --prefix spec9 run quality
npm --prefix spec9 run next
npm --prefix spec9 run review -- --base HEAD
npm --prefix spec9 run coverage
```

Для произвольной команды:

```bash
npm --prefix spec9 run spec9 -- --spec-root . --product-root .. flow issuer-cli
```

Git остаётся журналом изменений. `change` формирует секцию `Domain impact`, но
не сохраняет параллельное дерево delta-файлов. Код владеет внутренними полями,
типами и сигнатурами; OpenAPI/AsyncAPI/DDL/JSON Schema и дизайн-инструменты —
формой опубликованных границ; эта спецификация владеет именами, определениями,
инвариантами и связями между ними.

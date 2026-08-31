# spec2 — доменно-адресуемая спецификация Tessera

`spec2/` описывает Tessera как граф терминов, норм, процессов и границ. Каждый
Markdown-файл имеет один YAML-frontmatter: это единственный машиночитаемый
формат и источник структуры. Markdown-тело объясняет смысл и показывает
сценарии, но не дублирует метаданные.

## Что здесь моделируется

- `terms/` — сущности, операции и конфигурации bounded context;
- `operations/` — адресуемые системные операции и capability, владеющие нормами;
- `processes/` — причинность, пересекающая несколько узлов;
- `events/` — состоявшиеся доменные факты;
- `interfaces/` — границы человек ↔ система;
- `contracts/` — опубликованные границы процессов и контекстов;
- `persistence/` — контракт приложения с сохранённым состоянием;
- `patterns/` — плоские пакеты проверяемых обязательств;
- `decisions/` — решения с отвергнутыми альтернативами.

Профиль [profile.yaml](profile.yaml) объявляет допустимые виды, связи, якоря и
срезы. Правила авторства находятся в [constitution.md](constitution.md), точная
форма frontmatter — в [grammar/SYNTAX.md](grammar/SYNTAX.md).

## Минимальная страница

```markdown
---
id: revocation-check
kind: операция
context: auth
name: Проверка отзыва
relations:
  uses: [auth.credential, auth.device-config]
  invokes: [auth.revocation-check]
anchors:
  code: [crates/tessera_core/src/crl/store.rs#check_revocation]
  test: [tests/e2e/cases/25-trust-chain.yaml]
requirements:
  REV-001:
    kind: инвариант
    subjects: [auth.device-config]
    evidence:
      test: [tests/e2e/cases/15-configuration.yaml]
---

# Проверка отзыва

### REV-001 — Режим задаётся явно

[[auth.device-config|Конфигурация устройства]] MUST содержать режим проверки.
```

Вики-ссылки в прозе имеют вид `[[auth.credential|удостоверение]]`. Они нужны
для навигации; проверяемый граф строится из `relations`, а носители норм — из
`requirements.*.subjects`. Допустимые роли отношений и их типы концов заданы в
`profile.yaml → relation_types`; общий `references` не используется как ребро
причинного процесса.

## Команды

Из корня Tessera:

```bash
npm --prefix spec2 install
npm --prefix spec2 test
node spec2/tools/spec.mjs lint
node spec2/tools/spec.mjs graph
node spec2/tools/spec.mjs flow pam-conversation
node spec2/tools/spec.mjs flow issuer-cli
node spec2/tools/spec.mjs draft процесс issuance.example --name "Новый процесс"
node spec2/tools/spec.mjs trace issuance.leaf-scope-policy
node spec2/tools/spec.mjs trace --missing --json
node spec2/tools/spec.mjs decision auth.ADR-002
node spec2/tools/spec.mjs context revocation-check --slice implement
node spec2/tools/spec.mjs why crates/tessera_core/src/x509/mod.rs#Certificate
node spec2/tools/spec.mjs outcomes REV-002
node spec2/tools/spec.mjs candidates --new
node spec2/tools/spec.mjs doctor
node spec2/tools/spec.mjs quality --all
node spec2/tools/spec.mjs next
node spec2/tools/spec.mjs e2e --missing
node spec2/tools/spec.mjs review --seed-git origin/main
node spec2/tools/spec.mjs change --seed-git origin/main
node spec2/tools/spec.mjs coverage --missing
```

`draft` снимает только механическую работу: подставляет обязательные поля,
якоря, разделы и outcomes из профиля и печатает Markdown в stdout. Он не пишет
файл и не генерирует связи или нормы, потому что их смысл не выводится из
сигнатуры кода.

`trace` ничего не дублирует: он собирает матрицу из уже существующих
frontmatter и якорей. Фильтр `--missing` возвращает ненулевой код, когда найдены
неразрешённые subjects, недостающее обязательное evidence, битые evidence-якоря
или субъект без якоря реализации.

`decision` показывает объявленный и эффективный статус ADR, заменяемые и
отменяемые решения, прямой blast radius, зависимые узлы, нормы с `decided_by` и
их trace gaps. Принятый successor меняет эффективный статус старого ADR без
редактирования его исторической страницы.

`outcomes` требует `code:`-якорь на конкретный символ и явный
`outcome_map.<REQ-ID>`. Для Rust он различает `bool`, `Option` и `Result`; у
enum ошибки перечисляет `Err::Variant`, в том числе когда тип импортирован из
другого crate рабочего пространства. Такое разрешение помечается confidence
`workspace`: это консервативная поверхность типа, а не доказательство, что
конкретная функция достижимо возвращает каждый вариант. Код возврата `0`
означает полную сверку, `1` — расхождение, `2` — проверка не состоялась или
осталась неполной.

`candidates --new` ищет внешне публичные типы без человеческого вердикта.
Точный `type:` или `schema:`-якорь считается покрытием; `pub(crate)` и другие
ограниченные Rust visibility в очередь не входят. Остальное классифицируется в
[candidates.yaml](candidates.yaml) как термин, не домен или явный долг.

`doctor` собирает один отчёт о здоровье: размер графа, lint, дыры trace,
сверку outcomes, качество формулировок, очередь кандидатов и точность связей E2E. `ERROR` всегда
возвращает код `1`; `WARN` по умолчанию остаётся обзорным и возвращает `0`, а
с `--strict` — `1`. `--json` предназначен для CI и внешних представлений.

`quality` отдельно показывает не синтаксические ошибки, а признаки ложной
зелени: миграционную норму-оболочку вместо самостоятельного предиката,
единственный self-subject у операции/процесса, файловый evidence без точного
кейса или символа, широкий code-якорь и неразрешённое утверждение `KNOWN GAP`,
`TBD`, «не реализовано» или «проверяется вручную». Эти сигналы не доказывают
дефект и поэтому не раздувают основной lint; `--strict` позволяет временно
сделать их блокирующими в выбранном CI-контуре.

`next` превращает все проверки в одну приоритизированную очередь. P0/P1 —
сначала ошибки, расхождения, дыры trace/таблиц и несостоявшиеся сверки;
массовый миграционный долг группируется и не вытесняет конкретные риски.
Команда ничего не меняет и с `--strict` возвращает `1`, пока есть P0/P1.

`e2e` сопоставляет каждый кейс из `tests/e2e/cases/*.yaml` с evidence норм.
Якорь `test:...yaml#CASE-ID` имеет точность `exact`, ссылка только на файл —
`coarse`, отсутствие ссылки — `missing`. Поле `requirement` старого OpenSpec в
самом E2E-кейсе показывается как legacy-данные, но не считается связью со
spec2. `--missing` группирует долг по suite; missing/invalid дают код `1`.

`review` строит маршрут человеческого ревью сверху вниз по списку изменённых
файлов: контексты → термины и ADR → затронутые нормы → команда для детального
review-среза. Файлы берутся из `--seed-git <ref>` или из текстового
`--seed-files <path>`. Прямое изменение страницы или якоря показывает сущность,
даже если на её странице нет собственных требований; несопоставленные файлы
выводятся отдельно, а не теряются.

`change` использует тот же diff, но собирает пакет подготовки изменения:
затронутые контексты, термины, ADR и нормы, только локальные lint/trace/quality
риски, сверки outcomes и список команд проверки. В конце печатается секция
`Domain impact`, которую можно использовать как начало описания commit/MR.
Текущая команда строит impact по состоянию head и честно помечает, что
добавленные/удалённые связи и границы потребуют следующего semantic base/head
review. Несопоставленный файл повышает риск, а не исчезает из отчёта; high risk
даёт код `1`.

`coverage` сравнивает все заголовки `### Requirement:` из legacy OpenSpec с
`requirements.*.origins` в spec2. Одна старая норма обязана иметь ровно одного
владельца: отсутствие, двойное владение и ссылка на несуществующий requirement
дают ненулевой код. Полная матрица и ограничения миграции описаны в
[OPEN_SPEC_MIGRATION.md](OPEN_SPEC_MIGRATION.md).

В формате нет номера версии. Изменение frontmatter и Markdown совершается
атомарно одним коммитом; журнал изменений — Git. Версии опубликованных
протоколов и форматов остаются частью их предметного контракта.

Спека синхронизируется с кодом по именам, инвариантам и якорям. Поля, типы и
сигнатуры не копируются: их источниками истины остаются код, OpenAPI/JSON
Schema, DDL/migrations и дизайн-система.

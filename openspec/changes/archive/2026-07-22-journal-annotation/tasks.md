# Tasks: journal-annotation

## 1. Ядро журнала

- [x] 1.1 Вариант `Payload::Annotation { kind: String, data: serde_json::Value }` (op `annotation`), добавлен в конец enum; derive `Eq` снят с `Entry`/`Payload` (`Value` только `PartialEq`), `PartialEq` сохранён
- [x] 1.2 Варианты ошибок `JournalError::EmptyAnnotationKind` и `JournalError::AnnotationDataNotObject`
- [x] 1.3 Публичный метод `Journal::append_annotation(kind, data, now_unix)`: пустой `kind` → `EmptyAnnotationKind`, не-объект `data` → `AnnotationDataNotObject`, оба до записи (fail-closed); иначе append на общих основаниях
- [x] 1.4 `verify_lines`: структурная проверка аннотации (пустой `kind` или не-объект `data` → `Broken`), участие в неподписанном хвосте наравне с выпусками
- [x] 1.5 Документация модуля/методов: раздел «Annotations», компат-заметка про строгий разбор op

## 2. Тесты

- [x] 2.1 append + verify: цепочка с аннотациями цела (неподписанный хвост)
- [x] 2.2 tamper аннотации → разрыв на её позиции
- [x] 2.3 пустой `kind` отвергается на append (`EmptyAnnotationKind`, строка не записана)
- [x] 2.4 неизвестный `kind` + произвольный объект `data` проходит verify
- [x] 2.5 собранная вручную строка с пустым `kind` → `Broken` (структурная проверка в обход append)
- [x] 2.6 не-объект `data` (null/массив/скаляр) отвергается на append (`AnnotationDataNotObject`) и структурно в verify (`Broken`)
- [x] 2.7 голден NDJSON-строки аннотации (байт-в-байт)
- [x] 2.8 голдены всех прежних op'ов не изменились (байт-в-байт): `issue_root`, `issue_leaf`, `issue_ca`, `issue_crl`, `head_signature`

## 3. Прогоны

- [x] 3.1 `cargo fmt`
- [x] 3.2 `cargo clippy -p tessera_issuer --all-targets --all-features -- -D warnings`
- [x] 3.3 `cargo test -p tessera_issuer` (фичи как в CI: `cli,pkcs11,vault,serve,test-support`)

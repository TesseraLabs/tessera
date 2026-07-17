# Tasks: cabinet-operation-choice

## 1. Реализация (выполнено 2026-07-17 до оформления change)

- [x] 1.1 `cabinet/src/ui/operations.ts`: чистая логика доступных операций и дефолта + `operations.test.ts` (6 тестов)
- [x] 1.2 `cabinet/src/ui/app.ts`: переключатель операций для CA-родителя с рамками, состояние выбора, сброс на дефолт при смене родителя; CRL-секция без изменений
- [x] 1.3 `cabinet/src/i18n/dict.ts`: ключи переключателя (EN+RU), переформулированы описания родителя; `cabinet/public/styles.css`: стили пикера
- [x] 1.4 `docs/{ru,en}/issuer.md`: три места про вывод операций из родителя
- [x] 1.5 Проверки: tsc --noEmit чисто, 76/76 тестов кабинета, master-code-reviewer APPROVE

## 2. Хвосты

- [ ] 2.1 Пересобрать `cabinet/dist` (`cabinet/build.sh`) перед следующим релизом бинаря issuer

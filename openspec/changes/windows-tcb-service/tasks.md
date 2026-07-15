# Tasks: windows-tcb-service

## 1. Spike и фундамент

- [ ] 1.1 Spike стыковки с Winlogon (design D2): прототипы кандидатов (authentication package с LocalGroups vs LsaLogonUser из службы + возврат через CP), выбор фиксируется в design.md и спеке до волны 2
- [ ] 1.2 `tessera_core` под Windows-таргет: `cfg`/feature-гейты для verify-пути (trust, challenge, revocation, role); `cargo check --target x86_64-pc-windows-msvc` зелёный
- [ ] 1.3 Платформенная абстракция путей/ACL (роль-база, журнал, конфиг в `%ProgramData%\Tessera\`)
- [ ] 1.4 CI: build-джоба Windows-таргета (build + unit ядра)

## 2. Служба

- [ ] 2.1 Crate службы: SCM-интеграция (регистрация, автозапуск, recovery), panic-guard на всех входных точках
- [ ] 2.2 FFI-обвязка LSA/token: `LsaLogonUser` (LocalGroups), `SetTokenInformation(TokenIntegrityLevel)`, `AdjustTokenPrivileges`, `LookupAccountName` — safe-обёртки с тестами на error-пути
- [ ] 2.3 Открытие сессии: снапшот payload роли → резолв групп → логон по выбранной механике D2 → сужение токена → Job Object-лимиты; fail-closed на каждом шаге
- [ ] 2.4 Реестр сессий с персистом (ACL SYSTEM-only) + TTL-таймеры + forced logoff; восстановление после рестарта, немедленный logoff просроченных
- [ ] 2.5 Извлечение носителя: device notification (`SERVICE_CONTROL_DEVICEEVENT`) + WMI-fallback → grace → lock/logoff; отмена при возврате носителя

## 3. IPC и протокол

- [ ] 3.1 `tessera_proto`: транспортная абстракция (AF_UNIX | named pipe), сообщения CP-флоу (ListRoles, Authenticate); отказ CP-сообщений на AF_UNIX (1100)
- [ ] 3.2 Named pipe сервер в службе: дескриптор безопасности (SYSTEM-only), NDJSON-фрейминг, строгая версия, bounded read
- [ ] 3.3 Обработчики CP-флоу: перечень ролей из role-store, аутентификация через ядро, вердикт без oracle-деталей

## 4. Журнал, конфиг, CLI

- [ ] 4.1 Журнал hash-chain на Windows-путях с ACL; события входа/отказа/enforcement/TTL/носителя
- [ ] 4.2 Конфигурация: config.toml с платформенными путями, fail-closed семантика
- [ ] 4.3 `prepare` (техническая УЗ, каталоги/ACL, регистрация службы) и `doctor` (проверки готовности) для Windows
- [ ] 4.4 Domain-чеки `doctor`: исключение CP политикой, deny-логон технической УЗ, WDAC/AppLocker против модулей Tessera — диагностика с указанием политики-источника

## 5. Верификация

- [ ] 5.1 Unit-тесты: снапшот payload, резолв групп (мок), fail-closed ветки сужения/лимитов, реестр сессий/TTL-восстановление
- [ ] 5.2 Интеграционный прогон на Windows-стенде: вход по носителю, группы в токене (`whoami /groups`), integrity level, отзыв привилегий, TTL-logoff, извлечение носителя
- [ ] 5.3 Проверка «logoff без следов»: SAM-членство и персист после завершения сессии
- [ ] 5.4 E2E на domain-joined стенде: вход Tessera при недоступном DC (офлайн-инвариант), доменное имя группы в payload → fail-closed отказ, doctor-диагностика конфликтов GPO
- [ ] 5.5 Полный тест-сьют + clippy на обоих таргетах; sync delta-спек в main после реализации

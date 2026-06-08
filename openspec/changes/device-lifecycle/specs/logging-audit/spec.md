# logging-audit Delta Specification

## ADDED Requirements

### Requirement: Audit-событие device_unenrolled

Engine ДОЛЖЕН (MUST) эмитить audit-событие `device_unenrolled` перед reverse-flip при выполнении
`un-enroll`: причина (если задана) и перечень вытертого состояния. Событие ДОЛЖНО (MUST) попадать
в локальный hash-chain журнал (audit-visibility) до стирания enrollment-состояния, чтобы запись о
выводе устройства сохранялась для forensics; выгрузка в Control — best-effort при связности.

#### Scenario: Эмиссия события при un-enroll
- **WHEN** запущена `tessera un-enroll`
- **THEN** до reverse-flip и стирания состояния в hash-chain журнал пишется `device_unenrolled` с причиной и перечнем вытертого

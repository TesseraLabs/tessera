# Proposal: windows-tcb-service

## Why

Концепт Windows-адаптера (одобрен 2026-06-07, выведен из research-прохода №2:
24 источника, вердикт «реализуемо, включая локальный не-AD сценарий») делит
адаптер на два компонента: Credential Provider (UI, ноль enforcement) и
TCB-службу (Engine). Этот change — второй компонент: служба, которая верифицирует
удостоверение тем же `tessera_core` и применяет payload роли к сессии Windows.
Без неё Windows-срезы ролей (change `windows-payload`) остаются parse-only, а
CP (change `windows-cp`) не имеет стороны, принимающей решения.

## What Changes

- **Новая служба Windows** (LocalSystem, `SeTcbPrivilege`) — Engine-слой на
  Windows: хостит `tessera_core` (Rust-библиотека в службе) и владеет всей
  логикой верификации и enforcement. Сессия инженера остановить её не может.
- **Верификация удостоверения** — тот же путь `tessera_core`, что на Linux:
  цепочка доверия, challenge-response, revocation (CRL/OCSP, fail-closed),
  host-binding/user-binding, покрытие роли удостоверением. Полностью офлайн:
  LSA валидирует техническую УЗ по локальному SAM без внешнего authority.
- **Группы роли в токен сессии** — `LsaLogonUser(..., LocalGroups)`: SID'ы
  групп роли инъектируются в токен на входе и живут только в токене; logoff
  не оставляет следов. Синхронизация членства SAM (pGina-паттерн) —
  запрещённый путь: стейт переживает logoff.
- **Сужение токена** — integrity level из `payload.windows.integrity_level`
  (`SetTokenInformation(TokenIntegrityLevel)`; MIC проверяется до DACL,
  no write-up) и отзыв привилегий из `privileges_remove`
  (`AdjustTokenPrivileges` / `CreateRestrictedToken`). Применяется при
  открытии сессии; живые потоки ретроактивно не сужаются — принятое
  ограничение концепта.
- **Жёсткий TTL** — forced logoff по таймеру службы (`max_ttl` роли);
  реестр сессий персистится и переживает рестарт службы. Честно слабее
  ядерного cgroup-слоя Linux; компенсация — LocalSystem вне досягаемости
  сессии.
- **Извлечение носителя** — детект удаления устройства (device notification /
  WMI) → grace → настраиваемое действие lock/logoff: порт семантики
  session-monitoring по смыслу, не по коду.
- **Лимиты сессии** — `payload.windows.limits` (память, число процессов)
  через Job Object на процессы сессии.
- **Журнал hash-chain** — та же Rust-библиотека logging-audit; хранение в
  защищённом каталоге службы.
- **IPC для CP** — named pipe сервер: NDJSON-фреймы и семантика версии
  PROTOCOL_VERSION существующего протокола поверх нового транспорта; новые
  сообщения CP-флоу (перечень ролей для комбобокса, запрос верификации,
  вердикт). Доступ к pipe ограничен дескриптором безопасности; fail-closed.
- **Порт CLI-диагностики** — `doctor`/`prepare` для Windows-устройства.

Не в скоупе: сам Credential Provider и UI (change `windows-cp`), MSI-дистрибуция
(там же), AD/доменные устройства (отдельный research-проход), метод «код»
(qr-login на Windows — после портирования основного пути).

## Capabilities

### New Capabilities

- `windows-tcb-service`: контракт Engine-слоя Windows — служба LocalSystem,
  офлайн-верификация удостоверения, инъекция групп роли в токен через
  `LsaLogonUser LocalGroups`, сужение (integrity level, отзыв привилегий),
  TTL forced logoff, реакция на извлечение носителя, Job Object-лимиты,
  hash-chain журнал, IPC-сервер для CP, fail-closed инварианты.

### Modified Capabilities

- `ipc-protocol`: добавляется Windows-транспорт (named pipe с дескриптором
  безопасности) и сообщения CP-флоу; существующий AF_UNIX-контракт не
  меняется.

## Impact

- **Новый crate** (Windows-таргет) для службы: SCM-интеграция, LSA/token
  FFI-обвязка (те же требования, что к root-процессу логина: panic-guard,
  Rust-обвязка над unsafe FFI — класс риска T3/T6).
- `tessera_core`: компиляция ядра под Windows-таргет (verify-путь без
  PAM/nix-зависимостей), файловые пути/ACL через платформенную абстракцию;
  role-store для `os = "windows"` уже готов (`windows-payload`).
- `tessera_proto`: транспортная абстракция (AF_UNIX | named pipe), новые
  сообщения CP-флоу.
- CI: сборочный таргет Windows (build + unit-тесты ядра; интеграционные —
  на Windows-стенде, вне CI первой волны).
- Зависимость changes: требует `windows-payload`; блокирует `windows-cp`.
- Не затрагивает: Linux/Astra-пути (PAM, monitord, systemd), существующий
  AF_UNIX-протокол (обратная совместимость по compat-policy).

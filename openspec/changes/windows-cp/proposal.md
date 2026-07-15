# Proposal: windows-cp

## Why

Первый из двух компонентов Windows-адаптера (концепт 2026-06-07) — Credential
Provider: на Windows нативный UI выбора — не опция, а единственный путь
(текстового PAM-prompt нет; суффикс-механизм `user+role` не нужен). Без CP
инженеру негде выбрать метод и роль и нечем передать материал удостоверения
Engine-слою (`windows-tcb-service`). Завершает цепочку Windows-changes:
`windows-payload` → `windows-tcb-service` → `windows-cp`.

## What Changes

- **Tessera CP V2** — Credential Provider (COM DLL, реализация
  `ICredentialProvider`/V2) для LogonUI: тайл входа Tessera рядом со
  стандартными; поля декларируются, LogonUI рендерит их сам (CP свой UI
  не рисует).
- **Выбор метода и роли** — комбобоксы (`CPFT_COMBOBOX`): метод
  (серт-носитель | код; метод «код» — зарезервированная позиция UI,
  активируется при портировании qr-login) и роль (перечень — от TCB-службы
  по IPC; CP не читает role-store и вообще локальные данные Tessera сам).
  Ввод PIN носителя — поле парольного типа.
- **Ноль enforcement в CP** — канон, подтверждённый исходниками multiOTP CP /
  pGina: CP только собирает ввод, общается со службой и сериализует учётные
  данные (`GetSerialization` → `KERB_INTERACTIVE_UNLOCK_LOGON` технической УЗ)
  строго после вердикта службы. Никаких вызовов
  LsaLogonUser/SetTokenInformation/CreateRestrictedToken в CP.
- **Деградация fail-closed** — служба недоступна/отказ верификации → тайл
  сообщает об ошибке, вход методом Tessera невозможен; стандартные провайдеры
  Windows не затрагиваются (device readiness/lockdown-политики — вне скоупа
  первой волны).
- **Дистрибуция** — MSI-пакет: служба (`windows-tcb-service`) + CP DLL,
  регистрация CLSID в реестре, Authenticode-подпись обоих компонентов
  (WHQL не требуется — CP это COM DLL, не драйвер); `prepare` — post-install
  шаг. Supply-chain требования — аналог существующего канала поставки (T5).

Не в скоупе: реализация метода «код» на Windows; unlock-сценарии
кастомного удалённого доступа; AD; фильтрация чужих провайдеров
(credential provider filter) — отдельное будущее решение.

## Capabilities

### New Capabilities

- `windows-credential-provider`: контракт CP — тайл и поля LogonUI, выбор
  метода и роли, сбор PIN, обмен со службой, сериализация учётных данных
  технической УЗ после вердикта, запрет enforcement-логики в CP,
  fail-closed деградация, требования дистрибуции (MSI, подпись,
  регистрация).

### Modified Capabilities

_нет_ (обмен CP ↔ служба уже зафиксирован delta-спекой `ipc-protocol` в
change `windows-tcb-service`)

## Impact

- **Новый компонент CP DLL** (Windows-таргет): COM-обвязка
  `ICredentialProvider*` (Rust с COM-крейтом либо тонкий C++-шелл над
  Rust-ядром — решение в design), клиент named pipe.
- Инсталлятор: MSI (WiX или аналог), подпись, регистрация CLSID,
  постинсталляционный `prepare`.
- CI: сборка DLL и MSI в Windows-джобе; smoke — регистрация CP на стенде.
- Зависимость changes: требует `windows-tcb-service` (IPC-сервер и вердикты).
- Не затрагивает: Linux/Astra-пути, существующие спеки (CP-флоу протокола —
  уже в delta `windows-tcb-service`).

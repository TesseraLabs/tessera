# Миграция OpenSpec → spec2

## Результат

Все 32 capability и 202 заголовка `### Requirement:` из `openspec/specs/`
имеют единственного владельца среди норм spec2. Проверка выполняется командой:

```bash
node spec2/tools/spec.mjs coverage --missing
```

Текущий результат: `202/202 covered; 0 missing; 0 duplicate; 0 unknown`.

| Область | Capability | Покрытие |
|---|---|---:|
| Auth | cert-authentication-flow, cert-scope-binding, challenge-response, gost-crypto, host-identity, revocation, role-selection, role-store, token-pkcs11, trust-chain-validation, usb-media-pkcs12 | 77/77 |
| Issuance | cert-issuance, issuance-journal, issuer-signing | 21/21 |
| Runtime | cli-diagnostics, configuration, daemon-lifecycle, hooks, ipc-protocol, logging-audit, pam-module-runtime, session-monitoring | 59/59 |
| Fleet | clone-image-bootstrap, device-enrollment, device-tags | 10/10 |
| Platform | build-release, fly-dm-greeter, licensing-distribution, mac-integrity, pam-integration, windows-privileged-path, windows-removable-media | 35/35 |

## Что стало подробнее

OpenSpec группировал правила по файлу capability. После миграции каждое правило
получило:

- стабильный ID нормы и квалифицированного владельца `context.id`;
- тип нормы: инвариант, контракт, operational requirement или liveness;
- явный `subject`, который становится ребром графа;
- code/test evidence и проверку существования якоря;
- связь с существующими сущностями, контрактами и хранилищами домена;
- `origins`, по которому CI доказывает полноту и отсутствие двойного владения.

Подробные условия, отрицательные сценарии и rationale OpenSpec сохранены внутри
раздела соответствующей нормы. Они уточняют её границы, но не являются вторым
машиночитаемым представлением. Нормативная формулировка с `MUST` находится в
начале раздела; дальнейшие изменения вносятся только в spec2.

## Ограничения результата

`202/202` означает полную адресацию прежних требований, но не доказывает
полноту тестов. Значительная часть evidence пока указывает на suite целиком,
а не на `#CASE-ID`; это отдельно измеряет `spec.mjs e2e`. Проверка якоря также
доказывает существование символа или файла, но не семантическое соответствие.

Старый OpenSpec пока остаётся в репозитории как migration baseline. Удалять его
можно только после того, как CI начнёт выполнять `coverage`, а человеческое
ревью подтвердит ключевые security-разделы: trust chain, PKCS#11, issuer
signing, revocation и PAM runtime.

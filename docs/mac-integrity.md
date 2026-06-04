# МКЦ (мандатный контроль целостности) — открытая часть

Tessera интегрируется с МКЦ Astra Linux SE (Biba): X.509-сертификат несёт
**потолок** уровня целостности сессии (расширение `pam_cert_max_integrity`),
эффективная метка сессии = `min(потолок_из_серта, МНКЦ_пользователя)`
покомпонентно.

## Что в открытой части

| Компонент | Где |
|---|---|
| SPI `MacBackend` + `StubBackend` | `crates/tessera_core/src/mac/backend.rs` |
| Политика (`[mac].cert_integrity` = required/optional/ignore; `[mac].runtime` = required/auto/disabled) | `mac/orchestrator.rs` |
| Алгебра меток (level i8 + categories u64, DER-кодек) | `mac/label.rs` |
| Audit-события `mac_*` / `integrity_*` (target `mac.audit`) | `mac/audit.rs` |
| Конфиг-секция `[mac]` | `config/` |

Вся логика принятия решения открыта и аудируема.

## Что в коммерческой поставке

Реальное применение меток к ядру (ParsecBackend: libpdp/libparsec FFI),
активация на strict-mode (capdb, systemd drop-in, PAMName), защита
конфигурации МКЦ-метками и полная интеграционная документация — в составе
коммерческого пакета (`tessera-enterprise`). Контакт — см.
[LICENSE.commercial](../LICENSE.commercial).

## Поведение открытой сборки

- Backend всегда `StubBackend` (no-op enforcement).
- `[mac].cert_integrity = "required"` или `[mac].runtime = "required"` —
  **отвергаются на валидации конфига**: открытая сборка не имитирует
  enforcement молча.
- `optional` / `ignore` / `auto` / `disabled` — работают (политика
  вычисляется, события эмитятся, метка не применяется).

## Расширение сертификата

`pam_cert_max_integrity`, OID `2.25.273824307386008814506455310913083078403`,
`SEQUENCE { level INTEGER (-128..127), categories BIT STRING DEFAULT ''B }`,
non-critical. Выпуск — см. [cert-issuance.md](cert-issuance.md).

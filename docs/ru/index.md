# Документация Tessera

Русская документация — первичная (канон). Английский перевод —
в [docs/en/](../en/index.md); changelog ведётся только по-русски.

> **Примечание:** ранее проект назывался `pam_certauth`.

## Маршруты по ролям

### Оператор / интегратор (раскатка на машинах)

1. [terminal-deployment.md](terminal-deployment.md) — типовая
   конфигурация терминального парка: картина развёртывания, роли,
   границы прав (читать первым перед пилотом).
2. [install.md](install.md) — пошаговая установка `tessera`.
3. [pam-integration.md](pam-integration.md) — правка `/etc/pam.d/*`,
   режимы (`2fa` / `optional` / `cert-only`), SysV.
4. [configuration.md](configuration.md) — справочник по `config.toml`.
5. [mac-integrity.md](mac-integrity.md) — граница open/commercial
   по МКЦ и черта МКЦ/МРД (активация — [install.md](install.md)
   и [operations.md §7](operations.md#7-мкц-mac-integrity)).
6. [clone-image.md](clone-image.md) — раскатка парка через
   клонированный образ.
7. [fly-dm-greeter.md](fly-dm-greeter.md) — host_id на экране
   входа (для fly-dm под МКЦ — через обои).
8. [operations.md](operations.md) — runbook регулярных операций.

### CA-админ (выпуск сертификатов)

1. [cert-issuance.md](cert-issuance.md) — расширения
   `pam_cert_host_binding`, `pam_cert_user_binding`,
   `pam_cert_max_integrity`, сценарии выпуска.
2. [clone-image.md §6](clone-image.md) — CA-сторона clone-image
   workflow (выпуск per-host).

### Безопасник

1. [threat-model.md](threat-model.md) — модель угроз с evidence.
2. [architecture.md](architecture.md) — IPC-протокол, fail-closed
   правила, host identity chain.
3. [mac-integrity.md](mac-integrity.md) — граница МКЦ/МРД, состав
   открытой части и коммерческой поставки.

### Разработчик

1. [development.md](development.md) — гид контрибьютора.
2. [architecture.md](architecture.md) — внутренняя архитектура.
3. [changelog.md](changelog.md) — история изменений.
4. API: `cargo doc --workspace --no-deps` → `target/doc/tessera_core/index.html`.

### Когда что-то сломалось

- [troubleshooting.md](troubleshooting.md) — единый справочник по
  диагностике. Cert/auth-ошибки, USB, monitord, PAM lockout, МКЦ,
  fly-dm, clone-image, инциденты безопасности.

## Что нового в 0.4.0

- Проект переименован `pam_certauth` → **Tessera**: пакет `tessera`,
  модуль `/lib/security/pam_tessera.so`, бинарь `/usr/bin/tessera`.
- Пути перенесены: `/etc/tessera`, `/run/tessera`, `/var/lib/tessera`,
  `/var/cache/tessera`; юнит `tessera.service`, системный пользователь `tessera`.
- Контракт окружения хуков `PAM_CERTAUTH_*` → `TESSERA_*`;
  фильтр логов `TESSERA_LOG`.
- Неизменны: OID X.509-расширений, схема `config.toml`, IPC-протокол.
- Первый публичный релиз (dual-license AGPL-3.0 OR commercial).

## Что нового в 0.3.19

- `tessera dump-host-id` — TSV-дамп всех host_identity-источников.
- `finish-bootstrap.sh` — single-pass переход с clone-image bootstrap
  на production.
- `[fly_dm_greeter].update_wallpaper` — впечатать `host_id` в JPG-фон
  fly-dm.
- CA-инструменты вынесены из `.deb` (поставляются отдельно).

См. [changelog.md](changelog.md).

## Что нового в 0.3.0

- Интеграция мандатного контроля целостности (МКЦ) для Astra SE
  strict mode.
- X.509-расширение `pam_cert_max_integrity` — потолок целостности
  сессии инженера.
- Секция `[mac]` в `config.toml` с тринарной политикой
  `cert_integrity` (`required` / `optional` / `ignore`).
- Feature-флаг `astra-mac`; stub-сборка для не-Astra хостов.

## English documentation

- [docs/en/index.md](../en/index.md) — английское дерево документации.
- [README.md](../../README.md) — English entry point.

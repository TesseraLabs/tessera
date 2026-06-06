# Документация Tessera

Все документы — на русском языке (primary). Английская обзорная
страница доступна отдельно.

> **Примечание:** ранее проект назывался `pam_certauth`.

## Маршруты по ролям

### Оператор / интегратор (раскатка на машинах)

1. [install.md](install.md) — пошаговая установка `tessera`.
2. [pam-integration.md](pam-integration.md) — правка `/etc/pam.d/*`,
   режимы (`2fa` / `optional` / `cert-only`), SysV.
3. [configuration.md](configuration.md) — справочник по `config.toml`.
4. [mac-integrity.md](mac-integrity.md) — opt-in активация МКЦ
   на Astra strict-mode.
5. [clone-image.md](clone-image.md) — раскатка парка через
   клонированный образ.
6. [fly-dm-greeter.md](fly-dm-greeter.md) — wallpaper banner на
   fly-dm под МКЦ.
7. [operations.md](operations.md) — runbook регулярных операций.

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
3. [mac-integrity.md](mac-integrity.md) — МКЦ activation и защита
   `config.toml` через ilevel=63.

### Разработчик

1. [development.md](development.md) — гид контрибьютора.
2. [architecture.md](architecture.md) — внутренняя архитектура.
3. [changelog.md](changelog.md) — история изменений.
4. API: `cargo doc --workspace --no-deps` → `target/doc/tessera_core/index.html`.

### Когда что-то сломалось

- [troubleshooting.md](troubleshooting.md) — единый справочник по
  диагностике. Cert/auth-ошибки, USB, monitord, PAM lockout, МКЦ,
  fly-dm, clone-image, инциденты безопасности.

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

- [README.md](../README.md) (primary, English)

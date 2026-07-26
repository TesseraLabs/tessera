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
2. [issuer.md](issuer.md) — инструменты выпуска (`tessera_issuer`):
   CLI `issuer`, агент `serve`, CSR-поток, бэкенды PKCS#11 и
   Vault Transit, журнал выпусков, веб-кабинет.
3. [clone-image.md §6](clone-image.md) — CA-сторона clone-image
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

## Что нового

История изменений и «что нового» по версиям — в [changelog.md](changelog.md).

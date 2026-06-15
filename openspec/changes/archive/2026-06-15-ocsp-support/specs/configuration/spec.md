# configuration Delta Specification

## ADDED Requirements

### Requirement: OCSP-ключи [trust.revocation]

Ключи `ocsp_*` секции `[trust.revocation]` ДОЛЖНЫ (MUST) доходить до ValidatedConfig
(сейчас парсятся и теряются — validated.rs:328–337) со следующими правилами:

| Ключ | Тип | Дефолт | Диапазон | Семантика |
|---|---|---|---|---|
| `ocsp_responder_url` | строка URL | — | `http://`/`https://` | адрес responder'а; ОБЯЗАТЕЛЕН при mode ∈ {`ocsp`, `crl_then_ocsp`} |
| `ocsp_timeout_seconds` | целое | 5 | 1..=30 | общий deadline одного OCSP-обмена (connect+write+read) |
| `ocsp_cache_ttl_seconds` | целое | 3600 | 0..=86400 | верхний предел жизни кэш-записи; 0 = кэш выключен |

При mode ∉ {`ocsp`, `crl_then_ocsp`} заданные `ocsp_*`-ключи ДОЛЖНЫ (MUST) отвергаться
валидацией (по образцу `on_usb_removed_hook_path`: ключ, который молча игнорировался бы
в runtime, запрещён). AIA-извлечение URL из серта НЕ выполняется — responder задаётся
только конфигом.

#### Scenario: mode="ocsp" без ocsp_responder_url
- **WHEN** `mode = "ocsp"` (или `"crl_then_ocsp"`), `ocsp_responder_url` отсутствует или не начинается с http(s)://
- **THEN** валидация конфига завершается ошибкой (`OcspResponderInvalid`)

#### Scenario: ocsp_* при mode="crl"
- **WHEN** `mode = "crl"`, в конфиге задан `ocsp_responder_url` (или иной `ocsp_*`-ключ)
- **THEN** валидация конфига завершается ошибкой — ключ не может молча игнорироваться

#### Scenario: Значение вне диапазона
- **WHEN** `ocsp_timeout_seconds = 120` или `ocsp_cache_ttl_seconds = 604800`
- **THEN** валидация конфига завершается ошибкой

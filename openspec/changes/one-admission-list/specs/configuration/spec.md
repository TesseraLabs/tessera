# configuration Delta Specification

## MODIFIED Requirements

### Requirement: Секции

Каждая секция конфига ДОЛЖНА (MUST) валидироваться по описанным ниже правилам полей и диапазонов; неизвестные или невалидные значения отвергаются.

- `[monitor]`: socket_path, state_file_path, timeout_ms (2000, 100..=60000), fail_mode (`degraded`→Permissive; при отсутствии — fallback на legacy top-level `monitor_fail_mode`, validated.rs:1137–1152), on_usb_removed (+`on_usb_removed_hook_path`: обязателен при `on_usb_removed="hook"`, абсолютный путь, ЗАПРЕЩЁН в не-hook режиме — raw.rs:282–285, validated.rs:1166–1183), grace-поля (≤600), idle_timeout_seconds (30, 1..=3600), max_concurrent_connections (64, 1..=4096). Последние два пробрасываются в accept-loop через `AcceptConfig::from_monitor` (см. [ipc-protocol](../ipc-protocol/spec.md)).
- `[trust]`: anchors (непустой список — пустые anchors отклоняются валидацией конфига (`TrustError::AnchorsEmpty`); конструктор verifier'а дублирует проверку как defense-in-depth; каждый файл — PEM с BEGIN CERTIFICATE), intermediates, max_chain_depth (5, 1..=16), clock_skew_seconds (0, ≤600), allowed_signature_algorithms (пусто/опущено = безопасный дефолт `DEFAULT_SIGNATURE_ALGORITHMS`: SHA-256/384/512 RSA + ECDSA, без SHA-1 и GOST; GOST — только явный opt-in; см. [trust-chain-validation](../trust-chain-validation/spec.md)).
- `[trust.revocation]`: mode (none|crl|ocsp|crl_then_ocsp; ОБЯЗАТЕЛЕН — c 2026-07 пропуск секции `[trust.revocation]` или ключа `mode` = ошибка валидации, молчаливого дефолта `none` больше нет; `none` выбирается только явно; см. [revocation](../revocation/spec.md)). `crl_max_age_hours` (опционален, 1..=8760) пробрасывается в runtime как `crl_max_age`. `is_file`-проверка CRL — только при mode=crl. OCSP-ключи `ocsp_responder_url` (http/https, ОБЯЗАТЕЛЕН при mode ∈ {ocsp, crl_then_ocsp}), `ocsp_timeout_seconds` (5, 1..=30), `ocsp_cache_ttl_seconds` (3600, 0..=86400) пробрасываются в `RevocationSection`; при mode ∉ {ocsp, crl_then_ocsp} любой заданный `ocsp_*`-ключ ОТВЕРГАЕТСЯ валидацией (по образцу `on_usb_removed_hook_path` — мёртвых ключей нет).
- `[trust.pinning]`: enabled (false), allowed_root_spki_sha256 (64 hex, валидируется только при enabled).
- `[[trust_override]]`: when_host_id_in (непустой) + anchors/intermediates.
- `[host_identity]`: sources (обязателен, непустой, без дублей), fallback (deny), override, custom_command (absolute) + timeout (clamp 1..30).
- `[logging]`: level (trace..error; применяется демоном к tracing-фильтру после загрузки конфига, env `TESSERA_LOG` приоритетнее — см. [logging-audit](../logging-audit/spec.md)); syslog_facility (deprecated, ignored + WARN при валидации; значение всё ещё валидируется: auth|authpriv|user|daemon, прочие — включая local0..7 — отклоняются) и journald_priority (deprecated, ignored + WARN) в ValidatedConfig не пробрасываются.
- `[[hooks]]` — см. [hooks](../hooks/spec.md).
- `[mac]` — см. [mac-integrity](../mac-integrity/spec.md). Дефолты: cert_integrity=**optional**, runtime=auto.
- `[roles]`: dir (`/var/lib/tessera/roles`), default_session_ttl (duration, `12h`) — детали см. требование «Секция [roles]» ниже и [role-selection](../role-selection/spec.md) / [role-store](../role-store/spec.md).
- `[fly_dm_greeter]` — см. [fly-dm-greeter](../fly-dm-greeter/spec.md).

Секции `[[user_mapping]]` в конфиге существовать НЕ ДОЛЖНО (MUST NOT): допуск к
учётной записи решается расширением удостоверения, а не конфигурацией
устройства. Конфиг, содержащий её, ДОЛЖЕН (MUST) отвергаться с диагностикой,
называющей причину, — общей ошибки «неизвестное поле» недостаточно, поскольку
администратор, обновляющий парк, должен отличить намеренное изменение поведения
от опечатки.

#### Scenario: Конфиг с удалённой секцией user_mapping
- **WHEN** конфиг содержит `[[user_mapping]]` в любом виде
- **THEN** валидация отвергает конфиг с диагностикой об удалении секции и о том, что допуск решает удостоверение

#### Scenario: Пустой [trust].anchors
- **WHEN** `[trust].anchors` — пустой список
- **THEN** валидация конфига завершается ошибкой («trust.anchors must not be empty»)

#### Scenario: Deprecated-ключ [logging] присутствует
- **WHEN** в `[logging]` задан `syslog_facility` (допустимое значение) или `journald_priority`
- **THEN** конфиг валиден, при валидации эмитится WARN «deprecated and ignored» (target `tessera.config`); на runtime значения не влияют

#### Scenario: on_usb_removed_hook_path вне hook-режима
- **WHEN** в `[monitor]` задан `on_usb_removed_hook_path`, но `on_usb_removed` не равен `hook`
- **THEN** валидация секции завершается ошибкой (поле запрещено в не-hook режиме — иначе оно бы молча игнорировалось в runtime)

#### Scenario: hook-режим без on_usb_removed_hook_path
- **WHEN** `on_usb_removed = "hook"`, а `on_usb_removed_hook_path` не задан или не абсолютный
- **THEN** валидация секции завершается ошибкой

#### Scenario: [trust.revocation] или mode отсутствует
- **WHEN** секция `[trust.revocation]` опущена целиком, либо присутствует, но без ключа `mode`
- **THEN** валидация конфига завершается ошибкой (`mode` обязателен) — молчаливого отката к «отзыв не проверяется» нет; отказ от проверки требует явного `mode = "none"`

#### Scenario: mode="ocsp" без ocsp_responder_url
- **WHEN** `mode = "ocsp"` (или `"crl_then_ocsp"`), `ocsp_responder_url` отсутствует или не начинается с `http(s)://`
- **THEN** валидация конфига завершается ошибкой (`OcspResponderInvalid`)

#### Scenario: ocsp_* ключ при mode ∉ {ocsp, crl_then_ocsp}
- **WHEN** `mode = "crl"` (или `none`), в конфиге задан `ocsp_responder_url` (или иной `ocsp_*`-ключ)
- **THEN** валидация конфига завершается ошибкой — ключ не может молча игнорироваться

#### Scenario: OCSP-значение вне диапазона
- **WHEN** `ocsp_timeout_seconds = 120` или `ocsp_cache_ttl_seconds = 604800`
- **THEN** валидация конфига завершается ошибкой

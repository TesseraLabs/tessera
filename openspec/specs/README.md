# Спецификации Tessera — карта capability

Bootstrap-спеки текущей реализации **v0.4.0** (2026-06-09). Источник: код (file:line evidence) + прошлые сессии разработки (intended-поведение, rationale). Спеки описывают **intended**-поведение; маркеров KNOWN GAP в спеках больше нет — известные расхождения закрыты в коде/docs, а нереализованная функциональность вынесена в proposals в [`openspec/changes/`](../changes/).

## Карта

### Auth core
| Capability | Что |
|---|---|
| [cert-authentication-flow](cert-authentication-flow/spec.md) | Оркестрация pam_sm_authenticate, PKCS#12/PKCS#11 пути, FlowError→PAM |
| [challenge-response](challenge-response/spec.md) | Proof-of-possession (RSA-PSS/ECDSA/GOST), no replay by design |
| [trust-chain-validation](trust-chain-validation/spec.md) | Pre-validate, chain build, подписи, constraints, pinning |
| [revocation](revocation/spec.md) | CRL с верификацией подписи (fail-closed); OCSP (4 режима, кэш, fail-closed) |
| [gost-crypto](gost-crypto/spec.md) | Делегация в gost-engine, ленивая загрузка |
| [cert-scope-binding](cert-scope-binding/spec.md) | host/user_binding + max_integrity extensions, OID-контракт |
| [host-identity](host-identity/spec.md) | first-working-wins, normalize+sha256, override, fallback |

### Носители
| [usb-media-pkcs12](usb-media-pkcs12/spec.md) | USB discovery, hardened mount, anti-oracle перебор партиций, PIN |
| [token-pkcs11](token-pkcs11/spec.md) | Слоты, PIN-lock, C_Sign на токене |

### Runtime
| [pam-module-runtime](pam-module-runtime/spec.md) | panic guard, acct_mgmt, open/close session, XDG capture |
| [session-monitoring](session-monitoring/spec.md) | Реестр, udev REMOVE→grace→action, suspend, logind cleanup |
| [ipc-protocol](ipc-protocol/spec.md) | NDJSON, PROTOCOL_VERSION=2, коды ошибок, FailMode |
| [daemon-lifecycle](daemon-lifecycle/spec.md) | systemd, startup-check gate, shutdown |

### Конфигурация и обвязка
| [configuration](configuration/spec.md) | Схема config.toml, fail-closed, перечитывание |
| [hooks](hooks/spec.md) | 5 стадий, fork/execve контракт, on_failure |
| [logging-audit](logging-audit/spec.md) | tracing-targets, MAC audit events, секреты |
| [cli-diagnostics](cli-diagnostics/spec.md) | check, dump-host-id |

### Astra / fleet
| [mac-integrity](mac-integrity/spec.md) | МКЦ: потолок из серта, min(cert, МНКЦ), libpdp FFI |
| [fly-dm-greeter](fly-dm-greeter/spec.md) | Wallpaper banner (3 pivot'а) |
| [clone-image-bootstrap](clone-image-bootstrap/spec.md) | override-bootstrap, finish-bootstrap.sh, CA-контракт |
| [pam-integration](pam-integration/spec.md) | Режимы, parsec_mac/two-include ordering, postinst |
| [build-release](build-release/spec.md) | CI matrix, packaging, тестовые gap'ы |

### Лицензирование
| [licensing-distribution](licensing-distribution/spec.md) | Dual-license AGPL/commercial, граница open/commercial, SPI MacBackend, CLA |

## Состояние gap'ов (сводно)

Все известные на момент bootstrap расхождения закрыты в 0.4.0:

Security-класс (закрыто в коде):
- **Подпись CRL верифицируется** против issuer-сертификата, fail-closed (`TrustError::CrlSignatureInvalid`); issuer-DN сверка байт-в-байт — с f542df5.
- **Extractable PKCS#11-ключ отклоняется** (fail-closed); ослабление только явным opt-in `pkcs11_allow_extractable_keys`.
- **Malformed user_binding** — fail-closed (отказ вместо тихого fallback в legacy mapping).
- **Пустой sig-alg whitelist** подменяется безопасным дефолтом `DEFAULT_SIGNATURE_ALGORITHMS` (f542df5) вместо accept-all.

Функциональный класс (закрыто в коде): `pkcs12_pin_prompt` пробрасывается в PIN-prompt PKCS#12-пути; `monitor.idle_timeout_seconds`/`max_concurrent_connections` доходят до accept-loop (`AcceptConfig::from_monitor`); `[logging].level` применяется демоном (`apply_config_level`, приоритет `TESSERA_LOG` env > config > info); `clock_skew_seconds` — дефолт 0, диапазон 0..=600; startup sweep stale-маунтов после crash; VID/PID и anchors-валидация — по спекам. Также добавлен daemon-singleton через flock (ec4185b, [daemon-lifecycle](daemon-lifecycle/spec.md)).

Docs-класс (закрыто в docs): configuration.md, architecture.md (PROTOCOL_VERSION=2, коды 1101/1200, честная семантика `monitor_fail_mode`), mac-integrity.md, clone-image.md, cert-issuance.md, fly-dm-greeter.md приведены в соответствие коду.

Testing-класс: автоматизация оставшихся ручных проверок (ГОСТ E2E, libpdp runtime, hook-security, USB/токен) — proposal [ci-hardening](../changes/ci-hardening/); release-профиль тестов уже покрыт nightly workflow (`.github/workflows/nightly.yml`).

Нереализованная функциональность — proposals: GOST через PKCS#11 — [gost-pkcs11](../changes/gost-pkcs11/). OCSP реализован (change [ocsp-support](../changes/ocsp-support/), осталась ручная проверка на Astra VM — task 5.3).

## Чего НЕТ в текущей реализации (чтобы не путать со спеками 0.2.x / продуктовыми планами)

- Scopes / M-of-N / CMS work-order / `execute` / policy.toml — удалено в 0.3.0.
- Replay-protection challenge — отсутствует by design.
- SSH/CAF-продукт (PRODUCT_SPEC.md, offline-инварианты, accountability C2/C3) — будущий продукт, не этот репозиторий.

# Спецификации Tessera — карта capability

Bootstrap-спеки текущей реализации **v0.3.19** (main @ 916c41e, 2026-06-04). Источник: код (file:line evidence) + прошлые сессии разработки (intended-поведение, rationale). Спеки описывают **intended**-поведение; известные расхождения и баги помечены маркерами **⚠ KNOWN GAP** внутри спек.

## Карта

### Auth core
| Capability | Что |
|---|---|
| [cert-authentication-flow](cert-authentication-flow/spec.md) | Оркестрация pam_sm_authenticate, PKCS#12/PKCS#11 пути, FlowError→PAM |
| [challenge-response](challenge-response/spec.md) | Proof-of-possession (RSA-PSS/ECDSA/GOST), no replay by design |
| [trust-chain-validation](trust-chain-validation/spec.md) | Pre-validate, chain build, подписи, constraints, pinning |
| [revocation](revocation/spec.md) | CRL; ⚠ OCSP не реализован, подпись CRL не проверяется |
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
| [clone-image-bootstrap](clone-image-bootstrap/spec.md) | override-bootstrap, finish-bootstrap.sh, admin-tools |
| [pam-integration](pam-integration/spec.md) | Режимы, parsec_mac/two-include ordering, postinst |
| [build-release](build-release/spec.md) | CI matrix, packaging, тестовые gap'ы |

## Топ известных gap'ов (сводно)

Security-класс:
1. **OCSP не реализован** при заявленном в конфиге/docs ([revocation](revocation/spec.md)) — `mode="ocsp"` = fail-open на отзыв.
2. **Подпись и issuer CRL не проверяются** на пути check_revocation.
3. **Malformed user_binding → тихий fallback в legacy mapping** вместо отказа ([cert-authentication-flow](cert-authentication-flow/spec.md)).
4. **Пустой sig-alg whitelist = accept-all** (fail-open default).
5. **Extractable PKCS#11-ключ только WARN**, не блок.

Функциональный класс:
6. `pkcs12_pin_prompt` — мёртвый конфиг; `monitor.idle_timeout/max_connections` не доходят до accept-loop; `[logging]` демоном игнорируется; re-mount в open_session обещан комментарием, не реализован; sticky mount при crash (нет startup-cleanup).

Docs-класс: configuration.md (17 расхождений), architecture.md (PROTOCOL_VERSION, коды ошибок, monitord fail-closed), clone-image.md (интерфейс admin-tools), mac-integrity.md (default cert_integrity).

Testing-класс: ГОСТ E2E, реальный parsec, hook-security, release-профиль — не покрыты CI (см. [build-release](build-release/spec.md)).

## Чего НЕТ в текущей реализации (чтобы не путать со спеками 0.2.x / продуктовыми планами)

- Scopes / M-of-N / CMS work-order / `execute` / policy.toml — удалено в 0.3.0.
- Replay-protection challenge — отсутствует by design.
- SSH/CAF-продукт (PRODUCT_SPEC.md, offline-инварианты, accountability C2/C3) — будущий продукт, не этот репозиторий.

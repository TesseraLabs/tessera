# Changelog

> **Переименование проекта (2026-06-04):** проект `pam_certauth`
> переименован в **Tessera** (CLI/пакет `tessera`, модуль
> `pam_tessera.so`, пути `/etc/tessera` и т.д.). Записи ниже относятся
> к релизам под прежним именем `pam_certauth` и сохранены как есть —
> упомянутые в них команды, бинари и пути соответствуют тому, что
> поставлялось на момент релиза.

## [0.3.19] — 2026-05-27

### Added

- **`pam-certauth dump-host-id` CLI subcommand.** Пробует **ВСЕ**
  канонические `host_identity`-источники (не только подмножество в
  `[host_identity].sources`) и пишет TSV-отчёт. Колонки:
  `source`, `status`, `hash_hex`, `hash_prefix`, `raw`, `normalized`,
  `active_under_current_config`, `reason`. Строка с
  `active_under_current_config=yes` отмечает источник, который daemon
  сейчас реально использует. Запись атомарная через `--output FILE`
  или `--usb` (автоматический mount первой USB r/w, имя
  `host-ids-<hostname>-<UTC>.tsv`). Stdout без флагов. Exit ≠ 0,
  если ни один источник не отдал непустое значение — сигнал «не
  выписывать сертификат, пока не починён вход».
- **`/usr/share/pam-certauth/finish-bootstrap.sh`** — single-pass
  переход с clone-image bootstrap state на production. Атомарный
  rewrite `config.toml` (`sources = ["override"]` → реальные источники)
  с backup'ом `.bak.<UTC>`, валидация через `pam-certauth check`,
  рестарт daemon'а, `dump-host-id --usb`. Флаги: `--non-interactive`
  (Ansible), `--sources "A,B"` (или env `POST_INSTALL_SOURCES`),
  `--no-restart`, `--no-dump`. Идемпотент: повторный запуск без
  `sources = ["override"]` exit 0 без изменений.
- **fly-dm greeter pivot #2: wallpaper writer.** GreetString.desktop
  writer из 0.3.16 оказался no-op на production МКЦ-3 АРМ (fly-modern
  hardcoded'но рендерит «Усиленный уровень защищенности» в headline
  place). Замена: впечатать `host_id` в JPG, на который смотрит
  `[background].path` в `/etc/X11/fly-dm/fly-modern/settings.ini`.
  Opt-in: `[fly_dm_greeter].update_wallpaper = true`. Pure Rust
  (`image` + `ab_glyph`), без native deps. Templates `template_ru` /
  `template_en` (по locale), one-time backup оригинала. Atomic save.
- **Admin-tools release tarball** `pam-certauth-admin-tools-<ver>.tar.gz`
  загружается в GitHub Release **рядом** с `.deb` (НЕ упакован в `.deb`):
  `issue-service-cert.sh` (per-host / wildcard / bootstrap modes),
  `vault-pki-setup.sh`, `prepare-usb-flash.sh`, README. Project-neutral
  naming. Хранится на CA-машине, не на боевых АРМ.

### Docs

- Новый документ `docs/clone-image.md` — end-to-end runbook раскатки
  парка АРМ через клонированный образ (bootstrap-эталон,
  `finish-bootstrap.sh`, CA-сторона, troubleshooting, Ansible).
- `docs/install.md` §2.4¾, `docs/operations.md` §2.4,
  `docs/cert-issuance.md` cross-linked на новый документ.

## [0.3.18] — 2026-05-26

### Removed

- **Drop debconf prompt в `debian/postinst`** (введён в 0.3.16).
  Операторы раскатывают через готовые `config.toml` (Ansible /
  centralized rollout) — debconf-шаг при `dpkg install` только
  переключал флаг в `config.toml` и добавлял moving parts (templates,
  debconf dep, postinst branching) без изменения production-поведения.
- Удалены `debian/templates`, `debian/config`, debconf-branch в
  `debian/postinst`, `debconf` из `debian/control Depends`,
  `confmodule` sourcing.

### Unchanged

- Daemon-side feature не менялась: `[fly_dm_greeter].update_greet_string = true`
  в `config.toml` по-прежнему заставляет демон переписывать
  `/etc/X11/fly-dm/override/GreetString.desktop` на старте.

## [0.3.17] — 2026-05-26

### CI-only

- Per-build pipeline time снижено:
  - `astra` job теперь `cargo nextest run --workspace --features astra-mac`
    в **debug** profile. Прежний release-run занимал 510s vs ubuntu 56s
    (9.1×) из-за workflow-level `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`
    + `LTO=thin` (нужны для production `.deb`), которые делают release
    test compilation катастрофически медленным. Тесты по-прежнему
    проходят `astra-mac` feature-gate.
  - `scripts/build-deb.sh` больше не делает `cargo clean && cargo build --release`
    перед `dpkg-buildpackage`. `debian/rules` уже чистит `target/` через
    `override_dh_auto_clean` и пересобирает через `override_dh_auto_build` —
    pre-build был чистым дублированием работы (~60s/pipeline).
- Source-code изменений vs 0.3.16 нет. Тот же `.deb`, быстрее CI.

## [0.3.16] — 2026-05-26

### Changed

- **fly-dm greeter pivot.** Revert `fly-dmrc greeter-show-messages`
  (cargo-cult из 0.3.15 — таргетил KDM/LightDM legacy key, который
  fly-qdm не парсит). Переключение на механизм, который реально
  работает на Astra fly-qdm 2.15+: `/etc/X11/fly-dm/override/GreetString.desktop`
  (freedesktop i18n `.desktop` файл). Live-testing на Astra VM
  подтвердил рендер `host_id` в headline login-form'ы.
- Opt-in: `[fly_dm_greeter].update_greet_string = true`. На старте
  daemon резолвит host identity и переписывает `GreetString.desktop`
  с short hash + source:
  ```
  Устройство astra184 · host_id=abc12345 (dmi_board_serial)
  ```
  Original сохраняется как `.orig` при первом запуске. Atomic write
  (tmpfile + rename). Silent skip на хостах без `/etc/X11/fly-dm/`.
  Log-and-continue — auth никогда не блокируется ошибкой greeter writer.
- Debconf prompt в `debian/postinst` (en + ru) спрашивает оператора
  про включение banner'а; default off. **Удалён в 0.3.18** (см. выше).
- `pam-certauth check` validator: `fly_dm_greeter_greet_string_customized`,
  `_default`, `_override_missing`, `_read_failed` — Info-записи.
- `integrate-pam.sh`: убраны `--enable-greeter-messages` /
  `--no-greeter-messages` флаги и `fly-dmrc patcher` из 0.3.15.
  Скрипт снова занимается **только** PAM-stack editing.

## [0.3.15] — 2026-05-26

### Added (superseded by 0.3.16 → 0.3.19)

- Попытка №1 заставить fly-dm показать PAM_TEXT_INFO с `host_id`:
  патч `fly-dmrc` через `integrate-pam.sh` (`greeter-show-messages = true`
  под `[greeter]`). Идемпотент, backup `fly-dmrc.bak.<UTC>`. Флаги
  `--enable-greeter-messages` (default ON для `fly-dm*`),
  `--no-greeter-messages` (CI). `--unintegrate` `fly-dmrc` не трогает.
- Startup-check `fly_dm_greeter` читает `fly-dmrc` и эмитит Info-запись:
  `messages_on` / `_off` / `_default` / `_read_failed`. Silent skip
  при отсутствии файла (sshd-only хосты, серверы).
- **Не сработало на fly-qdm 2.15+** — таргетили KDM legacy key. Revert
  в 0.3.16, окончательный workaround через wallpaper writer в 0.3.19.

## [0.3.14] — 2026-05-25

### Fixed

- **Build hotfix.** Timestamp в `debian/changelog` для 0.3.13
  (12:00 +0300) был раньше чем 0.3.12 (18:00 +0300) — Ubuntu lintian
  `latest-changelog-entry-without-new-date` валил `.deb` build. Astra
  `.deb` в 0.3.13 release собрался (Astra pipeline пропускает lintian).
  Этот релиз бампает версию + timestamp, оба `.deb` строятся.
- Функциональных изменений vs 0.3.13 нет.

## [0.3.13] — 2026-05-25

### Fixed

- **Hotfix: ACTUALLY implement `XDG_SESSION_ID` capture in
  `pam_sm_open_session`.** Версии 0.3.10/0.3.11/0.3.12 в changelog'е
  заявили, что капчурят `XDG_SESSION_ID` и отправляют
  `UpdateSessionTarget` в monitord, но в cdylib код этого не было —
  `pam_sm_open_session` не вызывал `pam_getenv`, не открывал IPC и не
  слал `UpdateSessionTarget`. На production-терминалах USB-removal
  Logout/Lock молча не работал три релиза подряд: action handler не
  имел logind id и падал на `terminate_session`.
- Добавлены: `crate::pam_helpers::pam_get_env_string` (thin
  обёртка над `pam_getenv`) и новый модуль `crate::xdg_capture` с
  чистой функцией `capture_xdg` (unit-тесты на три ветки: XDG
  отсутствует / присутствует и IPC ok / IPC fail). Production cdylib
  зовёт `capture_xdg` после MAC pipeline и до session_open hooks;
  любая IPC-ошибка логируется WARN и НЕ ломает session-open
  (best-effort semantics).
- Wire-протокол не меняется — переиспользуется `UpdateSessionTarget`
  фрейм, отправленный с daemon-side ещё в 0.3.10.

## [0.3.9] — 2026-05-25

### Added

- **Startup validation pipeline.** Daemon теперь на старте, сразу после
  `load_validated_config`, прогоняет `run_startup_checks` — единый
  sweep из шести проверок, который ловит мисконфиги, не видимые
  TOML-валидатором:
  1. **PAM stack ordering.** Сканирует `/etc/pam.d/{login,fly-dm,
     fly-dm-np,sshd,sudo,su}`. Если `@include certauth-*` стоит ПЕРЕД
     `auth required pam_parsec_mac.so` — ERROR с подсказкой про
     `integrate-pam.sh` (регрессия фикса из 0.3.8: на Astra SE
     неправильный порядок убивает account-фазу `pam_parsec_mac`).
  2. **`[mac].runtime` vs ядро.** `required` без активного
     `parsec_strict_mode()=1` — ERROR + fail-fast (раньше demon
     стартовал, и фейл случался на каждой auth). Остальные комбинации
     — INFO/WARN с явным текстом.
  3. **Trust anchors / intermediates.** Существование + не-ноль байт +
     счётчик `BEGIN CERTIFICATE` маркеров. Defense-in-depth: TOML
     валидатор отвергает невалидные пути на загрузке, startup-check
     ловит сценарий «файл удалили/обрезали между провизионингом и
     рестартом».
  4. **`/etc/pam_certauth/ca/` permissions.** WARN, если каталог
     world-writable (`mode & 0o002 != 0`).
  5. **`PARSEC_CAP_CHMAC`.** WARN, если МКЦ-ядро активно и
     `[mac].runtime ≠ disabled`, но у процесса нет capability —
     метки на `sessions.json` не лягут.
  6. **`host_identity` probe.** По одной INFO/WARN-строке на каждый
     настроенный источник — admin сразу видит резолв, не дожидаясь
     первой auth-сессии.

  Каждая запись помечена стабильным `check` ID
  (`pam_stack_misorder`, `mac_runtime_required_missing_kernel`,
  `trust_anchor_missing`, ...) — grep'абельно через
  `journalctl -u pam-certauth -g startup_check`. При наличии хотя бы
  одного ERROR boot обрывается с явным сообщением — заметно в
  `systemctl status`, а не в первой неудачной auth-сессии.

- **`pam-certauth check` subcommand.** Standalone preflight: загружает
  config + прогоняет тот же pipeline без открытия socket'а. Печатает
  `[INFO ]/[WARN ]/[ERROR]` лог + summary. Exit 0 — чисто, exit 1 —
  есть ERROR. Можно навесить на `ExecStartPre=` в systemd-unit, чтобы
  превратить preflight в hard gate. Документация в `docs/install.md`
  §2.4½.

## [0.3.8] — 2026-05-25

### Critical

- **`integrate-pam.sh` placement fix для Astra SE.** Скрипт теперь
  вставляет `@include certauth*` ПОСЛЕ существующей строки
  `auth ... pam_parsec_mac.so`, если она есть, а не перед первой
  `auth`-строкой. Боевой кейс: на Astra SE 1.8.3 `/etc/pam.d/login` и
  `/etc/pam.d/fly-dm` штатно начинаются с `auth required
  pam_parsec_mac.so`; placement до неё приводил к тому, что
  `success=done` jump из `certauth-only` snippet'а обходил
  auth-инстанс pam_parsec_mac, и account/session-инстансы валились
  `"Can't obtain required data"` → login deny несмотря на успешную
  cert-аутентификацию. Подтверждено на проде (Astra SE 1.8.3, kernel
  6.1.141): после reordering login проходит до конца, fly-dm greeter
  banner и MAC integrity level 63 — всё работает.
- Test harness: `tests/scripts/test_integrate_pam.sh` проверяет
  инвариант «`@include certauth-only` строго после `pam_parsec_mac.so`».

### Документация

- `docs/install.md` §8 — описана логика placement anchor.
- `docs/install.md` §10 «Что делать, если…» расширен на 8 новых
  troubleshooting-кейсов из боевой отладки:
  - `pam_parsec_mac: Can't obtain required data` (три причины + фиксы)
  - `parsec.mac=0` + pam_parsec_mac в стеке (включить kernel МКЦ vs
    убрать из стека)
  - Legacy `[mac].enabled = true` (TOML parse error → миграция на
    `[mac].runtime`)
  - WARN `mac_caps_missing` / `pdp_set_fd rc=-1` — не блокеры, как
    выдать `PARSEC_CAP_CHMAC` если нужна метка на session-файле
  - 14-секундная тишина после `trying USB candidate` на 0.3.5
    (фикс через апгрейд на 0.3.6+)
  - `dmi_board_serial = 0` в виртуалках, drift host_id при пересборке
  - fly-dm не показывает greeter banner (`greeter-show-messages = true`)
  - DIGSIG enforce без подписи (подписание или logging-only)
  - `pam-certauth` модуль не загружается (ldd missing libparsec-mic.so.3)

## [0.3.7] — 2026-05-25

### Critical

- **`[mac].runtime` runtime-переключатель Parsec backend.** Новое поле
  `[mac].runtime` (`required` | `auto` | `disabled`, default `auto`)
  разводит compile-time feature `astra-mac` от runtime-выбора backend'а.
  Боевой кейс: один `.deb` (собранный с `astra-mac`) ставится на
  терминалы с МКЦ и без — поведение управляется через `config.toml`.
  - `disabled` — гарантированный `StubBackend`, никаких `pdp_*`
    вызовов даже на сборке с `astra-mac` (фиксирует событие
    `mac_runtime_disabled` в syslog).
  - `required` — fail-closed: если `parsec_strict_mode()` ядра вернул
    не «активно», аутентификация отклоняется с событием
    `mac_runtime_required` (вместо тихой деградации).
  - `auto` *(default)* — probe ядра на старте сессии; настоящий
    `ParsecBackend` при активном МКЦ, fallback на `StubBackend` с
    одноразовым `mac_runtime_fallback` (WARN) иначе.
  - Валидация: `disabled + cert_integrity=required` и `required` без
    `astra-mac` отвергаются на старте.
  - Снимает блокер на терминале МКЦ: `pam_parsec_mac: Can't obtain
    required data` теперь решается выставлением `runtime = "disabled"`
    + удалением `pam_parsec_mac` из стека, а не пересборкой `.deb`.

### Диагностика

- `HostIdentityResolver::probe_all()` — публичный API, возвращающий
  одно `ProbeResult` на каждый сконфигурированный источник
  (`[host_identity].sources`) без влияния на политику выбора
  (`resolve()` остаётся first-working-wins). cdylib теперь на старте
  каждой auth-сессии логирует по строке INFO на источник в
  `pam_certauth.host_identity` (`probe ok` / `probe error` +
  `probe selected`). Источник истины для регистрации терминала в
  реестре — этот лог; `sha256sum /etc/machine-id` вручную больше
  не нужен и даёт расхождение, если `[host_identity].sources`
  содержит не только `machine_id`.
- `ResolvedHostId::hash_prefix()` — первые 8 hex символов sha256 для
  on-screen диагностик. Сообщение `host_binding` mismatch на лок-скрине
  терминала теперь показывает короткий `host_id=a1b2c3d4 (source=…)`
  вместо нечитаемых 64 hex. Полный hash остаётся в syslog.
- fly-dm greeter baseline: в начале `pam_sm_authenticate` модуль
  отправляет `PAM_TEXT_INFO` с короткой идентификацией машины
  («Это устройство: host_id=… (source=…)»). `fly-dm` показывает её
  в greeter UI при `greeter-show-messages = true` в
  `/etc/X11/fly-dm/fly-dmrc` — инженер у терминала мгновенно сверяет
  hash с реестром, не заходя в shell.

### Документация

- `configuration.md` §«MAC integrity» — новая подсекция «Семантика
  `runtime`» с матрицей `runtime × cert_integrity × astra-mac`,
  таблица полей дополнена `runtime` и `warn_on_homedir_label_mismatch`.
- `install.md` §8.5 переписан под runtime-переключатель: один и тот же
  `.deb` для трёх сценариев (МКЦ выключен / включён / смешанный парк).
  Подсекция §8.5.1 — baseline для fly-dm greeter.
- `install.md` Troubleshooting — команда `journalctl … 'host_identity:
  probe'` теперь источник истины для регистрации терминала.

### Внутреннее

- Новые audit-события `mac_runtime_fallback` (WARN) и
  `mac_runtime_disabled` (INFO) в target `mac.audit`.
- `MacRuntimeMode` (validated layer) и `RawMacRuntimeMode`
  (raw config) — pub re-exports через `pam_certauth_core::config::validated`
  и `::config::raw`.
- `build_backend(MacRuntimeMode)` в `pam_certauth::session` —
  единственная точка решения «Parsec vs Stub», вместо двух compile-time
  ветвей.

## [0.3.6] — 2026-05-25

### Диагностика

- `host_id` логируется при каждом `resolve()` с указанием `source`,
  `raw` и полного `host_id_hash` (target `pam_certauth.host_identity`).
  Fallback на `unknown` тоже логируется. **Регистрация терминала в
  реестре теперь по факту resolved hash из syslog**, не ручное
  вычисление `sha256(/etc/machine-id)` — устраняет drift между скриптом
  выпуска cert'а и развёрнутыми `[host_identity].sources`.
- `PAM_TEXT_INFO` на экране при `host_binding` mismatch: показывает
  `host_id_hash` этой машины + тип источника + просьбу передать
  админу. Текст дублируется в syslog (`warn`).
- `PAM_TEXT_INFO` на экране при wrong .p12 PIN (`MAC verify`): если
  cert лежит в незашифрованном SafeBag (новый issuance-скрипт), модуль
  читает его без пароля и показывает host/user, для которых cert
  выпущен — инженер сразу видит «вставлена не та флешка». Для
  legacy-формата (cert тоже зашифрован) — обычное «пароль неверный».
- Per-candidate USB-iteration логирование на уровне `info`: mount
  succeeded → discovery → envelope parsed → chain validated → final
  outcome. Был «провал тишины» 14 секунд между «trying USB candidate»
  и concluding модулем; теперь каждый шаг видим в
  `journalctl -t pam_certauth`.

### Безопасность

- Fail-closed на неверный PIN: не перебираем USB-партиции (lock-test
  `wrong_pin_does_not_fall_back_to_next_partition`). Multi-partition
  fallback остаётся ограничен pre-password failures (ASN.1 envelope),
  иначе создаётся PIN-oracle / chain-probing по сменным носителям.
- Multi-source matching по `[host_identity].sources` намеренно НЕ
  делается (weakest-link bypass: атакующий с root спуфит самый
  писабельный источник → байпасит host-binding). Это зафиксировано в
  threat-model.md §4.10.

### Документация

- `install.md` — новая секция «Сертификат не принимается на терминале»
  (чек-лист: host_id из syslog → сверка с реестром → перевыпуск или
  чтение cert plaintext из .p12). Обновлён раздел `host_binding
  mismatch` (cert в новом формате читается без PIN).
- `install.md` §8.5 — два сценария PAM-стека (с/без МКЦ PARSEC MAC)
  с явной инструкцией где `pam_parsec_mac.so` нужен, а где он завалит
  account-фазу с `Can't obtain required data`.
- `threat-model.md` §4.10 — multi-source iteration по host_identity
  явно отмечена как НЕ выполняемая по причине weakest-link bypass.

### Внутреннее

- Новый pub helper `pam_certauth_core::pkcs12::try_extract_cert_without_pin`
  — best-effort чтение leaf-cert из PKCS#12 без пароля. Возвращает
  `None` для legacy-формата. Используется wrong-PIN диагностикой.
- Новый pub метод `FlowIo::show_info(&str)` (default no-op) — путь
  доставки `PAM_TEXT_INFO` на экран. `RealFlowIo::with_pamh()`
  привязывает live PAM-handle для cdylib; тест-фейки остаются без
  изменений.

### Deferred (планируется к 0.3.7)

- `[mac].runtime = "auto" | "required" | "disabled"` — runtime-
  переключатель Parsec backend без пересборки (сейчас compile-time
  feature `astra-mac` решает однозначно). Боевой кейс: бинарь собран
  с `astra-mac`, но на конкретной машине МКЦ-ядро выключено — нужен
  fallback на StubBackend без пересборки .deb.
- `HostIdentityResolver::probe_all()` — вернёт значения всех
  сконфигурированных источников (а не только первого работающего)
  для startup-логирования и admin-troubleshooting'а.
- `host_id_hash_prefix` (первые 8 hex) в PAM_TEXT_INFO — полный
  64-char hash на экране нечитаем.
- Baseline-строка `«Это устройство: source=… hash_prefix=…»` для
  fly-dm greeter (до prompt'а PIN).

## [0.3.5] — 2026-05-25

### Fixed

- USB partition iteration теперь делает fallback на следующий раздел
  при ASN.1-ошибке парсинга PKCS#12 (т.е. «файл по нашему пути есть,
  но это не P12»). Раньше такая коллизия имён — типичная для
  USB-устройств с несколькими разделами и Apple-форматированных
  носителей — мгновенно роняла auth с
  `asn1_check_tlen: wrong tag, Type=PKCS12`, не пробуя оставшиеся
  партиции.

### Security

- Fallback срабатывает ТОЛЬКО на ASN.1-fail (pre-parse БЕЗ пароля).
  Ошибки MAC verify / decrypt / chain validation (всё, что требует
  пароля или валидации сертификата) остаются fail-closed без
  перебора — не создаёт PIN-oracle и не позволяет chain-probing по
  разделам.

### Added

- `pam_certauth_core::pkcs12::validate_p12_envelope(&[u8])` —
  pure-функция, проверяющая ASN.1-конверт PKCS#12 без обращения к
  паролю. Используется в `flow.rs::authenticate_pkcs12` как граница
  между «файл на USB не P12 → пробуем следующий раздел» и «файл —
  валидный P12, но не расшифровывается → fail-closed».
- `FlowError::P12Envelope` (мапится на `PAM_AUTHINFO_UNAVAIL` (9))
  для случая «ни одна партиция не дала валидного P12-конверта».

## [0.3.3] — unreleased

### Fixed

- `pkcs12_path_pattern` теперь реально применяется при discovery
  credentials с USB-носителя. До этого параметр декларировался в
  конфиге, но игнорировался — discovery всегда искал
  `<mountpoint>/certs/user.p12`. Default остался прежним
  (`certs/user.p12`) для backwards compat. Поддержан плейсхолдер
  `${user}`, добавлена защита от path-traversal в валидаторе
  (отклоняются абсолютные пути, пустая строка, сегменты `..` и `.`).

### Changed

- Снято требование `LABEL=PAMCERT` на партиции USB-носителя.
  `pam_certauth` теперь перебирает все партиции с FS из allowlist
  (`vfat`, `exfat`, `ext4`, `ntfs`) и останавливается на первой, где
  найден `.p12`. Реальная граница доверия — расшифровка `.p12`
  паролем пользователя и валидация цепочки сертификатов; label-фильтр
  ничего не добавлял к безопасности, только UX-friction.
- Удалена ошибка `UsbError::AmbiguousPartition` (несколько партиций с
  меткой `PAMCERT`) — она теряет смысл без обязательной метки.

### Added

- Новый конфиг-параметр `max_usb_partitions` (default `8`, range
  `1..=64`) ограничивает число перебираемых партиций. Анти-DoS guard
  против атакующего с физическим доступом, который мог бы подсунуть
  устройство с огромным числом разделов и заставить модуль крутить
  бесконечный цикл mount/umount.
- Новая ошибка `UsbError::TooManyPartitions { devnode, count, limit }`
  (fail-closed при превышении лимита).

### Migration

- Конфиги 0.3.2 совместимы как есть: `max_usb_partitions` опционален,
  default `8` достаточен для всех реалистичных USB-носителей.
- Раздел `LABEL=PAMCERT` продолжает работать, но метка больше не
  обязательна — можно оставить как есть или убрать на следующем
  переоформлении флешки.

## [0.3.2] — unreleased

### Added

- Поддержка USB-флешек с partition table: если на whole-device нет FS,
  pam_certauth ищет среди разделов один с label=PAMCERT и FS из allowlist.
  Несколько подходящих разделов → отказ (fail-closed). Обратная
  совместимость: установки с FS на whole-device работают как раньше.

## [0.3.0] — 2026-05-15

### Added

- **MAC integrity (МКЦ) integration for Astra SE strict-mode.**
  Сессия теперь получает метку `(level, categories)`, выбранную как
  пересечение расширения `MAX_INTEGRITY` сертификата
  (OID `2.25.273824307386008814506455310913083078403`) с потолком
  рантайма от libpdp/libparsec. Новая секция `[mac]` в `config.toml`
  c полями `cert_integrity` (`required` / `optional` / `ignore`) и
  `fallback_max_integrity`.
- Feature-флаг `astra-mac` (включается на сборке для Astra SE);
  stub-бэкенд используется на не-Astra хостах и отвергает
  `cert_integrity = "required"` на этапе загрузки конфига.
- DER-кодек `IntegrityLabel` со строгим парсером и компонентным
  `strictly_below` для сравнения меток.
- Метки `pdpl-file :::iinh` накладываются на
  `/etc/pam_certauth/`, `/var/lib/pam_certauth/`,
  `/var/cache/pam_certauth/` через postinst при `astra-strictmode-control
  is-enabled`. `host_id` получает `chattr +i` после первой записи.
- Атомарная запись `sessions.json` теперь использует fd-based labeling
  через `pdp_set_fd` (метка накладывается до публикации имени файла,
  закрывает TOCTOU-окно). `irelax` через fd-API ядро не принимает
  (EINVAL) — relax-семантика для `sessions.json` обеспечивается
  `iinh`-наследованием от parent dir.
- E2E-сценарии T1-T12 (`vagrant/scripts/test-mac.sh`) и
  perf-bench (`vagrant/scripts/bench-mac.sh`) для Astra VM.
- Документация: `docs/install.md`, `docs/cert-issuance.md`,
  `docs/configuration.md`, `docs/threat-model.md` пополнены секциями
  по МКЦ.

### Build

- `debian/control`: добавлен `Recommends: libpdp3 (>= 3.11+ci97~)` и
  `libparsec-base3 (>= 3.11+ci97~)` (оба runtime-dep при сборке с
  `astra-mac`).
- **Linker fix:** `parsec_capget` оказался экспортируемым из
  `libparsec-base.so`, а не `libpdp.so` — Astra CI build падал с
  `undefined symbol: parsec_capget` (verified run 25903325006,
  2026-05-15). `build.rs` теперь emits и `-lpdp`, и `-lparsec-base`;
  extern-блок с `parsec_capget` помечен `#[link(name = "parsec-base")]`.
- **Linker fix:** `getmicnam` / `freemicent_r` живут в
  `libparsec-mic.so.3`, а не в `libpdp.so` (комментарий в `build.rs`,
  утверждавший обратное, исправлен). `build.rs` / `Dockerfile` теперь
  линкуют `-lparsec-mic`.

### Fixed

- **libpdp text-codec grammar.** Кодировщик `encode_label_text`
  раньше формировал строку `"0:0:cat:flags:level"` (пять сегментов,
  пятый = линейный ilevel) — это была устаревшая интерпретация
  заголовков. Реальное strict-mode-ядро Astra 1.8.4 принимает
  четырёхсегментную грамматику `level:ilevel:cat[:flags]`.
  Кодек переписан, e2e-применение метки на `sessions.json` теперь
  отображается `pdpl-file` как
  `Уровень_0:Сетевые_сервисы:Нет:0x0!`.
- **`pdp_set_fd` + `irelax` несовместимы.** Ядро возвращает EINVAL,
  если irelax передан через fd-based API. Демон теперь вызывает
  `set_fd_label(.., irelax=false)`. Path-based `pdp_set_path`
  irelax по-прежнему принимает (используется postinst через
  `pdpl-file`).
- **`getmicnam` возвращает library-private static memory** (per
  `man getmicnam` на Astra 1.8.4), а не heap-аллоцированную структуру.
  Прежний код звал `freemicent_r` на результат и падал в
  `pam_sm_open_session` с `free(): invalid pointer` → SIGABRT.
  Указатель больше не освобождается.
- **Daemon под `User=pamcertauth` (не root)** при опциональной
  активации МКЦ. Шипованный drop-in `mac-integrity.conf.example`
  использует `PAMName=pam-certauth` + парный PAM-стек
  `dist/pam.d/pam-certauth.example` (`pam_parsec_cap.so` +
  `pam_parsec_mac.so`) для подъёма ilevel=63 и `PARSEC_CAP_CHMAC` на
  процессе демона. Ранее обсуждавшийся `execaps -c 0x8 -- ...`-обход
  не используется — `execaps` сам требует `PARSEC_CAP_CAP` у
  запускающего процесса, которой у `pamcertauth` нет.
- **Sessions registry на tmpfs.** Переехал из
  `/var/lib/pam_certauth/sessions.json` (persistent) в
  `/run/pam_certauth/sessions.json` (volatile, `RuntimeDirectory=`).
  Снимает stale-state-after-reboot foot-gun и MAC-labelling churn на
  каталоге. `daemon.lock` и кэши остаются в `/var/lib/`.

### Removed

- Откат 0.2.x-набора `pam_cert_scopes` / CMS M-of-N work-order /
  approver-EKU / external policy TOML / `pam-certauth execute|policy|gc`.
  Бинарь оставляет только `pam-certauth daemon`. IPC v2 retains
  `engineer_ski` + `engineer_cert_sha256` (МКЦ-audit), `scopes`
  убран. Подробности см. в плане
  `docs/superpowers/plans/2026-05-14-strip-scopes-mofn.md`.

## [0.1.1] — 2026-05-06

- Cert-binding extensions take precedence over the legacy
  `[[user_mapping]]` TOML list. `pam_cert_user_binding` /
  `pam_cert_host_binding` are the sole source of authorisation when
  present; `[[user_mapping]]` is consulted only for certificates
  without `pam_cert_user_binding`.
- PAM cdylib syslog backend wired into the `tracing` subscriber:
  every `error!` / `warn!` emitted from `libpam_certauth.so` lands
  in `/var/log/auth.log` (LOG_AUTH facility, ident `pam_certauth`,
  `pam_certauth[<pid>]:` prefix). Production diagnosis no longer
  blind.
- Three PAM-stack snippets shipped alongside the module:
  `/etc/pam.d/certauth` (2FA, default), `/etc/pam.d/certauth-optional`
  (phased rollout), `/etc/pam.d/certauth-only` (cert-only,
  lockout-strict). `integrate-pam.sh --mode=2fa|optional|cert-only`
  selects which one to wire in. The deprecated `--strict` /
  `--optional` flags still work as aliases.
- SysV init script (`/etc/init.d/pam-certauth`) shipped for
  hosts without systemd; adds `lsb-base` dependency to the `.deb`.
- Manpage `pam-certauth(8)` shipped.
- Docs: USBGuard interop, Astra ЗПС (DIGSIG) caveat, USB-lockout
  pre-deploy checklist, full `on_usb_removed` mode reference.

## [0.1.0] — 2026-05-05

Initial public release.

- PAM module for X.509 certificate authentication on Astra Linux SE 1.7+.
- USB token support: PKCS#11 (Rutoken/JaCarta/ESMART), PKCS#12 file.
- GOST cryptography (Р 34.10-2012, Р 34.11-2012) via openssl + gost-engine.
- Cert-driven authorisation: per-cert host_binding and user_binding X.509
  v3 extensions; no central ACL.
- Host-removal monitor daemon (pam-certauth) with udev + logind
  integration: lock/logout/shutdown on USB unplug.
- Configurable hook execution (pre_auth/post_auth_success/session_open/
  session_close) via fork+execve with full sandboxing.
- Debian package for Astra Linux SE.

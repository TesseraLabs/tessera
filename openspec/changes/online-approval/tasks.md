# Tasks: online-approval

Пререквизиты: `qr-login-core` реализован (challenge/nonce-машинерия, верификатор MAC,
consumed-state); крипто-контракт Change-0 финализирован. Сетевой канал агент↔Control —
вне scope (change `sync-agent`); здесь всё тестируется mock-агентом по IPC.

## 1. IPC-контракт агента

- [ ] 1.1 Сообщения `ATTEMPT`/`GRANT`/`REFRESH`/`ATTEMPT_CANCEL`/`ERROR` в `tessera_proto`
      (или соседняя схема — закрыть Open Question 3 design.md): framing length-prefixed,
      версия, bounded-длины, схема attempt_id/nonce_id единая с контрактом оверлея
- [ ] 1.2 Server-side socket в `pam_tessera`: защищённая runtime-dir, mode 0600,
      `SO_PEERCRED`, single-connection per peer-class, cleanup при закрытии/крэше
- [ ] 1.3 Негативные сценарии: duplicate GRANT, чужой attempt_id, коннект без ATTEMPT,
      обрыв, флуд сверх bounded-очереди — каждый в определённое терминальное состояние
- [ ] 1.4 Юнит-тесты framing сообщений: roundtrip, битые кадры, превышение длин

## 2. Верификация гранта

- [ ] 2.1 Обобщить верификатор кода до двух представлений: full-MAC и `truncate_N` —
      одна каноническая формула, общий код-путь, constant-time сравнение
- [ ] 2.2 Атомарный консьюм nonce со способом потребления (manual|online) в consumed-state,
      офлайн-персист (расширение формата `qr-login-core`)
- [ ] 2.3 Остаточные проверки на грант-пути: локальная роль покрывает level,
      TOCTOU-перечитка уровня перед `PAM_SUCCESS` (переиспользование, не копия)
- [ ] 2.4 Юнит-тесты: невалидный MAC, mac на мёртвый/чужой nonce, гонка manual-vs-grant
      (оба порядка), повтор после reboot

## 3. Мультиплекс в pam_tessera

- [ ] 3.1 Ожидание на источниках {prompt | socket оверлея | socket агента} через poll,
      без потоков; отсутствие агента не задерживает попытку (non-blocking connect + отправка)
- [ ] 3.2 Регистрация попытки: `ATTEMPT` после генерации challenge, конфиг-гейт
      (connectivity-секция), `REFRESH` при ротации nonce, `ATTEMPT_CANCEL` на всех
      терминальных переходах
- [ ] 3.3 Таблица терминальных состояний попытки расширена: грант-победил, код-победил,
      cancel/timeout с живой регистрацией, агент умер посреди ожидания
- [ ] 3.4 Интеграционные тесты с mock-агентом: happy path (грант → PAM_SUCCESS),
      обрыв после регистрации → ручной ввод, поздний грант, зависший агент

## 4. Аудит и конфиг

- [ ] 4.1 События `attempt_registered`, `grant_received`, `grant_discarded{reason}`,
      `completion=online|manual` в `qr_code_login` — hash-chain, без sensitive
- [ ] 4.2 Конфиг: включение онлайн-завершения per-device (connectivity-секция профиля),
      дефолт = выключено; без агента поведение байт-в-байт `qr-login-core`
- [ ] 4.3 Тест деградации: конфиг выключен / агент отсутствует → ни одного нового syscall
      на auth-пути (сравнительный прогон)

## 5. Security-gate и документация

- [ ] 5.1 threat-model дополнение: sync-агент как недоверенный транспорт в auth-пути
      (подмена/replay/задержка гранта, флуд ATTEMPT, QoS) — приватные спеки tessera-ws
      отдельным PR (инвариант hybrid-fleets, platform roadmap-запись)
- [ ] 5.2 Обязательный pre-merge: `threat-model` + `vuln-scan` harness на изменённые
      `pam_tessera`/`tessera_core`/`tessera_proto`
- [ ] 5.3 E2E-план на Astra VM (техника VM-E2E): грант через mock-агент в живом fly-dm
      стеке; сценарий «обрыв посреди ожидания → ручной код»

# Design: qr-login-core

Канон дизайна — `tessera-ws/specs/2026-07-03-qr-login-display-design.md` (спайк-верифицирован на
Astra 1.8.4, прошёл ревью). Здесь — device-side решения для openspec.

## Модель

QR рождается **внутри попытки входа** (не idle-экран): `pam_tessera` в `pam_sm_authenticate`
генерит nonce и challenge после того, как попытка начата и известны роль-учётка + уровень МКЦ.
Даёт привязку к попытке (nonce) и к уровню (в challenge и MAC). Согласуется с инвариантом
платформы «уровень — часть challenge, подмена после выдачи невозможна».

## Уровень МКЦ — канал `/proc/self/attr/current`

Метка процесса (parsec, SELinux-подобно), формат `конф:целостность:лин:кат:роли`;
**МКЦ = уровень целостности = 2-е поле**. `pam_tessera` читает обычным `read`, парсит 2-е поле —
без FFI, без parsec-dev, без xparsec. Спайк-доказано на включённом МКЦ (`pdp-exec -l "0:N:0:0:0"`
→ метка `0:N`; реальный вход fly-dm несёт `0:3`). Отвергнуты: env `PAM_MAC_SAVED_MACLABEL` (пуст
на базовом уровне), xparsec (тяжелее). **TOCTOU:** перечитать перед финальной валидацией, сверить
с уровнем в challenge, расхождение → fail-closed.

## Крипто-контракт (блокер верификации)

Каноническая формула (единый источник — §8.1 дизайна):
```
код = truncate_N( MAC(per_device_key, canon(device_id, nonce, role_id, level, ttl)) )
```
Устройство пересчитывает MAC **byte-identical** с бэкендом → поля/порядок/кодировка/`N` каноничны.
**TTL: рекомендация — вне MAC** (устройство бракует код по локальному сроку), MAC вяжет
`device_id/nonce/role_id/level`. Финализация формулы и payload-схемы — совместно с Codes
(`issuance-signals`). Пока не финализировано — «локальная проверка MAC» не имплементируется.

## Trust-модель уровня (code-path ≠ cert-path)

Cert-путь: авторизация уровня device-local (серт несёт `pam_cert_max_integrity`). **Code-путь:
серта нет** — per-инженер авторизация уровня на backend PDP (закодирована фактом «валидный MAC
существует»). Device-side остаточная проверка: MAC-валидность + локальная роль-учётка покрывает
`level`; если MAC валиден, но локальная роль НЕ даёт уровень → **fail-closed**. Источник уровня
(`/proc/self/attr/current`) pre-auth/greeter-производный, сам не доверенный — безопасность держит
цепочка «backend PDP переавторизует + MAC вяжет уровень».

## Brute-force короткого кода

Стойкость = f(`N`, rate-limit, TTL, число живых nonce). Design-constraint:
`10^N ≫ rate_limit_per_min × TTL_min × grace_N`. `grace_N` (число одновременно живых nonce при
ротации) — **security-параметр**, выводится из неравенства, не UX-калибровка. Дефолт:
консервативный `N`, узкое grace-окно, жёсткий rate-limit. `PAM_MAXTRIES` не ловит socket-ввод
(режим 3) → собственный счётчик в `pam_tessera`.

## nonce lifecycle

CSPRNG, per-попытка, одноразовый. Consumed-state трекается в grace-окне и **через reboot**
(офлайн-персист) — иначе one-time не держится. Device-clock недоверен (`product.md`
time-confidence) → TTL best-effort по monotonic-since-boot, реальный контроль — rate-limit +
одноразовость.

## Fail-closed vs fallback

- **QR-метод fail-closed**: нет канала / рендер провалился / метка уровня битая → вход по QR не
  продолжается.
- **PAM-стек fallback**: контроль-флаг метода такой, что отсутствие кода роняет на следующий метод
  (пароль/серт) для доступности. Точная семантика (`sufficient` fail-open ↔ fail-closed) и порядок
  стека фиксируются в tasks; поведение на {нет канала, неверный код, ошибка модуля, timeout};
  исключить password-bypass вне валидного MAC.

## Открытые вопросы (из дизайна §10)

- Крипто-контракт §8 — финализация с Codes (блокер верификации).
- Полная длительность four-eyes (3–5 мин) в живом fly-dm; sshd `LoginGraceTime` для SSH-пути.
- Параметры grace-окна (security, из неравенства).

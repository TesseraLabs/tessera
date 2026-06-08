# Design: tags-delegation

## Context

Источник семантики — `tessera-ws/specs/2026-06-08-device-tags-delegation-design.md`
(brainstorming 2026-06-08). Здесь — контракт реализации для tessera. Tessera v0.3.19:
`trust-chain-validation` строит и проверяет цепь по RFC 5280; `cert-scope-binding` авторизует
по листовым custom-расширениям (арка `2.25.<UUID>`, все non-critical); `role-store` доставляет
базу ролей managed-манифестом с `bundle_version` (anti-rollback) или standalone (права ФС).

Ограничения: офлайн-устройство (никаких онлайн-проверок); open-core — Engine обязан работать
без Control; `tessera_core` — sync, без tokio; fail-closed на auth-пути; на непонятый critical
ext — reject (PwnKit-урок, threat-model §4).

## Goals / Non-Goals

**Goals:**
- Теги устройства как generic-данные: Engine не знает имён → новые теги без изменения кода.
- Рамки делегирования на CA-сертах: `requireTags`/`allowRoles`/`maxLevel`/`maxTtl`, монотонно.
- Гарантия на устройстве, офлайн: конверт проверяется против собственных подписанных тегов.
- AND/MIN по всем звеньям → устойчивость к misissued промежуточному CA.
- Version-gate: reject сертов формата новее известного (fail-closed).

**Non-Goals:**
- Богатый язык рамок (OR/range/отрицания) — не воскрешаем вырезанный в 0.3.0 движок scopes/M-of-N.
- Авторинг тегов и словарь тегов — серверная фича Control (не в этом change).
- Issuance-side проверка конверта (PDP) — контракт Codes/Control, фиксируется, но не реализуется здесь.
- Group-bound лист отдельной формой — выражается существующим wildcard `host_binding` + конвертом.

## Ключевые решения

1. **Опаковые теги + generic superset.** Набор тегов устройства = map `key→value` (UTF8).
   Проверка конверта = `∀(k,v)∈requireTags: device.tags[k]==v`. Engine не хардкодит имён тегов.
   Новый ключ/значение = данные (не бампает версию, не трогает код); новое *измерение* рамки =
   бамп версии + код.

2. **Источник тегов = manifest role-store.** Managed: теги едут в том же подписанном манифесте
   и под тем же `bundle_version`, что база ролей → один счётчик anti-rollback (threat-model §5.1),
   не второй канал. Standalone: локальный файл тегов под доверием прав ФС (паритет с role-store
   standalone).

3. **Рамки только на CA-сертах.** `delegation_constraints` валиден лишь при `CA=TRUE`; на листе →
   malformed → reject. Лист рамок не несёт — конверт наследуется из цепи.

4. **Edge-устойчивость через AND/MIN.** Engine применяет рамки **каждого** CA-серта цепи:
   `device.tags ⊇ requireTags` (для каждого), роль ∈ `allowRoles` (каждого), уровень ≤ `maxLevel`
   (каждого), TTL звена ≤ `maxTtl` родителя. Поэтому misissued дочерний CA с более широкой рамкой
   не вырывается из родительского конверта. Issuance-side монотонность (потомок ⊆ родителя) —
   ранний отказ/ясность, но безопасность не зависит от честности звеньев.

5. **Два слоя fail-closed на эволюцию формата.** (1) Непонятый OID critical-расширения → reject
   (RFC). (2) Понятый `profile_version > max_supported` → reject. Старый Engine не пропустит серт
   нового формата ни одним путём.

6. **Critical-флаг — отличие от существующих расширений.** `host/user_binding`, `max_integrity`,
   `allowed_roles` — non-critical. Новые два — **critical**: их игнор = обход рамок, что недопустимо.

## Риски

- Rollout Engine-first: серты с новыми critical-расширениями отвергаются старым парком до апгрейда
  Engine. Митигатор: version-gate и поэтапная выкатка (canary — открытый вопрос серверного блока).
- Устройство без тегов под групповым (wildcard) листом → конверт неудовлетворим → отказ. Это
  корректный fail-closed, но требует надёжной доставки тегов перед выпуском wildcard-листов.
- Расширение периметра path validation (H5) — фиксируется при ФСБ/ФСТЭК-заключении.

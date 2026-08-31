// Реестр реализованных ключей profile.yaml (лечение класса C2 + подраздела
// «профиль обещает — код не читает»). Идея: КАЖДЫЙ ключ, реально присутствующий
// в profile.yaml, обязан иметь владельца — проверку, которая его читает, ЛИБО
// запись в MANIFEST с явной причиной, почему он намеренно не реализован.
// Профиль, который читается человеком как описание того, что проверяется,
// не имеет права молчаливо обещать больше, чем делает код.
//
// Механизм статический (декларативный), не runtime-трассировка обращений к
// объекту профиля: трассировка обращений доказала бы только "значение было
// прочитано хоть где-то", а не "гарантия действительно проверяется" — ровно
// то расхождение, из-за которого C2 и возник (kinds.*.anchors.required
// технически "читался" в checkEntityTypeAnchor, но только ради значения
// "type", остальные типы пролетали молча). Владение объявляется явно, по
// одному пункту манифеста на каждую РЕАЛЬНО реализованную гарантию.

/**
 * @typedef {{
 *   pattern: string,
 *   owner: string,
 *   status: 'implemented'|'not_implemented',
 *   reason: string,
 * }} RegistryEntry
 */

/**
 * Манифест владения ключами profile.yaml. `pattern` — путь через точку,
 * где `*` соответствует ЛЮБОМУ единственному сегменту (имени вида, контекста,
 * среза, типа нормы) на этой позиции. Порядок пунктов — порядок, в котором
 * их стоит чинить (см. REVIEW.md C2 и подраздел "профиль обещает — код не
 * читает"), не порядок исполнения.
 * @type {RegistryEntry[]}
 */
export const MANIFEST = [
  { pattern: 'profile', owner: 'loadProfile', status: 'implemented', reason: 'метаданные, не гарантия — используется только для человека' },
  { pattern: 'sources', owner: 'findSpecFiles (loadRepo)', status: 'implemented', reason: 'ограничивает обход директориями с реальными спеками — файл вне списка (напр. grammar/SYNTAX.md) не линтуется вовсе' },
  { pattern: 'relation_types.*.cardinality', owner: 'checkRelationTypes', status: 'implemented', reason: 'проверяет scalar/list форму отношения' },
  { pattern: 'relation_types.*.sources', owner: 'checkRelationTypes', status: 'implemented', reason: 'ограничивает kind источника ребра' },
  { pattern: 'relation_types.*.targets', owner: 'checkRelationTypes', status: 'implemented', reason: 'ограничивает kind цели ребра' },
  { pattern: 'relation_types.*.flow', owner: 'traceFlow', status: 'implemented', reason: 'задаёт причинное направление relation независимо от места объявления' },

  { pattern: 'contexts.*.prefix', owner: 'checkReqPrefix', status: 'implemented', reason: '' },
  { pattern: 'contexts.*.title', owner: 'loadProfile', status: 'implemented', reason: 'человеческая метка, не гарантия' },

  { pattern: 'kinds.*.title', owner: 'loadProfile', status: 'implemented', reason: 'человеческая метка, не гарантия' },
  { pattern: 'kinds.*.review_role', owner: 'buildSemanticDiff', status: 'implemented', reason: 'роль boundary поднимает изменения вида в отдельный раздел semantic review' },
  { pattern: 'kinds.*.required_fields', owner: 'checkKindShape', status: 'implemented', reason: 'для вида проверяется наличие и непустота каждого обязательного поля frontmatter' },
  { pattern: 'kinds.*.required_sections', owner: 'checkKindShape', status: 'implemented', reason: 'для вида проверяется наличие каждого обязательного смыслового раздела Markdown' },
  { pattern: 'kinds.*.anchors.required', owner: 'checkKindAnchors', status: 'implemented', reason: 'для каждого типа якоря из required проверяется наличие хотя бы одного якоря этого типа у термина' },
  { pattern: 'kinds.*.anchors.optional', owner: 'checkKindAnchors', status: 'implemented', reason: 'вместе с required задаёт допустимое множество типов якоря для вида; якорь типа вне required∪optional — находка' },
  { pattern: 'kinds.*.links.may_reference', owner: 'checkLinkMayReference', status: 'implemented', reason: '' },
  { pattern: 'kinds.*.must', owner: 'checkKindMust', status: 'implemented', reason: 'значения "outcomes", "rejected_alternative", "producer" — см. checkKindMust' },
  { pattern: 'kinds.*.computes_obligations', owner: 'loadRepo (buildGraph.patternKind)', status: 'implemented', reason: 'помечает вид, требования которого вычисляются для каждого применения' },
  { pattern: 'kinds.*.append_only', owner: 'loadRepo (decisionKind) + buildSemanticDiff', status: 'implemented', reason: 'semantic base/head review запрещает удаление решения и изменение уже принятого ADR; смена выбора оформляется новым replaces/revokes' },
  { pattern: 'kinds.*.applicable_to', owner: 'checkPatternApplication', status: 'implemented', reason: 'значение из profile.yaml — умолчание; frontmatter файла паттерна может переопределить (REVIEW.md P4)' },
  { pattern: 'kinds.*.lifecycle', owner: 'checkLifecycle', status: 'implemented', reason: 'status страницы обязан входить в закрытый список вида' },

  { pattern: 'non_domain_outcomes', owner: 'cmdOutcomes', status: 'implemented', reason: '' },

  { pattern: 'outcomes.closed', owner: 'checkOutcomesFormat', status: 'implemented', reason: 'при closed:false проверка E-OUTCOMES-NOT-CLOSED выключается (REVIEW.md P6)' },
  { pattern: 'outcomes.auto_fix', owner: 'checkAutoFixForbidden', status: 'implemented', reason: 'единственное поддерживаемое значение — "forbidden" (авто-исправления в CLI нет физически); любое другое значение — находка о несоответствии профиля возможностям инструмента (REVIEW.md P7)' },
  { pattern: 'outcomes.partition_must_be_total', owner: 'checkPartitions', status: 'implemented', reason: '' },
  { pattern: 'outcomes.combinations.require_total', owner: 'checkCombinations', status: 'implemented', reason: '' },
  { pattern: 'outcomes.combinations.require_disjoint', owner: 'checkCombinations', status: 'implemented', reason: '' },

  { pattern: 'norm_kinds.*.evidence', owner: 'checkEvidenceMissing', status: 'implemented', reason: '' },
  { pattern: 'norm_kinds.*.any_of', owner: 'checkEvidenceMissing', status: 'implemented', reason: 'при any_of не true требуется присутствие ВСЕХ типов evidence из списка, а не любого одного (REVIEW.md P1)' },

  { pattern: 'slices.*.seed', owner: 'reviewSlice (spec.mjs context --seed-files/--seed-git); контекстно — cmdOutcomes/why для "символ"/"норма"', status: 'implemented', reason: 'засев по типу узла ("норма", "символ") читается контекстно самой командой (context/why); засев списком изменённых файлов (срез "review") — `spec.mjs context --slice review --seed-files <файл>` либо `--seed-git <ref>` (REVIEW.md P2, задание фазы 2 п.3)' },
  { pattern: 'slices.*.follow', owner: 'contextSlice', status: 'implemented', reason: '' },
  { pattern: 'slices.*.cross_context', owner: 'contextSlice', status: 'implemented', reason: '' },

  { pattern: 'candidates.threshold', owner: 'cmdCandidates', status: 'implemented', reason: '' },
  { pattern: 'candidates.weights.*', owner: 'scanCandidates', status: 'implemented', reason: '' },

  { pattern: 'budget.max_files', owner: 'contextSlice (Budget)', status: 'implemented', reason: '' },
  { pattern: 'budget.on_exhaustion', owner: 'runNamedSlice (Budget)', status: 'implemented', reason: 'два значения: "degrade_to_names" (умолчание — узлы за границей бюджета деградируют до строки-имени) и "error" (обход бросает Error со списком неотрисованных узлов вместо частичного вывода)' },
];

/**
 * Превращает шаблон вида "kinds.*.anchors.required" в RegExp, где `*`
 * соответствует одному сегменту без точек.
 * @param {string} pattern
 * @returns {RegExp}
 */
function patternToRegExp(pattern) {
  const escaped = pattern
    .split('.')
    .map((seg) => (seg === '*' ? '[^.]+' : seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    .join('\\.');
  return new RegExp(`^${escaped}$`);
}

/**
 * Рекурсивно перечисляет ЛИСТОВЫЕ дотированные пути значения profile.yaml.
 * Массивы и скаляры — листья (не углубляемся внутрь массива: элементы среза
 * `follow` или список типов evidence — это значение ключа целиком, а не
 * отдельные подключи с собственным владением). Объекты — узлы, продолжаем.
 * @param {*} value
 * @param {string} prefix
 * @returns {string[]}
 */
function leafPaths(value, prefix) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return prefix ? [prefix] : [];
  }
  const out = [];
  for (const [key, val] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    out.push(...leafPaths(val, path));
  }
  return out;
}

/**
 * Сверяет фактические ключи `profile.yaml` с {@link MANIFEST}: каждый
 * присутствующий лист обязан совпасть хотя бы с одним пунктом манифеста.
 * Отсутствие совпадения — E-PROFILE-KEY-UNREGISTERED (профиль обещает то,
 * за что явно никто не расписался — ни implemented, ни not_implemented).
 * Совпадение с пунктом `not_implemented` даёт информационную находку
 * W-PROFILE-KEY-NOT-IMPLEMENTED, чтобы это не осталось тихим фактом кода.
 * @param {Record<string,*>} profile
 * @returns {{ unregistered: string[], notImplemented: Array<{path: string, reason: string}> }}
 */
export function checkProfileKeyOwnership(profile) {
  const paths = leafPaths(profile, '');
  const compiled = MANIFEST.map((e) => ({ ...e, re: patternToRegExp(e.pattern) }));
  const unregistered = [];
  const notImplemented = [];
  const notImplementedSeen = new Set();
  for (const path of paths) {
    const matches = compiled.filter((e) => e.re.test(path));
    if (matches.length === 0) {
      unregistered.push(path);
      continue;
    }
    const impl = matches.find((e) => e.status === 'implemented');
    if (impl) continue;
    // Все совпадения — not_implemented: сообщить один раз на паттерн, не на
    // каждый присутствующий лист (иначе шесть видов дают шесть одинаковых
    // предупреждений про один и тот же необъявленный title).
    for (const m of matches) {
      if (notImplementedSeen.has(m.pattern)) continue;
      notImplementedSeen.add(m.pattern);
      notImplemented.push({ path: m.pattern, reason: m.reason });
    }
  }
  return { unregistered, notImplemented };
}

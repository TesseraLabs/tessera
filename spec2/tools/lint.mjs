// Проверки линта spec2 (см. constitution.md и задание команды). Каждая
// функция check* возвращает список находок; lint(repo) их собирает и сортирует.

import { resolveLink, resolveAnchor, computeObligations } from './graph.mjs';
import { analyzeCoverage, formatCombo, countUndefinedOnlyCoverage } from './combinations.mjs';
import { checkProfileKeyOwnership } from './profile-registry.mjs';
import { decisionCycles, decisionIndex, effectiveDecisionStatus } from './decision.mjs';

/**
 * @typedef {{ path: string, line: number, level: 'ERROR'|'WARN', code: string, message: string }} Finding
 */

/**
 * @param {string} path
 * @param {number} line
 * @param {'ERROR'|'WARN'} level
 * @param {string} code
 * @param {string} message
 * @returns {Finding}
 */
function mk(path, line, level, code, message) {
  return { path, line, level, code, message };
}

/**
 * Ищет номер строки первого совпадения regex в сыром тексте frontmatter файла.
 * @param {import('./parse.mjs').SpecFile} file
 * @param {RegExp} regex
 * @returns {number|null}
 */
function findFrontmatterLine(file, regex) {
  const lines = file.frontmatterText.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) if (regex.test(lines[i])) return file.frontmatterStartLine + i;
  return null;
}

/**
 * Все номера строк frontmatter, совпадающие с regex, по порядку — используется,
 * чтобы сопоставить строки `pattern: X` внутри `applies:` с элементами массива.
 * @param {import('./parse.mjs').SpecFile} file
 * @param {RegExp} regex
 * @returns {number[]}
 */
function findFrontmatterLines(file, regex) {
  const lines = file.frontmatterText.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) if (regex.test(lines[i])) out.push(file.frontmatterStartLine + i);
  return out;
}

/**
 * E-FRONTMATTER — нет frontmatter, не парсится, нет id/kind/context.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkFrontmatter(repo) {
  const out = [];
  for (const file of repo.files) {
    if (file.frontmatterError) {
      out.push(mk(file.path, 1, 'ERROR', 'E-FRONTMATTER', `frontmatter: ${file.frontmatterError}`));
      continue;
    }
    const fm = file.frontmatter;
    const missing = ['id', 'kind', 'context'].filter((k) => !fm || !fm[k]);
    if (missing.length > 0) {
      out.push(mk(file.path, file.frontmatterStartLine, 'ERROR', 'E-FRONTMATTER', `frontmatter не содержит обязательных полей: ${missing.join(', ')}`));
    }
  }
  return out;
}

/**
 * Файл валиден для дальнейших проверок, если у него есть frontmatter с id/kind/context.
 * @param {import('./parse.mjs').SpecFile} file
 * @returns {boolean}
 */
function hasValidFrontmatter(file) {
  return !!(file.frontmatter && file.frontmatter.id && file.frontmatter.kind && file.frontmatter.context);
}

/**
 * E-KIND-UNKNOWN — kind отсутствует в profile.yaml.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkKindUnknown(repo) {
  const out = [];
  const kinds = repo.profile.kinds || {};
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const kind = String(file.frontmatter.kind);
    if (!(kind in kinds)) {
      const line = findFrontmatterLine(file, /^kind:/) ?? file.frontmatterStartLine;
      out.push(mk(file.path, line, 'ERROR', 'E-KIND-UNKNOWN', `kind "${kind}" отсутствует в profile.yaml`));
    }
  }
  return out;
}

/**
 * Значение обязательного поля считается заданным, только если оно несёт
 * данные. Пустая строка/коллекция не должна удовлетворять контракту вида:
 * это создало бы формально зелёную страницу с `consumers: []` или
 * `owner: ""`, то есть ровно без той информации, ради которой существует
 * отдельный kind.
 * @param {*} value
 * @returns {boolean}
 */
function isPresent(value) {
  if (value === undefined || value === null) return false;
  if (typeof value === 'string') return value.trim() !== '';
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}

function valueAtPath(object, dottedPath) {
  return String(dottedPath).split('.').reduce((value, key) => value && value[key], object);
}

/**
 * E-KIND-FIELD-MISSING / E-KIND-SECTION-MISSING — профиль может дать виду
 * собственную проверяемую форму, не добавляя в линтер новый if на каждый
 * предметный профиль. `required_fields` проверяет frontmatter, а
 * `required_sections` — именованные Markdown-разделы. Это минимальный
 * механизм для контрактов границ, конфигураций, интерфейсов и хранилищ:
 * вид существует не как цветная метка, а потому что требует информации,
 * которой другие виды не требуют.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkKindShape(repo) {
  const out = [];
  const kinds = repo.profile.kinds || {};
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const fm = file.frontmatter;
    const kind = String(fm.kind);
    const kindSpec = kinds[kind];
    if (!kindSpec) continue;

    const requiredFields = Array.isArray(kindSpec.required_fields) ? kindSpec.required_fields : [];
    for (const field of requiredFields) {
      if (isPresent(valueAtPath(fm, field))) continue;
      const line = findFrontmatterLine(file, new RegExp(`^${String(field).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:`))
        ?? file.frontmatterStartLine;
      out.push(mk(file.path, line, 'ERROR', 'E-KIND-FIELD-MISSING', `термин "${fm.id}" (kind=${kind}) не содержит непустого обязательного поля frontmatter "${field}"`));
    }

    const requiredSections = Array.isArray(kindSpec.required_sections) ? kindSpec.required_sections : [];
    const presentSections = new Set(file.headings.map((h) => h.text.trim()));
    for (const section of requiredSections) {
      if (presentSections.has(String(section).trim())) continue;
      out.push(mk(file.path, file.bodyStartLine, 'ERROR', 'E-KIND-SECTION-MISSING', `термин "${fm.id}" (kind=${kind}) не содержит обязательного раздела "${section}"`));
    }
  }
  return out;
}

/**
 * E-ID-DUP — id термина (в рамках контекста) или ID требования (глобально)
 * встречается дважды.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkIdDup(repo) {
  const out = [];

  const termSeen = new Map();
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const key = `${file.frontmatter.context} ${file.frontmatter.id}`;
    const line = findFrontmatterLine(file, /^id:/) ?? file.frontmatterStartLine;
    if (!termSeen.has(key)) termSeen.set(key, []);
    termSeen.get(key).push({ path: file.path, line });
  }
  for (const [key, locs] of termSeen) {
    if (locs.length < 2) continue;
    const id = key.split(' ')[1];
    for (const loc of locs) out.push(mk(loc.path, loc.line, 'ERROR', 'E-ID-DUP', `id термина "${id}" встречается дважды`));
  }

  const reqSeen = new Map();
  for (const file of repo.files) {
    for (const req of file.requirements) {
      if (!req.id) continue;
      if (!reqSeen.has(req.id)) reqSeen.set(req.id, []);
      reqSeen.get(req.id).push({ path: file.path, line: req.headingLine });
    }
  }
  for (const [id, locs] of reqSeen) {
    if (locs.length < 2) continue;
    for (const loc of locs) out.push(mk(loc.path, loc.line, 'ERROR', 'E-ID-DUP', `ID требования "${id}" встречается дважды`));
  }

  return out;
}

/**
 * E-LINK-UNRESOLVED / E-LINK-KIND / E-LINK-CROSS-CONTEXT.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkLinks(repo) {
  const out = [];
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const context = String(file.frontmatter.context);
    for (const link of [...file.links, ...(file.navigationLinks || [])]) {
      const res = resolveLink(link, context, repo);
      if (res.unresolved) {
        out.push(mk(file.path, link.line, 'ERROR', 'E-LINK-UNRESOLVED', `ссылка на "${link.ref}" не разрешается`));
        continue;
      }
      if (res.crossContext) {
        out.push(mk(file.path, link.line, 'ERROR', 'E-LINK-CROSS-CONTEXT', `ссылка на "${link.ref}" ведёт в другой контекст без квалификации "${res.target.context}.${res.target.id}"`));
      }
    }
  }
  return out;
}

function checkRelationTypes(repo) {
  const out = [];
  const definitions = repo.profile.relation_types || {};
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const relations = file.frontmatter.relations;
    if (relations === undefined) continue;
    if (!relations || typeof relations !== 'object' || Array.isArray(relations)) {
      out.push(mk(file.path, findFrontmatterLine(file, /^relations:/) ?? file.frontmatterStartLine, 'ERROR', 'E-RELATIONS-SHAPE', 'relations должен быть объектом relation → qualified id или список id'));
      continue;
    }
    for (const [name, rawTargets] of Object.entries(relations)) {
      const line = findFrontmatterLine(file, new RegExp(`^\\s*${String(name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:`)) ?? file.frontmatterStartLine;
      const definition = definitions[name];
      if (!definition) {
        out.push(mk(file.path, line, 'ERROR', 'E-RELATION-UNKNOWN', `тип отношения "${name}" не объявлен в profile.yaml relation_types`));
        continue;
      }
      if (definition.cardinality === 'one' && Array.isArray(rawTargets)) {
        out.push(mk(file.path, line, 'ERROR', 'E-RELATION-CARDINALITY', `relation "${name}" имеет cardinality=one и должна быть scalar id`));
      }
      if (definition.cardinality === 'many' && !Array.isArray(rawTargets)) {
        out.push(mk(file.path, line, 'ERROR', 'E-RELATION-CARDINALITY', `relation "${name}" имеет cardinality=many и должна быть списком id`));
      }
      const values = Array.isArray(rawTargets) ? rawTargets : [rawTargets];
      for (const value of values) {
        if (typeof value !== 'string' || value.trim() === '') {
          out.push(mk(file.path, line, 'ERROR', 'E-RELATION-TARGET', `relation "${name}" содержит нестроковую или пустую цель: ${JSON.stringify(value)}`));
        }
      }
      if (Array.isArray(definition.sources) && !definition.sources.includes(file.frontmatter.kind)) {
        out.push(mk(file.path, line, 'ERROR', 'E-RELATION-SOURCE-KIND', `relation "${name}" нельзя объявлять из kind=${file.frontmatter.kind}; разрешены [${definition.sources.join(', ')}]`));
      }
      if (Array.isArray(definition.targets)) {
        for (const link of file.links.filter((candidate) => candidate.relation === name)) {
          const resolved = resolveLink(link, String(file.frontmatter.context), repo);
          if (resolved.target && !definition.targets.includes(resolved.target.kind)) {
            out.push(mk(file.path, line, 'ERROR', 'E-RELATION-TARGET-KIND', `relation "${name}" не может вести в kind=${resolved.target.kind}; разрешены [${definition.targets.join(', ')}]`));
          }
        }
      }
    }
  }
  return out;
}

/**
 * Процесс без причинного входа или выхода обычно является обычной статьёй,
 * которую нельзя встроить в flow. Это предупреждение, а не ошибка: внешний
 * trigger может быть ещё не описан, но такая неполнота должна быть видна автору.
 */
function checkCausalCompleteness(repo) {
  const incoming = new Set();
  const outgoing = new Set();
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const sourceKey = `${file.frontmatter.context}.${file.frontmatter.id}`;
    for (const link of file.links) {
      const definition = repo.profile.relation_types?.[link.relation];
      if (definition?.flow !== 'forward' && definition?.flow !== 'reverse') continue;
      const resolved = resolveLink(link, String(file.frontmatter.context), repo);
      if (!resolved.target) continue;
      const targetKey = `${resolved.target.context}.${resolved.target.id}`;
      const from = definition.flow === 'forward' ? sourceKey : targetKey;
      const to = definition.flow === 'forward' ? targetKey : sourceKey;
      outgoing.add(from);
      incoming.add(to);
    }
  }

  const out = [];
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file) || file.frontmatter.kind !== 'процесс') continue;
    const key = `${file.frontmatter.context}.${file.frontmatter.id}`;
    const line = findFrontmatterLine(file, /^relations:/) ?? file.frontmatterStartLine;
    if (!incoming.has(key)) {
      out.push(mk(file.path, line, 'WARN', 'W-PROCESS-NO-TRIGGER', `процесс "${key}" не имеет причинного входа (starts/triggered_by или другой relation с flow)`));
    }
    if (!outgoing.has(key)) {
      out.push(mk(file.path, line, 'WARN', 'W-PROCESS-NO-NEXT', `процесс "${key}" не имеет причинного выхода (invokes/emits или другой relation с flow)`));
    }
  }
  return out;
}

/**
 * E-LINK-NOT-ALLOWED — реализация `kinds.<вид>.links.may_reference`
 * (REVIEW.md C2): relation, разрешённая по контексту,
 * может ссылаться на терм, чей вид не входит в список легальных связей ИЗ
 * вида файла-источника. Раньше это ключевое обещание профиля не читалось
 * НИГДЕ (0 вхождений в коде): ссылка `политика → паттерн`, запрещённая
 * профилем, проходила молча.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkLinkMayReference(repo) {
  const out = [];
  const kinds = repo.profile.kinds || {};
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const context = String(file.frontmatter.context);
    const sourceKind = String(file.frontmatter.kind);
    const kindSpec = kinds[sourceKind];
    if (!kindSpec || !kindSpec.links || !Array.isArray(kindSpec.links.may_reference)) continue;
    const mayReference = new Set(kindSpec.links.may_reference);
    for (const link of file.links) {
      const res = resolveLink(link, context, repo);
      if (res.unresolved || res.kindMismatch || !res.target) continue; // отдельные находки E-LINK-*
      if (res.target.id === file.frontmatter.id && res.target.context === context) continue; // ссылка на себя не связь между видами
      if (mayReference.has(res.target.kind)) continue;
      out.push(mk(file.path, link.line, 'ERROR', 'E-LINK-NOT-ALLOWED', `relation на "${link.ref}": вид "${sourceKind}" не вправе ссылаться на вид "${res.target.kind}" — нет в kinds.${sourceKind}.links.may_reference profile.yaml`));
    }
  }
  return out;
}

/**
 * E-RU-OPERATOR — запрещённые русские операторы и SHOULD.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkRuOperators(repo) {
  const out = [];
  for (const file of repo.files) {
    for (const occ of file.ruOperators) {
      out.push(mk(file.path, occ.line, 'ERROR', 'E-RU-OPERATOR', `запрещённый оператор "${occ.match}" — используйте MUST/MUST NOT/MAY`));
    }
  }
  return out;
}

// Норма паттерна параметризована по применяющей стороне (конституция §6):
// конкретного субъекта у неё по построению нет, поэтому типизированная
// ссылка не требуется — вместо неё обязателен фиксированный оборот в начале
// предложения.
// \b не годится: JS не считает кириллицу "словесными" символами (тот же
// нюанс, что у RU_OPERATOR_RE в markdown.mjs), поэтому граница проверяется
// явно — оборот должен либо заканчивать предложение, либо продолжаться
// не-буквой (пробелом перед сказуемым).
const APPLIER_PHRASE_RE = /^\s*Применяющая сторона(?![A-Za-zА-Яа-яЁё])/;

/**
 * E-NORM-NO-SUBJECT / E-PATTERN-NORM-NO-APPLIER / W-NORM-COORDINATION.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkNormSentences(repo) {
  const out = [];
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const isPattern = file.frontmatter.kind === repo.patternKind;
    for (const req of file.requirements) {
      if (!Array.isArray(req.subjects) || req.subjects.length === 0) {
        out.push(mk(file.path, req.headingLine, 'ERROR', 'E-NORM-NO-SUBJECT', `у требования ${req.id} во frontmatter не задан subjects`));
        continue;
      }
      const norms = file.norms.filter((sentence) => sentence.startLine >= req.sectionStart && sentence.startLine < req.sectionEnd);
      if (norms.length === 0) {
        out.push(mk(file.path, req.headingLine, 'ERROR', 'E-REQ-NO-NORM', `требование ${req.id} не содержит ни одного нормативного предложения с MUST/MUST NOT/MAY`));
      }
      for (const subject of req.subjects) {
        if (subject === 'application' && isPattern) continue;
        const resolution = resolveLink({ ref: subject }, String(file.frontmatter.context), repo);
        if (!resolution.target) {
          out.push(mk(file.path, req.headingLine, 'ERROR', 'E-SUBJECT-UNRESOLVED', `subjects требования ${req.id} содержит неразрешимый id "${subject}"`));
          continue;
        }
        const appears = file.navigationLinks?.some((link) => link.ref === subject && link.line >= req.sectionStart && link.line < req.sectionEnd);
        if (!appears) {
          out.push(mk(file.path, req.headingLine, 'ERROR', 'E-SUBJECT-NOT-IN-PROSE', `subject "${subject}" требования ${req.id} не встречается ссылкой в его Markdown-теле`));
        }
      }
    }
    for (const sentence of file.norms) {
      const req = file.requirements.find((candidate) => sentence.startLine >= candidate.sectionStart && sentence.startLine < candidate.sectionEnd);
      if (!req) {
        out.push(mk(file.path, sentence.startLine, 'ERROR', 'E-NORM-OUTSIDE-REQ', 'нормативное предложение находится вне Markdown-раздела требования, объявленного во frontmatter'));
        continue;
      }
      const hasApplier = isPattern && APPLIER_PHRASE_RE.test(sentence.sentenceText);
      for (const operator of sentence.operators) {
        if (isPattern && req.subjects.includes('application')) {
          if (!hasApplier) out.push(mk(file.path, operator.line, 'ERROR', 'E-PATTERN-NORM-NO-APPLIER', `норма паттерна ${req.id} с subject=application должна начинаться оборотом "Применяющая сторона"`));
          continue;
        }
        if (!operator.precedingLink) {
          out.push(mk(file.path, operator.line, 'ERROR', 'E-NORM-NO-SUBJECT', `перед оператором "${operator.op}" нет ссылки на subject требования ${req.id}`));
        } else if (!req.subjects.includes(operator.precedingLink.ref)) {
          out.push(mk(file.path, operator.line, 'ERROR', 'E-NORM-SUBJECT-MISMATCH', `субъект предложения "${operator.precedingLink.ref}" отсутствует в requirements.${req.id}.subjects`));
        }
      }
      if (sentence.hasCoordination) {
        out.push(mk(file.path, sentence.startLine, 'WARN', 'W-NORM-COORDINATION', 'в предложении с оператором есть союз "и"/"либо" — вероятны две нормы в одной'));
      }
    }
  }
  return out;
}

/**
 * E-REQ-ID-MISSING — запись requirements.<ID> без Markdown-заголовка `ID — название`.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkReqIdMissing(repo) {
  const out = [];
  for (const file of repo.files) {
    for (const req of file.requirements) {
      if (req.missingHeading) {
        out.push(mk(file.path, req.headingLine, 'ERROR', 'E-REQ-ID-MISSING', `для требования ${req.id} из frontmatter нет Markdown-заголовка "${req.id} — название"`));
      }
    }
  }
  return out;
}

/**
 * E-REQ-KIND — kind= требования отсутствует в norm_kinds профиля (или не задан).
 * Проверяется для требований предметной страницы; обязательства паттерна имеют
 * собственный evidence-контракт через conformance применения.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkReqKind(repo) {
  const out = [];
  const normKinds = repo.profile.norm_kinds || {};
  for (const file of repo.files) {
    for (const req of file.requirements) {
      if (req.missingId || !req.isCanonical) continue;
      if (!req.kindAttr || !(req.kindAttr in normKinds)) {
        const reason = req.kindAttr ? `kind "${req.kindAttr}" отсутствует в norm_kinds профиля` : 'kind= не указан';
        out.push(mk(file.path, req.headingLine, 'ERROR', 'E-REQ-KIND', `требование ${req.id}: ${reason}`));
      }
    }
  }
  return out;
}

/**
 * E-REQ-PREFIX — префикс ID канонического требования не объявлен у контекста
 * файла. Обязательства паттернов (не-канонические заголовки) — отдельная
 * ID-схема самого паттерна, к контекстным префиксам не привязана.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkReqPrefix(repo) {
  const out = [];
  const contexts = repo.profile.contexts || {};
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const ctxDef = contexts[file.frontmatter.context];
    const allowedPrefixes = ctxDef && Array.isArray(ctxDef.prefix) ? ctxDef.prefix : [];
    for (const req of file.requirements) {
      if (req.missingId || !req.isCanonical || !req.id) continue;
      const prefix = req.id.split('-')[0];
      if (!allowedPrefixes.includes(prefix)) {
        out.push(mk(file.path, req.headingLine, 'ERROR', 'E-REQ-PREFIX', `префикс "${prefix}" требования ${req.id} не объявлен у контекста "${file.frontmatter.context}" в profile.yaml`));
      }
    }
  }
  return out;
}

/** Requirement-level provenance: `decided_by` ведёт только на qualified ADR. */
function checkRequirementDecisions(repo) {
  const out = [];
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    for (const req of file.requirements) {
      if ((req.unparsedDecidedBy || []).length > 0) {
        out.push(mk(file.path, req.headingLine, 'ERROR', 'E-DECIDED-BY-SHAPE', `требование ${req.id}: decided_by должен быть списком строк context.ADR-id`));
      }
      for (const ref of req.decidedBy || []) {
        if (!/^[^.]+\.[^.]+$/.test(ref)) {
          out.push(mk(file.path, req.headingLine, 'ERROR', 'E-DECIDED-BY-QUALIFIED', `требование ${req.id}: решение "${ref}" должно быть квалифицировано как context.id`));
          continue;
        }
        const resolution = resolveLink({ ref }, String(file.frontmatter.context), repo);
        if (!resolution.target) {
          out.push(mk(file.path, req.headingLine, 'ERROR', 'E-DECIDED-BY-UNRESOLVED', `требование ${req.id}: решение "${ref}" не найдено`));
        } else if (resolution.target.kind !== repo.decisionKind) {
          out.push(mk(file.path, req.headingLine, 'ERROR', 'E-DECIDED-BY-KIND', `требование ${req.id}: decided_by ведёт в kind=${resolution.target.kind}, ожидалось ${repo.decisionKind}`));
        }
      }
    }
  }
  return out;
}

/**
 * E-EVIDENCE-MISSING — у канонического требования нет обязательного для его
 * kind evidence.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkEvidenceMissing(repo) {
  const out = [];
  const normKinds = repo.profile.norm_kinds || {};
  for (const file of repo.files) {
    for (const req of file.requirements) {
      if (req.missingId || !req.isCanonical || !req.kindAttr) continue;
      const spec = normKinds[req.kindAttr];
      if (!spec || !Array.isArray(spec.evidence) || spec.evidence.length === 0) continue;
      const presentTypes = new Set(req.evidenceAnchors.map((a) => a.type));
      // any_of:true — достаточно одного из перечисленных типов (напр.
      // "контракт": evidence из schema ИЛИ test). Без any_of профиль
      // объявляет "нужны ВСЕ" — по умолчанию код читал это как "любой из"
      // независимо от флага (REVIEW.md P1); безвредно, пока ни один тип
      // нормы не объявляет несколько evidence без any_of, но флаг обязан
      // что-то значить сам по себе.
      const satisfied = spec.any_of
        ? spec.evidence.some((t) => presentTypes.has(t))
        : spec.evidence.every((t) => presentTypes.has(t));
      if (!satisfied) {
        const need = spec.any_of ? `нужен один из [${spec.evidence.join(', ')}]` : `нужны ВСЕ из [${spec.evidence.join(', ')}]`;
        out.push(mk(file.path, req.headingLine, 'ERROR', 'E-EVIDENCE-MISSING', `требование ${req.id} (kind=${req.kindAttr}) без обязательного evidence: ${need}`));
      }
    }
  }
  return out;
}

/**
 * E-ANCHOR-BROKEN — якорь не разрешается: файл не найден либо символ/ID не
 * встречается в файле.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkAnchors(repo) {
  const out = [];
  for (const file of repo.files) {
    /** @type {Array<{anchor: import('./parse.mjs').Anchor, line: number}>} */
    const all = [];
    for (const a of file.frontmatterAnchors) all.push({ anchor: a, line: findFrontmatterLine(file, new RegExp(`${a.type}:`)) ?? file.frontmatterStartLine });
    for (const req of file.requirements) for (const a of req.evidenceAnchors) all.push({ anchor: a, line: req.headingLine });
    for (const c of file.conformance) for (const a of c.anchors) all.push({ anchor: a, line: c.line });
    for (const { anchor, line } of all) {
      const res = resolveAnchor(anchor, repo.productRoot);
      if (!res.ok) {
        out.push(mk(file.path, line, 'ERROR', 'E-ANCHOR-BROKEN', `якорь ${anchor.type}:${anchor.target} не разрешается: ${res.reason}`));
      }
    }
  }
  return out;
}

/**
 * W-SOURCE-UNREADABLE — директория или симлинк внутри `sources:`, которые
 * обход не смог прочитать (REVIEW.md M5). Раньше `findSpecFiles` глотал такие
 * случаи молча (`try { … } catch { return; }`), и целое поддерево спек
 * пропадало из линта без единого следа — "нарушений нет" по всему поддереву
 * неотличимо от "нарушений в нём никто не искал".
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkSourceWarnings(repo) {
  return repo.sourceWarnings.map((w) => mk(w.path, 1, 'WARN', 'W-SOURCE-UNREADABLE', `обход source-директории прерван: ${w.reason} — часть спек могла остаться непроверенной`));
}

/**
 * E-ANCHOR-UNPARSED — элемент frontmatter `anchors:`, не разобранный ни одной
 * известной формой якоря (REVIEW.md M4): опечатка в типе (`cod:` вместо
 * `code:`) или якорь без двоеточия раньше пропадал из `frontmatterAnchors`
 * молча — не было ни E-ANCHOR-BROKEN, ни отдельной находки, автор терял якорь
 * без единого сигнала об этом.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkUnparsedAnchors(repo) {
  const out = [];
  for (const file of repo.files) {
    if (file.unparsedFrontmatterAnchors.length === 0) continue;
    const line = findFrontmatterLine(file, /^anchors:/) ?? file.frontmatterStartLine;
    for (const raw of file.unparsedFrontmatterAnchors) {
      out.push(mk(file.path, line, 'ERROR', 'E-ANCHOR-UNPARSED', `элемент anchors: не разобран как якорь известного типа (code/test/schema/exemplar/counterexample/type): ${JSON.stringify(raw)}`));
    }
  }
  return out;
}

/**
 * Проверяет, объявлена ли у термина причина отсутствия обязательного якоря
 * данного типа. Две формы, обе непустые: новая `no_anchor: { <тип>: <причина> }`
 * (любой обязательный для вида тип якоря) и устаревшая `no_type_anchor: <причина>`
 * (только для `type`, принимается как синоним `no_anchor: { type: <причина> }`).
 * "У этого нет кода" — тоже утверждение о домене, поэтому пустая причина не
 * считается объявленной: `attempted` отличает "поле есть, но пусто" от "поля
 * нет вовсе" — сообщения об этих случаях разные.
 * @param {Record<string,*>} fm
 * @param {string} type
 * @returns {{ ok: boolean, legacy: boolean, attempted: boolean }}
 */
function anchorEscapeReason(fm, type) {
  const stated = fm.no_anchor && typeof fm.no_anchor === 'object' && !Array.isArray(fm.no_anchor)
    ? fm.no_anchor[type]
    : undefined;
  if (typeof stated === 'string' && stated.trim() !== '') return { ok: true, legacy: false, attempted: true };
  const legacyStated = type === 'type' ? fm.no_type_anchor : undefined;
  if (typeof legacyStated === 'string' && legacyStated.trim() !== '') return { ok: true, legacy: true, attempted: true };
  return { ok: false, legacy: false, attempted: stated !== undefined || legacyStated !== undefined };
}

/**
 * W-ENTITY-NO-TYPE-ANCHOR / E-KIND-ANCHOR-MISSING / W-KIND-ANCHOR-TYPE-UNLISTED /
 * W-NO-TYPE-ANCHOR-LEGACY / E-ANCHOR-UNPARSED —
 * реализация `kinds.<вид>.anchors.required` и `kinds.<вид>.anchors.optional`
 * ЦЕЛИКОМ, а не только ради значения `type` (REVIEW.md C2): раньше
 * `операция: anchors.required: [code, test]`, `паттерн: [exemplar]`,
 * `событие: [test]`, `политика: [test]` не проверялись ничем — файл вида
 * "операция" вовсе без секции `anchors:` проходил линт молча.
 *
 * `type` сохраняет свою историческую особую трактовку (WARN, не ERROR) —
 * не у каждой сущности домена есть тип в коде, и придумывать для неё ложную
 * привязку хуже, чем явно сказать, что типа нет, и почему. Escape-хетч
 * `no_anchor: { <тип>: <причина> }` (см. {@link anchorEscapeReason}) теперь
 * снимает находку для ЛЮБОГО обязательного типа якоря, не только `type`:
 * сущность-актор вида "оператор устройства" — человек, у неё по построению
 * нет ни `type:`, ни `code:`-якоря, и оба отсутствия законны, если названа
 * причина — «у этого нет кода» тоже утверждение о домене, и его стоит
 * произнести, а не молчать. Для типов якоря вне `type` находка при
 * незакрытом требовании остаётся ERROR: профиль не считает их отсутствие
 * рутинным, как отсутствие типа у человека.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkKindAnchors(repo) {
  const out = [];
  const kinds = repo.profile.kinds || {};
  for (const file of repo.files) {
    const fm = file.frontmatter;
    if (!fm || !fm.kind) continue;
    const kindSpec = kinds[fm.kind];
    const anchorsSpec = kindSpec && kindSpec.anchors;
    if (!anchorsSpec) continue;
    const required = Array.isArray(anchorsSpec.required) ? anchorsSpec.required : [];
    const optional = Array.isArray(anchorsSpec.optional) ? anchorsSpec.optional : [];
    if (required.length === 0 && optional.length === 0) continue;

    const anchors = [
      ...file.frontmatterAnchors,
      ...file.requirements.flatMap((r) => r.evidenceAnchors),
      ...file.conformance.flatMap((c) => c.anchors),
    ];
    const presentTypes = new Set(anchors.map((a) => a.type));

    for (const reqType of required) {
      if (presentTypes.has(reqType)) continue;
      const esc = anchorEscapeReason(fm, reqType);
      if (esc.legacy) {
        out.push(mk(file.path, file.frontmatterStartLine, 'WARN', 'W-NO-TYPE-ANCHOR-LEGACY', `термин "${fm.id}" использует устаревшее поле no_type_anchor — перейдите на "no_anchor: { type: <причина> }"`));
      }
      if (esc.ok) continue;
      if (reqType === 'type') {
        const reason = esc.attempted
          ? 'причина пуста — "у этого нет типа" тоже утверждение о домене'
          : 'нет ни якоря type:, ни поля no_anchor.type (или устаревшего no_type_anchor) с причиной';
        out.push(mk(file.path, file.frontmatterStartLine, 'WARN', 'W-ENTITY-NO-TYPE-ANCHOR', `термин "${fm.id}" (kind=${fm.kind}) без обязательного якоря type: — ${reason}`));
        continue;
      }
      // Обобщение частного escape-хетча no_type_anchor (REVIEW.md, п.1
      // задания второй фазы): сущность-актор вида "оператор устройства" —
      // человек, у неё нет ни type:, ни code:-якоря, и оба отсутствия
      // законны, если названа причина. "no_anchor: { code: <причина> }"
      // работает для ЛЮБОГО обязательного для вида типа якоря, не только type.
      const reason = esc.attempted
        ? `причина пуста в no_anchor.${reqType} — "у этого нет ${reqType}" тоже утверждение о домене`
        : `profile.yaml требует kinds.${fm.kind}.anchors.required: [${required.join(', ')}]; отсутствие можно объявить как "no_anchor: { ${reqType}: <причина> }"`;
      out.push(mk(file.path, file.frontmatterStartLine, 'ERROR', 'E-KIND-ANCHOR-MISSING', `термин "${fm.id}" (kind=${fm.kind}) без обязательного якоря ${reqType}: — ${reason}`));
    }

    const allowed = new Set([...required, ...optional]);
    if (allowed.size === 0) continue;
    const unlisted = [...presentTypes].filter((t) => !allowed.has(t));
    for (const t of unlisted) {
      out.push(mk(file.path, file.frontmatterStartLine, 'WARN', 'W-KIND-ANCHOR-TYPE-UNLISTED', `термин "${fm.id}" (kind=${fm.kind}) использует якорь типа "${t}", не входящий ни в anchors.required, ни в anchors.optional вида в profile.yaml`));
    }
  }
  return out;
}

/**
 * E-PATTERN-UNKNOWN / E-PATTERN-TARGET / E-PATTERN-BINDING-LITERAL /
 * W-PATTERN-COUNT.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkPatternApplication(repo) {
  const out = [];
  if (!repo.patternKind) return out;

  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const applies = Array.isArray(file.frontmatter.applies) ? file.frontmatter.applies : [];
    if (applies.length === 0) continue;
    const patternLines = findFrontmatterLines(file, /^-?\s*pattern:/);

    if (applies.length > 3) {
      const line = patternLines[0] ?? file.frontmatterStartLine;
      out.push(mk(file.path, line, 'WARN', 'W-PATTERN-COUNT', `термин применяет ${applies.length} паттернов — больше трёх на один термин`));
    }

    for (let i = 0; i < applies.length; i++) {
      const app = applies[i];
      const line = patternLines[i] ?? file.frontmatterStartLine;
      // Элемент applies: не объект вида {pattern: ...} —
      // правдоподобная опечатка автора (список имён вместо списка объектов:
      // "- fail-closed" вместо "- pattern: fail-closed"). Раньше это молча
      // пропускалось: паттерн не применялся, обязательства не вычислялись,
      // и никакой находки не было (REVIEW.md H2).
      if (!app || typeof app !== 'object' || Array.isArray(app) || typeof app.pattern !== 'string' || app.pattern.trim() === '') {
        out.push(mk(file.path, line, 'ERROR', 'E-PATTERN-MALFORMED', `элемент applies: не является объектом вида "{pattern: <имя>}": ${JSON.stringify(app)}`));
        continue;
      }

      const reg = repo.patternRegistry.get(app.pattern);
      if (!reg) {
        out.push(mk(file.path, line, 'ERROR', 'E-PATTERN-UNKNOWN', `паттерн "${app.pattern}" не существует`));
      } else {
        // frontmatter файла паттерна переопределяет profile.yaml (частный
        // случай важнее общего); если в frontmatter поля нет — умолчание
        // берётся из kinds.<вид-паттерна>.applicable_to профиля. Раньше
        // профильное значение не читалось вовсе, и каждый файл паттерна
        // был обязан повторять список у себя (REVIEW.md P4).
        const profileDefault = repo.profile.kinds && repo.profile.kinds[reg.entity.kind] && Array.isArray(repo.profile.kinds[reg.entity.kind].applicable_to)
          ? repo.profile.kinds[reg.entity.kind].applicable_to
          : [];
        const applicableTo = Array.isArray(reg.entity.file.frontmatter.applicable_to) ? reg.entity.file.frontmatter.applicable_to : profileDefault;
        if (!applicableTo.includes(file.frontmatter.kind)) {
          out.push(mk(file.path, line, 'ERROR', 'E-PATTERN-TARGET', `вид термина "${file.frontmatter.kind}" отсутствует в applicable_to паттерна "${app.pattern}"`));
        }
      }

      if (app.bindings && typeof app.bindings === 'object') {
        for (const [bindingKey, bindingVal] of Object.entries(app.bindings)) {
          if (typeof bindingVal !== 'string' || !/^[^.]+\.[^.]+$/.test(bindingVal.trim())) {
            out.push(mk(file.path, line, 'ERROR', 'E-PATTERN-BINDING-LITERAL', `binding "${bindingKey}" паттерна "${app.pattern}" — не квалифицированный id context.term`));
          }
        }
      }
    }
  }
  return out;
}

/**
 * E-PATTERN-OBLIGATION-NO-EVIDENCE — у вычисленного обязательства применённого
 * паттерна нет evidence в секции Conformance файла термина.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkObligationEvidence(repo) {
  const out = [];
  for (const entity of repo.entities) {
    const obligations = computeObligations(entity, repo);
    for (const ob of obligations) {
      if (!ob.hasEvidence) {
        const line = entity.file.headings.find((h) => h.text.trim() === 'Conformance')?.line ?? entity.file.bodyStartLine;
        out.push(mk(entity.file.path, line, 'ERROR', 'E-PATTERN-OBLIGATION-NO-EVIDENCE', `нет evidence для обязательства ${ob.id}`));
      }
    }
  }
  return out;
}

/**
 * E-DECISION-NO-ALTERNATIVE — файл вида, чей `kinds.<вид>.must` включает
 * "rejected_alternative", без непустой секции "## Отвергнутые альтернативы".
 * Раньше проверка была захардкожена на `repo.decisionKind` (определяется
 * через `append_only`, отдельный ключ) вместо чтения `must` — вид с этим
 * требованием, но без `append_only`, был бы не покрыт (REVIEW.md C2).
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkDecisionAlternative(repo) {
  const out = [];
  const kinds = repo.profile.kinds || {};
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const kindSpec = kinds[String(file.frontmatter.kind)];
    if (!kindSpec || !Array.isArray(kindSpec.must) || !kindSpec.must.includes('rejected_alternative')) continue;
    const idx = file.headings.findIndex((h) => h.text.trim() === 'Отвергнутые альтернативы');
    if (idx === -1) {
      out.push(mk(file.path, file.bodyStartLine, 'ERROR', 'E-DECISION-NO-ALTERNATIVE', 'нет секции "## Отвергнутые альтернативы"'));
      continue;
    }
    const heading = file.headings[idx];
    const nextHeading = file.headings.slice(idx + 1).find((h) => h.level <= heading.level);
    const endLine = nextHeading ? nextHeading.line : file.bodyStartLine + file.bodyLines.length;
    const bodyText = file.bodyLines
      .slice(heading.line - file.bodyStartLine + 1, endLine - file.bodyStartLine)
      .join('\n')
      .trim();
    if (bodyText === '') {
      out.push(mk(file.path, heading.line, 'ERROR', 'E-DECISION-NO-ALTERNATIVE', 'секция "## Отвергнутые альтернативы" пуста'));
    }
  }
  return out;
}

function checkLifecycle(repo) {
  const out = [];
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const lifecycle = repo.profile.kinds?.[file.frontmatter.kind]?.lifecycle;
    if (!Array.isArray(lifecycle)) continue;
    const status = file.frontmatter.status;
    if (typeof status !== 'string' || !lifecycle.includes(status)) {
      out.push(mk(file.path, findFrontmatterLine(file, /^status:/) ?? file.frontmatterStartLine, 'ERROR', 'E-LIFECYCLE-STATUS', `status должен быть одним из [${lifecycle.join(', ')}], получено ${JSON.stringify(status)}`));
    }
  }
  return out;
}

function checkDecisionGraph(repo) {
  if (!repo.decisionKind) return [];
  const out = [];
  const index = decisionIndex(repo);
  for (const record of index.values()) {
    const line = record.entity.file.frontmatterStartLine;
    const replaces = new Set(record.replaces);
    const revokes = new Set(record.revokes);
    if (replaces.has(record.id) || revokes.has(record.id)) {
      out.push(mk(record.entity.path, line, 'ERROR', 'E-DECISION-SELF', `решение "${record.id}" не может заменять или отменять само себя`));
    }
    for (const target of replaces) {
      if (revokes.has(target)) out.push(mk(record.entity.path, line, 'ERROR', 'E-DECISION-RELATION-CONFLICT', `решение "${record.id}" одновременно replaces и revokes "${target}"`));
    }
    const acceptedIncoming = record.incoming.filter((edge) => index.get(edge.source)?.declaredStatus === 'принято');
    if (acceptedIncoming.length > 1) {
      out.push(mk(record.entity.path, line, 'WARN', 'W-DECISION-MULTIPLE-SUCCESSORS', `решение "${record.id}" имеет несколько принятых successors: ${acceptedIncoming.map((edge) => edge.source).join(', ')}`));
    }
  }
  for (const cycle of decisionCycles(index)) {
    for (const id of new Set(cycle.slice(0, -1))) {
      const record = index.get(id);
      if (record) out.push(mk(record.entity.path, record.entity.file.frontmatterStartLine, 'ERROR', 'E-DECISION-CYCLE', `цикл решений: ${cycle.join(' -> ')}`));
    }
  }

  for (const file of repo.files) {
    const context = String(file.frontmatter?.context || '');
    for (const req of file.requirements) {
      for (const ref of req.decidedBy || []) {
        const target = resolveLink({ ref }, context, repo).target;
        if (!target || target.kind !== repo.decisionKind) continue;
        const record = index.get(`${target.context}.${target.id}`);
        if (record && ['заменено', 'отменено'].includes(effectiveDecisionStatus(record, index))) {
          out.push(mk(file.path, req.headingLine, 'WARN', 'W-REQ-SUPERSEDED-DECISION', `требование ${req.id} всё ещё decided_by ${record.id}, чей эффективный статус — ${effectiveDecisionStatus(record, index)}`));
        }
      }
    }
  }
  return out;
}

/**
 * E-EVENT-NO-PRODUCER — файл вида, чей `kinds.<вид>.must` включает
 * "producer", на который никто не ссылается: событие обязано иметь
 * источник — норму или операцию, которая его порождает (profile.yaml,
 * комментарий у `kinds.событие`). Операционально это входящая ссылка от
 * ЧУЖОГО термина/нормы — сам термин на себя сослаться источником быть
 * не может. Раньше `must: [producer]` не читался нигде (REVIEW.md C2).
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkKindMustProducer(repo) {
  const out = [];
  const kinds = repo.profile.kinds || {};
  const kindsRequiringProducer = new Set(
    Object.keys(kinds).filter((k) => kinds[k] && Array.isArray(kinds[k].must) && kinds[k].must.includes('producer')),
  );
  if (kindsRequiringProducer.size === 0) return out;

  for (const e of repo.entities) {
    if (!kindsRequiringProducer.has(e.kind)) continue;
    if (!isPresent(e.file.frontmatter.relations?.producer)) {
      out.push(mk(e.file.path, e.file.frontmatterStartLine, 'ERROR', 'E-EVENT-NO-PRODUCER', `термин "${e.id}" (kind=${e.kind}) не содержит relations.producer`));
    }
  }
  return out;
}

/**
 * W-DECISION-ORPHAN — на решение никто не ссылается.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkDecisionOrphan(repo) {
  const out = [];
  if (!repo.decisionKind) return out;
  // Ключ — контекст+id, не голый id (REVIEW.md M11): решение "ADR-1" в
  // контексте auth не считалось orphan-ом только потому, что термин "ADR-1"
  // существовал в другом контексте и на НЕГО была ссылка — уникальность id
  // гарантирована только парой контекст+id (см. checkIdDup), а множество
  // ключевалось голым id.
  const referenced = new Set();
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const context = String(file.frontmatter.context);
    for (const link of file.links) {
      const res = resolveLink(link, context, repo);
      if (res.target && res.target.kind === repo.decisionKind) referenced.add(`${res.target.context} ${res.target.id}`);
    }
    for (const req of file.requirements) {
      for (const ref of req.decidedBy || []) {
        const res = resolveLink({ ref }, context, repo);
        if (res.target?.kind === repo.decisionKind) referenced.add(`${res.target.context} ${res.target.id}`);
      }
    }
  }
  for (const e of repo.entities) {
    if (e.kind !== repo.decisionKind) continue;
    if (!referenced.has(`${e.context} ${e.id}`)) {
      out.push(mk(e.file.path, e.file.frontmatterStartLine, 'WARN', 'W-DECISION-ORPHAN', `на решение "${e.id}" никто не ссылается`));
    }
  }
  return out;
}

/**
 * W-TERM-ORPHAN — у термина нет ни входящих, ни исходящих ссылок.
 * Термины и решения не считаются: у решения своя проверка (W-DECISION-ORPHAN),
 * а паттерны предполагаются переиспользуемыми без обратных ссылок в себе.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkTermOrphan(repo) {
  const out = [];
  // Ключ — контекст+id (REVIEW.md M11, тот же класс, что и W-DECISION-ORPHAN
  // выше): голый id глушил находку, если однофамилец из ЧУЖОГО контекста
  // имел исходящую/входящую ссылку.
  const incoming = new Set();
  const outgoing = new Set();
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const context = String(file.frontmatter.context);
    for (const link of file.links) {
      const res = resolveLink(link, context, repo);
      if (!res.target) continue;
      outgoing.add(`${context} ${file.frontmatter.id}`);
      incoming.add(`${res.target.context} ${res.target.id}`);
    }
  }
  for (const e of repo.entities) {
    if (repo.decisionKind && e.kind === repo.decisionKind) continue;
    if (repo.patternKind && e.kind === repo.patternKind) continue;
    const key = `${e.context} ${e.id}`;
    if (!incoming.has(key) && !outgoing.has(key)) {
      out.push(mk(e.file.path, e.file.frontmatterStartLine, 'WARN', 'W-TERM-ORPHAN', `у термина "${e.id}" нет ни входящих, ни исходящих ссылок`));
    }
  }
  return out;
}

/**
 * Заголовки уровня 4 "#### Scenario: ..." в диапазоне строк [start, end), с
 * телом каждого (до следующего заголовка того же или более высокого уровня).
 * @param {import('./parse.mjs').SpecFile} file
 * @param {number} start
 * @param {number} end
 * @returns {string[]}
 */
function scenarioBodiesInRange(file, start, end) {
  const out = [];
  for (let idx = 0; idx < file.headings.length; idx++) {
    const h = file.headings[idx];
    if (h.level !== 4 || !/^Scenario:/.test(h.text) || h.line < start || h.line >= end) continue;
    let endLine = file.bodyStartLine + file.bodyLines.length;
    for (let j = idx + 1; j < file.headings.length; j++) {
      if (file.headings[j].level <= h.level) { endLine = file.headings[j].line; break; }
    }
    out.push(file.bodyLines.slice(h.line - file.bodyStartLine, endLine - file.bodyStartLine).join('\n'));
  }
  return out;
}

/**
 * Определяет, какие из значений набора `candidates` ДЕЙСТВИТЕЛЬНО присутствуют
 * в `text` как самостоятельные токены. Проверка подстрокой (`text.includes(v)`)
 * ложно засчитывает исход покрытым, если он — суффикс ДРУГОГО, более длинного
 * исхода из того же набора: `"не отозвано".includes("отозвано")` истинно,
 * хотя сценарий говорит про противоположный исход (REVIEW.md H4). Здесь
 * значения ищутся ОДНОЙ альтернацией, отсортированной по убыванию длины,
 * с границей токена по обеим сторонам (`\b` не годится — JS не считает
 * кириллицу "словесными" символами, тот же нюанс, что у RU_OPERATOR_RE в
 * markdown.mjs): при совпадении на данной позиции более длинный кандидат
 * поглощается первым, и вложенный в него короткий повторно не засчитывается,
 * потому что глобальное сканирование продолжается ПОСЛЕ уже потреблённого
 * совпадения, а не заходит внутрь него.
 * @param {string} text
 * @param {string[]} candidates
 * @returns {Set<string>}
 */
function presentTokens(text, candidates) {
  const nonEmpty = [...new Set(candidates.filter((c) => c.trim() !== ''))];
  if (nonEmpty.length === 0) return new Set();
  const sorted = nonEmpty.slice().sort((a, b) => b.length - a.length);
  const escaped = sorted.map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const re = new RegExp(`(?<![A-Za-zА-Яа-яЁё0-9_])(${escaped.join('|')})(?![A-Za-zА-Яа-яЁё0-9_])`, 'g');
  const found = new Set();
  let m;
  while ((m = re.exec(text))) found.add(m[1]);
  return found;
}

/**
 * Все блоки Outcomes файла — как приписанные требованиям, так и файловые
 * (раздел "## Исходы" процесса) — с владельцем для сообщений.
 * @param {import('./parse.mjs').SpecFile} file
 * @returns {Array<import('./parse.mjs').OutcomesBlock & { owner: string }>}
 */
function allOutcomeBlocks(file) {
  const owner = hasValidFrontmatter(file) ? String(file.frontmatter.id) : file.path;
  const out = [];
  for (const req of file.requirements) if (req.outcomes) out.push({ ...req.outcomes, owner: req.id });
  for (const b of file.outcomesBlocks) out.push({ ...b, owner });
  return out;
}

/**
 * E-OUTCOMES-MISSING — вид термина требует блок Outcomes (profile.yaml
 * kinds.<kind>.must включает "outcomes"), а в файле нет ни одного.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkOutcomesMissing(repo) {
  const out = [];
  const kinds = repo.profile.kinds || {};
  for (const file of repo.files) {
    if (!hasValidFrontmatter(file)) continue;
    const kindDef = kinds[String(file.frontmatter.kind)];
    if (!kindDef || !Array.isArray(kindDef.must) || !kindDef.must.includes('outcomes')) continue;
    const hasAny = file.outcomesBlocks.length > 0 || file.requirements.some((r) => r.outcomes);
    if (!hasAny) {
      out.push(mk(file.path, file.frontmatterStartLine, 'ERROR', 'E-OUTCOMES-MISSING', `у термина вида "${file.frontmatter.kind}" нет блока Outcomes ни под требованием, ни в разделе "## Исходы"`));
    }
  }
  return out;
}

/**
 * E-OUTCOMES-NOT-CLOSED / E-OUTCOMES-DUP.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkOutcomesFormat(repo) {
  const out = [];
  // profile.yaml: outcomes.closed — "множество исходов операции замкнуто".
  // Раньше проверка была безусловной независимо от значения ключа: закрытость
  // нельзя было выключить через профиль (REVIEW.md P6). Умолчание true —
  // историческое поведение сохраняется, когда ключ не задан вовсе.
  const requireClosed = !(repo.profile.outcomes && repo.profile.outcomes.closed === false);
  for (const file of repo.files) {
    for (const block of allOutcomeBlocks(file)) {
      if (requireClosed && !block.closed) {
        out.push(mk(file.path, block.line, 'ERROR', 'E-OUTCOMES-NOT-CLOSED', `блок Outcomes ("${block.owner}") без маркера "(закрыто)"`));
      }
      const seen = new Set();
      for (const v of block.values) {
        if (seen.has(v)) out.push(mk(file.path, block.line, 'ERROR', 'E-OUTCOMES-DUP', `исход "${v}" повторяется в Outcomes ("${block.owner}")`));
        seen.add(v);
      }
    }
  }
  return out;
}

/**
 * W-OUTCOMES-NO-SCENARIO — исход не упомянут ни в одном "#### Scenario"
 * требования. Пропускается, если у требования вообще нет ни одного Scenario:
 * исходы процесса вправе описываться прозой под собственными подзаголовками,
 * а не сценариями, и тогда сравнивать не с чем.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkOutcomesScenarioCoverage(repo) {
  const out = [];
  for (const file of repo.files) {
    for (const req of file.requirements) {
      if (!req.isCanonical || !req.id || !req.outcomes) continue;
      const bodies = scenarioBodiesInRange(file, req.sectionStart, req.sectionEnd);
      if (bodies.length === 0) continue;
      const combined = bodies.join('\n');
      const present = presentTokens(combined, req.outcomes.values);
      for (const v of req.outcomes.values) {
        if (!present.has(v)) {
          out.push(mk(file.path, req.outcomes.line, 'WARN', 'W-OUTCOMES-NO-SCENARIO', `исход "${v}" требования ${req.id} не упомянут ни в одном "#### Scenario"`));
        }
      }
    }
  }
  return out;
}

/**
 * E-PARTITION-UNKNOWN-OUTCOME / E-PARTITION-NOT-TOTAL / W-PARTITION-CLASS-NO-SCENARIO.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkPartitions(repo) {
  const out = [];
  const partitionMustBeTotal = !!(repo.profile.outcomes && repo.profile.outcomes.partition_must_be_total);
  for (const file of repo.files) {
    const owner = hasValidFrontmatter(file) ? String(file.frontmatter.id) : file.path;
    /** @type {Array<{ outcomeValues: string[], partitions: import('./parse.mjs').PartitionBlock[], sectionStart: number, sectionEnd: number, owner: string }>} */
    const scopes = [];
    for (const req of file.requirements) {
      if (!req.isCanonical || !req.id || req.partitions.length === 0) continue;
      scopes.push({ outcomeValues: req.outcomes ? req.outcomes.values : [], partitions: req.partitions, sectionStart: req.sectionStart, sectionEnd: req.sectionEnd, owner: req.id });
    }
    if (file.partitionBlocks.length > 0) {
      const outcomeValues = file.outcomesBlocks.flatMap((b) => b.values);
      scopes.push({ outcomeValues, partitions: file.partitionBlocks, sectionStart: file.bodyStartLine, sectionEnd: file.bodyStartLine + file.bodyLines.length, owner });
    }
    for (const scope of scopes) {
      for (const p of scope.partitions) {
        if (!scope.outcomeValues.includes(p.outcome)) {
          out.push(mk(file.path, p.line, 'ERROR', 'E-PARTITION-UNKNOWN-OUTCOME', `разбиение для исхода "${p.outcome}" — такого исхода нет в Outcomes "${scope.owner}"`));
        }
        if (partitionMustBeTotal && !p.total) {
          out.push(mk(file.path, p.line, 'ERROR', 'E-PARTITION-NOT-TOTAL', `разбиение для исхода "${p.outcome}" без маркера "(полное)"`));
        }
        // Класс разбиения может быть исчерпывающе разобран разделом
        // "## Combinations" того же файла вместо прозы "#### Scenario" —
        // таблица строже сценария (она сама проверяется на полноту и
        // непересечение). Формулировки класса ("нет покрывающей CRL") и
        // значений измерений таблицы ("CRL: нет") обычно расходятся текстово,
        // поэтому точное сопоставление класса с конкретной ячейкой таблицы
        // ненадёжно; вместо него — дешёвый, но честный признак: у требования
        // есть Combinations-таблица хотя бы с одной строкой, дающей ИМЕННО
        // этот исход. Раньше отсутствие такого признака давало 100% находок
        // на REV-002, где вся полнота этого разбиения уже доказана таблицей.
        const tableCoversOutcome = file.combinations.some((t) => t.rows.some((r) => !r.undefined && r.outcome === p.outcome));
        const bodies = scenarioBodiesInRange(file, scope.sectionStart, scope.sectionEnd);
        const combined = bodies.join('\n');
        const present = presentTokens(combined, p.classes);
        for (const c of p.classes) {
          if (present.has(c)) continue;
          if (tableCoversOutcome) continue;
          out.push(mk(file.path, p.line, 'WARN', 'W-PARTITION-CLASS-NO-SCENARIO', `класс "${c}" разбиения для "${p.outcome}" не упомянут ни в одном "#### Scenario"`));
        }
      }
    }
  }
  return out;
}

/**
 * E-COMBINATIONS-NOT-TOTAL / E-COMBINATIONS-OVERLAP / E-COMBINATIONS-UNKNOWN-OUTCOME /
 * E-COMBINATIONS-NO-DIMENSIONS / E-COMBINATIONS-DIM-UNPARSED / E-COMBINATIONS-DIM-EMPTY /
 * E-COMBINATIONS-ROW-COLUMNS / W-COMBINATIONS-UNDEFINED-ROW.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkCombinations(repo) {
  const out = [];
  const cfg = (repo.profile.outcomes && repo.profile.outcomes.combinations) || {};
  for (const file of repo.files) {
    // Файл может нести НЕСКОЛЬКО разделов "## Combinations" (REVIEW.md M6) —
    // раньше проверялся только первый, и второй проходил линт молча.
    for (const table of file.combinations) {
    // Combinations синтаксически не привязан к одному требованию — сверяем
    // исход строки с объединением всех Outcomes, объявленных в файле.
    const declaredOutcomes = new Set();
    for (const req of file.requirements) if (req.outcomes) for (const v of req.outcomes.values) declaredOutcomes.add(v);
    for (const b of file.outcomesBlocks) for (const v of b.values) declaredOutcomes.add(v);

    for (const { line, text } of table.unparsedDimLines) {
      out.push(mk(file.path, line, 'ERROR', 'E-COMBINATIONS-DIM-UNPARSED', `строка похожа на объявление измерения, но не разобрана (нужен формат "- \`имя\` — знач1 | знач2"): "${text}"`));
    }

    for (const dim of table.dims) {
      if (dim.values.length === 0) {
        out.push(mk(file.path, dim.line, 'ERROR', 'E-COMBINATIONS-DIM-EMPTY', `измерение "${dim.name}" объявлено без единого значения — вырождает декартово произведение в ноль сочетаний, таблица ложно выглядит полной`));
      }
    }

    for (const row of table.rows) {
      if (row.columnMismatch) {
        out.push(mk(file.path, row.line, 'ERROR', 'E-COMBINATIONS-ROW-COLUMNS', `строка #${row.num}: число столбцов не совпадает с числом измерений (${table.dims.length}) + 2 — сверка по этой строке недостоверна`));
      }
      if (row.undefined) {
        out.push(mk(file.path, row.line, 'WARN', 'W-COMBINATIONS-UNDEFINED-ROW', `строка #${row.num} помечена "**НЕ ОПРЕДЕЛЕНО**" — задокументированная дыра в спецификации, а не ошибка`));
        continue;
      }
      if (row.outcome === null || !declaredOutcomes.has(row.outcome)) {
        out.push(mk(file.path, row.line, 'ERROR', 'E-COMBINATIONS-UNKNOWN-OUTCOME', `строка #${row.num}: исход "${row.outcome ?? row.outcomeRaw}" отсутствует в Outcomes`));
      }
    }

    if (table.rows.length === 0) continue;

    if (table.dims.length === 0) {
      // Раздел "## Combinations" присутствует, строки таблицы присутствуют,
      // но НИ ОДНОГО измерения не распознано — раньше это пропускалось молча
      // (проверка полноты просто не запускалась, и нигде не сообщалось, что
      // она вообще не состоялась). REVIEW.md H3: "путь Б".
      out.push(mk(file.path, table.sectionLine, 'ERROR', 'E-COMBINATIONS-NO-DIMENSIONS', 'раздел "## Combinations" содержит таблицу, но ни одного измерения не распознано — проверка полноты и непересечения НЕ выполнена'));
      continue;
    }
    if (table.dims.some((d) => d.values.length === 0)) continue; // E-COMBINATIONS-DIM-EMPTY уже сообщено выше — считать нечего

    // REVIEW.md M10: декартово произведение измерений материализуется целиком
    // ДО начала анализа (`analyzeCoverage` → `cartesianProduct`), а `uncovered`
    // может вырасти до полного размера произведения. Восемь измерений по пять
    // значений уже дают 390 625 сочетаний, а `analyzeCoverage` дополнительно
    // умножает это на число строк таблицы и на число измерений — при таком
    // размере авторская опечатка в измерении превращается в зависание/OOM
    // вместо находки. Считается ДЁШЕВО (произведение размеров, без аллокации)
    // ДО вызова analyzeCoverage — предел проверяемой сложности, а не попытка
    // осилить любой размер.
    const totalCombos = table.dims.reduce((a, d) => a * d.values.length, 1);
    const MAX_COMBOS = 200000;
    if (totalCombos > MAX_COMBOS) {
      out.push(mk(file.path, table.sectionLine, 'ERROR', 'E-COMBINATIONS-TOO-LARGE', `таблица слишком велика для проверки: ${table.dims.length} измерений дают ${totalCombos} сочетаний (предел ${MAX_COMBOS}) — проверка полноты и непересечения НЕ выполнена`));
      continue;
    }

    const { uncovered, overlaps } = analyzeCoverage(table);

    if (cfg.require_total !== false && uncovered.length > 0) {
      const total = table.dims.reduce((a, d) => a * d.values.length, 1);
      const sample = uncovered.slice(0, 10).map((c) => `(${formatCombo(table.dims, c)})`).join('; ');
      const more = uncovered.length > 10 ? `, ещё ${uncovered.length - 10} не показаны` : '';
      out.push(mk(file.path, table.sectionLine, 'ERROR', 'E-COMBINATIONS-NOT-TOTAL', `таблица не покрывает ${uncovered.length} сочетаний из ${total}: ${sample}${more}`));
    }

    // REVIEW.md M16: строка "**НЕ ОПРЕДЕЛЕНО**" — легальная задокументированная
    // дыра (W-COMBINATIONS-UNDEFINED-ROW уже сообщил о ней построчно), и она
    // ЗАСЧИТЫВАЕТСЯ как покрытие в analyzeCoverage — иначе E-COMBINATIONS-NOT-TOTAL
    // срабатывал бы на каждой честно объявленной дыре. Но факт того, что часть
    // "полноты" держится на такой дыре, не должен быть невидим: сообщение
    // называет число сочетаний, покрытых ИСКЛЮЧИТЕЛЬНО строкой "НЕ ОПРЕДЕЛЕНО".
    if (cfg.require_total !== false) {
      const undefinedOnly = countUndefinedOnlyCoverage(table);
      if (undefinedOnly > 0) {
        out.push(mk(file.path, table.sectionLine, 'WARN', 'W-COMBINATIONS-UNDEFINED-COVERAGE', `${undefinedOnly} сочетаний засчитаны в полноту таблицы только строкой(ами) "**НЕ ОПРЕДЕЛЕНО**" — поведение для них не определено`));
      }
    }

    if (cfg.require_disjoint !== false) {
      for (const ov of overlaps.slice(0, 10)) {
        const rowNums = ov.rows.map((r) => `#${r.num}`).join(', ');
        out.push(mk(file.path, ov.rows[0].line, 'ERROR', 'E-COMBINATIONS-OVERLAP', `сочетание (${formatCombo(table.dims, ov.combo)}) покрыто более чем одной строкой: ${rowNums}`));
      }
      if (overlaps.length > 10) {
        out.push(mk(file.path, table.sectionLine, 'ERROR', 'E-COMBINATIONS-OVERLAP', `и ещё ${overlaps.length - 10} пересекающихся сочетаний не показаны`));
      }
    }
    } // конец цикла по всем разделам "## Combinations" файла (REVIEW.md M6)
  }
  return out;
}

/**
 * E-AUTO-FIX-UNSUPPORTED — `outcomes.auto_fix` в profile.yaml объявлен со
 * значением, отличным от "forbidden". Единственное, что CLI умеет делать, —
 * не иметь `--fix` вовсе (конституция §10); профиль, обещающий иное
 * значение этого ключа, обещает возможность, которой физически нет
 * (REVIEW.md P7).
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkAutoFixForbidden(repo) {
  const autoFix = repo.profile.outcomes && repo.profile.outcomes.auto_fix;
  if (autoFix === undefined || autoFix === 'forbidden') return [];
  return [mk('profile.yaml', 1, 'ERROR', 'E-AUTO-FIX-UNSUPPORTED', `outcomes.auto_fix: "${autoFix}" — CLI не поддерживает авто-исправление ни в каком виде, единственное легальное значение — "forbidden"`)];
}

/**
 * E-PROFILE-KEY-UNREGISTERED / W-PROFILE-KEY-NOT-IMPLEMENTED — реестр
 * владения ключами profile.yaml (см. profile-registry.mjs, REVIEW.md C2).
 * Каждый присутствующий в профиле ключ обязан иметь владельца: проверку,
 * которая его читает, либо явную запись "не реализовано, потому что…".
 * Ключ без ни одной из двух записей — E-PROFILE-KEY-UNREGISTERED: профиль
 * обещает гарантию, за которую прямо сейчас не отвечает НИКТО, и это
 * обязано быть находкой линта, а не фактом, который нужно перечитывать код,
 * чтобы обнаружить.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
function checkProfileRegistry(repo) {
  const { unregistered, notImplemented } = checkProfileKeyOwnership(repo.profile);
  const out = [];
  for (const path of unregistered) {
    out.push(mk('profile.yaml', 1, 'ERROR', 'E-PROFILE-KEY-UNREGISTERED', `ключ "${path}" присутствует в profile.yaml, но ни одна проверка не заявляет, что его читает, и он не отмечен как намеренно нереализованный в profile-registry.mjs`));
  }
  for (const { path, reason } of notImplemented) {
    out.push(mk('profile.yaml', 1, 'WARN', 'W-PROFILE-KEY-NOT-IMPLEMENTED', `ключ "${path}" из profile.yaml намеренно не реализован: ${reason}`));
  }
  return out;
}

const ALL_CHECKS = [
  checkSourceWarnings,
  checkFrontmatter,
  checkKindUnknown,
  checkKindShape,
  checkIdDup,
  checkLinks,
  checkRelationTypes,
  checkCausalCompleteness,
  checkLinkMayReference,
  checkRuOperators,
  checkNormSentences,
  checkReqIdMissing,
  checkReqKind,
  checkReqPrefix,
  checkRequirementDecisions,
  checkEvidenceMissing,
  checkAnchors,
  checkUnparsedAnchors,
  checkKindAnchors,
  checkKindMustProducer,
  checkPatternApplication,
  checkObligationEvidence,
  checkDecisionAlternative,
  checkLifecycle,
  checkDecisionGraph,
  checkDecisionOrphan,
  checkTermOrphan,
  checkOutcomesMissing,
  checkOutcomesFormat,
  checkOutcomesScenarioCoverage,
  checkPartitions,
  checkCombinations,
  checkAutoFixForbidden,
  checkProfileRegistry,
];

/**
 * Запускает все проверки линта над репозиторием и возвращает находки,
 * отсортированные по файлу и строке.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Finding[]}
 */
export function lint(repo) {
  /** @type {Finding[]} */
  const out = [];
  for (const check of ALL_CHECKS) out.push(...check(repo));
  out.sort((a, b) => (a.path === b.path ? a.line - b.line : a.path < b.path ? -1 : 1));
  return out;
}

/**
 * Форматирует находку в строку `путь:строка: [LEVEL] код — сообщение`.
 * @param {Finding} f
 * @returns {string}
 */
export function formatFinding(f) {
  return `${f.path}:${f.line}: [${f.level}] ${f.code} — ${f.message}`;
}

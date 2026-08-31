// Модель репозитория spec2: загрузка profile.yaml и всех спек-файлов,
// индекс сущностей, разрешение квалифицированных ID, evidence-якорей,
// реестр паттернов и вычисление обязательств применённого паттерна, построение
// графа узлов/рёбер для `spec.mjs graph`.

import fs from 'node:fs';
import path from 'node:path';
import { parseYAML } from './yaml.mjs';
import { findSpecFiles, parseSpecFile } from './parse.mjs';

/**
 * Загружает и разбирает profile.yaml.
 * @param {string} root
 * @returns {Record<string, *>}
 */
export function loadProfile(root) {
  const text = fs.readFileSync(path.join(root, 'profile.yaml'), 'utf8');
  return parseYAML(text, 1);
}

/**
 * @typedef {{ id: string, kind: string, context: string, path: string, name: string,
 *   file: import('./parse.mjs').SpecFile }} Entity
 */

/**
 * @typedef {{ root: string, productRoot: string, profile: Record<string,*>,
 *   files: import('./parse.mjs').SpecFile[], filesByPath: Map<string, import('./parse.mjs').SpecFile>,
 *   sourceWarnings: Array<{ path: string, reason: string }>,
 *   entities: Entity[],
 *   entitiesByContextId: Map<string, Entity>, entitiesById: Map<string, Entity[]>,
 *   requirementsById: Map<string, { file: import('./parse.mjs').SpecFile, req: import('./parse.mjs').Requirement }>,
 *   patternKind: string|null, decisionKind: string|null,
 *   patternRegistry: Map<string, { entity: Entity, obligations: import('./parse.mjs').Requirement[] }> }} Repo
 */

/**
 * Загружает весь репозиторий spec2: профиль, все спек-файлы (только внутри
 * `profile.yaml` → `sources:`, см. {@link findSpecFiles}), индекс сущностей.
 * `productRoot` — корень, относительно которого разрешаются evidence-якоря
 * (`code:`/`test:`/`schema:`); по умолчанию совпадает с `root` (сам spec2/).
 * @param {string} root
 * @param {string} [productRoot]
 * @returns {Repo}
 */
export function loadRepo(root, productRoot = root) {
  const profile = loadProfile(root);
  // Отсутствующий или пустой `sources:` обязан быть ошибкой загрузки, а не
  // тихим нулём файлов: `findSpecFiles(root, undefined)` не бросает и не
  // сканирует ничего, поэтому `lint()` на таком профиле молча отчитался бы
  // "нарушений нет", просканировав ноль файлов — тот самый класс ложной
  // зелёности, ради которого затевалось ревью.
  if (!Array.isArray(profile.sources) || profile.sources.length === 0) {
    throw new Error('profile.yaml: ключ "sources" отсутствует или пуст — без него findSpecFiles молча просканирует ноль файлов; укажите список директорий со спеками, напр. sources: [terms, processes, patterns, decisions, events]');
  }
  const { files: paths, warnings: sourceWarnings } = findSpecFiles(root, profile.sources);
  const files = paths.map((p) => parseSpecFile(p, root));
  const filesByPath = new Map(files.map((f) => [f.path, f]));

  /** @type {Entity[]} */
  const entities = [];
  for (const file of files) {
    const fm = file.frontmatter;
    if (!fm || !fm.id || !fm.kind || !fm.context) continue;
    entities.push({ id: String(fm.id), kind: String(fm.kind), context: String(fm.context), path: file.path, name: fm.name ? String(fm.name) : String(fm.id), file });
  }

  const entitiesByContextId = new Map();
  const entitiesById = new Map();
  for (const e of entities) {
    entitiesByContextId.set(`${e.context} ${e.id}`, e);
    if (!entitiesById.has(e.id)) entitiesById.set(e.id, []);
    entitiesById.get(e.id).push(e);
  }

  const kinds = profile.kinds || {};
  const patternKind = Object.keys(kinds).find((k) => kinds[k] && kinds[k].computes_obligations) || null;
  const decisionKind = Object.keys(kinds).find((k) => kinds[k] && kinds[k].append_only) || null;

  const patternRegistry = new Map();
  if (patternKind) {
    for (const e of entities) {
      if (e.kind !== patternKind) continue;
      const obligations = e.file.requirements.filter((r) => !r.missingId && r.id);
      patternRegistry.set(e.id, { entity: e, obligations });
    }
  }

  // Индекс требований по ID — построен один раз здесь, а не линейным сканом
  // всех файлов на каждый вызов (REVIEW.md M9: `findRequirement` в slice.mjs
  // сканировал repo.files × file.requirements внутри поэрёберного цикла).
  const requirementsById = new Map();
  for (const file of files) {
    for (const req of file.requirements) {
      if (!req.id || requirementsById.has(req.id)) continue; // дубли ID — отдельная находка E-ID-DUP, здесь берём первый
      requirementsById.set(req.id, { file, req });
    }
  }

  return { root, productRoot, profile, files, filesByPath, sourceWarnings, entities, entitiesByContextId, entitiesById, requirementsById, patternKind, decisionKind, patternRegistry };
}

/**
 * @typedef {{ target: Entity|null, unresolved: boolean, crossContext: boolean, kindMismatch: boolean }} LinkResolution
 */

/**
 * Разрешает квалифицированный или локальный ID: сначала как id
 * внутри своего контекста, затем — если ref квалифицирован (`контекст.id`) —
 * напрямую по указанному контексту, иначе — глобальным поиском (что и
 * помечается как межконтекстная ссылка без квалификации).
 * @param {{ref:string}} link
 * @param {string} sourceContext
 * @param {Repo} repo
 * @returns {LinkResolution}
 */
export function resolveLink(link, sourceContext, repo) {
  const dotIdx = link.ref.indexOf('.');
  let target = null;
  let crossContext = false;
  if (dotIdx !== -1) {
    const ctx = link.ref.slice(0, dotIdx);
    const id = link.ref.slice(dotIdx + 1);
    target = repo.entitiesByContextId.get(`${ctx} ${id}`) || null;
  } else {
    target = repo.entitiesByContextId.get(`${sourceContext} ${link.ref}`) || null;
    if (!target) {
      const candidates = repo.entitiesById.get(link.ref) || [];
      if (candidates.length > 0) {
        target = candidates[0];
        crossContext = target.context !== sourceContext;
      }
    }
  }
  if (!target) return { target: null, unresolved: true, crossContext: false, kindMismatch: false };
  return { target, unresolved: false, crossContext, kindMismatch: false };
}

/**
 * @typedef {{ ok: boolean, reason: string|null }} AnchorResolution
 */

/**
 * Символ считается "идентификаторным" символом, если это буква ASCII, цифра
 * или подчёркивание — общий знаменатель для идентификаторов Rust/TS/C#/Python.
 * @param {string|undefined} ch
 * @returns {boolean}
 */
function isIdentChar(ch) {
  return ch !== undefined && /[A-Za-z0-9_]/.test(ch);
}

/**
 * Ищет `needle` в `haystack` как ЦЕЛЫЙ токен — по обеим сторонам совпадения
 * не должно быть идентификаторного символа. Простое `content.includes(...)`
 * (REVIEW.md H5) резольвит `check_revocation` внутри `check_revocation_disabled`
 * и держит якорь "разрешённым" после удаления самой функции — а также
 * вырождается в тождественную истину для коротких символов (`new`, `id`).
 * @param {string} haystack
 * @param {string} needle
 * @returns {boolean}
 */
function containsAsToken(haystack, needle) {
  let from = 0;
  for (;;) {
    const idx = haystack.indexOf(needle, from);
    if (idx === -1) return false;
    if (!isIdentChar(haystack[idx - 1]) && !isIdentChar(haystack[idx + needle.length])) return true;
    from = idx + 1;
  }
}

/**
 * Разрешает evidence-якорь: файл существует ВНУТРИ корня продукта (не
 * директория, не путь, вышедший наружу через `../`), и (для якорей с
 * символом) искомый символ встречается в файле как целый токен.
 * @param {import('./parse.mjs').Anchor} anchor
 * @param {string} root
 * @returns {AnchorResolution}
 */
export function resolveAnchor(anchor, root) {
  const resolvedRoot = path.resolve(root);
  const filePath = path.resolve(resolvedRoot, anchor.file);
  // `path.join`/`path.resolve` не ограничены корнем сами по себе — якорь
  // `code:../../etc/passwd` резольвился бы наружу репозитория молча
  // (REVIEW.md H5). Разрешённый путь обязан остаться ВНУТРИ resolvedRoot.
  const rel = path.relative(resolvedRoot, filePath);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    return { ok: false, reason: `якорь выходит за пределы корня репозитория: ${anchor.file}` };
  }
  if (!fs.existsSync(filePath)) return { ok: false, reason: `файл не найден: ${anchor.file}` };
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (e) {
    return { ok: false, reason: `не удалось прочитать файл: ${e.message}` };
  }
  if (!stat.isFile()) {
    // fs.existsSync истинен и для директорий: code:crates/ резольвился бы
    // как "существующий файл" (REVIEW.md H5).
    return { ok: false, reason: `путь не является файлом: ${anchor.file}` };
  }
  if (anchor.symbol) {
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      return { ok: false, reason: `не удалось прочитать файл: ${e.message}` };
    }
    if (!containsAsToken(content, anchor.symbol)) {
      return { ok: false, reason: `символ "${anchor.symbol}" не найден в ${anchor.file}` };
    }
  }
  return { ok: true, reason: null };
}

/**
 * @typedef {{ id: string, pattern: string, version: number, obligationId: string,
 *   kindAttr: string|null, hasEvidence: boolean, evidenceAnchors: import('./parse.mjs').Anchor[] }} ObligationInstance
 */

/**
 * Вычисляет обязательства применённых паттернов для термина (конституция §6):
 * `<term-id> × <pattern>@<v>/<norm-id>`, с отметкой, найдено ли для каждого
 * evidence в секции `## Conformance` файла термина.
 * @param {Entity} entity
 * @param {Repo} repo
 * @returns {ObligationInstance[]}
 */
export function computeObligations(entity, repo) {
  const applies = (entity.file.frontmatter && Array.isArray(entity.file.frontmatter.applies))
    ? entity.file.frontmatter.applies
    : [];
  /** @type {ObligationInstance[]} */
  const out = [];
  for (const app of applies) {
    if (!app || !app.pattern) continue;
    const reg = repo.patternRegistry.get(app.pattern);
    if (!reg) continue;
    for (const obligation of reg.obligations) {
      const conformanceEntry = entity.file.conformance.find(
        (c) => c.pattern === app.pattern && c.normId === obligation.id,
      );
      out.push({
        id: `${entity.id} × ${app.pattern}/${obligation.id}`,
        pattern: app.pattern,
        obligationId: obligation.id,
        kindAttr: obligation.kindAttr,
        hasEvidence: !!conformanceEntry,
        evidenceAnchors: conformanceEntry ? conformanceEntry.anchors : [],
      });
    }
  }
  return out;
}

/**
 * @typedef {{ id: string, kind: string, context: string, path: string, name: string }} GraphNode
 * @typedef {{ from: string, to: string, type: string, [key: string]: * }} GraphEdge
 */

/**
 * Строит граф узлов/рёбер репозитория. Узлы — сущности (frontmatter) и
 * требования (заголовки-нормы, вид "норма"). Рёбра — только "прямые" типы:
 * субъект, ссылка, evidence, применённый-паттерн, решение; обратные
 * вычисляются на лету при обходе (см. slice.mjs), отдельно не хранятся.
 * @param {Repo} repo
 * @returns {{ nodes: GraphNode[], edges: GraphEdge[], nodesById: Map<string, GraphNode> }}
 */
export function buildGraph(repo) {
  /** @type {GraphNode[]} */
  const nodes = [];
  /** @type {GraphEdge[]} */
  const edges = [];

  const entityByPathId = new Map();
  for (const e of repo.entities) {
    nodes.push({ id: e.id, kind: e.kind, context: e.context, path: e.path, name: e.name });
    entityByPathId.set(`${e.file.path} ${e.id}`, e);
  }

  for (const file of repo.files) {
    const fm = file.frontmatter;
    if (!fm || !fm.id || !fm.kind || !fm.context) continue;
    const fileEntity = repo.entitiesByContextId.get(`${fm.context} ${fm.id}`);
    if (!fileEntity) continue;

    for (const req of file.requirements) {
      if (!req.id) continue;
      nodes.push({ id: req.id, kind: 'норма', context: fm.context, path: file.path, name: req.title });
    }

    for (const link of file.links) {
      const resolution = resolveLink(link, fm.context, repo);
      if (resolution.unresolved) continue;
      const type = resolution.target.kind === repo.decisionKind ? 'решение' : `relation:${link.relation || 'references'}`;
      edges.push({ from: fm.id, to: resolution.target.id, type });
    }

    for (const req of file.requirements) {
      if (!req.id) continue;
      for (const subject of req.subjects || []) {
        if (subject === 'application') continue;
        const resolution = resolveLink({ ref: subject }, fm.context, repo);
        if (resolution.target) edges.push({ from: req.id, to: resolution.target.id, type: 'субъект' });
      }
      if (!req.isCanonical) continue;
      for (const decisionRef of req.decidedBy || []) {
        const resolution = resolveLink({ ref: decisionRef }, fm.context, repo);
        if (resolution.target?.kind === repo.decisionKind) {
          edges.push({ from: req.id, to: resolution.target.id, type: 'решение', relation: 'decided_by' });
        }
      }
      for (const anchor of req.evidenceAnchors) {
        edges.push({ from: req.id, to: anchor.target, type: 'evidence', anchorType: anchor.type });
      }
    }

    // Якоря самой сущности (frontmatter `anchors:`, напр. `type:путь#Имя`) —
    // это evidence не конкретного требования, а термина целиком: узел-источник
    // здесь fm.id, не req.id. Без этого цикла `spec.mjs why` не находит термин
    // по type:-якорю, объявленному только в frontmatter (а не в теле Evidence).
    for (const anchor of file.frontmatterAnchors) {
      edges.push({ from: fm.id, to: anchor.target, type: 'evidence', anchorType: anchor.type });
    }

    const applies = Array.isArray(fm.applies) ? fm.applies : [];
    for (const app of applies) {
      if (!app || !app.pattern) continue;
      const reg = repo.patternRegistry.get(app.pattern);
      if (!reg) continue;
      edges.push({ from: fm.id, to: reg.entity.id, type: 'применённый-паттерн' });
    }

    for (const c of file.conformance) {
      for (const anchor of c.anchors) {
        edges.push({ from: fm.id, to: anchor.target, type: 'evidence', anchorType: anchor.type, pattern: c.pattern, normId: c.normId });
      }
    }
  }

  // Построен один раз здесь, а не линейным сканом `nodes.find(...)` на каждый
  // поиск узла (REVIEW.md M9): при 500+ файлах поэрёберный обход в slice.mjs
  // становится O(E·N).
  const nodesById = new Map(nodes.map((n) => [n.id, n]));

  return { nodes, edges, nodesById };
}

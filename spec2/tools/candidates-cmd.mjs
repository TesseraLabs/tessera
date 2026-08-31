// `spec.mjs candidates [--new]` — поиск вероятных доменных сущностей в коде,
// не покрытых spec2 (задача команды). Сканирует исходники продукта, ранжирует
// публичные типы по сигналам «за»/«против» (веса — `profile.yaml` → `candidates`),
// сверяет с уже описанными терминами и печатает очередь кандидатов с
// обоснованием. Вердикт человека фиксируется в `spec2/candidates.yaml` —
// команда его читает и никогда не пишет сама (авто-разрешения нет, как и
// у `outcomes`, конституция §10 — тот же принцип: выбор за человеком).

import fs from 'node:fs';
import path from 'node:path';
import { adapterForFile } from './adapters/index.mjs';
import { parseYAML } from './yaml.mjs';

// Директории, которые не сканируются: служебные (VCS/сборка), вендоренные
// зависимости (cargo-registry, кеши сборки под debian/target-*) и сам spec2/.
// Без этого команда честно находит тысячи "кандидатов" в исходниках libc.
const IGNORE_DIRS = new Set([
  '.git', 'target', 'node_modules', 'dist', 'build', '.next', 'bin', 'obj',
  '.venv', 'venv', '__pycache__', 'spec2', '.claude',
  'cargo_home', 'registry', '.cargo', 'vendor', 'debian', 'artifacts',
  'target-linux', 'target-windows', 'docker', 'vagrant',
]);

const GENERIC_NAMES = new Set([
  'Error', 'Result', 'State', 'Config', 'Context', 'Builder', 'Manager',
  'Helper', 'Handle', 'Inner', 'Args', 'Opts', 'Options', 'Level', 'Mode', 'Field',
]);

const UTIL_MODULE_RE = /\butil\b|\binternal\b|\btest\b|\bmock\b|\bliar\b/i;
const DOMAIN_MODULE_RE = /_contract\b|\bdomain\b|\bmodel\b|\bcore\b/i;
const SIGNAL_LINE_RE = /\berror\b|\baudit\b|\bevent\b/i;
const WORD_RE = /\b[A-Za-z_][A-Za-z0-9_]*\b/g;

/**
 * Рекурсивно находит файлы исходников продукта (по расширениям, известным
 * реестру адаптеров), исключая генерируемые/служебные директории и сам spec2/.
 * @param {string} root
 * @returns {string[]} относительные пути (posix-разделитель, как в якорях)
 */
function walkSourceFiles(root) {
  const out = [];
  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      if (!entry.isFile()) continue;
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (adapterForFile(rel)) out.push(rel);
    }
  }
  walk(root);
  return out.sort();
}

/**
 * Модуль объявления — крейт (`crates/<name>`) для Rust-раскладки этого
 * репозитория, иначе первые два сегмента пути. Связанность считается МЕЖДУ
 * модулями, а не файлами: два файла одного крейта, ссылающихся друг на
 * друга, не создают кросс-модульный сигнал.
 * @param {string} relPath
 * @returns {string}
 */
function computeModule(relPath) {
  const parts = relPath.split('/');
  if (parts[0] === 'crates' && parts.length > 1) return `crates/${parts[1]}`;
  return parts.length > 1 ? parts.slice(0, 2).join('/') : parts[0];
}

/**
 * Разбивает `PascalCase`/`snake_case` имя на слова, в нижнем регистре.
 * @param {string} name
 * @returns {string[]}
 */
function splitWords(name) {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * Собирает все evidence-якоря репозитория (frontmatter + требования +
 * Conformance) — единый список, откуда берутся и «уже покрыто», и словарь
 * латинских символов для сигнала пересечения со spec2.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {import('./parse.mjs').Anchor[]}
 */
function collectAllAnchors(repo) {
  const out = [];
  for (const file of repo.files) {
    out.push(...file.frontmatterAnchors);
    for (const req of file.requirements) out.push(...req.evidenceAnchors);
    for (const c of file.conformance) out.push(...c.anchors);
  }
  return out;
}

/**
 * Словарь для сигнала «имя пересекается со spec2»: латинские name/aliases
 * терминов (как фразы через пробел) и базовые имена символов из якорей
 * (последний сегмент после `::`/`.`, без generic-параметров).
 * @param {import('./graph.mjs').Repo} repo
 * @param {import('./parse.mjs').Anchor[]} anchors
 * @returns {{ phrases: Set<string>, symbolNames: Set<string> }}
 */
function buildVocabulary(repo, anchors) {
  const phrases = new Set();
  const LATIN_RE = /^[A-Za-z0-9 _-]+$/;
  for (const e of repo.entities) {
    const fm = e.file.frontmatter || {};
    const candidates = [fm.name, ...(Array.isArray(fm.aliases) ? fm.aliases : [])].filter(Boolean);
    for (const c of candidates) {
      const s = String(c).trim();
      if (LATIN_RE.test(s)) phrases.add(splitWords(s).join(' '));
    }
  }
  const symbolNames = new Set();
  for (const a of anchors) {
    if (!a.symbol) continue;
    const base = a.symbol.split(/[:.]/).pop().replace(/<.*>/, '').replace(/\(.*\)/, '');
    if (base) symbolNames.add(base.toLowerCase());
  }
  return { phrases, symbolNames };
}

/**
 * Читает вердикты `spec2/candidates.yaml` (человек→вердикт). Отсутствующий
 * файл — пустой реестр, не ошибка (ещё никто не триажил).
 * @param {string} spec2Root
 * @returns {Map<string, { verdict: string, term_id?: string, reason?: string }>}
 */
export function loadVerdicts(spec2Root) {
  const p = path.join(spec2Root, 'candidates.yaml');
  const out = new Map();
  if (!fs.existsSync(p)) return out;
  const parsed = parseYAML(fs.readFileSync(p, 'utf8'), 1);
  if (!parsed || typeof parsed !== 'object') return out;
  for (const [key, val] of Object.entries(parsed)) {
    if (val && typeof val === 'object' && val.verdict) out.set(key, val);
  }
  return out;
}

/**
 * @typedef {{
 *   key: string, name: string, kind: string, file: string, line: number, module: string,
 *   signals: { crossModuleRefs: number, publicSignature: boolean, serialization: boolean,
 *     errorOrAudit: boolean, vocabularyOverlap: boolean, domainModule: boolean,
 *     genericName: boolean, utilModule: boolean, noUsage: boolean },
 *   weight: number
 * }} Candidate
 */

/**
 * Сканирует продукт и считает кандидатов с сигналами и весом. Не фильтрует
 * по вердиктам/threshold — это делает {@link cmdCandidates}, чтобы сканирование
 * оставалось тестируемым отдельно от печати.
 * @param {import('./graph.mjs').Repo} repo
 * @returns {Candidate[]}
 */
export function scanCandidates(repo) {
  const cfgWeights = (repo.profile.candidates && repo.profile.candidates.weights) || {};
  const w = (key, def) => (typeof cfgWeights[key] === 'number' ? cfgWeights[key] : def);

  const relFiles = walkSourceFiles(repo.productRoot);
  /** @type {{ rel: string, source: string, adapter: * }[]} */
  const fileRecords = relFiles.map((rel) => {
    const adapter = adapterForFile(rel);
    const source = fs.readFileSync(path.join(repo.productRoot, rel), 'utf8');
    return { rel, source, adapter };
  });

  // Проход 1: все объявления публичных типов.
  /** @type {{ name: string, kind: string, file: string, line: number, module: string, hasSerialization: boolean }[]} */
  const decls = [];
  for (const fr of fileRecords) {
    if (typeof fr.adapter.extractPublicTypes !== 'function') continue;
    for (const t of fr.adapter.extractPublicTypes(fr.source)) {
      if (!t.isPublic) continue;
      decls.push({ name: t.name, kind: t.kind, file: fr.rel, line: t.line, module: computeModule(fr.rel), hasSerialization: t.hasSerialization });
    }
  }

  const uniqueNames = new Set(decls.map((d) => d.name));

  // Проход 2: по каждому файлу — множество идентификаторов, идентификаторы
  // на «сигнальных» строках (error/audit/event) и идентификаторы в тексте
  // публичных сигнатур. Один проход на файл вместо перебора файлов на
  // каждое имя кандидата.
  /** @type {Map<string, Set<string>>} имя → модули, где встречается */
  const refModules = new Map();
  /** @type {Set<string>} имена, встреченные на сигнальной строке хоть где-то */
  const errorAuditHit = new Set();
  /** @type {Set<string>} имена, встреченные в тексте публичной сигнатуры хоть где-то */
  const publicSigHit = new Set();
  for (const name of uniqueNames) { refModules.set(name, new Set()); }

  for (const fr of fileRecords) {
    const module = computeModule(fr.rel);
    const idents = new Set();
    WORD_RE.lastIndex = 0;
    let m;
    while ((m = WORD_RE.exec(fr.source))) idents.add(m[0]);

    for (const name of uniqueNames) {
      if (idents.has(name)) refModules.get(name).add(module);
    }

    const signalLineIdents = new Set();
    for (const line of fr.source.split('\n')) {
      if (!SIGNAL_LINE_RE.test(line)) continue;
      WORD_RE.lastIndex = 0;
      let lm;
      while ((lm = WORD_RE.exec(line))) signalLineIdents.add(lm[0]);
    }
    for (const name of uniqueNames) if (signalLineIdents.has(name)) errorAuditHit.add(name);

    if (typeof fr.adapter.findPublicSignatureText === 'function') {
      const sigText = fr.adapter.findPublicSignatureText(fr.source);
      const sigIdents = new Set();
      WORD_RE.lastIndex = 0;
      let sm;
      while ((sm = WORD_RE.exec(sigText))) sigIdents.add(sm[0]);
      for (const name of uniqueNames) if (sigIdents.has(name)) publicSigHit.add(name);
    }
  }

  const anchors = collectAllAnchors(repo);
  // `type:` marks a domain implementation type; `schema:` marks a published
  // boundary shape.  Both deliberately name an exact code symbol and both
  // answer the candidate scanner's question: "has a human already attached
  // meaning to this public type?"  Treating only `type:` as coverage made
  // every DTO of an otherwise fully described contract reappear as a gap.
  const covered = new Set(
    anchors
      .filter((a) => a.type === 'type' || a.type === 'schema')
      .map((a) => `${a.file}#${a.symbol}`),
  );
  const vocab = buildVocabulary(repo, anchors);

  /** @type {Candidate[]} */
  const out = [];
  for (const d of decls) {
    const key = `${d.file}#${d.name}`;
    if (covered.has(key)) continue; // уже отмечено type:/schema:-якорем — не гэп

    const modules = refModules.get(d.name);
    const crossModuleRefs = [...modules].filter((mod) => mod !== d.module).length;
    const publicSignature = publicSigHit.has(d.name);
    const errorOrAudit = errorAuditHit.has(d.name);

    const nameWords = splitWords(d.name).join(' ');
    const nameLower = d.name.toLowerCase();
    const vocabularyOverlap = vocab.phrases.has(nameWords) || vocab.symbolNames.has(nameLower);

    const domainModule = DOMAIN_MODULE_RE.test(d.file) || DOMAIN_MODULE_RE.test(d.module);
    const genericName = GENERIC_NAMES.has(d.name) || [...GENERIC_NAMES].some((g) => d.name.endsWith(g));
    const utilModule = UTIL_MODULE_RE.test(d.file) || UTIL_MODULE_RE.test(d.module);
    const noUsage = crossModuleRefs === 0 && !publicSignature;

    let weight = 0;
    weight += crossModuleRefs * w('cross_module_ref', 2);
    if (publicSignature) weight += w('public_signature', 3);
    if (d.hasSerialization) weight += w('serialization', 2);
    if (errorOrAudit) weight += w('error_or_audit', 2);
    if (vocabularyOverlap) weight += w('vocabulary_overlap', 3);
    if (domainModule) weight += w('domain_module_name', 1);
    if (genericName) weight -= w('generic_name', 3);
    if (utilModule) weight -= w('util_module', 2);
    if (noUsage) weight -= w('no_usage', 2);

    out.push({
      key, name: d.name, kind: d.kind, file: d.file, line: d.line, module: d.module,
      signals: { crossModuleRefs, publicSignature, serialization: d.hasSerialization, errorOrAudit, vocabularyOverlap, domainModule, genericName, utilModule, noUsage },
      weight,
    });
  }

  out.sort((a, b) => (b.weight - a.weight) || (b.signals.crossModuleRefs - a.signals.crossModuleRefs) || a.name.localeCompare(b.name));
  return out;
}

/**
 * Расшифровывает сработавшие сигналы кандидата в короткую строку — находка
 * без обоснования бесполезна (задание команды).
 * @param {Candidate} c
 * @returns {string}
 */
function formatSignals(c) {
  const s = c.signals;
  const pro = [];
  const contra = [];
  if (s.crossModuleRefs > 0) pro.push(`cross_module_ref×${s.crossModuleRefs}`);
  if (s.publicSignature) pro.push('public_signature');
  if (s.serialization) pro.push('serialization');
  if (s.errorOrAudit) pro.push('error_or_audit');
  if (s.vocabularyOverlap) pro.push('vocabulary_overlap');
  if (s.domainModule) pro.push('domain_module_name');
  if (s.genericName) contra.push('generic_name');
  if (s.utilModule) contra.push('util_module');
  if (s.noUsage) contra.push('no_usage');
  const parts = [];
  if (pro.length) parts.push(pro.join(', '));
  if (contra.length) parts.push(contra.join(', '));
  return parts.join(' | ') || '(сигналов нет)';
}

/**
 * `spec.mjs candidates [--new]`.
 * @param {import('./graph.mjs').Repo} repo
 * @param {{ onlyNew?: boolean }} [opts]
 * @returns {{ text: string, hasNew: boolean }}
 */
export function cmdCandidates(repo, opts = {}) {
  const pending = pendingCandidates(repo);
  const threshold = (repo.profile.candidates && typeof repo.profile.candidates.threshold === 'number')
    ? repo.profile.candidates.threshold
    : 1;

  if (opts.onlyNew) {
    if (pending.length === 0) {
      return { text: 'новых кандидатов без вердикта нет', hasNew: false };
    }
    const lines = pending.map((c) => `${c.file}#${c.name}  (вес ${c.weight}, ${formatSignals(c)})`);
    return {
      text: [`НОВЫЕ КАНДИДАТЫ БЕЗ ВЕРДИКТА (${pending.length}) — вердикт в spec2/candidates.yaml`, ...lines].join('\n'),
      hasNew: true,
    };
  }

  if (pending.length === 0) {
    return { text: 'кандидатов без вердикта нет (порог ' + threshold + ')', hasNew: false };
  }
  const lines = pending.map((c, i) => `${i + 1}. ${c.file}#${c.name} (${c.kind}, вес ${c.weight}) — ${formatSignals(c)}`);
  return {
    text: [`ОЧЕРЕДЬ КАНДИДАТОВ (${pending.length}, порог ${threshold}) — вердикт: spec2/candidates.yaml`, ...lines].join('\n'),
    hasNew: pending.length > 0,
  };
}

/** Возвращает структурированную очередь для doctor/review, не форматируя CLI. */
export function pendingCandidates(repo) {
  const verdicts = loadVerdicts(repo.root);
  const threshold = (repo.profile.candidates && typeof repo.profile.candidates.threshold === 'number')
    ? repo.profile.candidates.threshold
    : 1;
  const all = scanCandidates(repo);
  return all.filter((c) => !verdicts.has(c.key) && c.weight >= threshold);
}

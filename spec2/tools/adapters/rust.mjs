// Rust-адаптер для `spec.mjs outcomes` (конституция §10): источник множества
// исходов в коде — возвращаемый тип, а не бросок. Здесь это варианты `enum`.

import { escapeRegExp } from './shared.mjs';

/**
 * Находит начало объявления `enum <symbol>` в исходнике и возвращает индекс
 * открывающей `{` тела, либо -1, если такого enum нет.
 * @param {string} source
 * @param {string} symbol
 * @returns {number}
 */
function findEnumBraceStart(source, symbol) {
  const declRe = new RegExp(`(?:pub(?:\\([^)]*\\))?\\s+)?enum\\s+${escapeRegExp(symbol)}\\b`);
  const m = declRe.exec(source);
  if (!m) return -1;
  return source.indexOf('{', m.index);
}

/**
 * Вырезает тело `enum { ... }`, начиная с символа сразу после открывающей `{`,
 * учитывая вложенные `{}` (варианты со struct-полями), построчные и блочные
 * комментарии, строковые литералы и лайфтаймы (`'a`, которые не строковые
 * литералы, хотя тоже начинаются с одинарной кавычки).
 * @param {string} source
 * @param {number} braceStart индекс открывающей `{`
 * @returns {string|null} тело без внешних скобок, либо null, если скобка не закрылась
 */
function extractBalancedBody(source, braceStart) {
  let depth = 1;
  let j = braceStart + 1;
  let inLineComment = false;
  let inBlockComment = false;
  let inString = false;
  const chars = [];
  while (j < source.length) {
    const c = source[j];
    const c2 = source[j + 1];

    if (inLineComment) { if (c === '\n') inLineComment = false; j++; continue; }
    if (inBlockComment) { if (c === '*' && c2 === '/') { inBlockComment = false; j += 2; continue; } j++; continue; }
    if (inString) {
      if (c === '\\') { j += 2; continue; }
      if (c === '"') inString = false;
      j++;
      continue;
    }
    if (c === '/' && c2 === '/') { inLineComment = true; j += 2; continue; }
    if (c === '/' && c2 === '*') { inBlockComment = true; j += 2; continue; }
    if (c === '"') { inString = true; j++; continue; }
    if (c === "'") {
      // Различить char-литерал ('x', '\n') от лайфтайма ('a, 'static):
      // char-литерал закрывается второй кавычкой в пределах пары символов
      // (с учётом возможного экранирования), лайфтайм — нет.
      if (c2 === '\\' && source[j + 3] === "'") { j += 4; continue; }
      if (source[j + 2] === "'") { j += 3; continue; }
      j++; // лайфтайм — сама кавычка не несёт структурного смысла
      continue;
    }
    if (c === '{') { depth++; chars.push(c); j++; continue; }
    if (c === '}') {
      depth--;
      if (depth === 0) return chars.join('');
      chars.push(c);
      j++;
      continue;
    }
    chars.push(c);
    j++;
  }
  return null; // скобка не закрылась — источник обрезан или испорчен
}

/**
 * Разбивает тело enum на варианты верхнего уровня по запятым, не заходя
 * внутрь `()`, `[]`, `{}` варианта (кортежные/struct-варианты) и строк.
 * @param {string} body
 * @returns {string[]}
 */
function splitTopLevelVariants(body) {
  const parts = [];
  let cur = '';
  let depth = 0;
  let inString = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (inString) {
      cur += c;
      if (c === '\\') { cur += body[i + 1] ?? ''; i++; continue; }
      if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') { depth++; cur += c; continue; }
    if (c === ')' || c === ']' || c === '}') { depth--; cur += c; continue; }
    if (c === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim() !== '') parts.push(cur);
  return parts;
}

/**
 * Извлекает имена вариантов `pub enum <symbol> { A, B(..), C { .. } }` из
 * исходника Rust. Возвращает `null`, если символ не найден или не является
 * enum (тело не закрылось / декларации нет).
 * @param {string} source
 * @param {string} symbol
 * @returns {string[]|null}
 */
export function extractEnumVariants(source, symbol) {
  const braceStart = findEnumBraceStart(source, symbol);
  if (braceStart === -1) return null;
  const body = extractBalancedBody(source, braceStart);
  if (body === null) return null;
  const nameRe = /^\s*([A-Za-z_][A-Za-z0-9_]*)/;
  return splitTopLevelVariants(body)
    .map((part) => nameRe.exec(part.replace(/#!?\[[^\]]*\]/g, '')))
    .filter(Boolean)
    .map((m) => m[1]);
}

/**
 * Находит начало тела функции `fn <symbol>(...) [-> RetType] { ... }` и
 * возвращает индекс открывающей `{`, либо -1, если функция не найдена.
 * Ищет от заголовка `fn <symbol>` до первой `{` верхнего уровня (после
 * необязательного `-> RetType`), чтобы не спутать её со скобкой в generic-
 * параметрах или в типе возврата (`-> Result<X, Y>`).
 * @param {string} source
 * @param {string} symbol
 * @returns {number}
 */
function findFnBraceStart(source, symbol) {
  const declRe = new RegExp(`fn\\s+${escapeRegExp(symbol)}\\s*(?:<[^>]*>)?\\s*\\(`);
  const m = declRe.exec(source);
  if (!m) return -1;
  // Пропустить параметры (сбалансированные скобки), затем необязательный
  // `-> RetType`, затем найти первую `{` — тело функции.
  let depth = 1;
  let j = source.indexOf('(', m.index) + 1;
  while (j < source.length && depth > 0) {
    if (source[j] === '(') depth++;
    else if (source[j] === ')') depth--;
    j++;
  }
  const brace = source.indexOf('{', j);
  const semi = source.indexOf(';', j);
  if (brace === -1) return -1;
  if (semi !== -1 && semi < brace) return -1; // объявление без тела (trait)
  return brace;
}

const ESCAPE_PATTERNS = [
  { re: /\bpanic!/g, label: 'panic!' },
  { re: /\bunreachable!/g, label: 'unreachable!' },
  { re: /\btodo!/g, label: 'todo!' },
  { re: /\.unwrap\(\)/g, label: '.unwrap()' },
  { re: /\.expect\(/g, label: '.expect(' },
];

/**
 * Ищет в теле функции сайты, где исход уходит мимо возвращаемого типа:
 * паника и её эквиваленты, `.unwrap()`/`.expect(`, индексация среза.
 * @param {string} body
 * @returns {string[]}
 */
function findEscapingSites(body) {
  const found = [];
  for (const { re, label } of ESCAPE_PATTERNS) {
    // Регэксп объявлен на уровне модуля с флагом /g: без сброса lastIndex
    // позиция сохраняется между вызовами (в т.ч. на РАЗНЫХ телах функций),
    // и `.test()` через раз возвращает false, хотя совпадение есть.
    re.lastIndex = 0;
    if (re.test(body)) found.push(label);
  }
  // Индексация среза `arr[i]`: идентификатор впритык к `[`, не тип-аннотация
  // (`: [T; N]`) и не макрос (`vec![...]` — между именем и `[` стоит `!`).
  const sliceRe = /\b([A-Za-z_][A-Za-z0-9_]*)\[[^\]\n]*\]/g;
  let sm;
  while ((sm = sliceRe.exec(body))) {
    found.push(`индексация ${sm[0]}`);
  }
  return found;
}

/**
 * Извлекает исходы функции `symbol`: `declared` — варианты enum, если
 * возвращаемый тип назван и это enum в этом же файле; `escaping` — паника,
 * unwrap/expect и индексация среза в теле. `null`, если функция не найдена.
 * @param {string} source
 * @param {string} symbol
 * @returns {import('./shared.mjs').OutcomeExtraction|null}
 */
function extractFunctionOutcomes(source, symbol, options = {}) {
  const braceStart = findFnBraceStart(source, symbol);
  if (braceStart === -1) return null;
  const body = extractBalancedBody(source, braceStart);
  if (body === null) return null;

  const headerEnd = source.lastIndexOf('->', braceStart);
  const declRe = new RegExp(`fn\\s+${escapeRegExp(symbol)}\\s*(?:<[^>]*>)?\\s*\\(`);
  const declStart = declRe.exec(source)?.index ?? -1;
  let retTypeName = null;
  let retText = '';
  if (headerEnd !== -1 && headerEnd > declStart) {
    retText = source.slice(headerEnd + 2, braceStart).trim();
    retText = retText.replace(/\s+where\b[\s\S]*$/, '').trim();
    const nameMatch = /^([A-Za-z_][A-Za-z0-9_]*)/.exec(retText);
    if (nameMatch) retTypeName = nameMatch[1];
  }

  let declared = [];
  let confidence = 'shallow';
  const unresolved = [];
  if (retText === 'bool') {
    declared = ['true', 'false'];
    confidence = 'exact';
  } else if (/^Option\s*</.test(retText)) {
    declared = ['Some', 'None'];
    confidence = 'syntactic';
  } else if (/^Result\s*</.test(retText)) {
    // Result always exposes success and failure. If its error is a local enum,
    // retain the useful detail without pretending to resolve imports.
    const inner = retText.slice(retText.indexOf('<') + 1, retText.lastIndexOf('>'));
    const args = [];
    let current = '';
    let depth = 0;
    for (const char of inner) {
      if (char === '<' || char === '(' || char === '[') depth++;
      if (char === '>' || char === ')' || char === ']') depth--;
      if (char === ',' && depth === 0) {
        args.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    if (current.trim()) args.push(current.trim());
    const errorText = args[1] || '';
    const errorName = /([A-Za-z_][A-Za-z0-9_]*)\s*$/.exec(errorText)?.[1] || null;
    const localErrorVariants = errorName ? extractEnumVariants(source, errorName) : null;
    const hasLocalStruct = errorName
      ? new RegExp(`(?:pub\\s+)?struct\\s+${escapeRegExp(errorName)}\\b`).test(source)
      : false;
    const resolved = !localErrorVariants && !hasLocalStruct && errorName && typeof options.resolveType === 'function'
      ? options.resolveType(errorName)
      : null;
    const errorVariants = localErrorVariants || (resolved?.kind === 'enum' ? resolved.variants : null);
    const hasStruct = hasLocalStruct || resolved?.kind === 'struct';
    declared = errorVariants
      ? ['Ok', ...errorVariants.map((variant) => `Err::${variant}`)]
      : ['Ok', 'Err'];
    confidence = resolved ? 'workspace' : errorVariants || hasStruct ? 'syntactic' : 'shallow';
    if (!errorVariants && !hasStruct) {
      unresolved.push(
        errorName
          ? `тип ошибки "${errorName}" не найден как enum в файле`
          : 'тип ошибки Result не разобран',
      );
    }
  } else if (retTypeName) {
    const variants = extractEnumVariants(source, retTypeName);
    if (variants) {
      declared = variants;
      confidence = 'syntactic';
    } else {
      unresolved.push(`тип возврата "${retTypeName}" не найден как enum в файле`);
    }
  } else {
    unresolved.push('тип возврата не указан или не разобран');
  }

  return { declared, escaping: findEscapingSites(body), confidence, unresolved };
}

/**
 * Единая точка входа адаптера (новый контракт): если `symbol` — enum,
 * возвращает его варианты как `declared` с `confidence: "exact"`; если это
 * функция — см. {@link extractFunctionOutcomes}; иначе `null`.
 * @param {string} source
 * @param {string} symbol
 * @returns {import('./shared.mjs').OutcomeExtraction|null}
 */
export function extractOutcomes(source, symbol, options = {}) {
  const enumVariants = extractEnumVariants(source, symbol);
  if (enumVariants) {
    return { declared: enumVariants, escaping: [], confidence: 'exact', unresolved: [] };
  }
  return extractFunctionOutcomes(source, symbol, options);
}

const DERIVE_RE = /derive\s*\([^)]*\b(?:Serialize|Deserialize)\b/;
const SERDE_ATTR_RE = /#\[serde\(/;

/**
 * Извлекает публичные типы (`pub struct`/`pub enum`) файла для
 * `spec.mjs candidates` (поиск доменных сущностей, не покрытых spec2).
 * Не путать с {@link extractEnumVariants}/{@link extractOutcomes} — там ищут
 * КОНКРЕТНЫЙ символ по имени, здесь — перечисляют ВСЕ объявления файла.
 * @param {string} source
 * @returns {{ name: string, kind: 'struct'|'enum', line: number, isPublic: boolean, hasSerialization: boolean }[]}
 */
export function extractPublicTypes(source) {
  const lines = source.split('\n');
  // Only externally public items belong in the domain-candidate queue.
  // `pub(crate)`, `pub(super)` and `pub(in ...)` are visibility restrictions,
  // not public API; accepting them made private persistence records look like
  // boundary/domain types.
  const declRe = /^\s*pub\s+(struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)/;
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = declRe.exec(lines[i]);
    if (!m) continue;
    // Атрибуты (`#[derive(...)]` и т.п.) стоят строго над объявлением —
    // собрать их текст, идя вверх, пока строки похожи на атрибут/доккомментарий.
    let attrText = '';
    for (let j = i - 1; j >= 0 && j >= i - 20; j--) {
      const t = lines[j].trim();
      if (t === '' || t.startsWith('#[') || t.startsWith('///') || t.startsWith('//!') || /^[\w,\s"()<>:=.]*\]$/.test(t)) {
        attrText = `${lines[j]}\n${attrText}`;
        continue;
      }
      break;
    }
    const hasSerialization = DERIVE_RE.test(attrText) || SERDE_ATTR_RE.test(attrText);
    out.push({ name: m[2], kind: m[1], line: i + 1, isPublic: true, hasSerialization });
  }
  return out;
}

const PUBLIC_FN_RE = /pub(?:\s+async)?\s+fn\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]*>)?\s*\(/g;

/**
 * Извлекает и склеивает текст сигнатур всех `pub fn` (параметры + `-> RetType`,
 * БЕЗ тела) — для сигнала «тип встречается в публичной сигнатуре» команды
 * `spec.mjs candidates`. Тело функции сюда не попадает: упоминание типа
 * внутри тела — не публичный контракт.
 * @param {string} source
 * @returns {string}
 */
export function findPublicSignatureText(source) {
  const spans = [];
  let m;
  PUBLIC_FN_RE.lastIndex = 0;
  while ((m = PUBLIC_FN_RE.exec(source))) {
    let depth = 1;
    let j = source.indexOf('(', m.index) + 1;
    while (j < source.length && depth > 0) {
      if (source[j] === '(') depth++;
      else if (source[j] === ')') depth--;
      j++;
    }
    const tail = source.slice(j, j + 300);
    const endRel = tail.search(/[{;]/);
    spans.push(source.slice(m.index, j) + (endRel === -1 ? tail : tail.slice(0, endRel)));
  }
  return spans.join('\n');
}

export default {
  language: 'rust',
  extensions: ['.rs'],
  extractEnumVariants,
  extractOutcomes,
  extractPublicTypes,
  findPublicSignatureText,
};

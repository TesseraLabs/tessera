// C#-адаптер для `spec.mjs outcomes` (конституция §10; тот же синтаксис
// обслуживает и Unity-код). Источник Declared — тип возврата (enum, иерархия
// result-типов, `OneOf<...>`/`Result<...>`, либо `<exception cref>` в
// XML-доке — единственная форма декларации исключений в C#). Escaping —
// необъявленный `throw`.

import { extractBalancedBraces, splitTopLevel, blankNonCode, escapeRegExp } from './shared.mjs';

const MODIFIERS_RE = /^(?:(?:public|private|protected|internal|static|virtual|override|sealed|async|abstract|new|partial|readonly)\s+)+/;

/**
 * Находит начало тела `enum X : byte { A, B = 1, C }` — индекс `{`, либо -1.
 * @param {string} source
 * @param {string} name
 * @returns {number}
 */
function findEnumBraceStart(source, name) {
  const re = new RegExp(`(?:public\\s+|internal\\s+|private\\s+|protected\\s+)?enum\\s+${escapeRegExp(name)}\\b(?:\\s*:\\s*\\w+)?`);
  const m = re.exec(blankNonCode(source));
  if (!m) return -1;
  return source.indexOf('{', m.index);
}

/**
 * Извлекает имена членов `enum X { A, B = 1, [Foo] C }`.
 * @param {string} source
 * @param {string} name
 * @returns {string[]|null}
 */
function extractEnumMembers(source, name) {
  const braceStart = findEnumBraceStart(source, name);
  if (braceStart === -1) return null;
  const res = extractBalancedBraces(source, braceStart);
  if (!res) return null;
  const nameRe = /^\s*([A-Za-z_][A-Za-z0-9_]*)/;
  return splitTopLevel(res.body, ',')
    .map((part) => nameRe.exec(part.replace(/\[[^\]]*\]/g, '')))
    .filter(Boolean)
    .map((m) => m[1]);
}

/**
 * Ищет `abstract record|class X` и прямых наследников `record|class A : X`
 * (в т.ч. с primary-конструктором `record A(...) : X`) в том же файле.
 * @param {string} source
 * @param {string} name
 * @returns {string[]|null}
 */
function extractHierarchySubclasses(source, name) {
  const codeOnly = blankNonCode(source);
  const baseRe = new RegExp(`abstract\\s+(?:record|class)\\s+${escapeRegExp(name)}\\b`);
  if (!baseRe.test(codeOnly)) return null;
  const subRe = new RegExp(`\\b(?:record|class)\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*(?:\\([^)]*\\))?\\s*:\\s*${escapeRegExp(name)}\\b`, 'g');
  const names = [];
  let m;
  while ((m = subRe.exec(codeOnly))) names.push(m[1]);
  return names.length > 0 ? names : null;
}

/**
 * Разрешает именованный тип `name`: enum → его члены, иерархия result-типа
 * → её прямые наследники. `null`, если ни то ни другое не найдено в файле.
 * @param {string} source
 * @param {string} name
 * @returns {{ values: string[], unresolved: string[] }|null}
 */
function resolveTypeByName(source, name) {
  const enumMembers = extractEnumMembers(source, name);
  if (enumMembers) return { values: enumMembers, unresolved: [] };
  const subclasses = extractHierarchySubclasses(source, name);
  if (subclasses) return { values: subclasses, unresolved: [] };
  return null;
}

/**
 * Находит заголовок метода `[модификаторы] RetType symbol(...) { ... }` (в
 * т.ч. generic-класс/метод, `partial`) и возвращает `{ declStart, braceStart,
 * retTypeText }`, либо null. Пропускает совпадения без тела (интерфейсные
 * члены, `;`) в поисках следующего.
 * @param {string} source
 * @param {string} symbol
 * @returns {{ declStart: number, braceStart: number, retTypeText: string }|null}
 */
function findMethodHeader(source, symbol) {
  // Поиск заголовка идёт по «забелённой» копии (комментарии и строки — в
  // пробелы), чтобы широкий класс символов `[\w<>[\],.\s]` не зацепил хвост
  // XML-доккомментария (там тоже есть `<...>` и буквы) как часть сигнатуры.
  // Индексы совпадают с оригиналом — длина не меняется.
  const codeOnly = blankNonCode(source);
  const re = new RegExp(`([\\w<>\\[\\],.\\s]+?)\\s+${escapeRegExp(symbol)}\\s*(?:<[^(]*>)?\\s*\\(`, 'g');
  let m;
  while ((m = re.exec(codeOnly))) {
    const parenStart = codeOnly.indexOf('(', m.index + m[0].length - 1);
    let depth = 1;
    let j = parenStart + 1;
    while (j < codeOnly.length && depth > 0) {
      if (codeOnly[j] === '(') depth++;
      else if (codeOnly[j] === ')') depth--;
      j++;
    }
    const window = codeOnly.slice(j, j + 400);
    const braceRel = window.search(/\{/);
    const semiRel = window.search(/;/);
    if (braceRel === -1) continue;
    if (semiRel !== -1 && semiRel < braceRel) continue; // объявление без тела
    const retTypeText = m[1].trim().replace(MODIFIERS_RE, '').trim();
    // `m.index` — начало «ленивого» совпадения, которое из-за пустых строк
    // на месте забелённых комментариев может уехать далеко назад; для
    // поиска доккомментария нужен именно старт реального текста сигнатуры.
    const leadingWs = /^\s*/.exec(m[1])[0].length;
    return { declStart: m.index + leadingWs, braceStart: j + braceRel, retTypeText };
  }
  return null;
}

/**
 * Собирает `<exception cref="...">` из блока XML-документации (`///`)
 * непосредственно над объявлением, пропуская атрибуты (`[...]`) между
 * доккомментарием и сигнатурой.
 * @param {string} source
 * @param {number} declStart
 * @returns {string[]}
 */
function findXmlDocExceptions(source, declStart) {
  const lines = source.slice(0, declStart).split('\n');
  const docLines = [];
  for (let i = lines.length - 1; i >= 0; i--) {
    const trimmed = lines[i].trim();
    if (trimmed === '') continue;
    if (trimmed.startsWith('///')) { docLines.unshift(trimmed); continue; }
    if (/^\[.*\]$/.test(trimmed)) continue; // атрибут над методом — доккомментарий может быть выше
    break;
  }
  const docText = docLines.join('\n');
  const names = [];
  const re = /<exception\s+cref="([^"]+)"/g;
  let m;
  while ((m = re.exec(docText))) {
    const cref = m[1].replace(/^[A-Za-z]:/, '');
    names.push(cref.slice(cref.lastIndexOf('.') + 1));
  }
  return names;
}

const THROW_STMT_RE = /\bthrow\s*([^;]*);/g;
const NEW_CALL_RE = /^new\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\(/;
const BARE_IDENT_RE = /^[A-Za-z_][A-Za-z0-9_.]*$/;
const THROW_IF_NULL_RE = /\bArgumentNullException\.ThrowIfNull\(/g;
const THROW_IF_RE = /\bObjectDisposedException\.ThrowIf\(/g;
const REFLECTION_RE = /\bActivator\.CreateInstance\(/;

/**
 * Ищет в теле метода сайты, где исход уходит мимо возвращаемого типа:
 * `throw new Foo(...)`, `throw;`, `throw caughtEx;` — распознаваемые формы;
 * прочие выражения после `throw` (вызов фабрики, индексация) не разобраны.
 * @param {string} body
 * @returns {{ escaping: { label: string, exceptionType: string|null }[], unresolved: string[] }}
 */
function findEscapingSites(body) {
  const escaping = [];
  const unresolved = [];
  let m;
  THROW_STMT_RE.lastIndex = 0;
  while ((m = THROW_STMT_RE.exec(body))) {
    const expr = m[1].trim();
    if (expr === '') { escaping.push({ label: 'throw;', exceptionType: null }); continue; }
    const newCall = NEW_CALL_RE.exec(expr);
    if (newCall) {
      const shortName = newCall[1].slice(newCall[1].lastIndexOf('.') + 1);
      escaping.push({ label: `throw new ${newCall[1]}`, exceptionType: shortName });
      continue;
    }
    if (BARE_IDENT_RE.test(expr)) { escaping.push({ label: `throw ${expr}`, exceptionType: null }); continue; }
    unresolved.push(`throw с неразобранным выражением: ${expr.slice(0, 60)}`);
  }
  THROW_IF_NULL_RE.lastIndex = 0;
  while ((m = THROW_IF_NULL_RE.exec(body))) escaping.push({ label: 'ArgumentNullException.ThrowIfNull(', exceptionType: null });
  THROW_IF_RE.lastIndex = 0;
  while ((m = THROW_IF_RE.exec(body))) escaping.push({ label: 'ObjectDisposedException.ThrowIf(', exceptionType: null });
  if (REFLECTION_RE.test(body)) unresolved.push('Activator.CreateInstance(...) — динамическое создание, не разобрано');
  return { escaping, unresolved };
}

/**
 * @param {string} source
 * @param {string} symbol
 * @returns {import('./shared.mjs').OutcomeExtraction|null}
 */
export function extractOutcomes(source, symbol) {
  const enumMembers = extractEnumMembers(source, symbol);
  if (enumMembers) {
    return { declared: enumMembers, escaping: [], confidence: 'exact', unresolved: [] };
  }

  const subclasses = extractHierarchySubclasses(source, symbol);
  if (subclasses) {
    return { declared: subclasses, escaping: [], confidence: 'exact', unresolved: [] };
  }

  const header = findMethodHeader(source, symbol);
  if (!header) return null;
  const bodyRes = extractBalancedBraces(source, header.braceStart);
  if (!bodyRes) return null;

  const { escaping: rawEscaping, unresolved: escapingUnresolved } = findEscapingSites(bodyRes.body);
  const xmlDocExceptions = findXmlDocExceptions(source, header.declStart);
  // `throw new FooException(...)`, документированный `<exception cref>` над
  // методом, — объявленный исход (единственная форма декларации в C#), не
  // необъявленный побег: убрать его из escaping.
  const escaping = rawEscaping
    .filter((site) => !(site.exceptionType && xmlDocExceptions.includes(site.exceptionType)))
    .map((site) => site.label);

  let text = header.retTypeText;
  const taskMatch = /^Task<([\s\S]*)>$/.exec(text);
  if (taskMatch) text = taskMatch[1].trim();

  if (text === 'void' || text === '') {
    const confidence = xmlDocExceptions.length > 0 ? 'syntactic' : 'shallow';
    return { declared: xmlDocExceptions, escaping, confidence, unresolved: escapingUnresolved };
  }

  const wrapperMatch = /^(?:OneOf|Result)<([\s\S]*)>$/.exec(text);
  if (wrapperMatch) {
    const args = splitTopLevel(wrapperMatch[1], ',');
    return { declared: [...xmlDocExceptions, ...args], escaping, confidence: 'syntactic', unresolved: escapingUnresolved };
  }

  const bareName = text.replace(/<[\s\S]*>/, '').trim();
  const resolved = resolveTypeByName(source, bareName);
  if (resolved) {
    return {
      declared: [...xmlDocExceptions, ...resolved.values],
      escaping,
      confidence: 'syntactic',
      unresolved: [...escapingUnresolved, ...resolved.unresolved],
    };
  }

  return {
    declared: xmlDocExceptions,
    escaping,
    confidence: 'shallow',
    unresolved: [...escapingUnresolved, `тип возврата "${text}" не enum/иерархия/OneOf|Result — не разобран`],
  };
}

const PUBLIC_TYPE_RE = /^\s*public\s+(?:sealed\s+|abstract\s+|static\s+|partial\s+)*(class|record|struct|enum)\s+([A-Za-z_][\w]*)/;
const SERIALIZATION_ATTR_RE = /\[(?:Serializable|DataContract|JsonSerializable)\b/;

/**
 * Извлекает публичные типы (`public class/record/struct/enum`) файла для
 * `spec.mjs candidates`, включая наличие сериализационных атрибутов над
 * объявлением. В отличие от {@link extractOutcomes}, перечисляет ВСЕ типы.
 * @param {string} source
 * @returns {{ name: string, kind: string, line: number, isPublic: boolean, hasSerialization: boolean }[]}
 */
export function extractPublicTypes(source) {
  const codeOnly = blankNonCode(source);
  const searchLines = codeOnly.split('\n');
  const rawLines = source.split('\n');
  const out = [];
  for (let i = 0; i < searchLines.length; i++) {
    const m = PUBLIC_TYPE_RE.exec(searchLines[i]);
    if (!m) continue;
    let attrText = '';
    for (let j = i - 1; j >= 0 && j >= i - 10; j--) {
      const t = rawLines[j].trim();
      if (t === '' || t.startsWith('[') || t.startsWith('///')) { attrText = `${rawLines[j]}\n${attrText}`; continue; }
      break;
    }
    out.push({ name: m[2], kind: m[1], line: i + 1, isPublic: true, hasSerialization: SERIALIZATION_ATTR_RE.test(attrText) });
  }
  return out;
}

const PUBLIC_METHOD_RE = /public\s+[\w<>[\],.\s]+?\s+[A-Za-z_][\w]*\s*(?:<[^(]*>)?\s*\(/g;

/**
 * Склеивает текст сигнатур всех `public` методов (параметры + возврат перед
 * `(`, без тела) — сигнал «публичная сигнатура» для `spec.mjs candidates`.
 * Работает по забелённой копии (комментарии/строки — в пробелы), как и
 * {@link findMethodHeader}, по той же причине: не зацепить хвост XML-доки.
 * @param {string} source
 * @returns {string}
 */
export function findPublicSignatureText(source) {
  const codeOnly = blankNonCode(source);
  const spans = [];
  let m;
  PUBLIC_METHOD_RE.lastIndex = 0;
  while ((m = PUBLIC_METHOD_RE.exec(codeOnly))) {
    const parenStart = codeOnly.indexOf('(', m.index + m[0].length - 1);
    let depth = 1;
    let j = parenStart + 1;
    while (j < codeOnly.length && depth > 0) {
      if (codeOnly[j] === '(') depth++;
      else if (codeOnly[j] === ')') depth--;
      j++;
    }
    const tail = codeOnly.slice(j, j + 300);
    const endRel = tail.search(/[{;]/);
    // Текст берём из ОРИГИНАЛА (по тем же индексам) — забелённая копия годна
    // только для поиска границ, не для содержимого.
    spans.push(source.slice(m.index, j) + (endRel === -1 ? tail : tail.slice(0, endRel)));
  }
  return spans.join('\n');
}

export default { language: 'csharp', extensions: ['.cs'], extractOutcomes, extractPublicTypes, findPublicSignatureText };

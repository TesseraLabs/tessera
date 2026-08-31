// Python-адаптер для `spec.mjs outcomes` (конституция §10). Синтаксис
// значимых отступов — тело функции/класса определяется отступом, а не
// скобками, поэтому парсер здесь построчный, не скобочный, как у остальных.

import { splitTopLevel, escapeRegExp } from './shared.mjs';

/**
 * @param {string} line
 * @returns {number} длина ведущего отступа (пробелы и табы считаются как есть)
 */
function indentOf(line) {
  return /^[ \t]*/.exec(line)[0].length;
}

/**
 * Находит тело блока (класса/функции), начинающегося на строке `headerIdx`
 * с отступом `headerIndent`: все последующие строки со строго большим
 * отступом, до первой непустой строки с отступом `<= headerIndent`.
 * @param {string[]} lines
 * @param {number} bodyStartIdx
 * @param {number} headerIndent
 * @returns {string[]}
 */
function collectIndentedBlock(lines, bodyStartIdx, headerIndent) {
  const body = [];
  for (let i = bodyStartIdx; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') { body.push(line); continue; }
    if (indentOf(line) <= headerIndent) break;
    body.push(line);
  }
  return body;
}

/**
 * Находит `class <name>(...Enum...):` и возвращает строки его тела, либо
 * null, если такого класса нет или он не наследует `Enum`/`StrEnum`/`IntEnum`.
 * @param {string} source
 * @param {string} name
 * @returns {string[]|null}
 */
function findEnumClassBody(source, name) {
  const lines = source.split('\n');
  const classRe = new RegExp(`^([ \\t]*)class\\s+${escapeRegExp(name)}\\s*\\(([^)]*)\\)\\s*:`);
  for (let i = 0; i < lines.length; i++) {
    const m = classRe.exec(lines[i]);
    if (!m) continue;
    if (!/\b(?:enum\.)?(?:Enum|StrEnum|IntEnum)\b/.test(m[2])) continue;
    return collectIndentedBlock(lines, i + 1, m[1].length);
  }
  return null;
}

/**
 * Извлекает имена членов `class X(Enum): A = 1; B = auto(); C = 'c'`.
 * @param {string} source
 * @param {string} name
 * @returns {string[]|null}
 */
function extractEnumMembers(source, name) {
  const bodyLines = findEnumClassBody(source, name);
  if (bodyLines === null) return null;
  const members = [];
  for (const raw of bodyLines) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith('"""') || line.startsWith("'''")) continue;
    if (line.startsWith('def ') || line.startsWith('@') || line.startsWith('class ')) continue;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=/.exec(line);
    if (m) members.push(m[1]);
  }
  return members;
}

/**
 * Разрешает один член аннотации возврата: `None`, строковый литерал внутри
 * `Literal[...]`, `Optional[X]`, либо ссылку на локальный enum-класс.
 * @param {string} source
 * @param {string} part
 * @returns {{ values: string[], unresolved: string[] }}
 */
function resolveAnnotationPart(source, part) {
  const text = part.trim();
  if (text === 'None') return { values: ['None'], unresolved: [] };

  const literalMatch = /^(?:typing\.)?Literal\[([\s\S]*)\]$/.exec(text);
  if (literalMatch) {
    const values = splitTopLevel(literalMatch[1], ',').map((v) => {
      const s = /^(['"])([\s\S]*)\1$/.exec(v.trim());
      return s ? s[2] : v.trim();
    });
    return { values, unresolved: [] };
  }

  const optionalMatch = /^(?:typing\.)?Optional\[([\s\S]*)\]$/.exec(text);
  if (optionalMatch) {
    const inner = resolveAnnotationPart(source, optionalMatch[1]);
    return { values: [...inner.values, 'None'], unresolved: inner.unresolved };
  }

  const identMatch = /^([A-Za-z_][A-Za-z0-9_.]*)$/.exec(text);
  if (identMatch) {
    const enumMembers = extractEnumMembers(source, identMatch[1]);
    if (enumMembers) return { values: enumMembers, unresolved: [] };
    return { values: [], unresolved: [`аннотация возврата ссылается на "${text}" — не enum и не разобран`] };
  }

  return { values: [], unresolved: [`аннотация возврата не разобрана: ${text.slice(0, 60)}`] };
}

/**
 * Находит `def <symbol>(...) [-> RetType]:`, включая многострочную сигнатуру
 * (параметры через несколько строк), и возвращает исходный отступ, полную
 * сигнатуру одной строкой и тело (строки с бо́льшим отступом).
 * @param {string} source
 * @param {string} symbol
 * @returns {{ signature: string, body: string[], indent: number }|null}
 */
function findFunction(source, symbol) {
  const lines = source.split('\n');
  const defRe = new RegExp(`^([ \\t]*)(?:async\\s+)?def\\s+${escapeRegExp(symbol)}\\s*\\(`);
  for (let i = 0; i < lines.length; i++) {
    const m = defRe.exec(lines[i]);
    if (!m) continue;
    const indent = m[1].length;
    let depth = 0;
    let sigEnd = -1;
    const sigLines = [];
    for (let j = i; j < lines.length; j++) {
      sigLines.push(lines[j]);
      for (const ch of lines[j]) {
        if ('([{'.includes(ch)) depth++;
        else if (')]}'.includes(ch)) depth--;
      }
      if (depth === 0 && /:\s*(#.*)?$/.test(lines[j])) { sigEnd = j; break; }
    }
    if (sigEnd === -1) return null; // сигнатура не закрылась
    return {
      signature: sigLines.join('\n'),
      body: collectIndentedBlock(lines, sigEnd + 1, indent),
      indent,
    };
  }
  return null;
}

const RAISE_CALL_RE = /^raise\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\(/;
const RAISE_BARE_RE = /^raise\s*(?:#.*)?$/;
const RAISE_IDENT_RE = /^raise\s+([A-Za-z_][A-Za-z0-9_.]*)\s*(?:#.*)?$/;
const RAISE_ANY_RE = /^raise\b/;

/**
 * Ищет в теле функции сайты, где исход уходит мимо аннотации возврата:
 * `raise Foo(...)`, `raise foo`, голый `raise`, `assert ...`. `raise` с
 * произвольным выражением (`raise errors[key]`, вызов через переменную)
 * не разобран — попадает в `unresolved`.
 * @param {string[]} bodyLines
 * @returns {{ escaping: string[], unresolved: string[] }}
 */
function findEscapingSites(bodyLines) {
  const escaping = [];
  const unresolved = [];
  for (const raw of bodyLines) {
    const line = raw.trim();
    if (line === '') continue;
    if (RAISE_CALL_RE.test(line)) { escaping.push(`raise ${RAISE_CALL_RE.exec(line)[1]}`); continue; }
    if (RAISE_BARE_RE.test(line)) { escaping.push('raise'); continue; }
    if (RAISE_IDENT_RE.test(line)) { escaping.push(`raise ${RAISE_IDENT_RE.exec(line)[1]}`); continue; }
    if (RAISE_ANY_RE.test(line)) { unresolved.push(`raise с неразобранным выражением: ${line.slice(0, 60)}`); continue; }
    if (/^assert\b/.test(line)) { escaping.push(`assert ${line.slice(6).trim().slice(0, 60)}`); continue; }
    if (/\beval\s*\(|\bexec\s*\(/.test(line)) { unresolved.push(`${line.slice(0, 60)} — динамический код, не разобрано`); }
  }
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

  const fn = findFunction(source, symbol);
  if (!fn) return null;
  const { escaping, unresolved: escapingUnresolved } = findEscapingSites(fn.body);

  const retMatch = /->\s*([\s\S]*?):\s*(?:#.*)?$/.exec(fn.signature);
  if (!retMatch) {
    // Отсутствие аннотации в Python — норма, а не дефект кода: честнее
    // сказать «мало знаю», чем сделать вид, что исходов нет (задача §10).
    return { declared: [], escaping, confidence: 'shallow', unresolved: [...escapingUnresolved, 'аннотация возврата отсутствует'] };
  }

  const values = [];
  const unresolved = [...escapingUnresolved];
  for (const part of splitTopLevel(retMatch[1], '|')) {
    const r = resolveAnnotationPart(source, part);
    values.push(...r.values);
    unresolved.push(...r.unresolved);
  }
  return { declared: values, escaping, confidence: 'syntactic', unresolved };
}

const TOP_LEVEL_CLASS_RE = /^class\s+([A-Za-z_][\w]*)/;
const SERIALIZATION_HINT_RE = /@dataclass|\bBaseModel\b|\bpydantic\b/;

/**
 * Извлекает классы верхнего уровня (отступ 0) для `spec.mjs candidates`.
 * Приватность в Python — соглашение об имени (`_Foo`), не язык: `isPublic`
 * отражает это соглашение, а не что-либо проверяемое компилятором.
 * @param {string} source
 * @returns {{ name: string, kind: 'class', line: number, isPublic: boolean, hasSerialization: boolean }[]}
 */
export function extractPublicTypes(source) {
  const lines = source.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = TOP_LEVEL_CLASS_RE.exec(lines[i]);
    if (!m) continue;
    let attrText = '';
    for (let j = i - 1; j >= 0 && j >= i - 6; j--) {
      const t = lines[j].trim();
      if (t === '' || t.startsWith('@')) { attrText = `${lines[j]}\n${attrText}`; continue; }
      break;
    }
    out.push({
      name: m[1],
      kind: 'class',
      line: i + 1,
      isPublic: !m[1].startsWith('_'),
      hasSerialization: SERIALIZATION_HINT_RE.test(attrText) || SERIALIZATION_HINT_RE.test(lines[i]),
    });
  }
  return out;
}

const PUBLIC_DEF_RE = /^([ \t]*)def\s+([A-Za-z][\w]*)\s*\(/;

/**
 * Склеивает текст сигнатур всех функций/методов, чьё имя не начинается с
 * `_` (соглашение Python о публичности), — параметры + `-> RetType`, без
 * тела. Сигнал «публичная сигнатура» для `spec.mjs candidates`.
 * @param {string} source
 * @returns {string}
 */
export function findPublicSignatureText(source) {
  const lines = source.split('\n');
  const spans = [];
  for (let i = 0; i < lines.length; i++) {
    const m = PUBLIC_DEF_RE.exec(lines[i]);
    if (!m) continue;
    let depth = 0;
    let sigEnd = -1;
    const sigLines = [];
    for (let j = i; j < lines.length; j++) {
      sigLines.push(lines[j]);
      for (const ch of lines[j]) {
        if ('([{'.includes(ch)) depth++;
        else if (')]}'.includes(ch)) depth--;
      }
      if (depth === 0 && /:\s*(#.*)?$/.test(lines[j])) { sigEnd = j; break; }
    }
    if (sigEnd === -1) continue;
    spans.push(sigLines.join('\n'));
  }
  return spans.join('\n');
}

export default { language: 'python', extensions: ['.py'], extractOutcomes, extractPublicTypes, findPublicSignatureText };
